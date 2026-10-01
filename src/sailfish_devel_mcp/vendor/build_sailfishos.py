#!/usr/bin/env python3

import argparse
from contextlib import contextmanager, nullcontext
import fcntl
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import urlopen


CONTAINER_UID = 100000
# Third-party mirror. Its tags describe available build images, not the current
# official SailfishOS release or installed SDK target.
CONTAINER_IMAGE = "coderus/sailfishos-platform-sdk"
HELPER_VERSION = "2.4.4"
LIVE_RELEASE = "live"
LOCAL_SDK_CANDIDATES = (
    Path("/srv/mer/sdks/sfossdk/sdk-chroot"),
    Path("/srv/sfos/sdks/sdk/sdk-chroot"),
)
DEFAULT_LOCAL_SDK = LOCAL_SDK_CANDIDATES[0]
LOCAL_SDK_BUILD_ENGINE_IMAGE_ENV = "SAILFISH_SDK_BUILD_ENGINE_IMAGE"
STATE_DIRNAME = "build-sailfishos-skill"
MANIFEST_NAME = "build-sailfishos-skill-manifest.txt"
BUILD_LOG_NAME = "build-sailfishos-skill-last.log"
BUILD_METADATA_NAME = "build-sailfishos-skill-last-build.json"
BUILD_LOCK_NAME = "build-sailfishos-skill.lock"
LOCAL_RPMS_STAGING_NAME = "local-rpms"
DEFAULT_PERMISSION_FALLBACK = "error"
QUIET_FAILURE_TAIL_BYTES = 65536
QUIET_FAILURE_TAIL_LINES = 80
QUIET_FAILURE_TAIL_CHARS = 6000
_QUIET_OUTPUT = False

LOCAL_RPM_EXCLUDED_MARKERS = (
    "-debuginfo-",
    "-debugsource-",
    "-tests-",
    "-examples-",
    "-doc-",
    "-ts-devel-",
)

ROOT_PATTERNS = (
    "Makefile",
    ".qmake.stash",
    "*.o",
    "*.a",
    "*.so",
    "*.prl",
    "moc_*.cpp",
    "moc_*.o",
    "qrc_*.cpp",
    "qrc_*.o",
    "ui_*.h",
    "CMakeCache.txt",
    "cmake_install.cmake",
    "compile_commands.json",
    "build.ninja",
    "rules.ninja",
    "install_manifest.txt",
)

RECURSIVE_PATTERNS = (
    "**/Makefile",
    "**/.qmake.stash",
    "**/moc_*.cpp",
    "**/moc_*.o",
    "**/qrc_*.cpp",
    "**/qrc_*.o",
    "**/*.o",
    "**/*.a",
    "**/*.so",
    "**/*.prl",
    "**/ui_*.h",
    "**/CMakeCache.txt",
    "**/cmake_install.cmake",
    "**/compile_commands.json",
    "**/build.ninja",
    "**/rules.ninja",
    "**/install_manifest.txt",
    "**/CMakeFiles",
)

ROOT_DIRS = (
    "installroot",
)

LOCAL_TARGET_ARCHES = ("aarch64", "armv7hl", "i486")
SNAPSHOT_KEY_MAX_LENGTH = 48
SNAPSHOT_REPOSITORY_ALIAS_PREFIX = "build-sailfishos"


@dataclass(frozen=True)
class LocalSdkTarget:
    arch: str
    target: str
    release: str
    version_id: str
    flavour: str
    snapshot_of: str = ""
    registered: bool = True


@dataclass(frozen=True)
class LocalSdkBuild:
    arch: str
    target: str
    snapshot: str | None = None


@dataclass(frozen=True)
class SnapshotRepository:
    alias: str
    url: str


@dataclass(frozen=True)
class BuildContext:
    backend: str
    release: str
    image: str | None
    image_id: str | None
    local_sdk: str | None


def log(message: str, *, force: bool = False) -> None:
    if force or not _QUIET_OUTPUT:
        print(message, file=sys.stderr)


def run(cmd: list[str], cwd: Path | None = None, capture_output: bool = False) -> subprocess.CompletedProcess[str]:
    if _QUIET_OUTPUT and not capture_output:
        with tempfile.TemporaryFile() as output:
            completed = subprocess.run(
                cmd,
                cwd=str(cwd) if cwd else None,
                check=False,
                stdout=output,
                stderr=subprocess.STDOUT,
            )
            if completed.returncode:
                output.seek(0, os.SEEK_END)
                size = output.tell()
                output.seek(max(0, size - QUIET_FAILURE_TAIL_BYTES))
                tail = output.read().decode("utf-8", errors="replace")
                lines = tail.splitlines()[-QUIET_FAILURE_TAIL_LINES:]
                excerpt = "\n".join(lines)
                if len(excerpt) > QUIET_FAILURE_TAIL_CHARS:
                    excerpt = excerpt[-QUIET_FAILURE_TAIL_CHARS:]
                    excerpt = "[failure output truncated]\n" + excerpt
                if excerpt:
                    print(excerpt, file=sys.stderr)
                raise subprocess.CalledProcessError(completed.returncode, cmd)
            return completed
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        check=True,
        text=True,
        capture_output=capture_output,
    )


def require_tool(name: str) -> None:
    if shutil.which(name):
        return
    raise SystemExit(f"Required tool not found: {name}")


def project_state_dir(project_dir: Path) -> Path:
    return project_dir / ".mb2" / STATE_DIRNAME


def manifest_path(project_dir: Path) -> Path:
    return project_dir / ".mb2" / MANIFEST_NAME


def build_log_path(project_dir: Path) -> Path:
    return project_dir / ".mb2" / BUILD_LOG_NAME


def build_metadata_path(project_dir: Path) -> Path:
    return project_dir / ".mb2" / BUILD_METADATA_NAME


def build_lock_path(project_dir: Path) -> Path:
    return project_dir / ".mb2" / BUILD_LOCK_NAME


def default_artifacts_dir(project_dir: Path) -> Path:
    return project_dir / "RPMS"


def staging_rpms_dir(project_dir: Path) -> Path:
    return project_state_dir(project_dir) / "rpms"


def local_rpms_staging_dir(project_dir: Path) -> Path:
    return project_state_dir(project_dir) / LOCAL_RPMS_STAGING_NAME


def write_json_atomic(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{time.time_ns()}.tmp")
    try:
        temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


@contextmanager
def project_build_lock(project_dir: Path):
    path = build_lock_path(project_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+", encoding="utf-8") as lock_file:
        try:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            lock_file.seek(0)
            owner = lock_file.read().strip()
            detail = f" (owner {owner})" if owner else ""
            raise SystemExit(f"Another SailfishOS build is already active for {project_dir}{detail}.") from exc
        lock_file.seek(0)
        lock_file.truncate()
        lock_file.write(f"pid={os.getpid()} started_utc={datetime.now(timezone.utc).isoformat()}\n")
        lock_file.flush()
        try:
            yield
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def local_sdk_target_lock_path(local_sdk: Path, target: str) -> Path:
    identity = f"{local_sdk.resolve(strict=False)}\0{canonical_local_target_name(target)}"
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
    root = Path(tempfile.gettempdir()) / f"build-sailfishos-{os.getuid()}"
    return root / f"sdk-target-{digest}.lock"


@contextmanager
def local_sdk_target_lock(local_sdk: Path, target: str):
    target = canonical_local_target_name(target)
    path = local_sdk_target_lock_path(local_sdk, target)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    directory = path.parent.stat()
    if (
        path.parent.is_symlink()
        or directory.st_uid != os.getuid()
        or directory.st_mode & 0o077
    ):
        raise SystemExit(f"Unsafe SDK target lock directory: {path.parent}")
    with path.open("a+", encoding="utf-8") as lock_file:
        try:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            lock_file.seek(0)
            owner = lock_file.read().strip()
            detail = f" (owner {owner})" if owner else ""
            raise SystemExit(
                f"Another SailfishOS build is already using SDK target {target}{detail}."
            ) from exc
        lock_file.seek(0)
        lock_file.truncate()
        lock_file.write(
            f"pid={os.getpid()} started_utc={datetime.now(timezone.utc).isoformat()}\n"
        )
        lock_file.flush()
        try:
            yield
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def has_spec_files(project_dir: Path) -> bool:
    rpm_dir = project_dir / "rpm"
    return rpm_dir.is_dir() and any(rpm_dir.glob("*.spec"))


def parse_version(value: str) -> tuple[int, ...]:
    return tuple(int(part) for part in value.split("."))


def is_version_release_tag(value: str) -> bool:
    return bool(re.fullmatch(r"\d+(?:\.\d+){3}", value))


def fetch_coderus_mirror_tags(prefix: str | None = None) -> list[str]:
    name_filter = quote(prefix) if prefix else ""

    matches: list[str] = []
    next_url = (
        "https://registry.hub.docker.com/v2/repositories/"
        f"{CONTAINER_IMAGE}/tags?page_size=100"
        f"{f'&name={name_filter}' if name_filter else ''}"
    )
    while next_url:
        with urlopen(next_url, timeout=10) as response:
            payload = json.load(response)
        for result in payload.get("results", []):
            name = result.get("name", "").strip()
            if prefix:
                if not (name == prefix or name.startswith(f"{prefix}.")):
                    continue
            if is_version_release_tag(name):
                matches.append(name)
        next_url = payload.get("next")
    return sorted(dict.fromkeys(matches), key=parse_version)


def latest_coderus_mirror_tag() -> str:
    matches = fetch_coderus_mirror_tags()
    if not matches:
        raise SystemExit(
            f"Could not determine the newest available Docker image tag from {CONTAINER_IMAGE}."
        )
    return matches[-1]


def normalize_release_tag(release: str) -> str:
    if release.lower() == LIVE_RELEASE:
        return LIVE_RELEASE

    if release == "latest":
        try:
            resolved = latest_coderus_mirror_tag()
        except (HTTPError, URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError) as exc:
            raise SystemExit(f"Could not resolve Docker image tag 'latest' from {CONTAINER_IMAGE}") from exc
        log(f"Resolved newest available {CONTAINER_IMAGE} image tag to {resolved}")
        return resolved

    if not re.fullmatch(r"\d+(?:\.\d+){2,3}", release):
        return release
    if release.count(".") >= 3:
        return release

    try:
        matches = fetch_coderus_mirror_tags(release)
    except (HTTPError, URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError):
        return release

    if not matches:
        return release
    if release in matches:
        return release

    resolved = max(matches, key=parse_version)
    log(f"Resolved release shorthand {release} to {CONTAINER_IMAGE} image tag {resolved}")
    return resolved


def infer_release_from_workflows(project_dir: Path) -> str | None:
    workflows_dir = project_dir / ".github" / "workflows"
    if not workflows_dir.is_dir():
        return None

    regexes = (
        re.compile(r"^\s*RELEASE:\s*([^\s#]+)\s*$"),
        re.compile(rf"{re.escape(CONTAINER_IMAGE)}:([^\s'\"#]+)"),
    )

    for workflow in sorted(workflows_dir.glob("*.y*ml")):
        try:
            text = workflow.read_text(encoding="utf-8")
        except OSError:
            continue
        for line in text.splitlines():
            for regex in regexes:
                match = regex.search(line)
                if match:
                    return match.group(1).strip()
    return None


def resolve_release(project_dirs: Iterable[Path], explicit_release: str | None) -> str:
    if explicit_release:
        return normalize_release_tag(explicit_release)

    env_release = os.environ.get("SAILFISHOS_RELEASE")
    if env_release:
        return normalize_release_tag(env_release)

    seen: set[Path] = set()
    for project_dir in project_dirs:
        if project_dir in seen:
            continue
        seen.add(project_dir)
        inferred = infer_release_from_workflows(project_dir)
        if inferred:
            return normalize_release_tag(inferred)

    try:
        resolved = latest_coderus_mirror_tag()
    except (HTTPError, URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(
            "Could not determine a build release from arguments, environment, workflows, "
            f"or available {CONTAINER_IMAGE} image tags."
        ) from exc

    log(
        f"No build release specified; using newest available {CONTAINER_IMAGE} "
        f"image tag {resolved}. This does not identify the current SailfishOS release."
    )
    return resolved


def parse_last_arch(project_dir: Path) -> str | None:
    target_file = project_dir / ".mb2" / "target"
    if not target_file.is_file():
        return None

    target = target_file.read_text(encoding="utf-8").strip()
    if not target:
        return None

    if target.startswith("SailfishOS-"):
        arch = target.rsplit("-", 1)[-1]
        if arch.endswith(".default"):
            arch = arch[: -len(".default")]
        return arch

    for arch in LOCAL_TARGET_ARCHES:
        if target == arch or target.startswith(f"{arch}.") or target.startswith(f"{arch}-"):
            return arch

    prefix = target.split(".", 1)[0].strip()
    return prefix or None


def pull_image(release: str) -> None:
    image = f"{CONTAINER_IMAGE}:{release}"
    log(f"Pulling {image}")
    run(["docker", "pull", image])


def docker_image_exists(image: str) -> bool:
    result = subprocess.run(
        ["docker", "image", "inspect", image],
        check=False,
        text=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0


def docker_image_id(image: str) -> str | None:
    try:
        result = run(
            ["docker", "image", "inspect", "--format", "{{.Id}}", image],
            capture_output=True,
        )
    except subprocess.CalledProcessError:
        return None
    return result.stdout.strip() or None


def ensure_image(release: str, pull_policy: str) -> tuple[str, bool]:
    image = f"{CONTAINER_IMAGE}:{release}"
    exists = docker_image_exists(image)
    should_pull = pull_policy == "always" or (pull_policy == "missing" and not exists)
    if should_pull:
        pull_image(release)
        return image, True
    if not exists:
        raise SystemExit(
            f"Docker image {image} is not available locally and pull policy is '{pull_policy}'."
        )
    return image, False


def list_supported_arches(release: str) -> list[str]:
    image = f"{CONTAINER_IMAGE}:{release}"
    result = run(
        [
            "docker",
            "run",
            "--rm",
            image,
            "bash",
            "-lc",
            "sb2-config -l",
        ],
        capture_output=True,
    )

    arches: list[str] = []
    seen: set[str] = set()
    prefix = f"SailfishOS-{release}-"
    for line in result.stdout.splitlines():
        line = line.strip()
        if line.startswith(prefix):
            arch = line[len(prefix) :]
            if arch.endswith(".default") or arch in seen:
                continue
            arches.append(arch)
            seen.add(arch)
    if not arches:
        raise SystemExit(f"No supported architectures found in {image}")
    return arches


def resolve_arches(requested_arches: list[str], build_all: bool, supported_arches: list[str], project_dir: Path) -> list[str]:
    if build_all:
        return supported_arches

    if requested_arches:
        invalid = [arch for arch in requested_arches if arch not in supported_arches]
        if invalid:
            raise SystemExit(
                f"Unsupported architectures: {', '.join(invalid)}. Supported: {', '.join(supported_arches)}"
            )
        return requested_arches

    last_arch = parse_last_arch(project_dir)
    if last_arch and last_arch in supported_arches:
        return [last_arch]

    raise SystemExit(
        "No architecture was specified and .mb2/target did not contain a supported one. "
        f"Pass --arch or --all. Supported: {', '.join(supported_arches)}"
    )


def resolve_local_sdk_arches(requested_arches: list[str], build_all: bool, project_dir: Path) -> list[str]:
    if build_all:
        raise SystemExit("Local SDK builds use installed SDK targets; pass one or more explicit --arch values.")

    if requested_arches:
        return requested_arches

    last_arch = parse_last_arch(project_dir)
    if last_arch:
        return [last_arch]

    raise SystemExit(
        "No architecture was specified and .mb2/target did not contain a previous target. "
        "Pass --arch for local SDK builds."
    )


def spec_names(project_dir: Path) -> set[str]:
    names: set[str] = set()
    for spec in sorted((project_dir / "rpm").glob("*.spec")):
        try:
            text = spec.read_text(encoding="utf-8")
        except OSError:
            continue
        for line in text.splitlines():
            match = re.match(r"^\s*Name:\s*(\S+)\s*$", line)
            if match:
                names.add(match.group(1))
                break
    return names


def pro_targets(project_dir: Path) -> set[str]:
    targets: set[str] = set()
    for pro in sorted(project_dir.glob("*.pro")):
        try:
            text = pro.read_text(encoding="utf-8")
        except OSError:
            continue
        for line in text.splitlines():
            match = re.match(r"^\s*TARGET\s*=\s*([^\s#]+)\s*$", line)
            if match and "$" not in match.group(1):
                targets.add(match.group(1))
                break
    return targets


def generated_candidate_paths(project_dir: Path) -> set[Path]:
    tracked_paths = tracked_git_paths(project_dir)
    paths: set[Path] = set()

    for dirname in ROOT_DIRS:
        path = project_dir / dirname
        if path.exists():
            paths.add(path)

    for pattern in ROOT_PATTERNS:
        paths.update(path for path in project_dir.glob(pattern) if path.exists())

    for pattern in RECURSIVE_PATTERNS:
        paths.update(
            path
            for path in project_dir.glob(pattern)
            if path.exists() and ".git" not in path.parts and ".mb2" not in path.parts
        )

    for qm in (project_dir / "translations").glob("*.qm") if (project_dir / "translations").is_dir() else []:
        if qm.exists():
            paths.add(qm)

    for name in sorted(spec_names(project_dir) | pro_targets(project_dir)):
        candidate = project_dir / name
        if candidate.exists():
            paths.add(candidate)

    state_dir = project_state_dir(project_dir)
    if state_dir.exists():
        paths.discard(state_dir)

    return {
        path
        for path in paths
        if path.exists() and path.resolve() not in tracked_paths
    }


def tracked_git_paths(project_dir: Path) -> set[Path]:
    try:
        repo_roots = git_worktree_roots(project_dir)
    except OSError:
        return set()

    tracked: set[Path] = set()
    for root in repo_roots:
        try:
            result = run(
                ["git", "-C", str(root), "ls-files", "-z"],
                capture_output=True,
            )
        except (subprocess.CalledProcessError, FileNotFoundError):
            continue

        for rel_path in result.stdout.split("\0"):
            if not rel_path:
                continue
            tracked.add((root / rel_path).resolve())
    return tracked


def git_worktree_roots(project_dir: Path) -> list[Path]:
    roots = {project_dir.resolve()}
    for git_marker in project_dir.rglob(".git"):
        if ".mb2" in git_marker.parts:
            continue
        repo_root = git_marker.parent.resolve()
        roots.add(repo_root)
    return sorted(roots)


def load_manifest(project_dir: Path) -> list[Path]:
    path = manifest_path(project_dir)
    if not path.is_file():
        return []

    result: list[Path] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        candidate = (project_dir / line).resolve()
        try:
            candidate.relative_to(project_dir.resolve())
        except ValueError:
            continue
        if candidate.exists():
            result.append(candidate)
    return result


def write_manifest(project_dir: Path, paths: Iterable[Path]) -> None:
    manifest = manifest_path(project_dir)
    manifest.parent.mkdir(parents=True, exist_ok=True)

    rel_paths = []
    root = project_dir.resolve()
    for path in sorted({p.resolve() for p in paths if p.exists()}):
        try:
            rel_paths.append(str(path.relative_to(root)))
        except ValueError:
            continue

    manifest.write_text("\n".join(rel_paths) + ("\n" if rel_paths else ""), encoding="utf-8")


def write_build_metadata(
    project_dir: Path,
    *,
    context: BuildContext,
    builds: list[dict[str, object]],
    debug_build: bool,
    artifacts_dir: Path,
    status: str,
    started_at: datetime,
    failure_class: str | None = None,
    failure_message: str | None = None,
) -> None:
    metadata_file = build_metadata_path(project_dir)
    finished_at = datetime.now(timezone.utc)
    serialized_builds: list[dict[str, object]] = []
    for build in builds:
        serialized = dict(build)
        serialized["rpms"] = [str(path) for path in build.get("rpms", [])]
        serialized_builds.append(serialized)
    rpms = [path for build in serialized_builds for path in build.get("rpms", [])]
    payload = {
        "schema_version": 2,
        "helper_version": HELPER_VERSION,
        "started_utc": started_at.isoformat(),
        "updated_utc": finished_at.isoformat(),
        "finished_utc": None if status == "running" else finished_at.isoformat(),
        "duration_seconds": round((finished_at - started_at).total_seconds(), 3),
        "backend": context.backend,
        "release": context.release,
        "image": context.image,
        "image_id": context.image_id,
        "local_sdk": context.local_sdk,
        "debug": debug_build,
        "status": status,
        "failure_class": failure_class,
        "failure_message": failure_message,
        "artifacts_dir": str(artifacts_dir),
        "build_log": str(build_log_path(project_dir)),
        "builds": serialized_builds,
        "rpms": rpms,
        "rpmlint": rpmlint_summary(build_log_path(project_dir)),
    }
    write_json_atomic(metadata_file, payload)


def write_target_marker(project_dir: Path, arch: str) -> None:
    mb2_dir = project_dir / ".mb2"
    mb2_dir.mkdir(parents=True, exist_ok=True)
    (mb2_dir / "target").write_text(f"{arch}.{STATE_DIRNAME}\n", encoding="utf-8")


def remove_path(path: Path) -> None:
    if not path.exists():
        return
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    else:
        path.unlink()


def cleanup_generated_artifacts(project_dir: Path, reason: str) -> list[Path]:
    manifest_paths = load_manifest(project_dir)
    cleanup_paths = set(manifest_paths) | generated_candidate_paths(project_dir)

    removed: list[Path] = []
    for path in sorted(cleanup_paths):
        if project_state_dir(project_dir) in path.parents or path == project_state_dir(project_dir):
            continue
        if path == manifest_path(project_dir):
            continue
        if path.exists():
            remove_path(path)
            removed.append(path)

    log(f"{reason}; removed {len(removed)} stale in-place artifacts")
    return removed


def cleanup_in_place_artifacts(project_dir: Path, previous_arch: str, next_arch: str) -> list[Path]:
    return cleanup_generated_artifacts(
        project_dir,
        f"Switched architecture from {previous_arch} to {next_arch}",
    )


def ensure_container_write_access(project_dir: Path, permission_fallback: str) -> None:
    current_uid = os.getuid()
    if shutil.which("setfacl"):
        log(
            f"Granting read ACLs under {project_dir} and scoped output write ACLs to container uid {CONTAINER_UID}"
        )
        (project_dir / ".mb2").mkdir(parents=True, exist_ok=True)
        run(
            [
                "find",
                str(project_dir),
                "-type",
                "d",
                "-uid",
                str(current_uid),
                "-exec",
                "setfacl",
                "-m",
                f"u:{CONTAINER_UID}:rX",
                "{}",
                "+",
            ]
        )
        run(
            [
                "find",
                str(project_dir),
                "-type",
                "f",
                "-uid",
                str(current_uid),
                "-exec",
                "setfacl",
                "-m",
                f"u:{CONTAINER_UID}:rX",
                "{}",
                "+",
            ]
        )
        writable_paths = {project_dir, project_dir / ".mb2"}
        translations = project_dir / "translations"
        if translations.is_dir():
            writable_paths.add(translations)
        writable_paths.update(generated_candidate_paths(project_dir))
        for path in sorted(writable_paths):
            if not path.exists():
                continue
            run(["setfacl", "-m", f"u:{CONTAINER_UID}:rwX", str(path)])
            if path.is_dir():
                run(["setfacl", "-m", f"d:u:{CONTAINER_UID}:rwX", str(path)])
        return

    if permission_fallback == "chmod":
        log("setfacl unavailable; falling back to chmod -R a+rwX")
        run(["chmod", "-R", "a+rwX", str(project_dir)])
        return

    raise SystemExit(
        "setfacl is unavailable, so the Docker container may not be able to write in place. "
        "Install acl utilities or rerun with --permission-fallback chmod."
    )


def usable_local_rpms(directory: Path) -> list[Path]:
    if not directory.is_dir():
        raise SystemExit(f"Local RPM directory not found: {directory}")
    return [
        rpm
        for rpm in sorted(directory.glob("*.rpm"))
        if not any(marker in rpm.name for marker in LOCAL_RPM_EXCLUDED_MARKERS)
    ]


def validate_local_rpm_dirs(directories: list[Path]) -> dict[Path, list[Path]]:
    selected: dict[Path, list[Path]] = {}
    for directory in directories:
        rpms = usable_local_rpms(directory)
        if not rpms:
            raise SystemExit(f"No installable RPMs found in local RPM directory: {directory}")
        selected[directory] = rpms
    return selected


@contextmanager
def stage_local_sdk_rpms(project_dir: Path, selected: dict[Path, list[Path]]):
    staging_root = local_rpms_staging_dir(project_dir)
    if staging_root.exists():
        shutil.rmtree(staging_root)
    staged_dirs: list[Path] = []
    try:
        for index, rpms in enumerate(selected.values()):
            destination = staging_root / str(index)
            destination.mkdir(parents=True, exist_ok=True)
            for rpm in rpms:
                shutil.copy2(rpm, destination / rpm.name)
            staged_dirs.append(destination)
        yield staged_dirs
    finally:
        if staging_root.exists():
            shutil.rmtree(staging_root)


def rpmlint_summary(log_file: Path) -> dict[str, int]:
    summary = {"errors": 0, "warnings": 0}
    if not log_file.is_file():
        return summary
    try:
        text = log_file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return summary
    final = re.findall(r"(?im);\s*(\d+)\s+errors?,\s*(\d+)\s+warnings?\.?$", text)
    if final:
        summary["errors"], summary["warnings"] = map(int, final[-1])
        return summary
    summary["errors"] = len(re.findall(r"(?m)^\S.*:\s+E:\s+", text))
    summary["warnings"] = len(re.findall(r"(?m)^\S.*:\s+W:\s+", text))
    return summary


def classify_failure(error: BaseException, log_file: Path | None = None) -> str:
    text = str(error)
    if log_file and log_file.is_file():
        try:
            text += "\n" + log_file.read_text(encoding="utf-8", errors="replace")[-20000:]
        except OSError:
            pass
    lowered = text.lower()
    if "failed build dependencies" in lowered or "is needed by" in lowered:
        return "missing-build-requires"
    if "no basic authentication credentials" in lowered or "repository" in lowered and "not found" in lowered:
        return "repository"
    if "signature" in lowered or "gpg" in lowered or "unsigned rpm" in lowered:
        return "package-trust"
    if "permission denied" in lowered or "operation not permitted" in lowered:
        return "permission"
    if "docker image" in lowered or "manifest unknown" in lowered or "pull access denied" in lowered:
        return "image"
    if isinstance(error, subprocess.TimeoutExpired):
        return "timeout"
    return "build"


def parse_missing_build_requires(log_text: str) -> list[str]:
    missing: list[str] = []
    capture = False
    for line in log_text.splitlines():
        if line.strip() == "error: Failed build dependencies:":
            capture = True
            continue
        if not capture:
            continue
        if line.startswith("\t") or line.startswith("    "):
            requirement = line.strip()
            if " is needed by " in requirement:
                requirement = requirement.split(" is needed by ", 1)[0].strip()
            if requirement:
                missing.append(requirement)
            continue
        if missing and line.strip():
            break
    return sorted(dict.fromkeys(missing))


def extract_zypper_names(output: str) -> list[str]:
    names: list[str] = []
    for line in output.splitlines():
        if "|" not in line or line.lstrip().startswith("--+"):
            continue
        parts = [part.strip() for part in line.split("|")]
        if len(parts) < 3:
            continue
        name = parts[1]
        if name and name not in {"Name", "S"}:
            names.append(name)
    return sorted(dict.fromkeys(names))


def diagnose_missing_dependencies(
    project_dir: Path, release: str, arch: str, *,
    local_sdk: Path | None = None, target: str | None = None,
) -> list[dict[str, object]]:
    log_file = build_log_path(project_dir)
    if not log_file.is_file():
        return []
    with log_file.open("rb") as handle:
        handle.seek(max(0, log_file.stat().st_size - 256 * 1024))
        missing = parse_missing_build_requires(handle.read().decode("utf-8", errors="replace"))
    diagnostics = []
    for requirement in missing[:20]:
        selected_target = target or f"SailfishOS-{release}-{arch}"
        query = ["sb2", "-t", selected_target, "-m", "sdk-install", "-R",
                 "zypper", "search", "--provides", "--match-exact", requirement]
        command = (local_sdk_command(local_sdk, query) if local_sdk else
                   ["docker", "run", "--rm", f"{CONTAINER_IMAGE}:{release}",
                    "bash", "-lc", shlex.join(query)])
        item: dict[str, object] = {"requirement": requirement, "target": selected_target}
        try:
            result = subprocess.run(command, text=True, capture_output=True, timeout=15, check=False)
            item.update(providers=extract_zypper_names(result.stdout)[:20], returncode=result.returncode)
        except (OSError, subprocess.TimeoutExpired) as error:
            item["error"] = str(error)[:500]
        diagnostics.append(item)
    if diagnostics:
        with log_file.open("a", encoding="utf-8") as handle:
            handle.write("\nDependency diagnostics: " + json.dumps(diagnostics) + "\n")
    return diagnostics


def verify_expected_rpms(rpms: list[Path], debug_build: bool) -> None:
    if not rpms:
        raise SystemExit("Build completed but no RPMs were captured")
    if debug_build:
        names = {rpm.name for rpm in rpms}
        if not any("-debuginfo-" in name for name in names):
            raise SystemExit("Debug build completed but no -debuginfo RPM was produced")
        if not any("-debugsource-" in name for name in names):
            raise SystemExit("Debug build completed but no -debugsource RPM was produced")


def variant_destination_dir(base_dir: Path, release: str, arch: str, debug_build: bool) -> Path:
    return base_dir / release / arch / ("debug" if debug_build else "release")


def host_user() -> str:
    return os.environ.get("USER") or os.environ.get("LOGNAME") or Path.home().name


def local_sdk_build_engine_image(user: str) -> str:
    return os.environ.get(LOCAL_SDK_BUILD_ENGINE_IMAGE_ENV, f"sailfish-sdk-build-engine:{user}")


def default_local_sdk() -> Path:
    for candidate in LOCAL_SDK_CANDIDATES:
        if os.access(candidate, os.X_OK):
            return candidate
    return DEFAULT_LOCAL_SDK


def local_sdk_project_mount_root(project_dir: Path) -> Path:
    home = Path.home().resolve()
    resolved = project_dir.resolve()
    try:
        resolved.relative_to(home)
    except ValueError as exc:
        raise SystemExit(
            "Local SDK builds currently require the project to live under the current user's home "
            "directory so the installed SDK chroot can see the same path."
        ) from exc
    return home


def local_sdk_mount_root(local_sdk: Path) -> Path:
    resolved = local_sdk.resolve(strict=False)
    for parent in resolved.parents:
        if (parent / "targets").is_dir():
            return parent
    return resolved.parent


def local_sdk_command(local_sdk: Path, command: list[str]) -> list[str]:
    user = host_user()
    uid = os.getuid()
    gid = os.getgid()
    home = str(Path.home().resolve())
    image = local_sdk_build_engine_image(user)
    sdk_mount_root = local_sdk_mount_root(local_sdk)
    # sdk-chroot's default non-recursive home bind hides an outer ~/.scratchbox2
    # mount. Mount only the registry at its final chroot path and skip that bind.
    sdk_home = local_sdk.resolve(strict=False).parent / Path(home).relative_to("/")
    inner = shlex.join(command)
    wrapper_command = f"""
set -euo pipefail
if [ ! -x "$LOCAL_SDK" ]; then
    echo "Installed Sailfish SDK chroot not found or not executable at $LOCAL_SDK" >&2
    exit 1
fi
if getent passwd mersdk >/dev/null 2>&1; then
    sed -i 's#^mersdk:[^:]*:[0-9]*:[0-9]*:[^:]*:[^:]*:#{user}:x:{uid}:{gid}::{home}:#' /etc/passwd
elif ! getent passwd {shlex.quote(user)} >/dev/null 2>&1; then
    printf '%s:x:%s:%s::%s:/bin/bash\\n' {shlex.quote(user)} {uid} {gid} {shlex.quote(home)} >> /etc/passwd
fi
if [ "$(getent group {gid} | cut -d: -f1)" != {shlex.quote(user)} ]; then
    sed -i -e '/^{user}:/d' -e '/^[^:]*:[^:]*:{gid}:/d' /etc/group
    printf '%s:x:%s:\\n' {shlex.quote(user)} {gid} >> /etc/group
fi
"$LOCAL_SDK" -u {shlex.quote(user)} -m root {inner}
""".strip()
    return [
        "docker",
        "run",
        "--rm",
        "--privileged",
        "-v",
        f"{sdk_mount_root}:{sdk_mount_root}",
        "-v",
        f"{home}/.scratchbox2:{sdk_home}/.scratchbox2",
        "-e",
        f"LOCAL_SDK={local_sdk}",
        image,
        "bash",
        "-lc",
        wrapper_command,
    ]


def sdk_refresh_target(local_sdk: Path, target: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", target):
        raise ValueError("invalid SDK target name")
    canonical_target = canonical_local_target_name(target)
    if target.endswith(".default"):
        return f"{canonical_target}.default"
    metadata = target_metadata(local_sdk_targets_dir(local_sdk) / canonical_target)
    return canonical_target if metadata.get("snapshot_of") else f"{canonical_target}.default"


def sdk_refresh_command(local_sdk: Path, target: str, force: bool = False) -> list[str]:
    working_target = sdk_refresh_target(local_sdk, target)
    command = ["sb2", "-t", working_target, "-m", "sdk-install", "-R", "zypper", "ref"]
    if force:
        command.append("-f")
    return local_sdk_command(local_sdk, command)


def doctor(local_sdk: Path | None = None) -> dict[str, object]:
    return {
        "helper_version": HELPER_VERSION,
        "tools": {name: bool(shutil.which(name)) for name in ("docker", "git", "setfacl", "ssh", "scp", "osc", "rg")},
        "local_sdk": str(local_sdk) if local_sdk else None,
        "sdk_executable": bool(local_sdk and os.access(local_sdk, os.X_OK)),
        "targets": [
            {"name": target.target, "arch": target.arch, "release": target.release,
             "registered": target.registered, "snapshot_of": target.snapshot_of}
            for target in list_local_sdk_targets(local_sdk)
        ] if local_sdk else [],
    }


def local_sdk_targets_dir(local_sdk: Path) -> Path:
    return local_sdk_mount_root(local_sdk) / "targets"


def normalize_snapshot_key(value: str) -> str:
    key = re.sub(r"[^a-z0-9]+", "-", value.strip().lower()).strip("-")
    if not key:
        raise SystemExit("Snapshot key must contain at least one letter or digit")
    if len(key) > SNAPSHOT_KEY_MAX_LENGTH:
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:10]
        key = f"{key[: SNAPSHOT_KEY_MAX_LENGTH - len(digest) - 1].rstrip('-')}-{digest}"
    return key


def git_branch_name(project_dir: Path) -> str | None:
    try:
        completed = subprocess.run(
            ["git", "-C", str(project_dir), "branch", "--show-current"],
            check=False,
            text=True,
            capture_output=True,
        )
    except FileNotFoundError:
        return None
    branch = completed.stdout.strip()
    return branch or None


def git_common_project_name(project_dir: Path) -> str | None:
    try:
        completed = subprocess.run(
            ["git", "-C", str(project_dir), "rev-parse", "--git-common-dir"],
            check=False,
            text=True,
            capture_output=True,
        )
    except FileNotFoundError:
        return None
    if completed.returncode:
        return None
    common_dir = Path(completed.stdout.strip())
    if not common_dir.is_absolute():
        common_dir = (project_dir / common_dir).resolve()
    if not common_dir.name:
        return None
    return common_dir.parent.name if common_dir.name == ".git" else common_dir.name


def infer_snapshot_key(project_dir: Path) -> str:
    candidates = [part for part in reversed(project_dir.resolve().parts) if part]
    candidates.extend(sorted(spec_names(project_dir)))
    branch = git_branch_name(project_dir)
    if branch:
        candidates.append(branch)

    esr_pattern = re.compile(r"(?:^|[^a-z0-9])esr[-_.]?(\d{2,3})(?=$|[^0-9])", re.IGNORECASE)
    for candidate in candidates:
        match = esr_pattern.search(candidate)
        if match:
            return f"browser-esr{match.group(1)}"

    names = sorted(spec_names(project_dir))
    if len(names) == 1:
        return normalize_snapshot_key(names[0])

    common_name = git_common_project_name(project_dir)
    return normalize_snapshot_key(common_name or project_dir.name)


def local_snapshot_names(base_target: str, snapshot_key: str) -> tuple[str, str]:
    base_target = canonical_local_target_name(base_target)
    key = normalize_snapshot_key(snapshot_key)
    root = key if key.startswith(f"{base_target}-") else f"{base_target}-{key}"
    return root, f"{root}.default"


def parse_snapshot_repositories(values: list[str]) -> list[SnapshotRepository]:
    repositories: list[SnapshotRepository] = []
    for value in values:
        if not value or any(character in value for character in "\0\n\r\t"):
            raise SystemExit("Snapshot repository must be a non-empty ALIAS=URL or URL value")
        alias = ""
        url = value
        if "=" in value:
            possible_alias, possible_url = value.split("=", 1)
            if re.fullmatch(r"[A-Za-z0-9_.-]+", possible_alias) and possible_url:
                alias = possible_alias
                url = possible_url
        if not alias:
            digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:12]
            alias = f"{SNAPSHOT_REPOSITORY_ALIAS_PREFIX}-{digest}"
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", alias):
            raise SystemExit(f"Invalid snapshot repository alias: {alias}")
        repositories.append(SnapshotRepository(alias=alias, url=url))
    return repositories


def validate_snapshot_packages(values: list[str]) -> list[str]:
    packages: list[str] = []
    for value in values:
        if not value or any(character in value for character in "\0\n\r\t"):
            raise SystemExit("Snapshot package names must be non-empty single-line values")
        packages.append(value)
    return packages


def canonical_local_target_name(name: str) -> str:
    while name.endswith(".default"):
        name = name[: -len(".default")]
    return name


def local_sdk_build_target(base_target: str, target: str) -> str:
    base_target = canonical_local_target_name(base_target)
    target = canonical_local_target_name(target)
    return f"{base_target}.default" if target == base_target else target


def split_local_target_arch(target: str) -> tuple[str, str] | None:
    for arch in LOCAL_TARGET_ARCHES:
        if target == arch:
            return arch, ""
        if target.startswith(f"{arch}-"):
            return arch, target[len(arch) + 1 :]
    return None


def read_key_value_file(path: Path) -> dict[str, str]:
    if not path.is_file():
        return {}

    metadata: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("[") or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        metadata[key.strip()] = value.strip().strip('"')
    return metadata


def target_metadata(target_dir: Path) -> dict[str, str | bool]:
    sailfish = read_key_value_file(target_dir / "etc" / "sailfish-release")
    ssu = read_key_value_file(target_dir / "etc" / "ssu" / "ssu.ini")
    sdk_manage = read_key_value_file(target_dir / ".sdk-manage.conf")
    return {
        "release": ssu.get("release", ""),
        "version_id": sailfish.get("VERSION_ID", ""),
        "flavour": ssu.get("flavour") or sailfish.get("SAILFISH_FLAVOUR", ""),
        "snapshot_of": sdk_manage.get("snapshot-of", ""),
        "registered": ssu.get("registered", "").lower() == "true",
    }


def list_local_sdk_targets(local_sdk: Path) -> list[LocalSdkTarget]:
    targets_dir = local_sdk_targets_dir(local_sdk)
    if not targets_dir.is_dir():
        return []

    targets: dict[str, LocalSdkTarget] = {}
    for child in sorted(targets_dir.iterdir()):
        if not child.is_dir() or ".pool." in child.name:
            continue

        target = canonical_local_target_name(child.name)
        arch_and_suffix = split_local_target_arch(target)
        if arch_and_suffix is None:
            continue
        arch, suffix = arch_and_suffix

        if target in targets and child.name != target:
            continue

        metadata = target_metadata(child)
        release = str(metadata.get("release", ""))
        version_id = str(metadata.get("version_id", ""))
        flavour = str(metadata.get("flavour", ""))
        if not release and suffix:
            release = suffix
        targets[target] = LocalSdkTarget(
            arch=arch,
            target=target,
            release=release,
            version_id=version_id,
            flavour=flavour,
            snapshot_of=str(metadata.get("snapshot_of", "")),
            registered=bool(metadata.get("registered", False)),
        )
    return sorted(targets.values(), key=lambda item: (item.arch, item.target))


def release_component_count(release: str) -> int:
    return len(release.split(".")) if re.fullmatch(r"\d+(?:\.\d+){2,3}", release) else 0


def local_target_matches_release(target: LocalSdkTarget, release: str) -> bool:
    release = normalize_local_release(release)
    if not release or release == LIVE_RELEASE:
        return target.release == LIVE_RELEASE
    if release == "latest":
        return False

    if target.release == release or target.version_id == release:
        return True

    component_count = release_component_count(release)
    if component_count == 3:
        return target.version_id.startswith(f"{release}.") or target.target.endswith(f"-{release}")

    return target.target.endswith(f"-{release}")


def normalize_local_release(release: str | None) -> str:
    if not release:
        return ""
    release = release.strip()
    if release.lower() == LIVE_RELEASE:
        return LIVE_RELEASE
    return release


def requested_release(project_dirs: Iterable[Path], explicit_release: str | None) -> str | None:
    requested = explicit_requested_release(explicit_release)
    if requested:
        return requested

    seen: set[Path] = set()
    for project_dir in project_dirs:
        if project_dir in seen:
            continue
        seen.add(project_dir)
        inferred = infer_release_from_workflows(project_dir)
        if inferred:
            return inferred

    return None


def explicit_requested_release(explicit_release: str | None) -> str | None:
    if explicit_release:
        return explicit_release

    env_release = os.environ.get("SAILFISHOS_RELEASE")
    if env_release:
        return env_release

    return None


def local_sdk_requested_release(explicit_release: str | None) -> str:
    return normalize_local_release(explicit_requested_release(explicit_release)) or LIVE_RELEASE


def select_local_sdk_builds(
    local_sdk: Path,
    release: str,
    requested_arches: list[str],
    build_all: bool,
    project_dir: Path,
    requested_targets: list[str] | None = None,
) -> list[LocalSdkBuild] | None:
    requested_targets = requested_targets or []
    installed = list_local_sdk_targets(local_sdk)
    base_targets = [
        target
        for target in installed
        if not target.snapshot_of and target.registered
    ]
    matching = [
        target
        for target in base_targets
        if local_target_matches_release(target, release)
    ]
    if requested_targets:
        by_name = {target.target: target for target in base_targets}
        builds: list[LocalSdkBuild] = []
        for requested in requested_targets:
            target = by_name.get(canonical_local_target_name(requested))
            if target is None:
                return None
            if release != LIVE_RELEASE and not local_target_matches_release(target, release):
                return None
            builds.append(LocalSdkBuild(target.arch, target.target))
        return builds
    if not matching:
        return None

    by_arch = {target.arch: target for target in matching}
    by_target = {target.target: target for target in matching}

    if build_all:
        return [LocalSdkBuild(target.arch, target.target) for target in matching]

    requested = requested_arches[:]
    if not requested:
        last_arch = parse_last_arch(project_dir)
        if last_arch:
            requested = [last_arch]

    if not requested:
        return None

    builds: list[LocalSdkBuild] = []
    for arch in requested:
        target = by_target.get(arch) or by_arch.get(arch)
        if target is None:
            return None
        builds.append(LocalSdkBuild(target.arch, target.target))
    return builds


def plan_local_sdk_snapshots(
    builds: list[LocalSdkBuild],
    project_dir: Path,
    requested_key: str | None,
    *,
    has_custom_inputs: bool,
) -> tuple[str | None, list[LocalSdkBuild]]:
    snapshot_key = None
    if requested_key:
        snapshot_key = normalize_snapshot_key(requested_key)
    elif has_custom_inputs:
        snapshot_key = infer_snapshot_key(project_dir)

    planned = []
    for build in builds:
        if snapshot_key is None:
            build_target = canonical_local_target_name(build.target)
        else:
            build_target, _ = local_snapshot_names(build.target, snapshot_key)
        planned.append(LocalSdkBuild(build.arch, build.target, build_target))
    return snapshot_key, planned


def build_local_sdk_arch(
    project_dir: Path,
    local_sdk: Path,
    release: str,
    arch: str,
    base_target: str,
    target: str,
    debug_build: bool = False,
    local_rpm_dirs: list[Path] | None = None,
    snapshot_repositories: list[SnapshotRepository] | None = None,
    snapshot_packages: list[str] | None = None,
    no_vcs_apply: bool = True,
    allow_untrusted_rpms: bool = False,
) -> None:
    user = host_user()
    uid = os.getuid()
    gid = os.getgid()
    home = str(Path.home().resolve())
    image = local_sdk_build_engine_image(user)
    project_mount_root = local_sdk_project_mount_root(project_dir)
    sdk_mount_root = local_sdk_mount_root(local_sdk)
    binary_names = ":".join(sorted(spec_names(project_dir) | pro_targets(project_dir)))
    local_rpm_dirs = local_rpm_dirs or []
    snapshot_repositories = snapshot_repositories or []
    snapshot_packages = snapshot_packages or []
    base_target = canonical_local_target_name(base_target)
    target = canonical_local_target_name(target)
    if target != base_target and not target.startswith(f"{base_target}-"):
        raise SystemExit(
            f"Managed snapshot {target!r} does not belong to base target {base_target!r}"
        )
    repository_recipe = "\n".join(
        f"{repository.alias}\t{repository.url}" for repository in snapshot_repositories
    )
    package_recipe = "\n".join(snapshot_packages)

    inner_command = r'''
set -euo pipefail
cd "$PROJECT_DIR"
mkdir -p .mb2
mkdir -p .mb2/build-sailfishos-skill
logfile="$BUILD_LOG"
: > "$logfile"
{
  echo "# build-sailfishos-skill"
  echo "release=${RELEASE:-}"
  echo "arch=${ARCH:-}"
  echo "debug=${DEBUG_BUILD:-0}"
  echo "base_target=${BASE_TARGET:-}"
  echo "target=${TARGET:-}"
  echo
} >> "$logfile"

# The registered architecture target is an immutable base. Custom inputs use
# an isolated snapshot that is reset after the base changes and built directly.
# Ordinary base builds retain mb2's shared .default working snapshot.
if [ "$TARGET" != "$BASE_TARGET" ]; then
  sdk-manage target snapshot --reset=outdated --no-sync \
    "$BASE_TARGET" "$TARGET" 2>&1 | tee -a "$logfile"
fi

if [ -n "${SNAPSHOT_REPOSITORIES:-}" ]; then
  while IFS=$'\t' read -r repository_alias repository_url; do
    [ -n "$repository_alias" ] || continue
    sb2 -t "$TARGET" -m sdk-install -R zypper --non-interactive \
      removerepo "$repository_alias" >> "$logfile" 2>&1 || true
    sb2 -t "$TARGET" -m sdk-install -R zypper --non-interactive \
      addrepo --refresh "$repository_url" "$repository_alias" 2>&1 | tee -a "$logfile"
  done <<< "$SNAPSHOT_REPOSITORIES"
fi

if [ -n "${SNAPSHOT_PACKAGES:-}" ]; then
  snapshot_packages=()
  while IFS= read -r package_name; do
    [ -n "$package_name" ] || continue
    snapshot_packages+=("$package_name")
  done <<< "$SNAPSHOT_PACKAGES"
  if [ "${#snapshot_packages[@]}" -gt 0 ]; then
    sb2 -t "$TARGET" -m sdk-install -R zypper --non-interactive \
      install "${snapshot_packages[@]}" 2>&1 | tee -a "$logfile"
  fi
fi

if [ -n "${LOCAL_RPM_DIRS:-}" ]; then
  rpm_files=()
  OLDIFS="$IFS"
  IFS=':'
  for dir in ${LOCAL_RPM_DIRS}; do
    [ -d "$dir" ] || continue
    for rpm in "$dir"/*.rpm; do
      [ -e "$rpm" ] || continue
      case "$(basename "$rpm")" in
        *-debuginfo-*|*-debugsource-*|*-tests-*|*-examples-*|*-doc-*|*-ts-devel-*)
          continue
          ;;
      esac
      rpm_files+=("$rpm")
    done
  done
  IFS="$OLDIFS"
  if [ "${#rpm_files[@]}" -gt 0 ]; then
    zypper_args=( --non-interactive install --oldpackage --force-resolution )
    if [ "${ALLOW_UNTRUSTED_RPMS:-0}" = "1" ]; then
      zypper_args+=( --allow-unsigned-rpm )
    fi
    sb2 -t "$TARGET" -m sdk-install -R zypper "${zypper_args[@]}" \
      "${rpm_files[@]}" 2>&1 | tee -a "$logfile"
  fi
fi

mb2_args=( -t "$TARGET" )
if [ "$TARGET" != "$BASE_TARGET" ]; then
  mb2_args+=( --no-snapshot=force )
fi
if [ "${NO_VCS_APPLY:-0}" = "1" ]; then
  mb2_args+=( --no-vcs-apply )
fi
mb2_args+=( build --prepare )
if [ "${DEBUG_BUILD:-0}" = "1" ]; then
  mb2_args+=( -d )
fi
mb2 "${mb2_args[@]}" 2>&1 | tee -a "$logfile"

rm -rf .mb2/build-sailfishos-skill/rpms
if [ -d RPMS ]; then
  mkdir -p .mb2/build-sailfishos-skill/rpms
  find RPMS -maxdepth 1 -type f -name '*.rpm' -exec cp -f {} .mb2/build-sailfishos-skill/rpms/ \;
  chmod -R u+rwX .mb2/build-sailfishos-skill/rpms >/dev/null 2>&1 || true
fi

OLDIFS="$IFS"
IFS=':'
for name in ${SYNC_BINARIES:-}; do
  [ -n "$name" ] || continue
  [ -e "$name" ] || continue
  cp -f "$name" .mb2/build-sailfishos-skill/ >/dev/null 2>&1 || true
done
IFS="$OLDIFS"
'''
    wrapper_command = rf'''
set -euo pipefail
if [ ! -x "$LOCAL_SDK" ]; then
  echo "Installed Sailfish SDK chroot not found or not executable at $LOCAL_SDK" >&2
  exit 1
fi
if getent passwd mersdk >/dev/null 2>&1; then
  sed -i 's#^mersdk:[^:]*:[0-9]*:[0-9]*:[^:]*:[^:]*:#{user}:x:{uid}:{gid}::{home}:#' /etc/passwd
elif ! getent passwd {shlex.quote(user)} >/dev/null 2>&1; then
  printf '%s:x:%s:%s::%s:/bin/bash\n' {shlex.quote(user)} {uid} {gid} {shlex.quote(home)} >> /etc/passwd
fi
if [ "$(getent group {gid} | cut -d: -f1)" != {shlex.quote(user)} ]; then
    sed -i -e '/^{user}:/d' -e '/^[^:]*:[^:]*:{gid}:/d' /etc/group
    printf '%s:x:%s:\n' {shlex.quote(user)} {gid} >> /etc/group
fi
"$LOCAL_SDK" -u {shlex.quote(user)} env \
  PROJECT_DIR="$PROJECT_DIR" \
  RELEASE="$RELEASE" \
  BASE_TARGET="$BASE_TARGET" \
  TARGET="$TARGET" \
  ARCH="$ARCH" \
  DEBUG_BUILD="$DEBUG_BUILD" \
  BUILD_LOG="$BUILD_LOG" \
  LOCAL_RPM_DIRS="$LOCAL_RPM_DIRS" \
  SNAPSHOT_REPOSITORIES="$SNAPSHOT_REPOSITORIES" \
  SNAPSHOT_PACKAGES="$SNAPSHOT_PACKAGES" \
  NO_VCS_APPLY="$NO_VCS_APPLY" \
  ALLOW_UNTRUSTED_RPMS="$ALLOW_UNTRUSTED_RPMS" \
  SYNC_BINARIES="$SYNC_BINARIES" \
  bash -lc {shlex.quote(inner_command)}
'''
    log(
        f"Building local SDK target {target} from {base_target} "
        f"for {release} via installed SDK {local_sdk}"
    )
    run(
        [
            "docker",
            "run",
            "--rm",
            "--privileged",
            "-v",
            f"{sdk_mount_root}:{sdk_mount_root}",
            "-v",
            f"{project_mount_root}:{project_mount_root}",
            "-w",
            str(project_dir),
            "-e",
            f"PROJECT_DIR={project_dir}",
            "-e",
            f"LOCAL_SDK={local_sdk}",
            "-e",
            f"RELEASE={release}",
            "-e",
            f"BASE_TARGET={base_target}",
            "-e",
            f"TARGET={target}",
            "-e",
            f"ARCH={arch}",
            "-e",
            f"DEBUG_BUILD={'1' if debug_build else '0'}",
            "-e",
            f"BUILD_LOG={build_log_path(project_dir)}",
            "-e",
            f"LOCAL_RPM_DIRS={':'.join(str(path) for path in local_rpm_dirs)}",
            "-e",
            f"SNAPSHOT_REPOSITORIES={repository_recipe}",
            "-e",
            f"SNAPSHOT_PACKAGES={package_recipe}",
            "-e",
            f"NO_VCS_APPLY={'1' if no_vcs_apply else '0'}",
            "-e",
            f"ALLOW_UNTRUSTED_RPMS={'1' if allow_untrusted_rpms else '0'}",
            "-e",
            f"SYNC_BINARIES={binary_names}",
            image,
            "bash",
            "-lc",
            wrapper_command,
        ]
    )


def build_arch(
    project_dir: Path,
    release: str,
    arch: str,
    debug_build: bool = False,
    local_rpm_dirs: list[Path] | None = None,
    no_vcs_apply: bool = False,
    allow_untrusted_rpms: bool = False,
) -> None:
    image = f"{CONTAINER_IMAGE}:{release}"
    target = f"SailfishOS-{release}-{arch}"
    binary_names = ":".join(sorted(spec_names(project_dir) | pro_targets(project_dir)))
    is_gecko_build = (project_dir / "gecko-dev").is_dir() and (project_dir / "rpm" / "xulrunner-qt5.spec").is_file()
    local_rpm_dirs = local_rpm_dirs or []
    local_rpm_mounts = [f"/local-rpms/{index}" for index, _ in enumerate(local_rpm_dirs)]
    build_command = r'''
set -euo pipefail
workroot="${HOME:-/tmp}"
if [ ! -d "$workroot" ] || [ ! -w "$workroot" ]; then
  workroot=/tmp
fi
workdir="$workroot/build-sailfishos-skill"
mkdir -p /share/.mb2
mkdir -p /share/.mb2/build-sailfishos-skill
logfile=/share/.mb2/build-sailfishos-skill-last.log
: > "$logfile"
{
  echo "# build-sailfishos-skill"
  echo "release=${RELEASE:-}"
  echo "arch=${ARCH:-}"
  echo "debug=${DEBUG_BUILD:-0}"
  echo "target=${TARGET:-}"
  echo
} >> "$logfile"
rm -rf "$workdir"
mkdir -p "$workdir"
cp -a /share/. "$workdir/"
rm -rf "$workdir/RPMS"
cd "$workdir"
if [ "${IS_GECKO_BUILD:-0}" = "1" ]; then
  # The local Sailfish gecko checkout already has the rpm/ patch stack applied,
  # so keep %prep for its bootstrap side effects but disable patch re-apply in
  # the copied spec.
  sed -i \
    -e 's/^%autosetup -p1 -n /%autosetup -N -n /' \
    rpm/xulrunner-qt5.spec
fi

if [ -n "${LOCAL_RPM_DIRS:-}" ]; then
  rpm_files=()
  OLDIFS="$IFS"
  IFS=':'
  for dir in ${LOCAL_RPM_DIRS}; do
    [ -d "$dir" ] || continue
    for rpm in "$dir"/*.rpm; do
      [ -e "$rpm" ] || continue
      case "$(basename "$rpm")" in
        *-debuginfo-*|*-debugsource-*|*-tests-*|*-examples-*|*-doc-*|*-ts-devel-*)
          continue
          ;;
      esac
      rpm_files+=("$rpm")
    done
  done
  IFS="$OLDIFS"
  if [ "${#rpm_files[@]}" -gt 0 ]; then
    zypper_args=( --non-interactive install --oldpackage --force-resolution )
    if [ "${ALLOW_UNTRUSTED_RPMS:-0}" = "1" ]; then
      zypper_args+=( --allow-unsigned-rpm )
    fi
    zypper "${zypper_args[@]}" "${rpm_files[@]}" 2>&1 | tee -a "$logfile"
  fi
fi

mb2_args=( -t "$TARGET" )
if [ "${IS_GECKO_BUILD:-0}" = "1" ] || [ "${NO_VCS_APPLY:-0}" = "1" ]; then
  mb2_args+=( --no-vcs-apply )
fi
mb2_args+=( build )
if [ "${IS_GECKO_BUILD:-0}" = "1" ]; then
  mb2_args+=( --prepare )
fi
if [ "${DEBUG_BUILD:-0}" = "1" ]; then
  mb2_args+=( -d )
fi
mb2 "${mb2_args[@]}" 2>&1 | tee -a "$logfile"

for state_file in .mb2/target .mb2/spec .mb2/snapshot.lock; do
  if [ -e "$state_file" ]; then
    cp -f "$state_file" /share/.mb2/
  fi
done
chmod -R a+rwX /share/.mb2 >/dev/null 2>&1 || true

rm -rf /share/.mb2/build-sailfishos-skill/rpms
if [ -d RPMS ]; then
  mkdir -p /share/.mb2/build-sailfishos-skill/rpms
  find RPMS -maxdepth 1 -type f -name '*.rpm' -exec cp -f {} /share/.mb2/build-sailfishos-skill/rpms/ \;
  chmod -R a+rwX /share/.mb2/build-sailfishos-skill/rpms >/dev/null 2>&1 || true
fi

for pattern in \
  Makefile .qmake.stash '*.o' '*.a' '*.so' '*.prl' '*.list' \
  'moc_*.cpp' 'moc_*.o' 'qrc_*.cpp' 'qrc_*.o' 'ui_*.h' \
  CMakeCache.txt cmake_install.cmake compile_commands.json build.ninja rules.ninja install_manifest.txt
do
  for f in $pattern; do
    [ -e "$f" ] || continue
    cp -f "$f" /share/
  done
done

if [ -d translations ]; then
  mkdir -p /share/translations
  for f in translations/*.qm; do
    [ -e "$f" ] || continue
    cp -f "$f" /share/translations/
  done
fi

OLDIFS="$IFS"
IFS=':'
for name in ${SYNC_BINARIES:-}; do
  [ -n "$name" ] || continue
  [ -e "$name" ] || continue
  cp -f "$name" /share/
done
IFS="$OLDIFS"
'''
    gecko_wrapper_command = rf'''
set -euo pipefail
if [ ! -e /usr/lib/libclang.so.15 ]; then
  zypper --non-interactive install clang-libs
fi
if ! rpm -q gcc-c++ >/dev/null 2>&1; then
  zypper --non-interactive install gcc-c++
fi
python3 - <<'PY'
import os
import pwd

pw = pwd.getpwnam("mersdk")
os.environ["HOME"] = pw.pw_dir
os.setgroups([])
os.setgid(pw.pw_gid)
os.setuid(pw.pw_uid)
os.execvp("bash", ["bash", "-lc", {build_command!r}])
PY
'''
    log(f"Building {target} via container shadow build and syncing artifacts back in place")
    try:
        docker_cmd = [
            "docker",
            "run",
            "--rm",
            "--privileged",
            "-v",
            f"{project_dir}:/share",
        ]
        if is_gecko_build:
            docker_cmd.extend(["-u", "0"])
        for mount_path, local_rpm_dir in zip(local_rpm_mounts, local_rpm_dirs):
            docker_cmd.extend(["-v", f"{local_rpm_dir}:{mount_path}:ro"])
        docker_cmd.extend(
            [
                "-e",
                f"TARGET={target}",
                "-e",
                f"RELEASE={release}",
                "-e",
                f"ARCH={arch}",
                "-e",
                f"DEBUG_BUILD={'1' if debug_build else '0'}",
                "-e",
                f"BUILD_LOG={build_log_path(project_dir)}",
                "-e",
                f"SYNC_BINARIES={binary_names}",
                "-e",
                f"LOCAL_RPM_DIRS={':'.join(local_rpm_mounts)}",
                "-e",
                f"NO_VCS_APPLY={'1' if no_vcs_apply else '0'}",
                "-e",
                f"ALLOW_UNTRUSTED_RPMS={'1' if allow_untrusted_rpms else '0'}",
                "-e",
                f"IS_GECKO_BUILD={'1' if is_gecko_build else '0'}",
                image,
                "bash",
                "-lc",
                gecko_wrapper_command if is_gecko_build else build_command,
            ]
        )
        run(docker_cmd)
    except subprocess.CalledProcessError:
        raise


def copy_rpms(project_dir: Path, release: str, arch: str, debug_build: bool, artifacts_dir: Path) -> list[Path]:
    rpm_dir = staging_rpms_dir(project_dir)
    if not rpm_dir.is_dir():
        raise SystemExit("Build completed but staged RPMs were not captured")

    rpms = sorted(rpm_dir.glob("*.rpm"))
    if not rpms:
        raise SystemExit("Build completed but no staged RPMs were found")

    destination_dir = variant_destination_dir(artifacts_dir, release, arch, debug_build)
    if destination_dir.exists():
        shutil.rmtree(destination_dir)
    destination_dir.mkdir(parents=True, exist_ok=True)

    copied: list[Path] = []
    for rpm in rpms:
        destination = destination_dir / rpm.name
        shutil.copy2(rpm, destination)
        copied.append(destination)

    shutil.rmtree(rpm_dir)
    return copied


def resolve_project_dir(project_dir: Path) -> Path:
    if not project_dir.is_dir():
        raise SystemExit(f"Project directory not found: {project_dir}")

    if has_spec_files(project_dir):
        return project_dir

    matches = [child for child in sorted(project_dir.iterdir()) if child.is_dir() and has_spec_files(child)]
    if len(matches) == 1:
        log(f"Using SailfishOS build root {matches[0]} discovered under {project_dir}")
        return matches[0]
    if len(matches) > 1:
        options = ", ".join(str(path) for path in matches)
        raise SystemExit(
            f"{project_dir} contains multiple one-level-deep SailfishOS build roots: {options}. "
            "Pass --project-dir pointing at the intended one."
        )

    raise SystemExit(
        f"Could not find rpm/*.spec in {project_dir} or one level below it. "
        "Pass --project-dir pointing at the SailfishOS build root."
    )


def build_preflight_payload(
    *,
    project_dir: Path,
    context: BuildContext,
    builds: list[LocalSdkBuild | str],
    artifacts_dir: Path,
    local_rpms: dict[Path, list[Path]],
    snapshot_key: str | None,
    snapshot_repositories: list[SnapshotRepository],
    snapshot_packages: list[str],
    debug_build: bool,
    clean: bool,
    no_vcs_apply: bool,
    allow_untrusted_rpms: bool,
    pull_policy: str,
    image_available: bool | None,
) -> dict[str, object]:
    planned_builds = [
        {
            "arch": build.arch if isinstance(build, LocalSdkBuild) else build,
            "target": (
                build.snapshot or build.target
                if isinstance(build, LocalSdkBuild)
                else f"SailfishOS-{context.release}-{build}"
            ),
            **(
                {"base_target": build.target}
                if isinstance(build, LocalSdkBuild)
                else {}
            ),
        }
        for build in builds
    ]
    permission_strategy = "local-sdk-user"
    if context.backend == "docker":
        permission_strategy = "scoped-acl" if shutil.which("setfacl") else "configured-fallback"
    would_pull = bool(
        context.backend == "docker"
        and (pull_policy == "always" or (pull_policy == "missing" and image_available is False))
    )
    return {
        "schema_version": 1,
        "helper_version": HELPER_VERSION,
        "project_dir": str(project_dir),
        "backend": context.backend,
        "release": context.release,
        "image": context.image,
        "image_available": image_available,
        "local_sdk": context.local_sdk,
        "builds": planned_builds,
        "debug": debug_build,
        "clean": clean,
        "no_vcs_apply": no_vcs_apply,
        "artifacts_dir": str(artifacts_dir),
        "local_rpms": {
            str(directory): [str(rpm) for rpm in rpms]
            for directory, rpms in local_rpms.items()
        },
        "snapshot_key": snapshot_key,
        "snapshot_repositories": [
            {"alias": repository.alias, "url": repository.url}
            for repository in snapshot_repositories
        ],
        "snapshot_packages": snapshot_packages,
        "allow_untrusted_rpms": allow_untrusted_rpms,
        "pull_policy": pull_policy,
        "would_pull": would_pull,
        "permission_strategy": permission_strategy,
        "mutates_project": False,
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    selected_local_sdk = default_local_sdk()
    parser = argparse.ArgumentParser(description="Build a SailfishOS project with Docker or an installed SDK")
    parser.add_argument("--doctor", action="store_true", help="Report local tools and SDK targets as JSON without building")
    parser.add_argument("--refresh-metadata", action="store_true", help="Refresh one installed SDK working target, without building")
    parser.add_argument("--force-refresh", action="store_true", help="Force metadata refresh with zypper ref -f")
    parser.add_argument("--version", action="version", version=f"%(prog)s {HELPER_VERSION}")
    parser.add_argument("--project-dir", default=".", help="Project root containing rpm/*.spec")
    parser.add_argument("--release", help="SailfishOS release, for example 3.4.0.24")
    parser.add_argument("--arch", action="append", default=[], help="Architecture to build, may be repeated")
    parser.add_argument(
        "--target",
        action="append",
        default=[],
        help="Exact registered local SDK base target; builds use a managed project snapshot",
    )
    parser.add_argument(
        "--snapshot-key",
        help=(
            "Stable isolation key for a managed local SDK snapshot. Ordinary "
            "builds share the base target's .default snapshot; custom inputs "
            "default to an ESR-aware key or the package/repository name"
        ),
    )
    parser.add_argument(
        "--snapshot-repository",
        action="append",
        default=[],
        metavar="[ALIAS=]URL",
        help="Repository to ensure in the managed project snapshot; may be repeated",
    )
    parser.add_argument(
        "--snapshot-package",
        action="append",
        default=[],
        help="Package to ensure in the managed project snapshot; may be repeated",
    )
    parser.add_argument("--all", action="store_true", help="Build every architecture supported by the chosen SDK image")
    parser.add_argument("--list-arches", action="store_true", help="Print supported architectures and exit")
    parser.add_argument(
        "--backend",
        choices=("auto", "docker", "local"),
        default="auto",
        help="Build backend. Auto uses --local-sdk/--target when supplied, otherwise Docker",
    )
    parser.add_argument(
        "--permission-fallback",
        choices=("error", "chmod"),
        default=DEFAULT_PERMISSION_FALLBACK,
        help="Fallback when setfacl is unavailable",
    )
    parser.add_argument(
        "--artifacts-dir",
        help="Directory where built RPMs are copied. Defaults to RPMS/",
    )
    parser.add_argument("--clean", action="store_true", help="Remove generated in-place build artifacts before building")
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Pass -d to mb2 build so main binaries are stripped and debug packages are generated",
    )
    parser.add_argument(
        "--local-rpms-dir",
        action="append",
        default=[],
        help="Directory of locally built RPMs to install into the SDK target before building; may be repeated",
    )
    parser.add_argument(
        "--pull-policy",
        choices=("always", "missing", "never"),
        default="always",
        help="When to pull the release Docker image",
    )
    parser.add_argument("--no-pull", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument(
        "--local-sdk",
        nargs="?",
        const=str(selected_local_sdk),
        help=(
            "Use the installed SDK chroot through a privileged Docker wrapper "
            f"instead of a release Docker image. Defaults to {selected_local_sdk} "
            "when no path is supplied."
        ),
    )
    vcs_group = parser.add_mutually_exclusive_group()
    vcs_group.add_argument(
        "--no-vcs-apply",
        dest="no_vcs_apply",
        action="store_true",
        default=None,
        help="Tell mb2 not to apply VCS changes before building",
    )
    vcs_group.add_argument(
        "--vcs-apply",
        dest="no_vcs_apply",
        action="store_false",
        help="Allow mb2 to apply VCS changes (local SDK builds default to no VCS apply)",
    )
    parser.add_argument(
        "--allow-untrusted-rpms",
        action="store_true",
        help="Allow unsigned RPMs supplied with --local-rpms-dir",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate inputs and print the build plan without pulling, cleaning, changing ACLs, or building",
    )
    parser.add_argument("--json", action="store_true", help="Print --dry-run output as JSON")
    parser.add_argument(
        "--quiet",
        action="store_true",
        help=(
            "Suppress successful command output; keep the full project build log and "
            "print only a bounded tail when a command fails"
        ),
    )
    args = parser.parse_args(argv)
    if args.json and not args.dry_run:
        parser.error("--json requires --dry-run")
    if args.target and args.backend == "docker":
        parser.error("--target requires --backend local or auto")
    if (
        args.snapshot_key or args.snapshot_repository or args.snapshot_package
    ) and args.backend == "docker":
        parser.error("snapshot options require --backend local or auto")
    if args.local_sdk and args.backend == "docker":
        parser.error("--local-sdk cannot be combined with --backend docker")
    return args


def concise_error(error: BaseException) -> str:
    if isinstance(error, subprocess.CalledProcessError):
        command = error.cmd if isinstance(error.cmd, list) else [str(error.cmd)]
        return f"Command exited with status {error.returncode}: {shlex.join(command)[:500]}"
    return str(error) or error.__class__.__name__


def main(argv: list[str] | None = None) -> int:
    global _QUIET_OUTPUT
    args = parse_args(argv)
    _QUIET_OUTPUT = args.quiet
    if args.doctor:
        sdk = Path(args.local_sdk) if args.local_sdk else default_local_sdk()
        print(json.dumps(doctor(sdk), sort_keys=True))
        return 0
    if args.refresh_metadata:
        if len(args.target) != 1 or args.backend == "docker" or args.dry_run:
            raise SystemExit("--refresh-metadata requires one --target and a local backend; cannot use --dry-run")
        sdk = Path(args.local_sdk) if args.local_sdk else default_local_sdk()
        sdk = sdk.expanduser().resolve()
        run(sdk_refresh_command(sdk, args.target[0], args.force_refresh))
        return 0
    if args.force_refresh:
        raise SystemExit("--force-refresh requires --refresh-metadata")
    require_tool("docker")

    requested_project_dir = Path(args.project_dir).resolve()
    project_dir = resolve_project_dir(requested_project_dir)

    if args.no_pull:
        args.pull_policy = "never"

    local_requested = (
        args.backend == "local"
        or args.local_sdk is not None
        or bool(args.target)
        or bool(args.snapshot_key)
        or bool(args.snapshot_repository)
        or bool(args.snapshot_package)
    )
    local_sdk_value = args.local_sdk or (str(default_local_sdk()) if local_requested else None)
    local_sdk_path = Path(local_sdk_value).expanduser().resolve(strict=False) if local_sdk_value else None
    local_builds: list[LocalSdkBuild] | None = None

    if local_requested and args.backend != "docker":
        assert local_sdk_path is not None
        local_release = local_sdk_requested_release(args.release)
        local_builds = select_local_sdk_builds(
            local_sdk_path,
            local_release,
            args.arch,
            args.all or args.list_arches,
            project_dir,
            args.target,
        )
        if local_builds:
            if local_release == LIVE_RELEASE:
                installed_by_name = {target.target: target for target in list_local_sdk_targets(local_sdk_path)}
                selected = installed_by_name.get(local_builds[0].target)
                release = (selected.release or selected.version_id) if selected else LIVE_RELEASE
                release = release or LIVE_RELEASE
            else:
                release = local_release
        elif args.backend == "local" or args.target or local_release == LIVE_RELEASE:
            available = ", ".join(
                target.target
                for target in list_local_sdk_targets(local_sdk_path)
                if not target.snapshot_of and target.registered
            ) or "none"
            raise SystemExit(
                f"No matching registered local SDK base target for release {local_release}. "
                f"Available base targets: {available}"
            )
        else:
            log(
                f"No matching local SDK target for release {local_release}; "
                f"falling back to {CONTAINER_IMAGE}"
            )
            release = resolve_release((requested_project_dir, project_dir), args.release)
    else:
        release = resolve_release((requested_project_dir, project_dir), args.release)
        if release == LIVE_RELEASE:
            raise SystemExit("Release 'live' requires --local-sdk with a matching installed SDK target.")

    use_local_sdk = local_sdk_path is not None and local_builds is not None

    image: str | None = None
    image_available: bool | None = None
    if use_local_sdk:
        image = local_sdk_build_engine_image(host_user())
        image_available = docker_image_exists(image)
        if not image_available and not args.dry_run:
            raise SystemExit(f"Local SDK wrapper image is not available: {image}")
    else:
        image = f"{CONTAINER_IMAGE}:{release}"
        image_available = docker_image_exists(image)

    supported_arches: list[str] = []
    if not use_local_sdk and not args.dry_run:
        image, _ = ensure_image(release, args.pull_policy)
        image_available = True
        supported_arches = list_supported_arches(release)
    elif not use_local_sdk and image_available:
        supported_arches = list_supported_arches(release)

    if args.list_arches:
        if use_local_sdk:
            print("\n".join(build.arch for build in local_builds))
            return 0
        if args.dry_run and not supported_arches:
            raise SystemExit(f"Cannot list architectures because Docker image {image} is not available locally.")
        print("\n".join(supported_arches))
        return 0

    snapshot_repositories = parse_snapshot_repositories(args.snapshot_repository)
    snapshot_packages = validate_snapshot_packages(args.snapshot_package)
    local_rpm_dirs = [Path(path).resolve() for path in args.local_rpms_dir]
    selected_local_rpms = validate_local_rpm_dirs(local_rpm_dirs)
    snapshot_key: str | None = None
    if use_local_sdk:
        assert local_builds is not None
        snapshot_key, local_builds = plan_local_sdk_snapshots(
            local_builds,
            project_dir,
            args.snapshot_key,
            has_custom_inputs=bool(
                snapshot_repositories or snapshot_packages or selected_local_rpms
            ),
        )

    if use_local_sdk:
        builds: list[LocalSdkBuild | str] = local_builds
    elif args.dry_run and not supported_arches:
        if args.all:
            builds = ["<all-supported-architectures>"]
        else:
            requested = args.arch or ([parse_last_arch(project_dir)] if parse_last_arch(project_dir) else [])
            if not requested:
                raise SystemExit("Pass --arch or make the Docker image available so targets can be discovered.")
            builds = [arch for arch in requested if arch]
    else:
        builds = resolve_arches(args.arch, args.all, supported_arches, project_dir)
    artifacts_dir = Path(args.artifacts_dir).resolve() if args.artifacts_dir else default_artifacts_dir(project_dir)
    no_vcs_apply = args.no_vcs_apply if args.no_vcs_apply is not None else use_local_sdk

    context = BuildContext(
        backend="local" if use_local_sdk else "docker",
        release=release,
        image=image,
        image_id=docker_image_id(image) if image_available and image else None,
        local_sdk=str(local_sdk_path) if use_local_sdk else None,
    )
    if args.dry_run:
        payload = build_preflight_payload(
            project_dir=project_dir,
            context=context,
            builds=builds,
            artifacts_dir=artifacts_dir,
            local_rpms=selected_local_rpms,
            snapshot_key=snapshot_key,
            snapshot_repositories=snapshot_repositories,
            snapshot_packages=snapshot_packages,
            debug_build=args.debug,
            clean=args.clean,
            no_vcs_apply=no_vcs_apply,
            allow_untrusted_rpms=args.allow_untrusted_rpms,
            pull_policy=args.pull_policy,
            image_available=image_available,
        )
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print(f"Backend: {payload['backend']}")
            print(f"Release: {payload['release']}")
            print(f"Builds: {', '.join(item['target'] for item in payload['builds'])}")
            print(f"Artifacts: {payload['artifacts_dir']}")
            print(f"Would pull image: {'yes' if payload['would_pull'] else 'no'}")
        return 0

    started_at = datetime.now(timezone.utc)
    all_copied_rpms: list[Path] = []
    build_records: list[dict[str, object]] = []
    rpm_context = stage_local_sdk_rpms(project_dir, selected_local_rpms) if use_local_sdk else nullcontext(local_rpm_dirs)
    with project_build_lock(project_dir), rpm_context as effective_local_rpm_dirs:
        if not use_local_sdk:
            ensure_container_write_access(project_dir, args.permission_fallback)

        for build in builds:
            arch = build.arch if isinstance(build, LocalSdkBuild) else build
            target = (
                build.snapshot or build.target
                if isinstance(build, LocalSdkBuild)
                else f"SailfishOS-{release}-{arch}"
            )
            record: dict[str, object] = {
                "arch": arch,
                "target": target,
                "status": "running",
                "rpms": [],
            }
            if isinstance(build, LocalSdkBuild):
                record["base_target"] = build.target
                record["snapshot_key"] = snapshot_key
            build_records.append(record)
            write_build_metadata(
                project_dir,
                context=context,
                builds=build_records,
                debug_build=args.debug,
                artifacts_dir=artifacts_dir,
                status="running",
                started_at=started_at,
            )
            build_started = time.monotonic()
            try:
                previous_arch = parse_last_arch(project_dir)
                if previous_arch and previous_arch != arch:
                    cleanup_in_place_artifacts(project_dir, previous_arch, arch)
                elif args.clean:
                    cleanup_generated_artifacts(project_dir, "Explicit cleanup requested")

                if isinstance(build, LocalSdkBuild):
                    assert local_sdk_path is not None
                    assert build.snapshot is not None
                    isolated = canonical_local_target_name(
                        build.snapshot
                    ) != canonical_local_target_name(build.target)
                    target_lock = (
                        local_sdk_target_lock(local_sdk_path, build.snapshot)
                        if isolated
                        else nullcontext()
                    )
                    with target_lock:
                        build_local_sdk_arch(
                            project_dir,
                            local_sdk_path,
                            release,
                            arch,
                            build.target,
                            build.snapshot,
                            debug_build=args.debug,
                            local_rpm_dirs=effective_local_rpm_dirs,
                            snapshot_repositories=snapshot_repositories,
                            snapshot_packages=snapshot_packages,
                            no_vcs_apply=no_vcs_apply,
                            allow_untrusted_rpms=args.allow_untrusted_rpms,
                        )
                else:
                    build_arch(
                        project_dir,
                        release,
                        arch,
                        debug_build=args.debug,
                        local_rpm_dirs=effective_local_rpm_dirs,
                        no_vcs_apply=no_vcs_apply,
                        allow_untrusted_rpms=args.allow_untrusted_rpms,
                    )
                write_target_marker(project_dir, arch)
                write_manifest(project_dir, generated_candidate_paths(project_dir))
                copied = copy_rpms(project_dir, release, arch, args.debug, artifacts_dir)
                verify_expected_rpms(copied, args.debug)
                record.update(
                    status="success",
                    duration_seconds=round(time.monotonic() - build_started, 3),
                    rpms=copied,
                )
                all_copied_rpms.extend(copied)
                log(
                    f"Copied {len(copied)} RPM(s) for {arch} to "
                    f"{variant_destination_dir(artifacts_dir, release, arch, args.debug)}"
                )
            except BaseException as error:
                failure_class = classify_failure(error, build_log_path(project_dir))
                try:
                    record["dependency_diagnostics"] = diagnose_missing_dependencies(
                        project_dir, release, arch,
                        local_sdk=local_sdk_path if isinstance(build, LocalSdkBuild) else None,
                        target=local_sdk_build_target(build.target, build.snapshot or build.target)
                        if isinstance(build, LocalSdkBuild) else None,
                    )
                except Exception as diagnostic_error:
                    record["dependency_diagnostics"] = [{"error": str(diagnostic_error)[:500]}]
                message = concise_error(error)
                record.update(
                    status="failed",
                    duration_seconds=round(time.monotonic() - build_started, 3),
                    failure_class=failure_class,
                    failure_message=message,
                )
                write_build_metadata(
                    project_dir,
                    context=context,
                    builds=build_records,
                    debug_build=args.debug,
                    artifacts_dir=artifacts_dir,
                    status="failed",
                    started_at=started_at,
                    failure_class=failure_class,
                    failure_message=message,
                )
                raise

        write_build_metadata(
            project_dir,
            context=context,
            builds=build_records,
            debug_build=args.debug,
            artifacts_dir=artifacts_dir,
            status="success",
            started_at=started_at,
        )

    if not args.quiet:
        print("Built RPMs:")
    for rpm in all_copied_rpms:
        print(rpm)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except subprocess.CalledProcessError as error:
        log(f"Build failed: {concise_error(error)}", force=True)
        sys.exit(error.returncode or 1)
    except OSError as error:
        log(f"Build failed: {concise_error(error)}", force=True)
        sys.exit(1)
