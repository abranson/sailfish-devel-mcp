#!/usr/bin/env python3

import argparse
import hashlib
import json
import subprocess
import importlib.util
import os
from pathlib import Path
import shutil
import tempfile


DESTINATION = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "sailfish_devel_mcp"
    / "vendor"
    / "build_sailfishos.py"
)


def helper_version(path: Path) -> str:
    spec = importlib.util.spec_from_file_location("candidate_build_sailfishos", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load helper: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    version = getattr(module, "HELPER_VERSION", None)
    if not isinstance(version, str) or not version:
        raise RuntimeError(f"helper has no HELPER_VERSION: {path}")
    required = (
        "parse_args",
        "resolve_project_dir",
        "sdk_refresh_target",
        "sdk_refresh_command",
        "doctor",
    )
    if any(not callable(getattr(module, name, None)) for name in required):
        raise RuntimeError("helper lacks the required build/SDK interface")
    module.parse_args(["--backend", "local", "--target", "aarch64", "--snapshot-key", "compatibility",
                       "--no-vcs-apply", "--quiet", "--dry-run", "--json"])
    return version


def main() -> int:
    parser = argparse.ArgumentParser(description="Update the vendored build-sailfishos helper")
    parser.add_argument("source", type=Path, help="Canonical build_sailfishos.py")
    parser.add_argument("--check", action="store_true", help="Verify source, vendor and manifest without changing files")
    args = parser.parse_args()

    source = args.source.expanduser().resolve()
    if not source.is_file():
        parser.error(f"source helper not found: {source}")
    version = helper_version(source)
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    manifest_path = DESTINATION.with_name("build-helper.json")
    if args.check:
        manifest = json.loads(manifest_path.read_text())
        if (source.read_bytes() != DESTINATION.read_bytes() or manifest.get("sha256") != digest
                or manifest.get("helper_version") != version):
            parser.error("vendored helper or provenance differs from canonical source")
        print(f"helper {version}: source, vendor and provenance match")
        return 0
    # The exact content hash identifies uncommitted sources too.
    revision = subprocess.run(["git", "-C", str(source.parent), "rev-parse", "HEAD"],
                              capture_output=True, text=True)
    dirty = subprocess.run(["git", "-C", str(source.parent), "status", "--porcelain", "--", str(source)],
                           capture_output=True, text=True)
    manifest = {"helper_version": version, "sha256": digest,
                "source": "build-sailfishos-skill/scripts/build_sailfishos.py",
                "source_revision": revision.stdout.strip() if revision.returncode == 0 else None,
                "source_dirty": bool(dirty.stdout.strip()) if dirty.returncode == 0 else None}
    compile(source.read_text(), str(source), "exec")

    DESTINATION.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{DESTINATION.name}.",
        suffix=".tmp",
        dir=DESTINATION.parent,
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        shutil.copyfile(source, temporary)
        temporary.chmod(0o755 if source.stat().st_mode & 0o111 else 0o644)
        os.replace(temporary, DESTINATION)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    manifest_tmp = manifest_path.with_suffix(".tmp")
    manifest_tmp.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    os.replace(manifest_tmp, manifest_path)
    print(f"vendored build helper {version}: {DESTINATION}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
