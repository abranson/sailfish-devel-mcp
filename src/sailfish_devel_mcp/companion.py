"""Standalone device companion. Keep compatible with Python 3.6+ and stdlib only."""
import argparse
import collections
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
import pwd
import re
import shutil
import signal
import socket
import socketserver
import subprocess
import sys
import threading
import time
import uuid

VERSION = '0.3.0'
IDLE_TIMEOUT = 60 * 60
CAPTURE_TIMEOUT = 60 * 60
UNIT = 'sailfish-devel-companion.service'
LEGACY_MARKER = 'sailfish-devel-companion-v1\n'
MARKER = 'sailfish-devel-companion-root-v2\n'
MAX_LINE = 4096
MAX_REQUEST = 256 * 1024


def schema(properties, required=()):
    return dict(type='object', properties=properties, required=list(required), additionalProperties=False)


STRING = {'type': 'string'}
TOOLS = {
    'status': ('Inspect companion identity, capture state and available executables.', schema({})),
    'capture_start': ('Start one bounded journal or D-Bus capture; rejects an existing capture.', schema({
        'source': {'type': 'string', 'enum': ['journal', 'dbus']},
        'unit': STRING, 'interface': STRING,
        'scope': {'type': 'string', 'enum': ['user', 'system']},
        'bus': {'type': 'string', 'enum': ['session', 'system']},
    }, ['source'])),
    'capture_stop': ('Stop capture; retain its bounded in-memory history.', schema({})),
    'events': ('Read captured lines by cursor; wait locally up to ten seconds for new lines.', schema({
        'after': {'type': 'integer', 'minimum': 0},
        'instance': STRING,
        'limit': {'type': 'integer', 'minimum': 1, 'maximum': 100},
        'wait_seconds': {'type': 'integer', 'minimum': 0, 'maximum': 10},
    })),
    'wait_service': ('Wait locally for a system or user unit to reach an ActiveState.', schema({
        'unit': STRING, 'state': {'type': 'string', 'enum': ['active', 'inactive', 'failed']},
        'scope': {'type': 'string', 'enum': ['user', 'system']},
        'wait_seconds': {'type': 'integer', 'minimum': 0, 'maximum': 10},
    }, ['unit', 'state'])),
}


def validate(name, args):
    if name not in TOOLS or not isinstance(args, dict):
        raise ValueError('unknown companion tool or invalid arguments')
    spec = TOOLS[name][1]
    if set(args) - set(spec['properties']) or set(spec['required']) - set(args):
        raise ValueError('unexpected or missing arguments')
    for key, value in args.items():
        prop = spec['properties'][key]
        if prop['type'] == 'integer':
            if type(value) is not int or not prop['minimum'] <= value <= prop.get('maximum', 2**63 - 1):
                raise ValueError('invalid ' + key)
        elif not isinstance(value, str) or not value or len(value) > 256:
            raise ValueError('invalid ' + key)
        if 'enum' in prop and value not in prop['enum']:
            raise ValueError('invalid ' + key)
    if 'unit' in args and not re.match(r'^[A-Za-z0-9_][A-Za-z0-9_.@:-]*\.(service|socket|target)$', args['unit']):
        raise ValueError('invalid unit name')
    if 'interface' in args and not re.match(r'^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+$', args['interface']):
        raise ValueError('invalid D-Bus interface')


def paths():
    return ('/opt/sailfish-devel-companion',
            '/etc/systemd/system/' + UNIT, '/run/sailfish-devel-companion')


def private_dir(path):
    os.makedirs(path, mode=0o700, exist_ok=True)
    info = os.lstat(path)
    if os.path.islink(path) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError('directory must be private, owned by the session user and not a symlink: ' + path)


def command(argv, timeout=2):
    result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            stdin=subprocess.DEVNULL, universal_newlines=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or 'command failed: ' + argv[0])
    return result.stdout.strip()


class Capture:
    def __init__(self):
        self.instance = uuid.uuid4().hex
        self.condition = threading.Condition()
        self.lines = collections.deque(maxlen=512)
        self.sequence = 0
        self.process = None
        self.reader = None
        self.source = None
        self.started_at = None
        self.expired = False

    def record(self, source, text):
        with self.condition:
            self.sequence += 1
            self.lines.append(dict(sequence=self.sequence, time=time.time(), source=source, text=text[:MAX_LINE]))
            self.condition.notify_all()

    def stop(self):
        if self.process is not None:
            if self.process.poll() is None:
                try:
                    os.killpg(self.process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    self.process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(self.process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    self.process.wait()
            self.reader.join(timeout=1)
        return self.status()

    def status(self):
        return dict(version=VERSION, api_version=API_VERSION, capabilities=['execute', 'workflow', 'job_start', 'job_status', 'job_cancel'],
                    session_user=SESSION.get('username'), instance=self.instance, uid=os.getuid(),
                    idle_timeout_seconds=IDLE_TIMEOUT, capture_timeout_seconds=CAPTURE_TIMEOUT,
                    capture_expired=self.expired, capture_source=self.source,
                    capturing=self.process is not None and self.process.poll() is None,
                    capture_exit_code=self.process.poll() if self.process else None,
                    latest=self.sequence, capacity=512,
                    tools={name: bool(shutil.which(name)) for name in ('journalctl', 'dbus-monitor', 'systemctl')})

    def start(self, args):
        if self.process and self.process.poll() is None:
            raise ValueError('capture already running; stop it explicitly first')
        if self.reader:
            self.reader.join(timeout=1)
        source = args['source']
        if source == 'journal':
            if not args.get('unit') or 'interface' in args or 'bus' in args:
                raise ValueError('journal capture requires unit, without interface or bus')
            argv = ['journalctl', '--follow', '--lines=0', '--no-pager', '--output=json']
            if args.get('scope', 'user') == 'user':
                uid = pwd.getpwnam(SESSION['username']).pw_uid
                argv += ['_SYSTEMD_USER_UNIT=' + args['unit'], '_UID=' + str(uid)]
            else:
                argv += ['--unit=' + args['unit']]

        else:
            if not args.get('interface') or 'unit' in args or 'scope' in args:
                raise ValueError('D-Bus capture requires interface, without unit')
            argv = ['dbus-monitor', '--' + args.get('bus', 'session'),
                    "type='signal',interface='" + args['interface'] + "'"]
            if args.get('bus', 'session') == 'session':
                argv = session_argv(argv)
        self.process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, start_new_session=True)
        self.source = source
        self.started_at = time.monotonic()
        self.expired = False
        process = self.process

        def read():
            try:
                while True:
                    line = process.stdout.readline(MAX_LINE)
                    if not line:
                        break
                    self.record(source, line.decode('utf-8', 'replace').rstrip())
                process.wait()
                self.record('capture', 'exited with status ' + str(process.returncode))
            finally:
                process.stdout.close()

        self.reader = threading.Thread(target=read)
        self.reader.daemon = True
        self.reader.start()
        return self.status()

    def expire(self, timeout=CAPTURE_TIMEOUT):
        with CAPTURE_LOCK:
            if (self.started_at is not None and self.process is not None
                    and self.process.poll() is None
                    and time.monotonic() - self.started_at >= timeout):
                self.stop()
                self.expired = True
                self.record('capture', 'capture expired after ' + str(timeout) + ' seconds')

    def events(self, args):
        after = args.get('after', 0)
        reset = args.get('instance', self.instance) != self.instance
        if reset:
            after = 0
        deadline = time.monotonic() + args.get('wait_seconds', 0)
        with self.condition:
            while self.sequence <= after and time.monotonic() < deadline:
                self.condition.wait(deadline - time.monotonic())
            first = self.lines[0]['sequence'] if self.lines else self.sequence + 1
            lines = []
            characters = 0
            for item in self.lines:
                if item['sequence'] <= after:
                    continue
                if len(lines) >= args.get('limit', 50) or characters + len(item['text']) > 65536:
                    break
                lines.append(item)
                characters += len(item['text'])
            return dict(instance=self.instance, reset=reset, dropped=after < first - 1,
                        events=lines, next_after=lines[-1]['sequence'] if lines else after,
                        latest=self.sequence)

    def call(self, name, args):
        validate(name, args)
        if name == 'status':
            return self.status()
        if name == 'capture_start':
            with CAPTURE_LOCK:
                return self.start(args)
        if name == 'capture_stop':
            with CAPTURE_LOCK:
                return self.stop()
        if name == 'events':
            return self.events(args)
        deadline = time.monotonic() + args.get('wait_seconds', 10)
        argv = ['systemctl'] + (['--user'] if args.get('scope', 'user') == 'user' else [])
        if args.get('scope', 'user') == 'user':
            argv = session_argv(argv)
        while True:
            output = command(argv + ['show', args['unit'], '--property=ActiveState', '--property=LoadState'])
            values = dict(line.split('=', 1) for line in output.splitlines() if '=' in line)
            if values.get('LoadState') == 'not-found':
                raise ValueError('unit not found')
            state = values.get('ActiveState')
            matched = state == args['state']
            if matched or time.monotonic() >= deadline:
                return dict(unit=args['unit'], state=state, matched=matched, timed_out=not matched)
            time.sleep(min(0.2, max(0, deadline - time.monotonic())))


def ensure_running():
    # Only the pre-execution connection probe may start a recognized installation.
    # Explicit management stop persists across host calls and device reboots.
    root, unit, _ = paths()
    with control_lock():
        if not managed(root, unit) or os.path.lexists(os.path.join(root, 'paused')):
            return False
        try:
            request('status', {})
            return True
        except (FileNotFoundError, ConnectionRefusedError):
            pass
        try:
            command(['systemctl', 'start', UNIT], timeout=4)
        except (OSError, subprocess.TimeoutExpired, RuntimeError):
            return False
        deadline = time.monotonic() + 3
        while True:
            try:
                request('status', {})
                return True
            except (FileNotFoundError, ConnectionRefusedError):
                if time.monotonic() >= deadline:
                    return False
                time.sleep(0.1)


def request(name, args, internal=False, start=False):
    if not internal:
        validate(name, args)
    _, _, runtime = paths()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(min(86410, args.get('timeout', args.get('wait_seconds', 10)) + 5))
        try:
            sock.connect(os.path.join(runtime, 'socket'))
        except (FileNotFoundError, ConnectionRefusedError):
            if not start or not ensure_running():
                raise
            sock.connect(os.path.join(runtime, 'socket'))
        sock.sendall((json.dumps(dict(name=name, arguments=args, internal=internal)) + '\n').encode('utf-8'))
        with sock.makefile('rb') as stream:
            raw = stream.readline(32 * 1024 * 1024)
        result = json.loads(raw.decode('utf-8'))
        if 'error' in result:
            raise RuntimeError(result['error'])
        return result['result']


class IdleLifetime:
    def __init__(self, timeout):
        self.timeout = timeout
        self.lock = threading.Lock()
        self.active = 0
        self.last_activity = time.monotonic()

    def begin(self):
        with self.lock:
            self.active += 1

    def finish(self):
        with self.lock:
            self.active -= 1
            self.last_activity = time.monotonic()

    def expired(self, jobs_running=False):
        with self.lock:
            if self.active or jobs_running:
                self.last_activity = time.monotonic()
                return False
            return time.monotonic() - self.last_activity >= self.timeout


def serve(idle_timeout=IDLE_TIMEOUT, capture_timeout=CAPTURE_TIMEOUT):
    _, _, runtime = paths()
    private_dir(runtime)
    lock = open(os.path.join(runtime, 'lock'), 'a')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    address = os.path.join(runtime, 'socket')
    if os.path.lexists(address):
        os.unlink(address)
    capture = Capture()
    lifetime = IdleLifetime(idle_timeout)

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            self.connection.settimeout(2)
            try:
                raw = self.rfile.readline(MAX_REQUEST + 1)
                if len(raw) > MAX_REQUEST or not raw.endswith(b'\n'):
                    raise ValueError('invalid request size')
                message = json.loads(raw.decode('utf-8'))
                if message.get('internal'):
                    result = dict(result=internal_call(message['name'], message.get('arguments', {})))
                else:
                    result = dict(result=capture.call(message['name'], message.get('arguments', {})))
            except Exception as exc:
                result = dict(error=str(exc))
            self.wfile.write((json.dumps(result) + '\n').encode('utf-8'))

    class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
        daemon_threads = True
        slots = threading.BoundedSemaphore(8)

        def process_request(self, request, address):
            if not self.slots.acquire(False):
                request.close()
                return
            lifetime.begin()
            super().process_request(request, address)

        def process_request_thread(self, request, address):
            try:
                super().process_request_thread(request, address)
            finally:
                lifetime.finish()
                self.slots.release()

    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    try:
        with Server(address, Handler) as server:
            os.chmod(address, 0o600)
            server.timeout = min(1, idle_timeout)
            while True:
                server.handle_request()
                capture.expire(capture_timeout)
                # Job submission and lifecycle operations share this lock. Never
                # exit between accepting a job and recording its supervisor.
                with control_lock():
                    if lifetime.expired(bool(active_jobs())):
                        break
    finally:
        capture.stop()
        if os.path.exists(address):
            os.unlink(address)
        lock.close()


def stdio():
    for raw in sys.stdin:
        message = None
        try:
            if len(raw) > MAX_REQUEST:
                raise ValueError('request too large')
            message = json.loads(raw)
            if not isinstance(message, dict) or message.get('jsonrpc') != '2.0':
                raise ValueError('invalid JSON-RPC request')
            if 'id' not in message:
                continue
            method = message.get('method')
            params = message.get('params') or {}
            if method == 'initialize':
                versions = ['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05']
                version = params.get('protocolVersion')
                result = dict(protocolVersion=version if version in versions else versions[0],
                              capabilities={'tools': {}}, serverInfo=dict(name='sailfish-device-companion', version=VERSION),
                              instructions='Capture is opt-in and bounded. Save instance and cursor when retrieving events. History is lost on service restart.')
            elif method == 'ping':
                result = {}
            elif method == 'tools/list':
                result = dict(tools=[dict(name=name, description=item[0], inputSchema=item[1],
                                         annotations={'readOnlyHint': name in ('status', 'events', 'wait_service')})
                                    for name, item in sorted(TOOLS.items())])
            elif method == 'tools/call':
                try:
                    data = request(params['name'], params.get('arguments', {}),
                                   start=params['name'] == 'capture_start')
                    result = dict(content=[dict(type='text', text=json.dumps(data))], structuredContent=data, isError=False)
                except Exception as exc:
                    result = dict(content=[dict(type='text', text=str(exc))], isError=True)
            else:
                raise ValueError('unsupported method')
            reply = dict(jsonrpc='2.0', id=message['id'], result=result)
        except Exception as exc:
            reply = dict(jsonrpc='2.0', id=message.get('id') if isinstance(message, dict) else None,
                         error=dict(code=-32600, message=str(exc)))
        print(json.dumps(reply), flush=True)


def unit_text(root):
    executable = os.path.join(root, 'agent.py').replace('%', '%%').replace('\\', '\\\\').replace('"', '\\"')
    if any(c in executable for c in '\n\r\0'):
        raise ValueError('invalid service path')
    return ('# ' + MARKER + '[Unit]\nDescription=Sailfish development companion (root)\n'
            '[Service]\nType=simple\nUser=root\nExecStart=/usr/bin/python3 "' + executable + '" --serve\n'
            'UMask=0077\nRestart=on-failure\nRestartSec=2\nKillMode=control-group\nTimeoutStopSec=5\n')


def managed(root, unit):
    marker = os.path.join(root, 'owner')
    if not os.path.lexists(root) and not os.path.lexists(unit):
        return False
    if not os.path.isdir(root) or os.path.islink(root):
        raise ValueError('unrecognized installation directory')
    info = os.stat(root)
    if info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError('installation directory must be private and owned by root')
    for path in (marker, os.path.join(root, 'agent.py'), os.path.join(root, 'session.json'), unit):
        if os.path.islink(path) or not os.path.isfile(path) or os.stat(path).st_uid != os.getuid() or os.stat(path).st_mode & 0o022:
            raise ValueError('unrecognized installation; refusing to modify ' + path)
    with open(marker) as stream:
        if stream.read() != MARKER:
            raise ValueError('unrecognized ownership marker')
    with open(unit) as stream:
        if not stream.read().startswith('# ' + MARKER):
            raise ValueError('unrecognized service unit')
    return True


def atomic_write(path, content):
    temporary = path + '.' + uuid.uuid4().hex
    try:
        with open(temporary, 'x') as stream:
            os.chmod(temporary, 0o600)
            stream.write(content)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def resume_on_demand(root):
    path = os.path.join(root, 'paused')
    if os.path.lexists(path):
        os.unlink(path)


def require_root():
    if os.getuid() != 0:
        raise ValueError("root SSH login is required for companion management")


@contextmanager
def control_lock():
    path = paths()[2] + '.control'
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError('unsafe companion control lock')
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def manage(action, source=None, confirm_initial_install=False, session=None):
    global SESSION
    require_root()
    if session is not None:
        SESSION = session_config(session)
    if action == 'status':
        return _manage(action, source, confirm_initial_install)
    root, unit, _ = paths()
    # Keep an unapproved first-install attempt entirely read-only.
    if action == 'deploy' and not managed(root, unit) and not legacy_installed() and not confirm_initial_install:
        return _manage(action, source, confirm_initial_install)
    with control_lock():
        return _manage(action, source, confirm_initial_install)


def _manage(action, source=None, confirm_initial_install=False, session=None):
    global SESSION
    require_root()
    if session is not None:
        SESSION = session_config(session)
    root, unit, runtime = paths()
    installed = managed(root, unit)
    if action == 'status':
        result = dict(installed=installed, on_demand=installed and not os.path.lexists(os.path.join(root, 'paused')))
        if installed:
            with open(os.path.join(root, 'agent.py'), 'rb') as stream:
                result['sha256'] = hashlib.sha256(stream.read()).hexdigest()
            try:
                result.update(request('status', {}))
                result['running'] = True
            except (OSError, RuntimeError) as exc:
                result.update(running=False, detail=str(exc))
        return result
    if action == 'deploy':
        legacy = legacy_installed()
        if not installed and not legacy and confirm_initial_install is not True:
            raise ValueError('Development/test devices only: do not install on personal or primary phones containing real accounts or sensitive data. Captures may expose private application/account data to the host MCP client and model context. First installation requires explicit user permission for this device; present this warning and retry with confirm_initial_install=true only after approval')
        if not source:
            raise ValueError('missing companion source')
        compile(source, 'agent.py', 'exec')
        if active_jobs():
            raise ValueError('active companion jobs must finish or be cancelled before deployment')
        command(['systemctl', 'show-environment'])
        private_dir(root)
        os.makedirs(os.path.dirname(unit), mode=0o700, exist_ok=True)
        resume_on_demand(root)
        atomic_write(os.path.join(root, 'agent.py'), source)
        atomic_write(os.path.join(root, 'owner'), MARKER)
        atomic_write(os.path.join(root, 'session.json'), json.dumps(SESSION))
        atomic_write(unit, unit_text(root))
        command(['systemctl', 'daemon-reload'])
        command(['systemctl', 'restart', UNIT], timeout=4)
        deadline = time.monotonic() + 3
        while True:
            try:
                status = request('status', {})
                break
            except (OSError, RuntimeError):
                if time.monotonic() >= deadline:
                    raise RuntimeError('installed but service readiness failed; inspect system journal')
                time.sleep(0.1)
        if legacy:
            retire_legacy()
        return dict(installed=True, updated=installed or legacy, migrated=legacy, sha256=hashlib.sha256(source.encode('utf-8')).hexdigest(), status=status)
    if action not in ('start', 'stop', 'remove'):
        raise ValueError('unknown management action')
    if not installed:
        raise ValueError('companion is not installed')
    if action in ('stop', 'remove') and active_jobs():
        raise ValueError('active companion jobs must finish or be cancelled before stopping/removing')
    if action == 'remove':
        command(['systemctl', 'stop', UNIT], timeout=4)
        resume_on_demand(root)
        for path in (unit, os.path.join(root, 'agent.py'), os.path.join(root, 'owner'), os.path.join(root, 'session.json')):
            os.unlink(path)
        # Never recursively delete: unexpected files are retained.
        try:
            os.rmdir(root)
        except OSError:
            pass
        command(['systemctl', 'daemon-reload'])
        if os.path.isdir(runtime) and not os.path.islink(runtime):
            info = os.stat(runtime)
            if info.st_uid == os.getuid() and not info.st_mode & 0o077:
                for name in ('socket', 'lock'):
                    path = os.path.join(runtime, name)
                    if os.path.lexists(path):
                        os.unlink(path)
                try:
                    os.rmdir(runtime)
                except OSError:
                    pass
        return dict(installed=False)
    if action == 'stop':
        atomic_write(os.path.join(root, 'paused'), 'explicit stop\n')
    elif action == 'start':
        resume_on_demand(root)
    command(['systemctl', action, UNIT], timeout=4)
    return dict(installed=True, action=action)


# Internal RPC operations are reachable only through the root-owned Unix socket.
# Keep the public MCP surface small; existing host tools supply validated commands.
API_VERSION = 2
SESSION = {}
OPERATION_LOCK = threading.RLock()
CAPTURE_LOCK = threading.RLock()
TERMINAL = ('finished', 'failed', 'timed_out', 'cancelled')
MAX_OUTPUT = 2 * 1024 * 1024


def session_config(value):
    if not isinstance(value, dict) or set(value) != {'username', 'runtime', 'bus'}:
        raise ValueError('invalid session configuration')
    user = pwd.getpwnam(value['username'])
    if user.pw_uid == 0:
        raise ValueError('the graphical session user must not be root')
    if value['runtime'] != '/run/user/' + str(user.pw_uid):
        raise ValueError('session runtime does not match the configured user')
    if not value['bus'].startswith('unix:path=' + value['runtime'] + '/') or any(c in value['bus'] for c in '\n\r\0'):
        raise ValueError('session bus must be a socket in the configured runtime directory')
    return dict(value)


def session_argv(argv, group=None):
    if not SESSION:
        raise ValueError('no graphical session configured')
    user = pwd.getpwnam(SESSION['username'])
    env = ['env', 'HOME=' + user.pw_dir, 'USER=' + user.pw_name,
           'LOGNAME=' + user.pw_name, 'XDG_RUNTIME_DIR=' + SESSION['runtime'],
           'DBUS_SESSION_BUS_ADDRESS=' + SESSION['bus']]
    if group not in (None, 'privileged'):
        raise ValueError('unsupported session group')
    if os.getuid() == user.pw_uid and group is None:
        return env + argv
    prefix = ['runuser', '-u', user.pw_name]
    if group:
        prefix += ['-g', group]
    return prefix + ['--'] + env + argv


def group_alive(pgid):
    for entry in os.listdir('/proc'):
        if not entry.isdigit():
            continue
        try:
            with open('/proc/' + entry + '/stat') as stream:
                raw = stream.read()
            fields = raw[raw.rfind(') ') + 2:].split()
            if int(fields[2]) == pgid and fields[0] not in ('Z', 'X'):
                return True
        except (OSError, ValueError, IndexError):
            continue
    return False


def stop_group(process):
    # The leader may exit before its children. Always consider the whole group.
    for sig, grace in ((signal.SIGTERM, 1), (signal.SIGKILL, 2)):
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            break
        end = time.monotonic() + grace
        while group_alive(process.pid) and time.monotonic() < end:
            process.poll()
            time.sleep(0.02)
        if not group_alive(process.pid):
            break
    process.wait(timeout=2)
    if group_alive(process.pid):
        raise RuntimeError('process group still alive after SIGKILL')


def execution_args(args):
    argv = args.get('argv')
    timeout = args.get('timeout', 15)
    if (not isinstance(argv, list) or not argv or len(argv) > 1024 or
            not all(isinstance(v, str) and '\0' not in v for v in argv) or
            sum(len(v) for v in argv) > 180000):
        raise ValueError('invalid command argv')
    if type(timeout) is not int or not 1 <= timeout <= 86400:
        raise ValueError('invalid command timeout')
    if type(args.get('user', False)) is not bool:
        raise ValueError('invalid command user flag')
    if args.get('user'):
        argv = session_argv(argv, args.get('group'))
    elif args.get('group'):
        raise ValueError('group requires a session-user command')
    if not args.get('user') and SESSION:
        argv = ['env', 'XDG_RUNTIME_DIR=' + SESSION['runtime'], 'DBUS_SESSION_BUS_ADDRESS=' + SESSION['bus']] + argv
    return argv, timeout


def execute(args):
    argv, timeout = execution_args(args)
    outputs = [bytearray(), bytearray()]
    counts = [0, 0]
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, start_new_session=True)
    def drain(stream, index):
        try:
            while True:
                data = stream.read1(8192)
                if not data:
                    break
                counts[index] += len(data)
                room = MAX_OUTPUT - len(outputs[index])
                outputs[index].extend(data[:max(0, room)])
        finally:
            stream.close()
    threads = [threading.Thread(target=drain, args=(stream, index))
               for index, stream in enumerate((process.stdout, process.stderr))]
    for thread in threads:
        thread.daemon = True
        thread.start()
    timed_out = False
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        stop_group(process)
    # Some launchers intentionally leave daemonized children. Do not terminate
    # successful commands' detached apps; bound readers if a child kept a pipe.
    for thread in threads:
        thread.join(timeout=0.2)
    if any(thread.is_alive() for thread in threads):
        stop_group(process)
        for thread in threads:
            thread.join(timeout=1)
    result = dict(returncode=124 if timed_out else process.returncode,
                  stdout=outputs[0].decode('utf-8', 'replace'),
                  stderr=outputs[1].decode('utf-8', 'replace'), backend='companion')
    if timed_out:
        result['stderr'] += '\ncommand timed out after ' + str(timeout) + 's'
    if any(count > MAX_OUTPUT for count in counts):
        result['stderr'] += '\n[companion output truncated at 2 MiB per stream]'
    transform = args.get('filter', {})
    if transform:
        lines = result['stdout'].splitlines()
        if transform.get('contains'):
            lines = [line for line in lines if transform['contains'] in line]
        result['matched_lines'] = len(lines)
        maximum = transform.get('max_lines', len(lines))
        result['stdout'] = '\n'.join(lines[:maximum])
        if len(lines) > maximum:
            result['stdout'] += '\n[truncated after ' + str(maximum) + ' lines]'
    return result


def execute_operation(args):
    with OPERATION_LOCK:
        result = execute(args)
        if args.get('service'):
            service = args['service']
            unit = service['unit']
            argv = ['systemctl'] + (['--user'] if service['mode'] == 'user' else [])
            query = dict(argv=argv + ['show', unit, '--property=ActiveState', '--property=SubState', '--property=Result'],
                         timeout=3, user=service['mode'] == 'user')
            status = execute(query)
            result['service_state'] = dict(line.split('=', 1) for line in status['stdout'].splitlines() if '=' in line)
            if result['returncode']:
                match = ['_SYSTEMD_USER_UNIT=' + unit, '_UID=' + str(pwd.getpwnam(SESSION['username']).pw_uid)] if service['mode'] == 'user' else ['-u', unit]
                logs = execute(dict(argv=['journalctl', '--no-pager', '-n', '20', '--since=-2min'] + match, timeout=3))
                result['stderr'] += '\n' + logs['stdout'][-6000:]
        if args.get('foreground') and result['returncode'] == 0:
            result.update(foreground(args['foreground'], args.get('foreground_wait', 0)))
        return result


def foreground(desktop, seconds):
    expected = None
    try:
        import configparser
        import shlex
        config = configparser.ConfigParser(interpolation=None)
        config.read(desktop)
        tokens = shlex.split(config.get('Desktop Entry', 'Exec', fallback=''))
        # Only assert a match for simple Exec entries. Invoker/env wrappers and
        # activated D-Bus services cannot reliably be identified from gio's PID.
        if tokens and os.path.basename(tokens[0]) not in ('env', 'invoker'):
            expected = os.path.basename(tokens[0])
        elif tokens and os.path.basename(tokens[0]) == 'invoker':
            expected = next((os.path.basename(token) for token in tokens[1:] if token.startswith('/')), None)
    except (OSError, ValueError, configparser.Error):
        pass
    deadline = time.monotonic() + min(seconds, 5)
    while True:
        result = execute(dict(argv=['dbus-send', '--session', '--print-reply', '--dest=org.nemomobile.lipstick', '/',
                              'org.nemomobile.compositor.privateTopmostWindowProcessId'], user=True, timeout=2))
        match = re.search(r'(?:u?int32|u?int64)\s+(\d+)', result['stdout'])
        pid = int(match.group(1)) if match else None
        verified = False
        if pid and expected:
            try:
                verified = os.path.basename(os.readlink('/proc/' + str(pid) + '/exe')) == expected
            except OSError:
                pass
        if verified or time.monotonic() >= deadline or not expected:
            return dict(foreground_pid=pid, foreground_verified=verified,
                        foreground_expected=expected)
        time.sleep(0.1)


def workflow(args):
    steps = args.get('steps')
    if not isinstance(steps, list) or not 1 <= len(steps) <= 12:
        raise ValueError('invalid workflow steps')
    # Validate every command before performing any side effect.
    for step in steps:
        execution_args(step)
    with OPERATION_LOCK:
        result = []
        for step in steps:
            value = execute(step)
            value['name'] = step['name']
            result.append(value)
            if value['returncode']:
                break
        return dict(steps=result, backend='companion')


def jobs_root():
    return '/var/lib/sailfish-devel-companion/jobs'


def job_path(job_id):
    if not isinstance(job_id, str) or not re.fullmatch(r'device-[A-Za-z0-9-]{1,100}', job_id):
        raise ValueError('invalid companion job id')
    return os.path.join(jobs_root(), job_id)


def read_json(path):
    with open(path) as stream:
        return json.load(stream)


def write_json(path, data):
    atomic_write(path, json.dumps(data, sort_keys=True))


def process_identity(pid):
    try:
        with open('/proc/' + str(pid) + '/stat') as stream:
            raw = stream.read()
        fields = raw[raw.rfind(') ') + 2:].split()
        if fields[0] in ('Z', 'X'):
            return None
        with open('/proc/sys/kernel/random/boot_id') as stream:
            boot = stream.read().strip()
        return boot + ':' + fields[19]
    except (OSError, IndexError):
        return None


def job_state(job_id):
    directory = job_path(job_id)
    status = read_json(os.path.join(directory, 'status.json'))
    if status['state'] not in TERMINAL:
        pid = status.get('supervisor_pid')
        if pid and process_identity(pid) != status.get('supervisor_identity'):
            status.update(state='failed', failure_class='supervisor-lost',
                          failure_message='device supervisor exited or device rebooted', returncode=None)
            write_json(os.path.join(directory, 'status.json'), status)
    return status


def job_start(args):
    with control_lock():
        return _job_start(args)


def _job_start(args):
    execution_args(args)
    directory = job_path(args['job_id'])
    private_dir(jobs_root())
    with OPERATION_LOCK:
        if os.path.exists(directory):
            if read_json(os.path.join(directory, 'request.json')) != args:
                raise ValueError('job id already belongs to another request')
            return job_state(args['job_id'])
        private_dir(directory)
        write_json(os.path.join(directory, 'request.json'), args)
        status = dict(job_id=args['job_id'], state='starting', returncode=None,
                      backend='companion', created_at=time.time(),
                      remote_log_path=os.path.join(directory, 'command.log'),
                      remote_status_path=os.path.join(directory, 'status.json'))
        write_json(os.path.join(directory, 'status.json'), status)
        try:
            process = subprocess.Popen([sys.executable, os.path.join(paths()[0], 'agent.py'), '--job-worker', directory],
                                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL, start_new_session=True)
        except Exception as exc:
            status.update(state='failed', failure_class='spawn', failure_message=str(exc))
            write_json(os.path.join(directory, 'status.json'), status)
            raise
        # Worker waits for the parent receipt, avoiding a status write race.
        status.update(supervisor_pid=process.pid, supervisor_identity=process_identity(process.pid))
        write_json(os.path.join(directory, 'status.json'), status)
        threading.Thread(target=process.wait, daemon=True).start()
        return status


def job_worker(directory):
    args = read_json(os.path.join(directory, 'request.json'))
    status_path = os.path.join(directory, 'status.json')
    deadline = time.monotonic() + 3
    while True:
        status = read_json(status_path)
        if status.get('supervisor_pid') == os.getpid():
            break
        if time.monotonic() > deadline:
            raise RuntimeError('missing supervisor receipt')
        time.sleep(0.01)
    argv, timeout = execution_args(args)
    process = None
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    try:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        status.update(state='running', started_at=time.time(), command_pid=process.pid)
        write_json(status_path, status)
        log_info = {'bytes': 0, 'truncated': False}
        def drain():
            with open(os.path.join(directory, 'command.log'), 'wb') as log:
                while True:
                    data = process.stdout.read1(8192)
                    if not data:
                        break
                    log.write(data)
                    log.flush()
                    log_info['bytes'] += len(data)
            process.stdout.close()
        reader = threading.Thread(target=drain, daemon=True)
        reader.start()
        end = time.monotonic() + timeout
        state = 'finished'
        while process.poll() is None or group_alive(process.pid):
            if os.path.exists(os.path.join(directory, 'cancel.requested')):
                state = 'cancelled'; stop_group(process); break
            if time.monotonic() >= end:
                state = 'timed_out'; stop_group(process); break
            time.sleep(0.05)
        process.wait()
        reader.join(timeout=2)
        status.update(state=state, returncode=process.returncode, finished_at=time.time(),
                      log_truncated=log_info['truncated'])
        write_json(status_path, status)
    except BaseException as exc:
        if process is not None:
            stop_group(process)
        status.update(state='failed', failure_class='worker-interrupted', failure_message=str(exc))
        write_json(status_path, status)
        raise


def job_status(args):
    job_id = args['job_id']
    directory = job_path(job_id)
    wait = args.get('wait_seconds', 0)
    if type(wait) is not int or not 0 <= wait <= 15:
        raise ValueError('invalid job wait')
    deadline = time.monotonic() + wait
    status = job_state(job_id)
    while status['state'] not in TERMINAL and time.monotonic() < deadline:
        time.sleep(0.1)
        status = job_state(job_id)
    log_path = os.path.join(directory, 'command.log')
    output = ''
    if os.path.exists(log_path):
        with open(log_path, 'rb') as stream:
            size = os.fstat(stream.fileno()).st_size
            if 'log_offset' in args:
                offset, maximum = args['log_offset'], args.get('max_bytes', 6000)
                if type(offset) is not int or offset < 0 or type(maximum) is not int or not 1 <= maximum <= 12000:
                    raise ValueError('invalid log page')
                stream.seek(offset); data = stream.read(maximum)
                output = data.decode('utf-8', 'replace')
                status.update(next_offset=offset + len(data), eof=offset + len(data) >= size)
            else:
                lines = args.get('lines', 0)
                if type(lines) is not int or not 0 <= lines <= 1000:
                    raise ValueError('invalid log lines')
                if lines or status['state'] in ('failed', 'timed_out') or status.get('returncode') not in (None, 0):
                    stream.seek(max(0, size - 64000))
                    output = '\n'.join(stream.read().decode('utf-8', 'replace').splitlines()[-(lines or 80):])[-12000:]
    status.update(log_tail=output, log_included=bool(output), log_chars=len(output),
                  log_kind='page' if 'log_offset' in args else ('tail' if args.get('lines') else ('failure_excerpt' if output else 'none')))
    return status


def job_cancel(args):
    status = job_state(args['job_id'])
    if status['state'] not in TERMINAL:
        atomic_write(os.path.join(job_path(args['job_id']), 'cancel.requested'), 'cancel\n')
        status['cancel_requested'] = True
    return status


def active_jobs():
    root = jobs_root()
    if not os.path.isdir(root):
        return []
    return [name for name in os.listdir(root) if name.startswith('device-') and job_state(name)['state'] not in TERMINAL]


def internal_call(name, args):
    handlers = {'execute': execute_operation, 'workflow': workflow, 'job_start': job_start,
                'job_status': job_status, 'job_cancel': job_cancel}
    if name not in handlers or not isinstance(args, dict):
        raise ValueError('invalid internal operation')
    return handlers[name](args)

def legacy_paths():
    user = pwd.getpwnam(SESSION['username'])
    root = os.path.join(user.pw_dir, '.local/share/sailfish-devel-companion')
    return user, root, os.path.join(user.pw_dir, '.config/systemd/user', UNIT)


def legacy_installed():
    if not SESSION:
        return False
    user, root, unit = legacy_paths()
    if not os.path.exists(root) and not os.path.exists(unit):
        return False
    # Inspect metadata only. Never execute a user-owned script as root.
    for path in (root, os.path.join(root, 'owner'), os.path.join(root, 'agent.py'), unit):
        info = os.lstat(path)
        if os.path.islink(path) or info.st_uid != user.pw_uid:
            raise ValueError('unrecognized legacy companion; refusing migration')
    with open(os.path.join(root, 'owner')) as stream:
        if stream.read(100) != LEGACY_MARKER:
            raise ValueError('unrecognized legacy companion marker')
    with open(unit) as stream:
        if not stream.read(100).startswith('# ' + LEGACY_MARKER):
            raise ValueError('unrecognized legacy service unit')
    return True


def retire_legacy():
    user, root, unit = legacy_paths()
    command(session_argv(['systemctl', '--user', 'stop', UNIT]), timeout=4)
    cleanup = '''import os,sys
root,unit,runtime=sys.argv[1:]
for path in (unit,os.path.join(root,'agent.py'),os.path.join(root,'owner')):
    os.unlink(path)
for directory in (root,runtime):
    if directory==runtime:
        for name in ('socket','lock'):
            try: os.unlink(os.path.join(directory,name))
            except FileNotFoundError: pass
    try: os.rmdir(directory)
    except OSError: pass
'''
    command(session_argv(['python3', '-c', cleanup, root, unit,
                          os.path.join(SESSION['runtime'], 'sailfish-devel-companion')]), timeout=3)
    command(session_argv(['systemctl', '--user', 'daemon-reload']))


def dispatch(encoded):
    import base64
    message = json.loads(base64.b64decode(encoded).decode('utf-8'))
    if message.get('api_version') != API_VERSION:
        print(json.dumps(dict(companion_available=False)))
        return
    # Fall back only when the pre-execution probe proves the service unavailable.
    try:
        status = request('status', {}, start=True)
    except (FileNotFoundError, ConnectionRefusedError):
        print(json.dumps(dict(companion_available=False)))
        return
    if status.get('api_version') != API_VERSION or message['name'] not in status.get('capabilities', []):
        print(json.dumps(dict(companion_available=False)))
        return
    if message.get('session_user') != SESSION.get('username'):
        raise ValueError('host session user differs from the installed companion configuration')
    result = request(message['name'], message.get('arguments', {}), internal=True)
    print(json.dumps(dict(companion_available=True, result=result)))


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--serve', action='store_true')
    group.add_argument('--stdio', action='store_true')
    group.add_argument('--request')
    group.add_argument('--dispatch')
    group.add_argument('--job-worker')
    args = parser.parse_args()
    global SESSION
    settings = os.path.join(paths()[0], 'session.json')
    if os.path.isfile(settings):
        SESSION = session_config(read_json(settings))
    if args.serve:
        if os.getuid() != 0:
            raise ValueError('the system companion must run as root')
        serve()
    elif args.stdio:
        stdio()
    elif args.job_worker:
        job_worker(args.job_worker)
    elif args.dispatch:
        dispatch(args.dispatch)
    else:
        message = json.loads(args.request)
        print(json.dumps(request(message['name'], message.get('arguments', {}),
                                 start=message['name'] == 'capture_start')))


if __name__ == '__main__':
    main()
