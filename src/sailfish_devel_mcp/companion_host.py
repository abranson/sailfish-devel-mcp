"""Host bridge and deployment for the optional device companion."""
from __future__ import annotations

import base64
import gzip
import shlex
from dataclasses import asdict
from pathlib import Path
import json

from . import companion


AGENT_PATH = '/opt/sailfish-devel-companion/agent.py'


MANAGE_SCHEMA = companion.schema({
    'action': {'type': 'string', 'enum': ['status', 'start', 'stop', 'remove']},
}, ['action'])


def register(config):
    # Import here to keep tools.py's registry dependencies acyclic.
    from .tools import Tool, _device_prop, _mutating_annotations, _read_only_annotations
    result = []
    for name, (description, schema) in companion.TOOLS.items():
        schema = dict(schema, properties=dict(schema['properties'], device=_device_prop()))
        annotation = _read_only_annotations if name in ('status', 'events', 'wait_service') else _mutating_annotations
        result.append(Tool(dict(name='sailfish_device_companion_' + name,
                                description=description, inputSchema=schema,
                                annotations=annotation('Device companion ' + name)),
                           lambda args, name=name: invoke(config, name, args)))
    result.append(Tool(dict(name='sailfish_device_companion_manage',
                           description='Inspect, start, stop or remove an existing companion. Use sailfish_device_setup for installation and updates.',
                           inputSchema=dict(MANAGE_SCHEMA, properties=dict(MANAGE_SCHEMA['properties'], device=_device_prop())),
                           annotations=_mutating_annotations('Manage device companion', destructive=True)),
                       lambda args: invoke(config, 'manage', args)))
    return result


def invoke(config, name, args, *, allow_deploy=False):
    from .tools import _device, ok_text, tool_error
    from .runner import run
    args = dict(args)
    device = _device(config, args)
    args.pop('device', None)
    if name == 'manage':
        if set(args) - {'action', 'confirm_initial_install'}:
            raise ValueError('unexpected management arguments')
        allowed = MANAGE_SCHEMA['properties']['action']['enum'] + (['deploy'] if allow_deploy else [])
        if args.get('action') not in allowed:
            raise ValueError('invalid management action')
        if type(args.get('confirm_initial_install', False)) is not bool:
            raise ValueError('confirm_initial_install must be a boolean')
        source = Path(companion.__file__).read_text(encoding='utf-8')
        encoded = base64.b64encode(gzip.compress(source.encode('utf-8'))).decode('ascii')
        script = (
            'import base64,gzip,json,os,sys; os.umask(0o077); '
            'source=gzip.decompress(base64.b64decode(sys.argv[1])).decode("utf-8"); '
            'namespace={"__name__":"companion_bootstrap"}; '
            'exec(compile(source,"companion_bootstrap","exec"),namespace); '
            'args=json.loads(sys.argv[2]); '
            'print(json.dumps(namespace["manage"](args["action"],source,args.get("confirm_initial_install",False),json.loads(sys.argv[3]))))'
        )
        command = ['python3', '-c', script, encoded, json.dumps(args), json.dumps(device_session(device))]
    else:
        companion.validate(name, args)
        command = ['python3', '/opt/sailfish-devel-companion/agent.py', '--request',
                   json.dumps(dict(name=name, arguments=args))]
    from .runner import remote_command, ssh_argv
    result = run(ssh_argv(device, config.paths.ssh_config, remote_command(command)), timeout=15)
    if not result.ok:
        # Do not return bootstrap argv: it contains the entire uploaded source.
        return tool_error('companion operation failed', {
            'device': device.name, 'returncode': result.returncode,
            'stderr': result.stderr[-4000:], 'stdout': result.stdout[-4000:],
        })
    try:
        data = json.loads(result.stdout)
        if not isinstance(data, dict):
            raise ValueError('expected object')
    except (ValueError, TypeError):
        return tool_error('invalid companion response', {'stdout': result.stdout[-4000:]})
    data['device'] = device.name
    return ok_text(json.dumps(data, sort_keys=True), data)


def device_session(device):
    return dict(username=device.username, runtime=device.user_bus_runtime_dir,
                bus=device.user_bus_address)


def dispatch_command(device, name, args, fallback=None):
    from .runner import remote_command
    payload = dict(api_version=companion.API_VERSION, name=name, arguments=args,
                   session_user=device.username)
    encoded = base64.b64encode(json.dumps(payload).encode()).decode()
    path = AGENT_PATH
    bootstrap = (
        'import json,os,runpy,sys; ns=runpy.run_path(sys.argv[1]); '
        'compatible=ns.get("API_VERSION")==2; '
        'ns["SESSION"].update(ns["session_config"](ns["read_json"](os.path.join(os.path.dirname(sys.argv[1]),"session.json")))) if compatible else None; '
        'ns["dispatch"](sys.argv[2]) if compatible else print(json.dumps({"companion_available":False}))'
    )
    probe = remote_command(['python3', '-c', bootstrap, path, encoded])
    if fallback is None:
        absent = "printf '%s\\n' '{\"companion_available\":false}'"
        return 'if [ -r ' + shlex.quote(path) + ' ]; then ' + probe + '; else ' + absent + '; fi'
    # The Python bridge cannot choose a shell fallback after execution. Emit an
    # explicit unavailable receipt first, then let a shell dispatcher choose.
    # Use a temporary private response file so stdout is not interpreted as code.
    return remote_command(['sh', '-c', 'set -eu\nif [ ! -r "$1" ]; then exec sh -c "$3"; fi\nreply=$(mktemp)\ntrap \'rm -f "$reply"\' EXIT HUP INT TERM\nif sh -c "$2" >"$reply"; then\n    if [ "$(cat "$reply")" = \'{"companion_available": false}\' ]; then\n        rm -f "$reply"\n        trap - EXIT HUP INT TERM\n        exec sh -c "$3"\n    fi\n    cat "$reply"\nelse\n    code=$?\n    cat "$reply"\n    exit "$code"\nfi\n', 'companion-route', path, probe, fallback])


def routed(config, device, argv, *, timeout, user=False, group=None, extra=None, fallback=None, steps=None):
    from .runner import remote_command, ssh_argv, CommandResult
    from .tools import run, _device_user_session_argv
    args = dict(argv=argv, timeout=timeout, user=user)
    if group:
        args['group'] = group
    args.update(extra or {})
    if fallback is None:
        fallback = (_device_user_session_argv(config, device, argv, run_as_user=True)[-1]
                    if user else remote_command(argv))
    if steps is None:
        remote = dispatch_command(device, 'execute', args, fallback)
    else:
        remote = dispatch_command(device, 'workflow', dict(steps=steps, timeout=timeout), fallback)
    result = run(ssh_argv(device, config.paths.ssh_config, remote), timeout=timeout + 5)
    try:
        envelope = json.loads(result.stdout)
    except ValueError:
        return result
    if not isinstance(envelope, dict) or envelope.get('companion_available') is not True:
        return result
    data = envelope['result']
    if steps is not None:
        records = data['steps']
        data.update(returncode=records[-1]['returncode'], stdout=records[-1]['stdout'],
                    stderr='\n'.join(record['stderr'] for record in records if record['stderr']))
    metadata = {key: value for key, value in data.items() if key not in ('returncode', 'stdout', 'stderr')}
    return CommandResult(result.argv, data['returncode'], data['stdout'], data['stderr'], metadata)


def optional_call(config, device, name, args):
    from .runner import ssh_argv
    from .tools import run
    result = run(ssh_argv(device, config.paths.ssh_config, dispatch_command(device, name, args)),
                 timeout=max(15, args.get('wait_seconds', 0) + 5, args.get('timeout', 0) + 5 if name == 'workflow' else 0))
    if not result.ok:
        raise RuntimeError('Companion operation failed; not retried over SSH: ' + result.stderr[-2000:])
    data = json.loads(result.stdout)
    if not data.get('companion_available'):
        return None
    return data['result']


def start_job(config, device, args):
    from .tools import (_new_local_job, _device_command_jobs_dir, _write_json_atomic,
                        _compact_device_command_status, ok_text, tool_error)
    job_id, directory = _new_local_job(_device_command_jobs_dir(), 'device')
    route = dict(device=asdict(device))
    # Persist the intended destination before submission, including unknown outcomes.
    _write_json_atomic(directory / 'companion.json', route)
    status = dict(job_id=job_id, job_kind='device_command', backend='companion',
                  device=device.name, username=device.username, state='starting',
                  log_path=str(directory / 'command.log'), status_path=str(directory / 'status.json'))
    _write_json_atomic(directory / 'status.json', status)
    try:
        result = optional_call(config, device, 'job_start', dict(job_id=job_id,
                              argv=args['command'], timeout=args.get('timeout', 3600),
                              user=args.get('run_as_user', False)))
    except Exception as exc:
        return tool_error(str(exc), dict(status, submission_unknown=True))
    if result is None:
        for name in ('status.json', 'companion.json'):
            (directory / name).unlink()
        directory.rmdir()
        return None
    status.update(result)
    _write_json_atomic(directory / 'status.json', status)
    return ok_text('started device companion job ' + job_id, _compact_device_command_status(status))


def job_operation(config, args, cancel=False):
    from .config import DeviceConfig
    from .tools import (_device_command_jobs_dir, _local_job_dir, _read_job_status,
                        _write_json_atomic, _compact_device_command_status, ok_text, tool_error)
    directory = _local_job_dir(_device_command_jobs_dir(), args['job_id'])
    route_path = directory / 'companion.json'
    if not route_path.exists():
        return None
    route = json.loads(route_path.read_text())
    device = DeviceConfig(**route['device'])
    request = {key: value for key, value in args.items()
               if key in ('job_id', 'lines', 'wait_seconds', 'log_offset', 'max_bytes')}
    try:
        result = optional_call(config, device, 'job_cancel' if cancel else 'job_status', request)
        if result is None:
            raise RuntimeError('This job belongs to a device companion; it is unavailable. No SSH fallback was attempted.')
    except Exception as exc:
        return tool_error(str(exc), {'job_id': args['job_id'], 'backend': 'companion'})
    status = _read_job_status(directory / 'status.json') or {}
    status.update(result)
    _write_json_atomic(directory / 'status.json', status)
    data = dict(status) if args.get('verbose') else _compact_device_command_status(status)
    for key in ('next_offset', 'eof', 'log_kind', 'log_chars', 'log_included', 'log_truncated', 'cancel_requested'):
        if key in status:
            data[key] = status[key]
    text = 'job_id: ' + args['job_id'] + '\nstate: ' + status['state']
    if result.get('log_tail'):
        text += '\n\n' + result['log_tail']
    response = ok_text(text, data)
    response['isError'] = status['state'] in ('failed', 'timed_out') or (status['state'] == 'finished' and status.get('returncode') not in (None, 0))
    return response
