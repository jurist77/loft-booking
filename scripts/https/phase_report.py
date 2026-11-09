"""Fixed diagnostic vocabulary only. Never serialize exception text or traceback."""
import json

MODULES = ('transport_settings', 'backup', 'maintenance', 'studio_installer',
           'probe_studio_network', 'rules', 'bindings', 'configuration', 'checks', 'inventory', 'host')
READS = ('service', 'caddy', 'sockets4', 'sockets6', 'web4', 'web6', 'interfaces',
         'ufw', 'nft', 'ip4', 'ip6', 'legacy4', 'legacy6')
REMOTE_PHASES = frozenset({
    'BOOTSTRAP_HEADER', 'BOOTSTRAP_PAYLOAD', 'BOOTSTRAP_EXEC', 'MODULE_PHASE_REPORT',
    *("MODULE_" + name.upper() for name in MODULES),
    'CHECK_ROOT', 'CHECK_INPUT', 'CHECK_PENDING', 'CHECK_STATE', 'CHECK_TLS_OWNER', 'CHECK_TRANSPORT',
    'CHECK_PLATFORM', 'CHECK_IDENTITY', 'CHECK_STORAGE', 'CHECK_ENVIRONMENT',
    *("READ_" + name.upper() for name in READS),
    'CHECK_FIREWALL', 'CHECK_SERVICE', 'CHECK_LISTENER', 'CHECK_HEALTH', 'CHECK_API',
    'CHECK_TLS_LISTENER', 'CHECK_INTERFACES', 'CHECK_MEMORY', 'CHECK_ACME', 'CHECK_STABILITY',
    'CHECK_LOCAL_TLS', 'CHECK_COMPLETE',
})
RUNNER_PHASES = frozenset({'RUNNER_INPUT', 'RUNNER_MAIN_CI', 'RUNNER_DNS', 'RUNNER_SSH_CHECK',
                         'RUNNER_ARTIFACT', 'RUNNER_SSH_APPLY', 'RUNNER_RESULT', 'RUNNER_EXTERNAL_PROOF'})
ERROR_KINDS = frozenset({'EXPECTED', 'JSON_INVALID', 'NAME_ERROR', 'ATTRIBUTE_ERROR', 'IMPORT_ERROR', 'TYPE_ERROR', 'LOOKUP_ERROR', 'ACCESS_DENIED',
                        'FILE_MISSING', 'OS_ERROR', 'TIMEOUT', 'VALUE_ERROR', 'RUNTIME_ERROR', 'OTHER'})

INPUT_ERROR_CODES = frozenset({'INVALID_INPUT', 'INVALID_SERVER_IP', 'PUBLIC_LITERAL_IP_REQUIRED',
    'ONE_ADDRESS_PER_FAMILY_REQUIRED', 'INVALID_MODE', 'CONFIRMATION_REQUIRED',
    'INVALID_BACKEND_PORT', 'INVALID_CADDY_PATH', 'INVALID_HTTPS_HOSTNAME', 'INVALID_HTTPS_STATE'})


def error_kind(error):
    # Types are mapped to constants. No type.__name__, str/repr, errno paths or raw stderr.
    for kind, cls in (('JSON_INVALID', json.JSONDecodeError), ('NAME_ERROR', NameError),
                      ('ATTRIBUTE_ERROR', AttributeError), ('IMPORT_ERROR', ImportError), ('TYPE_ERROR', TypeError),
                      ('LOOKUP_ERROR', LookupError), ('ACCESS_DENIED', PermissionError),
                      ('FILE_MISSING', FileNotFoundError), ('TIMEOUT', TimeoutError),
                      ('OS_ERROR', OSError), ('VALUE_ERROR', ValueError), ('RUNTIME_ERROR', RuntimeError)):
        if isinstance(error, cls): return kind
    return 'OTHER'


class Progress:
    def __init__(self, emit): self.emit, self.phase = emit, None

    def mark(self, phase):
        if phase not in REMOTE_PHASES: raise ValueError('INVALID_CHECK_PHASE')
        self.phase = phase
        self.emit('phase', phase=phase)


def report(rows):
    text = '## HTTPS execution phases\n\n| Side | Phase started |\n|---|---|\n'
    for side, phase in rows:
        if side in ('RUNNER', 'REMOTE') and phase in (RUNNER_PHASES if side == 'RUNNER' else REMOTE_PHASES):
            text += '| ' + side + ' | ' + phase + ' |\n'
    return text + '\nA started phase is not proof of success. Error kinds are fixed categories, not exception messages. No raw stderr, traceback, paths or configuration is reported.\n'
