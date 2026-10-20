"""One Chack invocation in a clean, temporary working directory.

No scan credentials enter prompts, argv or process environment. Only their file
format and path are described. Parent handles timeouts and descendant cleanup.
"""
import json
import os
import sys
from pathlib import Path


def main():
    from chack_agent import Chack, load_config
    from .prompting import access_instructions, agent_config_path
    stage = sys.argv[1]
    root = Path.cwd()
    auth_path = root / 'codex-auth.json'
    token = json.loads(auth_path.read_text())['access_token']
    auth_path.unlink()
    entries = json.loads((root / 'credentials.json').read_text())['entries']
    config = load_config(str(agent_config_path(stage)))
    config.credentials.codex_access_token = token
    config.credentials.openai_api_key = ''
    config.env = {'CHACK_EXEC_CWD': str(root)}
    relay = os.getenv('PEASO_AI_MODEL_RELAY')
    if relay:
        from .codex_relay_cli import relay_origin
        relay = relay_origin(relay)
        # Chack writes a fresh CODEX_HOME, so enforce routing through the CLI
        # wrapper rather than hoping its generated config preserves our keys.
        wrapper = root / 'relay-codex'
        wrapper.write_text('#!' + sys.executable + '\nfrom peaso.ai.codex_relay_cli import main\nmain()\n')
        wrapper.chmod(0o700)
        os.environ['CODEX_PATH'] = str(wrapper)
        config.env.update(OPENAI_BASE_URL=relay + '/codex', CHACK_CODEX_DIRECT_CACHE_TRANSPORT='off')
    result = Chack(config).run(
        'cspm-' + stage, exec_cwd=str(root),
        prompt_variables_override={'access_instructions': access_instructions(entries)},
    )
    if getattr(result, 'error', None):
        raise RuntimeError('agent_failed')
    data = json.loads(result.output)
    (root / 'result.json').write_text(json.dumps(data))


if __name__ == '__main__':
    main()
