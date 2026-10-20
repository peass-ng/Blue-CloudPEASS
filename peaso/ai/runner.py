"""Bounded Chack review in a private working directory.

No scan credentials enter prompts, argv or process environment. Only their file
format and path are described. Parent handles timeouts and descendant cleanup.
"""
import json
import os
import sys
import time
from pathlib import Path


def main():
    started = time.monotonic()
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
    from .deadline import configure_runner
    configure_runner(config)
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
    from .deadline import ENVIRONMENT_KEY, timeout_seconds
    from .output_validation import context, validate, feedback, private_file, InvalidAgentOutput, MAX_OUTPUT
    original = context(stage, root)
    budget = timeout_seconds(os.getenv(ENVIRONMENT_KEY, str(config.agent.max_runtime_minutes * 60)))
    end = started + budget
    text = ''
    for attempt in range(2):
        remaining = end - time.monotonic()
        if remaining <= 0:
            raise TimeoutError()
        configure_runner(config, remaining=remaining)
        result = Chack(config).run(
            'cspm-' + stage, text, exec_cwd=str(root),
            prompt_variables_override={'access_instructions': access_instructions(entries)},
        )
        if getattr(result, 'error', None):
            raise RuntimeError('agent_failed')
        if len(result.output.encode('utf-8')) > MAX_OUTPUT:
            raise InvalidAgentOutput('agent_output_limit')
        data = None
        try:
            data = json.loads(result.output)
            validate(stage, data, original)
        except ValueError as error:
            if attempt:
                raise InvalidAgentOutput('invalid_agent_result') from None
            private_file(root/'candidate-output.json', data if data is not None else
                         {'unparsed_output': result.output[:100000]})
            private_file(root/'validation-feedback.json', feedback(error))
            text = ('Correct candidate-output.json using validation-feedback.json. Both files and all original '
                    'inputs are in the working directory. Resolve references against original findings/resources '
                    'with the supplied local reader. Preserve confirmed facts and uncertainty; return the complete '
                    'requested JSON with valid references, ranks and field limits. Use only read-only access.\n\n'
                    '### AVAILABLE ACCESS\n' + access_instructions(entries))
            continue
        private_file(root/'result.json', data)
        return



def entrypoint():
    from .output_validation import InvalidAgentOutput
    try:
        main()
    except TimeoutError:
        return 124
    except InvalidAgentOutput:
        return 65
    return 0


if __name__ == '__main__':
    sys.exit(entrypoint())
