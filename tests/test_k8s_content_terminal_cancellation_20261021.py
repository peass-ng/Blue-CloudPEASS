"""A cancelled native read aborts collection instead of emitting an UNKNOWN item."""
import pytest

from peaso.collectors import k8s_selected_registry_image_20261021 as registry
from peaso.collectors import k8s_selected_flux_artifact_20261021 as flux


@pytest.mark.parametrize('code', ['collection_cancelled', 'deadline_exceeded'])
@pytest.mark.parametrize('reader', ['registry', 'flux'])
def test_terminal_native_error_is_propagated(reader, code):
    class TerminalReadError(RuntimeError):
        pass
    error = TerminalReadError(code)
    error.code = code
    reads = []

    def native_read(_target):
        reads.append('native')
        raise error

    def unexpected(*_args, **_kwargs):
        raise AssertionError('Further content access after terminal error')

    with pytest.raises(TerminalReadError) as caught:
        if reader == 'registry':
            registry.inspect({'image': 'ghcr.io/owned/app@sha256:' + '1' * 64}, native_read,
                             allowed_hosts=['ghcr.io'], registry_factory=unexpected, scanner=unexpected)
        else:
            flux.inspect({'artifact_digest': 'sha256:' + '1' * 64, 'artifact_revision': 'selected'},
                         native_read, unexpected, unexpected, scanner=unexpected)
    assert caught.value is error
    assert reads == ['native']
