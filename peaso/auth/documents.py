"""Bounded data-only parsing for untrusted credential documents."""
import yaml
from yaml.events import AliasEvent


MAX_CREDENTIAL_BYTES = 2_000_000


class CredentialLoader(yaml.SafeLoader):
    def __init__(self, stream):
        super().__init__(stream)
        self.document_nodes = 0
        self.document_depth = 0

    def compose_node(self, parent, index):
        # SafeLoader prevents object construction, but still permits cyclic
        # and exponentially repeated alias graphs. Credentials need plain data.
        if self.check_event(AliasEvent):
            raise ValueError('credential YAML aliases are prohibited')
        self.document_nodes += 1
        self.document_depth += 1
        try:
            if self.document_nodes > 20_000 or self.document_depth > 64:
                raise ValueError('credential document structure exceeds limits')
            return super().compose_node(parent, index)
        finally:
            self.document_depth -= 1


def credential_document(text):
    if not isinstance(text, str) or len(text.encode()) > MAX_CREDENTIAL_BYTES:
        raise ValueError('credential document exceeds size limit')
    try:
        return yaml.load(text, Loader=CredentialLoader)
    except yaml.YAMLError:
        raise ValueError('invalid credential document') from None
