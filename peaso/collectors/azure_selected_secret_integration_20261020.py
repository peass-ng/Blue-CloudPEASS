"""Final bounded union scrub for independently reviewed selected Azure readers."""
from . import azure_selected_configuration_secret_indicators as arm
from . import azure_selected_storage_secret_indicators as storage
from . import azure_devops_selected_content_secret_indicators as devops
MAX_UNION_VALUES=5000


def remember(reader,attribute,values):
    """Transient callback for admitted old readers; overflow withholds output."""
    current=getattr(reader,attribute)
    if getattr(reader,'storage_source_secret_overflow',False):return
    if (len(values)>MAX_UNION_VALUES or
            any(len(v.encode())>storage.MAX_REDACTION_VALUE_BYTES for v in values)):
        reader.storage_source_secret_overflow=True;current.clear();return
    current.update(values)
    if len(current)>MAX_UNION_VALUES or sum(len(v.encode())for v in current)>storage.MAX_REDACTION_TOTAL:
        reader.storage_source_secret_overflow=True;current.clear()


def final_snapshot(reader,snapshot):
    attributes=('configuration_secret_redactions','storage_source_secret_redactions','devops_selected_redactions',
                'app_setting_secret_redactions','acr_image_secret_redactions','azure_aks_image_redactions')
    values=set();overflow=getattr(reader,'storage_source_secret_overflow',False)
    try:
        # Merge every ledger before any scrub; later finalizers must not
        # reintroduce a metadata value already detected in another surface.
        for name in ('configuration_secret_metadata','storage_source_secret_metadata','devops_selected_metadata'):
            snapshot.setdefault('metadata',{}).update(getattr(reader,name,{}))
        for name in attributes:
            existing=getattr(reader,name,set())
            if (len(existing)>MAX_UNION_VALUES or any(len(v.encode())>storage.MAX_REDACTION_VALUE_BYTES for v in existing)):
                overflow=True;continue
            values.update(existing)
            if len(values)>MAX_UNION_VALUES or sum(len(v.encode()) for v in values)>storage.MAX_REDACTION_TOTAL:
                overflow=True;values.clear()
        if not hasattr(reader,'storage_source_secret_metadata'):reader.storage_source_secret_metadata={}
        snapshot=devops.final_snapshot(reader,snapshot)
        snapshot=arm.final_snapshot(reader,snapshot)
        # Other finalizers clear their own sets, so preserve the union in the
        # bounded final scrub, including when Storage itself was not selected.
        getattr(reader,'storage_source_secret_redactions',set()).clear()
        reader.storage_source_secret_redactions=values
        reader.storage_source_secret_overflow=overflow
        return storage.final_snapshot(reader,snapshot)
    finally:
        values.clear()
        for name in attributes:getattr(reader,name,set()).clear()
