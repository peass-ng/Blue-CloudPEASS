"""Function declaration metadata enters the complete current union before cleanup."""
from copy import deepcopy
from . import azure_function_settings_declarations_20261020 as source
from . import azure_ml_selected_asset_secret_indicators as current
from peaso.snapshot import seal


def final_snapshot(reader,snapshot):
    snapshot.setdefault('metadata',{}).update(deepcopy(getattr(reader,'function_declaration_metadata',{})))
    safe=current.final_snapshot(reader,snapshot)
    reader.function_declaration_metadata={k:deepcopy(v)for k,v in safe['metadata'].items()if k.startswith(source.KIND+'_')}
    return seal(safe)
