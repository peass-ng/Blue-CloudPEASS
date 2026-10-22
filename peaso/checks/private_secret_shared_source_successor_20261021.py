"""Exact portable sentinel and signed source-artifact successor over the immutable Azure epoch.

Only the parent package aliases this bridge. Canonical historical modules,
receipts, callable objects, grant identities and native witnesses stay intact.
"""
from copy import deepcopy
from contextvars import ContextVar
import ast
import gzip
import hashlib
import hmac
import inspect
import importlib
import json
import linecache
import marshal
import os
from pathlib import Path
import re
import sys
import textwrap
import types
from . import azure_function_package_shared_successor_20261020 as predecessor
from . import azure_metadata_only_shared_successor_20261020 as historical_bridge
original = predecessor.original
PREDECESSOR_REVIEWED_INPUTS = predecessor.PREDECESSOR_REVIEWED_INPUTS
historical = importlib.import_module(__package__ + '.aws_workload_command_shared_successor_20261020')
accepted = importlib.import_module(__package__ + '.aws_deployed_ai_shared_successor_20261020')
_ACCEPTED_FUNCTIONS = dict(accepted._FUNCTIONS)
prior_bridge = importlib.import_module(__package__ + '.azure_jit_parent_type_shared_successor_20261020')
_PRIOR_FUNCTIONS = dict(prior_bridge._FUNCTIONS)
_PACKAGE_SUCCESSOR = importlib.import_module(__package__ + '.collector_noop_package_admission_successor_20261020')
_PACKAGE_FUNCTIONS = dict(_PACKAGE_SUCCESSOR._FUNCTIONS)
accepted_native = importlib.import_module(__package__ + '.native_admission_cpu_shared_successor_20261020')
_NATIVE_FUNCTIONS = dict(accepted_native._FUNCTIONS)
_NATIVE_PACKAGE = importlib.import_module(__package__ + '.azure_function_package_callable_cpu_successor_20261020')
_NATIVE_PACKAGE_FUNCTIONS = dict(_NATIVE_PACKAGE._FUNCTIONS)
_COMMAND_SUCCESSOR = importlib.import_module(__package__ + '.collector_noop_command_admission_successor_20261020')
_CODEBUILD_SUCCESSOR = importlib.import_module(__package__ + '.collector_noop_codebuild_admission_successor_20261020')
_AUTHORIZATION_SUCCESSORS = (_COMMAND_SUCCESSOR, _CODEBUILD_SUCCESSOR, _PACKAGE_SUCCESSOR)
_AUTHORIZATION_FUNCTIONS = {name: fn for module in _AUTHORIZATION_SUCCESSORS for name, fn in module._FUNCTIONS.items()}
_HISTORICAL_FUNCTIONS = dict(historical._FUNCTIONS)
accepted_noop = importlib.import_module(__package__ + '.collector_noop_authorization_shared_successor_20261020')
_NOOP_FUNCTIONS = dict(accepted_noop._FUNCTIONS)
_METADATA_AZURE = importlib.import_module('peaso.collectors.azure')
_METADATA_COLLECT = _METADATA_AZURE.collect
_METADATA_CLASS = _METADATA_AZURE._MetadataOnlyCollection
_METADATA_WEAKREF = vars(_METADATA_CLASS)['__weakref__']
_METADATA_TDE = importlib.import_module(__package__ + '.azure_metadata_only_tde_admission_successor_20261020')
_METADATA_TDE_FUNCTIONS = dict(_METADATA_TDE._FUNCTIONS)
_COMPILED_TRANSACTION = ContextVar('deployed_ai_compiled_transaction', default=None)
_TRANSACTION_CONTEXT = _COMPILED_TRANSACTION
_DATAFLOW_ADMISSION = importlib.import_module(__package__ + '.gcp_dataflow_batch_source_runtime_admission_20261020')
_DATAFLOW_FUNCTIONS = dict(_DATAFLOW_ADMISSION._FUNCTIONS)
_DATAFLOW_REVIEWED_INPUTS = _DATAFLOW_FUNCTIONS[_DATAFLOW_ADMISSION.__name__ + ':reviewed_inputs']
RECEIPT = 'azure_metadata_only_shared_successor_20261020.json'
RECEIPT_SHA256 = '12bf2cd88f943bcb3cdb91a3701cd3197e78d6ba7ed7e956afd854d6d1b292ed'
BRIDGE_RECEIPT_SHA256 = '5889b51b210bf8a45f3eb07c5b4a027a2fceec9562e5b6baed8c2ba614d27f1e'
_CURRENT_INIT_SHA256 = '0fa143a274905e52dad14d6eecfb641fdc98ebbd17db90d54d9908594b458e08'
_PREDECESSOR_INIT_SHA256 = 'e828e145917364fcd20a5a2d6de7e24eb304eee5698fea1cb1bed8669fef01c6'



from peaso import private_secret_source_epoch_20261021 as _private_source_epoch
from . import gcp_positive_conservation_shared_source_successor_20261020 as _private_canonical
_PRIVATE_SOURCE_RECORDS = (('peaso/collectors/aws_additional_secret_indicators.py', 'e2cfc9bcd839b1a7a803580b549b3d02d8a67757274551a0afc4130e5d184787', ('_scan', 'codebuild_indicator')), ('peaso/collectors/aws_code_log_content_indicators.py', '06fd10cdc45542e15e31d4e735256fa62b3733c805dc5eb1865b7e3923013355', ('project_response',)), ('peaso/collectors/aws_codebuild_buildspec_source_20261020.py', '4890d8a97cd86cdcee0df334956531432ae26ec2f6a1758f1ecb858e7f778bce', ('collect',)), ('peaso/collectors/aws_configuration_payload_secret_indicators.py', 'eef6d7241cc5f09f9560c427fa9f336a636d1996130f0eb5b05d17377883fdc9', ('marker', 'project_response')), ('peaso/collectors/aws_configuration_secret_indicators.py', 'cbeb631ac665dea0c221a3ad370d21000b8c458a33072b4f0d5c855bedbc147c', ('_indicators', 'lambda_indicators')), ('peaso/collectors/aws_lambda_environment_secret_indicators.py', '2fce27977e83ba4f9abc6baa6ac78d4ff5e0e4a2b8b27d52d333a0458e67f289', ('project_response',)), ('peaso/collectors/aws_package_content_indicators.py', 'ce459d4b5ed0ae991591f09f61b462f7841f0977d5935579e561409c0117e7e6', ('_image', '_lambda', '_layer', '_scan')), ('peaso/collectors/aws_s3_selected_source_secret_indicators.py', 'b040a3b23746561fe913b1bd985669a0820fdde72b12fd864c5f6b5b894e3053', ('_scan_part', 'collect_selected')), ('peaso/collectors/aws_selected_configuration_secret_indicators.py', 'c7a87afb1fc02740979a34efa2a03141d4e0daddbfdda1e45c604507c31c450f', ('collect_selected', 'project_response')), ('peaso/collectors/aws_user_data_secret_indicators.py', '077b5d258d6728c0b712935d34899c0feb27e3d11f758a81e793a6a240016205', ('project', 'scan_selected_content')), ('peaso/collectors/aws_workload_command_source_20261020.py', 'c5c5c24b7fbd4b696903d38b6e84a02ad3ebfa35616e6378a67afb97b8ae757e', ('collect',)), ('peaso/collectors/azure.py', 'd27a5f2b861fef622c20bff80bf5e8f559d7f5d70604606643eb9267254101e5', ('AzureTransport',)), ('peaso/collectors/azure_acr_image_secret_indicators.py', '8e9c55f0fcee045b9c283554e7e5908f8ef1aff5225bfd3eb6a4e037b1a0995d', ('_scan_bytes', '_scan_json', 'inspect_image')), ('peaso/collectors/azure_app_settings_secret_indicators.py', 'f7fed346ff359f463e72cff63f4de9e1971e2aeef2223ed8b338c91c7520248b', ('_scan',)), ('peaso/collectors/azure_databricks_notebook_secret_indicators.py', '6eed83bf1d6b6e8055dabb1c0cee052f1b7c636121c742e74b8727bc23b4b222', ('_scan',)), ('peaso/collectors/azure_devops_git_native.py', '7b01f9f26acae14414d33b42095caad14adaf4644b3706fde2120e170b4c2c63', ('collect', 'project_response')), ('peaso/collectors/azure_devops_selected_content_secret_indicators.py', '3def2355bfad985b1543022cc14443677dd6ed37928a4d1109eeffb741fb5434', ('_part', '_scan')), ('peaso/collectors/azure_ml_selected_asset_secret_indicators.py', 'e5d98f9692035b60342526497ca70076a06cdafd3dbf8bfc0aa706ea70f2486f', ('_one',)), ('peaso/collectors/azure_ml_selected_job_secret_indicators.py', 'a0644628612d680fea88a9dcedca7541f1560278fc5d4ea116710739035143c3', ('_scan',)), ('peaso/collectors/azure_selected_configuration_secret_indicators.py', '570bf399805ef12cd647007d43ea450f1138244d58c4326972842c42281d7604', ('_scan',)), ('peaso/collectors/azure_selected_declaration_secret_indicators.py', '31b9a452cc530f4ceee89b1ca5b6892217eeea82d1699b9c86126e3fd9bdc6f2', ('_scan',)), ('peaso/collectors/azure_selected_log_sample_secret_indicators.py', 'fd07ef51f86ef4ed6889c62c532de732f69f7c76e568c08db6d39271094718f8', ('_scan',)), ('peaso/collectors/azure_selected_storage_secret_indicators.py', '59db1280c49909db57368b7e4e61e846f5f2c8ee1b323c6b2204f2110646beda', ('_inspect', '_scan')), ('peaso/collectors/gcp.py', 'f7554a0e905d712242bfd2826866517bbc410b1a4aa9e3ef195c75c07df37e96', ('Transport',)), ('peaso/collectors/gcp_additional_literal_secret_indicators.py', '0bfb934509a3ae9cd00f826371bbc1d7a7999d755d62a2234f1da650cc9ca492', ('scan_row',)), ('peaso/collectors/gcp_appengine_source_secret_indicators.py', '5f0dc6ceb82d853f10f4af47858504ae09b266e50800f49ecf8724238385ad61', ('collect_sources',)), ('peaso/collectors/gcp_artifact_file_secret_indicators.py', 'da4edfdac77dda5c80891ac7d812c1859e536e4786360b8d5656f64af289d4ff', ('_inspect',)), ('peaso/collectors/gcp_batch_referenced_source_20261020.py', 'c0bb32c6b0f8aaa0975ec3ed28875b2618ab8c2a674e16b41173e21ba4082921', ('collect',)), ('peaso/collectors/gcp_cloudrun_v2_job_declared_images_20261020.py', '91e6118e969286fd577eea11c65f5f2129e4711604c45414f601fbeb71ed0f51', ('_inspect',)), ('peaso/collectors/gcp_composer_source_secret_indicators.py', '2b357152018fc33b6cf31bba99ac52c2bd5bd9390a9c9c60233c26b66915f903', ('collect_sources',)), ('peaso/collectors/gcp_configuration_secret_indicators.py', '8c573da30b8bf20c1dfa88d450e44caf0935aa68f831fef941ef58f832901549', ('project_response',)), ('peaso/collectors/gcp_dataflow_referenced_source_20261020.py', 'c638e6ad782b475e9d6bc2ee93aed1bc57da67281bbb53ffa364935f84c6ad59', ('inspect_payload',)), ('peaso/collectors/gcp_dataform_secret_indicators.py', 'ca02f4a3025442421b25433a7930f157cb9ffd01295c8a07b8dce1d8a9428a70', ('collect_selected_files',)), ('peaso/collectors/gcp_dataproc_referenced_source_secret_indicators.py', '75f3bb777dd00bb154f24de0f459994fefbced29262c91ec17967618f54801f0', ('collect_sources',)), ('peaso/collectors/gcp_function_secret_indicators.py', 'f0107e484b39ca361710b0c838c07eb861fe8701239f79e91b41230a211b58c3', ('_scan_function',)), ('peaso/collectors/gcp_function_secret_pairs_20261020.py', 'e6f344088f0fbbbb50ff782852495cc9c23a874448e9b732543027e01e068598', ('_scan_function',)), ('peaso/collectors/gcp_gke_literal_secret_indicators.py', '9939b98e6393d33fc105d9f1f6ece556f697d19a69f6064149fcbbc0b52a3def', ('project_resource',)), ('peaso/collectors/gcp_image_secret_indicators.py', '2022bbd2816bfe82679b160c12b90d674c12746e14d95138bb3bb236dc0514c3', ('_tar', 'inspect_image')), ('peaso/collectors/gcp_job_literal_secret_indicators.py', 'afe4305155c2350cab0faa3f00d8a2a1431de0d23f890fe3780075abd77c8055', ('project_row',)), ('peaso/collectors/gcp_log_secret_indicators.py', '7600114140eef746787981f73b18b47910c0d82797662050f2a6944306b7b161', ('project_page',)), ('peaso/collectors/gcp_notebook_airflow_secret_indicators.py', '70d808587cca4847f5979f7ed9eb6452b6f332c6996d68157c7af00cf3278118', ('project_response',)), ('peaso/collectors/gcp_selected_archive_secret_indicators.py', '4dc9fd5feb8b193f5a119ee7b2f2b387d5eaf9f3c04fe2502c5df7e7ed07a4d3', ('_parse', 'collect_selected_archives')), ('peaso/collectors/gcp_selected_object_secret_indicators.py', 'fb9d1c2837660501bd87ab9642519f4caadfc395eee3193d1ccefd1bb2517959', ('collect_selected_objects',)), ('peaso/collectors/gcp_selected_task_routine_secret_indicators.py', '393720df111585dfd41e586f548ce35140a01e86dd980564805552b1b085cc66', ('collect_sources',)), ('peaso/collectors/gcp_sourcerepo_secret_indicators.py', 'ba809b97f9e9b36674b2938c74a1f9ee874e3121cbef947008db66091dbaf9e4', ('collect_sources',)), ('peaso/collectors/gcp_workbench_referenced_source_20261020.py', '3c8a3b4dcaf51c6f1544dd1d4465d8a60c00ec1d605a3d808e7590b0ce219b73', ('collect_sources',)), ('peaso/collectors/k8s.py', '86eca83f116bc8fe4a2b28d5ced1ae6612507c5cc3f53968fe6ec28df14a15f1', ('_native',)), ('peaso/collectors/k8s_literal_secret_indicators.py', '1ee91c6b52cf142d30ef58f55dd11f8e1688d129791c869a1a6783e7a80aa47b', ('collect',)), ('peaso/collectors/k8s_selected_log_sample_secret_indicators.py', '0fe2d51cb83f4126994f1bfaf1eff50c96469c3b1e285c44d78825f48328e9c0', ('collect',)), ('peaso/secret_scanning.py', '3897b64c134f88e7ad17c3c1f31df2b5497d34df6c1340d04e536313652f94f6', ('_scan_kingfisher', '_scan_trufflehog', 'scan_content')))
_PRIVATE_SOURCE_PATHS = frozenset(record[0] for record in _PRIVATE_SOURCE_RECORDS)
_PRIVATE_RECEIPT = 'peaso/checks/private_secret_shared_source_successor_20261021.json'
_PRIVATE_RECEIPT_SHA256 = '4ae938246f6998e2e00f21d2c02e701a699a76cd02fc7482ab92be8aafc51b13'


def _private_binding_equal(actual, expected):
    # The inherited function maps have exact string keys. Check each field
    # without the quadratic arbitrary-key matching used for general literals.
    if type(actual) is not type(expected):
        return False
    if type(actual) is dict and all(type(key) is str for key in actual) and all(type(key) is str for key in expected):
        return (actual.keys() == expected.keys()
                and all(_private_binding_equal(actual[key], expected[key]) for key in expected))
    if type(actual) in (tuple, list):
        return len(actual) == len(expected) and all(_private_binding_equal(a, b) for a, b in zip(actual, expected))
    return _private_source_epoch._same(actual, expected)


def _private_receipt(parse=True):
    raw = (Path(__file__).resolve().parents[2] / _PRIVATE_RECEIPT).read_bytes()
    if hashlib.sha256(raw).hexdigest() != _PRIVATE_RECEIPT_SHA256:
        raise RuntimeError('Private shared receipt changed')
    return json.loads(raw) if parse else None


# BEGIN PRIVATE SELF CODE CACHE FACTORY
def _private_code_cache_factory():
    """Keep only authenticated, immutable code and source metadata."""
    import builtins as local_builtins
    import hashlib as local_hashlib
    import hmac as local_hmac
    import marshal as local_marshal
    import os as local_os
    import sys as local_sys
    import types as local_types

    entries = {}
    secret = local_os.urandom(32)

    def lookup(path, raw):
        if local_os is not local_sys.modules.get('os'):
            raise local_builtins.ValueError('Private cache random source changed')
        key = (local_builtins.str(path), local_builtins.str(path.resolve(strict=True)),
               local_hashlib.sha256(raw).digest(), local_sys.implementation.cache_tag,
               local_sys.flags.optimize)
        entry = entries.get(key)
        if entry is None:
            return None
        if (local_builtins.type(entry) is not local_builtins.tuple
                or local_builtins.len(entry) != 3
                or local_builtins.type(entry[0]) is not local_types.CodeType
                or local_builtins.type(entry[2]) is not local_builtins.bytes
                or not local_hmac.compare_digest(entry[2], local_hmac.digest(secret,
                    local_marshal.dumps((key, local_builtins.id(entry[0]), entry[1]), 2),
                    'sha256'))):
            raise local_builtins.ValueError('Private cache artifact changed')
        return entry[0], entry[1]

    return lookup
# END PRIVATE SELF CODE CACHE FACTORY


_PRIVATE_CODE_CACHE = _private_code_cache_factory()
_PRIVATE_CODE_CACHE_ANCHOR = _PRIVATE_CODE_CACHE
_PRIVATE_CODE_CACHE_STORAGE = _PRIVATE_CODE_CACHE.__closure__[0].cell_contents


def _private_self():
    receipt = _private_receipt(parse=True)
    path = Path(__file__).resolve()
    raw = path.read_bytes()
    normalized, count = re.subn(rb"(?m)^_PRIVATE_RECEIPT_SHA256 = '[0-9a-f]{64}'$", b"_PRIVATE_RECEIPT_SHA256 = '" + b'0' * 64 + b"'", raw)
    if count != 1 or hashlib.sha256(normalized).hexdigest() != receipt['source_sha256']:
        raise RuntimeError('Private shared source changed')
    root = path.parents[2]
    original_path = root / receipt['canonical_path']
    if hashlib.sha256(original_path.read_bytes()).hexdigest() != receipt['canonical_sha256']:
        raise RuntimeError('Private shared canonical predecessor changed')
    if (sys.modules.get('peaso.private_secret_source_epoch_20261021') is not _private_source_epoch
            or Path(_private_source_epoch.__file__).resolve() != root / 'peaso/private_secret_source_epoch_20261021.py'
            or hashlib.sha256(Path(_private_source_epoch.__file__).read_bytes()).hexdigest() != receipt['common_source_sha256']):
        raise RuntimeError('Private shared common attestor changed')
    _private_source_epoch.source_rows()
    lines = raw.splitlines(keepends=True)
    begin = [i for i, line in enumerate(lines) if line == b'# BEGIN PRIVATE SELF CODE CACHE FACTORY\n']
    end = [i for i, line in enumerate(lines) if line == b'# END PRIVATE SELF CODE CACHE FACTORY\n']
    if len(begin) != 1 or len(end) != 1 or end[0] <= begin[0] + 1:
        raise RuntimeError('Private cache factory source changed')
    fragment = b'\n' * (begin[0] + 1) + b''.join(lines[begin[0] + 1:end[0]])
    boot_code = compile(fragment, __file__, 'exec', dont_inherit=True, optimize=sys.flags.optimize)
    factory_code = [code for code in boot_code.co_consts
                    if type(code) is types.CodeType and code.co_name == '_private_code_cache_factory']
    if len(factory_code) != 1:
        raise RuntimeError('Private cache factory ambiguous')
    lookup_code = [code for code in factory_code[0].co_consts
                   if type(code) is types.CodeType and code.co_name == 'lookup']
    factory = globals().get('_private_code_cache_factory')
    lookup = globals().get('_PRIVATE_CODE_CACHE')
    if (len(lookup_code) != 1 or type(factory) is not types.FunctionType
            or factory.__globals__ is not globals() or factory.__closure__ is not None
            or factory.__defaults__ is not None or factory.__kwdefaults__ is not None
            or factory.__module__ != __name__ or factory.__qualname__ != '_private_code_cache_factory'
            or not _private_source_epoch._immutable_code_constants(factory.__code__)
            or not _private_source_epoch._code_equal(factory.__code__, factory_code[0])
            or type(lookup) is not types.FunctionType or lookup is not _PRIVATE_CODE_CACHE_ANCHOR
            or lookup.__globals__ is not globals() or lookup.__module__ != __name__
            or lookup.__qualname__ != '_private_code_cache_factory.<locals>.lookup'
            or lookup.__defaults__ is not None or lookup.__kwdefaults__ is not None
            or not _private_source_epoch._immutable_code_constants(lookup.__code__)
            or not _private_source_epoch._code_equal(lookup.__code__, lookup_code[0])
            or lookup.__closure__ is None):
        raise RuntimeError('Private cache binding changed')
    cells = dict(zip(lookup.__code__.co_freevars, (cell.cell_contents for cell in lookup.__closure__)))
    if (set(cells) != {'entries', 'local_builtins', 'local_hashlib', 'local_hmac',
                       'local_marshal', 'local_os', 'local_sys', 'local_types', 'secret'}
            or cells['entries'] is not _PRIVATE_CODE_CACHE_STORAGE
            or type(_PRIVATE_CODE_CACHE_STORAGE) is not dict
            or type(cells['secret']) is not bytes or len(cells['secret']) != 32
            or cells['local_builtins'] is not sys.modules.get('builtins')
            or cells['local_hashlib'] is not hashlib or cells['local_hmac'] is not hmac
            or cells['local_marshal'] is not marshal or cells['local_os'] is not os
            or cells['local_sys'] is not sys or cells['local_types'] is not types):
        raise RuntimeError('Private cache closure changed')
    try:
        artifact = lookup(path, raw)
    except (ValueError, TypeError, AttributeError) as exc:
        raise RuntimeError('Private cache artifact changed') from exc
    if artifact is None:
        tree = ast.parse(raw, filename=__file__)
        pinned_records = next(ast.literal_eval(node.value) for node in tree.body
                              if isinstance(node, ast.Assign) and len(node.targets) == 1
                              and isinstance(node.targets[0], ast.Name) and node.targets[0].id == '_PRIVATE_SOURCE_RECORDS')
        literal_bindings = {node.targets[0].id: ast.literal_eval(node.value) for node in tree.body
                            if isinstance(node, ast.Assign) and len(node.targets) == 1
                            and isinstance(node.targets[0], ast.Name)
                            and node.targets[0].id in ('_PRIVATE_RECEIPT', '_PRIVATE_RECEIPT_SHA256')}
        compiled = compile(raw, __file__, 'exec', dont_inherit=True, optimize=sys.flags.optimize)
        metadata = (pinned_records, tuple(sorted(literal_bindings.items())))
    else:
        compiled, metadata = artifact
        if (type(metadata) is not tuple or len(metadata) != 2
                or type(metadata[0]) is not tuple or type(metadata[1]) is not tuple):
            raise RuntimeError('Private cache metadata changed')
        pinned_records, bindings = metadata
        literal_bindings = dict(bindings)
    def immutable(value):
        if type(value) is types.CodeType:
            return all(immutable(item) for item in value.co_consts)
        if type(value) in (tuple, frozenset):
            return all(immutable(item) for item in value)
        return value is None or value is Ellipsis or type(value) in (
            bool, int, float, complex, str, bytes)
    if not immutable(compiled) or not immutable(metadata):
        raise RuntimeError('Private cache artifact is mutable')
    if (not _private_source_epoch._same(_PRIVATE_SOURCE_RECORDS, pinned_records)
            or type(_PRIVATE_SOURCE_PATHS) is not frozenset
            or _PRIVATE_SOURCE_PATHS != frozenset(record[0] for record in pinned_records)):
        raise RuntimeError('Private shared finite source roster binding changed')
    if (sys.modules.get('peaso.checks.gcp_positive_conservation_shared_source_successor_20261020') is not _private_canonical
            or Path(_private_canonical.__file__).resolve() != original_path.resolve()):
        raise RuntimeError('Private shared canonical module binding changed')
    for key, expected in vars(_private_canonical).items():
        if key.startswith('__') or key in ('_COMPILED_TRANSACTION', '_TRANSACTION_CONTEXT'):
            continue
        if isinstance(expected, types.FunctionType) and expected.__globals__ is vars(_private_canonical):
            continue
        if key not in globals() or not _private_binding_equal(globals()[key], expected):
            raise RuntimeError('Private shared inherited binding changed: ' + key)
    module = sys.modules.get(__name__)
    if module is None or vars(module) is not globals():
        raise RuntimeError('Private shared live module changed')
    if (literal_bindings.get('_PRIVATE_RECEIPT') != _PRIVATE_RECEIPT
            or literal_bindings.get('_PRIVATE_RECEIPT_SHA256') != _PRIVATE_RECEIPT_SHA256):
        raise RuntimeError('Private shared receipt literal binding changed')
    expected_functions = {code.co_name: code for code in compiled.co_consts if type(code) is types.CodeType}
    functions = {name: value for name, value in globals().items()
                 if isinstance(value, types.FunctionType) and value.__globals__ is globals()
                 and name not in ('_PRIVATE_CODE_CACHE', '_PRIVATE_CODE_CACHE_ANCHOR')}
    if set(functions) != set(receipt['functions']):
        raise RuntimeError('Private shared live roster changed')
    for name, function in functions.items():
        expected_code = expected_functions.get(name)
        row = receipt['functions'][name]
        if (expected_code is None or function.__module__ != __name__ or function.__qualname__ != name
                or inspect.unwrap(function) is not function
                or not _private_source_epoch._code_equal(function.__code__, expected_code)
                or function.__closure__ is not None
                or repr(function.__defaults__) != row['defaults']
                or repr(function.__kwdefaults__) != row['kwdefaults']):
            raise RuntimeError('Private shared live callable changed: ' + name)
    if artifact is None:
        key = (str(path), str(path.resolve(strict=True)), hashlib.sha256(raw).digest(),
               sys.implementation.cache_tag, sys.flags.optimize)
        signature = hmac.digest(cells['secret'], marshal.dumps((key, id(compiled), metadata), 2), 'sha256')
        if len(_PRIVATE_CODE_CACHE_STORAGE) >= 4:
            _PRIVATE_CODE_CACHE_STORAGE.clear()
        _PRIVATE_CODE_CACHE_STORAGE[key] = (compiled, metadata, signature)



def _private_before(relative, raw, root):
    if relative in ('peaso/engine.py', 'peaso/collectors/aws.py', 'peaso/server/validation.py', 'peaso/collectors/aws_workload_command_runtime_20261020.py', 'peaso/collectors/azure_function_package_source_20261020.py', 'peaso/checks/azure_metadata_only_tde_admission_successor_20261020.py', 'peaso/checks/azure_acr_image_secret_review_20261020.py', 'peaso/checks/gcp_cloudbuild_log_secret_review_20261019.py', 'peaso/checks/k8s_literal_secret_review_20261020.py', 'peaso/checks/k8s_ports_components.py', 'peaso/collectors/gcp_cloudbuild_log_secret_indicators.py', 'peaso/collectors/gcp_cloudrun_content_sources.py', 'peaso/collectors/gcp_job_image_vulnerability_runtime_20261021.py', 'peaso/server/image_selection_options_20261021.py', 'peaso/collectors/azure_selected_secret_integration_20261020.py', 'peaso/checks/k8s_selected_metadata_secret_admission_20261020.py', 'peaso/snapshot.py', 'peaso/collectors/azure_function_settings_declarations_20261020.py', 'peaso/collectors/azure_apim_operation_window_20261020.py'):
        transition = _private_receipt()['provider_group_files'][relative]
        _private_self()
        if raw != (root / relative).read_bytes():
            raise RuntimeError('Provider group source bytes differ from disk')
        restored = _reverse(raw.decode('utf-8'), transition).encode('utf-8')
        if hashlib.sha256(restored).hexdigest() != transition['predecessor_sha256']:
            raise RuntimeError('Provider group source predecessor changed')
        return restored
    if relative not in _PRIVATE_SOURCE_PATHS:
        return raw
    before = next(row[1] for row in _PRIVATE_SOURCE_RECORDS if row[0] == relative)
    return _private_source_epoch.predecessor_bytes(relative, raw, before, root)


def _private_row(function, row, root):
    path = row.get('path')
    if path not in _PRIVATE_SOURCE_PATHS and path not in ('peaso/engine.py', 'peaso/collectors/aws.py', 'peaso/server/validation.py', 'peaso/collectors/aws_workload_command_runtime_20261020.py', 'peaso/collectors/azure_function_package_source_20261020.py', 'peaso/checks/azure_metadata_only_tde_admission_successor_20261020.py', 'peaso/checks/azure_acr_image_secret_review_20261020.py', 'peaso/checks/gcp_cloudbuild_log_secret_review_20261019.py', 'peaso/checks/k8s_literal_secret_review_20261020.py', 'peaso/checks/k8s_ports_components.py', 'peaso/collectors/gcp_cloudbuild_log_secret_indicators.py', 'peaso/collectors/gcp_cloudrun_content_sources.py', 'peaso/collectors/gcp_job_image_vulnerability_runtime_20261021.py', 'peaso/snapshot.py', 'peaso/server/image_selection_options_20261021.py', 'peaso/collectors/azure_selected_secret_integration_20261020.py', 'peaso/checks/k8s_selected_metadata_secret_admission_20261020.py', 'peaso/collectors/azure_function_settings_declarations_20261020.py', 'peaso/collectors/azure_apim_operation_window_20261020.py'):
        _private_receipt(parse=False)
        return row
    key = str(path) + ':' + function.__qualname__
    transition = _private_receipt()['provider_group_callables'].get(key)
    if transition is not None and not (path == 'peaso/collectors/azure.py' and function.__qualname__ == 'collect'):
        if row.get('sha256') != transition['predecessor_sha256'] or row.get('qualname') != function.__qualname__:
            raise RuntimeError('Provider group callable predecessor row changed')
        _private_before(path, (root / path).read_bytes(), root)
        return dict(row, sha256=transition['current_sha256'], defaults=transition.get('defaults', row.get('defaults')), kwdefaults=transition.get('kwdefaults', row.get('kwdefaults')))
    if path == 'peaso/collectors/azure.py' and function.__qualname__ == 'collect':
        transition = _private_receipt()['provider_group_azure_collect']
        if row.get('qualname') != 'collect' or row.get('sha256') != transition['predecessor_sha256']:
            raise RuntimeError('Provider group Azure collect predecessor row changed')
        _private_before(path, (root / path).read_bytes(), root)
        return dict(row, sha256=transition['current_sha256'], defaults=transition.get('defaults', row.get('defaults')), kwdefaults=transition.get('kwdefaults', row.get('kwdefaults')))
    if path not in _PRIVATE_SOURCE_PATHS:
        return row
    if path == 'peaso/secret_scanning.py':
        from peaso.rawv2_private_source_successor_20261021 import producer_row
        return producer_row(function, row, root)
    names = next(record[2] for record in _PRIVATE_SOURCE_RECORDS if record[0] == path)
    if function.__qualname__ not in names:
        if function.__qualname__ not in ('AzureTransport.request', 'Transport.request'):
            _private_before(path, (root / path).read_bytes(), root)
            return row
    if path in ('peaso/checks/gcp_artifact_file_secret_review_20261019.py', 'peaso/checks/gcp_composer_source_secret_review_20261019.py', 'peaso/checks/gcp_image_secret_review_20261019.py', 'peaso/checks/gcp_selected_archive_secret_review_20261019.py', 'peaso/checks/gcp_sourcerepo_secret_review_20261019.py', 'peaso/checks/gcp_task_routine_secret_review_20261020.py', 'peaso/collectors/gcp_artifact_file_secret_indicators.py', 'peaso/collectors/gcp_composer_source_secret_indicators.py', 'peaso/collectors/gcp_image_secret_indicators.py', 'peaso/collectors/gcp_selected_archive_secret_indicators.py', 'peaso/collectors/gcp_selected_task_routine_secret_indicators.py', 'peaso/collectors/gcp_sourcerepo_secret_indicators.py'):
        # The retained positive-conservation guard binds this older row to
        # its exact 12-leaf predecessor. Prove the private-current function
        # separately; do not mislabel the older row as the private predecessor.
        _private_source_epoch.trusted_definition(function, root)
        return row
    if 'line' in row:
        before = _private_before(path, (root / path).read_bytes(), root)
        matches = [(record, code) for record, code in _compiled_source(before, str(root / path), sys.flags.optimize)
                   if record['qualname'] == row.get('qualname')]
        if (len(matches) != 1 or type(row['line']) is not int
                or row['line'] != matches[0][1].co_firstlineno):
            raise RuntimeError('Private historical callable line changed')
        projected = _private_source_epoch.callable_projection(function, {key: value for key, value in row.items() if key != 'line'}, root)
        return dict(projected, line=inspect.unwrap(function).__code__.co_firstlineno)
    return _private_source_epoch.callable_projection(function, row, root)

def _admitted_scanner_bytes(name, raw, expected, root):
    if name == 'peaso/checks/k8s_selected_metadata_secret_admission_20261020.py':
        live = (root / name).read_bytes()
        if raw != original.prepared._self(live):
            raise RuntimeError('Metadata admission self normalization changed')
        transition = _private_source_epoch._receipt()[0]['current_reviewed_files'][name]
        predecessor = _private_source_epoch.predecessor_bytes(name, live, transition['predecessor_sha256'], root)
        raw = original.prepared._self(predecessor)
    if name in ('peaso/engine.py', 'peaso/collectors/aws.py', 'peaso/server/validation.py', 'peaso/collectors/aws_workload_command_runtime_20261020.py', 'peaso/collectors/azure_function_package_source_20261020.py', 'peaso/checks/azure_metadata_only_tde_admission_successor_20261020.py', 'peaso/checks/azure_acr_image_secret_review_20261020.py', 'peaso/checks/gcp_cloudbuild_log_secret_review_20261019.py', 'peaso/checks/k8s_literal_secret_review_20261020.py', 'peaso/checks/k8s_ports_components.py', 'peaso/collectors/gcp_cloudbuild_log_secret_indicators.py', 'peaso/collectors/gcp_cloudrun_content_sources.py', 'peaso/collectors/gcp_job_image_vulnerability_runtime_20261021.py', 'peaso/server/image_selection_options_20261021.py', 'peaso/collectors/azure_selected_secret_integration_20261020.py', 'peaso/snapshot.py', 'peaso/collectors/azure_function_settings_declarations_20261020.py', 'peaso/collectors/azure_apim_operation_window_20261020.py'):
        raw = _private_before(name, raw, root)
    from peaso.rawv2_private_source_successor_20261021 import source_bytes
    return source_bytes(name, raw, expected, root)


def _published_initialization_predecessor(raw):
    if hashlib.sha256(raw).hexdigest() != _CURRENT_INIT_SHA256:
        raise RuntimeError('GCP positive conservation initializer changed')
    rawv2_edits = (
        (b'collector_noop_authorization_shared_successor_20261020 = aws_workload_command_shared_successor_20261020\n', b''),
        (b'_rawv2_source.install_admission("gcp_dataproc_source_runtime_admission_20261020")\n', b'gcp_dataproc_source_runtime_admission_20261020.install()\n'),
        (b'_rawv2_source.install_admission("azure_declaration_secrets_admission_20261020")\n', b'azure_declaration_secrets_admission_20261020.install()\n'),
        (b'from peaso import rawv2_public_source_successor_20261021 as _rawv2_source\n', b''),
        (b'_rawv2_source.install_selected_aws()\n', b'aws_selected_configuration_admission_20261020.install()\n'),
        (b'_rawv2_source.install_selected_azure()\n', b'azure_selected_secrets_admission_20261020.install()\n'),
        (b'_rawv2_source.install_admission("azure_log_samples_admission_20261020")\n', b'azure_log_samples_admission_20261020.install()\n'),
        (b'_rawv2_source.install_admission("azure_ml_job_secrets_admission_20261020")\n', b'azure_ml_job_secrets_admission_20261020.install()\n'),
        (b'_rawv2_source.install_admission("azure_databricks_notebook_secrets_admission_20261020")\n', b'azure_databricks_notebook_secrets_admission_20261020.install()\n'),
        (b'_rawv2_source.install_admission("azure_ml_asset_secrets_admission_20261020")\n', b'azure_ml_asset_secrets_admission_20261020.install()\n'),
        (b'_rawv2_source.install_admission("azure_function_settings_runtime_admission_20261020")\n', b'azure_function_settings_runtime_admission_20261020.install()\n'),
    )
    for after, before in rawv2_edits:
        if raw.count(after) != 1:
            raise RuntimeError('RawV2 initializer successor delta changed')
        raw = raw.replace(after, before, 1)
    edits = (
        (b'from . import gcp_positive_conservation_shared_source_successor_20261020 as _positive_shared_source\n', b''),
        (b'aws_workload_command_shared_successor_20261020 = _positive_shared_source\n',
         b'aws_workload_command_shared_successor_20261020 = _deployed_ai_shared_source\n'),
        (b'from peaso import gcp_positive_conservation_source_admission_successor_20261020 as _positive_source\n'
         b'gcp_function_secret_page_admission_20261020.source_inputs = _positive_source.reviewed_inputs\n', b''),
    )
    for after, before in edits:
        if raw.count(after) != 1:
            raise RuntimeError('GCP positive conservation initializer delta ambiguous')
        raw = raw.replace(after, before, 1)
    if hashlib.sha256(raw).hexdigest() != _PREDECESSOR_INIT_SHA256:
        raise RuntimeError('GCP positive conservation initializer predecessor changed')
    return raw


def _initialization_predecessor(raw):
    _private_self()
    receipt = _private_receipt()
    if hashlib.sha256(raw).hexdigest() != receipt['initializer_after_sha256']:
        raise RuntimeError('Private source initializer changed')
    for before, after in reversed(receipt['initializer_edits']):
        before, after = before.encode(), after.encode()
        if raw.count(after) != 1:
            raise RuntimeError('Private source initializer edit changed')
        raw = raw.replace(after, before, 1)
    if hashlib.sha256(raw).hexdigest() != _CURRENT_INIT_SHA256:
        raise RuntimeError('Private source initializer predecessor changed')
    return _published_initialization_predecessor(raw)


def _self(raw):
    value, count = re.subn(rb"(?m)^RECEIPT_SHA256 = '[0-9a-f]{64}'$", b"RECEIPT_SHA256 = '" + b'0' * 64 + b"'", raw)
    if count != 1:
        raise RuntimeError('AWS command successor self binding changed')
    return value


def _reverse(text, row):
    for transition in (() if hashlib.sha256(text.encode()).hexdigest() == row['current_sha256'] else _private_receipt()['provider_group_callables'].values()):
        if row != transition and hashlib.sha256(text.encode()).hexdigest() == transition['current_sha256']:
            text = _reverse(text, transition)
            if hashlib.sha256(text.encode()).hexdigest() != transition['predecessor_sha256']:
                raise RuntimeError('Provider group callable predecessor changed')
            break
    if hashlib.sha256(text.encode()).hexdigest() != row['current_sha256']:
        raise RuntimeError('Deployed AI current source changed: expected=' + row['current_sha256'] + ' observed=' + hashlib.sha256(text.encode()).hexdigest())
    for before, after in row.get('exact_replacements', []):
        if text.count(after) != 1:
            raise RuntimeError('Deployed AI exact replacement changed')
        text = text.replace(after, before, 1)
    for addition in row['exact_additions']:
        if text.count(addition) != 1:
            raise RuntimeError('Deployed AI exact addition changed')
        text = text.replace(addition, '', 1)
    return text


def _compiled_source(raw, filename, optimize):
    """Compile locally without computing the historical unused AST digest."""
    text = raw.decode('utf-8')
    lines = text.splitlines(keepends=True)
    definitions = {}

    def visit(node, prefix=''):
        child_prefix = prefix
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            name = prefix + node.name
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                start = min([node.lineno] + [d.lineno for d in node.decorator_list])
                key = (node.name, start)
                if key in definitions:
                    raise RuntimeError('Ambiguous annotation source definition')
                definitions[key] = {
                    'qualname': name,
                    'source_sha256': hashlib.sha256(''.join(lines[start - 1:node.end_lineno]).encode()).hexdigest(),
                    'source': ''.join(lines[start - 1:node.end_lineno]),
                }
                child_prefix = name + '.<locals>.'
            else:
                child_prefix = name + '.'
        for child in ast.iter_child_nodes(node):
            # Definitions occur only in statement suites, exception handlers
            # and match cases; expression subtrees cannot introduce one.
            if isinstance(child, (ast.stmt, ast.excepthandler, ast.match_case)):
                visit(child, child_prefix)

    tree = ast.parse(text, filename=filename, type_comments=True)
    visit(tree)
    del visit
    records = []

    def walk(code):
        definition = definitions.get((code.co_name, code.co_firstlineno))
        if definition is not None:
            records.append((definition, code))
        for member in code.co_consts:
            if isinstance(member, types.CodeType):
                walk(member)

    walk(compile(tree, filename, 'exec', dont_inherit=True, optimize=optimize))
    del walk
    return records


def _transaction_compiler():
    """Keep only signed immutable compiled artifacts for one install wave."""
    cache = {}
    secret = os.urandom(32)
    source_bytes = 0
    source_cache = {}
    code_cache = {}
    code_bytes = 0

    def immutable(value):
        # Exact builtins only: a tuple/bytes subclass can have mutable methods.
        if type(value) is types.CodeType:
            return all(immutable(item) for item in value.co_consts)
        if type(value) in (tuple, frozenset):
            return all(immutable(item) for item in value)
        if type(value) is slice:
            return all(immutable(item) for item in (value.start, value.stop, value.step))
        return value is None or value is Ellipsis or type(value) in (str, int, bool, float, bytes, complex)

    def normalized(key, code):
        nonlocal code_bytes
        artifact_key = (key, id(code))
        entry = code_cache.get(artifact_key)
        if entry is None:
            if not immutable(code):
                raise RuntimeError('Mutable native code artifact refused')
            value = json.dumps(original.proof._code(code), sort_keys=True)
            signature = hmac.digest(secret, marshal.dumps((artifact_key, value), 2), 'sha256')
            entry = (code, value, signature)
            if len(code_cache) < 4096 and code_bytes + len(value.encode()) <= 4 * 1024 * 1024:
                code_cache[artifact_key] = entry
                code_bytes += len(value.encode())
        saved, value, signature = entry
        # This is a serialization artifact, never a live-function verdict.
        # Exact recursive immutability was checked before retaining this code.
        # The signed key contains its identity; holding the code prevents ID
        # reuse. Replacing live __code__ gets a new key and fresh serialization.
        if (saved is not code or not hmac.compare_digest(signature,
                hmac.digest(secret, marshal.dumps((artifact_key, value), 2), 'sha256'))):
            raise RuntimeError('Normalized code artifact changed')
        return value

    def lookup(key, raw, qualname, native=None, want_source=False):
        nonlocal source_bytes, code_bytes
        if key != (key[0], hashlib.sha256(raw).hexdigest(), sys.flags.optimize):
            raise RuntimeError('Deployed AI compiled cache source binding changed')
        if key not in cache:
            rows = tuple((record['qualname'], record['source_sha256'], code, record['source'])
                         for record, code in _compiled_source(raw, key[0], key[2]))
            # Version 2 has no reference-sharing flags, so holding another
            # reference to an immutable code object cannot change its digest.
            signed = tuple((record, hmac.digest(secret, marshal.dumps((key, record), 2), 'sha256'))
                           for record in rows)
            artifact_bytes = len(raw) + sum(len(row[3].encode()) for row in rows)
            if len(cache) >= 128 or source_bytes + artifact_bytes > 16 * 1024 * 1024:
                cache.clear()
                source_cache.clear()
                code_cache.clear()
                source_bytes = code_bytes = 0
            if artifact_bytes <= 16 * 1024 * 1024:
                cache[key] = signed
                source_bytes += artifact_bytes
        else:
            signed = cache[key]
        matches = []
        source_fragment = None
        for record, signature in signed:
            if record[0] == qualname:
                if not hmac.compare_digest(signature, hmac.digest(secret, marshal.dumps((key, record), 2), 'sha256')):
                    raise RuntimeError('Deployed AI compiled cache artifact changed')
                matches.append(({'qualname': record[0], 'source_sha256': record[1],
                                 'compiled_code_json': normalized(key, record[2])}, record[2]))
                source_fragment = record[3]
        if native is None:
            return matches
        filename = inspect.getsourcefile(native)
        if (not isinstance(filename, str)
                or filename != key[0] and Path(filename).resolve() != Path(key[0])):
            raise RuntimeError('Native CPU inspect source identity changed')
        # Preserve inspect's linecache view as well as the independently reread
        # disk bytes. Mutable cached source lines never share a successful key.
        linecache.checkcache(filename)
        cached_lines = linecache.getlines(filename, native.__globals__)
        line_digest = hashlib.sha256(''.join(cached_lines).encode()).hexdigest()
        code = native.__code__
        source_key = (key, id(code), native.__module__, native.__qualname__,
                      code.co_filename, code.co_firstlineno, line_digest)
        # Validate recursive immutability before retaining an identity artifact.
        live_json = normalized(key, code)
        entry = source_cache.get(source_key)
        if entry is None:
            digest = original.prepared._hash(inspect.getsource(native).encode())
            payload = (source_key, digest)
            signature = hmac.digest(secret, marshal.dumps(payload, 2), 'sha256')
            entry = (code, digest, signature)
            if key in cache and len(source_cache) < 4096:
                source_cache[source_key] = entry
        saved_code, digest, signature = entry
        if (saved_code is not code or not hmac.compare_digest(signature,
                hmac.digest(secret, marshal.dumps((source_key, digest), 2), 'sha256'))):
            raise RuntimeError('Native CPU source cache artifact changed')
        for record, _ in matches:
            record['live_code_json'] = live_json
        return (matches, digest, source_fragment) if want_source else (matches, digest)

    return lookup


def _check_function(fn, row, root, compiled):
    """Reuse compilation only within this admission; recheck every live input."""
    row = current_producer_row(fn, row, root)
    native = inspect.unwrap(fn)
    path = (root / row['path']).resolve()
    if not path.is_relative_to(root):
        raise RuntimeError('metadata runtime source escaped package')
    raw = path.read_bytes()
    key = (str(path), hashlib.sha256(raw).hexdigest(), sys.flags.optimize)
    compiler = _COMPILED_TRANSACTION.get()
    if compiler is None:
        if key not in compiled:
            compiled[key] = _compiled_source(raw, str(path), sys.flags.optimize)
        matches = [(record, code) for record, code in compiled[key] if record['qualname'] == row['qualname']]
        source_digest = original.prepared._hash(inspect.getsource(native).encode())
    else:
        expected = next(code for code in _transaction_compiler.__code__.co_consts
                        if isinstance(code, types.CodeType) and code.co_name == 'lookup')
        if (not isinstance(compiler, types.FunctionType) or compiler.__code__ is not expected
                or compiler.__globals__ is not globals()):
            raise RuntimeError('Deployed AI compiled cache callable changed')
        matches, source_digest = compiler(key, raw, row['qualname'], native)
    expected_source_sha = row['sha256']
    if row['path'].startswith(('peaso/collectors/gcp_', 'peaso/checks/gcp_')):
        from peaso.gcp_private_source_successor_20261021 import _source_delta, _source_hash
        source_rows = _source_delta(root)
        if row['path'] in source_rows:
            _source_hash(row['path'], raw, source_rows[row['path']]['before_sha256'], source_rows)
            if len(matches) != 1:
                raise RuntimeError('GCP positive callable source ambiguous')
            expected_source_sha = matches[0][0]['source_sha256']
    live_json = matches[0][0].get('live_code_json') if len(matches) == 1 else None
    expected_json = matches[0][0].get('compiled_code_json') if len(matches) == 1 else None
    if live_json is None:
        live_json = json.dumps(original.proof._code(native.__code__), sort_keys=True)
    if expected_json is None and len(matches) == 1:
        expected_json = json.dumps(original.proof._code(matches[0][1]), sort_keys=True)
    if (len(matches) != 1 or matches[0][0]['source_sha256'] != expected_source_sha
            or source_digest != expected_source_sha
            or live_json != expected_json
            or native.__globals__ is not vars(sys.modules[native.__module__])
            or json.dumps(native.__defaults__, sort_keys=True) != json.dumps(row['defaults'], sort_keys=True)
            or json.dumps(native.__kwdefaults__, sort_keys=True) != json.dumps(row['kwdefaults'], sort_keys=True)):
        raise RuntimeError('metadata runtime executing callable changed: ' + native.__module__ + ':' + native.__qualname__)


def _verify_bridge(root):
    """Run the unmodified bridge proof and bind the exact initializer delta."""
    _private_self()
    if _COMPILED_TRANSACTION is not _TRANSACTION_CONTEXT:
        raise RuntimeError('GCP positive conservation compiled transaction carrier changed')
    from peaso.gcp_private_source_successor_20261021 import _bridge_source
    _bridge_source(root)
    # Preserve the historical proof, but send its immutable callable rows
    # through this wave's signed artifact cache instead of recompiling the
    # same module once per nested admission. No verification result is cached.
    if historical_bridge._COMPILED_TRANSACTION is not historical_bridge._TRANSACTION_CONTEXT:
        raise RuntimeError('Deployed AI compiled transaction carrier changed')
    raw = (root / 'peaso/checks' / historical_bridge.RECEIPT).read_bytes()
    if hashlib.sha256(raw).hexdigest() != historical_bridge.RECEIPT_SHA256:
        raise RuntimeError('Deployed AI bridge receipt changed')
    receipt = json.loads(raw)
    helper = 'peaso/checks/azure_metadata_only_shared_successor_20261020.py'
    if hashlib.sha256(historical_bridge._self((root / helper).read_bytes())).hexdigest() != receipt['sources'][helper]['sha256']:
        raise RuntimeError('Deployed AI bridge self source changed')
    if historical_bridge._FUNCTIONS != _FUNCTIONS:
        raise RuntimeError('Deployed AI bridge callable snapshot changed')
    compiled = {}
    for qualified, function in _FUNCTIONS.items():
        name = qualified.split(':')[1]
        if vars(historical_bridge).get(name) is not function:
            raise RuntimeError('Deployed AI bridge executing callable replaced: ' + name)
        _check_function(function, receipt['functions'][qualified], root, compiled)
    _initialization_predecessor((root / 'peaso/checks/__init__.py').read_bytes())


def reviewed_delta(root=None):
    root = Path(root or Path(__file__).resolve().parents[2]).resolve()
    _verify_bridge(root)
    verify_metadata_only(root)
    raw = (root / 'peaso/checks' / RECEIPT).read_bytes()
    if hashlib.sha256(raw).hexdigest() != RECEIPT_SHA256:
        raise RuntimeError('AWS command successor receipt changed')
    receipt = json.loads(raw)
    native_raw = (root / 'peaso/checks' / accepted_native.RECEIPT).read_bytes()
    if (hashlib.sha256(native_raw).hexdigest() != accepted_native.RECEIPT_SHA256
            or receipt['accepted_native_receipt_sha256'] != accepted_native.RECEIPT_SHA256):
        raise RuntimeError('No-op native predecessor receipt changed')
    for name, row in receipt['native_epoch_file_deltas'].items():
        restored = _reverse(predecessor_epoch_bytes(name, (root / name).read_bytes(), root).decode('utf-8'), row)
        if hashlib.sha256(restored.encode()).hexdigest() != row['predecessor_sha256']:
            raise RuntimeError('No-op native whole-file epoch changed')
    for name, row in receipt['producer_file_deltas'].items():
        predecessor_producer_bytes(name, (root / name).read_bytes(), root)
    if receipt['accepted_receipt_sha256'] != historical.RECEIPT_SHA256:
        raise RuntimeError('Deployed AI historical receipt binding changed')
    if receipt['accepted_bridge_receipt_sha256'] != accepted.RECEIPT_SHA256:
        raise RuntimeError('JIT READY bridge receipt binding changed')
    prior_raw = (root / 'peaso/checks' / prior_bridge.RECEIPT).read_bytes()
    if (receipt['prior_bridge_receipt_sha256'] != prior_bridge.RECEIPT_SHA256
            or hashlib.sha256(prior_raw).hexdigest() != prior_bridge.RECEIPT_SHA256):
        raise RuntimeError('Native CPU predecessor bridge receipt changed')
    prior_receipt = json.loads(prior_raw)
    for name, row in receipt['prior_epoch_file_deltas'].items():
        restored = _reverse(predecessor_epoch_bytes(name, (root / name).read_bytes(), root).decode('utf-8'), row)
        if hashlib.sha256(restored.encode()).hexdigest() != row['predecessor_sha256']:
            raise RuntimeError('Native CPU whole predecessor epoch changed')
        for section in ('parent_file_deltas', 'integration_file_deltas', 'file_deltas'):
            if name in prior_receipt[section] and row['predecessor_sha256'] != prior_receipt[section][name]['current_sha256']:
                raise RuntimeError('Native CPU predecessor file binding changed')
    accepted_receipt = json.loads((root / 'peaso/checks' / accepted.RECEIPT).read_bytes())
    for name, row in receipt['parent_file_deltas'].items():
        restored = _reverse(predecessor_epoch_bytes(name, (root / name).read_bytes(), root).decode('utf-8'), row)
        if hashlib.sha256(restored.encode()).hexdigest() != row['predecessor_sha256']:
            raise RuntimeError('JIT READY whole-file reconstruction changed: ' + name)
        if name in accepted_receipt['integration_file_deltas']:
            prior = accepted_receipt['integration_file_deltas'][name]
            prior_source = _reverse(restored, prior)
            if hashlib.sha256(prior_source.encode()).hexdigest() != prior['predecessor_sha256']:
                raise RuntimeError('JIT READY historical integration reversal changed: ' + name)
    # This unchanged predecessor verifies WB/DF/CodeBuild historical source,
    # receipts, helpers, the isolated K8s router and prepared native contracts.
    predecessor.predecessor.reviewed_delta(root)
    for name, row in receipt['sources'].items():
        data = (root / name).read_bytes()
        if row['normalization'] == 'self':
            data = _self(data)
        data = _admitted_scanner_bytes(name, data, row['sha256'], root)
        if hashlib.sha256(data).hexdigest() != row['sha256']:
            raise RuntimeError('AWS command successor source changed: ' + name)
    sealed = json.loads((root / 'peaso/checks' / historical.RECEIPT).read_bytes())
    # First reconstruct the *entire* accepted AWS-command epoch. Then the
    # unchanged epoch's exact reversals below reconstruct its own predecessor.
    for name, row in receipt['integration_file_deltas'].items():
        restored = _reverse(predecessor_epoch_bytes(name, (root / name).read_bytes(), root).decode('utf-8'), row)
        if hashlib.sha256(restored.encode()).hexdigest() != row['predecessor_sha256']:
            raise RuntimeError('Deployed AI whole-file historical reconstruction changed: ' + name)
        if name in sealed['file_deltas'] and row['predecessor_sha256'] != sealed['file_deltas'][name]['current_sha256']:
            raise RuntimeError('Deployed AI historical file binding changed: ' + name)
        if name in sealed['file_deltas']:
            previous = _reverse(restored, sealed['file_deltas'][name])
            if hashlib.sha256(previous.encode()).hexdigest() != sealed['file_deltas'][name]['predecessor_sha256']:
                raise RuntimeError('Deployed AI sealed historical reversal changed: ' + name)
        if name == 'peaso/collectors/azure.py':
            azure_receipt = json.loads((root / 'peaso/checks' / predecessor.RECEIPT).read_bytes())
            ancestor = azure_receipt['file_deltas'][name]
            previous = _reverse(restored, ancestor)
            if hashlib.sha256(previous.encode()).hexdigest() != ancestor['predecessor_sha256']:
                raise RuntimeError('JIT sealed Azure package reversal changed')
    compiled = {}
    for qualified, row in receipt['integration_functions'].items():
        owner, name = qualified.split(':')
        function = getattr(importlib.import_module(owner), name)
        if function is not _INTEGRATION_FUNCTIONS[qualified]:
            raise RuntimeError('Deployed AI shared callable replaced: ' + qualified)
        if qualified == 'peaso.collectors.aws_facts_swc:_event_rule':
            facts = importlib.import_module(owner)
            if (function.__closure__ is not _EVENT_RULE_CLOSURE
                    or len(function.__closure__) != 1
                    or function.__closure__[0].cell_contents is not _EVENT_RULE_INNER
                    or facts.ENRICHERS.get('eventbridge_rule') is not function
                    or facts.ENRICHERS.get('event_rule') is not function):
                raise RuntimeError('Deployed AI event-rule wrapper/closure binding changed')
            _check_function(function, row['wrapper'], root, compiled)
            function = _EVENT_RULE_INNER
        try:
            restored = _reverse(inspect.getsource(inspect.unwrap(function)), row)
        except RuntimeError as exc:
            raise RuntimeError('Deployed AI shared source changed: ' + qualified) from exc
        if hashlib.sha256(restored.encode()).hexdigest() != row['predecessor_sha256']:
            raise RuntimeError('Deployed AI shared callable historical reconstruction changed: ' + qualified)
        _check_function(function, row['current'], root, compiled)
    for name, row in receipt['file_deltas'].items():
        restored = predecessor_epoch_bytes(name, (root / name).read_bytes(), root).decode('utf-8')
        for before, after in row.get('exact_replacements', []):
            if restored.count(after) != 1:
                raise RuntimeError('AWS command exact entrypoint changed')
            restored = restored.replace(after, before, 1)
        for addition in row['exact_additions']:
            if restored.count(addition) != 1:
                raise RuntimeError('AWS command exact source addition changed')
            restored = restored.replace(addition, '', 1)
        if hashlib.sha256(restored.encode()).hexdigest() != row['predecessor_sha256']:
            raise RuntimeError('AWS command changed outside admitted source additions')
        # Re-run the previous epoch's exact whole-file reconstruction, on the
        # just-proven previous bytes, without mutating files or guard globals.
        historical_receipt = json.loads((root / 'peaso/checks' / predecessor.RECEIPT).read_bytes())
        if name in historical_receipt['file_deltas']:
            prior = historical_receipt['file_deltas'][name]
            for before, after in prior.get('exact_replacements', []):
                if restored.count(after) != 1:
                    raise RuntimeError('AWS command historical entrypoint changed')
                restored = restored.replace(after, before, 1)
            for addition in prior['exact_additions']:
                if restored.count(addition) != 1:
                    raise RuntimeError('AWS command historical file delta changed')
                restored = restored.replace(addition, '', 1)
            if hashlib.sha256(restored.encode()).hexdigest() != prior['predecessor_sha256']:
                raise RuntimeError('AWS command historical whole-file source changed')
    for qualified, row in receipt['functions'].items():
        module_name, name = qualified.split(':')
        module = importlib.import_module(module_name)
        function = module
        for part in name.split('.'):
            function = getattr(function, part)
        if qualified == 'peaso.checks.gcp_workbench_head3_admission_20261020:reviewed_inputs':
            historical_function = module._ORIGINALS[qualified]
            successor = importlib.import_module('peaso.checks.gcp_cloudrun_job_image_workbench_source_successor_20261020')
            if function not in (historical_function, successor.reviewed_inputs):
                current_source = importlib.import_module('peaso.checks.gcp_private_workbench_head3_source_successor_20261021')
                if function is not current_source.reviewed_inputs:
                    raise RuntimeError('Workbench shared admission alias changed')
                current_source._private_self(root)
            function = historical_function
        if qualified == 'peaso.gcp_function_secret_page_source_20261020:reviewed_inputs':
            successor = importlib.import_module('peaso.gcp_cloudrun_job_image_function_source_successor_20261020')
            historical_function = successor._HISTORICAL_PAGE_REVIEWED_INPUTS
            if function not in (historical_function, successor.reviewed_inputs):
                current_source = importlib.import_module('peaso.gcp_private_source_successor_20261021')
                if function is not current_source.reviewed_inputs:
                    raise RuntimeError('Functions shared runtime admission alias changed')
                current_source._private_receipt(root)
            function = historical_function
        if qualified in _NOOP_FUNCTIONS and function is not _NOOP_FUNCTIONS[qualified]:
            raise RuntimeError('Azure metadata-only canonical no-op callable replaced')
        if qualified in _NATIVE_FUNCTIONS and function is not _NATIVE_FUNCTIONS[qualified]:
            raise RuntimeError('No-op canonical native callable replaced')
        if qualified in _NATIVE_PACKAGE_FUNCTIONS and function is not _NATIVE_PACKAGE_FUNCTIONS[qualified]:
            raise RuntimeError('No-op canonical package CPU callable replaced')
        if qualified in _AUTHORIZATION_FUNCTIONS and function is not _AUTHORIZATION_FUNCTIONS[qualified]:
            raise RuntimeError('No-op current authorization callable replaced')
        if qualified in _PRIOR_FUNCTIONS and function is not _PRIOR_FUNCTIONS[qualified]:
            raise RuntimeError('Native CPU predecessor canonical callable replaced')
        if qualified in _PACKAGE_FUNCTIONS and function is not _PACKAGE_FUNCTIONS[qualified]:
            raise RuntimeError('Native CPU package successor callable replaced')
        if qualified in _ACCEPTED_FUNCTIONS and function is not _ACCEPTED_FUNCTIONS[qualified]:
            raise RuntimeError('JIT READY canonical callable replaced: ' + qualified)
        if qualified in _HISTORICAL_FUNCTIONS and function is not _HISTORICAL_FUNCTIONS[qualified]:
            raise RuntimeError('Deployed AI canonical historical callable replaced: ' + qualified)
        if qualified in _FUNCTIONS and function is not _FUNCTIONS[qualified]:
            raise RuntimeError('AWS command successor callable replaced')
        try:
            _check_function(function, row, root, compiled)
        except RuntimeError as exc:
            raise RuntimeError('AWS command executing callable changed: ' + qualified) from exc
    historical_receipt = json.loads((root / 'peaso/checks' / predecessor.RECEIPT).read_bytes())
    # Existing consumers require the unchanged Azure collection binding.
    receipt['azure_collect'] = historical_receipt['azure_collect']
    transition = _private_receipt()['provider_group_azure_collect']
    receipt['metadata_only_collect']['current_sha256'] = transition['current_sha256']
    receipt['metadata_only_collect']['current']['sha256'] = transition['current_sha256']
    receipt['metadata_only_collect']['exact_additions'] += transition['exact_additions']
    return receipt


def check_shared(fn, historical, name, root, compiled, receipt):
    current = receipt['shared_functions'][name]
    restored = inspect.getsource(inspect.unwrap(fn))
    transition = _private_receipt()['provider_group_callables'].get(fn.__module__.replace('.', '/') + '.py:' + fn.__qualname__)
    if transition is not None:
        restored = _reverse(restored, transition)
        if hashlib.sha256(restored.encode()).hexdigest() != transition['predecessor_sha256']:
            raise RuntimeError('Provider group shared callable predecessor changed')
    layers = [current]
    for module in (predecessor, predecessor.predecessor,
                   predecessor.predecessor.predecessor,
                   predecessor.predecessor.predecessor.predecessor):
        layers.append(json.loads((root / 'peaso/checks' / module.RECEIPT).read_bytes())['shared_functions'][name])
    for row in layers:
        if hashlib.sha256(restored.encode()).hexdigest() != row['current_sha256']:
            raise RuntimeError('AWS command shared executing source changed')
        for addition in row['exact_additions']:
            if restored.count(addition) != 1:
                raise RuntimeError('AWS command inherited source addition changed')
            restored = restored.replace(addition, '', 1)
        if hashlib.sha256(restored.encode()).hexdigest() != row.get('predecessor_sha256', row.get('predecessor', {}).get('sha256')):
            raise RuntimeError('AWS command inherited source epoch changed')
    if hashlib.sha256(restored.encode()).hexdigest() != historical['sha256']:
        raise RuntimeError('AWS command original callable source changed')
    _check_function(fn, dict(historical, sha256=current['current_sha256']), root, compiled)


def _prepared_ast(node):
    """Emit the sealed 3.13 AST format without interpreter dump defaults.

    Only empty list fields and optional None fields are omitted. Every node,
    populated field, literal and ordering remains part of the comparison;
    exact reconstructed source bytes are checked independently first.
    """
    if isinstance(node, ast.AST):
        fields = []
        for name, value in ast.iter_fields(node):
            if (isinstance(value, list) and not value
                    or value is None and getattr(type(node), name, ...) is None):
                continue
            fields.append(name + '=' + _prepared_ast(value))
        return type(node).__name__ + '(' + ', '.join(fields) + ')'
    if isinstance(node, list):
        return '[' + ', '.join(_prepared_ast(value) for value in node) + ']'
    return repr(node)


def _check_prepared_shared(fn, historical, name, root, compiled, successor):
    row = successor['prepared_functions'][name]
    if row['predecessor'] != historical:
        raise RuntimeError('Deployed AI prepared predecessor changed')
    source = inspect.getsource(inspect.unwrap(fn))
    if hashlib.sha256(source.encode()).hexdigest() != row['current_sha256']:
        raise RuntimeError('Deployed AI prepared current source changed')
    restored = source
    for addition in row['exact_additions']:
        if restored.count(addition) != 1:
            raise RuntimeError('Deployed AI prepared exact addition changed')
        restored = restored.replace(addition, '', 1)
    if (hashlib.sha256(restored.encode()).hexdigest() != historical['sha256']
            or _prepared_ast(ast.parse(textwrap.dedent(restored))) != row['predecessor_ast']):
        raise RuntimeError('Deployed AI prepared historical source changed')
    _check_function(fn, dict(historical, sha256=row['current_sha256']), root, compiled)


def prepared_inputs(root, compiled, successor):
    """Retain every sealed prepared guard with portable AST serialization."""
    from . import gcp_workbench_shared_hook_successor_20261020 as workbench
    successor = workbench.reviewed_delta(root)
    prepared, proof = original.prepared, original.proof
    raw = (root / 'peaso/checks' / prepared.RECEIPT).read_bytes()
    if prepared._hash(raw) != prepared.RECEIPT_SHA256:
        raise RuntimeError('metadata predecessor receipt changed')
    receipt = json.loads(raw, object_pairs_hook=proof._pairs)
    if json.dumps(receipt['schema'], sort_keys=True) != json.dumps(prepared._schema(), sort_keys=True):
        raise RuntimeError('metadata predecessor schema changed')
    for relative, expected in receipt['sources'].items():
        path = (root / relative).resolve()
        raw = path.read_bytes()
        if relative == receipt['helper_path']:
            raw = prepared._self(raw)
        raw = _admitted_scanner_bytes(relative, raw, expected, root)
        if not path.is_relative_to(root) or prepared._hash(raw) != expected:
            raise RuntimeError('metadata predecessor source changed')
    assets = json.loads(gzip.decompress((root / 'peaso/checks' / original.ASSETS).read_bytes()), object_pairs_hook=proof._pairs)
    required = [row for row in receipt['fixtures'] if row['path'].startswith('peaso/checks/')
                or row['path'].endswith('/k8s_selected_metadata_secret_native_20261020.json.gz')]
    if set(assets) != {row['path'] for row in required}:
        raise RuntimeError('metadata packaged predecessor assets changed')
    for row in required:
        entry = assets[row['path']]
        if entry['sha256'] != row['sha256'] or prepared._hash(bytes.fromhex(entry['hex'])) != row['sha256']:
            raise RuntimeError('metadata packaged predecessor fixture changed')
    current = prepared._runtime()
    if set(current) != set(prepared._ORIGINALS) or set(current) != set(receipt['functions']):
        raise RuntimeError('metadata predecessor callable set changed')
    for name, fn in current.items():
        if fn is not prepared._ORIGINALS[name] or inspect.unwrap(fn) is not prepared._INNERS[name]:
            raise RuntimeError('metadata predecessor callable replacement')
        if name in successor['prepared_functions']:
            _check_prepared_shared(fn, receipt['functions'][name], name, root, compiled, successor)
        else:
            _check_function(fn, receipt['functions'][name], root, compiled)
        if isinstance(fn, types.FunctionType) and (fn.__code__ is not prepared._CODES[name] or fn.__closure__ != prepared._CLOSURES[name]):
            raise RuntimeError('metadata predecessor wrapper replacement')
    prepared._clone_bindings()
    from peaso.collectors import k8s_network_extensions as network
    if (json.dumps(network.RESOURCES, sort_keys=True) != json.dumps(successor['network_resources'], sort_keys=True)
            or network.BY_ENDPOINT != {(group, plural): kind for kind, (groups, plural, ns) in network.RESOURCES.items() for group in groups}):
        raise RuntimeError('metadata network router map changed')
    _check_function(network.match, successor['network_matcher'], root, compiled)
    for kind, (version, plural, _) in prepared.producer.NATIVE_KINDS.items():
        prefix = '/api/v1' if version == 'v1' else '/apis/' + version
        for path in (prefix + '/namespaces/review/' + plural,
                     prefix + '/namespaces/review/' + plural + '/selected-name'):
            if network.match(path) is not None:
                raise RuntimeError('metadata selected routes overlap network router')


def reviewed_inputs(root=None):
    root = Path(root or Path(__file__).resolve().parents[2]).resolve()
    _verify_bridge(root)
    successor = reviewed_delta(root)
    raw = (root / 'peaso/checks' / original.RECEIPT).read_bytes()
    if original.prepared._hash(raw) != original.RECEIPT_SHA256:
        raise RuntimeError('metadata runtime receipt changed')
    receipt = json.loads(raw, object_pairs_hook=original.proof._pairs)
    compiled = {}
    runtime = original.runtime
    if (receipt['check'] != original.CHECK or runtime.CHECK != original.CHECK
            or runtime.KIND != original.prepared.producer.KIND or runtime.OPTION != original.prepared.producer.OPTION
            or runtime.GRANT != '_k8s_selected_metadata_grant'
            or json.dumps(receipt['declaration'], sort_keys=True) != json.dumps(original.candidate.DECLARATION, sort_keys=True)
            or runtime._Grant is not original._GRANT_CLASS or runtime._TOKEN is not original._TOKEN
            or runtime.source is not original.prepared.producer or original.candidate is not original.prepared.candidate
            or original.k8s.TYPES.count(runtime.KIND) != 1 or runtime.KIND in original.k8s.ENDPOINTS
            or runtime.KIND not in original.engine.BULK_STREAM_TYPES['k8s'] or runtime.OPTION not in original.validation.OPTIONS):
        raise RuntimeError('metadata runtime metadata/binding changed')
    for name, expected in receipt['sources'].items():
        path = (root / name).resolve()
        raw = path.read_bytes()
        if name == receipt['helper_path']:
            raw = original._self(raw)
        raw = _admitted_scanner_bytes(name, raw, expected, root)
        if not path.is_relative_to(root) or original.prepared._hash(raw) != expected:
            raise RuntimeError('metadata runtime source changed')
    for row in receipt['fixtures']:
        path = (root / row['path']).resolve()
        if not path.is_relative_to(root / 'peaso/checks') or original.prepared._hash(path.read_bytes()) != row['sha256']:
            raise RuntimeError('metadata packaged runtime fixture changed')
    prepared_inputs(root, compiled, successor)
    current = original._runtime()
    alias = original.__name__ + ':reviewed_inputs'
    if original.reviewed_inputs is reviewed_inputs:
        if alias in current:
            raise RuntimeError('metadata runtime successor alias changed')
        current[alias] = PREDECESSOR_REVIEWED_INPUTS
    elif original.reviewed_inputs not in (accepted.reviewed_inputs, PREDECESSOR_REVIEWED_INPUTS, historical.reviewed_inputs, predecessor.reviewed_inputs, predecessor.predecessor.reviewed_inputs, predecessor.predecessor.predecessor.reviewed_inputs, predecessor.predecessor.predecessor.predecessor.reviewed_inputs):
        raise RuntimeError('metadata runtime successor alias replaced')
    if set(current) != set(original._ORIGINALS) or set(current) != set(receipt['functions']):
        raise RuntimeError('metadata runtime callable set changed')
    for name, fn in current.items():
        if fn is not original._ORIGINALS[name]:
            raise RuntimeError('metadata runtime callable replacement')
        if name in successor['shared_functions']:
            check_shared(fn, receipt['functions'][name], name, root, compiled, successor)
        else:
            _check_function(fn, receipt['functions'][name], root, compiled)
    cases = json.loads((root / 'peaso/checks' / original.CASES).read_bytes(), object_pairs_hook=original.proof._pairs)
    if set(cases) != {original.CHECK}:
        raise RuntimeError('metadata runtime CASES changed')
    for branch in ('pass', 'fail', 'unknown'):
        if original.candidate.evaluate(deepcopy(cases[original.CHECK][branch]), deepcopy(cases[original.CHECK][branch + '_index']))[0] != branch.upper():
            raise RuntimeError('metadata runtime native witness changed')
    return receipt, cases, deepcopy(original.candidate.DECLARATION), original.candidate.evaluate


def install():
    from . import CHECKS, CHECK_ALIASES, register
    from .fixtures import CASES as store
    receipt, cases, declaration, function = reviewed_inputs()
    # The immutable authorize/collect functions import this original module path.
    # Route only its reviewed-input entrypoint; the historical object is retained
    # and attested separately, while this actual successor source is self-pinned.
    original.reviewed_inputs = reviewed_inputs
    ident = original.CHECK
    if ident in CHECK_ALIASES or ident in CHECK_ALIASES.values():
        raise RuntimeError('metadata runtime alias collision')
    found = [check for check in CHECKS if check.id == ident]
    if found:
        if len(found) != 1 or not original._INSTALLED:
            raise RuntimeError('metadata runtime collision')
        original._verify(found[0], receipt)
        if json.dumps(store.get(ident), sort_keys=True) != json.dumps(cases[ident], sort_keys=True):
            raise RuntimeError('metadata runtime CASES replacement')
        return
    if ident in store:
        raise RuntimeError('metadata runtime CASES collision')
    before = tuple(CHECKS)
    try:
        register(ident, 'k8s', declaration['category'], original.runtime.KIND, declaration['title'], declaration['severity'],
                 'security_configuration', declaration['remediation'], dependencies=[original.runtime.KIND], allow_incomplete_failure=True)(function)
        check = CHECKS[-1]
        setattr(check.evaluate, original.MARK, ident)
        original._verify(check, receipt)
        store[ident] = deepcopy(cases[ident])
        original._INSTALLED = (check.evaluate, original.proof._bindings(check.evaluate)['checked'])
    except Exception:
        CHECKS[:] = before
        store.pop(ident, None)
        raise


def _dataflow_gcp_delta(root, receipt):
    """Retain exact sealed GCP branches using explicit portable AST output."""
    from peaso.collectors import gcp
    archive = json.loads(gzip.decompress((root / receipt['hook_predecessor']).read_bytes()))
    prior = archive['peaso/collectors/gcp.py']
    if hashlib.sha256(prior['content'].encode()).hexdigest() != prior['sha256']:
        raise RuntimeError('Selected job GCP predecessor changed')
    source = (root / 'peaso/collectors/gcp.py').read_text()
    for delta in receipt['gcp_global_additions']:
        if source.count(delta) != 1:
            raise RuntimeError('Selected job GCP global hook changed')
    for name, row in receipt['gcp_function_deltas'].items():
        function = getattr(gcp.GCPCollector, name)
        restored = inspect.getsource(function)
        transition = _private_receipt()['provider_group_callables'].get('peaso/collectors/gcp.py:GCPCollector.' + name)
        if transition is not None:
            restored = _reverse(restored, transition)
        for addition in row['exact_additions']:
            if restored.count(addition) != 1:
                raise RuntimeError('Selected job GCP exact branch changed')
            restored = restored.replace(addition, '', 1)
        if (hashlib.sha256(restored.encode()).hexdigest() != row['predecessor_sha256']
                or _prepared_ast(ast.parse(textwrap.dedent(restored))) != row['predecessor_ast']):
            raise RuntimeError('Selected job GCP non-selected-source branch changed')


def dataflow_reviewed_inputs(root=None):
    """Explicit portable entrypoint; all canonical Dataflow code stays sealed."""
    root = Path(root or Path(__file__).resolve().parents[2]).resolve()
    _verify_bridge(root)
    admission = _DATAFLOW_ADMISSION
    if (sys.modules.get(admission.__name__) is not admission
            or admission.reviewed_inputs not in (_DATAFLOW_REVIEWED_INPUTS, dataflow_reviewed_inputs)
            or admission._FUNCTIONS != _DATAFLOW_FUNCTIONS
            or _DATAFLOW_REVIEWED_INPUTS is not _DATAFLOW_FUNCTIONS[admission.__name__ + ':reviewed_inputs']):
        raise RuntimeError('Deployed AI Dataflow admission entrypoint changed')
    if admission.shared not in (historical, predecessor.predecessor.predecessor, predecessor.predecessor, predecessor, sys.modules[__name__]):
        raise RuntimeError('Deployed AI Dataflow shared alias replaced')
    runtime, candidate = admission.runtime, admission.candidate
    raw = (root / 'peaso/checks' / admission.RECEIPT).read_bytes()
    if hashlib.sha256(raw).hexdigest() != admission.RECEIPT_SHA256:
        raise RuntimeError('Selected job admission receipt changed')
    receipt = json.loads(raw)
    from peaso.gcp_private_source_successor_20261021 import _source_delta, _source_hash
    source_rows = _source_delta(root)
    if (receipt['schema_version'] != 1 or tuple(d['id'] for d in receipt['declarations']) != runtime.CHECKS
            or receipt['declarations'] != candidate.DECLARATIONS
            or runtime._Grant is not admission._GRANT or runtime._SEAL is not admission._SEAL
            or candidate.runtime is not runtime or candidate.dataflow.predecessor.source is not runtime.dataflow
            or candidate.batch.source is not runtime.batch):
        raise RuntimeError('Selected job admission metadata/binding changed')
    for name, digest in receipt['sources'].items():
        path = (root / name).resolve()
        if not path.is_relative_to(root / 'peaso'):
            raise RuntimeError('Selected job admission dependency outside package')
        raw = path.read_bytes()
        if name == receipt['helper_path']:
            raw = admission._self(raw)
        _source_hash(name, raw, digest, source_rows)
    if any(actual is not expected for actual, expected in admission._bindings()):
        raise RuntimeError('Selected job admission imported binding changed')
    public_profiles = {name: {k: p[k] for k in ('check', 'kind', 'marker')} for name, p in runtime.PROFILES.items()}
    if public_profiles != receipt['profiles'] or any(p['source'] is not (runtime.dataflow if name == 'dataflow' else runtime.batch) for name, p in runtime.PROFILES.items()):
        raise RuntimeError('Selected job admission profile changed')
    _dataflow_gcp_delta(root, receipt)
    reviewed_inputs(root)
    compiled = {}
    for qualified, row in receipt['runtime_functions'].items():
        owner_name, attribute = qualified.split(':'); owner = importlib.import_module(owner_name)
        function = owner
        for part in attribute.split('.'):
            function = getattr(function, part)
        if qualified == admission.__name__ + ':reviewed_inputs':
            if function not in (_DATAFLOW_REVIEWED_INPUTS, dataflow_reviewed_inputs):
                raise RuntimeError('Deployed AI Dataflow admission entrypoint replaced')
            function = _DATAFLOW_REVIEWED_INPUTS
        if qualified in _DATAFLOW_FUNCTIONS and function is not _DATAFLOW_FUNCTIONS[qualified]:
            raise RuntimeError('Selected job admission callable replaced')
        _check_function(function, row, root, compiled)
    path = (root / 'peaso/checks' / admission.CASES).resolve()
    if not path.is_relative_to(root / 'peaso/checks') or hashlib.sha256(path.read_bytes()).hexdigest() != receipt['cases_sha256']:
        raise RuntimeError('Selected job native cases changed')
    cases = json.loads(path.read_bytes())
    if set(cases) != set(runtime.CHECKS):
        raise RuntimeError('Selected job native case identities changed')
    declarations = []
    for profile, declaration in zip(runtime.PROFILES, candidate.DECLARATIONS):
        function = getattr(candidate, profile + '_source'); case = cases[declaration['id']]
        for branch in ('pass', 'fail', 'unknown', 'partial', 'missing', 'malformed'):
            status, details = function(deepcopy(case[branch]), deepcopy(case.get(branch + '_index', case['index'])))
            expected = 'FAIL' if branch == 'partial' else branch.upper() if branch in ('pass', 'fail') else 'UNKNOWN'
            if status != expected or branch == 'partial' and details.get('complete') is not False:
                raise RuntimeError('Selected job native branch changed')
        declarations.append((declaration, function))
    return receipt, cases, declarations


def install_dataflow(admission):
    """Publish one checked entrypoint alias, retaining every original function."""
    reviewed_delta()
    if admission is not _DATAFLOW_ADMISSION:
        raise RuntimeError('Deployed AI Dataflow admission module replaced')
    dataflow_reviewed_inputs()
    old_shared, old_reviewed = admission.shared, admission.reviewed_inputs
    admission.shared = sys.modules[__name__]
    admission.reviewed_inputs = dataflow_reviewed_inputs
    try:
        admission.install()
    except Exception:
        admission.shared, admission.reviewed_inputs = old_shared, old_reviewed
        raise


def install_bundle():
    """Release this wave's compilation cache on success and every exception."""
    root = Path(__file__).resolve().parents[2]
    _verify_bridge(root)
    from peaso import gcp_positive_conservation_source_admission_successor_20261020 as canonical_artifacts
    # _verify_bridge freshly proves the canonical provider source, executing
    # functions and defaults before either artifact context is established.
    canonical_context = canonical_artifacts._MODULE_ARTIFACTS
    if (canonical_context is not canonical_artifacts._MODULE_CONTEXT
            or not isinstance(canonical_context, ContextVar)):
        raise RuntimeError('GCP canonical module artifact context changed')
    from peaso import gcp_private_source_successor_20261021 as source_artifacts
    artifact_context = source_artifacts._MODULE_ARTIFACTS
    canonical_token = canonical_context.set(canonical_artifacts._module_compiler())
    try:
        artifact_token = artifact_context.set(source_artifacts._module_compiler())
        try:
            token = _COMPILED_TRANSACTION.set(_transaction_compiler())
            try:
                return _install_bundle()
            finally:
                _COMPILED_TRANSACTION.reset(token)
        finally:
            artifact_context.reset(artifact_token)
    finally:
        canonical_context.reset(canonical_token)



def _install_bundle():
    """Preflight before registry/alias mutation, then roll back this whole wave."""
    _verify_bridge(Path(__file__).resolve().parents[2])
    from . import CHECKS
    from .fixtures import CASES
    from . import gcp_workbench_source_runtime_admission_20261020 as workbench
    from . import gcp_dataflow_batch_source_runtime_admission_20261020 as dataflow
    from . import collector_noop_codebuild_admission_successor_20261020 as codebuild_successor
    codebuild = codebuild_successor.original
    from . import collector_noop_package_admission_successor_20261020 as package
    from . import azure_metadata_only_tde_admission_successor_20261020 as tde
    from . import gcp_function_secret_page_admission_20261020 as function_pairs
    # This validation has no registry or shared-alias writes.
    from . import collector_noop_command_admission_successor_20261020 as commands
    commands.reviewed_inputs()
    package.reviewed_inputs()
    codebuild_successor.reviewed_inputs()
    tde.reviewed_inputs()
    function_pairs.reviewed_inputs()
    ids = {commands.runtime.CHECK, original.CHECK, *workbench.CHECK_IDS, *dataflow.runtime.CHECKS, codebuild.runtime.CHECK, package.runtime.CHECK, *tde.IDS, function_pairs.original.CHECK_ID}
    before = tuple(CHECKS)
    old_cases = {ident: CASES[ident] for ident in ids if ident in CASES}
    old_reviewed, old_installed, old_shared = original.reviewed_inputs, original._INSTALLED, dataflow.shared
    old_dataflow_reviewed = dataflow.reviewed_inputs
    old_package, old_tde = package._INSTALLED, dict(tde.original._INSTALLED)
    old_codebuild_reviewed = codebuild.reviewed_inputs
    old_command_reviewed = commands.runtime.source.reviewed_sources
    old_command_inputs = commands.original.reviewed_inputs
    old_package_inputs = package.original.reviewed_inputs
    try:
        tde.install()
        install()
        from peaso.rawv2_private_source_successor_20261021 import install_admission
        install_admission('gcp_workbench_source_runtime_admission_20261020')
        install_dataflow(dataflow)
        codebuild_successor.install()
        package.install()
        function_pairs.install()
        commands.install()
    except Exception:
        CHECKS[:] = before
        for ident in ids:
            if ident in old_cases:
                CASES[ident] = old_cases[ident]
            else:
                CASES.pop(ident, None)
        original.reviewed_inputs, original._INSTALLED, dataflow.shared = old_reviewed, old_installed, old_shared
        dataflow.reviewed_inputs = old_dataflow_reviewed
        package._INSTALLED = old_package
        package.original._INSTALLED = old_package
        package.original.reviewed_inputs = old_package_inputs
        commands.original.reviewed_inputs = old_command_inputs
        codebuild.reviewed_inputs = old_codebuild_reviewed
        commands.runtime.source.reviewed_sources = old_command_reviewed
        tde.original._INSTALLED.clear()
        tde.original._INSTALLED.update(old_tde)
        raise


def check_aws(function, expected):
    from . import aws_s3_selected_source_admission_20261020 as s3
    receipt = reviewed_delta()
    row = receipt['shared_functions']['aws.collect']
    restored = inspect.getsource(function)
    transition = _private_receipt()['provider_group_callables'].get(function.__module__.replace('.', '/') + '.py:' + function.__qualname__)
    if transition is not None:
        restored = _reverse(restored, transition)
    for layer in (row, json.loads(Path(predecessor.predecessor.__file__).with_suffix('.json').read_bytes())['shared_functions']['aws.collect']):
        if hashlib.sha256(restored.encode()).hexdigest() != layer['current_sha256']:
            raise RuntimeError('AWS command collector source epoch changed')
        for addition in layer['exact_additions']:
            if restored.count(addition) != 1:
                raise RuntimeError('AWS command collector addition changed')
            restored = restored.replace(addition, '', 1)
    if hashlib.sha256(restored.encode()).hexdigest() != expected['sha256']:
        raise RuntimeError('AWS command original S3 collector changed')
    if s3.proof(function) != dict(expected, sha256=transition['current_sha256'] if transition is not None else row['current_sha256']):
        raise RuntimeError('AWS command native collector code changed')


def s3_reviewed_inputs():
    from . import aws_s3_selected_source_admission_20261020 as original
    root = Path(__file__).resolve().parents[2]
    _verify_bridge(root)
    receipt = json.loads((root / 'peaso/checks' / original.RECEIPT).read_bytes())
    reviewed_delta(root)
    for name, digest in receipt['source_hashes'].items():
        path = (root / name).resolve()
        data = _admitted_scanner_bytes(name, path.read_bytes(), digest, root)
        if not path.is_relative_to(root) or hashlib.sha256(data).hexdigest() != digest:
            raise RuntimeError('Selected S3 unchanged source changed')
    for expected in receipt['callables']:
        function = importlib.import_module(expected['module'])
        for name in expected['qualname'].split('.'):
            function = getattr(function, name)
        if expected['module'] == 'peaso.collectors.aws' and expected['qualname'] == 'collect':
            check_aws(function, expected)
        elif expected['module'] == 'peaso.secret_scanning':
            from peaso.rawv2_private_source_successor_20261021 import verify_callable_proof
            verify_callable_proof(function, expected, original.proof(function), root)
        else:
            transition = _private_receipt()['provider_group_callables'].get(function.__module__.replace('.', '/') + '.py:' + function.__qualname__)
            if transition is not None:
                _check_function(function, dict(expected, defaults=None, kwdefaults=None), root, {})
                if original.proof(function) != dict(expected, sha256=transition['current_sha256']):
                    raise RuntimeError('Selected S3 current scope-selection proof changed')
            else:
                from peaso.rawv2_private_source_successor_20261021 import verify_callable_proof
                verify_callable_proof(function, expected, original.proof(function), root)
    from peaso.collectors import aws_s3_selected_source_secret_indicators as producer
    if original.schema(producer) != dict(receipt['producer_schema'], **_private_receipt()['provider_group_s3_schema_additions']):
        raise RuntimeError('Selected S3 producer schema changed')
    for binding in receipt['bindings']:
        left = importlib.import_module(binding['module'])
        right = importlib.import_module(binding['origin_module'])
        if getattr(left, binding['name']) is not getattr(right, binding['origin_name']):
            raise RuntimeError('Selected S3 unchanged imported binding changed')
    fixture = receipt['fixture']
    path = (root / fixture['path']).resolve()
    if not path.is_relative_to(root / 'peaso/checks') or hashlib.sha256(path.read_bytes()).hexdigest() != fixture['sha256']:
        raise RuntimeError('Selected S3 packaged native fixture changed')
    cases = json.loads(path.read_bytes())
    from .aws_s3_selected_source_secret_review_20261020 import CHECK, evaluate
    if set(cases) != {CHECK}:
        raise RuntimeError('Selected S3 native identities changed')
    for branch in ('pass', 'fail', 'unknown'):
        if evaluate(cases[CHECK][branch], cases[CHECK][branch + '_index'])[0] != branch.upper():
            raise RuntimeError('Selected S3 native branch changed')
    return cases


def install_s3():
    # This installer runs before install_bundle; use the same bounded signed
    # artifacts for its own nested proof calls and always release the wave.
    root = Path(__file__).resolve().parents[2]
    from peaso.gcp_private_source_successor_20261021 import _bridge_source
    _bridge_source(root)
    from peaso import gcp_positive_conservation_source_admission_successor_20261020 as canonical_artifacts
    canonical_context = canonical_artifacts._MODULE_ARTIFACTS
    if (canonical_context is not canonical_artifacts._MODULE_CONTEXT
            or not isinstance(canonical_context, ContextVar)):
        raise RuntimeError('GCP canonical module artifact context changed')
    from peaso import gcp_private_source_successor_20261021 as source_artifacts
    artifact_context = source_artifacts._MODULE_ARTIFACTS
    canonical_token = canonical_context.set(canonical_artifacts._module_compiler())
    try:
        artifact_token = artifact_context.set(source_artifacts._module_compiler())
        try:
            token = _COMPILED_TRANSACTION.set(_transaction_compiler())
            try:
                from . import CHECKS,register
                from .fixtures import CASES
                from . import aws_s3_selected_source_secret_review_20261020 as reviewed
                cases=s3_reviewed_inputs();declaration,=reviewed.DECLARATIONS
                old=[c for c in CHECKS if c.id==reviewed.CHECK]
                if old:
                    if len(old)!=1 or inspect.unwrap(old[0].evaluate) is not reviewed.evaluate or old[0].kind!=declaration['kind']:
                        raise RuntimeError('Selected S3 registration collision')
                    if CASES.get(reviewed.CHECK)!=cases[reviewed.CHECK]:raise RuntimeError('Selected S3 registered fixture changed')
                    return
                before=tuple(CHECKS);had_case=reviewed.CHECK in CASES;previous=deepcopy(CASES.get(reviewed.CHECK))
                try:
                    register(reviewed.CHECK,'aws',declaration['category'],declaration['kind'],declaration['title'],'high',
                        'security_configuration',declaration['remediation'],dependencies=declaration['dependencies'],
                        allow_incomplete_failure=True)(reviewed.evaluate)
                    CASES[reviewed.CHECK]=deepcopy(cases[reviewed.CHECK])
                except Exception:
                    CHECKS[:]=before
                    if had_case:CASES[reviewed.CHECK]=previous
                    else:CASES.pop(reviewed.CHECK,None)
                    raise
            finally:
                _COMPILED_TRANSACTION.reset(token)
        finally:
            artifact_context.reset(artifact_token)
    finally:
        canonical_context.reset(canonical_token)




def verify_package_successor(root):
    """Attest every additive helper before its equivalent compiler dispatch."""
    _verify_bridge(root)
    raw = (root / 'peaso/checks' / RECEIPT).read_bytes()
    if hashlib.sha256(raw).hexdigest() != RECEIPT_SHA256:
        raise RuntimeError('Native CPU package bridge receipt changed')
    receipt = json.loads(raw)
    helper = 'peaso/checks/collector_noop_package_admission_successor_20261020.py'
    if (sys.modules.get(_PACKAGE_SUCCESSOR.__name__) is not _PACKAGE_SUCCESSOR
            or hashlib.sha256((root / helper).read_bytes()).hexdigest() != receipt['sources'][helper]['sha256']
            or _PACKAGE_SUCCESSOR.original is not importlib.import_module('peaso.checks.azure_function_package_integration_admission_20261020')):
        raise RuntimeError('Native CPU package successor source/binding changed')
    original_package = _PACKAGE_SUCCESSOR.original
    for name in _PACKAGE_SUCCESSOR.BINDINGS:
        if getattr(_PACKAGE_SUCCESSOR, name) is not getattr(original_package, name):
            raise RuntimeError('Native CPU package historical imported binding changed')
    if _PACKAGE_SUCCESSOR.BINDINGS != tuple(receipt['package_bindings']):
        raise RuntimeError('Native CPU package binding set changed')
    if _PACKAGE_SUCCESSOR._FUNCTIONS != _PACKAGE_FUNCTIONS:
        raise RuntimeError('Native CPU package callable set changed')
    compiled = {}
    for qualified, function in _PACKAGE_FUNCTIONS.items():
        if getattr(_PACKAGE_SUCCESSOR, qualified.split(':')[1]) is not function:
            raise RuntimeError('Native CPU package executing callable replaced')
        _check_function(function, receipt['functions'][qualified], root, compiled)



def predecessor_producer_bytes(relative, raw, root):
    """Reconstruct exactly three former source files; no source reader is changed."""
    if relative != 'peaso/secret_scanning.py':
        raw = _private_before(relative, raw, root)
    if relative == 'peaso/secret_scanning.py':
        from peaso.rawv2_private_source_successor_20261021 import source_bytes, SCANNER_BEFORE
        return source_bytes(relative, raw, SCANNER_BEFORE, root)
    paths = ('peaso/collectors/aws_workload_command_runtime_20261020.py',
             'peaso/collectors/aws_codebuild_buildspec_runtime_20261020.py',
             'peaso/collectors/azure_function_package_integration_20261020.py')
    if relative not in paths:
        return raw
    receipt_raw = (root / 'peaso/checks' / RECEIPT).read_bytes()
    if hashlib.sha256(receipt_raw).hexdigest() != RECEIPT_SHA256:
        raise RuntimeError('No-op producer receipt changed')
    receipt = json.loads(receipt_raw)
    if set(receipt['producer_file_deltas']) != set(paths):
        raise RuntimeError('No-op producer source set changed')
    row = receipt['producer_file_deltas'][relative]
    restored = _reverse(raw.decode('utf-8'), row).encode()
    if hashlib.sha256(restored).hexdigest() != row['predecessor_sha256']:
        raise RuntimeError('No-op producer predecessor source changed')
    return restored


def current_producer_row(function, historical_row, root):
    """Bind only three current authorizers to their exact historical callable rows."""
    if historical_row.get('path') == 'peaso/secret_scanning.py':
        from peaso.rawv2_private_source_successor_20261021 import producer_row
        return producer_row(function, historical_row, root)
    historical_row = _private_row(function, historical_row, root)
    qualified = function.__module__ + ':' + function.__qualname__
    names = ('peaso.collectors.aws_workload_command_runtime_20261020:authorize_collector',
             'peaso.collectors.aws_codebuild_buildspec_runtime_20261020:authorize_collector',
             'peaso.collectors.azure_function_package_integration_20261020:authorize')
    if qualified not in names:
        return historical_row
    raw = (root / 'peaso/checks' / RECEIPT).read_bytes()
    if hashlib.sha256(raw).hexdigest() != RECEIPT_SHA256:
        raise RuntimeError('No-op producer callable receipt changed')
    row = json.loads(raw)['producer_functions'][qualified]
    if historical_row != row['predecessor']:
        raise RuntimeError('No-op historical callable proof changed')
    if function is not _PRODUCER_FUNCTIONS[qualified]:
        raise RuntimeError('No-op producer callable identity changed')
    predecessor_producer_bytes(historical_row['path'], (root / historical_row['path']).read_bytes(), root)
    source = inspect.getsource(inspect.unwrap(function))
    restored = _reverse(source, row)
    if hashlib.sha256(restored.encode()).hexdigest() != historical_row['sha256']:
        raise RuntimeError('No-op producer callable predecessor changed')
    return dict(historical_row, sha256=row['current_sha256'])


def verify_authorization_successors(root):
    """Attest all added owners, their executing functions and canonical bindings."""
    _verify_bridge(root)
    raw = (root / 'peaso/checks' / RECEIPT).read_bytes()
    if hashlib.sha256(raw).hexdigest() != RECEIPT_SHA256:
        raise RuntimeError('No-op authorization successor receipt changed')
    receipt = json.loads(raw)
    compiled = {}
    if set(_PRODUCER_FUNCTIONS) != set(receipt['producer_functions']):
        raise RuntimeError('No-op producer callable set changed')
    for qualified, function in _PRODUCER_FUNCTIONS.items():
        owner, name = qualified.split(':')
        if getattr(importlib.import_module(owner), name) is not function:
            raise RuntimeError('No-op producer executing callable replaced')
        _check_function(function, receipt['producer_functions'][qualified]['predecessor'], root, compiled)
    for module in _AUTHORIZATION_SUCCESSORS:
        if sys.modules.get(module.__name__) is not module:
            raise RuntimeError('No-op authorization successor module changed')
        expected_grant = getattr(module.original, '_GRANT', getattr(module.original, '_GRANT_CLASS', None))
        if module.runtime._Grant is not expected_grant or module.runtime._TOKEN is not module.original._TOKEN:
            raise RuntimeError('No-op typed grant identity changed')
        expected_functions = {name: function for name, function in _AUTHORIZATION_FUNCTIONS.items()
                              if name.startswith(module.__name__ + ':')}
        if module._FUNCTIONS != expected_functions:
            raise RuntimeError('No-op authorization successor callable set changed')
        path = str(Path(module.__file__).resolve().relative_to(root))
        if hashlib.sha256((root / path).read_bytes()).hexdigest() != receipt['sources'][path]['sha256']:
            raise RuntimeError('No-op authorization successor source changed')
        if module.BINDINGS != tuple(receipt['authorization_bindings'][module.__name__]):
            raise RuntimeError('No-op authorization binding set changed')
        for name in module.BINDINGS:
            if getattr(module, name) is not getattr(module.original, name):
                raise RuntimeError('No-op authorization original binding changed')
        if module.original.reviewed_inputs not in (module.HISTORICAL_REVIEWED_INPUTS, module.reviewed_inputs):
            raise RuntimeError('No-op authorization canonical entrypoint changed')
        for qualified, function in module._FUNCTIONS.items():
            if (function is not _AUTHORIZATION_FUNCTIONS[qualified]
                    or getattr(module, qualified.split(':')[1]) is not function):
                raise RuntimeError('No-op authorization successor callable changed')
            _check_function(function, receipt['functions'][qualified], root, compiled)



def predecessor_epoch_bytes(relative, raw, root):
    """Apply the finite initializer delta, then run the old epoch proof."""
    if relative == 'peaso/checks/__init__.py':
        raw = _initialization_predecessor(raw)
    else:
        raw = _private_before(relative, raw, root)
    return historical_bridge.predecessor_epoch_bytes(relative, raw, root)


def predecessor_azure_collect(source, root):
    """Prove the complete current callable then reconstruct its fixed predecessor."""
    _private_self()
    source = _reverse(source, _private_receipt()['provider_group_azure_collect'])
    receipt_raw = (root / 'peaso/checks' / RECEIPT).read_bytes()
    if hashlib.sha256(receipt_raw).hexdigest() != RECEIPT_SHA256:
        raise RuntimeError('Azure metadata-only collect receipt changed')
    receipt = json.loads(receipt_raw)
    row = receipt['metadata_only_collect']
    restored = _reverse(source, row)
    if hashlib.sha256(restored.encode()).hexdigest() != row['predecessor_sha256']:
        raise RuntimeError('Azure metadata-only collect predecessor changed')
    return restored


def verify_metadata_only(root):
    """Bind class identity/attributes and every executing function to exact source."""
    _verify_bridge(root)
    receipt_raw = (root / 'peaso/checks' / RECEIPT).read_bytes()
    if hashlib.sha256(receipt_raw).hexdigest() != RECEIPT_SHA256:
        raise RuntimeError('Azure metadata-only receipt changed')
    receipt = json.loads(receipt_raw)
    prior_raw = (root / 'peaso/checks' / accepted_noop.RECEIPT).read_bytes()
    if (hashlib.sha256(prior_raw).hexdigest() != accepted_noop.RECEIPT_SHA256
            or receipt['accepted_noop_receipt_sha256'] != accepted_noop.RECEIPT_SHA256):
        raise RuntimeError('Azure metadata-only fixed no-op receipt changed')
    prior = json.loads(prior_raw)
    expected_self = {name for name in receipt['functions'] if name.startswith(historical_bridge.__name__ + ':')}
    expected_noop = {name for name in prior['functions'] if name.startswith(accepted_noop.__name__ + ':')}
    if (set(_FUNCTIONS) != expected_self or set(_NOOP_FUNCTIONS) != expected_noop
            or accepted_noop._FUNCTIONS != _NOOP_FUNCTIONS):
        raise RuntimeError('Azure metadata-only callable snapshot carrier changed')
    for key in ('shared_functions', 'integration_functions', 'azure_collect',
                'file_deltas', 'parent_file_deltas', 'integration_file_deltas',
                'prior_epoch_file_deltas', 'native_epoch_file_deltas',
                'producer_file_deltas', 'producer_functions'):
        if receipt[key] != prior[key]:
            raise RuntimeError('Azure metadata-only historical proof row changed')
    if any(receipt['functions'].get(name) != row for name, row in prior['functions'].items()):
        raise RuntimeError('Azure metadata-only historical callable row changed')
    for relative in ('peaso/checks/__init__.py', 'peaso/collectors/azure.py'):
        predecessor_epoch_bytes(relative, (root / relative).read_bytes(), root)
    if (sys.modules.get('peaso.collectors.azure') is not _METADATA_AZURE
            or _METADATA_AZURE.collect is not _METADATA_COLLECT
            or _METADATA_AZURE._MetadataOnlyCollection is not _METADATA_CLASS
            or _METADATA_COLLECT.__globals__ is not vars(_METADATA_AZURE)):
        raise RuntimeError('Azure metadata-only collector/class/global identity changed')
    cls = _METADATA_CLASS
    expected = receipt['metadata_only_class']
    attributes = vars(cls)
    class_keys = {'__module__', '__doc__', '__weakref__'}
    if sys.version_info >= (3, 13):
        class_keys |= {'__firstlineno__', '__static_attributes__'}
        if (type(attributes.get('__firstlineno__')) is not int
                # The exact merged collector source fixes this sentinel location
                # before this unchanged sentinel; predecessor_epoch_bytes above
                # has already verified current bytes and the historical view.
                or (receipt['portable_class_source']['firstlineno'],
                    attributes['__firstlineno__']) != (1820, 1828)
                or type(attributes.get('__static_attributes__')) is not tuple
                or attributes['__static_attributes__'] != ()):
            raise RuntimeError('Portable sentinel interpreter attributes changed')
    if (cls.__bases__ != (Exception,) or cls.__mro__ != (cls, Exception, BaseException, object)
            or set(attributes) != class_keys
            or cls.__module__ != expected['module'] or cls.__qualname__ != expected['qualname']
            or cls.__doc__ != expected['doc'] or attributes['__weakref__'] is not _METADATA_WEAKREF
            or _METADATA_WEAKREF.__objclass__ is not cls
            or cls.__new__ is not Exception.__new__ or cls.__init__ is not Exception.__init__
            or class_source_digest(cls, root, receipt) != expected['source_sha256']):
        raise RuntimeError('Azure metadata-only sentinel class behavior changed')
    compiled = {}
    row = receipt['metadata_only_collect']
    _check_function(_METADATA_COLLECT, row['current'], root, compiled)
    _, _, source_fragment = native_artifacts(_METADATA_COLLECT, root / row['current']['path'])
    restored = predecessor_azure_collect(source_fragment, root)
    if hashlib.sha256(restored.encode()).hexdigest() != prior['azure_collect']['current_sha256']:
        raise RuntimeError('Azure metadata-only exact prior collect row changed')
    if sys.modules.get(_METADATA_TDE.__name__) is not _METADATA_TDE:
        raise RuntimeError('Azure metadata-only TDE module identity changed')
    original_tde = importlib.import_module('peaso.checks.azure_nsp_query_cmk_production_tde_successor_20261020')
    if _METADATA_TDE.original is not original_tde:
        raise RuntimeError('Azure metadata-only TDE predecessor identity changed')
    for name in receipt['metadata_only_tde_bindings']:
        if getattr(_METADATA_TDE, name) is not getattr(original_tde, name):
            raise RuntimeError('Azure metadata-only TDE imported binding changed')
    expected_tde = {name.split(':')[1] for name in receipt['functions'] if name.startswith(_METADATA_TDE.__name__ + ':')}
    if _METADATA_TDE._FUNCTIONS != _METADATA_TDE_FUNCTIONS or set(_METADATA_TDE_FUNCTIONS) != expected_tde:
        raise RuntimeError('Azure metadata-only TDE function set changed')
    for name, function in _METADATA_TDE_FUNCTIONS.items():
        if getattr(_METADATA_TDE, name) is not function:
            raise RuntimeError('Azure metadata-only TDE function identity changed')
        _check_function(function, receipt['functions'][function.__module__ + ':' + name], root, compiled)

def native_artifacts(native, path, raw=None):
    """Read fresh source; reuse only signed compiled/source artifacts in one wave."""
    path = path.resolve()
    raw = path.read_bytes() if raw is None else raw
    key = (str(path), hashlib.sha256(raw).hexdigest(), sys.flags.optimize)
    compiler = _COMPILED_TRANSACTION.get()
    if compiler is None:
        records = _compiled_source(raw, str(path), sys.flags.optimize)
        matches = [(record, code) for record, code in records if record['qualname'] == native.__qualname__]
        source = inspect.getsource(native)
        return matches, hashlib.sha256(source.encode()).hexdigest(), source
    expected = next(code for code in _transaction_compiler.__code__.co_consts
                    if isinstance(code, types.CodeType) and code.co_name == 'lookup')
    if (not isinstance(compiler, types.FunctionType) or compiler.__code__ is not expected
            or compiler.__globals__ is not globals()):
        raise RuntimeError('Portable signed source compiler callable changed')
    return compiler(key, raw, native.__qualname__, native, want_source=True)


def class_source_digest(cls, root, receipt):
    """Recheck full disk and linecache bytes; slice only the pinned AST class span."""
    row = receipt['portable_class_source']
    path = (root / row['path']).resolve()
    filename = inspect.getsourcefile(cls)
    if not isinstance(filename, str) or Path(filename).resolve() != path:
        raise RuntimeError('Portable class source file identity changed')
    raw = path.read_bytes()
    before = _private_before(row['path'], raw, root)
    if hashlib.sha256(before).hexdigest() != receipt['metadata_only_epoch_file_deltas'][row['path']]['current_sha256']:
        raise RuntimeError('Portable class disk source changed')
    linecache.checkcache(filename)
    cached = ''.join(linecache.getlines(filename, vars(_METADATA_AZURE))).encode()
    if cached != raw:
        raise RuntimeError('Portable class linecache source changed')
    lines = before.decode().splitlines(keepends=True)
    return hashlib.sha256(''.join(lines[row['firstlineno'] - 1:row['endlineno']]).encode()).hexdigest()

_FUNCTIONS = historical_bridge._FUNCTIONS

# Capture executing objects before any bridge installer can publish aliases.
_INTEGRATION_FUNCTIONS = {
    'peaso.collectors.azure:_arm_parent_native_type': importlib.import_module('peaso.collectors.azure')._arm_parent_native_type,
    'peaso.collectors.aws:collect': importlib.import_module('peaso.collectors.aws').collect,
    'peaso.collectors.aws:_safe': importlib.import_module('peaso.collectors.aws')._safe,
    'peaso.engine:collect_snapshot': importlib.import_module('peaso.engine').collect_snapshot,
    'peaso.collectors.aws_facts_swc:_event_rule': importlib.import_module('peaso.collectors.aws_facts_swc')._event_rule,
}
_EVENT_RULE_CLOSURE = _INTEGRATION_FUNCTIONS['peaso.collectors.aws_facts_swc:_event_rule'].__closure__
_EVENT_RULE_INNER = _EVENT_RULE_CLOSURE[0].cell_contents

_PRODUCER_FUNCTIONS = {name: getattr(importlib.import_module(name.split(':')[0]), name.split(':')[1]) for name in (
    'peaso.collectors.aws_workload_command_runtime_20261020:authorize_collector',
    'peaso.collectors.aws_codebuild_buildspec_runtime_20261020:authorize_collector',
    'peaso.collectors.azure_function_package_integration_20261020:authorize')}
