"""Existing immutable-image predicate with practical verified archive capacities.

No verdict, evidence or binding logic changes. The collector validates compressed
digests/rootfs hashes against the same archive limits before emitting witnesses.
Installation into the registered catalog is a separate integration transaction.
"""
from types import FunctionType
from . import gcp_image_secret_review_20261019 as predecessor
from peaso import container_image_archive_20261020 as archive

_globals = {**vars(predecessor), 'MAX_LAYER': archive.MAX_LAYER,
            'MAX_IMAGE': archive.MAX_COMPRESSED, 'MAX_EXPANDED': archive.MAX_EXPANDED,
            'MAX_LAYERS': archive.MAX_LAYERS, 'MAX_MEMBERS': archive.MAX_MEMBERS}
evaluate = FunctionType(predecessor.evaluate.__code__, _globals, 'evaluate',
                        predecessor.evaluate.__defaults__, predecessor.evaluate.__closure__)
evaluate.__kwdefaults__ = dict(predecessor.evaluate.__kwdefaults__ or {})


def install():
    """Replace only the existing image predicate after the grouped integration."""
    from dataclasses import replace
    from . import CHECKS, register
    matches = [index for index, check in enumerate(CHECKS) if check.id == predecessor.CHECK_ID]
    if len(matches) != 1:
        raise RuntimeError('one existing selected GCP image check required')
    index = matches[0]
    check = CHECKS[index]
    if getattr(check.evaluate, '__wrapped__', None) is evaluate:
        return
    if (check.provider != 'gcp' or check.kind != 'artifact_image'
            or getattr(check.evaluate, '__wrapped__', None) is not predecessor.evaluate):
        raise RuntimeError('unexpected selected GCP image predicate')
    # Build the ordinary register() safety wrapper in a private output list.
    # Replacing the registry row with a bare predicate would bypass its native
    # fact guard/exception normalization; mutating the shared list during wrapper
    # creation would expose transient duplicate/missing entries to readers.
    prepared = []
    registrar = FunctionType(register.__code__, {**register.__globals__, 'CHECKS': prepared},
                             register.__name__, register.__defaults__, register.__closure__)
    registrar.__kwdefaults__ = dict(register.__kwdefaults__ or {})
    registrar(check.id, check.provider, check.category, check.kind, check.title,
              check.severity, check.control, check.remediation, target=check.target,
              dependencies=check.declared_dependencies,
              allow_incomplete_failure=check.allow_incomplete_failure,
              empty_applicability_dependencies=check.empty_applicability_dependencies)(evaluate)
    CHECKS[index] = replace(check, evaluate=prepared[0].evaluate)
