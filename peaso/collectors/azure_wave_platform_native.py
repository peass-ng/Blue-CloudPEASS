"""Pure, secret-free predicates for Azure platform evidence.

These helpers consume only already projected ARM metadata. They perform no reads.
"""

import math


def apim_rest_api_has_no_configured_ai_trace(api_diagnostics, service_diagnostics, loggers):
    """Prove no API or service diagnostic can configure AI tracing.

    All three inputs must be complete, independently bound native inventories.
    A service diagnostic is treated as a possible route even when an API-level
    override exists, because optional multiplexing cannot be excluded here.
    A configured route remains undecided because logger credentials are not
    measured. Callers validate ARM identity and provenance first.
    """
    if (not isinstance(api_diagnostics, (list, tuple))
            or not isinstance(service_diagnostics, (list, tuple))
            or not isinstance(loggers, dict)):
        raise ValueError("APIM child inventory malformed")
    configured = False
    for diagnostic in (*api_diagnostics, *service_diagnostics):
        if not isinstance(diagnostic, dict):
            raise ValueError("APIM diagnostic malformed")
        properties = diagnostic.get("properties")
        if not isinstance(properties, dict):
            raise ValueError("APIM diagnostic properties malformed")
        reference = properties.get("loggerId")
        sampling = properties.get("sampling")
        percentage = sampling.get("percentage") if isinstance(sampling, dict) else None
        sampling_type = sampling.get("samplingType") if isinstance(sampling, dict) else None
        always = properties.get("alwaysLog")
        if (not isinstance(reference, str) or not reference
                or sampling_type != "fixed"
                or type(percentage) not in (int, float)
                or not math.isfinite(percentage) or not 0 <= percentage <= 100
                or "alwaysLog" not in properties or always not in (None, "allErrors")):
            raise ValueError("APIM diagnostic metadata incomplete")
        logger = loggers.get(reference.casefold())
        if logger is None:
            continue
        logger_properties = logger.get("properties") if isinstance(logger, dict) else None
        if not isinstance(logger_properties, dict) or logger_properties.get("loggerType") not in {
                "applicationInsights", "azureMonitor", "azureEventHub"}:
            raise ValueError("APIM logger type unresolved")
        if (logger_properties["loggerType"] == "applicationInsights"
                and (percentage > 0 or always == "allErrors")):
            configured = True
    return not configured
