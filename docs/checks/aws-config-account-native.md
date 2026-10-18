# AWS Config across enabled Regions

`aws_nist_config_enabled_all_regions` emits one account-global verdict. It joins the existing STS caller identity and complete EC2 DescribeRegions(AllRegions=True) response to Config recorder, recorder-status and delivery-channel reads in every enabled Region. It does not consume company-provided enabled-region or global-resource-region lists. No cloud operation was added.

PASS requires a complete account/capture-bound join and compliant recording in every enabled Region. A complete empty recorder/channel or proven stopped/restricted recorder produces FAIL. Missing, denied, partial, duplicated, foreign or malformed discovery or regional evidence cannot produce PASS. Not-opted-in Regions are outside the enabled set.

Global resource recording is still required: when includeGlobalResourceTypes is false and applicability cannot be established from the native proof, the result remains UNKNOWN. Known commercial, China and GovCloud Region/partition shapes are supported; unfamiliar shapes remain UNKNOWN. Explicit regional scans cannot claim complete account coverage without authoritative discovery.

The runtime inventory is config_account_region_coverage, derived from existing provider reads. Historical signed source provenance retains its original config_recorder resource-kind reference. Old stored results are not reclassified by a code update.
