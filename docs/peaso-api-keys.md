# External read-only API keys

In **Settings → API keys**, give a key a name and optional expiry. Copy the secret when it appears: the API returns it only in the creation response. Store it in your external tool's secret manager. Settings later shows only the name, display prefix, creation, expiry, revocation, and last-use times. Each account can keep at most 20 unrevoked keys; revoke an old key to free a slot.

Use the key as a Bearer token over HTTPS. The initial key scope permits account GET reads, including account and usage, sanitized connectors, schedules, scans, paginated findings, coverage, maps, inventory metadata and individual native resources, catalog, and report downloads. It cannot create other keys, start scans, edit connectors or schedules, change quota, or retrieve stored cloud connector credentials. Revocation takes effect on the next request; expiry and a disabled or deleted hosted identity also stop access.

```sh
export PEASO_API='https://cspm.hacktricks.wiki/api'
export PEASO_KEY='<secret copied once from Settings>'

curl --fail-with-body --header "Authorization: Bearer $PEASO_KEY" "$PEASO_API/me"
curl --fail-with-body --header "Authorization: Bearer $PEASO_KEY" "$PEASO_API/scans"
curl --fail-with-body --header "Authorization: Bearer $PEASO_KEY" "$PEASO_API/scans/<scan-id>/findings?sort_by=severity&sort_order=desc&offset=0&limit=100"
curl --fail-with-body --header "Authorization: Bearer $PEASO_KEY" "$PEASO_API/scans/<scan-id>/resources?offset=0&limit=100"
```

For findings, repeat the request with `offset` increased by `limit` until all `total` items have been read. Filters (`categories`, `framework`, `severity`, `service`, `status`, `search`) and all six sort fields (`severity`, `title`, `service`, `account`, `status`, `resource_id`) are applied before pagination. Inventory returns metadata; the individual resource route `/scans/<scan-id>/resources/<url-encoded-resource-id>` supplies stored native facts where available.

Report downloads use either a direct response in local mode or a short-lived private artifact URL in hosted mode. In hosted mode, extract `download_url` and fetch it promptly without sending the API key to artifact storage:

```sh
json_url=$(curl --fail-with-body --header "Authorization: Bearer $PEASO_KEY" "$PEASO_API/scans/<scan-id>/report?format=json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["download_url"])')
curl --fail-with-body "$json_url" -o report.json
markdown_url=$(curl --fail-with-body --header "Authorization: Bearer $PEASO_KEY" "$PEASO_API/scans/<scan-id>/report?format=markdown" | python3 -c 'import json,sys; print(json.load(sys.stdin)["download_url"])')
curl --fail-with-body "$markdown_url" -o report.md
```

For local mode, the report endpoint responds with the file directly; use `curl --header "Authorization: Bearer $PEASO_KEY" "$PEASO_API/scans/<scan-id>/report?format=json" -o report.json`.

Rotate a key by creating a replacement in Settings, updating the external secret, checking a GET request, and revoking the old key in Settings. Only a signed-in user can create, list, or revoke keys; API keys cannot manage themselves. The local API's existing bearer token remains a separate login credential, and hosted cookie writes keep their Origin check.
