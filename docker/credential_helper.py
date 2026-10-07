#!/usr/bin/env python3
"""Expose only the resolved scanner credentials to the upstream SDKs.

The Azure plugins invoke a small subset of Azure CLI authentication commands.
This adapter returns tokens supplied by the host scanner, without reading CLI
caches or selecting another account. No login or cloud mutation is implemented.
"""

import datetime
import json
import os
import pathlib
import sys


def main(argv):
    root = pathlib.Path(os.environ.get("BLUEPEASS_AUTH_DIR", "/input"))
    if argv == ["aws"]:
        print((root / "aws-credentials.json").read_text())
        return 0
    data = json.loads((root / "azure-tokens.json").read_text())
    if argv[:2] == ["account", "get-access-token"]:
        resource = "https://management.azure.com"
        if "--resource-type=ms-graph" in argv or ("--resource-type" in argv and argv[argv.index("--resource-type") + 1] == "ms-graph"):
            resource = "https://graph.microsoft.com"
        for flag in ["--resource", "--scope"]:
            if flag in argv:
                resource = argv[argv.index(flag) + 1]
            for item in argv:
                if item.startswith(flag + "="):
                    resource = item.split("=", 1)[1]
        resource = resource.removesuffix("/.default").rstrip("/")
        token = data["tokens"].get(resource)
        if not token or token["expires_on"] <= datetime.datetime.now().timestamp():
            print("The selected scanner identity has no valid token for audience " + resource + ".", file=sys.stderr)
            return 1
        expiry = datetime.datetime.fromtimestamp(token["expires_on"], datetime.timezone.utc)
        result = {"accessToken": token["token"], "expiresOn": expiry.strftime("%Y-%m-%d %H:%M:%S.%f"),
                  "expires_on": token["expires_on"], "tokenType": "Bearer", "subscription": data["subscription"], "tenant": data["tenant"]}
    elif argv[:2] == ["account", "show"]:
        result = {"id": data["subscription"], "tenantId": data["tenant"], "environmentName": "AzureCloud"}
    elif argv[:2] == ["cloud", "show"]:
        result = {"name": "AzureCloud", "endpoints": {"resourceManager": "https://management.azure.com/", "activeDirectory": "https://login.microsoftonline.com/"}}
    else:
        print("Unsupported Azure credential-adapter command.", file=sys.stderr)
        return 1
    if "--query" in argv:
        key = argv[argv.index("--query") + 1]
        if key not in result:
            return 1
        print(result[key])
    else:
        print(json.dumps(result))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except (OSError, ValueError, KeyError, IndexError):
        print("Resolved scanner credentials are unavailable.", file=sys.stderr)
        sys.exit(1)
