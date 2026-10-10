"""Print only existing Cognito client prerequisite metadata, never credentials."""
import json
import boto3


def main():
    identity = boto3.client("sts", region_name="us-east-1").get_caller_identity()
    if identity["Account"] != "202533532952":
        raise RuntimeError("Expected wiki hosting account")
    client = boto3.client("cognito-idp", region_name="us-east-1")
    data = client.describe_user_pool_client(UserPoolId="us-east-1_7rbhezdKX", ClientId="3g2u5ilb7kbte92lra40ji2ht0")["UserPoolClient"]
    pool = client.describe_user_pool(UserPoolId="us-east-1_7rbhezdKX")["UserPool"]
    print(json.dumps({"account": identity["Account"], "pool_id": pool["Id"], "client_id": data["ClientId"],
        "auth_flows": data.get("ExplicitAuthFlows"), "write_attributes": data.get("WriteAttributes"),
        "username_attributes": pool.get("UsernameAttributes"), "required_attributes": [a["Name"] for a in pool.get("SchemaAttributes", []) if a.get("Required")],
        "client_secret_required": "ClientSecret" in data}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("Cognito prerequisite read failed:", type(exc).__name__)
        raise SystemExit(1)
