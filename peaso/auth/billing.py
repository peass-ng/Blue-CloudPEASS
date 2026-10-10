"""Live Stripe entitlement verification; browser/Cognito plan flags are untrusted."""
import os
import requests


class StripeEntitlements:
    def __init__(self, *, secret=None, price=None, session=None, secrets_client=None):
        self.secret = secret
        self.price = price or os.getenv("PEASO_STRIPE_PRICE_ID")
        self.secret_arn = os.getenv("PEASO_STRIPE_SECRET_ARN")
        self.session = session or requests.Session()
        self.secrets_client = secrets_client

    def _key(self):
        if self.secret:
            return self.secret
        if not self.secret_arn:
            return None
        if self.secrets_client is None:
            import boto3
            self.secrets_client = boto3.client("secretsmanager")
        return self.secrets_client.get_secret_value(SecretId=self.secret_arn).get("SecretString", "").strip()

    def _get(self, path, key, params=None):
        response = self.session.get("https://api.stripe.com/v1/" + path, headers={"Authorization": "Bearer " + key}, params=params, timeout=(3, 8))
        response.raise_for_status()
        return response.json()

    def paid(self, attributes):
        try:
            email = attributes.get("email", "").strip().lower()
            customer_id = attributes.get("custom:stripe_customer_id", "")
            if attributes.get("email_verified") != "true" or not email or not customer_id.startswith("cus_") or not customer_id.replace("_", "").isalnum() or not self.price:
                return False
            key = self._key()
            if not key:
                return False
            customer = self._get("customers/" + customer_id, key)
            metadata = customer.get("metadata", {})
            if customer.get("deleted") or metadata.get("source") != "hacktricks-tools" or customer.get("email", "").lower() != email or metadata.get("user_email", "").lower() != email:
                return False
            cursor = None
            for _ in range(5):
                params = {"customer": customer_id, "status": "all", "limit": 100}
                if cursor:
                    params["starting_after"] = cursor
                page = self._get("subscriptions", key, params)
                for subscription in page.get("data", []):
                    if subscription.get("customer") != customer_id or subscription.get("status") not in {"active", "trialing"}:
                        continue
                    if subscription.get("metadata", {}).get("source") != "hacktricks-tools":
                        continue
                    if any(item.get("price", {}).get("id") == self.price for item in subscription.get("items", {}).get("data", [])):
                        return True
                if not page.get("has_more") or not page.get("data"):
                    break
                cursor = page["data"][-1]["id"]
        except Exception:
            # Billing outage, malformed data, or missing identity proof is free tier.
            pass
        return False
