"""Live Stripe entitlement verification; browser/Cognito plan flags are untrusted."""
import os
import threading
import time
import requests


class ProtectedToolsPlan:
    """Use the shared Tools plan only while every pool client cannot write it."""

    _PAGE_SIZE = 60
    _MAX_PAGES = 2  # A larger or incomplete client inventory fails closed.

    def __init__(self, cognito, user_pool_id, app_client_id, *, clock=time.monotonic):
        self.cognito = cognito
        self.user_pool_id = user_pool_id
        self.app_client_id = app_client_id
        self.clock = clock
        self._lock = threading.Lock()
        self._protected = False
        self._expires_at = 0.0

    def _read_protection(self):
        client_ids = set()
        cursor = None
        cursors = set()
        for _ in range(self._MAX_PAGES):
            request = {"UserPoolId": self.user_pool_id, "MaxResults": self._PAGE_SIZE}
            if cursor:
                request["NextToken"] = cursor
            page = self.cognito.list_user_pool_clients(**request)
            if not isinstance(page, dict) or not isinstance(page.get("UserPoolClients"), list):
                return False
            clients = page["UserPoolClients"]
            if len(clients) > self._PAGE_SIZE or (cursor and not clients):
                return False
            for client in clients:
                if not isinstance(client, dict):
                    return False
                ident = client.get("ClientId")
                if (not isinstance(ident, str) or not ident or ident in client_ids
                        or client.get("UserPoolId") != self.user_pool_id):
                    return False
                client_ids.add(ident)
            next_cursor = page.get("NextToken")
            if next_cursor is None:
                break
            if not isinstance(next_cursor, str) or not next_cursor or next_cursor in cursors:
                return False
            cursors.add(next_cursor)
            cursor = next_cursor
        else:
            return False
        if self.app_client_id not in client_ids:
            return False
        for ident in sorted(client_ids):
            response = self.cognito.describe_user_pool_client(UserPoolId=self.user_pool_id, ClientId=ident)
            client = response.get("UserPoolClient") if isinstance(response, dict) else None
            if not isinstance(client, dict) or client.get("UserPoolId") != self.user_pool_id or client.get("ClientId") != ident:
                return False
            writes = client.get("WriteAttributes")
            # Cognito's omitted WriteAttributes means default broad write access.
            if not isinstance(writes, list) or not writes or not all(isinstance(value, str) for value in writes):
                return False
            if any(value.strip().casefold() in {"custom:plan", "custom:*", "*"} for value in writes):
                return False
        return True

    def plan(self, attributes):
        now = self.clock()
        with self._lock:
            if now >= self._expires_at:
                try:
                    self._protected = self._read_protection()
                except Exception:
                    self._protected = False
                self._expires_at = self.clock() + (30 if self._protected else 5)
            if not self._protected or not isinstance(attributes, dict):
                return None
            value = attributes.get("custom:plan")
            if not isinstance(value, str):
                return None
            plan = value.strip().casefold()
            return plan if plan in {"free", "pentester"} else None


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
