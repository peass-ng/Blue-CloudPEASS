"""Local bearer identities and verification against the existing Cognito pool."""
from dataclasses import dataclass
import hmac
import secrets
import jwt
from fastapi import HTTPException
from .secrets import private_file


@dataclass(frozen=True)
class Identity:
    tenant_id: str
    paid: bool = False
    auth_kind: str = "user"
    cognito_username: str | None = None
    email: str | None = None
    email_verified: bool | None = None
    name: str | None = None
    plan_source: str | None = None
    plan_expires_at: float | None = None
    workspace_role: str = "admin"

    @property
    def weekly_limit(self):
        return 10 if self.paid else 1


class Authenticator:
    def __init__(self, settings, cognito=None, jwks=None, entitlements=None):
        self.settings = settings
        self.cognito = cognito
        self.jwks = jwks
        self.entitlements = entitlements
        self.plan_authority = None
        self.store = None
        self.token = None
        if settings.auth_mode == "local":
            self.token = settings.local_token or private_file(settings.identity_dir / "local.token", lambda: secrets.token_urlsafe(32).encode()).decode()
            if len(self.token) < 24:
                raise ValueError("Local token must contain at least 24 characters")
        elif settings.auth_mode == "cognito":
            if not settings.issuer.startswith("https://cognito-idp.") or not settings.audience:
                raise ValueError("Existing Cognito issuer and client ID are required")
            self.jwks = jwks or jwt.PyJWKClient(settings.issuer + "/.well-known/jwks.json", timeout=5)
            if cognito is None:
                import boto3
                self.cognito = boto3.client("cognito-idp", region_name=settings.issuer.split(".")[1])
            from .billing import ProtectedToolsPlan
            self.plan_authority = ProtectedToolsPlan(self.cognito, settings.issuer.rsplit("/", 1)[1], settings.audience)
        else:
            raise ValueError("Unsupported authentication mode")

    def authenticate(self, authorization: str | None) -> Identity:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(401, "Bearer authentication required")
        token = authorization[7:]
        if self.settings.auth_mode == "local":
            if not hmac.compare_digest(token, self.token):
                raise HTTPException(401, "Invalid authentication")
            return Identity("local")
        try:
            key = self.jwks.get_signing_key_from_jwt(token).key
            claims = jwt.decode(token, key, algorithms=["RS256"], issuer=self.settings.issuer,
                                audience=self.settings.audience, options={"require": ["exp", "iat", "iss", "sub", "aud"]})
            if claims.get("token_use") != "id":
                raise ValueError("ID token required")
            tenant = claims["sub"]
            if not isinstance(tenant, str) or not tenant:
                raise ValueError("Invalid subject")
        except Exception:
            raise HTTPException(401, "Invalid authentication") from None
        attributes = self.live_user(tenant, claims.get("cognito:username", tenant))
        email, name, email_verified = self.public_profile(attributes)
        paid, source, expires_at = self.entitlement(
            tenant, username=claims.get("cognito:username", tenant), attributes=attributes)
        return Identity(tenant, paid,
                        cognito_username=claims.get("cognito:username", tenant), email=email,
                        email_verified=email_verified, name=name,
                        plan_source=source, plan_expires_at=expires_at)

    @staticmethod
    def public_profile(attributes):
        """Display identity from live Cognito attributes, never caller-supplied claims."""
        def clean(value, maximum):
            if not isinstance(value, str):
                return None
            value = value.strip()
            return value if value and len(value) <= maximum and all(ord(char) >= 32 and ord(char) != 127 for char in value) else None
        # This is display data from the live, subject-matched Cognito user. An
        # unverified address can identify the account in the UI, but must never
        # become billing or tenant authorization evidence.
        email = clean(attributes.get("email"), 254)
        if email is not None and "@" not in email:
            email = None
        verified = attributes.get("email_verified") == "true" if email is not None else None
        return email, clean(attributes.get("name"), 120), verified

    def find_user_by_email(self, email: str):
        """Resolve a verified, enabled account from the live user directory."""
        if self.settings.auth_mode != "cognito":
            return None
        escaped = email.replace("\\", "\\\\").replace('"', '\\"')
        arguments = {"UserPoolId": self.settings.issuer.rsplit("/", 1)[1],
                     "Filter": f'email = "{escaped}"', "Limit": 60}
        while True:
            response = self.cognito.list_users(**arguments)
            for candidate in response.get("Users", []):
                if not candidate.get("Enabled") or candidate.get("UserStatus") == "UNCONFIRMED":
                    continue
                attributes = {item["Name"]: item["Value"] for item in candidate.get("Attributes", [])}
                if attributes.get("email", "").casefold() == email.casefold() and attributes.get("email_verified") == "true" and attributes.get("sub"):
                    return {"user_id": attributes["sub"], "email": attributes["email"]}
            if not response.get("PaginationToken"):
                break
            arguments["PaginationToken"] = response["PaginationToken"]
        return None

    def authenticate_refresh(self, refresh_token: str) -> Identity:
        if self.settings.auth_mode != "cognito":
            raise HTTPException(401, "Bearer authentication required")
        try:
            response = self.cognito.initiate_auth(ClientId=self.settings.audience, AuthFlow="REFRESH_TOKEN_AUTH", AuthParameters={"REFRESH_TOKEN": refresh_token})
            token = response["AuthenticationResult"]["IdToken"]
        except Exception:
            raise HTTPException(401, "Invalid authentication") from None
        return self.authenticate("Bearer " + token)

    def live_user(self, tenant, username=None):
        pool = self.settings.issuer.rsplit("/", 1)[1]
        try:
            user = self.cognito.admin_get_user(UserPoolId=pool, Username=username or tenant)
        except Exception as exc:
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            if code in {"UserNotFoundException", "NotAuthorizedException"}:
                raise HTTPException(401, "Invalid authentication") from None
            raise HTTPException(503, "Identity verification temporarily unavailable") from None
        attrs = {a["Name"]: a["Value"] for a in user.get("UserAttributes", [])}
        if user.get("Enabled") is not True or attrs.get("sub") != tenant:
            raise HTTPException(401, "Invalid authentication")
        return attrs

    def entitlement(self, tenant: str, username: str | None = None, attributes=None):
        """Return (paid, authority, expiry) after live subject verification."""
        if self.settings.auth_mode == "local":
            return False, None, None
        # Callers with preverified attributes came from live_user, never a JWT
        # claim, request body or API-key record. Worker calls verify live here.
        attrs = self.live_user(tenant, username) if attributes is None else attributes
        if self.store is not None:
            from .admin_qa import AUTHORITY, active_grant
            try:
                grant = self.store.get_admin_qa_grant(tenant)
            except Exception:
                # An unreadable grant never creates paid authority.
                grant = None
            if isinstance(grant, dict):
                # A second live check prevents an identity disabled between
                # the first lookup and entitlement resolution from retaining
                # paid authority. HTTP 401/503 propagates; it is not billing
                # cache failure and must not be swallowed.
                grant_attrs = self.live_user(tenant, username)
                if active_grant(grant, tenant=tenant,
                                pool_id=self.settings.issuer.rsplit("/", 1)[1],
                                client_id=self.settings.audience, attributes=grant_attrs):
                    return True, AUTHORITY, grant["hard_expires_at"]
        plan = self.plan_authority.plan(attrs) if self.plan_authority is not None else None
        if plan is not None:
            return plan == "pentester", "protected_tools_plan", None
        try:
            if self.store is not None:
                cached = self.store.get_entitlement(tenant)
                if cached is not None:
                    return cached, "stripe", None
            if self.entitlements is None:
                from .billing import StripeEntitlements
                self.entitlements = StripeEntitlements()
            paid = self.entitlements.paid(attrs)
            if self.store is not None:
                self.store.set_entitlement(tenant, paid, 3600 if paid else 60)
            return paid, "stripe", None
        except Exception:
            return False, None, None

    def is_paid(self, tenant: str, username: str | None = None, attributes=None) -> bool:
        return self.entitlement(tenant, username, attributes)[0]
