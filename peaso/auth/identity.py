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

    @property
    def weekly_limit(self):
        return 10 if self.paid else 1


class Authenticator:
    def __init__(self, settings, cognito=None, jwks=None, entitlements=None):
        self.settings = settings
        self.cognito = cognito
        self.jwks = jwks
        self.entitlements = entitlements
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
        return Identity(tenant, self.is_paid(tenant, claims.get("cognito:username", tenant)))

    def authenticate_refresh(self, refresh_token: str) -> Identity:
        if self.settings.auth_mode != "cognito":
            raise HTTPException(401, "Bearer authentication required")
        try:
            response = self.cognito.initiate_auth(ClientId=self.settings.audience, AuthFlow="REFRESH_TOKEN_AUTH", AuthParameters={"REFRESH_TOKEN": refresh_token})
            token = response["AuthenticationResult"]["IdToken"]
        except Exception:
            raise HTTPException(401, "Invalid authentication") from None
        return self.authenticate("Bearer " + token)

    def is_paid(self, tenant: str, username: str | None = None) -> bool:
        """Resolve live Cognito identity and independently verify Stripe billing."""
        if self.settings.auth_mode == "local":
            return False
        pool = self.settings.issuer.rsplit("/", 1)[1]
        try:
            if self.store is not None:
                cached = self.store.get_entitlement(tenant)
                if cached is not None:
                    return cached
            user = self.cognito.admin_get_user(UserPoolId=pool, Username=username or tenant)
            attrs = {a["Name"]: a["Value"] for a in user.get("UserAttributes", [])}
            if user.get("Enabled") is not True or attrs.get("sub") != tenant:
                return False
            if self.entitlements is None:
                from .billing import StripeEntitlements
                self.entitlements = StripeEntitlements()
            paid = self.entitlements.paid(attrs)
            if self.store is not None:
                self.store.set_entitlement(tenant, paid, 3600 if paid else 60)
            return paid
        except Exception:
            return False
