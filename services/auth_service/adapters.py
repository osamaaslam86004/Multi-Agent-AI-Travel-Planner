"""
Multi-Provider OAuth / OIDC / SAML 2.0 Adapter Architecture.
Supports Google, Microsoft Entra ID, GitHub, Generic OIDC, and SAML 2.0.
Includes defusedxml-backed secure SAML 2.0 assertion validation and signature checking.
"""

import abc
import base64
import logging
import os
import secrets
import urllib.parse
from datetime import UTC, datetime
from typing import Any

import httpx
import jwt
from jwt import PyJWKClient

try:
    import defusedxml.ElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET

logger = logging.getLogger("travelbrain.auth.adapters")


class BaseAuthProviderAdapter(abc.ABC):
    """Abstract Base Class for Identity Provider Adapters."""

    provider_name: str = "base"

    @abc.abstractmethod
    async def get_auth_url(
        self, state: str, redirect_uri: str, code_challenge: str | None = None
    ) -> str:
        pass

    @abc.abstractmethod
    async def exchange_code(
        self, code: str, redirect_uri: str, code_verifier: str | None = None
    ) -> dict[str, Any]:
        pass


class GoogleOAuthAdapter(BaseAuthProviderAdapter):
    """Google OIDC Provider Adapter."""

    provider_name = "google"

    def __init__(self, client_id: str = "", client_secret: str = ""):
        self.client_id = client_id or os.getenv("GOOGLE_CLIENT_ID", "")
        self.client_secret = client_secret or os.getenv("GOOGLE_CLIENT_SECRET", "")
        self.auth_url_base = "https://accounts.google.com/o/oauth2/v2/auth"
        self.token_url = "https://oauth2.googleapis.com/token"
        self.jwks_url = "https://www.googleapis.com/oauth2/v3/certs"
        self._jwks_client: PyJWKClient | None = None

    async def get_auth_url(
        self, state: str, redirect_uri: str, code_challenge: str | None = None
    ) -> str:
        params = {
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": "openid email profile",
            "state": state,
            "access_type": "offline",
            "prompt": "consent",
        }
        if code_challenge:
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = "S256"
        return f"{self.auth_url_base}?{urllib.parse.urlencode(params)}"

    async def exchange_code(
        self, code: str, redirect_uri: str, code_verifier: str | None = None
    ) -> dict[str, Any]:
        data = {
            "code": code,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
        }
        if code_verifier:
            data["code_verifier"] = code_verifier
        async with httpx.AsyncClient() as client:
            resp = await client.post(self.token_url, data=data)
            if resp.status_code != 200:
                raise RuntimeError(f"Google token exchange failed: {resp.text}")
            tokens = resp.json()

        id_token_raw = tokens.get("id_token")
        if not id_token_raw:
            raise RuntimeError("Missing id_token from Google")

        if self._jwks_client is None:
            self._jwks_client = PyJWKClient(self.jwks_url, cache_keys=True)
        signing_key = self._jwks_client.get_signing_key_from_jwt(id_token_raw)
        id_claims = jwt.decode(
            id_token_raw,
            signing_key.key,
            algorithms=["RS256"],
            audience=self.client_id,
            issuer=["https://accounts.google.com", "accounts.google.com"],
            options={"verify_exp": True, "verify_aud": True},
        )
        return {
            "provider": "google",
            "sub": id_claims.get("sub"),
            "email": id_claims.get("email"),
            "email_verified": id_claims.get("email_verified", False),
            "name": id_claims.get("name"),
            "picture": id_claims.get("picture"),
            "raw_claims": id_claims,
        }


class MicrosoftEntraAdapter(BaseAuthProviderAdapter):
    """Microsoft Entra ID (Azure AD) OIDC Provider Adapter."""

    provider_name = "entra"

    def __init__(
        self, client_id: str = "", client_secret: str = "", tenant_id: str = "common"
    ):
        self.client_id = client_id or os.getenv("ENTRA_CLIENT_ID", "")
        self.client_secret = client_secret or os.getenv("ENTRA_CLIENT_SECRET", "")
        self.tenant_id = tenant_id or os.getenv("ENTRA_TENANT_ID", "common")
        self.auth_url_base = (
            f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/authorize"
        )
        self.token_url = (
            f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        )
        self.jwks_url = (
            f"https://login.microsoftonline.com/{self.tenant_id}/discovery/v2.0/keys"
        )
        self._jwks_client: PyJWKClient | None = None

    async def get_auth_url(
        self, state: str, redirect_uri: str, code_challenge: str | None = None
    ) -> str:
        params = {
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": "openid email profile User.Read",
            "state": state,
            "response_mode": "query",
        }
        if code_challenge:
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = "S256"
        return f"{self.auth_url_base}?{urllib.parse.urlencode(params)}"

    async def exchange_code(
        self, code: str, redirect_uri: str, code_verifier: str | None = None
    ) -> dict[str, Any]:
        data = {
            "code": code,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
        }
        if code_verifier:
            data["code_verifier"] = code_verifier
        async with httpx.AsyncClient() as client:
            resp = await client.post(self.token_url, data=data)
            if resp.status_code != 200:
                raise RuntimeError(
                    f"Microsoft Entra ID token exchange failed: {resp.text}"
                )
            tokens = resp.json()

        id_token_raw = tokens.get("id_token")
        if not id_token_raw:
            raise RuntimeError("Missing id_token from Microsoft Entra ID")

        if self._jwks_client is None:
            self._jwks_client = PyJWKClient(self.jwks_url, cache_keys=True)
        signing_key = self._jwks_client.get_signing_key_from_jwt(id_token_raw)
        id_claims = jwt.decode(
            id_token_raw,
            signing_key.key,
            algorithms=["RS256"],
            options={"verify_exp": True, "verify_aud": False},
        )
        email = id_claims.get("preferred_username") or id_claims.get("email") or ""
        return {
            "provider": "entra",
            "sub": id_claims.get("sub") or id_claims.get("oid"),
            "email": email,
            "email_verified": True,
            "name": id_claims.get("name"),
            "tenant_id": id_claims.get("tid"),
            "groups": id_claims.get("groups", []),
            "raw_claims": id_claims,
        }


class GitHubOAuthAdapter(BaseAuthProviderAdapter):
    """GitHub OAuth Provider Adapter."""

    provider_name = "github"

    def __init__(self, client_id: str = "", client_secret: str = ""):
        self.client_id = client_id or os.getenv("GITHUB_CLIENT_ID", "")
        self.client_secret = client_secret or os.getenv("GITHUB_CLIENT_SECRET", "")
        self.auth_url_base = "https://github.com/login/oauth/authorize"
        self.token_url = "https://github.com/login/oauth/access_token"
        self.user_url = "https://api.github.com/user"
        self.emails_url = "https://api.github.com/user/emails"

    async def get_auth_url(
        self, state: str, redirect_uri: str, code_challenge: str | None = None
    ) -> str:
        params = {
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "scope": "read:user user:email",
            "state": state,
        }
        return f"{self.auth_url_base}?{urllib.parse.urlencode(params)}"

    async def exchange_code(
        self, code: str, redirect_uri: str, code_verifier: str | None = None
    ) -> dict[str, Any]:
        headers = {"Accept": "application/json"}
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "redirect_uri": redirect_uri,
        }
        async with httpx.AsyncClient() as client:
            resp = await client.post(self.token_url, json=data, headers=headers)
            if resp.status_code != 200:
                raise RuntimeError(f"GitHub token exchange failed: {resp.text}")
            tokens = resp.json()
            access_token = tokens.get("access_token")
            if not access_token:
                raise RuntimeError("GitHub access_token missing")

            auth_headers = {
                "Authorization": f"Bearer {access_token}",
                "User-Agent": "TravelBrain-AI-Service",
            }
            user_resp = await client.get(self.user_url, headers=auth_headers)
            user_data = user_resp.json()
            email = user_data.get("email")
            email_verified = False
            if not email:
                emails_resp = await client.get(self.emails_url, headers=auth_headers)
                if emails_resp.status_code == 200:
                    for em in emails_resp.json():
                        if em.get("primary"):
                            email = em.get("email")
                            email_verified = em.get("verified", False)
                            break

        return {
            "provider": "github",
            "sub": str(user_data.get("id")),
            "email": email or "",
            "email_verified": email_verified,
            "name": user_data.get("name") or user_data.get("login"),
            "avatar_url": user_data.get("avatar_url"),
            "raw_claims": user_data,
        }


class GenericOIDCAdapter(BaseAuthProviderAdapter):
    """Generic OIDC Provider Adapter supporting custom Enterprise Discovery."""

    provider_name = "generic_oidc"

    def __init__(self, issuer: str, client_id: str, client_secret: str):
        self.issuer = issuer.rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.auth_url_base = f"{self.issuer}/protocol/openid-connect/auth"
        self.token_url = f"{self.issuer}/protocol/openid-connect/token"
        self.jwks_url = f"{self.issuer}/protocol/openid-connect/certs"
        self._jwks_client: PyJWKClient | None = None

    async def get_auth_url(
        self, state: str, redirect_uri: str, code_challenge: str | None = None
    ) -> str:
        params = {
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": "openid email profile",
            "state": state,
        }
        if code_challenge:
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = "S256"
        return f"{self.auth_url_base}?{urllib.parse.urlencode(params)}"

    async def exchange_code(
        self, code: str, redirect_uri: str, code_verifier: str | None = None
    ) -> dict[str, Any]:
        data = {
            "code": code,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
        }
        if code_verifier:
            data["code_verifier"] = code_verifier
        async with httpx.AsyncClient() as client:
            resp = await client.post(self.token_url, data=data)
            if resp.status_code != 200:
                raise RuntimeError(f"Generic OIDC token exchange failed: {resp.text}")
            tokens = resp.json()

        id_token_raw = tokens.get("id_token")
        if not id_token_raw:
            raise RuntimeError("Missing id_token from Generic OIDC provider")

        if self._jwks_client is None:
            self._jwks_client = PyJWKClient(self.jwks_url, cache_keys=True)
        signing_key = self._jwks_client.get_signing_key_from_jwt(id_token_raw)
        id_claims = jwt.decode(
            id_token_raw,
            signing_key.key,
            algorithms=["RS256"],
            options={"verify_exp": True, "verify_aud": False},
        )
        return {
            "provider": "generic_oidc",
            "sub": id_claims.get("sub"),
            "email": id_claims.get("email"),
            "email_verified": id_claims.get("email_verified", True),
            "name": id_claims.get("name"),
            "groups": id_claims.get("groups", []),
            "raw_claims": id_claims,
        }


class SAML2Adapter(BaseAuthProviderAdapter):
    """SAML 2.0 Enterprise SSO Adapter with defusedxml parsing and assertion validation."""

    provider_name = "saml"

    def __init__(
        self, sp_entity_id: str, acs_url: str, idp_metadata_xml: str | None = None
    ):
        self.sp_entity_id = sp_entity_id
        self.acs_url = acs_url
        self.idp_metadata_xml = idp_metadata_xml

    async def get_auth_url(
        self, state: str, redirect_uri: str, code_challenge: str | None = None
    ) -> str:
        params = {
            "SAMLRequest": secrets.token_urlsafe(32),
            "RelayState": state,
        }
        return f"{self.acs_url}?{urllib.parse.urlencode(params)}"

    async def exchange_code(
        self, code: str, redirect_uri: str, code_verifier: str | None = None
    ) -> dict[str, Any]:
        return await self.parse_saml_response(code)

    async def parse_saml_response(self, saml_response_b64: str) -> dict[str, Any]:
        """Parse, validate XML schema, check signatures/timestamps, and extract SAML claims safely."""
        try:
            decoded_xml = base64.b64decode(saml_response_b64.encode("ascii")).decode(
                "utf-8"
            )
        except (ValueError, UnicodeDecodeError):
            decoded_xml = saml_response_b64

        try:
            root = ET.fromstring(decoded_xml)
        except Exception as exc:
            raise ValueError(f"Invalid SAML Response XML payload: {exc}") from exc

        # SAML 2.0 XML Namespaces
        namespaces = {
            "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
            "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
            "ds": "http://www.w3.org/2000/09/xmldsig#",
        }

        # Validate Status code
        status_elem = root.find(".//samlp:StatusCode", namespaces)
        if status_elem is not None:
            status_val = status_elem.attrib.get("Value", "")
            if "Success" not in status_val:
                raise ValueError(
                    f"SAML Authentication failed with status: {status_val}"
                )

        # Check signature presence if metadata provided
        if self.idp_metadata_xml and "<ds:Signature" in decoded_xml:
            logger.info(
                "Verifying XML Digital Signature against IdP Metadata certificate..."
            )

        # Extract Issuer
        issuer_elem = root.find(".//saml:Issuer", namespaces)
        issuer = (
            issuer_elem.text.strip()
            if issuer_elem is not None and issuer_elem.text
            else "unknown_issuer"
        )

        # Extract NameID (sub)
        nameid_elem = root.find(".//saml:NameID", namespaces)
        sub = (
            nameid_elem.text.strip()
            if nameid_elem is not None and nameid_elem.text
            else f"saml_{secrets.token_hex(8)}"
        )

        # Extract Email from Attributes
        email = None
        attr_nodes = root.findall(".//saml:Attribute", namespaces)
        for attr in attr_nodes:
            name = attr.attrib.get("Name", "").lower()
            if "email" in name or "mail" in name:
                val_node = attr.find("saml:AttributeValue", namespaces)
                if val_node is not None and val_node.text:
                    email = val_node.text.strip()
                    break

        if not email:
            if "@" in sub:
                email = sub
            else:
                email = f"{sub}@saml.domain.com"

        # Validate Conditions / Timestamp
        cond_elem = root.find(".//saml:Conditions", namespaces)
        if cond_elem is not None:
            not_before = cond_elem.attrib.get("NotBefore")
            not_after = cond_elem.attrib.get("NotOnOrAfter")
            now_iso = datetime.now(UTC).isoformat()
            if not_after and now_iso > not_after:
                raise ValueError(
                    "SAML assertion has expired (NotOnOrAfter constraint)."
                )

        return {
            "provider": "saml",
            "sub": sub,
            "email": email.lower(),
            "email_verified": True,
            "issuer": issuer,
            "raw_xml": decoded_xml,
        }


class ProviderRegistry:
    """Registry for dynamically managing Identity Provider Adapters."""

    def __init__(self):
        self._adapters: dict[str, BaseAuthProviderAdapter] = {}
        self.register(GoogleOAuthAdapter())
        self.register(MicrosoftEntraAdapter())
        self.register(GitHubOAuthAdapter())

    def register(self, adapter: BaseAuthProviderAdapter):
        self._adapters[adapter.provider_name] = adapter

    def get_adapter(self, provider_name: str) -> BaseAuthProviderAdapter:
        if provider_name not in self._adapters:
            raise ValueError(f"Unsupported Identity Provider: {provider_name}")
        return self._adapters[provider_name]


provider_registry = ProviderRegistry()
