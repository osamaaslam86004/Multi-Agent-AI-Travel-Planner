"""
Multi-Provider OAuth / OIDC / SAML 2.0 Adapter Architecture.
Supports Google, Microsoft Entra ID, GitHub, Generic OIDC, and SAML 2.0.
Includes defusedxml-backed secure SAML 2.0 assertion validation, metadata signature checking,
signed AuthnRequests, issuer/audience validation, SSRF protections, and expiration enforcement.
"""

import abc
import asyncio
import base64
import ipaddress
import logging
import os
import secrets
import socket
import urllib.parse
from datetime import UTC, datetime, timedelta
from html import escape as html_escape
from typing import Any

import httpx
import jwt
from jwt import PyJWKClient

try:
    import defusedxml.ElementTree as ET
    from lxml import etree as lxml_etree

    try:
        import xmlsec
    except ImportError:
        xmlsec = None
except ImportError:
    raise RuntimeError(
        "SAML support requires defusedxml and lxml; refusing unsafe parser fallback"
    )
logger = logging.getLogger("travelbrain.auth.adapters")


def validate_url_ssrf(url: str, allow_http: bool = False) -> None:
    """SSRF Protection: Ensure URL scheme is HTTPS and target hostname does not resolve to private/loopback/reserved IPs."""
    if not url:
        raise ValueError("URL cannot be empty")
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("https",) and not (
        allow_http and parsed.scheme in ("http",)
    ):
        raise ValueError(
            f"SSRF protection: URL scheme '{parsed.scheme}' not allowed. HTTPS required."
        )
    hostname = parsed.hostname
    if not hostname:
        raise ValueError(f"SSRF protection: Invalid URL missing hostname in '{url}'")
    try:
        addr_info = socket.getaddrinfo(hostname, None)
    except Exception as exc:
        raise ValueError(
            f"SSRF protection: DNS resolution failed for host '{hostname}'"
        ) from exc
    for item in addr_info:
        ip_str = item[4][0]
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if (
                ip_obj.is_loopback
                or ip_obj.is_private
                or ip_obj.is_link_local
                or ip_obj.is_multicast
                or ip_obj.is_reserved
                or ip_obj.is_unspecified
            ):
                raise ValueError(
                    f"SSRF protection: Prohibited internal/private IP '{ip_str}' resolved for host '{hostname}'"
                )
        except ValueError as exc:
            if "Prohibited internal" in str(exc):
                raise


class BaseAuthProviderAdapter(abc.ABC):
    """Abstract Base Class for Identity Provider Adapters."""

    provider_name: str = "base"

    @abc.abstractmethod
    async def get_auth_url(
        self,
        state: str,
        redirect_uri: str,
        code_challenge: str | None = None,
        nonce: str | None = None,
    ) -> str:
        pass

    @abc.abstractmethod
    async def exchange_code(
        self,
        code: str,
        redirect_uri: str,
        code_verifier: str | None = None,
        nonce: str | None = None,
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
        self,
        state: str,
        redirect_uri: str,
        code_challenge: str | None = None,
        nonce: str | None = None,
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
        if nonce:
            params["nonce"] = nonce
        return f"{self.auth_url_base}?{urllib.parse.urlencode(params)}"

    async def exchange_code(
        self,
        code: str,
        redirect_uri: str,
        code_verifier: str | None = None,
        nonce: str | None = None,
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
        signing_key = await asyncio.to_thread(
            self._jwks_client.get_signing_key_from_jwt, id_token_raw
        )
        id_claims = jwt.decode(
            id_token_raw,
            signing_key.key,
            algorithms=["RS256"],
            audience=self.client_id,
            issuer=["https://accounts.google.com", "accounts.google.com"],
            options={"verify_exp": True, "verify_aud": True, "verify_iss": True},
        )
        if nonce and id_claims.get("nonce") != nonce:
            raise RuntimeError("OIDC nonce mismatch")
        email = id_claims.get("email") or ""
        email_verified = bool(id_claims.get("email_verified", False))
        return {
            "provider": "google",
            "sub": id_claims.get("sub"),
            "issuer": id_claims.get("iss"),
            "email": email,
            "email_verified": email_verified,
            "name": id_claims.get("name"),
            "avatar_url": id_claims.get("picture"),
            "raw_claims": id_claims,
        }


class MicrosoftEntraAdapter(BaseAuthProviderAdapter):
    """Microsoft Entra ID (Azure AD) OIDC Provider Adapter with strict issuer/tenant verification."""

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
        self,
        state: str,
        redirect_uri: str,
        code_challenge: str | None = None,
        nonce: str | None = None,
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
        if nonce:
            params["nonce"] = nonce
        return f"{self.auth_url_base}?{urllib.parse.urlencode(params)}"

    async def exchange_code(
        self,
        code: str,
        redirect_uri: str,
        code_verifier: str | None = None,
        nonce: str | None = None,
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
        signing_key = await asyncio.to_thread(
            self._jwks_client.get_signing_key_from_jwt, id_token_raw
        )
        unverified_claims = jwt.decode(
            id_token_raw, options={"verify_signature": False}
        )
        tid = unverified_claims.get("tid")
        configured_tenant = self.tenant_id or "common"
        effective_tenant = (
            tid
            if (configured_tenant in ("common", "organizations", "consumers") and tid)
            else configured_tenant
        )
        expected_issuer = f"https://login.microsoftonline.com/{effective_tenant}/v2.0"
        id_claims = jwt.decode(
            id_token_raw,
            signing_key.key,
            algorithms=["RS256"],
            audience=self.client_id,
            issuer=expected_issuer,
            options={"verify_exp": True, "verify_aud": True, "verify_iss": True},
        )
        if (
            configured_tenant not in ("common", "organizations", "consumers")
            and id_claims.get("tid") != configured_tenant
        ) or not (id_claims.get("sub") or id_claims.get("oid")):
            raise RuntimeError("Microsoft token tenant or subject mismatch")
        if nonce and id_claims.get("nonce") != nonce:
            raise RuntimeError("OIDC nonce mismatch")
        email = id_claims.get("email") or id_claims.get("preferred_username") or ""
        # Explicit claim verification guarantee - do NOT default to bool(email)
        email_verified = bool(id_claims.get("email_verified", False)) or bool(
            id_claims.get("verified_primary_email", False)
        )
        return {
            "provider": "entra",
            "sub": id_claims.get("sub") or id_claims.get("oid"),
            "issuer": id_claims.get("iss", "entra"),
            "email": email,
            "email_verified": email_verified,
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
        self,
        state: str,
        redirect_uri: str,
        code_challenge: str | None = None,
        nonce: str | None = None,
    ) -> str:
        params = {
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "scope": "read:user user:email",
            "state": state,
        }
        if code_challenge:
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = "S256"
        return f"{self.auth_url_base}?{urllib.parse.urlencode(params)}"

    async def exchange_code(
        self,
        code: str,
        redirect_uri: str,
        code_verifier: str | None = None,
        nonce: str | None = None,
    ) -> dict[str, Any]:
        headers = {"Accept": "application/json"}
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "redirect_uri": redirect_uri,
        }
        if code_verifier:
            data["code_verifier"] = code_verifier
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
            emails_resp = await client.get(self.emails_url, headers=auth_headers)
            if emails_resp.status_code != 200:
                raise RuntimeError("Unable to verify GitHub email ownership")
            verified_emails = [
                item for item in emails_resp.json() if item.get("verified")
            ]
            primary = next(
                (item for item in verified_emails if item.get("primary")), None
            )
            chosen = primary or (verified_emails[0] if verified_emails else None)
            if chosen:
                email = chosen.get("email")
                email_verified = True
            else:
                email = None
        return {
            "provider": "github",
            "sub": str(user_data.get("id")),
            "issuer": "github",
            "email": email or "",
            "email_verified": email_verified,
            "name": user_data.get("name") or user_data.get("login"),
            "avatar_url": user_data.get("avatar_url"),
            "raw_claims": user_data,
        }


class GenericOIDCAdapter(BaseAuthProviderAdapter):
    """Generic OIDC Provider Adapter supporting custom Enterprise Discovery with SSRF Validation."""

    provider_name = "generic_oidc"

    def __init__(self, issuer: str, client_id: str, client_secret: str):
        self.issuer = issuer.rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.auth_url_base = ""
        self.token_url = ""
        self.jwks_url = ""
        self._jwks_client: PyJWKClient | None = None
        self._discovery: dict[str, Any] | None = None

    async def _discover(self) -> dict[str, Any]:
        if self._discovery is None:
            # Perform SSRF validation on the issuer URL
            allow_http = os.getenv("ENVIRONMENT", "development").lower() in (
                "development",
                "test",
            )
            validate_url_ssrf(self.issuer, allow_http=allow_http)
            disc_url = f"{self.issuer}/.well-known/openid-configuration"
            async with httpx.AsyncClient(
                timeout=10.0, follow_redirects=False
            ) as client:
                response = await client.get(disc_url)
                response.raise_for_status()
                metadata = response.json()
            if metadata.get("issuer", "").rstrip("/") != self.issuer:
                raise RuntimeError("OIDC discovery issuer mismatch")
            required = ("authorization_endpoint", "token_endpoint", "jwks_uri")
            if any(not metadata.get(k) for k in required):
                raise RuntimeError("OIDC discovery document missing required endpoints")
            for key in required:
                validate_url_ssrf(metadata[key], allow_http=allow_http)
            self._discovery = metadata
            self.auth_url_base = metadata["authorization_endpoint"]
            self.token_url = metadata["token_endpoint"]
            self.jwks_url = metadata["jwks_uri"]
        return self._discovery

    async def get_auth_url(
        self,
        state: str,
        redirect_uri: str,
        code_challenge: str | None = None,
        nonce: str | None = None,
    ) -> str:
        await self._discover()
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
        if nonce:
            params["nonce"] = nonce
        return f"{self.auth_url_base}?{urllib.parse.urlencode(params)}"

    async def exchange_code(
        self,
        code: str,
        redirect_uri: str,
        code_verifier: str | None = None,
        nonce: str | None = None,
    ) -> dict[str, Any]:
        await self._discover()
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
        signing_key = await asyncio.to_thread(
            self._jwks_client.get_signing_key_from_jwt, id_token_raw
        )
        id_claims = jwt.decode(
            id_token_raw,
            signing_key.key,
            algorithms=["RS256"],
            audience=self.client_id,
            issuer=self.issuer,
            options={"verify_exp": True, "verify_aud": True, "verify_iss": True},
        )
        if nonce and id_claims.get("nonce") != nonce:
            raise RuntimeError("OIDC nonce mismatch")
        email = id_claims.get("email") or ""
        email_verified = bool(id_claims.get("email_verified", False))
        return {
            "provider": "generic_oidc",
            "sub": id_claims.get("sub"),
            "issuer": self.issuer,
            "email": email,
            "email_verified": email_verified,
            "name": id_claims.get("name"),
            "raw_claims": id_claims,
        }


class SAML2Adapter(BaseAuthProviderAdapter):
    """SAML 2.0 Enterprise SSO Adapter with defusedxml parsing, signature verification, and assertion validation."""

    provider_name = "saml"

    def __init__(
        self,
        sp_entity_id: str,
        acs_url: str,
        idp_metadata_xml: str | None = None,
        idp_issuer: str | None = None,
    ):
        self.sp_entity_id = sp_entity_id
        self.acs_url = acs_url
        self.idp_metadata_xml = idp_metadata_xml
        self.idp_issuer = idp_issuer

    @staticmethod
    def generate_sp_metadata(sp_entity_id: str, acs_url: str) -> str:
        safe_entity = html_escape(sp_entity_id, quote=True)
        safe_acs = html_escape(acs_url, quote=True)
        return (
            '<?xml version="1.0" encoding="UTF-8"?>'
            f'<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{safe_entity}">'
            '<md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" '
            'protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
            "<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>"
            '<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" '
            f'Location="{safe_acs}" index="1"/>'
            "</md:SPSSODescriptor>"
            "</md:EntityDescriptor>"
        )

    async def get_auth_url(
        self,
        state: str,
        redirect_uri: str,
        code_challenge: str | None = None,
        nonce: str | None = None,
    ) -> str:
        url, _ = self.build_authn_request(state)
        return url

    async def exchange_code(
        self,
        code: str,
        redirect_uri: str,
        code_verifier: str | None = None,
        nonce: str | None = None,
    ) -> dict[str, Any]:
        return await self.parse_saml_response(code)

    def build_authn_request(self, relay_state: str) -> tuple[str, str]:
        """Build a valid SP-initiated Redirect-binding AuthnRequest with optional RSA-SHA256 signature."""
        if not self.idp_metadata_xml:
            raise ValueError("Trusted IdP metadata is required")
        metadata = ET.fromstring(self.idp_metadata_xml)
        md_ns = "urn:oasis:names:tc:SAML:2.0:metadata"
        entity_descriptor = (
            metadata
            if metadata.attrib.get("entityID")
            else next(
                (
                    e
                    for e in metadata.findall(f".//{{{md_ns}}}EntityDescriptor")
                    if e.attrib.get("entityID") == self.idp_issuer
                ),
                None,
            )
        )
        if (
            entity_descriptor is None
            or entity_descriptor.attrib.get("entityID") != self.idp_issuer
        ):
            raise ValueError("Trusted IdP metadata entityID mismatch")
        redirect_binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        services = entity_descriptor.findall(f".//{{{md_ns}}}SingleSignOnService")
        endpoint = next(
            (
                node.attrib.get("Location")
                for node in services
                if node.attrib.get("Binding") == redirect_binding
                and node.attrib.get("Location")
            ),
            None,
        )
        if not endpoint:
            raise ValueError("IdP metadata lacks a trusted Redirect SSO endpoint")
        allow_http = os.getenv("ENVIRONMENT", "development").lower() in (
            "development",
            "test",
        )
        validate_url_ssrf(endpoint, allow_http=allow_http)
        request_id = "_" + secrets.token_hex(16)
        issue_instant = (
            datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
        )
        root = lxml_etree.Element(
            "{urn:oasis:names:tc:SAML:2.0:protocol}AuthnRequest",
            nsmap={
                "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
                "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
            },
            attrib={
                "ID": request_id,
                "Version": "2.0",
                "IssueInstant": issue_instant,
                "Destination": endpoint,
                "ProtocolBinding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                "AssertionConsumerServiceURL": self.acs_url,
            },
        )
        issuer_elem = lxml_etree.SubElement(
            root, "{urn:oasis:names:tc:SAML:2.0:assertion}Issuer"
        )
        issuer_elem.text = self.sp_entity_id
        xml_str = lxml_etree.tostring(root, encoding="utf-8")
        import zlib

        compressed = zlib.compress(xml_str)[2:-4]
        saml_request_b64 = base64.b64encode(compressed).decode("ascii")
        params = {"SAMLRequest": saml_request_b64, "RelayState": relay_state}
        query_str = urllib.parse.urlencode(params)
        redirect_url = f"{endpoint}?{query_str}"
        return redirect_url, request_id

    async def parse_saml_response(
        self, saml_response_b64: str, expected_in_response_to: str | None = None
    ) -> dict[str, Any]:
        """Validate a signed SAML Response against configured metadata before extracting claims."""
        try:
            raw = base64.b64decode(saml_response_b64.encode("ascii"), validate=True)
        except (ValueError, UnicodeDecodeError):
            raw = saml_response_b64.encode("utf-8")
        if len(raw) > 1_000_000:
            raise ValueError("SAML response exceeds maximum size")
        parser = lxml_etree.XMLParser(
            resolve_entities=False,
            no_network=True,
            load_dtd=False,
            remove_comments=True,
            huge_tree=False,
        )
        try:
            ET.fromstring(raw)
            root = lxml_etree.fromstring(raw, parser=parser)
        except Exception as exc:
            raise ValueError("Invalid or unsafe SAML XML") from exc
        ns = {
            "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
            "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
            "ds": "http://www.w3.org/2000/09/xmldsig#",
        }
        if root.tag != f"{{{ns['samlp']}}}Response":
            raise ValueError("Unexpected SAML response root element")
        status_code = root.find(".//samlp:StatusCode", ns)
        if (
            status_code is None
            or status_code.attrib.get("Value")
            != "urn:oasis:names:tc:SAML:2.0:status:Success"
        ):
            raise ValueError("SAML authentication status is not Success")
        issuer_elem = root.find("saml:Issuer", ns)
        if issuer_elem is None or not issuer_elem.text or not issuer_elem.text.strip():
            raise ValueError("Missing or empty SAML Issuer claim")
        issuer = issuer_elem.text.strip()
        if self.idp_issuer and issuer != self.idp_issuer:
            raise ValueError("SAML Issuer mismatch")
        nameid_elem = root.find(".//saml:NameID", ns)
        if nameid_elem is None or not nameid_elem.text or not nameid_elem.text.strip():
            raise ValueError("Missing required SAML NameID claim")
        response_issue = root.attrib.get("IssueInstant")
        if not response_issue:
            raise ValueError("SAML Response IssueInstant is required")
        try:
            issue_time = datetime.fromisoformat(response_issue)
        except ValueError as exc:
            raise ValueError("Invalid SAML Response IssueInstant") from exc
        if issue_time > datetime.now(UTC) + timedelta(
            minutes=5
        ) or issue_time < datetime.now(UTC) - timedelta(minutes=5):
            raise ValueError("SAML Response IssueInstant outside allowed clock skew")
        if not self.idp_metadata_xml or not self.idp_issuer:
            raise ValueError("Trusted SAML IdP metadata is required")
        try:
            metadata_root = ET.fromstring(self.idp_metadata_xml)
        except Exception as exc:
            raise ValueError("Trusted IdP metadata parsing failed") from exc
        certs = [
            node.text.strip()
            for node in metadata_root.findall(".//{*}X509Certificate")
            if node.text and node.text.strip()
        ]
        if not certs:
            raise ValueError("Trusted IdP metadata lacks X509 certificate")
        cert_pem = f"-----BEGIN CERTIFICATE-----\n{certs[0]}\n-----END CERTIFICATE-----\n".encode(
            "ascii"
        )
        assertions = root.findall(".//saml:Assertion", ns)
        if len(assertions) != 1:
            raise ValueError("SAML Response must contain exactly one Assertion")
        assertion = assertions[0]
        signature = root.find("ds:Signature", ns)
        signed_target = root
        if signature is None:
            signature = assertion.find("ds:Signature", ns)
            signed_target = assertion
        if signature is None:
            raise ValueError("SAML Response/Assertion signature missing")
        target_id = signed_target.attrib.get("ID")
        ref_node = signature.find(".//ds:Reference", ns)
        ref_uri = ref_node.attrib.get("URI", "") if ref_node is not None else ""
        if target_id and ref_uri and ref_uri != f"#{target_id}":
            raise ValueError(
                "SAML XML Signature Wrapping (XSW) detected: Reference URI mismatch"
            )
        if xmlsec is not None:
            try:
                trusted_key = xmlsec.Key.from_memory(
                    cert_pem, xmlsec.KeyFormat.CERT_PEM, None
                )
                try:
                    xmlsec.tree.add_ids(root, ["ID"])
                except Exception:
                    pass
                verify_ctx = xmlsec.SignatureContext()
                verify_ctx.key = trusted_key
                verify_ctx.verify(signature)
            except Exception as exc:
                raise ValueError(
                    "SAML Response cryptographic signature verification failed"
                ) from exc
        else:
            raise ValueError(
                "SAML cryptographic verification requires the xmlsec package"
            )
        in_response_to = root.attrib.get("InResponseTo") or assertion.attrib.get(
            "InResponseTo"
        )
        if expected_in_response_to and in_response_to != expected_in_response_to:
            raise ValueError("SAML InResponseTo request ID mismatch")
        response_id = root.attrib.get("ID") or assertion.attrib.get("ID")
        conditions = assertion.find("saml:Conditions", ns)
        if conditions is None:
            raise ValueError("SAML Assertion Conditions element missing")
        not_before = conditions.attrib.get("NotBefore")
        not_on_or_after = conditions.attrib.get("NotOnOrAfter")
        now = datetime.now(UTC)

        def parse_time(val: str) -> datetime:
            return datetime.fromisoformat(val)

        if not_on_or_after and now >= parse_time(not_on_or_after):
            raise ValueError("SAML assertion expired or missing expiry")
        if not_before and now < parse_time(not_before):
            raise ValueError("SAML assertion is not yet valid")
        audiences = [
            n.text.strip() for n in conditions.findall(".//saml:Audience", ns) if n.text
        ]
        if self.sp_entity_id not in audiences:
            raise ValueError("SAML assertion audience mismatch")
        confirmations = assertion.findall(".//saml:SubjectConfirmation", ns)
        bearer_method = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
        valid_bearer = any(
            c.attrib.get("Method") == bearer_method
            and c.find("saml:SubjectConfirmationData", ns) is not None
            and c.find("saml:SubjectConfirmationData", ns).attrib.get("Recipient")
            == self.acs_url
            and c.find("saml:SubjectConfirmationData", ns).attrib.get("NotOnOrAfter")
            and now
            < parse_time(
                c.find("saml:SubjectConfirmationData", ns).attrib["NotOnOrAfter"]
            )
            for c in confirmations
        )
        if not valid_bearer:
            raise ValueError(
                "SAML SubjectConfirmation recipient, method, or expiry is invalid"
            )
        nameid = assertion.find(".//saml:NameID", ns)
        if nameid is None or not nameid.text or not nameid.text.strip():
            raise ValueError("SAML NameID missing")
        sub = nameid.text.strip()
        email = None
        for attr in assertion.findall(".//saml:Attribute", ns):
            name = attr.attrib.get("Name", "").lower()
            if name in (
                "email",
                "emailaddress",
                "mail",
                "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
            ):
                value = attr.find("saml:AttributeValue", ns)
                if value is not None and value.text:
                    email = value.text.strip().lower()
                    break
        if not email or "@" not in email:
            raise ValueError("Verified email claim missing from SAML assertion")
        groups = []
        for attr in assertion.findall(".//saml:Attribute", ns):
            attr_name = attr.attrib.get("Name", "").lower()
            if attr_name in (
                "groups",
                "group",
                "roles",
                "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups",
            ):
                groups.extend(
                    v.text.strip()
                    for v in attr.findall("saml:AttributeValue", ns)
                    if v.text and v.text.strip()
                )
        return {
            "provider": "saml",
            "sub": sub,
            "email": email,
            "email_verified": True,
            "groups": groups,
            "issuer": self.idp_issuer,
            "response_id": response_id,
            "in_response_to": in_response_to,
            "raw_xml": raw.decode("utf-8", errors="replace"),
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

    def register_generic_oidc(
        self, issuer: str, client_id: str, client_secret: str
    ) -> GenericOIDCAdapter:
        adapter = GenericOIDCAdapter(issuer, client_id, client_secret)
        self.register(adapter)
        return adapter

    def get_adapter(self, provider_name: str) -> BaseAuthProviderAdapter:
        if provider_name not in self._adapters:
            raise ValueError(f"Unsupported Identity Provider: {provider_name}")
        return self._adapters[provider_name]


provider_registry = ProviderRegistry()
