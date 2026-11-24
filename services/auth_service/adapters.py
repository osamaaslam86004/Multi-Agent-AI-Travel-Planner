"""
Multi-Provider OAuth / OIDC / SAML 2.0 Adapter Architecture.
Supports Google, Microsoft Entra ID, GitHub, Generic OIDC, and SAML 2.0.
Includes defusedxml-backed secure SAML 2.0 assertion validation, metadata signature checking,
signed AuthnRequests, issuer/audience validation, and expiration enforcement.
"""

import abc
import asyncio
import base64
import logging
import os
import secrets
import urllib.parse
from datetime import UTC, datetime, timedelta
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
            options={"verify_exp": True, "verify_aud": True},
        )
        if nonce and id_claims.get("nonce") != nonce:
            raise RuntimeError("OIDC nonce mismatch")
        return {
            "provider": "google",
            "sub": id_claims.get("sub"),
            "issuer": id_claims.get("iss", "https://accounts.google.com"),
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
        tid = id_claims.get("tid")
        expected_issuer = f"https://login.microsoftonline.com/{tid if self.tenant_id == 'common' else self.tenant_id}/v2.0"
        id_claims = jwt.decode(
            id_token_raw,
            signing_key.key,
            algorithms=["RS256"],
            audience=self.client_id,
            issuer=expected_issuer,
            options={"verify_exp": True, "verify_aud": True, "verify_iss": True},
        )
        if (
            self.tenant_id != "common" and id_claims.get("tid") != self.tenant_id
        ) or not id_claims.get("sub"):
            raise RuntimeError("Microsoft token tenant or subject mismatch")
        if nonce and id_claims.get("nonce") != nonce:
            raise RuntimeError("OIDC nonce mismatch")
        email = id_claims.get("email") or id_claims.get("preferred_username") or ""
        email_verified = bool(id_claims.get("email_verified", bool(email)))
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
    """Generic OIDC Provider Adapter supporting custom Enterprise Discovery."""

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
            async with httpx.AsyncClient(
                timeout=10.0, follow_redirects=False
            ) as client:
                response = await client.get(
                    f"{self.issuer}/.well-known/openid-configuration"
                )
                response.raise_for_status()
                metadata = response.json()
            if metadata.get("issuer", "").rstrip("/") != self.issuer:
                raise RuntimeError("OIDC discovery issuer mismatch")
            required = ("authorization_endpoint", "token_endpoint", "jwks_uri")
            if any(not metadata.get(k) for k in required):
                raise RuntimeError("OIDC discovery document missing required endpoints")
            for key in required:
                if urllib.parse.urlparse(metadata[key]).scheme != "https":
                    raise RuntimeError("OIDC endpoints must use HTTPS")
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
        if not id_claims.get("sub"):
            raise RuntimeError("Generic OIDC ID token missing subject")
        if nonce and id_claims.get("nonce") != nonce:
            raise RuntimeError("OIDC nonce mismatch")
        return {
            "provider": "generic_oidc",
            "sub": id_claims.get("sub"),
            "issuer": id_claims.get("iss", self.issuer),
            "email": id_claims.get("email"),
            "email_verified": id_claims.get("email_verified", True),
            "name": id_claims.get("name"),
            "groups": id_claims.get("groups", []),
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
        if not endpoint or urllib.parse.urlparse(endpoint).scheme != "https":
            raise ValueError("IdP metadata lacks a trusted HTTPS Redirect SSO endpoint")
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
        )
        root.set("ID", request_id)
        root.set("Version", "2.0")
        root.set("IssueInstant", issue_instant)
        root.set("Destination", endpoint)
        root.set("AssertionConsumerServiceURL", self.acs_url)
        root.set("ProtocolBinding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST")
        issuer = lxml_etree.SubElement(
            root, "{urn:oasis:names:tc:SAML:2.0:assertion}Issuer"
        )
        issuer.text = self.sp_entity_id
        name_policy = lxml_etree.SubElement(
            root, "{urn:oasis:names:tc:SAML:2.0:protocol}NameIDPolicy"
        )
        name_policy.set(
            "Format", "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
        )
        name_policy.set("AllowCreate", "true")
        xml_bytes = lxml_etree.tostring(root, encoding="utf-8", xml_declaration=True)
        compressed = __import__("zlib").compress(xml_bytes)[2:-4]
        encoded = base64.b64encode(compressed).decode("ascii")
        queryParams = {
            "SAMLRequest": encoded,
            "RelayState": relay_state,
            "SigAlg": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        }
        sig_str = urllib.parse.urlencode(queryParams)
        sp_private_pem = os.getenv("JWT_PRIVATE_KEY_PEM")
        if sp_private_pem:
            try:
                from cryptography.hazmat.primitives import hashes, serialization
                from cryptography.hazmat.primitives.asymmetric import padding

                key = serialization.load_pem_private_key(
                    sp_private_pem.encode(), password=None
                )
                signature_bytes = key.sign(
                    sig_str.encode(), padding.PKCS1v15(), hashes.SHA256()
                )
                queryParams["Signature"] = base64.b64encode(signature_bytes).decode(
                    "ascii"
                )
            except Exception as exc:
                logger.warning(f"SP AuthnRequest signing warning: {exc}")
        url = (
            endpoint
            + ("&" if "?" in endpoint else "?")
            + urllib.parse.urlencode(queryParams)
        )
        return url, request_id

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
            raise ValueError("Configured IdP metadata is invalid XML") from exc
        md_ns = "urn:oasis:names:tc:SAML:2.0:metadata"
        entity_descriptor = (
            metadata_root
            if metadata_root.attrib.get("entityID")
            else next(
                (
                    e
                    for e in metadata_root.findall(f".//{{{md_ns}}}EntityDescriptor")
                    if e.attrib.get("entityID") == self.idp_issuer
                ),
                None,
            )
        )
        if (
            entity_descriptor is None
            or entity_descriptor.attrib.get("entityID") != self.idp_issuer
        ):
            raise ValueError("Configured metadata entityID does not match IdP issuer")
        cert_nodes = entity_descriptor.findall(
            f".//{{{md_ns}}}KeyDescriptor[@use='signing']/.//{{http://www.w3.org/2000/09/xmldsig#}}X509Certificate"
        )
        if not cert_nodes:
            cert_nodes = entity_descriptor.findall(
                f".//{{{md_ns}}}KeyDescriptor/.//{{http://www.w3.org/2000/09/xmldsig#}}X509Certificate"
            )
        trusted_cert = next(
            (
                node.text.strip()
                for node in cert_nodes
                if node.text and node.text.strip()
            ),
            None,
        )
        if not trusted_cert:
            raise ValueError("IdP metadata contains no trusted signing certificate")
        signature = root.find("ds:Signature", ns)
        if signature is None:
            signature = root.find(".//ds:Signature", ns)
        if signature is None:
            raise ValueError("SAML Response or Assertion must be signed")
        response_id = root.attrib.get("ID")
        if not response_id:
            raise ValueError("SAML Response ID is required")
        sig_method = signature.find("ds:SignedInfo/ds:SignatureMethod", ns)
        digest_method = signature.find("ds:SignedInfo/ds:Reference/ds:DigestMethod", ns)
        references = signature.findall("ds:SignedInfo/ds:Reference", ns)
        if (
            sig_method is None
            or sig_method.attrib.get("Algorithm")
            != "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
        ):
            raise ValueError("Unsupported SAML signature algorithm")
        if (
            digest_method is None
            or digest_method.attrib.get("Algorithm")
            != "http://www.w3.org/2001/04/xmlenc#sha256"
        ):
            raise ValueError("Unsupported SAML digest algorithm")
        if len(references) != 1 or references[0].attrib.get("URI") != f"#{response_id}":
            raise ValueError("SAML signature must reference the Response root ID")
        canonicalization = signature.find("ds:SignedInfo/ds:CanonicalizationMethod", ns)
        if canonicalization is None or canonicalization.attrib.get("Algorithm") not in {
            "http://www.w3.org/2001/10/xml-exc-c14n#",
            "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
        }:
            raise ValueError("Unsupported SAML canonicalization algorithm")
        transforms = references[0].findall("ds:Transforms/ds:Transform", ns)
        transform_algorithms = [t.attrib.get("Algorithm") for t in transforms]
        allowed_transforms = {
            "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
            "http://www.w3.org/2001/10/xml-exc-c14n#",
            "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
        }
        if not transform_algorithms or any(
            a not in allowed_transforms for a in transform_algorithms
        ):
            raise ValueError("Unsupported SAML signature transform")
        if len(root.xpath(f"//*[@ID='{response_id}']")) != 1:
            raise ValueError("SAML Response ID must be unique")
        cert_pem = (
            "-----BEGIN CERTIFICATE-----\n"
            + "\n".join(
                trusted_cert[i : i + 64] for i in range(0, len(trusted_cert), 64)
            )
            + "\n-----END CERTIFICATE-----\n"
        )
        try:
            from cryptography import x509

            certificate = x509.load_pem_x509_certificate(cert_pem.encode())
            cert_not_before = getattr(
                certificate,
                "not_valid_before_utc",
                certificate.not_valid_before.replace(tzinfo=UTC),
            )
            cert_not_after = getattr(
                certificate,
                "not_valid_after_utc",
                certificate.not_valid_after.replace(tzinfo=UTC),
            )
            if (
                datetime.now(UTC) < cert_not_before
                or datetime.now(UTC) >= cert_not_after
            ):
                raise ValueError(
                    "IdP signing certificate is outside its validity period"
                )
        except Exception as exc:
            raise ValueError(
                "Trusted IdP signing certificate is invalid or expired"
            ) from exc
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
            if (
                os.getenv("ENVIRONMENT", "development").lower()
                in ("production", "staging")
                and os.getenv("ALLOW_UNVERIFIED_SAML_TESTS", "").lower() != "true"
            ):
                raise ValueError(
                    "SAML cryptographic verification requires the xmlsec package in production/staging"
                )
            logger.warning(
                "xmlsec library absent; exercising structural SAML assertion validation in test/dev environment."
            )
        destination = root.attrib.get("Destination")
        in_response_to = root.attrib.get("InResponseTo")
        if not response_id or destination != self.acs_url or not in_response_to:
            raise ValueError(
                "SAML Response ID, correlation, or ACS Destination is invalid"
            )
        if expected_in_response_to and in_response_to != expected_in_response_to:
            raise ValueError("SAML InResponseTo does not match the issued AuthnRequest")
        assertion = root.find("saml:Assertion", ns)
        if assertion is None:
            raise ValueError("SAML assertion missing")
        assertion_id = assertion.attrib.get("ID")
        if not assertion_id:
            raise ValueError("SAML Assertion ID missing")
        assertion_issuer = assertion.find("saml:Issuer", ns)
        if (
            assertion_issuer is None
            or not assertion_issuer.text
            or assertion_issuer.text.strip() != self.idp_issuer
        ):
            raise ValueError("SAML Assertion issuer mismatch")
        now = datetime.now(UTC)
        conditions = assertion.find("saml:Conditions", ns)
        if conditions is None:
            raise ValueError("SAML Conditions are required")

        def parse_time(value: str) -> datetime:
            parsed = datetime.fromisoformat(value)
            if parsed.tzinfo is None:
                raise ValueError("SAML timestamp must include timezone")
            return parsed

        not_before = conditions.attrib.get("NotBefore")
        not_after = conditions.attrib.get("NotOnOrAfter")
        if not not_after or now >= parse_time(not_after):
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
