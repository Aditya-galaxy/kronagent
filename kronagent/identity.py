"""
Operator identity and role-based access control for the human-decision surface.

The platform's whole trust story rests on "a human decided this." Until now that
human was a free-text `--by alice` string: the hash-chained audit log faithfully
recorded *that* "alice" approved, but not that alice was really alice, or that
alice was *authorized* to approve. For an audited-human-oversight product (EU AI
Act Article 14) that's a hole in the load-bearing claim. This module closes it:

  * **Authentication** — an operator proves who they are (a token checked against
    a registry). The `IdentityProvider` protocol is the seam: the shipped
    `LocalIdentityProvider` is a registry + hashed tokens; a SAML/OIDC provider
    for enterprise SSO is a drop-in implementing the same protocol, no caller
    change.
  * **Authorization (RBAC)** — roles carry permissions. Approving an action needs
    APPROVE; promoting an action class to autonomy (the most consequential
    decision in the system) needs PROMOTE. Reading needs VIEW.
  * **Non-repudiation** — the decision is attributed in the tamper-evident audit
    log to a *verified, authorized* principal, and the record states whether the
    identity was verified or merely self-asserted.

Enforcement is registry-gated, so nothing breaks that doesn't opt in:
  * A registry is configured (KRONAGENT_OPERATOR_REGISTRY / settings.operator_registry_path)
    → **enforced mode**: every command authenticates, mutating commands are
    authorized, and audit records carry `identity_verified: true`.
  * No registry → **unauthenticated mode** (dev/demo/back-compat): the old
    free-text `--by` flow, and audit records carry `identity_verified: false`.
    The audit trail is honest about the strength of the identity behind each
    decision rather than silently treating a string as proof.
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

import hashlib
import hmac
import json
import os
from enum import Enum
from typing import Callable, Optional

from pydantic import BaseModel, ConfigDict, Field


class Permission(str, Enum):
    VIEW = "view"        # list / show the approval queue and allowlist
    APPROVE = "approve"  # approve or deny a pending containment action
    PROMOTE = "promote"  # promote/demote an action class (earn-trust governance)


# Roles are named permission bundles. Adding a role is adding an entry here;
# separation of duty is expressed by which permissions a role does NOT carry
# (an 'approver' can authorize an action but cannot grant a class autonomy).
_ROLE_PERMISSIONS: dict[str, frozenset[Permission]] = {
    "viewer": frozenset({Permission.VIEW}),
    "approver": frozenset({Permission.VIEW, Permission.APPROVE}),
    "admin": frozenset({Permission.VIEW, Permission.APPROVE, Permission.PROMOTE}),
}


def role_permissions(role: str) -> frozenset[Permission]:
    return _ROLE_PERMISSIONS.get(role, frozenset())


def known_roles() -> list[str]:
    return sorted(_ROLE_PERMISSIONS)


# A tenants entry of "*" grants access to every tenant — for a platform or MSSP
# operator. It is spelled explicitly so that granting it is a visible, auditable
# decision in the registry rather than an accident of an omitted field.
ALL_TENANTS = "*"
DEFAULT_TENANT = "default"


class Operator(BaseModel):
    operator_id: str
    display_name: str
    roles: list[str] = Field(default_factory=list)
    active: bool = True
    # Tenants this operator may act on. Empty means the default tenant ONLY —
    # deliberately the narrowest reading, so an existing single-tenant registry
    # keeps working while a multi-tenant deployment cannot silently inherit
    # cross-tenant access from a field nobody filled in.
    tenants: list[str] = Field(default_factory=list)

    def permitted_tenants(self) -> list[str]:
        return self.tenants or [DEFAULT_TENANT]

    def permissions(self) -> frozenset[Permission]:
        perms: set[Permission] = set()
        for r in self.roles:
            perms |= role_permissions(r)
        return frozenset(perms)

    def can(self, permission: Permission) -> bool:
        return permission in self.permissions()


class AuthContext(BaseModel):
    """The resolved actor behind a command — verified or self-asserted. This is
    what gets written into the audit record, so the log carries the full
    provenance of every human decision."""

    operator_id: str
    display_name: str
    roles: list[str] = Field(default_factory=list)
    identity_verified: bool
    auth_method: str  # "local_token" | "unauthenticated"
    tenants: list[str] = Field(default_factory=lambda: [DEFAULT_TENANT])

    def may_access(self, tenant_id: str) -> bool:
        """Whether this actor may read or act on `tenant_id`.

        Permissions answer *what* an operator may do; this answers *whose data*
        they may do it to. Both are required. Without this the RBAC gate was
        complete and still allowed an admin of one tenant to approve another
        tenant's production containment, because nothing tied an identity to a
        tenant at all.
        """
        if ALL_TENANTS in self.tenants:
            return True
        return (tenant_id or DEFAULT_TENANT) in (self.tenants or [DEFAULT_TENANT])

    @property
    def label(self) -> str:
        """The `by=` attribution string used in human-facing output."""
        suffix = "" if self.identity_verified else " (unverified)"
        return f"{self.operator_id}{suffix}"

    def audit_fields(self) -> dict:
        return {
            "operator_id": self.operator_id,
            "display_name": self.display_name,
            "roles": self.roles,
            "identity_verified": self.identity_verified,
            "auth_method": self.auth_method,
            "tenants": self.tenants,
        }


class AuthorizationError(Exception):
    """Authentication failed, or the operator lacks the required permission."""


# --------------------------------------------------------------------------- #
# Token hashing — tokens are stored only as salted-free SHA-256 hex; the raw
# token is never persisted. Comparison is constant-time.
# --------------------------------------------------------------------------- #

def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class LocalIdentityProvider:
    """Registry-backed identity provider. The registry is a JSON object:

        {
          "alice": {
            "display_name": "Alice Ng",
            "roles": ["admin"],
            "token_sha256": "<sha256 hex of the operator's token>",
            "active": true
          }
        }
    """

    def __init__(self, registry_path: str) -> None:
        self._path = registry_path

    def _load(self) -> dict[str, dict]:
        if not os.path.exists(self._path):
            return {}
        with open(self._path, "r", encoding="utf-8") as fh:
            try:
                return json.load(fh)
            except json.JSONDecodeError:
                return {}

    def get_operator(self, operator_id: str) -> Optional[Operator]:
        record = self._load().get(operator_id)
        if record is None:
            return None
        return Operator(
            operator_id=operator_id,
            display_name=record.get("display_name", operator_id),
            roles=list(record.get("roles", [])),
            active=bool(record.get("active", True)),
            tenants=list(record.get("tenants", [])),
        )

    def authenticate(self, operator_id: str, token: Optional[str]) -> Optional[Operator]:
        record = self._load().get(operator_id)
        if record is None or not record.get("active", True):
            return None
        expected = record.get("token_sha256", "")
        if not token or not expected:
            return None
        # Constant-time comparison to avoid leaking the hash via timing.
        if not hmac.compare_digest(hash_token(token), expected):
            return None
        return Operator(
            operator_id=operator_id,
            display_name=record.get("display_name", operator_id),
            roles=list(record.get("roles", [])),
            active=bool(record.get("active", True)),
            tenants=list(record.get("tenants", [])),
        )


def registry_configured(registry_path: str) -> bool:
    return bool(registry_path) and os.path.exists(registry_path)


# --------------------------------------------------------------------------- #
# Owner standing — can this person still hold an allowlist entry?
# --------------------------------------------------------------------------- #

class OwnerVacancy(BaseModel):
    """Why an allowlist entry's owner can no longer hold it.

    `definitive` separates "the directory says this person is gone" from "the
    directory could not be read". Both refuse autonomy at the gate — an owner
    nobody can vouch for grants nothing — but only a definitive vacancy is
    latched as a suspension. A corrupt registry file has not made anyone leave,
    and latching on it would silently strand every entry on the allowlist.
    """

    model_config = ConfigDict(frozen=True)

    owner: str
    reason: str
    definitive: bool = True


def owner_vacancy(registry_path: str, owner: str, tenant_id: str) -> Optional[OwnerVacancy]:
    """None if `owner` may still hold an allowlist entry on `tenant_id`.

    Holding an entry means being the person who is asked to renew it and who
    can say yes, so the test is exactly what saying yes would need: an active
    operator in the registry, carrying PROMOTE, with access to this tenant.
    Anything less and the entry has nobody accountable for it — the orphan that
    ownership exists to prevent, just arrived at by someone leaving instead of
    by nobody being named.

    Only callable with a local registry. An OIDC-only deployment has no
    directory to ask about someone who is not currently signing in, so owner
    standing is not evaluated there; see `owner_vacancy_checker`.
    """
    try:
        with open(registry_path, "r", encoding="utf-8") as fh:
            registry = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        return OwnerVacancy(owner=owner, definitive=False,
                            reason=f"operator registry unreadable ({type(exc).__name__}) — "
                                   f"cannot confirm owner {owner!r}")
    if not isinstance(registry, dict) or not registry:
        return OwnerVacancy(owner=owner, definitive=False,
                            reason=f"operator registry is empty or malformed — "
                                   f"cannot confirm owner {owner!r}")

    record = registry.get(owner)
    if not isinstance(record, dict):
        return OwnerVacancy(owner=owner, reason=f"owner {owner!r} is not in the operator registry")
    operator = Operator(
        operator_id=owner,
        display_name=record.get("display_name", owner),
        roles=list(record.get("roles", [])),
        active=bool(record.get("active", True)),
        tenants=list(record.get("tenants", [])),
    )
    if not operator.active:
        return OwnerVacancy(owner=owner, reason=f"owner {owner!r} is deactivated")
    if not operator.can(Permission.PROMOTE):
        return OwnerVacancy(owner=owner,
                            reason=f"owner {owner!r} no longer holds the promote permission "
                                   f"(roles: {', '.join(operator.roles) or 'none'})")
    tenants = operator.permitted_tenants()
    if ALL_TENANTS not in tenants and (tenant_id or DEFAULT_TENANT) not in tenants:
        return OwnerVacancy(owner=owner,
                            reason=f"owner {owner!r} no longer has access to tenant "
                                   f"{tenant_id or DEFAULT_TENANT!r}")
    return None


def owner_vacancy_checker(
    registry_path: str, tenant_id: str,
) -> Optional[Callable[[str], Optional[OwnerVacancy]]]:
    """A per-tenant owner check, or None when there is no directory to check.

    None is a statement, not a default: with no local registry there are no
    verified identities at all (or only OIDC ones, which cannot be looked up
    while their holder is offline), so there is nothing to say an owner has
    left. Callers report that owner standing was not checked rather than
    implying it passed.
    """
    if not registry_configured(registry_path):
        return None
    return lambda owner: owner_vacancy(registry_path, owner, tenant_id)


# --------------------------------------------------------------------------- #
# OIDC / SAML SSO Identity Provider
# --------------------------------------------------------------------------- #

def base64url_decode(s: str) -> str:
    """Decodes a base64url encoded string (OIDC/JWT format)."""
    import base64
    rem = len(s) % 4
    if rem > 0:
        s += '=' * (4 - rem)
    return base64.urlsafe_b64decode(s.encode("utf-8")).decode("utf-8")


class OidcIdentityProvider:
    """OIDC Identity Provider.
    
    Verifies OIDC ID tokens (JWTs) against an issuer and audience, extracts
    user identity, and maps claims to system roles.
    """
    def __init__(
        self,
        issuer: str,
        audience: str,
        jwks_uri: Optional[str] = None,
        verify_signature: bool = True,
        roles_claim: str = "roles",
    ) -> None:
        self.issuer = issuer
        self.audience = audience
        self.jwks_uri = jwks_uri or f"{issuer.rstrip('/')}/.well-known/openid-configuration"
        self.verify_signature = verify_signature
        self.roles_claim = roles_claim
        self._resolved_jwks_uri: Optional[str] = None

    def _get_jwks_uri(self) -> str:
        if self._resolved_jwks_uri:
            return self._resolved_jwks_uri
            
        if self.jwks_uri.endswith("/openid-configuration"):
            import requests
            try:
                config = requests.get(self.jwks_uri, timeout=5).json()
                self._resolved_jwks_uri = config.get("jwks_uri")
            except Exception as e:
                raise AuthorizationError(f"Failed to discover OIDC JWKS URI: {e}")
        else:
            self._resolved_jwks_uri = self.jwks_uri
            
        return self._resolved_jwks_uri

    def authenticate(self, operator_id: str, token: Optional[str]) -> Optional[Operator]:
        if not token:
            return None

        parts = token.split(".")
        if len(parts) != 3:
            return None

        header_b64, payload_b64, signature_b64 = parts

        try:
            payload_str = base64url_decode(payload_b64)
            payload = json.loads(payload_str)
        except Exception:
            return None

        # Verify claims
        # 1. Expiration check
        import time
        exp = payload.get("exp")
        if not exp or exp < time.time():
            return None

        # 2. Issuer check
        iss = payload.get("iss", "")
        if iss.rstrip("/") != self.issuer.rstrip("/"):
            return None

        # 3. Audience check
        aud = payload.get("aud")
        if isinstance(aud, list):
            if self.audience not in aud:
                return None
        elif aud != self.audience:
            return None

        # 4. Operator identity check
        sub = payload.get("sub", "")
        email = payload.get("email", "")
        username = payload.get("preferred_username", "")
        
        matches_operator = (operator_id in {sub, email, username} and operator_id != "")
        if not matches_operator:
            return None

        # 5. Optional signature verification
        if self.verify_signature:
            try:
                import jwt
                jwks_url = self._get_jwks_uri()
                jwk_client = jwt.PyJWKClient(jwks_url)
                signing_key = jwk_client.get_signing_key_from_jwt(token)
                jwt.decode(
                    token,
                    signing_key.key,
                    algorithms=["RS256"],
                    audience=self.audience,
                    issuer=self.issuer
                )
            except ImportError:
                raise AuthorizationError(
                    "OIDC signature verification is enabled, but 'pyjwt' or 'cryptography' "
                    "is not installed. Install them or set KRONAGENT_OIDC_VERIFY_SIGNATURE=false."
                )
            except Exception:
                # Verification failed
                return None

        # Extract roles
        roles_val = payload.get(self.roles_claim, [])
        if isinstance(roles_val, str):
            roles = [roles_val]
        elif isinstance(roles_val, list):
            roles = [str(r) for r in roles_val]
        else:
            roles = []

        # Tenants from a claim, same shape as roles. Absent claim means the
        # default tenant only — an SSO identity must not inherit cross-tenant
        # access from an IdP that was never configured to express it.
        tenants_val = payload.get("tenants", [])
        if isinstance(tenants_val, str):
            tenants = [tenants_val]
        elif isinstance(tenants_val, list):
            tenants = [str(t) for t in tenants_val]
        else:
            tenants = []

        return Operator(
            operator_id=operator_id,
            display_name=payload.get("name") or payload.get("email") or operator_id,
            roles=roles,
            active=True,
            tenants=tenants,
        )


def resolve_actor(
    *,
    registry_path: str,
    required: Permission,
    by: Optional[str] = None,
    operator_id: Optional[str] = None,
    token: Optional[str] = None,
    oidc_issuer: Optional[str] = None,
    oidc_audience: Optional[str] = None,
    oidc_jwks_uri: Optional[str] = None,
    oidc_verify_signature: bool = True,
    oidc_roles_claim: str = "roles",
) -> AuthContext:
    """Resolve and authorize the operator behind a command.

    Enforced OIDC mode: if oidc_issuer and oidc_audience are configured,
    authenticate via OidcIdentityProvider.

    Enforced Local mode (registry configured): authenticate `operator_id` + `token`,
    then require `required`. Raises AuthorizationError on any failure.

    Unauthenticated mode (no registry): return a self-asserted context from
    `by`, marked identity_verified=False.
    """
    # 1. OIDC SSO Authentication
    if oidc_issuer and oidc_audience:
        if not operator_id:
            raise AuthorizationError(
                "authentication required — OIDC SSO is configured. "
                "Pass --as <operator_id> and a token (--token or KRONAGENT_OPERATOR_TOKEN)."
            )
        provider = OidcIdentityProvider(
            issuer=oidc_issuer,
            audience=oidc_audience,
            jwks_uri=oidc_jwks_uri,
            verify_signature=oidc_verify_signature,
            roles_claim=oidc_roles_claim,
        )
        operator = provider.authenticate(operator_id, token)
        if operator is None:
            raise AuthorizationError(f"OIDC authentication failed for operator '{operator_id}'.")
        if not operator.can(required):
            raise AuthorizationError(
                f"operator '{operator_id}' (roles: {operator.roles or 'none'}) "
                f"lacks the '{required.value}' permission required for this action."
            )
        return AuthContext(
            operator_id=operator.operator_id,
            display_name=operator.display_name,
            roles=operator.roles,
            identity_verified=True,
            auth_method="oidc",
            tenants=operator.permitted_tenants(),
        )

    # 2. Local Registry Authentication
    if registry_configured(registry_path):
        if not operator_id:
            raise AuthorizationError(
                "authentication required — an operator registry is configured. "
                "Pass --as <operator_id> and a token (--token or KRONAGENT_OPERATOR_TOKEN)."
            )
        operator = LocalIdentityProvider(registry_path).authenticate(operator_id, token)
        if operator is None:
            raise AuthorizationError(f"authentication failed for operator '{operator_id}'.")
        if not operator.can(required):
            raise AuthorizationError(
                f"operator '{operator_id}' (roles: {operator.roles or 'none'}) "
                f"lacks the '{required.value}' permission required for this action."
            )
        return AuthContext(
            operator_id=operator.operator_id,
            display_name=operator.display_name,
            roles=operator.roles,
            identity_verified=True,
            auth_method="local_token",
            tenants=operator.permitted_tenants(),
        )

    # 3. Unauthenticated fallback
    if not by:
        raise AuthorizationError(
            "--by <operator> is required (no operator registry configured)."
        )
    return AuthContext(
        operator_id=by,
        display_name=by,
        roles=[],
        identity_verified=False,
        auth_method="unauthenticated",
        tenants=[DEFAULT_TENANT],
    )
