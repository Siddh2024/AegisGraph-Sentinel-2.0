"""Identity Federation Data Models"""
from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field, field_validator

class IdentityProviderType(str, Enum):
    SAML = "saml"; OIDC = "oidc"; OAUTH2 = "oauth2"; LDAP = "ldap"
    AZURE_AD = "azure_ad"; OKTA = "okta"; AUTH0 = "auth0"; GOOGLE = "google"
    KEYCLOAK = "keycloak"; PING_IDENTITY = "ping_identity"; ONELOGIN = "onelogin"

class SSOProvider(str, Enum):
    AZURE_AD = "azure_ad"; MICROSOFT_ENTRA = "microsoft_entra"; OKTA = "okta"
    AUTH0 = "auth0"; GOOGLE_WORKSPACE = "google_workspace"; KEYCLOAK = "keycloak"
    PING_IDENTITY = "ping_identity"; ONELOGIN = "onelogin"

class TokenType(str, Enum):
    ACCESS_TOKEN = "access_token"; REFRESH_TOKEN = "refresh_token"
    ID_TOKEN = "id_token"; AUTHORIZATION_CODE = "authorization_code"

class SessionState(str, Enum):
    ACTIVE = "active"; EXPIRED = "expired"; REVOKED = "revoked"; INVALIDATED = "invalidated"

class IdentityProvider(BaseModel):
    id: str; name: str; provider_type: IdentityProviderType; enabled: bool = True
    issuer: str; metadata_url: Optional[str] = None; client_id: Optional[str] = None
    client_secret: Optional[str] = None; saml_entity_id: Optional[str] = None
    saml_sso_url: Optional[str] = None; saml_slo_url: Optional[str] = None
    saml_certificate: Optional[str] = None; oidc_discovery_url: Optional[str] = None
    oidc_authorization_endpoint: Optional[str] = None; oidc_token_endpoint: Optional[str] = None
    oidc_userinfo_endpoint: Optional[str] = None; oidc_jwks_uri: Optional[str] = None
    attribute_mappings: dict[str, str | list[str]] = Field(default_factory=dict)
    role_mappings: list["RoleMapping"] = Field(default_factory=list)
    sign_requests: bool = True; want_assertions_signed: bool = True
    validate_signature: bool = True; sso_provider: Optional[SSOProvider] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    class Config: use_enum_values = True

class FederatedUser(BaseModel):
    id: str; provider_id: str; provider_user_id: str; email: str
    username: Optional[str] = None; display_name: Optional[str] = None
    first_name: Optional[str] = None; last_name: Optional[str] = None
    groups: list[str] = Field(default_factory=list); roles: list[str] = Field(default_factory=list)
    profile_data: dict = Field(default_factory=dict); claims: dict = Field(default_factory=dict)
    enabled: bool = True; mfa_enabled: bool = False; last_login: Optional[datetime] = None
    provisioning_status: str = "pending"
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    
    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        if "@" not in v: raise ValueError("Invalid email format")
        return v.lower()

class FederationSession(BaseModel):
    id: str; user_id: str; provider_id: str
    access_token: Optional[str] = None; refresh_token: Optional[str] = None
    id_token: Optional[str] = None; token_type: TokenType = TokenType.ACCESS_TOKEN
    state: SessionState = SessionState.ACTIVE; session_index: Optional[str] = None
    relay_state: Optional[str] = None; nonce: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: datetime; last_activity: datetime = Field(default_factory=datetime.utcnow)
    ip_address: Optional[str] = None; user_agent: Optional[str] = None
    metadata: dict = Field(default_factory=dict)
    class Config: use_enum_values = True
    @property
    def is_expired(self) -> bool: return datetime.utcnow() > self.expires_at

class AuthenticationRequest(BaseModel):
    provider_id: str; return_url: Optional[str] = None; flow_type: str = "sso"
    saml_request_id: Optional[str] = None; saml_force_authn: bool = False
    oidc_prompt: Optional[str] = None; oidc_max_age: Optional[int] = None
    oidc_acr_values: Optional[str] = None; oauth2_scope: Optional[str] = None
    oauth2_response_type: Optional[str] = None; relay_state: Optional[str] = None
    nonce: Optional[str] = None; ip_address: Optional[str] = None; user_agent: Optional[str] = None

class AuthenticationResponse(BaseModel):
    success: bool; user: Optional[FederatedUser] = None; session: Optional[FederationSession] = None
    access_token: Optional[str] = None; id_token: Optional[str] = None; refresh_token: Optional[str] = None
    redirect_url: Optional[str] = None; error: Optional[str] = None
    error_description: Optional[str] = None; error_uri: Optional[str] = None
    provider_id: Optional[str] = None; authentication_method: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow); metadata: dict = Field(default_factory=dict)

class RoleMapping(BaseModel):
    id: str; provider_id: str; source_group: str; source_type: str = "group"
    target_role: str; target_permission_level: int = 1; conditions: dict = Field(default_factory=dict)
    enabled: bool = True; priority: int = 0
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

class IdentityMapping(BaseModel):
    id: str; provider_id: str; source_attribute: str; source_namespace: Optional[str] = None
    target_attribute: str; transform_type: str = "direct"; transform_function: Optional[str] = None
    default_value: Optional[str] = None; enabled: bool = True; required: bool = False
    created_at: datetime = Field(default_factory=datetime.utcnow)

class ProvisioningEvent(BaseModel):
    id: str; user_id: str; provider_id: str; event_type: str; status: str
    previous_values: dict = Field(default_factory=dict); new_values: dict = Field(default_factory=dict)
    changes: list[str] = Field(default_factory=list); error_message: Optional[str] = None
    retry_count: int = 0; created_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None; completed_at: Optional[datetime] = None
    triggered_by: str = "system"; request_id: Optional[str] = None

class AuditEvent(BaseModel):
    id: str; timestamp: datetime = Field(default_factory=datetime.utcnow)
    user_id: Optional[str] = None; username: Optional[str] = None; ip_address: Optional[str] = None
    action: str; resource_type: str; resource_id: Optional[str] = None
    success: bool = True; error_message: Optional[str] = None
    provider_id: Optional[str] = None; session_id: Optional[str] = None
    authentication_method: Optional[str] = None; metadata: dict = Field(default_factory=dict)
    user_agent: Optional[str] = None

IdentityProvider.model_rebuild(); FederatedUser.model_rebuild(); RoleMapping.model_rebuild()