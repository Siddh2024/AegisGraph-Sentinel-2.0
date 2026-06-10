"""Identity Provider Registry"""
import hashlib
from datetime import datetime
from typing import Optional
from .models import IdentityProvider, IdentityProviderType, SSOProvider
from .store import IdentityFederationStore

class IdentityProviderRegistry:
    DEFAULT_ATTR_MAPPINGS = {
        "email": ["email", "mail", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"],
        "username": ["username", "preferred_username", "sub"],
        "display_name": ["display_name", "name", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"],
        "first_name": ["given_name", "first_name", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"],
        "last_name": ["surname", "family_name", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"],
        "groups": ["groups", "roles", "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"],
    }
    
    def __init__(self, store: IdentityFederationStore): self._store = store
    
    def register_provider(self, name: str, provider_type: IdentityProviderType, issuer: str,
                          sso_provider: Optional[SSOProvider] = None, client_id: Optional[str] = None,
                          client_secret: Optional[str] = None, metadata_url: Optional[str] = None, **kwargs) -> IdentityProvider:
        provider_id = hashlib.sha256(f"{issuer}:{provider_type.value}".encode()).hexdigest()[:16]
        provider = IdentityProvider(id=provider_id, name=name, provider_type=provider_type, sso_provider=sso_provider,
                                    issuer=issuer, metadata_url=metadata_url, client_id=client_id,
                                    client_secret=client_secret, attribute_mappings=self.DEFAULT_ATTR_MAPPINGS.copy(), **kwargs)
        self._store.register_provider(provider)
        return provider
    
    def get_provider(self, provider_id: str) -> Optional[IdentityProvider]: return self._store.get_provider(provider_id)
    def get_provider_by_issuer(self, issuer: str) -> Optional[IdentityProvider]:
        for p in self._store.list_providers(): return p if p.issuer == issuer else None
    def list_providers(self, enabled_only: bool = False) -> list[IdentityProvider]: return self._store.list_providers(enabled_only)
    def update_provider(self, provider: IdentityProvider) -> None: self._store.update_provider(provider)
    def delete_provider(self, provider_id: str) -> bool: return self._store.delete_provider(provider_id)
    def enable_provider(self, provider_id: str) -> bool:
        p = self._store.get_provider(provider_id)
        if p: p.enabled = True; p.updated_at = datetime.utcnow(); self._store.update_provider(p); return True
        return False
    def disable_provider(self, provider_id: str) -> bool:
        p = self._store.get_provider(provider_id)
        if p: p.enabled = False; p.updated_at = datetime.utcnow(); self._store.update_provider(p); return True
        return False
    
    def validate_provider(self, provider: IdentityProvider) -> tuple[bool, list[str]]:
        errors = []
        provider_type = provider.provider_type.value if hasattr(provider.provider_type, 'value') else provider.provider_type
        if provider_type == "saml":
            if not provider.saml_entity_id: errors.append("SAML Entity ID is required")
            if not provider.saml_sso_url: errors.append("SAML SSO URL is required")
            if not provider.saml_certificate: errors.append("SAML Certificate is required")
        elif provider_type in ["oidc", "oauth2", "azure_ad", "okta", "auth0", "google", "keycloak"]:
            if not provider.client_id: errors.append("Client ID is required")
            if not provider.client_secret: errors.append("Client Secret is required")
        if not provider.name: errors.append("Provider name is required")
        if not provider.issuer: errors.append("Issuer URL is required")
        return len(errors) == 0, errors
    
    def register_azure_ad(self, tenant_id: str, client_id: str, client_secret: str, name: str = "Azure AD") -> IdentityProvider:
        issuer = f"https://login.microsoftonline.com/{tenant_id}/v2.0"
        metadata_url = f"https://login.microsoftonline.com/{tenant_id}/v2.0/.well-known/openid-configuration"
        return self.register_provider(name=name, provider_type=IdentityProviderType.AZURE_AD, sso_provider=SSOProvider.AZURE_AD,
                                      issuer=issuer, client_id=client_id, client_secret=client_secret, metadata_url=metadata_url,
                                      oidc_discovery_url=metadata_url)
    
    def register_okta(self, domain: str, client_id: str, client_secret: str, name: str = "Okta") -> IdentityProvider:
        issuer = f"https://{domain}/oauth2/default"
        metadata_url = f"https://{domain}/.well-known/openid-configuration"
        return self.register_provider(name=name, provider_type=IdentityProviderType.OKTA, sso_provider=SSOProvider.OKTA,
                                      issuer=issuer, client_id=client_id, client_secret=client_secret, metadata_url=metadata_url,
                                      oidc_discovery_url=metadata_url)
    
    def register_auth0(self, domain: str, client_id: str, client_secret: str, name: str = "Auth0") -> IdentityProvider:
        issuer = f"https://{domain}/"
        metadata_url = f"https://{domain}/.well-known/openid-configuration"
        return self.register_provider(name=name, provider_type=IdentityProviderType.AUTH0, sso_provider=SSOProvider.AUTH0,
                                      issuer=issuer, client_id=client_id, client_secret=client_secret, metadata_url=metadata_url,
                                      oidc_discovery_url=metadata_url)
    
    def register_google(self, client_id: str, client_secret: str, name: str = "Google Workspace") -> IdentityProvider:
        issuer = "https://accounts.google.com"
        metadata_url = "https://accounts.google.com/.well-known/openid-configuration"
        return self.register_provider(name=name, provider_type=IdentityProviderType.GOOGLE, sso_provider=SSOProvider.GOOGLE_WORKSPACE,
                                      issuer=issuer, client_id=client_id, client_secret=client_secret, metadata_url=metadata_url,
                                      oidc_discovery_url=metadata_url)
    
    def register_keycloak(self, realm: str, auth_server_url: str, client_id: str, client_secret: str, name: str = "Keycloak") -> IdentityProvider:
        issuer = f"{auth_server_url.rstrip('/')}/realms/{realm}"
        metadata_url = f"{auth_server_url.rstrip('/')}/realms/{realm}/.well-known/openid-configuration"
        return self.register_provider(name=name, provider_type=IdentityProviderType.KEYCLOAK, sso_provider=SSOProvider.KEYCLOAK,
                                      issuer=issuer, client_id=client_id, client_secret=client_secret, metadata_url=metadata_url,
                                      oidc_discovery_url=metadata_url)