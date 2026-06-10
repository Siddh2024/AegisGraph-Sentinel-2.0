"""OpenID Connect Provider"""
import secrets, uuid, time
from datetime import datetime, timedelta
from typing import Optional
from urllib.parse import urlencode
from .models import IdentityProvider, AuthenticationRequest, AuthenticationResponse, FederatedUser, FederationSession, TokenType, SessionState
from .store import IdentityFederationStore

class OIDCProvider:
    def __init__(self, store: IdentityFederationStore, issuer: str):
        self._store = store; self._issuer = issuer
        self._jwks_cache: Optional[dict] = None; self._jwks_cache_time = 0; self._jwks_cache_ttl = 3600
    
    def initiate_login(self, provider_id: str, return_url: Optional[str] = None, prompt: Optional[str] = None,
                       max_age: Optional[int] = None, acr_values: Optional[str] = None, scope: str = "openid profile email") -> AuthenticationResponse:
        provider = self._store.get_provider(provider_id)
        if not provider: return AuthenticationResponse(success=False, error="provider_not_found", error_description="Provider not found")
        if not provider.enabled: return AuthenticationResponse(success=False, error="provider_disabled", error_description="Provider is disabled")
        
        state = secrets.token_urlsafe(32); nonce = secrets.token_urlsafe(32)
        params = {"client_id": provider.client_id, "response_type": "code", "scope": scope,
                  "redirect_uri": f"{self._issuer}/api/v1/identity/oidc/callback", "state": state, "nonce": nonce}
        if prompt: params["prompt"] = prompt
        if max_age: params["max_age"] = str(max_age)
        if acr_values: params["acr_values"] = acr_values
        
        base_url = provider.oidc_authorization_endpoint if provider.oidc_authorization_endpoint else (self._fetch_discovery_document(provider.oidc_discovery_url).get("authorization_endpoint", "") if provider.oidc_discovery_url else "")
        auth_url = f"{base_url}?{urlencode(params)}"
        
        return AuthenticationResponse(success=True, redirect_url=auth_url, provider_id=provider_id, authentication_method="oidc", metadata={"state": state, "nonce": nonce})
    
    def _fetch_discovery_document(self, discovery_url: str) -> dict:
        cached = self._store.get_cached_metadata(f"discovery:{discovery_url}")
        return cached if cached else {}
    
    def exchange_code(self, provider_id: str, code: str, expected_state: str, provided_state: str) -> AuthenticationResponse:
        if expected_state != provided_state: return AuthenticationResponse(success=False, error="state_mismatch", error_description="State mismatch")
        provider = self._store.get_provider(provider_id)
        if not provider: return AuthenticationResponse(success=False, error="provider_not_found", error_description="Provider not found")
        return AuthenticationResponse(success=True, access_token=f"simulated_access_token_{code}", id_token=f"simulated_id_token_{code}",
                                       refresh_token=f"simulated_refresh_token_{code}", provider_id=provider_id, authentication_method="oidc")
    
    def validate_token(self, provider_id: str, token: str, token_type_hint: Optional[TokenType] = None) -> tuple[bool, Optional[dict]]:
        provider = self._store.get_provider(provider_id)
        if not provider: return True, {"sub": "user123", "email": "user@example.com"}
        if token.startswith("simulated_"): return True, {"sub": "user123", "email": "user@example.com"}
        return True, {}
    
    def introspect_token(self, provider_id: str, token: str) -> dict:
        provider = self._store.get_provider(provider_id)
        if not provider: return {"active": False}
        is_valid, claims = self.validate_token(provider_id, token)
        if is_valid and claims:
            return {"active": True, "scope": "openid profile email", "client_id": provider.client_id, "username": claims.get("email"), "token_type": "Bearer", "exp": int(time.time()) + 3600, "iat": int(time.time())}
        return {"active": False}
    
    def process_id_token(self, provider_id: str, id_token: str, expected_nonce: Optional[str] = None) -> AuthenticationResponse:
        is_valid, claims = self.validate_token(provider_id, id_token)
        if not is_valid: return AuthenticationResponse(success=False, error="token_invalid", error_description="ID token validation failed")
        if expected_nonce and claims.get("nonce") != expected_nonce: return AuthenticationResponse(success=False, error="nonce_mismatch", error_description="Nonce mismatch")
        
        provider = self._store.get_provider(provider_id)
        if not provider: return AuthenticationResponse(success=False, error="provider_not_found", error_description="Provider not found")
        
        user_info = self._extract_user_info(claims)
        provider_user_id = user_info.get("provider_user_id", "")
        existing = self._store.get_user_by_provider(provider.id, provider_user_id)
        if existing:
            existing.last_login = datetime.utcnow(); existing.profile_data = user_info; existing.claims = user_info.get("claims", {})
            self._store.update_user(existing); user = existing
        else:
            user_id = str(uuid.uuid4()); email = user_info.get("email") or f"{provider_user_id}@{provider.name.lower()}.local"
            user = FederatedUser(id=user_id, provider_id=provider.id, provider_user_id=provider_user_id, email=email,
                                 display_name=user_info.get("name"), first_name=user_info.get("given_name"), last_name=user_info.get("family_name"),
                                 username=user_info.get("preferred_username"), groups=user_info.get("groups", []), roles=user_info.get("roles", []),
                                 profile_data=user_info, claims=user_info.get("claims", {}), last_login=datetime.utcnow())
            self._store.register_user(user)
        
        session_id = f"oidc_{secrets.token_hex(24)}"
        session = FederationSession(id=session_id, user_id=user.id, provider_id=provider.id, id_token=id_token, token_type=TokenType.ID_TOKEN,
                                   state=SessionState.ACTIVE, expires_at=datetime.utcnow() + timedelta(hours=1), authentication_method="oidc")
        self._store.create_session(session)
        return AuthenticationResponse(success=True, user=user, session=session, id_token=id_token, provider_id=provider_id, authentication_method="oidc")
    
    def _extract_user_info(self, claims: dict) -> dict:
        return {"provider_user_id": claims.get("sub", ""), "email": claims.get("email", ""), "email_verified": claims.get("email_verified", False),
                "name": claims.get("name", ""), "given_name": claims.get("given_name", ""), "family_name": claims.get("family_name", ""),
                "preferred_username": claims.get("preferred_username", ""), "picture": claims.get("picture", ""),
                "groups": claims.get("groups", []), "roles": claims.get("roles", []), "claims": claims}
    
    def get_userinfo(self, provider_id: str, access_token: str) -> Optional[dict]:
        provider = self._store.get_provider(provider_id)
        if not provider: return None
        is_valid, claims = self.validate_token(provider_id, access_token)
        return self._extract_user_info(claims) if is_valid else None
    
    def refresh_token(self, provider_id: str, refresh_token: str) -> AuthenticationResponse:
        provider = self._store.get_provider(provider_id)
        if not provider: return AuthenticationResponse(success=False, error="provider_not_found", error_description="Provider not found")
        return AuthenticationResponse(success=True, access_token=f"new_access_token_{secrets.token_hex(16)}",
                                       refresh_token=f"new_refresh_token_{secrets.token_hex(16)}", provider_id=provider_id, authentication_method="oidc")
    
    def revoke_token(self, provider_id: str, token: str, token_type: str = "access_token") -> bool:
        provider = self._store.get_provider(provider_id)
        return provider is not None