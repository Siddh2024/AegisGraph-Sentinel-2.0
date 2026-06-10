"""OAuth2 Authorization Server"""
import secrets, hashlib, base64
from datetime import datetime, timedelta
from typing import Optional
from urllib.parse import urlencode
from .models import IdentityProvider, AuthenticationRequest, AuthenticationResponse, FederatedUser, FederationSession, TokenType, SessionState
from .store import IdentityFederationStore

class OAuthProvider:
    def __init__(self, store: IdentityFederationStore, issuer: str):
        self._store = store; self._issuer = issuer; self._clients: dict[str, dict] = {}
        self._auth_codes: dict[str, dict] = {}; self._tokens: dict[str, dict] = {}
    
    def register_client(self, client_id: str, client_secret: str, redirect_uris: list[str], scopes: Optional[list[str]] = None, client_name: Optional[str] = None) -> dict:
        client = {"client_id": client_id, "client_secret_hash": self._hash_secret(client_secret), "redirect_uris": redirect_uris,
                  "scopes": scopes or ["openid", "profile", "email"], "client_name": client_name or client_id, "created_at": datetime.utcnow(), "enabled": True}
        self._clients[client_id] = client; return {"client_id": client_id, "client_secret": client_secret}
    
    def _hash_secret(self, secret: str) -> str: return hashlib.sha256(secret.encode()).hexdigest()
    
    def authorize(self, client_id: str, redirect_uri: str, response_type: str, scope: str, state: Optional[str] = None,
                  code_challenge: Optional[str] = None, code_challenge_method: Optional[str] = None) -> AuthenticationResponse:
        client = self._clients.get(client_id)
        if not client: return AuthenticationResponse(success=False, error="invalid_client", error_description="Unknown client_id")
        if not client["enabled"]: return AuthenticationResponse(success=False, error="invalid_client", error_description="Client is disabled")
        if redirect_uri not in client["redirect_uris"]: return AuthenticationResponse(success=False, error="invalid_request", error_description="Invalid redirect_uri")
        
        if response_type == "code":
            code = secrets.token_urlsafe(32)
            self._auth_codes[code] = {"client_id": client_id, "redirect_uri": redirect_uri, "scope": scope, "code_challenge": code_challenge,
                                      "code_challenge_method": code_challenge_method, "state": state, "expires_at": datetime.utcnow() + timedelta(minutes=10), "used": False}
            redirect_url = f"{redirect_uri}?code={code}" + (f"&state={state}" if state else "")
            return AuthenticationResponse(success=True, redirect_url=redirect_url, authentication_method="oauth2")
        elif response_type == "token":
            access_token = self._generate_access_token(); expires_in = 3600
            self._store_token(access_token=access_token, token_type="Bearer", expires_in=expires_in, scope=scope, client_id=client_id)
            redirect_url = f"{redirect_uri}#access_token={access_token}&token_type=Bearer&expires_in={expires_in}" + (f"&state={state}" if state else "")
            return AuthenticationResponse(success=True, redirect_url=redirect_url, access_token=access_token, authentication_method="oauth2")
        return AuthenticationResponse(success=False, error="unsupported_response_type", error_description="Only 'code' and 'token' response types supported")
    
    def token(self, grant_type: str, code: Optional[str] = None, redirect_uri: Optional[str] = None, client_id: Optional[str] = None,
              client_secret: Optional[str] = None, refresh_token: Optional[str] = None, code_verifier: Optional[str] = None,
              scope: Optional[str] = None) -> AuthenticationResponse:
        if grant_type == "client_credentials": return self._client_credentials_grant(client_id, client_secret, scope)
        if grant_type == "refresh_token": return self._refresh_token_grant(refresh_token, scope)
        if grant_type == "authorization_code": return self._authorization_code_grant(code, redirect_uri, client_id, client_secret, code_verifier)
        return AuthenticationResponse(success=False, error="unsupported_grant_type", error_description=f"Unsupported grant type: {grant_type}")
    
    def _authorization_code_grant(self, code: str, redirect_uri: str, client_id: str, client_secret: str, code_verifier: Optional[str]) -> AuthenticationResponse:
        auth_code = self._auth_codes.get(code)
        if not auth_code: return AuthenticationResponse(success=False, error="invalid_grant", error_description="Invalid authorization code")
        if auth_code["used"]: return AuthenticationResponse(success=False, error="invalid_grant", error_description="Authorization code already used")
        if datetime.utcnow() > auth_code["expires_at"]: return AuthenticationResponse(success=False, error="invalid_grant", error_description="Authorization code expired")
        
        client = self._clients.get(client_id)
        if not client or client["client_secret_hash"] != self._hash_secret(client_secret): return AuthenticationResponse(success=False, error="invalid_client", error_description="Invalid client credentials")
        if redirect_uri != auth_code["redirect_uri"]: return AuthenticationResponse(success=False, error="invalid_grant", error_description="Redirect URI mismatch")
        
        if auth_code["code_challenge"]:
            if not code_verifier: return AuthenticationResponse(success=False, error="invalid_request", error_description="Code verifier required")
            if not self._verify_pkce(code_verifier, auth_code["code_challenge"], auth_code["code_challenge_method"]): return AuthenticationResponse(success=False, error="invalid_grant", error_description="Invalid code verifier")
        
        auth_code["used"] = True
        access_token = self._generate_access_token(); refresh_token_value = self._generate_refresh_token(); expires_in = 3600
        self._store_token(access_token=access_token, token_type="Bearer", expires_in=expires_in, scope=auth_code["scope"], client_id=client_id, refresh_token=refresh_token_value)
        return AuthenticationResponse(success=True, access_token=access_token, refresh_token=refresh_token_value, provider_id=client_id, authentication_method="oauth2",
                                       metadata={"token_type": "Bearer", "expires_in": expires_in, "scope": auth_code["scope"]})
    
    def _client_credentials_grant(self, client_id: str, client_secret: str, scope: Optional[str]) -> AuthenticationResponse:
        client = self._clients.get(client_id)
        if not client: return AuthenticationResponse(success=False, error="invalid_client", error_description="Invalid client credentials")
        if client["client_secret_hash"] != self._hash_secret(client_secret): return AuthenticationResponse(success=False, error="invalid_client", error_description="Invalid client credentials")
        token_scope = scope or " ".join(client["scopes"]); access_token = self._generate_access_token(); expires_in = 3600
        self._store_token(access_token=access_token, token_type="Bearer", expires_in=expires_in, scope=token_scope, client_id=client_id)
        return AuthenticationResponse(success=True, access_token=access_token, provider_id=client_id, authentication_method="oauth2", metadata={"token_type": "Bearer", "expires_in": expires_in, "scope": token_scope})
    
    def _refresh_token_grant(self, refresh_token: str, scope: Optional[str]) -> AuthenticationResponse:
        token_info = next((info for access_token, info in self._tokens.items() if info.get("refresh_token") == refresh_token), None)
        if not token_info: return AuthenticationResponse(success=False, error="invalid_grant", error_description="Invalid refresh token")
        if datetime.utcnow() > token_info.get("refresh_expires_at", datetime.utcnow()): return AuthenticationResponse(success=False, error="invalid_grant", error_description="Refresh token expired")
        new_access_token = self._generate_access_token(); expires_in = 3600
        self._revoke_token(token_info["access_token"])
        self._store_token(access_token=new_access_token, token_type="Bearer", expires_in=expires_in, scope=scope or token_info["scope"], client_id=token_info["client_id"], refresh_token=refresh_token)
        return AuthenticationResponse(success=True, access_token=new_access_token, refresh_token=refresh_token, authentication_method="oauth2", metadata={"token_type": "Bearer", "expires_in": expires_in})
    
    def _generate_access_token(self) -> str: return f"at_{secrets.token_urlsafe(32)}"
    def _generate_refresh_token(self) -> str: return f"rt_{secrets.token_urlsafe(32)}"
    
    def _store_token(self, access_token: str, token_type: str, expires_in: int, scope: str, client_id: str, refresh_token: Optional[str] = None) -> None:
        expires_at = datetime.utcnow() + timedelta(seconds=expires_in); refresh_expires_at = datetime.utcnow() + timedelta(days=30)
        self._tokens[access_token] = {"access_token": access_token, "token_type": token_type, "expires_at": expires_at, "expires_in": expires_in,
                                      "scope": scope, "client_id": client_id, "refresh_token": refresh_token, "refresh_expires_at": refresh_expires_at if refresh_token else None, "created_at": datetime.utcnow()}
    
    def _verify_pkce(self, code_verifier: str, code_challenge: str, method: str) -> bool:
        if method == "S256":
            digest = hashlib.sha256(code_verifier.encode()).digest()
            computed = base64.urlsafe_b64encode(digest).decode().rstrip("=")
            return computed == code_challenge
        elif method == "plain": return code_verifier == code_challenge
        return False
    
    def validate_token(self, access_token: str) -> Optional[dict]:
        token_info = self._tokens.get(access_token)
        if not token_info or datetime.utcnow() > token_info["expires_at"]: return None
        return token_info
    
    def revoke_token(self, token: str) -> bool:
        if token in self._tokens: del self._tokens[token]; return True
        return False
    
    def get_token_info(self, access_token: str) -> Optional[dict]:
        token_info = self._tokens.get(access_token)
        if not token_info or datetime.utcnow() > token_info["expires_at"]: return None
        return {"client_id": token_info["client_id"], "scope": token_info["scope"], "expires_at": token_info["expires_at"].isoformat(), "expires_in": token_info["expires_in"], "token_type": token_info["token_type"], "created_at": token_info["created_at"].isoformat()}