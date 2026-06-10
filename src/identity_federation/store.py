"""Identity Federation Data Store - Thread-safe with O(1) lookups"""
import threading
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Optional
from .models import IdentityProvider, FederatedUser, FederationSession, RoleMapping, IdentityMapping, SessionState

class IdentityFederationStore:
    def __init__(self, session_ttl: int = 3600, cache_size: int = 10000):
        self._lock = threading.RLock()
        self._providers: dict[str, IdentityProvider] = {}
        self._users: dict[str, FederatedUser] = {}
        self._users_by_email: dict[str, FederatedUser] = {}
        self._users_by_provider: dict[str, dict[str, FederatedUser]] = defaultdict(dict)
        self._sessions: dict[str, FederationSession] = {}
        self._sessions_by_user: dict[str, list[str]] = defaultdict(list)
        self._session_ttl = session_ttl
        self._role_mappings: dict[str, RoleMapping] = {}
        self._role_mappings_by_provider: dict[str, list[RoleMapping]] = defaultdict(list)
        self._identity_mappings: dict[str, IdentityMapping] = {}
        self._identity_mappings_by_provider: dict[str, list[IdentityMapping]] = defaultdict(list)
        self._metadata_cache: dict[str, tuple[datetime, dict]] = {}
        self._metadata_cache_ttl = 300
        self._stats = {"sessions_created": 0, "sessions_expired": 0, "sessions_revoked": 0, "authentications": 0, "cache_hits": 0, "cache_misses": 0}
    
    def register_provider(self, provider: IdentityProvider) -> None:
        with self._lock: self._providers[provider.id] = provider
    
    def get_provider(self, provider_id: str) -> Optional[IdentityProvider]:
        return self._providers.get(provider_id)
    
    def list_providers(self, enabled_only: bool = False) -> list[IdentityProvider]:
        with self._lock:
            providers = list(self._providers.values())
            return [p for p in providers if p.enabled] if enabled_only else providers
    
    def update_provider(self, provider: IdentityProvider) -> None:
        with self._lock:
            provider.updated_at = datetime.utcnow()
            self._providers[provider.id] = provider
    
    def delete_provider(self, provider_id: str) -> bool:
        with self._lock:
            if provider_id in self._providers: del self._providers[provider_id]; return True
            return False
    
    def register_user(self, user: FederatedUser) -> None:
        with self._lock:
            self._users[user.id] = user
            self._users_by_email[user.email] = user
            self._users_by_provider[user.provider_id][user.provider_user_id] = user
    
    def get_user(self, user_id: str) -> Optional[FederatedUser]:
        return self._users.get(user_id)
    
    def get_user_by_email(self, email: str) -> Optional[FederatedUser]:
        return self._users_by_email.get(email.lower())
    
    def get_user_by_provider(self, provider_id: str, provider_user_id: str) -> Optional[FederatedUser]:
        return self._users_by_provider.get(provider_id, {}).get(provider_user_id)
    
    def list_users_by_provider(self, provider_id: str) -> list[FederatedUser]:
        with self._lock: return list(self._users_by_provider.get(provider_id, {}).values())
    
    def update_user(self, user: FederatedUser) -> None:
        with self._lock:
            user.updated_at = datetime.utcnow()
            self._users[user.id] = user
            self._users_by_email[user.email] = user
    
    def delete_user(self, user_id: str) -> bool:
        with self._lock:
            user = self._users.get(user_id)
            if user:
                del self._users[user_id]
                self._users_by_email.pop(user.email, None)
                self._users_by_provider.get(user.provider_id, {}).pop(user.provider_user_id, None)
                return True
            return False
    
    def create_session(self, session: FederationSession) -> None:
        with self._lock:
            self._sessions[session.id] = session
            self._sessions_by_user[session.user_id].append(session.id)
            self._stats["sessions_created"] += 1
            self._stats["authentications"] += 1
            self._cleanup_expired_sessions()
    
    def get_session(self, session_id: str) -> Optional[FederationSession]:
        with self._lock:
            session = self._sessions.get(session_id)
            if session and not session.is_expired: return session
            elif session and session.is_expired: self._expire_session(session)
            return None
    
    def get_session_by_user(self, user_id: str) -> list[FederationSession]:
        with self._lock:
            sessions = []
            for sid in self._sessions_by_user.get(user_id, []):
                session = self._sessions.get(sid)
                if session:
                    if session.is_expired: self._expire_session(session)
                    elif session.state == SessionState.ACTIVE: sessions.append(session)
            return sessions
    
    def update_session(self, session: FederationSession) -> None:
        with self._lock:
            session.last_activity = datetime.utcnow()
            self._sessions[session.id] = session
    
    def revoke_session(self, session_id: str) -> bool:
        with self._lock:
            session = self._sessions.get(session_id)
            if session:
                session.state = SessionState.REVOKED
                self._stats["sessions_revoked"] += 1
                return True
            return False
    
    def revoke_user_sessions(self, user_id: str) -> int:
        with self._lock:
            count = 0
            for sid in self._sessions_by_user.get(user_id, []):
                session = self._sessions.get(sid)
                if session and session.state == SessionState.ACTIVE:
                    session.state = SessionState.REVOKED
                    count += 1
                    self._stats["sessions_revoked"] += 1
            return count
    
    def _expire_session(self, session: FederationSession) -> None:
        session.state = SessionState.EXPIRED
        self._stats["sessions_expired"] += 1
    
    def _cleanup_expired_sessions(self) -> None:
        for sid, s in self._sessions.items():
            if s.is_expired and s.state == SessionState.ACTIVE: self._expire_session(s)
    
    def cleanup_sessions(self) -> int:
        with self._lock:
            before = len(self._sessions)
            self._cleanup_expired_sessions()
            return before - len(self._sessions)
    
    def add_role_mapping(self, mapping: RoleMapping) -> None:
        with self._lock:
            self._role_mappings[mapping.id] = mapping
            self._role_mappings_by_provider[mapping.provider_id].append(mapping)
    
    def list_role_mappings(self, provider_id: Optional[str] = None, enabled_only: bool = False) -> list[RoleMapping]:
        with self._lock:
            mappings = self._role_mappings_by_provider.get(provider_id, []) if provider_id else list(self._role_mappings.values())
            return [m for m in mappings if m.enabled] if enabled_only else sorted(mappings, key=lambda m: m.priority, reverse=True)
    
    def delete_role_mapping(self, mapping_id: str) -> bool:
        with self._lock:
            mapping = self._role_mappings.get(mapping_id)
            if mapping:
                del self._role_mappings[mapping_id]
                self._role_mappings_by_provider[mapping.provider_id] = [m for m in self._role_mappings_by_provider.get(mapping.provider_id, []) if m.id != mapping_id]
                return True
            return False
    
    def add_identity_mapping(self, mapping: IdentityMapping) -> None:
        with self._lock:
            self._identity_mappings[mapping.id] = mapping
            self._identity_mappings_by_provider[mapping.provider_id].append(mapping)
    
    def list_identity_mappings(self, provider_id: Optional[str] = None, enabled_only: bool = False) -> list[IdentityMapping]:
        with self._lock:
            mappings = self._identity_mappings_by_provider.get(provider_id, []) if provider_id else list(self._identity_mappings.values())
            return [m for m in mappings if m.enabled] if enabled_only else mappings
    
    def delete_identity_mapping(self, mapping_id: str) -> bool:
        with self._lock:
            mapping = self._identity_mappings.get(mapping_id)
            if mapping:
                del self._identity_mappings[mapping_id]
                self._identity_mappings_by_provider[mapping.provider_id] = [m for m in self._identity_mappings_by_provider.get(mapping.provider_id, []) if m.id != mapping_id]
                return True
            return False
    
    def cache_metadata(self, key: str, metadata: dict) -> None:
        with self._lock: self._metadata_cache[key] = (datetime.utcnow(), metadata)
    
    def get_cached_metadata(self, key: str) -> Optional[dict]:
        with self._lock:
            if key in self._metadata_cache:
                timestamp, metadata = self._metadata_cache[key]
                if datetime.utcnow() - timestamp < timedelta(seconds=self._metadata_cache_ttl):
                    self._stats["cache_hits"] += 1
                    return metadata
                else: del self._metadata_cache[key]
            self._stats["cache_misses"] += 1
            return None
    
    def invalidate_metadata_cache(self, key: Optional[str] = None) -> None:
        with self._lock:
            if key: self._metadata_cache.pop(key, None)
            else: self._metadata_cache.clear()
    
    def get_stats(self) -> dict:
        with self._lock:
            return {
                **self._stats,
                "providers_count": len(self._providers),
                "users_count": len(self._users),
                "sessions_active": sum(1 for s in self._sessions.values() if s.state == SessionState.ACTIVE and not s.is_expired),
                "sessions_total": len(self._sessions),
                "role_mappings_count": len(self._role_mappings),
                "identity_mappings_count": len(self._identity_mappings),
            }