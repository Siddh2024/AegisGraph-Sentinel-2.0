"""Session Manager"""
import secrets
from datetime import datetime, timedelta
from typing import Optional
from .models import FederationSession, SessionState, TokenType
from .store import IdentityFederationStore

class SessionManager:
    def __init__(self, store: IdentityFederationStore, default_ttl: int = 3600, max_concurrent_sessions: int = 10):
        self._store = store; self._default_ttl = default_ttl; self._max_concurrent = max_concurrent_sessions
    
    def create_session(self, user_id: str, provider_id: str, access_token: Optional[str] = None, refresh_token: Optional[str] = None,
                       id_token: Optional[str] = None, session_index: Optional[str] = None, relay_state: Optional[str] = None,
                       nonce: Optional[str] = None, ip_address: Optional[str] = None, user_agent: Optional[str] = None, ttl: Optional[int] = None) -> FederationSession:
        session_id = self._generate_session_id()
        expires_at = datetime.utcnow() + timedelta(seconds=ttl or self._default_ttl)
        token_type = TokenType.ACCESS_TOKEN
        if id_token: token_type = TokenType.ID_TOKEN
        elif refresh_token: token_type = TokenType.REFRESH_TOKEN
        session = FederationSession(id=session_id, user_id=user_id, provider_id=provider_id, access_token=access_token, refresh_token=refresh_token,
                                    id_token=id_token, token_type=token_type, state=SessionState.ACTIVE, session_index=session_index,
                                    relay_state=relay_state, nonce=nonce, expires_at=expires_at, ip_address=ip_address, user_agent=user_agent)
        self._store.create_session(session)
        self._enforce_max_sessions(user_id)
        return session
    
    def _generate_session_id(self) -> str: return f"fs_{secrets.token_hex(24)}"
    
    def _enforce_max_sessions(self, user_id: str) -> None:
        sessions = self._store.get_session_by_user(user_id)
        if len(sessions) > self._max_concurrent:
            sessions_sorted = sorted(sessions, key=lambda s: s.last_activity)
            for session in sessions_sorted[:len(sessions) - self._max_concurrent]: self._store.revoke_session(session.id)
    
    def get_session(self, session_id: str) -> Optional[FederationSession]: return self._store.get_session(session_id)
    def get_user_sessions(self, user_id: str) -> list[FederationSession]: return self._store.get_session_by_user(user_id)
    
    def validate_session(self, session_id: str) -> tuple[bool, Optional[FederationSession], Optional[str]]:
        session = self._store.get_session(session_id)
        if not session: return False, None, "Session not found"
        if session.state != SessionState.ACTIVE: return False, session, f"Session is {session.state.value}"
        if session.is_expired: self._store.revoke_session(session_id); return False, session, "Session expired"
        return True, session, None
    
    def refresh_session(self, session_id: str, ttl: Optional[int] = None) -> bool:
        session = self._store.get_session(session_id)
        if not session or session.state != SessionState.ACTIVE: return False
        session.expires_at = datetime.utcnow() + timedelta(seconds=ttl or self._default_ttl)
        session.last_activity = datetime.utcnow()
        self._store.update_session(session)
        return True
    
    def revoke_session(self, session_id: str) -> bool: return self._store.revoke_session(session_id)
    
    def revoke_user_sessions(self, user_id: str, provider_id: Optional[str] = None) -> int:
        count = 0
        for session in self._store.get_session_by_user(user_id):
            if provider_id is None or session.provider_id == provider_id:
                if self._store.revoke_session(session.id): count += 1
        return count
    
    def revoke_expired_sessions(self) -> int: return self._store.cleanup_sessions()
    def update_session_activity(self, session_id: str) -> bool:
        session = self._store.get_session(session_id)
        if not session or session.state != SessionState.ACTIVE: return False
        session.last_activity = datetime.utcnow()
        self._store.update_session(session)
        return True
    
    def get_session_stats(self, user_id: str) -> dict:
        sessions = self._store.get_session_by_user(user_id)
        return {"total_sessions": len(sessions), "active_sessions": sum(1 for s in sessions if s.state == SessionState.ACTIVE),
                "expired_sessions": sum(1 for s in sessions if s.is_expired),
                "sessions_by_provider": {p: sum(1 for s in sessions if s.provider_id == p) for p in set(s.provider_id for s in sessions)},
                "oldest_session": min((s.created_at for s in sessions), default=None), "newest_session": max((s.created_at for s in sessions), default=None)}