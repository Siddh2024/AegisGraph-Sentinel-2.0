"""User Provisioning Service"""
import uuid
from datetime import datetime
from enum import Enum
from typing import Optional
from .models import IdentityProvider, FederatedUser, ProvisioningEvent
from .store import IdentityFederationStore

class ProvisioningAction(str, Enum): CREATE = "create"; UPDATE = "update"; DELETE = "delete"; DISABLE = "disable"; ENABLE = "enable"; SYNC = "sync"; DEPROVISION = "deprovision"
class ProvisioningStatus(str, Enum): PENDING = "pending"; IN_PROGRESS = "in_progress"; COMPLETED = "completed"; FAILED = "failed"; CANCELLED = "cancelled"

class ProvisioningService:
    def __init__(self, store: IdentityFederationStore, auto_provision: bool = True, default_role: str = "user"):
        self._store = store; self._auto_provision = auto_provision; self._default_role = default_role; self._pending_events: dict[str, ProvisioningEvent] = {}
    
    def provision_user(self, provider: IdentityProvider, user_info: dict, action: ProvisioningAction = ProvisioningAction.CREATE) -> tuple[Optional[FederatedUser], ProvisioningEvent]:
        event_id = str(uuid.uuid4()); event = ProvisioningEvent(id=event_id, user_id=user_info.get("id", ""), provider_id=provider.id, event_type=action.value, status=ProvisioningStatus.PENDING.value)
        try:
            event.status = ProvisioningStatus.IN_PROGRESS.value; event.started_at = datetime.utcnow()
            if action == ProvisioningAction.CREATE: user, changes = self._create_user(provider, user_info); event.new_values = user_info; event.changes = changes
            elif action == ProvisioningAction.UPDATE: user, changes = self._update_user(provider, user_info); event.previous_values = user_info.get("_previous", {}); event.new_values = user_info; event.changes = changes
            elif action == ProvisioningAction.DELETE: user = self._delete_user(user_info.get("id", "")); event.status = ProvisioningStatus.COMPLETED.value; return user, event
            elif action == ProvisioningAction.DISABLE: user = self._disable_user(user_info.get("id", "")); event.new_values = {"enabled": False}; event.changes = ["disabled"]
            elif action == ProvisioningAction.ENABLE: user = self._enable_user(user_info.get("id", "")); event.new_values = {"enabled": True}; event.changes = ["enabled"]
            elif action == ProvisioningAction.SYNC: user, changes = self._sync_user(provider, user_info); event.new_values = user_info; event.changes = changes
            else: raise ValueError(f"Unknown provisioning action: {action}")
            event.status = ProvisioningStatus.COMPLETED.value; event.completed_at = datetime.utcnow(); return user, event
        except Exception as e:
            event.status = ProvisioningStatus.FAILED.value; event.error_message = str(e); return None, event
    
    def _create_user(self, provider: IdentityProvider, user_info: dict) -> tuple[FederatedUser, list[str]]:
        user_id = str(uuid.uuid4()); user = FederatedUser(id=user_id, provider_id=provider.id, provider_user_id=user_info.get("provider_user_id", ""),
                                  email=user_info.get("email", ""), display_name=user_info.get("display_name"), first_name=user_info.get("first_name"),
                                  last_name=user_info.get("last_name"), username=user_info.get("username"), groups=user_info.get("groups", []),
                                  roles=user_info.get("roles", [self._default_role]), profile_data=user_info, claims=user_info.get("claims", {}), provisioning_status="active")
        self._store.register_user(user); return user, ["created"]
    
    def _update_user(self, provider: IdentityProvider, user_info: dict) -> tuple[FederatedUser, list[str]]:
        changes = []; existing = self._store.get_user_by_provider(provider.id, user_info.get("provider_user_id", ""))
        if not existing: return self._create_user(provider, user_info)
        if user_info.get("email") and user_info["email"] != existing.email: changes.append("email"); existing.email = user_info["email"]
        if user_info.get("display_name") and user_info["display_name"] != existing.display_name: changes.append("display_name"); existing.display_name = user_info["display_name"]
        if user_info.get("first_name") and user_info["first_name"] != existing.first_name: changes.append("first_name"); existing.first_name = user_info["first_name"]
        if user_info.get("last_name") and user_info["last_name"] != existing.last_name: changes.append("last_name"); existing.last_name = user_info["last_name"]
        if user_info.get("groups"): changes.append("groups"); existing.groups = user_info["groups"]
        if user_info.get("roles"): changes.append("roles"); existing.roles = user_info["roles"]
        existing.profile_data = user_info
        if user_info.get("claims"): existing.claims = user_info["claims"]
        existing.updated_at = datetime.utcnow(); self._store.update_user(existing); return existing, changes
    
    def _delete_user(self, user_id: str) -> Optional[FederatedUser]:
        user = self._store.get_user(user_id)
        if user: self._store.delete_user(user_id)
        return user
    
    def _disable_user(self, user_id: str) -> Optional[FederatedUser]:
        user = self._store.get_user(user_id)
        if user: user.enabled = False; user.updated_at = datetime.utcnow(); self._store.update_user(user); self._store.revoke_user_sessions(user_id)
        return user
    
    def _enable_user(self, user_id: str) -> Optional[FederatedUser]:
        user = self._store.get_user(user_id)
        if user: user.enabled = True; user.updated_at = datetime.utcnow(); self._store.update_user(user)
        return user
    
    def _sync_user(self, provider: IdentityProvider, user_info: dict) -> tuple[FederatedUser, list[str]]: return self._update_user(provider, user_info)
    
    def deprovision_user(self, user_id: str, reason: str = "deprovisioned") -> bool:
        user = self._store.get_user(user_id)
        if not user: return False
        user.enabled = False; user.provisioning_status = "deprovisioned"; user.updated_at = datetime.utcnow()
        self._store.update_user(user); self._store.revoke_user_sessions(user_id); return True
    
    def bulk_sync(self, provider_id: str, users_data: list[dict]) -> dict:
        provider = self._store.get_provider(provider_id)
        if not provider: return {"error": "Provider not found"}
        results = {"total": len(users_data), "created": 0, "updated": 0, "deleted": 0, "failed": 0, "errors": []}
        for user_data in users_data:
            try:
                user, event = self.provision_user(provider=provider, user_info=user_data, action=ProvisioningAction.SYNC)
                if event.status == ProvisioningStatus.COMPLETED.value:
                    if "created" in event.changes: results["created"] += 1
                    else: results["updated"] += 1
                else: results["failed"] += 1; results["errors"].append(event.error_message or "Unknown error")
            except Exception as e: results["failed"] += 1; results["errors"].append(str(e))
        return results
    
    def get_pending_events(self, provider_id: Optional[str] = None, limit: int = 100) -> list[ProvisioningEvent]: return list(self._pending_events.values())[:limit]
    def retry_event(self, event_id: str) -> bool:
        if event_id not in self._pending_events: return False
        event = self._pending_events[event_id]
        if event.status != ProvisioningStatus.FAILED.value: return False
        event.retry_count += 1; event.status = ProvisioningStatus.PENDING.value; event.error_message = None; return True
    def cancel_event(self, event_id: str) -> bool:
        if event_id in self._pending_events: self._pending_events[event_id].status = ProvisioningStatus.CANCELLED.value; return True
        return False