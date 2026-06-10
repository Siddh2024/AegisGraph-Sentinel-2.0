"""Identity Mapper"""
import uuid
from datetime import datetime
from typing import Optional
from .models import IdentityProvider, FederatedUser, RoleMapping, IdentityMapping
from .store import IdentityFederationStore

class IdentityMapper:
    def __init__(self, store: IdentityFederationStore): self._store = store
    
    def map_identity(self, provider: IdentityProvider, raw_attributes: dict) -> dict:
        mapped = {}; mappings = self._store.list_identity_mappings(provider.id, enabled_only=True)
        if mappings:
            for mapping in mappings:
                value = self._get_attribute_value(raw_attributes, mapping.source_attribute, mapping.source_namespace)
                if value is None and mapping.default_value: value = mapping.default_value
                if value is not None: mapped[mapping.target_attribute] = self._transform_value(value, mapping.transform_type, mapping.transform_function)
        else:
            attr_map = provider.attribute_mappings or {}
            for target_attr, source_attrs in attr_map.items():
                if isinstance(source_attrs, list):
                    for source_attr in source_attrs:
                        value = raw_attributes.get(source_attr)
                        if value: mapped[target_attr] = value; break
                elif isinstance(source_attrs, str):
                    value = raw_attributes.get(source_attrs)
                    if value: mapped[target_attr] = value
        return mapped
    
    def _get_attribute_value(self, attributes: dict, source_attribute: str, namespace: Optional[str] = None) -> Optional[str]:
        if source_attribute in attributes: return attributes[source_attribute]
        if namespace:
            namespaced = f"{namespace}/{source_attribute}"
            if namespaced in attributes: return attributes[namespaced]
        return None
    
    def _transform_value(self, value: str, transform_type: str, transform_function: Optional[str] = None) -> str:
        if transform_type == "lowercase": return value.lower()
        elif transform_type == "uppercase": return value.upper()
        elif transform_type == "titlecase": return value.title()
        elif transform_type == "trim": return value.strip()
        elif transform_type == "email_domain":
            return value.split("@")[1] if "@" in value else value
        elif transform_type == "extract_username":
            if "\\" in value: return value.split("\\")[1]
            if "@" in value: return value.split("@")[0]
            return value
        return value
    
    def map_roles(self, provider: IdentityProvider, raw_groups: list[str]) -> list[str]:
        roles = set(); mappings = self._store.list_role_mappings(provider.id, enabled_only=True)
        if mappings:
            for group in raw_groups:
                for mapping in mappings:
                    if self._matches_group(mapping.source_group, group) and self._check_conditions(mapping.conditions, raw_groups): roles.add(mapping.target_role)
        else: roles.update(raw_groups)
        return list(roles)
    
    def _matches_group(self, source_group: str, raw_group: str) -> bool:
        if source_group == raw_group or source_group.lower() == raw_group.lower(): return True
        import fnmatch
        return fnmatch.fnmatch(raw_group, source_group)
    
    def _check_conditions(self, conditions: dict, raw_groups: list[str]) -> bool:
        if not conditions: return True
        if "require_groups" in conditions:
            required = conditions["require_groups"] if isinstance(conditions["require_groups"], list) else [conditions["require_groups"]]
            if not any(g in raw_groups for g in required): return False
        if "exclude_groups" in conditions:
            excluded = conditions["exclude_groups"] if isinstance(conditions["exclude_groups"], list) else [conditions["exclude_groups"]]
            if any(g in raw_groups for g in excluded): return False
        return True
    
    def add_identity_mapping(self, provider_id: str, source_attribute: str, target_attribute: str, source_namespace: Optional[str] = None,
                             transform_type: str = "direct", transform_function: Optional[str] = None, default_value: Optional[str] = None, required: bool = False) -> IdentityMapping:
        mapping = IdentityMapping(id=str(uuid.uuid4()), provider_id=provider_id, source_attribute=source_attribute, source_namespace=source_namespace,
                                   target_attribute=target_attribute, transform_type=transform_type, transform_function=transform_function,
                                   default_value=default_value, required=required)
        self._store.add_identity_mapping(mapping); return mapping
    
    def add_role_mapping(self, provider_id: str, source_group: str, target_role: str, source_type: str = "group", conditions: Optional[dict] = None, priority: int = 0) -> RoleMapping:
        mapping = RoleMapping(id=str(uuid.uuid4()), provider_id=provider_id, source_group=source_group, source_type=source_type,
                               target_role=target_role, conditions=conditions or {}, priority=priority)
        self._store.add_role_mapping(mapping); return mapping
    
    def list_identity_mappings(self, provider_id: Optional[str] = None) -> list[IdentityMapping]: return self._store.list_identity_mappings(provider_id)
    def list_role_mappings(self, provider_id: Optional[str] = None) -> list[RoleMapping]: return self._store.list_role_mappings(provider_id)
    def delete_identity_mapping(self, mapping_id: str) -> bool: return self._store.delete_identity_mapping(mapping_id)
    def delete_role_mapping(self, mapping_id: str) -> bool: return self._store.delete_role_mapping(mapping_id)
    
    def sync_user_roles(self, user: FederatedUser, provider: IdentityProvider) -> FederatedUser:
        raw_groups = user.profile_data.get("groups", user.groups)
        if isinstance(raw_groups, str): raw_groups = [raw_groups]
        user.roles = self.map_roles(provider, raw_groups)
        user.updated_at = datetime.utcnow()
        self._store.update_user(user)
        return user