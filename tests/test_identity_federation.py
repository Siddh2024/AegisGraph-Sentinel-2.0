"""Identity Federation Tests"""
import pytest, threading
from datetime import datetime, timedelta
from src.identity_federation import (
    IdentityFederationService, IdentityFederationStore, IdentityProviderRegistry, IdentityProvider,
    IdentityProviderType, SSOProvider, FederatedUser, FederationSession, SessionState,
    SAMLProvider, OIDCProvider, OAuthProvider, SessionManager, IdentityMapper, ProvisioningService, AuditLogger
)

class TestIdentityFederationStore:
    def test_provider_crud(self):
        store = IdentityFederationStore()
        provider = IdentityProvider(id="p1", name="Test", provider_type=IdentityProviderType.OIDC, issuer="https://test.com", client_id="c1", client_secret="s1")
        store.register_provider(provider)
        assert store.get_provider("p1").name == "Test"
        provider.enabled = False; store.update_provider(provider)
        assert store.get_provider("p1").enabled is False
        assert store.delete_provider("p1") is True
    
    def test_user_crud(self):
        store = IdentityFederationStore()
        user = FederatedUser(id="u1", provider_id="p1", provider_user_id="ext1", email="user@test.com")
        store.register_user(user)
        assert store.get_user("u1").email == "user@test.com"
        assert store.get_user_by_email("user@test.com").id == "u1"
    
    def test_session_management(self):
        store = IdentityFederationStore()
        session = FederationSession(id="s1", user_id="u1", provider_id="p1", expires_at=datetime.utcnow() + timedelta(hours=1))
        store.create_session(session)
        assert store.get_session("s1").user_id == "u1"
        store.revoke_session("s1")
        assert store.get_session("s1").state == SessionState.REVOKED
    
    def test_o1_lookup(self):
        store = IdentityFederationStore()
        for i in range(100):
            store.register_provider(IdentityProvider(id=f"p{i}", name=f"P{i}", provider_type=IdentityProviderType.OIDC, issuer=f"https://p{i}.com"))
        import time; start = time.time()
        for i in range(100): store.get_provider(f"p{i}")
        assert time.time() - start < 0.1
    
    def test_thread_safety(self):
        store = IdentityFederationStore(); errors = []
        def worker(n):
            try:
                for i in range(50):
                    p = IdentityProvider(id=f"p{n}-{i}", name=f"P{n}-{i}", provider_type=IdentityProviderType.OIDC, issuer=f"https://p{n}-{i}.com")
                    store.register_provider(p); store.get_provider(f"p{n}-{i}")
            except Exception as e: errors.append(e)
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
        for t in threads: t.start()
        for t in threads: t.join()
        assert len(errors) == 0

class TestIdentityProviderRegistry:
    def test_register_azure_ad(self):
        store = IdentityFederationStore(); registry = IdentityProviderRegistry(store)
        provider = registry.register_azure_ad(tenant_id="t1", client_id="c1", client_secret="s1")
        assert provider.name == "Azure AD"; assert SSOProvider.AZURE_AD in str(provider.sso_provider)
    
    def test_register_okta(self):
        store = IdentityFederationStore(); registry = IdentityProviderRegistry(store)
        provider = registry.register_okta(domain="test.okta.com", client_id="c1", client_secret="s1")
        assert provider.sso_provider == SSOProvider.OKTA
    
    def test_validate_provider(self):
        store = IdentityFederationStore(); registry = IdentityProviderRegistry(store)
        valid = IdentityProvider(id="v1", name="Valid SAML", provider_type=IdentityProviderType.SAML, issuer="https://v.com", saml_entity_id="e1", saml_sso_url="https://v.com/sso", saml_certificate="cert")
        is_valid, errors = registry.validate_provider(valid)
        assert is_valid is True

class TestSAMLProvider:
    def test_initiate_login(self):
        store = IdentityFederationStore()
        store.register_provider(IdentityProvider(id="saml1", name="SAML", provider_type=IdentityProviderType.SAML, issuer="https://s.com", saml_sso_url="https://s.com/sso", saml_certificate="cert"))
        saml = SAMLProvider(store, "test-sp")
        response = saml.initiate_login(provider_id="saml1")
        assert response.success is True; assert "SAMLRequest=" in response.redirect_url

class TestOIDCProvider:
    def test_initiate_login(self):
        store = IdentityFederationStore()
        store.register_provider(IdentityProvider(id="oidc1", name="OIDC", provider_type=IdentityProviderType.OIDC, issuer="https://o.com", client_id="c1", client_secret="s1", oidc_authorization_endpoint="https://o.com/auth"))
        oidc = OIDCProvider(store, "https://app.com")
        response = oidc.initiate_login(provider_id="oidc1")
        assert response.success is True; assert "client_id=c1" in response.redirect_url
    
    def test_validate_token(self):
        store = IdentityFederationStore(); oidc = OIDCProvider(store, "https://app.com")
        is_valid, claims = oidc.validate_token(provider_id="any", token="simulated_token")
        assert is_valid is True

class TestOAuthProvider:
    def test_register_client(self):
        store = IdentityFederationStore(); oauth = OAuthProvider(store, "https://app.com")
        result = oauth.register_client(client_id="test", client_secret="secret", redirect_uris=["https://app.com/cb"])
        assert result["client_id"] == "test"
    
    def test_authorization_code_flow(self):
        store = IdentityFederationStore(); oauth = OAuthProvider(store, "https://app.com")
        oauth.register_client(client_id="test", client_secret="secret", redirect_uris=["https://app.com/cb"])
        response = oauth.authorize(client_id="test", redirect_uri="https://app.com/cb", response_type="code", scope="openid", state="s1")
        assert response.success is True; assert "code=" in response.redirect_url

class TestSessionManager:
    def test_create_session(self):
        store = IdentityFederationStore(); manager = SessionManager(store)
        session = manager.create_session(user_id="u1", provider_id="p1", ip_address="1.2.3.4")
        assert session.user_id == "u1"; assert session.state == SessionState.ACTIVE
    
    def test_validate_session(self):
        store = IdentityFederationStore(); manager = SessionManager(store)
        session = manager.create_session(user_id="u1", provider_id="p1")
        is_valid, sess, err = manager.validate_session(session.id)
        assert is_valid is True

class TestIdentityMapper:
    def test_map_identity(self):
        store = IdentityFederationStore(); mapper = IdentityMapper(store)
        provider = IdentityProvider(id="p1", name="Test", provider_type=IdentityProviderType.OIDC, issuer="https://t.com", attribute_mappings={"email": "email", "name": "display_name"})
        raw = {"email": "u@test.com", "display_name": "User Name"}
        mapped = mapper.map_identity(provider, raw)
        assert mapped["email"] == "u@test.com"; assert mapped["name"] == "User Name"
    
    def test_map_roles(self):
        store = IdentityFederationStore(); mapper = IdentityMapper(store)
        provider = IdentityProvider(id="p1", name="Test", provider_type=IdentityProviderType.OIDC, issuer="https://t.com")
        mapper.add_role_mapping(provider_id="p1", source_group="admins", target_role="admin")
        roles = mapper.map_roles(provider, ["admins"])
        assert "admin" in roles

class TestProvisioningService:
    def test_create_user(self):
        store = IdentityFederationStore(); provisioning = ProvisioningService(store)
        provider = IdentityProvider(id="p1", name="Test", provider_type=IdentityProviderType.OIDC, issuer="https://t.com")
        store.register_provider(provider)
        user, event = provisioning.provision_user(provider, {"provider_user_id": "ext1", "email": "new@test.com"})
        assert user.email == "new@test.com"; assert event.status == "completed"

class TestAuditLogger:
    def test_log_authentication(self):
        store = IdentityFederationStore(); audit = AuditLogger(store)
        event = audit.log_authentication(success=True, provider_id="p1", user_id="u1", authentication_method="oidc")
        assert event.action == "authentication"; assert event.success is True
    
    def test_query_events(self):
        store = IdentityFederationStore(); audit = AuditLogger(store)
        audit.log_authentication(True, "p1", "u1"); audit.log_authentication(False, "p2", "u2")
        events = audit.query(user_id="u1")
        assert len(events) == 1

class TestIdentityFederationService:
    def test_register_provider(self):
        service = IdentityFederationService()
        provider, is_valid, _ = service.register_provider(name="Test SAML", provider_type=IdentityProviderType.SAML, issuer="https://t.com", saml_entity_id="e1", saml_sso_url="https://t.com/sso", saml_certificate="cert")
        assert provider.name == "Test SAML"
    
    def test_authenticate(self):
        service = IdentityFederationService()
        provider, _, _ = service.register_provider(name="Test SAML", provider_type=IdentityProviderType.SAML, issuer="https://t.com", saml_entity_id="e1", saml_sso_url="https://t.com/sso", saml_certificate="cert")
        response = service.authenticate(provider_id=provider.id)
        assert response is not None
    
    def test_provision_user(self):
        service = IdentityFederationService()
        provider, _, _ = service.register_provider(name="Test", provider_type=IdentityProviderType.SAML, issuer="https://t.com", saml_entity_id="e1", saml_sso_url="https://t.com/sso", saml_certificate="cert")
        user = service.provision_user(provider.id, {"provider_user_id": "ext1", "email": "prov@test.com"})
        assert user.email == "prov@test.com"
    
    def test_get_stats(self):
        service = IdentityFederationService()
        stats = service.get_stats()
        assert "store" in stats; assert "audit" in stats

class TestIntegration:
    def test_full_flow(self):
        service = IdentityFederationService()
        provider, _, _ = service.register_provider(name="Test SAML", provider_type=IdentityProviderType.SAML, issuer="https://t.com", saml_entity_id="e1", saml_sso_url="https://t.com/sso", saml_certificate="cert")
        response = service.authenticate(provider_id=provider.id)
        assert response is not None
        user = service.provision_user(provider.id, {"provider_user_id": "u1", "email": "user@test.com"})
        assert user is not None; assert service.get_user(user.id).email == "user@test.com"
    
    def test_azure_ad_quick_setup(self):
        service = IdentityFederationService()
        provider = service.setup_azure_ad(tenant_id="t1", client_id="c1", client_secret="s1")
        assert provider.name == "Azure AD"; assert SSOProvider.AZURE_AD in str(provider.sso_provider)

if __name__ == "__main__": pytest.main([__file__, "-v"])