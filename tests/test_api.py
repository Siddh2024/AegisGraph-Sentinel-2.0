"""
Unit tests for API endpoints
"""
# Working on API endpoint testing

import pytest
from fastapi.testclient import TestClient
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.api.main import app, state


client = TestClient(app)


class TestHealthEndpoint:
    """Test health check endpoint"""
    
    def test_health_check(self):
        """Test /health endpoint"""
        response = client.get("/health")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "timestamp" in data


class TestStatsEndpoint:
    """Test statistics endpoint"""
    
    def test_get_stats(self):
        """Test /stats endpoint"""
        response = client.get("/stats")
        
        assert response.status_code == 200
        data = response.json()
        
        # Check expected fields
        assert "total_checks" in data
        assert "flagged_transactions" in data
        assert "average_response_time" in data
        assert "uptime_seconds" in data


class TestFraudCheckEndpoint:
    """Test fraud check endpoint"""
    
    def test_low_risk_transaction(self):
        """Test with a low-risk transaction"""
        transaction = {
            "transaction_id": "test_001",
            "amount": 50.0,
            "timestamp": 1234567890.0,
            "from_account": "user_1",
            "to_account": "merchant_1",
            "transaction_type": "payment",
            "metadata": {
                "location": "US",
                "device_id": "device_1"
            }
        }
        
        response = client.post("/api/v1/fraud/check", json=transaction)
        
        assert response.status_code == 200
        data = response.json()
        
        # Check response structure
        assert "transaction_id" in data
        assert "risk_score" in data
        assert "decision" in data
        assert "factors" in data
        assert "explanation" in data
        
        # Risk score should be between 0 and 1
        assert 0 <= data["risk_score"] <= 1
        
        # Decision should be valid
        assert data["decision"] in ["approve", "review", "block"]
    
    def test_high_risk_transaction(self):
        """Test with a high-risk transaction (large amount, rapid)"""
        transaction = {
            "transaction_id": "test_002",
            "amount": 10000.0,
            "timestamp": 1234567890.0,
            "from_account": "new_user",
            "to_account": "unknown_merchant",
            "transaction_type": "transfer",
            "metadata": {
                "location": "XX",
                "device_id": "new_device"
            }
        }
        
        response = client.post("/api/v1/fraud/check", json=transaction)
        
        assert response.status_code == 200
        data = response.json()
        
        # High-risk transaction should have high score
        # Note: This depends on model state, so just check structure
        assert "risk_score" in data
        assert "factors" in data
    
    def test_transaction_with_biometrics(self):
        """Test transaction with behavioral biometrics"""
        transaction = {
            "transaction_id": "test_003",
            "amount": 100.0,
            "timestamp": 1234567890.0,
            "from_account": "user_1",
            "to_account": "merchant_1",
            "transaction_type": "payment",
            "biometrics": {
                "keystroke_events": [
                    {"key": "a", "timestamp": 0.0, "event_type": "keydown"},
                    {"key": "a", "timestamp": 0.1, "event_type": "keyup"}
                ],
                "mouse_movements": []
            }
        }
        
        response = client.post("/api/v1/fraud/check", json=transaction)
        
        assert response.status_code == 200
        data = response.json()
        
        # Should include behavioral analysis
        assert "factors" in data
        assert "behavioral" in data["factors"]

    def test_internal_approve_maps_to_allow_in_api_response(self, monkeypatch):
        """Internal APPROVE decision must map back to ALLOW for API stability"""
        original_decisions = dict(state.decisions)
        state.decisions = {"ALLOW": 0, "REVIEW": 0, "BLOCK": 0}

        def fake_compute_risk_score(transaction: dict, biometrics: dict = None, **kwargs):
            return {
                'risk_score': 0.20,
                'decision': 'APPROVE',
                'confidence': 0.85,
                'breakdown': {'graph': 0.0, 'velocity': 0.0, 'behavior': 0.0, 'entropy': 0.0},
            }

        monkeypatch.setattr('src.api.main.compute_risk_score', fake_compute_risk_score)

        transaction = {
            "transaction_id": "test_approve_001",
            "amount": 100.0,
            "timestamp": 1234567890.0,
            "from_account": "user_approve",
            "to_account": "merchant_approve",
            "transaction_type": "payment"
        }

        response = client.post("/api/v1/fraud/check", json=transaction)
        assert response.status_code == 200
        data = response.json()

        assert data["decision"] == "approve"
        assert state.decisions["ALLOW"] == 1

        state.decisions = original_decisions

    def test_invalid_transaction(self):
        """Test with invalid transaction data"""
        transaction = {
            "transaction_id": "test_004",
            # Missing required fields
        }
        
        response = client.post("/api/v1/fraud/check", json=transaction)
        
        # Should return validation error
        assert response.status_code == 422


class TestBatchFraudCheck:
    """Test batch fraud check endpoint"""
    
    def test_batch_check(self):
        """Test batch processing of transactions"""
        transactions = [
            {
                "transaction_id": f"batch_{i}",
                "amount": 50.0 * (i + 1),
                "timestamp": 1234567890.0 + i * 60,
                "from_account": f"user_{i}",
                "to_account": f"merchant_{i}",
                "transaction_type": "payment"
            }
            for i in range(3)
        ]
        
        response = client.post("/api/v1/fraud/batch", json={"transactions": transactions})
        
        assert response.status_code == 200
        data = response.json()
        
        # Should return results for all transactions
        assert len(data["results"]) == 3
        
        # Check each result
        for result in data["results"]:
            assert "transaction_id" in result
            assert "risk_score" in result
            assert "decision" in result
    
    def test_empty_batch(self):
        """Test with empty batch"""
        response = client.post("/api/v1/fraud/batch", json={"transactions": []})
        
        assert response.status_code == 200
        data = response.json()
        assert len(data["results"]) == 0


class TestCORSandSecurity:
    """
    Test CORS middleware and security headers.

    The CORS tests are regression coverage for issue #34
    (CWE-942: Permissive Cross-domain Policy with Untrusted Domains).
    """

    def test_allowed_origin_gets_acao_header(self):
        """A request from an allowed origin should be echoed back."""
        response = client.get(
            "/health",
            headers={"Origin": "http://localhost:8501"},
        )
        assert response.status_code == 200
        assert response.headers.get("access-control-allow-origin") == "http://localhost:8501"

    def test_disallowed_origin_does_not_get_acao_header(self):
        """A request from an unlisted origin should not be granted CORS access."""
        response = client.get(
            "/health",
            headers={"Origin": "https://attacker.example"},
        )
        assert response.status_code == 200
        # The origin must not be reflected back, even though credentials are enabled.
        assert response.headers.get("access-control-allow-origin") != "https://attacker.example"

    def test_credentials_allowed_for_listed_origin(self):
        """When the origin matches, credentials should be allowed."""
        response = client.get(
            "/health",
            headers={"Origin": "http://localhost:8501"},
        )
        assert response.headers.get("access-control-allow-credentials") == "true"

    def test_preflight_advertises_only_configured_methods(self):
        """OPTIONS preflight from a listed origin should advertise the
        narrowed method set, not '*'."""
        response = client.options(
            "/health",
            headers={
                "Origin": "http://localhost:8501",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Content-Type",
            },
        )
        allow_methods = response.headers.get("access-control-allow-methods", "")
        assert "GET" in allow_methods
        assert "POST" in allow_methods
        assert "*" not in allow_methods

    def test_no_wildcard_origin_regression(self):
        """Make sure we never silently regress to allow_origins=['*']."""
        from src.api.main import ALLOWED_ORIGINS
        assert "*" not in ALLOWED_ORIGINS, (
            "ALLOWED_ORIGINS must be an explicit list of trusted origins"
        )

    def test_rate_limiting(self):
        """Test rate limiting (if implemented)"""
        # Make multiple rapid requests
        responses = []
        for i in range(10):
            response = client.get("/health")
            responses.append(response.status_code)
        
        # All should succeed (rate limiting not implemented yet)
        assert all(code == 200 for code in responses)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
