# GitHub Issues - To Be Created

## Issue 1: bug: Unhandled exceptions and missing validation in BlockchainEvidenceManager

### Description
The BlockchainEvidenceManager class has multiple unhandled exceptions and insufficient input validation that could cause runtime failures and return 500 errors instead of graceful error responses.

### Problems

#### 1. In `store_evidence()`: No validation that `transaction_id` is not None
- Missing null/empty string validation before string operations
- Could cause AttributeError or TypeError

#### 2. In `get_chain()`: Missing error handling for malformed blockchain data
- No try/except for data parsing
- Returns inconsistent responses (sometimes dict, sometimes None)

#### 3. In `verify_integrity()`: No exception handling for hash computation failures
- Could throw exceptions during cryptographic operations
- No fallback behavior defined

#### 4. Inconsistent error responses across methods
- Some methods return dict, some raise exceptions, some return None
- Makes API behavior unpredictable
- Difficult to handle errors in calling code

### Current Behavior
- API returns 500 Internal Server Error instead of 422 Unprocessable Entity
- Inconsistent error handling makes debugging difficult
- Production crashes on edge cases

### Expected Behavior
All methods should:
1. Validate all inputs at entry point
2. Handle exceptions gracefully with appropriate HTTP status codes
3. Return consistent response format
4. Log errors with context for debugging

### Steps to Reproduce

**Test null transaction_id:**
```bash
curl -X POST http://localhost:8000/api/v1/fraud/check \
  -H "Content-Type: application/json" \
  -d '{"transaction_id": null, "amount": 100.0, "timestamp": 1779883200.0, ...}'
```
**Expected:** 422 Validation Error  
**Actual:** 500 Internal Server Error

**Test empty transaction_id:**
```bash
curl -X POST http://localhost:8000/api/v1/fraud/check \
  -H "Content-Type: application/json" \
  -d '{"transaction_id": "", "amount": 100.0, "timestamp": 1779883200.0, ...}'
```
**Expected:** 422 Validation Error  
**Actual:** 500 Internal Server Error

**Test malformed blockchain data:**
```python
manager = BlockchainEvidenceManager()
manager.store_evidence(transaction_id="test_001", data="invalid_json")
manager.get_chain(transaction_id="test_001")  # Should handle gracefully
```

### Location
- **File:** `src/features/blockchain_evidence.py`
- **Lines:** 45-120
- **Class:** `BlockchainEvidenceManager`
- **Methods:** `store_evidence()`, `get_chain()`, `verify_integrity()`

### Impact
- **Severity:** Medium
- **Type:** Bug (Error Handling)
- **Affects:** API stability, Error responses, User experience
- **Production Risk:** Moderate - causes 500 errors on malformed input

### Solution Approach

**Phase 1: Input Validation**
```python
def store_evidence(self, transaction_id: str, data: dict) -> dict:
    # Add validation
    if not transaction_id or not isinstance(transaction_id, str):
        raise ValidationError("transaction_id must be non-empty string")
    if not data or not isinstance(data, dict):
        raise ValidationError("data must be non-empty dict")
    # ... rest of implementation
```

**Phase 2: Exception Handling**
```python
def get_chain(self, transaction_id: str) -> dict:
    try:
        # blockchain operations
    except JsonDecodeError as e:
        logger.error(f"Malformed blockchain data for {transaction_id}: {e}")
        raise ValidationError("Invalid blockchain data format")
    except Exception as e:
        logger.error(f"Unexpected error in get_chain: {e}")
        raise
```

**Phase 3: Consistent Error Responses**
All methods should raise `ValidationError` from `src.exceptions.base_exceptions` with:
- Clear error message
- HTTP status code context
- Suggestion for fix

### Acceptance Criteria
- [ ] All inputs validated at method entry point
- [ ] All exceptions handled with appropriate error types
- [ ] Error responses consistent across all methods
- [ ] Returns 422 validation errors (not 500)
- [ ] Added unit tests for all error paths
- [ ] All tests passing locally
- [ ] Code coverage for error handling >90%

### Related Issues
- Issue #7: API Input Validation and Error Handling
- Issue #338: Harden fragile fallback graph risk scoring

### Labels
`type:bug` `type:error-handling` `priority:medium`

---

## Issue 2: chore: Remove hardcoded config values and use environment variables

### Description
Multiple hardcoded values prevent flexible deployment across environments. All configuration should be externalized to environment variables and config files for true multi-environment support.

### Hardcoded Values to Externalize

#### 1. CORS Origins (src/api/main.py, line ~15)
```python
# Current (HARDCODED):
CORS_ORIGINS = ["http://localhost:3000"]

# Should be:
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")
```

#### 2. Max Batch Size (src/config/defaults.py, line ~23)
```python
# Current (HARDCODED):
MAX_BATCH_SIZE = 100

# Should be:
MAX_BATCH_SIZE = int(os.getenv("MAX_BATCH_SIZE", "100"))
```

#### 3. Risk Thresholds (src/features/entropy_calculator.py, lines ~12-15)
```python
# Current (HARDCODED):
HIGH_RISK_THRESHOLD = 0.8
MEDIUM_RISK_THRESHOLD = 0.5
LOW_RISK_THRESHOLD = 0.2

# Should be from config/thresholds.yaml:
HIGH_RISK_THRESHOLD: ${HIGH_RISK_THRESHOLD:-0.8}
MEDIUM_RISK_THRESHOLD: ${MEDIUM_RISK_THRESHOLD:-0.5}
LOW_RISK_THRESHOLD: ${LOW_RISK_THRESHOLD:-0.2}
```

#### 4. Model Paths (src/scoring/risk_model.py, line ~5)
```python
# Current (HARDCODED):
MODEL_PATH = "./models/"

# Should be:
MODEL_PATH = os.getenv("MODEL_PATH", "./models/")
```

#### 5. Rate Limiting Config (src/api/security.py)
```python
# Current (HARDCODED):
RATE_LIMIT_PER_ACCOUNT = 100  # req/min
RATE_LIMIT_PER_KEY = 1000     # req/min
RATE_LIMIT_PER_IP = 500       # req/min

# Should be:
RATE_LIMIT_PER_ACCOUNT = int(os.getenv("RATE_LIMIT_PER_ACCOUNT", "100"))
RATE_LIMIT_PER_KEY = int(os.getenv("RATE_LIMIT_PER_KEY", "1000"))
RATE_LIMIT_PER_IP = int(os.getenv("RATE_LIMIT_PER_IP", "500"))
```

#### 6. API Port (src/api/main.py)
```python
# Current (HARDCODED):
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)

# Should be:
if __name__ == "__main__":
    port = int(os.getenv("API_PORT", "8000"))
    host = os.getenv("API_HOST", "0.0.0.0")
    uvicorn.run(app, host=host, port=port)
```

### Current Issues
- Production deployment requires code changes
- Different environments (dev, staging, prod) need different values
- Can't use Docker environment variables
- K8s ConfigMaps not respected
- Difficult to update config without redeploying

### Expected Solution
1. **Environment Variables** for all configuration
   - `CORS_ORIGINS`
   - `MAX_BATCH_SIZE`
   - `MODEL_PATH`
   - `API_PORT`, `API_HOST`
   - `RATE_LIMIT_*`
   - `LOG_LEVEL`
   - Database credentials

2. **Config File** (config.yaml / config/thresholds.yaml)
   - Risk thresholds
   - Feature weights
   - Cache TTLs
   - Model parameters

3. **Priority Loading Order**
   1. Environment variables (highest)
   2. config.yaml
   3. config/thresholds.yaml
   4. Defaults in code

### Impact
- **Severity:** Medium
- **Type:** Operational (DevOps)
- **Affects:** Deployments, Configuration management, Environment parity
- **Benefits:** 
  - Same container image for dev/staging/prod
  - 12-factor app compliance
  - Kubernetes readiness
  - Docker best practices

### Acceptance Criteria
- [ ] All hardcoded values moved to environment variables or config files
- [ ] Environment variables documented in `.env.example`
- [ ] Config loading follows 12-factor app principles
- [ ] Works with Docker environment variables
- [ ] Works with Kubernetes ConfigMaps
- [ ] Backward compatible with existing deployments
- [ ] Tests verify config loading works correctly
- [ ] Updated deployment documentation

### Testing Strategy
```python
# Test 1: Environment variable override
os.environ["CORS_ORIGINS"] = "https://example.com,https://app.example.com"
config = load_config()
assert config.cors_origins == ["https://example.com", "https://app.example.com"]

# Test 2: Config file override
config_yaml = "MAX_BATCH_SIZE: 50"
config = load_config_from_yaml(config_yaml)
assert config.max_batch_size == 50

# Test 3: Environment takes priority
os.environ["MAX_BATCH_SIZE"] = "75"
config = load_config(config_yaml="MAX_BATCH_SIZE: 50")
assert config.max_batch_size == 75  # Env wins
```

### Labels
`type:chore` `type:devops` `priority:medium`

---

## Issue 3: feat: Implement health check and readiness probe endpoints for Kubernetes deployments

### Description
Application lacks standard health check endpoints needed for production orchestration. Kubernetes, Docker Swarm, and other orchestrators rely on `/health` and `/readiness` endpoints to determine pod status and make routing decisions.

### Missing Endpoints

#### 1. GET /health - Liveness Probe
**Purpose:** Determine if application process is alive
**Response (200 OK):**
```json
{
  "status": "ok",
  "timestamp": "2026-05-29T14:30:00Z",
  "uptime_seconds": 3600,
  "version": "2.0.1"
}
```
**Response (500 Internal Error):** When process is deadlocked or critical error

#### 2. GET /readiness - Readiness Probe
**Purpose:** Determine if application is ready to serve traffic
**Response (200 OK):**
```json
{
  "status": "ready",
  "timestamp": "2026-05-29T14:30:00Z",
  "checks": {
    "database": {
      "status": "ok",
      "latency_ms": 5
    },
    "cache": {
      "status": "ok",
      "latency_ms": 2
    },
    "model_loaded": {
      "status": "ok",
      "model": "fraud_detector_v2.0"
    },
    "dependencies": {
      "status": "ok",
      "torch": "available",
      "pandas": "available"
    }
  }
}
```
**Response (503 Service Unavailable):** When any critical dependency fails

#### 3. GET /metrics - Prometheus Metrics
**Purpose:** Expose application metrics for monitoring
**Response (200 OK):**
```
# HELP api_requests_total Total API requests
# TYPE api_requests_total counter
api_requests_total{method="POST",endpoint="/api/v1/fraud/check",status="200"} 1250
api_requests_total{method="POST",endpoint="/api/v1/fraud/check",status="422"} 45
api_requests_total{method="POST",endpoint="/api/v1/fraud/batch",status="200"} 890

# HELP api_request_duration_seconds Request latency
# TYPE api_request_duration_seconds histogram
api_request_duration_seconds_bucket{endpoint="/api/v1/fraud/check",le="0.1"} 1100
api_request_duration_seconds_bucket{endpoint="/api/v1/fraud/check",le="0.5"} 1200
api_request_duration_seconds_bucket{endpoint="/api/v1/fraud/check",le="1.0"} 1250

# HELP cache_hits_total Cache hit count
# TYPE cache_hits_total counter
cache_hits_total 5420

# HELP models_loaded_total Models currently loaded
# TYPE models_loaded_total gauge
models_loaded_total 3
```

### Kubernetes Configuration Examples

**Deployment with Health Checks:**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: aegis-graph-sentinel
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: app
        image: aegis-graph-sentinel:2.0
        ports:
        - containerPort: 8000
        
        # Liveness probe - restart if dead
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
          failureThreshold: 3
        
        # Readiness probe - stop traffic if not ready
        readinessProbe:
          httpGet:
            path: /readiness
            port: 8000
          initialDelaySeconds: 10
          periodSeconds: 5
          failureThreshold: 2
        
        # Graceful shutdown
        lifecycle:
          preStop:
            exec:
              command: ["/bin/sh", "-c", "sleep 5"]
```

### Current Issues Without These Endpoints
- ❌ Kubernetes can't determine pod health → random restarts
- ❌ No graceful shutdown draining → data loss
- ❌ No observability into deployment health
- ❌ Load balancers can't route away from unhealthy pods
- ❌ Rollouts can't verify successful deployments
- ❌ No monitoring/alerting on infrastructure level
- ❌ Failed deployments don't get caught automatically

### Expected Solution

**Location:** `src/api/main.py` (new routes)

**Implementation Requirements:**
1. `/health` endpoint returns 200 if process is running
2. `/readiness` endpoint checks all critical dependencies
3. `/metrics` endpoint exports Prometheus metrics
4. All endpoints exclude rate limiting (internal only)
5. Dependency checks are fast (<100ms)
6. Results cached for 5 seconds to avoid overload

**Dependency Checks:**
- Database connectivity (ping with timeout)
- Cache availability (check connection)
- Model loading status
- Optional dependency availability
- Filesystem access (if needed)

### Impact
- **Severity:** Medium
- **Type:** Feature (Infrastructure)
- **Affects:** Production deployments, Kubernetes readiness, Monitoring
- **Production Risk:** High - without this, Kubernetes can't manage pods properly
- **Benefits:**
  - Automatic pod restart on failure
  - Graceful rollouts
  - Reduced downtime
  - Better monitoring

### Acceptance Criteria
- [ ] GET /health endpoint implemented and returns 200
- [ ] GET /readiness endpoint checks all dependencies
- [ ] GET /metrics endpoint exports Prometheus metrics
- [ ] All endpoints exclude rate limiting
- [ ] Dependency checks timeout after 100ms
- [ ] Results cached to prevent overload
- [ ] Added integration tests for all endpoints
- [ ] Documentation updated with Kubernetes example
- [ ] Metrics include: requests, latency, errors, cache stats
- [ ] All tests passing

### Testing Strategy

```python
# Test 1: Health check returns OK when running
response = client.get("/health")
assert response.status_code == 200
data = response.json()
assert data["status"] == "ok"
assert "timestamp" in data
assert "uptime_seconds" in data

# Test 2: Readiness check passes when dependencies available
response = client.get("/readiness")
assert response.status_code == 200
data = response.json()
assert data["status"] == "ready"
assert data["checks"]["database"]["status"] == "ok"

# Test 3: Readiness check fails when database down
# (mock database disconnect)
response = client.get("/readiness")
assert response.status_code == 503
data = response.json()
assert data["status"] == "not_ready"
assert data["checks"]["database"]["status"] == "error"

# Test 4: Metrics endpoint returns Prometheus format
response = client.get("/metrics")
assert response.status_code == 200
assert "api_requests_total" in response.text
assert "api_request_duration_seconds" in response.text
```

### Dependencies
- `prometheus-client` for metrics export
- Existing logging and monitoring setup

### Related Issues
- Issue #262: BlockchainEvidenceManager refactor
- Issue #261: Monolithic API boot path

### Labels
`type:feature` `type:infrastructure` `priority:medium`

---

# How to Use This File

1. Copy each issue section (separated by `---`)
2. Remove the `---` separator
3. Paste into GitHub issue creation form
4. Adjust based on your needs
5. Add assignee, labels, and milestone
6. Create the issue

**Recommended order:**
1. Issue 1 (Bug - fixes immediate problems)
2. Issue 2 (Chore - improves operations)
3. Issue 3 (Feature - adds Kubernetes support)
