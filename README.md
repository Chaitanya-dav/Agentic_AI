# 🛡️ Agentic AI–Driven Secure Approval and Execution System

> **A zero-trust, cryptographically verified approval and execution framework combining Agentic AI orchestration with deterministic security guardrails.**

---

## 📌 Executive Summary & Architectural Principle

In modern enterprise workflows and AI-driven automation, LLM-based autonomous agents are increasingly deployed to trigger high-impact actions (financial transactions, infrastructure provisioning, access elevation). However, **relying on LLM reasoning for security decisions is fundamentally dangerous** due to prompt injection, hallucination, non-determinism, and parameter tampering.

### 🔑 The Core Architectural Rule
```
Agentic AI (LangGraph) -> Orchestration, NL Extraction, Risk Analysis, Decision Rationale
Deterministic Code     -> Cryptographic Canonicalization, SHA-256 Hashing, 9-Point Gate Enforcement
```
**An AI Agent or LLM is NEVER allowed to directly override cryptographic or deterministic security controls.** 
The LLM investigates, orchestrates, and explains; deterministic code makes the binary `PASS / REFUSE` execution decision.

---

## 🏗️ System Architecture & ASCII Diagram

```
                              [ Natural Language Prompt ]
                                          │
                                          ▼
                      ┌────────────────────────────────────────┐
                      │        ACTION ANALYSIS AGENT           │
                      │  • Parses structured parameters        │
                      │  • Evaluates risk level & necessity    │
                      └───────────────────┬────────────────────┘
                                          │
                                          ▼
                      ┌────────────────────────────────────────┐
                      │     DETERMINISTIC SECURITY TOOLS       │
                      │  • Alphabetical key-canonicalization   │
                      │  • SHA-256 payload hash computation    │
                      └───────────────────┬────────────────────┘
                                          │
                                          ▼
                      ┌────────────────────────────────────────┐
                      │      APPROVAL ORCHESTRATOR AGENT       │
                      │  • Assigns unique approval_id          │
                      │  • Determines required role            │
                      │  • Enforces Four-Eyes Policy           │
                      └───────────────────┬────────────────────┘
                                          │
                                          ▼
                      ┌────────────────────────────────────────┐
                      │        SUSPENSION & CHECKPOINT         │
                      │  • Saves canonical payload + hash      │
                      │  • Captures environment state snapshot │
                      │  • Action status: PENDING_APPROVAL     │
                      └───────────────────┬────────────────────┘
                                          │
                                          ▼
                              [ HUMAN APPROVAL EVENT ]
                                (Approver != Creator)
                                          │
                                          ▼
                      ┌────────────────────────────────────────┐
                      │         CRYPTOGRAPHIC TOKEN            │
                      │   { approval_id, payload_hash,         │
                      │     creator, approver, expires_at,     │
                      │     HMAC-SHA256 signature }            │
                      └───────────────────┬────────────────────┘
                                          │
                                          ▼
                              [ RESUME EXECUTION GATE ]
                                          │
                                          ▼
                      ┌────────────────────────────────────────┐
                      │      SECURITY VERIFICATION AGENT       │
                      │     (9-Point Deterministic Matrix)     │
                      │                                        │
                      │ 1. Current Payload Hash Recomputation  │
                      │ 2. Checkpoint Hash Match               │
                      │ 3. Token Payload Hash Match            │
                      │ 4. Approval ID Anti-Replay Binding     │
                      │ 5. Time-to-Live (TTL) Expiry           │
                      │ 6. Four-Eyes Separation (A != B)       │
                      │ 7. Approval State Machine (APPROVED)   │
                      │ 8. Single-Use Gate (Not Consumed)      │
                      │ 9. Dynamic Policy & Boundary Checks    │
                      └───────────────────┬────────────────────┘
                                          │
                        ┌─────────────────┴─────────────────┐
               [ All 9 Checks PASS ]               [ Any Check FAILS ]
                        │                                   │
                        ▼                                   ▼
        ┌───────────────────────────────┐   ┌───────────────────────────────┐
        │        EXECUTION AGENT        │   │       EXECUTION REFUSED       │
        │ • Atomic CAS DB Consume       │   │ • Action status: REFUSED      │
        │ • Status: EXECUTED            │   │ • Detailed failure audit log  │
        │ • Approval: CONSUMED          │   │ • Zero side-effects           │
        └───────────────────────────────┘   └───────────────────────────────┘
```

---

## 🔒 The 9-Point Deterministic Security Protocol

Before any suspended action can resume and execute, the deterministic validator evaluates all 9 conditions:

| # | Check Code | Name | Validation Rule | Threat Mitigated |
|---|------------|------|-----------------|------------------|
| **1** | `CHK_PAYLOAD_INTEGRITY` | Current Payload Hash | `SHA256(canonicalize(live)) == action.payload_hash` | Direct database alteration / tampering |
| **2** | `CHK_CHECKPOINT_HASH` | Checkpoint Hash Match | `checkpoint.payload_hash == current_hash` | Mid-flight state modification |
| **3** | `CHK_TOKEN_PAYLOAD_HASH` | Token Payload Hash | `token.payload_hash == current_hash` | Unauthorized parameter swapping |
| **4** | `CHK_APPROVAL_ID_BINDING`| Approval ID Binding | `token.approval_id == stored_approval_id` | **Cross-Action Token Replay** |
| **5** | `CHK_EXPIRY_VALIDATION` | TTL Expiry Validation | `current_time < approval.expires_at` | Stale or zombie authorization usage |
| **6** | `CHK_FOUR_EYES_POLICY` | Four-Eyes Separation | `creator_id != approver_id` | Rogue insider self-authorization |
| **7** | `CHK_APPROVAL_STATUS` | State Machine Gate | `approval.status == 'APPROVED'` | Unapproved or rejected execution |
| **8** | `CHK_NOT_CONSUMED` | Single-Use Gate | `approval.is_consumed == False` | **Double execution / Race conditions** |
| **9** | `CHK_DYNAMIC_POLICY_BOUNDARIES` | Live Policy Boundaries | Live check of limits, AML, sanctions, account status | Boundary drift between approval & resume |

---

## 🚨 Four Attack Demonstrations & Proof of Security

The system includes a dedicated **Interactive Attack Simulation Laboratory** in both the backend API and dashboard UI:

### Attack 1: Payload Tampering
- **Scenario**: Action is created (₹50,000 to Ravi) and approved. An adversary directly alters the database record to ₹500,000 before resume.
- **Defense**: At resume, the system re-computes `SHA256(canonicalize(live))`. `approved_hash != current_hash`.
- **Result**: `REFUSED — PAYLOAD TAMPERING DETECTED`.

### Attack 2: Replay Across Identical Approvals *(Critical Concept)*
- **Scenario**: Two identical actions exist:
  - Action A: ₹10,000 → Ravi, `approval_id = A001`
  - Action B: ₹10,000 → Ravi, `approval_id = A002`
- Both share the exact same `payload_hash`. An adversary attempts to execute unapproved Action B using Action A's approval token.
- **Why `payload_hash` alone is insufficient**: If the system only checked `token.payload_hash == current_payload_hash`, the attack would succeed!
- **Defense**: The token binds BOTH `payload_hash` AND `approval_id`. Check 4 fails (`token.approval_id == A001 != A002`).
- **Result**: `REFUSED — APPROVAL REPLAY / APPROVAL ID MISMATCH`.

### Attack 3: Expiry Attack
- **Scenario**: An action is approved, but the TTL window expires before execution resumes.
- **Defense**: Deterministic timestamp comparison rejects expired approvals.
- **Result**: `REFUSED — APPROVAL EXPIRED`.

### Attack 4: Self-Approval Attack
- **Scenario**: Creator `Alice` attempts to authorize her own high-value action.
- **Defense**: Approval orchestrator strictly enforces `creator_id != approver_id`.
- **Result**: `REFUSED — FOUR-EYES POLICY VIOLATION`.

### Additional Scenario: World Changed / Policy Boundary Drift
- **Scenario**: An action is approved when global risk is `LOW` and recipient is `TRUSTED`. Before resume, sanctions intelligence lists the recipient as `BLOCKED` or global risk escalates to `HIGH`.
- **Defense**: The system does NOT assume past approvals remain valid. Live policy boundaries are re-evaluated at resume time.
- **Result**: `REFUSED — POLICY BOUNDARIES CHANGED`.

---

## ⚡ Concurrency & Double-Execution Protection

When two or more simultaneous execution requests arrive for the same approval:
- The system executes an **Atomic Compare-And-Swap (CAS)** update:
  ```sql
  UPDATE approvals 
  SET is_consumed = 1, status = 'CONSUMED' 
  WHERE id = :id AND is_consumed = 0 AND status = 'APPROVED';
  ```
- **Result**: Exactly **1** thread receives `rowcount == 1` and proceeds to execution; all other **N - 1** threads receive `rowcount == 0` and are safely rejected.
- **Production Note**: In SQLite, WAL mode with `busy_timeout` is enabled. In production PostgreSQL, row-level locking (`SELECT FOR UPDATE`) is used.

---

## 📦 Installation & Setup

### 1. Prerequisites
- Python 3.10+ (tested on Python 3.14)
- Git / PowerShell / Bash

### 2. Clone and Setup Environment
```bash
git clone <repo-url>
cd Project_AI

# Create Python virtual environment
python -m venv venv

# Activate on Windows PowerShell:
.\venv\Scripts\Activate.ps1
# Activate on Linux / macOS:
# source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Environment Variables (`.env`)
Copy the template:
```bash
cp .env.example .env
```
Default `.env` configuration:
```ini
APP_NAME="Agentic AI Secure Approval & Execution System"
DATABASE_URL=sqlite:///./secure_execution.db
SECRET_KEY=super-secret-cryptographic-signing-key-2026
USE_MOCK_LLM=true
OPENAI_API_KEY=
```
> **Zero-Config Reliability**: If `USE_MOCK_LLM=true` (default), the system runs completely offline with deterministic NLP extraction. If you provide `OPENAI_API_KEY`, it connects to OpenAI LangChain agents automatically.

---

## 🚀 How to Run the Application

### Start Backend & Dashboard Server
```bash
# From project root with venv activated:
.\venv\Scripts\uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

### Open the Dashboard
Open your browser and navigate to:
```
http://127.0.0.1:8000
```
- **Web Dashboard**: `http://127.0.0.1:8000/`
- **Swagger API Docs**: `http://127.0.0.1:8000/docs`
- **Health Check**: `http://127.0.0.1:8000/health`

---

## 🧪 Running Automated Tests

Run the complete 13-scenario automated test suite:
```bash
.\venv\Scripts\pytest -v
```

### Test Coverage Breakdown:
1. `tests/test_approval.py`:
   - `test_normal_approval_workflow_success`: Full lifecycle test from natural language to settlement.
   - `test_structured_creation_and_rejection`: Rejection state transitions.
   - `test_checkpoint_hash_mismatch_fails`: State tampering detection.
   - `test_approval_id_mismatch_with_matching_payload_hash`: Cryptographic binding test.
2. `tests/test_attacks.py`:
   - `test_attack1_tampered_payload_fails`: Payload tampering attack.
   - `test_attack2_replay_across_identical_approvals_fails`: Cross-action replay attack.
   - `test_attack3_expired_approval_fails`: Token expiration attack.
   - `test_attack4_self_approval_fails`: Self-approval Four-Eyes violation.
   - `test_attack5_world_changed_boundary_fails`: Policy drift attack.
   - `test_consumed_approval_cannot_execute_again`: Double-execution prevention.
   - `test_attack_lab_service_demos`: Direct service demo assertions.
   - `test_api_attack_endpoints`: FastAPI REST endpoint validation.
3. `tests/test_concurrency.py`:
   - `test_concurrent_execution_race_condition`: 10 simultaneous threads attempting execution against 1 approval -> Exactly 1 succeeds, 9 fail cleanly.

---

## 🎮 Interactive Demo Walkthrough

1. **Natural Language Action Creation**:
   - In the dashboard, enter: `"Transfer ₹50,000 to Ravi for cloud server infrastructure"`.
   - Watch the live canonical payload preview and SHA-256 hash update in real time.
   - Click **Create Action, Checkpoint & Suspend**.
2. **Four-Eyes Review & Approval**:
   - Locate the pending action in the table. Click **Review & Approve**.
   - Select `Bob (Manager)`. Click **Issue Signed Token & Approve**.
3. **Resume & 9-Point Security Inspection**:
   - Click **Resume & Execute**.
   - Observe the 9 security cards glow green with `PASS` and view the execution logs.
4. **Attack Laboratory Testing**:
   - Click **Test Tampering**: Watch the system detect hash mismatch and refuse execution.
   - Click **Test Replay**: Observe payload hash pass while `approval_id` fails.
   - Click **Test Policy Drift**: Observe rejection due to simulated environment changes.

---

## 📂 Project Structure

```
Project_AI/
├── backend/
│   ├── config.py             # App settings & LLM configuration
│   ├── database.py           # SQLite connection with WAL mode & sessionmaker
│   ├── models.py             # SQLAlchemy models (Action, Approval, Checkpoint, AuditLog, etc.)
│   ├── schemas.py            # Pydantic v2 validation models & response schemas
│   ├── security/
│   │   ├── canonicalization.py  # Deterministic key-sorted canonical string builder
│   │   ├── hashing.py           # SHA-256 hashing tools
│   │   ├── tokens.py            # Signed approval token generation & verification
│   │   ├── policy.py            # Deterministic 9-point security verification engine
│   │   └── concurrency.py       # Atomic CAS state transitions
│   ├── agents/
│   │   ├── action_agent.py      # Action Analysis Agent (NL parsing & risk scoring)
│   │   ├── approval_agent.py    # Approval Orchestrator Agent (Four-Eyes & checkpoints)
│   │   ├── security_agent.py    # Security Verification Agent (Investigation & audit)
│   │   ├── execution_agent.py   # Execution Agent (Atomic settlement)
│   │   └── graph.py             # LangGraph state machine orchestrator
│   ├── services/
│   │   ├── action_service.py    # Action lifecycle management
│   │   ├── approval_service.py  # Claim, approve, reject handlers
│   │   ├── execution_service.py # Resume and verification orchestrator
│   │   ├── audit_service.py     # Immutable audit log recorder
│   │   └── attack_service.py    # Pre-built scenarios for the 5 attack vectors
│   └── main.py               # FastAPI application & static file router
├── frontend/
│   ├── index.html            # Cyber-security dashboard HTML
│   ├── style.css             # Glassmorphism dark aesthetic stylesheet
│   └── app.js                # Interactive UI logic & live attack lab runner
├── tests/
│   ├── conftest.py           # Test fixtures & isolated DB session
│   ├── test_approval.py      # Workflow & security baseline tests
│   ├── test_attacks.py       # 5 attack vector test suite
│   └── test_concurrency.py   # Race condition & concurrency stress test
├── requirements.txt
├── .env.example
└── README.md
```
