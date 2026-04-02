# Tamper-Evident Logging System

> **Task 1** — Cybersecurity & Network Security Internship Assessment  
> A production-grade secure audit-log prototype with cryptographic integrity guarantees.

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Project Structure](#project-structure)
4. [How to Run](#how-to-run)
5. [Modules](#modules)
6. [Tamper Detection Capabilities](#tamper-detection-capabilities)
7. [Sample Output](#sample-output)
8. [Manual Testing Guide](#manual-testing-guide)

---

## Overview

This system implements a **tamper-evident logging mechanism** that behaves like a real-world security audit trail. It guarantees that any attempt to **modify**, **delete**, or **reorder** log entries is immediately detectable through multi-layered cryptographic verification.

### Key Features

- **Append-only storage** — log entries can only be added, never edited or removed
- **SHA-256 hash chain** — each entry is cryptographically linked to the previous one
- **Merkle-tree checkpointing** — batches of entries are verified via Merkle roots
- **Ed25519 digital signatures** — checkpoint roots are signed for authenticity
- **RFC 3161-style trusted timestamps** — simulated timestamping for temporal integrity
- **Forensic tamper reports** — detailed, human-readable reports on detected anomalies
- **18 automated tests** — complete test coverage across all security layers
- **REST API (FastAPI)** — web-accessible endpoints with Swagger UI
- **Cloud-deployable** — ready for Render deployment with a public URL

---

## Architecture

The system uses a **5-layer security architecture**:

```
┌──────────────────────────────────────────────────────────┐
│  Layer 5: Immutable Append-Only Storage (JSONL + locks)  │
├──────────────────────────────────────────────────────────┤
│  Layer 4: Trusted Timestamping (RFC 3161 simulation)     │
├──────────────────────────────────────────────────────────┤
│  Layer 3: Digital Signatures (Ed25519 on checkpoints)    │
├──────────────────────────────────────────────────────────┤
│  Layer 2: Merkle-Tree Checkpointing (batch verification) │
├──────────────────────────────────────────────────────────┤
│  Layer 1: Entry-Level Hash Chain (SHA-256 linkage)       │
└──────────────────────────────────────────────────────────┘
```

### How Each Layer Works

| Layer | Mechanism | Detects |
|-------|-----------|---------|
| **1** | SHA-256 hash chain linking entries sequentially | Modified entries, broken chain |
| **2** | Merkle tree over fixed-size batches of entries | Batch-level tampering, scalable verification |
| **3** | Ed25519 signature on each Merkle root | Forged checkpoints, unauthorized modifications |
| **4** | HMAC-based simulated timestamp tokens | Timestamp manipulation, backdated entries |
| **5** | Append-only JSONL files with read-only enforcement | Direct file manipulation attempts |

---

## Project Structure

```
Task 1/
├── tamper_evident_logging/          # Core library
│   ├── __init__.py                  # Package metadata
│   ├── log_entry.py                 # LogEntry data structure + canonical hashing
│   ├── merkle_tree.py               # Merkle tree build, proof, verify
│   ├── crypto_signer.py             # Ed25519 key management + signing
│   ├── timestamp_authority.py       # Simulated RFC 3161 TSA
│   ├── storage.py                   # Append-only JSONL persistence
│   ├── log_writer.py                # Log writer (entry chaining + checkpointing)
│   └── verifier.py                  # Integrity verifier + tamper report generator
├── main.py                          # FastAPI web service entry point
├── demo.py                          # Automated demonstration script
├── cli.py                           # Interactive command-line interface
├── test_system.py                   # 18 automated tests
├── requirements.txt                 # Python dependencies
├── Procfile                         # Render deployment command
├── runtime.txt                      # Python version for deployment
├── .gitignore                       # Git ignore rules
├── README.md                        # This file
└── api_data/                        # Generated at runtime (API)
    ├── logs/entries.jsonl
    ├── checkpoints/checkpoints.jsonl
    ├── keys/
    └── reports/
```

---

## How to Run

### Prerequisites

- **Python 3.10+**
- Install dependencies: `pip install -r requirements.txt`

### 1. Run the Web API (FastAPI)

```bash
uvicorn main:app --host 0.0.0.0 --port 8000
```

Then open:
- **Landing page**: http://localhost:8000
- **Swagger UI**: http://localhost:8000/docs (interactive API testing)

### 2. Run the Automated Demo

```bash
python3 demo.py
```

This will:
1. Create 12 sample security events (logins, transactions, config changes, etc.)
2. Verify the pristine log → **PASS ✅**
3. Simulate a **modification** attack → **FAIL ❌** with forensic report
4. Simulate a **deletion** attack → **FAIL ❌** with forensic report
5. Simulate a **reorder** attack → **FAIL ❌** with forensic report
6. Save all reports to `data/reports/`

### 3. Run the Test Suite

```bash
python3 test_system.py
```

Runs 18 automated tests covering all layers.

### 4. Interactive CLI (Manual Testing)

```bash
python3 cli.py
```

Menu-driven interface for hands-on exploration.

---

## REST API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | Landing page with API overview |
| `GET` | `/health` | System health check |
| `POST` | `/logs` | Add a new log entry |
| `GET` | `/logs` | List all log entries (with pagination) |
| `GET` | `/logs/{seq}` | Get a specific log entry |
| `GET` | `/verify` | Run full 5-layer integrity verification |
| `GET` | `/checkpoints` | List all Merkle checkpoints |
| `POST` | `/simulate-tamper` | Deliberately corrupt an entry (demo) |
| `GET` | `/report` | Get the latest forensic report |
| `POST` | `/reset` | Reset all data (demo only) |

### Example: Add a log entry
```bash
curl -X POST http://localhost:8000/logs \
  -H "Content-Type: application/json" \
  -d '{"event_type":"LOGIN","description":"User alice logged in","actor":"alice"}'
```

### Example: Verify integrity
```bash
curl http://localhost:8000/verify
```

### Example: Simulate tampering
```bash
curl -X POST http://localhost:8000/simulate-tamper \
  -H "Content-Type: application/json" \
  -d '{"tamper_type":"modify","target_seq":3,"new_description":"HACKED"}'
```

---

## Deployment to Render

### Step 1: Push to GitHub
```bash
cd "Task 1"
git init
git add .
git commit -m "Tamper-evident logging system with FastAPI"
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO.git
git push -u origin main
```

### Step 2: Deploy on Render
1. Go to [render.com](https://render.com) → **New** → **Web Service**
2. Connect your GitHub repository
3. Settings:
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn main:app --host 0.0.0.0 --port $PORT`
4. Click **Create Web Service**
5. Wait for the build to complete → you'll get a public URL like `https://your-app.onrender.com`

### Step 3: Verify the deployment
- Visit `https://your-app.onrender.com/` → landing page
- Visit `https://your-app.onrender.com/docs` → Swagger UI
- Visit `https://your-app.onrender.com/health` → health check

---

## Modules

### 1. Log Entry (`log_entry.py`)

Each entry contains:

| Field | Description |
|-------|-------------|
| `seq` | Monotonic sequence number (1-based) |
| `timestamp` | ISO-8601 UTC timestamp |
| `event_type` | Category (LOGIN, TRANSACTION, etc.) |
| `description` | Human-readable event description |
| `actor` | User / service identifier |
| `prev_hash` | SHA-256 hash of the preceding entry |
| `entry_hash` | SHA-256 hash of canonical serialisation |
| `metadata` | Optional key-value pairs |

**Canonical hashing**: All fields are serialised with `json.dumps(payload, sort_keys=True, separators=(",", ":"))` before hashing, ensuring deterministic output across platforms.

### 2. Merkle Tree (`merkle_tree.py`)

- Builds a full binary tree from leaf hashes
- Domain separation: leaves hashed with `\x00` prefix
- Supports inclusion proofs for individual entries
- Handles odd-length layers via duplication padding

### 3. Crypto Signer (`crypto_signer.py`)

- Uses **Ed25519** (via the `cryptography` library)
- Generates, saves, and loads key pairs in PEM format
- Signs checkpoint Merkle roots
- Verifies signatures using only the public key

### 4. Timestamp Authority (`timestamp_authority.py`)

- Simulates **RFC 3161** Trusted Timestamping
- TSA produces `HMAC-SHA256(secret, checkpoint_hash || server_time)`
- Verification re-computes the HMAC and compares
- Clearly documented as a simulation

### 5. Storage (`storage.py`)

- **Append-only JSONL** format for log entries and checkpoints
- `lock_entries_file()` sets file to read-only mode
- `unlock_entries_file()` restores write (for tamper simulation only)
- Separate directories for entries, checkpoints, keys, and reports

### 6. Log Writer (`log_writer.py`)

- Assigns sequence numbers and timestamps automatically
- Computes entry hashes using the previous entry's hash
- Groups entries into batches (default size: 5)
- Creates signed, timestamped checkpoints for each batch

### 7. Integrity Verifier (`verifier.py`)

Runs **read-only** verification across all layers:

| Check | Description |
|-------|-------------|
| Hash chain | Recomputes each entry's hash and verifies the chain |
| Sequence numbers | Detects gaps (deletions) and disorder (reordering) |
| Merkle roots | Recomputes batch roots and compares to stored checkpoints |
| Signatures | Validates Ed25519 signatures on each checkpoint |
| Timestamps | Verifies TSA tokens and monotonic timestamp ordering |

**Tamper report generator** produces structured JSON reports with:
- Overall PASS/FAIL status
- First tamper point identification
- Type classification (MODIFIED, DELETED, REORDERED, FORGED_CHECKPOINT, etc.)
- Expected vs. actual hash values
- Human-readable explanations

---

## Tamper Detection Capabilities

| Attack | Detection Method | Layer |
|--------|-----------------|-------|
| **Modify** an entry's content | Self-hash recomputation fails | 1 |
| **Modify** an entry without updating hash | Next entry's prev_hash mismatches | 1 |
| **Delete** an entry | Sequence number gap detected | 1 |
| **Delete** from a checkpointed batch | Batch size mismatch in checkpoint | 2 |
| **Reorder** entries | Sequence number disorder + prev_hash break | 1 |
| **Reorder** timestamped entries | Timestamp monotonicity violation | 1 |
| **Forge** a checkpoint root | Ed25519 signature verification fails | 3 |
| **Modify** checkpoint hash | TSA token verification fails | 4 |
| **Backdate** timestamps | Trusted timestamp token mismatch | 4 |

---

## Sample Output

### Pristine Verification (PASS)
```
========================================================================
  Tamper-Evident Log – Integrity Verification Report
========================================================================
  Status            : PASS ✅
  Entries checked   : 12
  Checkpoints       : 3
  First tamper point: N/A
  Total anomalies   : 0
------------------------------------------------------------------------
  Summary: All integrity checks passed.
========================================================================
```

### After Modification Tamper (FAIL)
```
========================================================================
  Tamper-Evident Log – Integrity Verification Report
========================================================================
  Status            : FAIL ❌
  Entries checked   : 12
  Checkpoints       : 3
  First tamper point: 3
  Total anomalies   : 1
------------------------------------------------------------------------
  Summary: TAMPERING DETECTED. 1 anomalies found. Tamper types: MODIFIED.

  [1] Type: MODIFIED
      Entry #     : 3
      Explanation : Entry #3 stored hash does not match the recomputed
                    hash from its fields. The entry content was modified
                    after logging.
========================================================================
```

---

## Manual Testing Guide

### Step 1: Run the automated demo
```bash
python3 demo.py
```
- Observe all 4 verification reports (1 PASS, 3 FAIL)
- Check generated files in `data/` directory

### Step 2: Run the test suite
```bash
python3 test_system.py
```
- Confirm all 18 tests pass

### Step 3: Interactive manual testing
```bash
python3 cli.py
```

1. **Add entries**: Choose option `1`, enter event details
2. **View entries**: Option `2` to see the log chain
3. **Verify**: Option `4` — should show PASS ✅
4. **Tamper**: Use options `5`/`6`/`7` to modify, delete, or reorder
5. **Re-verify**: Option `4` — should now show FAIL ❌ with details
6. **Reset**: Option `8` to start fresh

### Step 4: Inspect raw data files
```bash
cat data/logs/entries.jsonl | python3 -m json.tool --no-ensure-ascii
cat data/checkpoints/checkpoints.jsonl | python3 -m json.tool
cat data/reports/01_pristine_verification.json | python3 -m json.tool
```

---

## Technologies Used

| Technology | Purpose |
|------------|---------|
| Python 3.12 | Core implementation language |
| FastAPI | REST API framework |
| Uvicorn | ASGI web server |
| Pydantic | Request/response validation |
| SHA-256 | Hash chain integrity |
| Ed25519 | Digital signature scheme |
| HMAC-SHA256 | Trusted timestamp simulation |
| JSONL | Append-only log storage format |
| `cryptography` library | Ed25519 key generation, signing, verification |
| Render | Cloud deployment platform |

---

*Built as part of the Cybersecurity & Network Security Internship Assessment — Task 1*
