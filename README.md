# SecureBank Management System v1.0.0

A high-security, full-stack desktop banking application combining an enterprise-grade **C11 banking engine** with a modern, responsive **HTML5/CSS3/JavaScript frontend**.

---

## 1. Architectural Overview

SecureBank is engineered with strict separation of concerns:
- **Banking Business Logic Solely in C:** All financial calculations, interest formulas, account balances, loan schedules, fixed deposit premature closure penalties, account lockouts, transaction ledgers, audit trails, and atomic CRC-32 persistence are executed exclusively in `bank_system.c`.
- **Zero Frontend Business Logic:** The JavaScript layer (`app.js`) acts strictly as a presentation and communication controller. It contains **zero** mock accounts, **zero** simulated balances, and **no** independent financial calculations.
- **Embedded C HTTP Server:** The C backend implements an embedded, non-blocking HTTP/1.1 REST server binding to `127.0.0.1`. It directly serves the static UI assets (`index.html`, `style.css`, `app.js`) and handles 38 REST API endpoints with JSON payloads.
- **Dual Execution Modes:**
  - **Server Mode (Default):** Runs the embedded web server and opens the browser interface.
  - **Terminal Mode (`--cli`):** Preserves the original ANSI interactive terminal console.

```
+-----------------------------------------------------------------------+
|                         Browser Interface                             |
|               (index.html + style.css + app.js)                       |
+-----------------------------------------------------------------------+
                                   |
                         HTTP REST API (JSON)
                      http://127.0.0.1:8080/api/
                                   |
+-----------------------------------------------------------------------+
|                    SecureBank C Core Engine                           |
|  - In-Memory HTTP/1.1 Engine (POSIX Sockets / WinSock2)               |
|  - JSON Parser & Serializer                                           |
|  - Authentication & Session Manager (X-Session-Token)                 |
|  - Customer & Admin Workflow Handlers                                 |
|  - Financial Calculation Engine (EMI, FD compounding, savings int)   |
|  - Transaction Ledger & Double-Entry Invariants                       |
|  - Audit Log Ring Buffer                                              |
|  - Atomic CRC-32 Binary Persistence Engine (*.dat & *.tmp)            |
+-----------------------------------------------------------------------+
                                   |
                         Atomic File System I/O
                                   v
             [ bank.dat ] <=== CRC-32 Checksum Validation
```

---

## 2. Minimal File Architecture

The repository has been streamlined into the minimum possible files:

| File | Purpose |
| :--- | :--- |
| [`Bankmanagement.c`](file:///c:/Users/kamat/Desktop/College/Bankmanagement.c) | Primary C11 source file with banking logic, crypto, persistence, and embedded HTTP server |
| [`Bankmanagement.exe`](file:///c:/Users/kamat/Desktop/College/Bankmanagement.exe) | Compiled native Windows executable (WinSock2 + C11) |
| [`index.html`](file:///c:/Users/kamat/Desktop/College/index.html) | Complete all-in-one frontend (HTML markup, embedded CSS design system, and embedded JS controller) |
| [`README.md`](file:///c:/Users/kamat/Desktop/College/README.md) | Comprehensive documentation and operational guide |

---

## 3. Compilation & Build Instructions

### Compilation Command

#### On Windows (PowerShell or Command Prompt):
```powershell
gcc -std=c11 -O2 -Wall -Wextra -o Bankmanagement.exe Bankmanagement.c -lm -lws2_32
```

#### On Linux / macOS:
```bash
gcc -std=c11 -O2 -Wall -Wextra -o Bankmanagement Bankmanagement.c -lm
```

> **Note:** The code compiles cleanly with `-Wall -Wextra` with **0 warnings and 0 errors**.

---

## 4. Launching the Application

### Running the Web Application (Default)
Run the executable to launch the embedded HTTP server:
```powershell
.\Bankmanagement.exe
```

Open **`http://127.0.0.1:8080`** in your browser.

- Default Administrator Password: `Admin@123`

#### Customizing Port and Database File:
- Specify custom port: `.\Bankmanagement.exe -p 8089`
- Specify custom database file: `.\Bankmanagement.exe -f my_bank.dat`
- Combine flags: `.\Bankmanagement.exe -f test_bank.dat -p 9000`

### Running the Legacy Terminal Menu
To access the original interactive terminal interface:
```powershell
.\Bankmanagement.exe --cli
```

---

## 5. Security Architecture

1. **Localhost Binding:** The HTTP server binds exclusively to `127.0.0.1`. It refuses external connections and is not exposed to public network interfaces.
2. **Session Authentication:**
   - On successful login, the C backend generates a 256-bit cryptographically secure random hexadecimal token.
   - All subsequent authenticated requests must include the header:
     `X-Session-Token: <token>`
   - The token expires automatically after 15 minutes of inactivity or upon explicit logout.
3. **No Credential Persistence in Frontend:**
   - Customer PINs and administrator passwords are never cached in `localStorage` or `sessionStorage`.
   - Only the ephemeral session token and public profile metadata (name, masked account number, role) are kept in `sessionStorage` for tab persistence.
4. **Defense in Depth on Business Logic:**
   - Daily withdrawal limits (₹50,000) and transfer limits (₹1,00,000) are enforced in C.
   - Minimum balance requirements (₹1,000 for Savings, ₹0 for Current) and overdraft limits (₹25,000 for Current) are checked in C.
   - Account lockout after 3 consecutive failed PIN attempts is executed in C.
   - Forced PIN change on first login or after admin reset is verified before allowing any transactional operations.
5. **Double-Entry & Reconciliation:**
   - Every transaction generates an immutable ledger entry with an incrementing `txn_id`.
   - Admin console includes an automated Ledger Reconciliation check that recalculates all customer balances from opening deposits + ledger entries, comparing them against recorded balances.
6. **Atomic Persistence with CRC-32:**
   - Saves are written to a temporary file (`.tmp`), flushed with `_commit()` / `fsync()`, and atomically renamed over the target `.dat` file.
   - File headers verify a magic constant and CRC-32 checksum to prevent corrupted state loading.

---

## 6. REST API Specification

### Authentication Endpoints
- `POST /api/auth/customer-login`
  - Body: `{"acc_num": 1000000001, "pin": "1234"}`
  - Returns: `{"ok": true, "token": "...", "must_change_pin": false, "customer": {...}}`
- `POST /api/auth/admin-login`
  - Body: `{"password": "..."}`
  - Returns: `{"ok": true, "token": "..."}`
- `POST /api/auth/logout` (Header: `X-Session-Token`)
- `POST /api/auth/change-pin` (Header: `X-Session-Token`)
  - Body: `{"old_pin": "1234", "new_pin": "5678"}`

### Customer Operations Endpoints (Header: `X-Session-Token`)
- `GET /api/customer/profile` — Full profile, balance, limits, active loans & FDs
- `POST /api/customer/deposit` — `{"amount": 5000.0}`
- `POST /api/customer/withdraw` — `{"amount": 2000.0}`
- `POST /api/customer/beneficiary-lookup` — `{"acc_num": 1000000002}`
- `POST /api/customer/transfer` — `{"to_acc": 1000000002, "amount": 1500.0, "pin": "5678", "remark": "Rent"}`
- `GET /api/customer/statement?limit=10` — Mini or full transaction statement
- `GET /api/customer/statement-csv` — Direct CSV statement download
- `POST /api/customer/fd/calc` — Calculate FD maturity and interest
- `POST /api/customer/fd/open` — Open fixed deposit
- `POST /api/customer/fd/close` — Premature or mature closure
- `POST /api/customer/loan/calc` — Calculate reducing-balance loan EMI, fee, and total interest
- `POST /api/customer/loan/apply` — Submit loan application
- `POST /api/customer/loan/pay-emi` — Pay monthly EMI from account balance
- `POST /api/customer/loan/foreclose` — Pay off entire remaining principal

### Administrator Endpoints (Header: `X-Session-Token`)
- `GET /api/admin/summary` — Overview of bank liquidity, deposits, loans, and reconciliations
- `POST /api/admin/open-account` — Open new Savings/Current account with initial deposit
- `GET /api/admin/accounts` — Searchable, filterable list of all accounts
- `GET /api/admin/account?acc_num=...` — Detailed account inspection with ledger history
- `POST /api/admin/freeze-account` / `POST /api/admin/unfreeze-account`
- `POST /api/admin/close-account`
- `POST /api/admin/reset-pin` — Resets customer PIN to temporary value & unlocks account
- `POST /api/admin/approve-loan` / `POST /api/admin/reject-loan`
- `POST /api/admin/post-interest` — Post monthly savings interest to all eligible accounts
- `POST /api/admin/advance-clock` — Simulated bank clock management (days advance)
- `GET /api/admin/audit-logs` — Bank security audit log viewer
- `POST /api/admin/change-password` — Change master admin password

---

## 7. Verification & Testing Workflow

To run a complete end-to-end test of the banking system:

1. **Launch Server:**
   ```powershell
   .\bank_system.exe -f test_bank.dat -p 8089
   ```
2. **Log In as Admin:**
   - Password: `Admin@123`
   - Observe Bank Summary metrics (₹0 deposits, 0 accounts initially).
3. **Open Customer Accounts:**
   - Click **Open New Account**.
   - Create **Alice Smith** (Savings, ₹5,000 initial deposit). Note the auto-generated Account Number (e.g., `1000000001`) and temporary PIN (e.g., `1234`).
   - Create **Bob Jones** (Current, ₹10,000 initial deposit). Note Account Number (e.g., `1000000002`).
4. **Log In as Customer (Alice):**
   - Enter Account `1000000001` and temporary PIN.
   - The UI immediately prompts the **Mandatory PIN Change** dialog.
   - Update PIN to `9999`.
5. **Execute Core Banking Transactions:**
   - **Deposit:** Add ₹2,500 cash. Observe updated balance ₹7,500 and receipt dialog.
   - **Withdraw:** Withdraw ₹1,000 cash. Observe remaining daily limit update.
   - **Transfer:** Transfer ₹1,500 to Bob's account (`1000000002`).
     - Review beneficiary name confirmation ("Bob Jones").
     - Re-enter PIN `9999` and submit.
     - Verify resulting balance ₹5,000.
6. **Fixed Deposit Workflow:**
   - Open FD section. Enter ₹3,000 for 12 months @ 6.50% p.a.
   - Inspect maturity calculation. Click **Open Fixed Deposit**.
   - Balance decreases to ₹2,000, and FD is recorded in Active Deposits table.
7. **Loan Workflow:**
   - Open Loan Center. Apply for Personal Loan of ₹10,000 for 12 months.
   - Review EMI calculation. Submit application.
   - Switch to Admin Console -> **Loan Review Queue**.
   - Click **Approve Loan**. Disbursed amount reflects in Alice's account balance.
8. **Audit Trail & Ledger Reconciliation:**
   - In Admin Console, run **Audit Trail** and observe logged events.
   - Check **Bank Summary** -> **Reconcile**: Confirms all accounts match double-entry ledger.
9. **Persistence Check:**
   - Stop the server (`Ctrl+C`) and restart it using the same file (`-f test_bank.dat`).
   - Log back in as Alice with PIN `9999`. All balances, loans, and transaction history are preserved intact!
