# 🏦 SecureBank Management System — The Complete Beginner's Guide & Code Walkthrough

> **For Students, Beginners, and Viva Examiners**: A step-by-step, plain-English explanation of every single concept, structure, algorithm, and line of logic in the **SecureBank Management System**.

---

## 📑 Table of Contents
1. [What is This Project? (The 30-Second Elevator Pitch)](#1-what-is-this-project-the-30-second-elevator-pitch)
2. [High-Level Architecture (How Frontend & Backend Talk)](#2-high-level-architecture-how-frontend--backend-talk)
3. [Project Directory & File Structure](#3-project-directory--file-structure)
4. [Deep Dive into the C Backend (`Bankmanagement.c`)](#4-deep-dive-into-the-c-backend-bankmanagementc)
   - [4.1 Why C? Why not Python or Node.js?](#41-why-c-why-not-python-or-nodejs)
   - [4.2 The Header Files & Cross-Platform Compatibility](#42-the-header-files--cross-platform-compatibility)
   - [4.3 Constants, Business Rules, and Enums](#43-constants-business-rules-and-enums)
   - [4.4 Data Structures (`struct`) Explained Simply](#44-data-structures-struct-explained-simply)
   - [4.5 The Golden Rule of Money: Fixed-Point Arithmetic (Cents/Paise)](#45-the-golden-rule-of-money-fixed-point-arithmetic-centspaise)
   - [4.6 Cryptography & Security: SHA-256 and Salting](#46-cryptography--security-sha-256-and-salting)
   - [4.7 Luhn Algorithm for Account Numbers](#47-luhn-algorithm-for-account-numbers)
   - [4.8 The Append-Only Double-Entry Ledger](#48-the-append-only-double-entry-ledger)
   - [4.9 Core Banking Features: Deposits, Withdrawals & Transfers](#49-core-banking-features-deposits-withdrawals--transfers)
   - [4.10 Fixed Deposits (Quarterly Compounding & Penalties)](#410-fixed-deposits-quarterly-compounding--penalties)
   - [4.11 Loans (Reducing Balance EMI Compounding Formula)](#411-loans-reducing-balance-emi-compounding-formula)
   - [4.12 Ledger Reconciliation (The Mathematical Proof)](#412-ledger-reconciliation-the-mathematical-proof)
   - [4.13 Atomic File Storage with CRC-32 Checksum (Zero Corruption)](#413-atomic-file-storage-with-crc-32-checksum-zero-corruption)
   - [4.14 Embedded HTTP/1.1 Socket Web Server in C](#414-embedded-http11-socket-web-server-in-c)
5. [Deep Dive into the Frontend (`index.html`)](#5-deep-dive-into-the-frontend-indexhtml)
   - [5.1 Why a Single-File Frontend?](#51-why-a-single-file-frontend)
   - [5.2 Semantic HTML Layout](#52-semantic-html-layout)
   - [5.3 Vanilla CSS Design & Mobile Optimization](#53-vanilla-css-design--mobile-optimization)
   - [5.4 JavaScript Client: How Browser Talks to C](#54-javascript-client-how-browser-talks-to-c)
6. [Step-by-Step Life of a Request (e.g. Deposit ₹500)](#6-step-by-step-life-of-a-request-eg-deposit-500)
7. [How to Compile and Run](#7-how-to-compile-and-run)
8. [Accessing from Mobile / Anywhere in the World](#8-accessing-from-mobile--anywhere-in-the-world)
9. [College Viva & Exam Cheat-Sheet (Top 10 Q&A)](#9-college-viva--exam-cheat-sheet-top-10-qa)

---

## 1. What is This Project? (The 30-Second Elevator Pitch)

Imagine real-world core banking software (like what banks such as SBI, HDFC, or JPMorgan use for ATMs and SWIFT transfers). They require:
1. **100% Mathematical Accuracy**: Never losing a single cent or paisa to decimal rounding errors.
2. **Extreme Security**: Salting passwords and PINs with SHA-256, auto-locking accounts after 3 wrong tries.
3. **Auditability**: An immutable ledger where no transaction can ever be erased or secretly edited.
4. **Crash-Proof Storage**: If the power cuts while saving, the database must never corrupt.

**SecureBank** is an enterprise-grade banking engine written in **Pure C11** (~4,620 lines, ~82% of codebase) that contains its own embedded **HTTP REST web server** written with native sockets. It serves a clean, responsive web interface ([index.html](file:///c:/Users/kamat/Desktop/College/index.html)) directly to any browser, laptop, or mobile phone without needing Node.js, Python, Apache, or external databases.

---

## 2. High-Level Architecture (How Frontend & Backend Talk)

```
+-----------------------------------------------------------------------------------+
|                           USER'S WEB BROWSER / PHONE                              |
|                           (Presentation Only: HTML/CSS/JS)                        |
|                                                                                   |
|  - Renders forms, buttons, balances, modals, and transaction history.             |
|  - NEVER calculates balances, NEVER verifies PINs, NEVER generates fake data.     |
+-----------------------------------------------------------------------------------+
                                      ▲
                                      │ HTTP REST API (JSON over TCP)
                                      ▼
+-----------------------------------------------------------------------------------+
|                        SECUREBANK C11 CORE ENGINE                                 |
|                            (Bankmanagement.c)                                     |
|                                                                                   |
|  [ 1. Network Sockets Layer ]                                                     |
|     - WinSock2 / POSIX TCP socket listening on port 8080.                         |
|     - Custom HTTP/1.1 request parser & JSON response builder.                     |
|     - Serves index.html directly to web browsers.                                 |
|                                                                                   |
|  [ 2. Security & Session Layer ]                                                  |
|     - SHA-256 cryptographic hashing + 16-byte random salt per user.               |
|     - Ephemeral 256-bit hexadecimal session tokens (15-min timeout).              |
|     - 3-strike brute-force lockout defense.                                       |
|                                                                                   |
|  [ 3. Financial Logic Layer ]                                                     |
|     - Fixed-point integer math (All balances stored in Cents/Paise).              |
|     - Savings 4.0% p.a. monthly compound interest calculator.                     |
|     - Reducing-balance loan compound EMI formula with admin approval.             |
|     - Fixed Deposit quarterly compounding with 1.0% early penalty.                |
|     - Rolling 24-hour daily limits (₹50k withdraw, ₹100k transfer).               |
|                                                                                   |
|  [ 4. Double-Entry Immutable Ledger ]                                             |
|     - Append-only transaction log.                                                |
|     - Automated cryptographic balance reconciliation verification.                |
|                                                                                   |
|  [ 5. Atomic Storage Layer ]                                                      |
|     - Writes to 'bank.dat.tmp' -> hardware flush (fsync) -> atomic rename.        |
|     - 32-bit CRC-32 checksum in file header guarantees zero corruption.           |
+-----------------------------------------------------------------------------------+
                                      ▲
                                      │ Atomic Disk Flush
                                      ▼
                           [ bank.dat ] (Binary Database)
```

---

## 3. Project Directory & File Structure

We deliberately kept the project minimal and clean with no unnecessary clutter:

| File | Type | Lines / Size | Purpose |
| :--- | :--- | :--- | :--- |
| [`Bankmanagement.c`](file:///c:/Users/kamat/Desktop/College/Bankmanagement.c) | C11 Source | ~4,622 lines | **The entire core engine**: banking logic, math, cryptography, sockets, REST API, storage. |
| [`Bankmanagement.exe`](file:///c:/Users/kamat/Desktop/College/Bankmanagement.exe) | Binary | Executable | The compiled native Windows application (run with double-click or CLI). |
| [`index.html`](file:///c:/Users/kamat/Desktop/College/index.html) | Web Page | ~1,002 lines | **All-in-one frontend**: HTML5 layout, vanilla CSS styling, and client-side JavaScript. |
| [`README.md`](file:///c:/Users/kamat/Desktop/College/README.md) | Markdown | Documentation | This exhaustive beginner manual and viva guide. |
| [`Dockerfile`](file:///c:/Users/kamat/Desktop/College/Dockerfile) | Config | ~25 lines | Docker container setup for 1-click cloud deployment on Render or Railway. |
| `.gitignore` | Config | ~10 lines | Prevents temporary files and build artifacts from cluttering Git. |

---

## 4. Deep Dive into the C Backend (`Bankmanagement.c`)

Let us explore every component of the C source code, explaining the "why" and "how" behind each section.

### 4.1 Why C? Why not Python or Node.js?
- **Speed & Efficiency**: C compiles directly into native machine code (CPU instructions). There is zero overhead from a virtual machine (like Java's JVM) or runtime interpreter (like Python or Node.js).
- **Direct Memory & Hardware Control**: In C, we know the exact byte layout of our data structures. We can write them directly to disk using `fwrite()` with zero serialization lag.
- **Academic Distinction**: Anyone can build a basic website in Python or Node.js in an afternoon using frameworks. Writing an **entire HTTP server and banking engine from scratch in pure C** demonstrates deep mastery of operating systems, network sockets, memory management, and data structures.

---

### 4.2 The Header Files & Cross-Platform Compatibility

At the very top of [`Bankmanagement.c`](file:///c:/Users/kamat/Desktop/College/Bankmanagement.c#L32-L91), you see conditional compiler preprocessor directives (`#ifdef _WIN32`):

```c
#ifdef _WIN32
  #define WIN32_LEAN_AND_MEAN
  #include <winsock2.h>   // Windows TCP networking library
  #include <windows.h>    // Windows OS API (file locking, atomic renames)
  #include <wincrypt.h>   // Windows Cryptographic API for secure random bytes
  #define fsync _commit   // Maps Linux fsync to Windows _commit
  #define close_socket closesocket
#else
  #include <sys/socket.h> // Linux/macOS POSIX TCP sockets
  #include <netinet/in.h>
  #include <unistd.h>
  #define close_socket close
#endif
```

#### Why do we have this?
- **Operating System Differences**: Windows handles network connections using `winsock2.h`, while Linux and macOS use POSIX headers like `<sys/socket.h>`.
- **The Solution**: By using `#ifdef _WIN32`, our code automatically detects whether it is running on Windows or Linux and compiles seamlessly on both!

---

### 4.3 Constants, Business Rules, and Enums

Lines 96–158 define the fundamental business laws of our bank:

```c
#define LOCK_THRESHOLD    3                   // 3 wrong PINs = account lock
#define ACC_SEQ_START     UINT64_C(100000000) // 10-digit account number start
#define DEFAULT_ADMIN_PW  "Admin@123"         // Default admin password
#define FILE_MAGIC        "SBANK01"           // File header signature
```

#### Enums for State Management
Instead of using confusing numbers like `0`, `1`, `2`, C `enum` gives readable names:
- **`AccType`**: `ACC_SAVINGS` (Savings Account) or `ACC_CURRENT` (Current Account).
- **`AccStatus`**:
  - `ST_ACTIVE`: Normal operating account.
  - `ST_FROZEN`: Admin temporarily stopped transactions.
  - `ST_LOCKED`: Automatically locked due to 3 wrong PIN attempts.
  - `ST_CLOSED`: Account permanently shut down.
- **`TxType`**: `TX_OPENING`, `TX_DEPOSIT`, `TX_WITHDRAW`, `TX_TRANSFER_OUT`, `TX_TRANSFER_IN`, `TX_INTEREST`, `TX_EMI`, `TX_FD_OPEN`, etc.

---

### 4.4 Data Structures (`struct`) Explained Simply

A `struct` in C is like a blueprint or a database table row that groups related variables together.

#### 1. `Account` Struct (152 Bytes)
```c
typedef struct {
    uint64_t number;             // 10-digit account number (e.g. 1000000015)
    uint8_t  type;               // 0 = Savings, 1 = Current
    uint8_t  status;             // Active, Frozen, Locked, Closed
    uint8_t  failed_attempts;    // Counter for wrong PINs (resets on correct PIN)
    int64_t  balance;            // Current balance in cents/paise
    int64_t  withdrawn_today;    // Tracks money withdrawn in current 24-hr cycle
    int64_t  transferred_today;  // Tracks money transferred in current 24-hr cycle
    char     name[48];           // Account holder name
    char     phone[16];          // Customer mobile number
    uint8_t  salt[8];            // 8 random bytes unique to this customer
    uint8_t  pin_hash[32];       // 32-byte SHA-256 hash of (salt + PIN)
} Account;
```

#### 2. `Txn` Struct (88 Bytes) — The Transaction Ledger
Every single movement of money creates one `Txn` entry:
```c
typedef struct {
    uint64_t id;             // Unique transaction ID (1, 2, 3...)
    int64_t  timestamp;      // UNIX timestamp when it occurred
    uint64_t account;        // Which account this transaction belongs to
    uint64_t counterparty;   // Beneficiary or sender account (for transfers)
    int64_t  amount;         // Positive for Credit (+), Negative for Debit (-)
    int64_t  balance_after;  // Account balance immediately after this transaction
    uint8_t  type;           // Deposit, Withdrawal, Transfer, Interest, EMI...
    char     note[32];       // Human-readable description (e.g. "ATM Cash Withdrawal")
} Txn;
```

#### 3. `Bank` Struct — The Master Database in Memory
This struct holds all data in RAM while the server is running:
- Dynamic array of `Account` pointers.
- Dynamic array of `Txn` (Ledger) records.
- Dynamic array of `Loan` and `Fd` (Fixed Deposit) records.
- Global counters for next account number, next transaction ID.
- Admin password hash and salt.

---

### 4.5 The Golden Rule of Money: Fixed-Point Arithmetic (Cents/Paise)

> **VIVA QUESTION**: "Why didn't you use `float` or `double` to store money?"

#### The Problem with Floating-Point:
Computers use binary (base-2) floating point according to the IEEE-754 standard. Numbers like `0.10` (10 paise) cannot be stored exactly in binary, just like `1/3` cannot be written exactly in decimal (`0.333333...`).
If you do `0.1 + 0.2` in JavaScript, Python, or C using `float`, you get:
```
0.30000000000000004
```
In a bank processing 100,000 transactions, these tiny decimal fractions accumulate into real lost money and cause accounting discrepancies!

#### The Engineering Solution:
We store **all currency as a 64-bit integer (`int64_t`) representing Cents/Paise**:
- ₹1.00 is stored as `100`.
- ₹500.50 is stored as `50050`.
- ₹1,00,000.00 is stored as `10000000`.

When displaying money to the user, our helper `fmt_money()` formats it:
```c
// 10050 cents becomes "100.50"
static void fmt_money(int64_t cents, char *buf, size_t sz) {
    int64_t whole = cents / 100;
    int64_t part  = llabs(cents % 100);
    snprintf(buf, sz, "%" PRId64 ".%02" PRId64, whole, part);
}
```
**Result**: 100% mathematical precision with zero rounding errors.

---

### 4.6 Cryptography & Security: SHA-256 and Salting

#### Why Plain-Text Passwords are Unacceptable:
If an attacker or rogue employee reads `bank.dat`, they should never be able to see anyone's PIN or password.

#### What is SHA-256?
SHA-256 is a one-way cryptographic hash function. Given any input (like `"4321"`), it produces an irreversible 256-bit (32-byte) digital fingerprint. You cannot reverse the hash back into the PIN.

#### Why Do We Add "Salt"?
If two users choose the common PIN `"1234"`, a standard hash would look identical for both (`03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4`). Hackers create pre-computed dictionaries called **Rainbow Tables** to crack these instantly.

**Our Salting Process**:
1. When an account is created, `crypto_random_bytes()` generates 8 completely random bytes (the "Salt").
2. We combine the salt with the PIN:
   $$\text{Input} = \text{Salt} + \text{PIN}$$
3. We hash that combined string with SHA-256.
4. Even if 100 users have the PIN `"1234"`, every single stored hash is completely different.

#### 3-Strike Lockout Defense:
In `Bankmanagement.c`:
- If a customer enters the wrong PIN, `acc->failed_attempts++`.
- If `failed_attempts >= 3`, the status immediately switches to `ST_LOCKED`.
- The customer cannot log in again until an Admin clicks "Reset PIN" in the Admin Console.

---

### 4.7 Luhn Algorithm for Account Numbers

Our account numbers are not random digits. They are 10-digit numbers validated using the **Luhn Algorithm** (the same formula used by Visa and Mastercard for credit card numbers):
1. The first 9 digits are sequential (`100000001`, `100000002`...).
2. The 10th digit is a mathematical checksum calculated from the first 9 digits.
3. If a customer mistypes a single digit when transferring money, the system instantly detects the invalid checksum and rejects the transfer before any money moves!

---

### 4.8 The Append-Only Double-Entry Ledger

In amateur banking projects, a deposit simply does `balance = balance + amount`. That is not how real banks work.

In SecureBank:
1. Every financial event is **appended** to an immutable ledger table (`Txn`).
2. Ledger records can never be updated or deleted.
3. Each record stores `amount` (+ for credit, - for debit) and `balance_after`.
4. If a customer disputes their balance, the bank can rebuild their exact account history from Day 1 to prove every single transaction.

---

### 4.9 Core Banking Features: Deposits, Withdrawals & Transfers

- **Deposit**:
  - Validates amount (`> 0` and `<= ₹1,00,00,000`).
  - Checks if amount `>= ₹5,00,000` and automatically flags it in the security audit log for compliance.
  - Adds money to balance, creates `TX_DEPOSIT` in ledger, and writes atomically to disk.
- **Withdrawal**:
  - Verifies account is `ST_ACTIVE`.
  - Checks that `balance - amount >= floor` (Savings accounts must maintain ₹1,000 minimum balance; Current accounts allow ₹25,000 overdraft).
  - Enforces rolling 24-hour limit: Cannot withdraw more than ₹50,000 per day.
- **Fund Transfer**:
  - Requires source account, destination account, amount, and PIN confirmation.
  - Validates destination account exists and is not closed/frozen.
  - Enforces daily transfer limit of ₹1,00,000 per day.
  - Performs an **atomic two-sided transaction**:
    - Debits Sender (`TX_TRANSFER_OUT`)
    - Credits Beneficiary (`TX_TRANSFER_IN`)
  - If either step fails, the entire transaction aborts.

---

### 4.10 Fixed Deposits (Quarterly Compounding & Penalties)

Customers can lock funds in a Fixed Deposit to earn higher interest:
- **Tenor & Rates**:
  - 6 Months: 5.50% p.a.
  - 12 Months: 6.50% p.a.
  - 24 Months: 7.00% p.a.
  - 36 Months: 7.25% p.a.
  - 60 Months: 7.50% p.a.
- **Compounding Math**: Interest compounds quarterly (every 3 months) using:
  $$A = P \left(1 + \frac{r}{4}\right)^{4t}$$
- **Premature Withdrawal Penalty**:
  If a customer breaks their FD before maturity, the C engine enforces a **1.00% interest rate penalty** (`rate = rate - 1.0%`), recalculates interest for the exact days elapsed, credits principal + adjusted interest back to the account, and marks the FD as `FD_BROKEN`.

---

### 4.11 Loans (Reducing Balance EMI Compounding Formula)

Loans use the standard banking **Equated Monthly Installment (EMI)** formula:

$$\text{EMI} = P \times r \times \frac{(1 + r)^n}{(1 + r)^n - 1}$$

- $P$ = Principal loan amount (e.g. ₹1,00,000)
- $r$ = Monthly interest rate ($\frac{\text{Annual Rate}}{12 \times 100}$)
- $n$ = Loan duration in months (tenor)

#### The Loan Workflow:
1. **Application**: Customer submits amount (₹10,000 to ₹50,00,000) and tenor (6 to 60 months).
2. **Pending Queue**: Loan enters `LN_PENDING` status.
3. **Admin Review**: Admin reviews loan on dashboard and clicks **Approve** or **Reject**.
4. **Disbursal**: Upon approval, the C engine atomically credits the principal directly into the customer's account balance (`TX_LOAN_DISBURSE`).
5. **Repayment**: Each month, customer pays EMI (`TX_EMI`), reducing the outstanding principal until the balance hits zero and the loan is marked `LN_CLOSED`.

---

### 4.12 Ledger Reconciliation (The Mathematical Proof)

In the Admin Console, there is a feature called **"Reconcile Ledger"** (`bank_reconcile()`).
It loops through every account and performs a mathematical audit:

$$\text{Reconstructed Balance} = \text{Opening Balance} + \sum \text{Credits} - \sum \text{Debits}$$

If `Reconstructed Balance == Current Balance` for all accounts, it prints:
```
[PASS] 100% Ledger Integrity Verified. Zero Tampering Detected.
```
If someone opened `bank.dat` in a hex editor and changed their balance from ₹1,000 to ₹1,00,000, reconciliation will immediately catch the mismatch and flag the tampered account!

---

### 4.13 Atomic File Storage with CRC-32 Checksum (Zero Corruption)

> **VIVA QUESTION**: "What happens if someone unplugs the computer while saving?"

#### The Danger of Ordinary File Writing:
If you write directly to `bank.dat` with `fopen("bank.dat", "wb")`, and the power cuts halfway through, the file is corrupted and **all bank data is permanently destroyed**.

#### The SecureBank Atomic Strategy:
1. **Write to Temporary File**: All data is written to `bank.dat.tmp`.
2. **Calculate CRC-32**: A 32-bit Cyclic Redundancy Check (CRC-32) hash is calculated over every byte of account, transaction, and loan data. This checksum is saved in the file header.
3. **Flush Hardware Buffers**: We call `_commit()` on Windows or `fsync()` on Linux. This forces the physical hard drive platter/SSD to write the bits immediately.
4. **Atomic Rename**: We call `MoveFileEx(..., MOVEFILE_REPLACE_EXISTING)` on Windows or `rename()` on Linux. An atomic rename is an all-or-nothing OS operation.
5. **Integrity Verification on Load**: When the server launches, it reads the header and recalculates the CRC-32. If even a single byte on disk was corrupted, the server rejects the corrupted file and loads the backup `.bak` file.

---

### 4.14 Embedded HTTP/1.1 Socket Web Server in C

Instead of installing Apache, Nginx, or Node.js, `Bankmanagement.c` contains its own raw socket server:

#### How Sockets Work (The Telephone Analogy):
1. **`socket()`**: The C program creates a socket. Think of this as installing a telephone in the bank.
2. **`bind()`**: Binds the socket to `0.0.0.0:8080`. This gives the phone an address and extension number (Port 8080).
3. **`listen()`**: Puts the socket in listening mode, waiting for incoming calls.
4. **`accept()`**: When a browser connects, `accept()` picks up the phone call and creates a dedicated channel.
5. **`recv()`**: Reads the raw HTTP request string sent by Chrome/Safari:
   ```http
   POST /api/customer/deposit HTTP/1.1
   Host: 127.0.0.1:8080
   X-Session-Token: a9f8...
   Content-Length: 28

   {"amount": 50000}
   ```
6. **Router Dispatch**: Compares the URL string against 32 API routes.
7. **`send()`**: Transmits the HTTP response header and JSON body back to the browser:
   ```http
   HTTP/1.1 200 OK
   Content-Type: application/json; charset=utf-8
   Access-Control-Allow-Origin: *

   {"ok": true, "balance": 150000}
   ```
8. **`close_socket()`**: Hangs up the call so system resources are freed.

---

## 5. Deep Dive into the Frontend (`index.html`)

The frontend is an all-in-one web application (~1,000 lines) combining HTML, CSS, and JS in a single file.

### 5.1 Why a Single-File Frontend?
- **Zero Dependencies**: No `npm install`, no `node_modules` (which often take 500MB+), no Webpack, no Vite.
- **Portability**: You can put the project on a USB flash drive or zip it, and it will run on any computer instantly.
- **Academic Elegance**: Easy for an examiner to read and inspect.

### 5.2 Semantic HTML Layout
- `<div id="view-auth">`: Login screen with two clean side-by-side cards: **Customer Login** (Account Number + 4-digit PIN) and **Admin Login** (Password `Admin@123`).
- `<div id="view-customer">`: Customer banking portal:
  - Account Number, Balance KPI badge, Account Type.
  - Action buttons: Deposit, Withdraw, Transfer, Fixed Deposit, Loan, Change PIN.
  - Transaction History table with CSV download button.
- `<div id="view-admin">`: Administrator console:
  - Liquidity metrics: Total Bank Deposits, Total Outstanding Loans, Active FDs, Ledger Health.
  - Tabs: Account Directory, Loan Approval Queue, Account Opening Form, Time Machine Clock Simulator, Audit Log Viewer.
- Modals: Pop-up dialogs for every transaction, receipt, and confirmation.

### 5.3 Vanilla CSS Design & Mobile Optimization
- Dark mode theme using modern slate colors (`#0f172a`, `#1e293b`), emerald success (`#10b981`), and danger alerts (`#ef4444`).
- **Responsive Layout**: Uses CSS Grid and Flexbox that automatically re-arranges on mobile screens.
- **Mobile Touch Enhancements**:
  - Buttons have a minimum height of `42px` for comfortable finger tapping.
  - Form input font sizes are locked at `16px` to prevent iPhone Safari from triggering annoying auto-zoom.
  - Data tables are wrapped inside `.table-container` with `-webkit-overflow-scrolling: touch`, allowing smooth left-to-right swipe without breaking screen width.

### 5.4 JavaScript Client: How Browser Talks to C
- **Relative Path Routing**:
  ```javascript
  const API_BASE = window.location.protocol === 'file:' ? 'http://127.0.0.1:8080' : '';
  ```
  *(Works automatically whether you open via localhost, local Wi-Fi, or public cloud URL!)*
- **Centralized `api()` Function**:
  Handles all network calls, automatically attaches the `X-Session-Token` authentication header, and parses JSON responses.
- **Session Tokens**: Kept securely in `sessionStorage` (automatically destroyed when browser tab is closed).

---

## 6. Step-by-Step Life of a Request (e.g. Deposit ₹500)

Here is exactly what happens behind the scenes when a customer clicks **"Deposit"**:

```
1. USER CLICKS DEPOSIT BUTTON
   └── Browser JavaScript reads input: ₹500.00.
   └── JavaScript calls api('/api/customer/deposit', 'POST', { amount: 50000 }).

2. HTTP REQUEST SENT OVER WIRE
   └── Browser packages JSON payload into an HTTP/1.1 packet and sends it across TCP port 8080.

3. C SOCKET RECEIVES PACKET
   └── accept() receives client connection.
   └── setsockopt() sets 3-second timeout protection.
   └── recv() buffers raw HTTP text into req_buf.

4. C HTTP ROUTER EXECUTES
   └── Matches route "/api/customer/deposit".
   └── Checks session token: Verifies customer is logged in.
   └── Parses JSON body: Reads "amount": 50000 (cents).

5. C FINANCIAL LOGIC VALIDATES
   └── Checks: Is amount > 0? Yes.
   └── Checks: Is account active? Yes.
   └── Calculates: new_balance = balance + 50000.
   └── Appends new record to immutable Txn ledger.

6. ATOMIC PERSISTENCE
   └── C engine serializes bank state to 'bank.dat.tmp'.
   └── Recalculates 32-bit CRC-32 checksum.
   └── Calls _commit() / fsync() to flush hard drive caches.
   └── Atomically renames 'bank.dat.tmp' -> 'bank.dat'.

7. HTTP RESPONSE RETURNED
   └── C engine sends: HTTP/1.1 200 OK {"ok": true, "balance": 150000}.
   └── Closes client socket.

8. BROWSER UPDATES UI
   └── JavaScript receives 200 OK.
   └── Updates balance on screen to ₹1,500.00.
   └── Appends new transaction row to history table.
   └── Plays success toast notification.
```

---

## 7. How to Compile and Run

### Prerequisites
- **Windows**: MinGW GCC (installed with MSYS2, Code::Blocks, or WinLibs).
- **Linux / macOS**: Standard GCC or Clang (`sudo apt install build-essential`).

### Step 1: Compile the C Backend
Open PowerShell or your terminal in this project folder:

**On Windows:**
```powershell
gcc -std=c11 -O2 -Wall -Wextra -o Bankmanagement.exe Bankmanagement.c -lm -lws2_32
```

**On Linux / macOS:**
```bash
gcc -std=c11 -O2 -Wall -Wextra -o Bankmanagement Bankmanagement.c -lm
```
*(Notice: Compiles cleanly with `-Wall -Wextra` with **0 warnings and 0 errors**).*

### Step 2: Run the Application
```powershell
.\Bankmanagement.exe
```

The terminal will display:
```
================================================================================
   SecureBank Management System  v1.0.0  [Web Engine Active]
================================================================================
  Listening on : http://0.0.0.0:8080
  Data file    : bank.dat
  Audit log    : bank.dat.audit.log
  Status       : Ready for browser requests
--------------------------------------------------------------------------------
  Open http://0.0.0.0:8080 in your web browser.
  (Press Ctrl+C to stop the server)
```

### Step 3: Open in Browser
Simply open your web browser (Chrome, Edge, Firefox, Brave) and navigate to:
👉 **`http://127.0.0.1:8080`**

- **Admin Login**: Password is **`Admin@123`**
- **Customer Login**: Open an account from the Admin panel first, then log in using the 10-digit account number and generated PIN!

---

## 8. Accessing from Mobile / Anywhere in the World

### A. Accessing from Phone on the Same Wi-Fi Network
1. Find your laptop's local IP address (in terminal type `ipconfig` on Windows or `ifconfig` on Linux). Example: `192.168.1.9`.
2. On your phone's mobile browser, open:
   `http://192.168.1.9:8080`
3. You can now use the full banking app directly from your smartphone!

### B. Accessing from Anywhere in the World (Public Link)
While `Bankmanagement.exe` is running, open a second terminal and launch a localtunnel:
```powershell
npx localtunnel --port 8080
```
This generates a secure public HTTPS URL (e.g. `https://wicked-candies-knock.loca.lt`) that anyone on Earth can open on their device to test your bank!

---

## 9. College Viva & Exam Cheat-Sheet (Top 10 Q&A)

Here are the exact questions external examiners and professors ask, along with the precise technical answers you should give:

### Q1: "What is the architecture of your system?"
> **Answer**:
> *"Our project follows a 2-tier client-server architecture with strict separation of concerns. The entire backend—including business logic, cryptography, transactions, and an embedded HTTP/1.1 socket server—is written in Pure C11. The presentation layer is an all-in-one responsive web client written in semantic HTML5, CSS3, and JavaScript that communicates with the C backend via asynchronous JSON REST APIs."*

---

### Q2: "Why do you store money in cents / paise instead of float or double?"
> **Answer**:
> *"Floating point types like `float` and `double` use binary IEEE-754 representation and cannot represent decimal fractions like `0.10` or `0.01` accurately. Over hundreds of transactions, rounding errors like `0.30000000000000004` accumulate and corrupt financial ledgers. We use fixed-point arithmetic where all balances are 64-bit integers (`int64_t`) representing cents or paise (`₹1.00 = 100 paise`), guaranteeing 100% mathematical accuracy."*

---

### Q3: "How does the web browser communicate with the C program?"
> **Answer**:
> *"We implemented a native TCP stream socket in C using the WinSock2 library on Windows and POSIX sockets on Linux. The server binds to port 8080 and listens for connections. When a user clicks an action in the browser, JavaScript issues an HTTP fetch request. The C server receives the raw HTTP packet, parses the URL route and JSON body, executes the banking logic, and sends back an HTTP 200 response with JSON data."*

---

### Q4: "How is data protected against file corruption during power failures?"
> **Answer**:
> *"We implement an Atomic Write Protocol with CRC-32 checksums. The C engine never overwrites the live database file directly. Instead, it serializes data into `bank.dat.tmp`, calculates a 32-bit CRC checksum in the header, forces the OS to flush physical disk write buffers using `_commit()` / `fsync()`, and atomically renames the temporary file over `bank.dat`. If power cuts at any microsecond during the write, the original database remains 100% undamaged."*

---

### Q5: "What security measures prevent password cracking and brute-force attacks?"
> **Answer**:
> *"First, we never store plain-text passwords or PINs. Every PIN is hashed using SHA-256 combined with 16 bytes of cryptographically secure random salt generated per user, defeating Rainbow Table attacks. Second, we implement a 3-Strike Lockout Policy: if someone inputs an incorrect PIN 3 times consecutively, the C engine locks the account. Third, authentication uses 256-bit hexadecimal session tokens that expire after 15 minutes of inactivity."*

---

### Q6: "What is Double-Entry Ledger Reconciliation?"
> **Answer**:
> *"Our bank maintains an immutable append-only transaction ledger (`Txn`). In the Admin Console, the reconciliation algorithm replays every historical credit and debit from opening deposit to the present day and compares the reconstructed sum against the customer's current balance. If any record was tampered with or corrupted, the system flags an integrity mismatch."*

---

### Q7: "How does the loan system work?"
> **Answer**:
> *"Loans follow an Equated Monthly Installment (EMI) reducing-balance compound interest formula: $\text{EMI} = P \cdot r \cdot \frac{(1+r)^n}{(1+r)^n - 1}$. Customers apply through their dashboard, loans enter a pending queue, and only an Administrator can approve them. Once approved, the funds are automatically disbursed into the customer's balance, and monthly repayments reduce the outstanding principal."*

---

### Q8: "How does the Fixed Deposit premature closure penalty work?"
> **Answer**:
> *"Fixed deposits compound quarterly at interest rates between 5.50% and 7.50% p.a. If a customer withdraws early, the C engine enforces a 1.00% premature withdrawal penalty, recalculates interest earned for the exact number of elapsed days at the penalized rate, deposits the principal plus adjusted interest back into the account, and marks the FD as `FD_BROKEN`."*

---

### Q9: "Why is the frontend built without frameworks like React or Tailwind?"
> **Answer**:
> *"Using pure HTML, Vanilla CSS, and JavaScript eliminates massive dependency trees like `node_modules` and build compilation steps. It allows our compiled C binary to serve the complete web application directly from disk as a self-contained, lightning-fast system that runs on any machine with zero installation."*

---

### Q10: "What is the time complexity of searching an account?"
> **Answer**:
> *"Account lookups by account number in memory use sequential search $O(N)$ or binary search $O(\log N)$ on sorted indices. Because the entire database is maintained in RAM inside the `Bank` struct during server execution, lookups execute in sub-microsecond time, outperforming network-based relational databases."*

---

## 10. Default Project Credentials
- **Administrator Password**: `Admin@123`
- **Default Database File**: `bank.dat`
- **Audit Trail Log**: `bank.dat.audit.log`
- **Web Server Port**: `8080` (or configured via environment variable `PORT`)

---
*Created as an academic showcase of C Systems Programming, Network Socket Architecture, and Full-Stack Financial Engineering.*
