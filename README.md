# 🏦 College Bank Management System (Pure C Engine & Modern Web UI)

> **College Project & Comprehensive Viva Guide**: A clean, beginner-friendly, and complete banking system written in **standard C** with an embedded **HTTP socket server** that serves a responsive, modern web interface.

---

## 📑 Table of Contents
1. [Project Overview (The 30-Second Elevator Pitch)](#1-project-overview-the-30-second-elevator-pitch)
2. [Project Architecture & File Layout](#2-project-architecture--file-layout)
3. [Deep Dive into the C Backend (`Bankmanagement.c`)](#3-deep-dive-into-the-c-backend-bankmanagementc)
   - [3.1 Header Files & Cross-Platform Sockets](#31-header-files--cross-platform-sockets)
   - [3.2 Data Structures (`struct`) Explained Simply](#32-data-structures-struct-explained-simply)
   - [3.3 Global In-Memory Arrays (Database in RAM)](#33-global-in-memory-arrays-database-in-ram)
   - [3.4 Binary File Persistence (`fopen`, `fwrite`, `fread`)](#34-binary-file-persistence-fopen-fwrite-fread)
   - [3.5 Core Banking Logic & Mathematical Formulas](#35-core-banking-logic--mathematical-formulas)
   - [3.6 Security: PIN Verification & 3-Strike Account Lockout](#36-security-pin-verification--3-strike-account-lockout)
   - [3.7 Embedded HTTP/1.1 Socket Web Server in C](#37-embedded-http11-socket-web-server-in-c)
   - [3.8 Simple JSON Parameter Extraction](#38-simple-json-parameter-extraction)
4. [Deep Dive into the Web Frontend (`index.html`)](#4-deep-dive-into-the-web-frontend-indexhtml)
   - [4.1 All-in-One Architecture](#41-all-in-one-architecture)
   - [4.2 Semantic HTML Layout](#42-semantic-html-layout)
   - [4.3 Responsive Vanilla CSS & Mobile Optimization](#43-responsive-vanilla-css--mobile-optimization)
   - [4.4 JavaScript Client Controller](#44-javascript-client-controller)
5. [Step-by-Step Life of a Transaction (e.g. Deposit ₹500)](#5-step-by-step-life-of-a-transaction-eg-deposit-500)
6. [How to Build and Run](#6-how-to-build-and-run)
7. [Mobile & Remote Access via Public Tunnel](#7-mobile--remote-access-via-public-tunnel)
8. [College Viva & Oral Exam Cheat-Sheet (Top 10 Q&A)](#8-college-viva--oral-exam-cheat-sheet-top-10-qa)

---

## 1. Project Overview (The 30-Second Elevator Pitch)

Most college banking projects run only as command-line terminal menus (`printf` and `scanf`). While functional, they lack the feel of real-world banking portals.

This project bridges **core systems programming in C** with a **modern web experience**:
1. **100% C Backend**: The entire banking engine—including account management, deposits, withdrawals, fund transfers, fixed deposits, loan EMI calculations, admin controls, and network sockets—is written in **clean, readable C99/C11** (~670 lines).
2. **Embedded Socket Server**: Instead of relying on heavy third-party servers like Apache, Node.js, or Python, the C code creates native TCP sockets using WinSock2 / POSIX to communicate directly with web browsers over HTTP/1.1 REST.
3. **Responsive Web Frontend**: A single, clean file ([index.html](file:///c:/Users/kamat/Desktop/College/index.html)) providing a customer portal, transaction receipts, passbook ledger, and administrator dashboard that works on both laptops and mobile phones.
4. **Student-Authentic Code**: Written using standard college programming concepts (arrays of structures, standard `fopen`/`fwrite`/`fread`, straightforward string matching). It looks authentic, understandable, and easy to defend in vivas.

---

## 2. Project Architecture & File Layout

```
+-----------------------------------------------------------------------------------+
|                           USER'S WEB BROWSER / PHONE                              |
|                           (Presentation Only: HTML/CSS/JS)                        |
|                                                                                   |
|  - Renders forms, buttons, cards, modals, and transaction history.                |
|  - NEVER simulates balances, NEVER stores fake data in localStorage.              |
+-----------------------------------------------------------------------------------+
                                      ▲
                                      │ HTTP REST API (JSON over TCP Port 8080)
                                      ▼
+-----------------------------------------------------------------------------------+
|                        COLLEGE BANK ENGINE IN PURE C                              |
|                            (Bankmanagement.c)                                     |
|                                                                                   |
|  [ 1. Network Sockets Layer ]                                                     |
|     - WinSock2 / POSIX TCP socket listening on port 8080.                         |
|     - Content-Length buffered HTTP/1.1 request reader & JSON response builder.    |
|     - Serves index.html directly from disk.                                       |
|                                                                                   |
|  [ 2. Security & Verification ]                                                   |
|     - 3-strike brute-force PIN lockout defense.                                   |
|     - Minimum balance enforcement (₹1,000 for Savings).                           |
|     - Ephemeral session tokens for role-based authorization.                      |
|                                                                                   |
|  [ 3. Financial Business Logic ]                                                  |
|     - Cash deposit & withdrawal validators.                                       |
|     - Two-sided atomic fund transfer.                                             |
|     - Fixed Deposit quarterly compounding: A = P * (1 + r/4)^(4*t).               |
|     - Reducing-balance loan compound EMI formula: EMI = P * r * (1+r)^n / ...     |
|     - Monthly Savings interest poster (4.0% p.a.).                                |
|     - Time Machine virtual calendar simulator.                                    |
|                                                                                   |
|  [ 4. Data Storage Layer ]                                                        |
|     - In-memory database using arrays of structs.                                 |
|     - Disk persistence using binary fwrite() and fread().                         |
+-----------------------------------------------------------------------------------+
                                      ▲
                                      │ Binary File I/O
                                      ▼
                      [ bank_records.dat ] (Binary Database)
```

### Clean Directory Layout:
| File | Size / Lines | Purpose |
| :--- | :--- | :--- |
| [`Bankmanagement.c`](file:///c:/Users/kamat/Desktop/College/Bankmanagement.c) | **~670 lines** | The entire C backend: business logic, math, file I/O, embedded HTTP server. |
| [`Bankmanagement.exe`](file:///c:/Users/kamat/Desktop/College/Bankmanagement.exe) | Compiled Binary | Native Windows executable compiled with GCC (`-Wall -Wextra`). |
| [`index.html`](file:///c:/Users/kamat/Desktop/College/index.html) | ~1,000 lines | Clean web frontend containing HTML5 markup, responsive CSS, and JavaScript. |
| [`run.bat`](file:///c:/Users/kamat/Desktop/College/run.bat) | Batch Script | 1-click Windows launcher that compiles if needed and opens your browser. |
| [`start_tunnel.bat`](file:///c:/Users/kamat/Desktop/College/start_tunnel.bat) | Batch Script | 1-click launcher for public sharing over localtunnel (`wicked-candies-knock`). |
| [`instructions.md`](file:///c:/Users/kamat/Desktop/College/instructions.md) | Markdown | Quick-start cheat-sheet for running and presenting the project. |
| [`README.md`](file:///c:/Users/kamat/Desktop/College/README.md) | Markdown | This complete educational reference and viva preparation manual. |

---

## 3. Deep Dive into the C Backend (`Bankmanagement.c`)

### 3.1 Header Files & Cross-Platform Sockets
At the beginning of `Bankmanagement.c`:
```c
#ifdef _WIN32
    #include <winsock2.h>
    #include <windows.h>
    #define close_socket closesocket
    typedef int socklen_t;
#else
    #include <unistd.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #define close_socket close
    typedef int SOCKET;
    #define INVALID_SOCKET -1
    #define SOCKET_ERROR -1
#endif
```

#### Why do we have this?
- **Operating System Portability**: Windows manages networking via `winsock2.h` and names its closing function `closesocket()`. Linux and macOS use POSIX headers `<sys/socket.h>` and `close()`.
- **The `#ifdef _WIN32` preprocessor trick**: By checking `_WIN32`, our single C source file compiles on Windows (using MinGW/GCC) and on Linux/macOS without modifying a single line of code!

---

### 3.2 Data Structures (`struct`) Explained Simply

In C, we use `struct` to model real-world banking objects:

#### 1. `Account` Struct (Customer Information)
```c
typedef struct {
    long long account_number; // 10-digit number (e.g. 1000000001)
    char name[60];            // Full name of customer
    char phone[20];           // Mobile phone number
    char pin[16];             // 4-digit security PIN
    double balance;           // Available balance (in INR)
    int account_type;         // 0 = Savings Account, 1 = Current Account
    int is_locked;            // 1 if account is locked after 3 failed PIN attempts
    int is_frozen;            // 1 if frozen by administrator
    int is_closed;            // 1 if account is permanently closed
    int failed_attempts;      // Counter tracking consecutive wrong PIN tries
} Account;
```

#### 2. `Transaction` Struct (The Passbook / Ledger)
```c
typedef struct {
    int id;                   // 1, 2, 3...
    long long account_number; // Account that this transaction belongs to
    long long target_account; // Beneficiary or sender account (for transfers)
    char type[30];            // "Deposit", "Withdrawal", "Transfer", "Interest", "Loan Credit"
    double amount;            // Transaction amount (+ for Credit, - for Debit)
    double balance_after;     // Balance immediately after transaction
    char note[100];           // Description (e.g. "Cash Deposit", "Monthly Loan EMI Paid")
    char timestamp[30];       // Date and time string ("YYYY-MM-DD HH:MM:SS")
} Transaction;
```

#### 3. `FixedDeposit` Struct
```c
typedef struct {
    int id;                   // FD ID number
    long long account_number; // Customer account number
    double principal;         // Deposit amount locked
    int term_months;          // Duration in months (6, 12, 24, 36, 60)
    double interest_rate;     // Annual rate (e.g. 6.50%)
    double maturity_amount;   // Final amount payable on maturity
    int is_active;            // 1 = Active, 0 = Closed
    char opened_date[30];     // Date when FD was booked
} FixedDeposit;
```

#### 4. `Loan` Struct
```c
typedef struct {
    int id;                   // Loan application ID
    long long account_number; // Applicant's account number
    char applicant_name[60];  // Applicant's full name
    double principal;         // Loan amount applied for
    double remaining_amount;  // Outstanding principal balance
    int tenor_months;         // Repayment period in months (6 to 60)
    double interest_rate;     // Annual interest rate (10.50% p.a.)
    double monthly_emi;       // Calculated monthly installment amount
    int status;               // 0 = Pending Review, 1 = Approved, 2 = Rejected, 3 = Repaid
} Loan;
```

---

### 3.3 Global In-Memory Arrays (Database in RAM)

To keep the code clean, fast, and easy to explain to an examiner:
```c
static Account accounts[MAX_ACCOUNTS];         // Up to 100 accounts
static int total_accounts = 0;

static Transaction transactions[MAX_TRANSACTIONS]; // Up to 500 transactions
static int total_transactions = 0;

static FixedDeposit fds[MAX_FDS];             // Up to 100 fixed deposits
static int total_fds = 0;

static Loan loans[MAX_LOANS];                 // Up to 50 loans
static int total_loans = 0;
```
- **Why In-Memory?**: Reading and updating memory takes nanoseconds, meaning the web interface updates instantaneously.
- When any transaction takes place, the arrays are updated in memory and immediately saved to disk.

---

### 3.4 Binary File Persistence (`fopen`, `fwrite`, `fread`)

In college programming courses, file handling is taught using standard C library functions. We use binary mode (`"wb"` and `"rb"`):

#### Saving Data to Disk (`save_all_data()`)
```c
static void save_all_data() {
    FILE *fp = fopen("bank_records.dat", "wb");
    if (!fp) return;
    
    fwrite(&total_accounts, sizeof(int), 1, fp);
    fwrite(accounts, sizeof(Account), total_accounts, fp);

    fwrite(&total_transactions, sizeof(int), 1, fp);
    fwrite(transactions, sizeof(Transaction), total_transactions, fp);

    fwrite(&total_fds, sizeof(int), 1, fp);
    fwrite(fds, sizeof(FixedDeposit), total_fds, fp);

    fwrite(&total_loans, sizeof(int), 1, fp);
    fwrite(loans, sizeof(Loan), total_loans, fp);

    fwrite(&system_offset_days, sizeof(int), 1, fp);
    fclose(fp);
}
```

#### Loading Data on Startup (`load_all_data()`)
```c
static void load_all_data() {
    FILE *fp = fopen("bank_records.dat", "rb");
    if (!fp) {
        // If file doesn't exist yet, automatically generate 2 sample accounts!
        // Account #1000000001: Rahul Sharma (Rs 15,000)
        // Account #1000000002: Priya Patel (Rs 25,000)
        save_all_data();
        return;
    }
    fread(&total_accounts, sizeof(int), 1, fp);
    fread(accounts, sizeof(Account), total_accounts, fp);
    // ... reads transactions, FDs, and loans
    fclose(fp);
}
```

---

### 3.5 Core Banking Logic & Mathematical Formulas

#### 1. Cash Deposit (`deposit_money`)
- Validates that `amount > 0`.
- Ensures the account is active (not closed or frozen).
- Adds amount to `accounts[idx].balance`.
- Calls `record_transaction()` and `save_all_data()`.

#### 2. Cash Withdrawal (`withdraw_money`)
- Verifies PIN.
- Checks if the account is locked or frozen.
- **Minimum Balance Rule**: Savings accounts must keep at least ₹1,000 minimum balance:
  ```c
  double min_balance = (accounts[idx].account_type == 0) ? 1000.00 : -25000.00;
  if (accounts[idx].balance - amount < min_balance) {
      // Reject withdrawal: Insufficient balance
  }
  ```
- Current accounts have an authorized overdraft facility of up to ₹25,000.

#### 3. Two-Sided Fund Transfer (`transfer_money`)
When transferring money from Account A to Account B:
1. Validates that sender and receiver exist and are distinct.
2. Verifies sender's PIN.
3. Checks that sender has sufficient balance above the minimum limit.
4. **Atomic Operation**:
   - Debits Sender: `accounts[src].balance -= amount;`
   - Credits Receiver: `accounts[dst].balance += amount;`
   - Logs two records in the passbook: `"Transfer Out"` for sender, `"Transfer In"` for receiver.

#### 4. Fixed Deposit Quarterly Compounding (`book_fd`)
Fixed deposits earn higher interest compounded **quarterly** (4 times a year):
$$A = P \left(1 + \frac{r}{400}\right)^{4t}$$
Where:
- $P$ = Principal deposit (minimum ₹5,000)
- $r$ = Annual interest rate (5.50% to 7.50% depending on tenure)
- $t$ = Time in years ($\text{term\_months} / 12.0$)

**Premature Closure Penalty**:
If a customer breaks their FD early, the bank applies a **1.0% interest rate penalty** (`rate = rate - 1.0%`), recalculates interest for elapsed time, and returns principal + reduced interest to the balance.

#### 5. Loan Reducing-Balance EMI Formula (`apply_loan`)
The system calculates standard banking Equated Monthly Installments using the compound reducing balance formula:

$$\text{EMI} = P \times r \times \frac{(1 + r)^n}{(1 + r)^n - 1}$$

Where:
- $P$ = Loan principal (₹10,000 to ₹50,00,000)
- $r$ = Monthly interest rate ($\frac{10.5\%}{12 \times 100} = 0.00875$)
- $n$ = Loan duration in months (6 to 60)

**The Loan Workflow**:
1. Customer submits amount and duration from their dashboard.
2. The loan enters `status = 0` (Pending Admin Review).
3. Admin views the application and clicks **Approve** or **Reject**.
4. Upon approval, the C engine credits the loan principal directly into the customer's balance.
5. Each month, customer clicks "Pay EMI" to reduce outstanding balance.

#### 6. Monthly Savings Interest (`admin_post_interest`)
Loops through all active savings accounts and credits interest:
$$\text{Interest} = \frac{\text{Balance} \times 0.04}{12}$$

---

### 3.6 Security: PIN Verification & 3-Strike Account Lockout

- Customer accounts are protected by a 4-digit PIN.
- Every wrong PIN increments `accounts[idx].failed_attempts`.
- If a customer enters the wrong PIN **3 times consecutively**:
  ```c
  if (accounts[idx].failed_attempts >= 3) {
      accounts[idx].is_locked = 1;
      save_all_data();
      // "Account has been LOCKED after 3 failed tries."
  }
  ```
- Once locked, all logins, withdrawals, and transfers are blocked until an Administrator clicks **"Reset PIN"** in the Admin Console.

---

### 3.7 Embedded HTTP/1.1 Socket Web Server in C

Instead of installing external web servers, `Bankmanagement.c` embeds its own socket listener:

1. **`socket(AF_INET, SOCK_STREAM, 0)`**: Creates a TCP network socket.
2. **`bind(...)`**: Binds the socket to port **8080** (or port specified via `PORT` env / CLI).
3. **`listen(server_sock, 10)`**: Sets socket to listening mode.
4. **`accept(...)`**: Accepts incoming connections from browsers or smartphones.
5. **Robust Multi-Packet Reader**:
   ```c
   /* Read complete HTTP request including body */
   char buffer[32768];
   int total_read = 0;
   int expected_len = -1;

   while (total_read < (int)sizeof(buffer) - 1) {
       int n_read = recv(client, buffer + total_read, (int)sizeof(buffer) - 1 - total_read, 0);
       if (n_read <= 0) break;
       total_read += n_read;
       buffer[total_read] = '\0';

       char *hdr_end = strstr(buffer, "\r\n\r\n");
       if (hdr_end) {
           if (expected_len < 0) {
               char *cl = strstr(buffer, "Content-Length:");
               if (!cl) cl = strstr(buffer, "content-length:");
               expected_len = cl ? atoi(cl + 15) : 0;
           }
           int body_len = total_read - (int)(hdr_end + 4 - buffer);
           if (body_len >= expected_len) break;
       }
   }
   ```
   *(This ensures that whenever a browser or mobile device sends headers and body across separate TCP packets, the C server reads the complete message without hanging or truncating!).*
6. **`send_json_response(...)`**: Sends standard HTTP headers with CORS permissions and JSON content:
   ```http
   HTTP/1.1 200 OK
   Content-Type: application/json; charset=utf-8
   Content-Length: ...
   Access-Control-Allow-Origin: *
   Connection: close
   ```

---

### 3.8 Simple JSON Parameter Extraction

Instead of a bulky 2,000-line external JSON library, our code uses clean, understandable string parsing that any student can explain in a viva:

```c
static int get_json_string(const char *json, const char *key, char *output, size_t max_len) {
    char search[80];
    snprintf(search, sizeof(search), "\"%s\"", key);
    char *pos = strstr(json, search);
    if (!pos) return 0;

    pos = strchr(pos + strlen(search), ':');
    if (!pos) return 0;
    pos++;

    while (*pos == ' ' || *pos == '\t') pos++;

    if (*pos == '\"') {
        // Quoted string value
        pos++;
        size_t idx = 0;
        while (*pos && *pos != '\"' && idx < max_len - 1) output[idx++] = *pos++;
        output[idx] = '\0';
        return 1;
    } else {
        // Numeric or boolean value
        size_t idx = 0;
        while (*pos && *pos != ',' && *pos != '}' && *pos != ' ' && idx < max_len - 1) output[idx++] = *pos++;
        output[idx] = '\0';
        return 1;
    }
}
```
If your teacher asks: *"How does your C program read JSON from the browser?"*
You can answer:
> *"Sir, I find the parameter key using `strstr()`, skip to the colon, and read the characters between quotes or commas. Then I convert numbers using `atof()` or `atoll()`."*

---

## 4. Deep Dive into the Web Frontend (`index.html`)

### 4.1 All-in-One Architecture
`index.html` bundles HTML, CSS, and JavaScript in one single file:
- Zero `npm install`, zero `node_modules`.
- Loads in under 5 milliseconds.
- Completely portable: works on any device simply by opening the URL.

### 4.2 Semantic HTML Layout
- `<div id="view-auth">`: Side-by-side cards for Customer Login and Administrator Login.
- `<div id="view-customer">`: Customer dashboard with balance badge, quick action buttons (Deposit, Withdraw, Transfer, FD, Loan, Change PIN), and a transaction passbook table.
- `<div id="view-admin">`: Bank-wide management dashboard with liquidity stats, customer directory, loan approval queue, new account creation form, and audit log.
- Accessible Modals: Dialogs for confirming transactions, booking FDs, applying for loans, and viewing receipts.

### 4.3 Responsive Vanilla CSS & Mobile Optimization
- Dark mode theme styled with slate colors (`#0f172a`, `#1e293b`), emerald success accents (`#10b981`), and danger alerts (`#ef4444`).
- **Mobile-Friendly Touch Targets**: Buttons have a 42px touch height for comfortable finger tapping.
- **Auto-Zoom Prevention**: Input font sizes are locked at `16px` to stop iPhone Safari from annoying auto-zooming.
- **Horizontal Touch Scrolling**: Tables are wrapped in `.table-container` with `-webkit-overflow-scrolling: touch`, allowing smooth left-right swiping on small screens.

### 4.4 JavaScript Client Controller
- Uses the browser's native `fetch()` API.
- Relative URL resolution:
  ```javascript
  const API_BASE = window.location.protocol === 'file:' ? 'http://127.0.0.1:8080' : '';
  ```
  *(Automatically works whether you access via localhost, local Wi-Fi, or public tunnel).*
- Automatically attaches `X-Session-Token` for authentication.

---

## 5. Step-by-Step Life of a Transaction (e.g. Deposit ₹500)

```
1. USER CLICKS "DEPOSIT" IN BROWSER
   └── JavaScript reads input amount (500).
   └── Issues asynchronous fetch: POST /api/customer/deposit with { "amount": 500 }.

2. NETWORK PACKET SENT OVER TCP
   └── Browser transmits HTTP/1.1 request to TCP Port 8080.

3. C SOCKET ACCEPTS CONNECTION
   └── accept() receives client connection.
   └── Reads complete request buffer using Content-Length loop.

4. C ROUTER DISPATCHES REQUEST
   └── Matches path "/api/customer/deposit".
   └── Reads "amount" using get_json_double(body, "amount", 0.0) -> 500.00.
   └── Reads session token header to identify customer account.

5. C FINANCIAL LOGIC EXECUTES
   └── Validates amount > 0 and account is active.
   └── updates balance: accounts[idx].balance += 500.00.
   └── Appends transaction record to transactions[] array.

6. DATA SAVED TO DISK
   └── Calls save_all_data().
   └── Writes updated accounts and transactions to bank_records.dat using fwrite().

7. HTTP RESPONSE RETURNED
   └── Sends HTTP 200 OK with JSON: { "success": true }.
   └── Closes client socket.

8. BROWSER UPDATES DISPLAY
   └── JavaScript receives success response.
   └── Updates balance on screen to reflect new total.
   └── Adds new row to transaction table and shows success toast.
```

---

## 6. How to Build and Run

### Prerequisites
- **Windows**: MinGW GCC (installed via MSYS2, Code::Blocks, or WinLibs).
- **Linux / macOS**: GCC or Clang (`sudo apt install build-essential`).

---

### Option A: 1-Click Launch (Windows)
Simply double-click **[`run.bat`](file:///c:/Users/kamat/Desktop/College/run.bat)**!
It will compile `Bankmanagement.c` (if not already compiled) and open the bank in your default web browser automatically.

---

### Option B: From Terminal / PowerShell

**1. Compile the C Backend:**
```powershell
gcc -std=c11 -O2 -Wall -Wextra -o Bankmanagement.exe Bankmanagement.c -lm -lws2_32
```
*(On Linux/macOS omit `-lws2_32`: `gcc -std=c11 -O2 -Wall -Wextra -o Bankmanagement Bankmanagement.c -lm`).*

**2. Run the Binary:**
```powershell
.\Bankmanagement.exe
```

**3. Open in Browser:**
Navigate to **`http://127.0.0.1:8080`**.

---

## 7. Mobile & Remote Access via Public Tunnel

You can access and demonstrate your bank from your mobile phone or from any computer in the world!

### Accessing via Public Tunnel:
1. Double-click **[`start_tunnel.bat`](file:///c:/Users/kamat/Desktop/College/start_tunnel.bat)** or run in a second terminal:
   ```powershell
   npx localtunnel --port 8080 --subdomain wicked-candies-knock
   ```
2. Open the live link on your phone:
   👉 **`https://wicked-candies-knock.loca.lt`**
3. If prompted for a tunnel password, enter your public IP address: **`223.181.61.24`**.

---

## 8. College Viva & Oral Exam Cheat-Sheet (Top 10 Q&A)

Here are the questions professors and external examiners typically ask, along with clear, student-friendly answers:

### Q1: "What is this project and what problem does it solve?"
> **Answer**:
> *"Sir, this is a full-stack Bank Management System. Instead of using a traditional console-only terminal with `printf` and `scanf`, I implemented a complete banking engine in pure C with an embedded socket web server. It provides a real-world web interface for customers and bank administrators while keeping all business logic, interest calculations, loan approvals, and file persistence strictly in C."*

### Q2: "How does the web page communicate with your C code?"
> **Answer**:
> *"My C program creates a TCP stream socket using `socket(AF_INET, SOCK_STREAM, 0)` and binds to port 8080 using WinSock on Windows. When a user clicks any button in `index.html`, the browser issues an HTTP REST request (such as `POST /api/customer/deposit`). My C code reads the HTTP request from the socket, extracts the JSON parameters, updates the in-memory structs and disk file, and sends back an HTTP 200 response with JSON."*

### Q3: "How is data stored and preserved when the computer restarts?"
> **Answer**:
> *"I use binary file persistence via standard C library functions `fopen()`, `fwrite()`, and `fread()`. Whenever an account is created, or a deposit, withdrawal, or transfer occurs, the program calls `save_all_data()`, which serializes the account and transaction arrays directly into `bank_records.dat`. When the server launches, `load_all_data()` reads the binary file back into memory."*

### Q4: "How does your C program parse JSON without third-party libraries?"
> **Answer**:
> *"I wrote a simple helper function `get_json_string()`. It searches for the parameter key in the JSON string using `strstr()`, locates the colon delimiter, and extracts the value between quotation marks or commas. Then helper functions like `get_json_double()` and `get_json_long()` convert the string into numbers using `atof()` and `atoll()`."*

### Q5: "What security features have you implemented?"
> **Answer**:
> *"I implemented a 3-Strike Lockout Policy: if someone enters an incorrect PIN 3 times consecutively, the account is automatically locked (`is_locked = 1`). Future transactions are rejected until the Administrator unlocks the account and resets the PIN from the Admin Console. I also enforce minimum balance checks (₹1,000 for Savings accounts) before allowing any withdrawal."*

### Q6: "How do fund transfers work?"
> **Answer**:
> *"Fund transfer is an atomic two-sided transaction. The C code verifies that both accounts exist, checks that the sender's PIN is correct, and verifies sufficient balance. It then deducts money from the sender and adds it to the receiver. It appends two separate transaction records to the ledger: a 'Transfer Out' debit for the sender and a 'Transfer In' credit for the receiver."*

### Q7: "How is Fixed Deposit interest calculated?"
> **Answer**:
> *"Fixed deposits compound quarterly using the compound interest formula: $A = P \times (1 + r/400)^{4t}$, where $P$ is principal, $r$ is annual rate (e.g. 6.5%), and $t$ is time in years. If a customer closes their FD before maturity, the system applies a 1.0% premature penalty, recalculating interest at the lower rate before returning funds to their balance."*

### Q8: "How does the loan calculation work?"
> **Answer**:
> *"Loans use standard banking Equated Monthly Installment (EMI) reducing-balance compound interest: $\text{EMI} = P \times r \times \frac{(1+r)^n}{(1+r)^n - 1}$. When a customer applies, the loan goes into a pending queue. Only an Administrator can approve the loan. Upon approval, the principal is credited to the customer's balance, and monthly EMI payments reduce the remaining balance until repaid."*

### Q9: "Why didn't you use Node.js, Python, or a database like MySQL?"
> **Answer**:
> *"Writing the system in pure C demonstrates fundamental computer science concepts: manual data structure design, socket networking, HTTP protocol mechanics, and low-level binary file I/O. It creates a self-contained, lightning-fast application with zero external dependencies that runs on any machine with just a double-click."*

### Q10: "What are the default credentials to demonstrate the system?"
> **Answer**:
> - *"Administrator Console: Password is `Admin@123`"*
> - *"Customer 1: Account #`1000000001`, PIN `1234` (Rahul Sharma — ₹15,000 balance)"*
> - *"Customer 2: Account #`1000000002`, PIN `1234` (Priya Patel — ₹25,000 balance)"*

---
*Created as a college mini-project demonstrating C systems programming, network socket architecture, and full-stack financial engineering.*
