# 🎓 Simple Bank Management System (Beginner College Version)

> **College Mini-Project in Pure C**: A clean, student-friendly banking system that any beginner can understand, modify, and explain in college vivas and presentations.

---

## 🌟 Why This Version Was Made

If a college professor or external examiner looks at complex code with thousands of lines of cryptographic bitwise math or advanced macros, they might suspect you didn't write it yourself.

This folder contains a **simple, authentic student version**:
- **Clean C Code**: ~650 lines of straightforward, readable C.
- **Classic College Concepts**: Uses standard arrays of structs (`Account accounts[100]`), standard `fopen()`/`fwrite()`/`fread()` binary file handling, and simple string checks.
- **Easy to Explain**: No complex macros or confusing bit-twiddling. Every function is named clearly like `deposit_money()`, `withdraw_money()`, and `transfer_money()`.
- **Full Web Frontend**: Still connects to the clean, mobile-friendly web UI ([index.html](file:///c:/Users/kamat/Desktop/College/simple-version/index.html)) via a simple socket server on port **8081**!

---

## 📁 Files in This Folder

| File | Description |
| :--- | :--- |
| [`bank.c`](file:///c:/Users/kamat/Desktop/College/simple-version/bank.c) | The main C source code containing all banking logic, file I/O, and the HTTP socket server. |
| [`index.html`](file:///c:/Users/kamat/Desktop/College/simple-version/index.html) | The web interface (HTML, CSS, and JavaScript bundled in one file). |
| [`run.bat`](file:///c:/Users/kamat/Desktop/College/simple-version/run.bat) | 1-click batch file for Windows that automatically compiles and opens the bank in your browser. |
| [`README.md`](file:///c:/Users/kamat/Desktop/College/simple-version/README.md) | This beginner guide and student viva cheat-sheet. |

---

## 🏗️ How the Code Works (Step-by-Step)

### 1. The Data Structures (`struct`)
Every beginner in C learns how to group variables using `struct`:

```c
// Holds customer account details
typedef struct {
    long long account_number; // e.g. 1000000001
    char name[60];            // Customer name
    char phone[20];           // Mobile number
    char pin[10];             // 4-digit PIN
    double balance;           // Current money in account
    int account_type;         // 0 for Savings, 1 for Current
    int is_locked;            // 1 if account is locked after 3 wrong tries
    int is_frozen;            // 1 if frozen by admin
    int is_closed;            // 1 if closed
    int failed_attempts;      // Counts wrong PIN tries
} Account;
```

```c
// Holds one transaction record (for the passbook/statement)
typedef struct {
    int id;                   // 1, 2, 3...
    long long account_number; // Whose account this belongs to
    long long target_account; // Transfer destination (if any)
    char type[30];            // "Deposit", "Withdrawal", "Transfer"
    double amount;            // Transaction amount
    double balance_after;     // Balance after this transaction
    char note[100];           // Description (e.g. "Cash Deposit")
    char timestamp[30];       // Date and time string
} Transaction;
```

---

### 2. File Storage (`fopen`, `fwrite`, `fread`)
In first-year and second-year C programming, binary file handling is taught using standard C library functions:

- **Saving Data (`save_all_data()`)**:
  ```c
  FILE *fp = fopen("bank_records.dat", "wb");
  fwrite(&total_accounts, sizeof(int), 1, fp);
  fwrite(accounts, sizeof(Account), total_accounts, fp);
  fclose(fp);
  ```
- **Loading Data (`load_all_data()`)**:
  ```c
  FILE *fp = fopen("bank_records.dat", "rb");
  if (!fp) {
      // First time running: create default sample accounts!
      return;
  }
  fread(&total_accounts, sizeof(int), 1, fp);
  fread(accounts, sizeof(Account), total_accounts, fp);
  fclose(fp);
  ```

---

### 3. Banking Logic Functions

1. **`deposit_money(acc_no, amount)`**:
   - Finds the account in the `accounts[]` array.
   - Checks if amount is greater than zero and account is not closed/frozen.
   - Adds amount: `accounts[idx].balance += amount`.
   - Records transaction and calls `save_all_data()`.

2. **`withdraw_money(acc_no, amount, pin)`**:
   - Verifies the PIN using `strcmp(accounts[idx].pin, pin) == 0`.
   - If PIN is wrong, increments `failed_attempts`. If it hits 3, sets `is_locked = 1`.
   - Checks that Savings accounts keep at least **₹1,000 minimum balance**.
   - Subtracts amount: `accounts[idx].balance -= amount`.
   - Records transaction and saves data.

3. **`transfer_money(from_acc, to_acc, amount, pin)`**:
   - Verifies sender PIN and checks if both accounts exist.
   - Subtracts from sender: `accounts[src].balance -= amount`.
   - Adds to receiver: `accounts[dst].balance += amount`.
   - Records two transactions (one debit for sender, one credit for receiver).

4. **`book_fd(acc_no, amount, term_months)`**:
   - Calculates compound interest using the standard quarterly formula:
     $$A = P \left(1 + \frac{r}{4}\right)^{4t}$$
   - Deducts principal from account and creates a `FixedDeposit` record.

5. **`apply_loan(acc_no, amount, tenor_months)`**:
   - Calculates monthly installment using the standard banking EMI formula:
     $$\text{EMI} = P \times r \times \frac{(1+r)^n}{(1+r)^n - 1}$$
   - Places the loan into a pending status for Admin review.

6. **Admin Functions**:
   - **Open Account**: Generates account number starting from `1000000001` and sets default temporary PIN `1234`.
   - **Freeze / Unfreeze**: Toggles `is_frozen` flag.
   - **Reset PIN**: Resets PIN to `1234` and unlocks account.
   - **Post Monthly Interest**: Loops through all active savings accounts and credits `balance * 0.04 / 12` (4.0% p.a.).

---

### 4. How the C Sockets Server Works

Instead of needing Node.js or Python, `bank.c` opens a native TCP network socket:

1. **`socket()`**: Creates a TCP socket.
2. **`bind()`**: Attaches it to port **`8081`** on your computer.
3. **`listen()`**: Waits for web browsers to connect.
4. **`accept()`**: Accepts a connection when you open the browser.
5. **`serve_index_html()`**: When the browser requests `/`, C opens `index.html`, reads it using `fread()`, and sends it to your browser with HTTP headers:
   ```http
   HTTP/1.1 200 OK
   Content-Type: text/html; charset=utf-8
   ```
6. **API Handling**: When you click "Deposit", JavaScript sends a request to `/api/customer/deposit`. The C code reads the amount, updates the balance, and responds with simple JSON:
   ```json
   {"success": true}
   ```

---

## 🚀 How to Run

### Method 1: Double-Click (Easiest)
Just double-click **`run.bat`**! It will compile the code and open the bank in your browser automatically.

### Method 2: From Terminal / PowerShell
```powershell
gcc -Wall -Wextra -o bank.exe bank.c -lm -lws2_32
.\bank.exe
```

Open your browser and go to:
👉 **`http://127.0.0.1:8081`**

---

## 🔑 Default Credentials for Testing

- **Administrator Login**: Password is **`Admin@123`**
- **Pre-created Sample Customer 1**:
  - Account Number: **`1000000001`**
  - PIN: **`1234`**
  - Name: Rahul Sharma (Savings Account, Initial Balance: ₹15,000)
- **Pre-created Sample Customer 2**:
  - Account Number: **`1000000002`**
  - PIN: **`1234`**
  - Name: Priya Patel (Current Account, Initial Balance: ₹25,000)

---

## 🗣️ How to Answer College Viva Questions

### Q1: "What did you use to build this project?"
> **Answer**:
> *"Sir, I built the entire backend in C using standard C99/C11. I used structures (`struct`) to represent accounts, transactions, fixed deposits, and loans. I used binary file handling (`fwrite` and `fread`) to persist data to disk so records are saved even when the program closes. To make it user-friendly, I implemented an embedded TCP socket server in C using WinSock that serves an HTML/CSS/JavaScript web interface on port 8081."*

### Q2: "How do you store and find accounts?"
> **Answer**:
> *"I use an array of `Account` structures: `Account accounts[100]`. Each account has an account number, name, phone, PIN, balance, and status flags. When a customer logs in or transfers money, I use a `find_account()` loop that searches the array by account number."*

### Q3: "How does the file saving work?"
> **Answer**:
> *"Whenever a deposit, withdrawal, or transfer occurs, my code calls `save_all_data()`. It opens `bank_records.dat` in binary write mode (`"wb"`), writes the account count and the `accounts` array using `fwrite()`, writes the transaction history, and closes the file with `fclose()`."*

### Q4: "How does the web page communicate with your C code?"
> **Answer**:
> *"My C program creates a stream socket using `socket(AF_INET, SOCK_STREAM, 0)` and listens on port 8081. When the user clicks a button on `index.html`, the browser sends an HTTP request (like `POST /api/customer/deposit`). My C code reads the request using `recv()`, checks the path, extracts the amount, updates the account balance in memory and file, and sends back a JSON response using `send()`."*

### Q5: "What security features did you include?"
> **Answer**:
> *"I implemented a 3-strike lockout rule: if an incorrect PIN is entered 3 times consecutively, the account is locked and cannot be used until the Administrator resets it from the Admin Console. I also check for minimum balance requirements (₹1,000 for Savings accounts) before allowing any withdrawal."*
