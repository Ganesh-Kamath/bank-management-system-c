# 📋 SecureBank — Quick Instructions & Demo Checklist

This guide gives you everything you need to **run, demonstrate, and test** the Bank Management System in under 2 minutes.

---

## ⚡ Quick Start (1-Click)

### On Windows:
1. Double-click **[`run.bat`](file:///c:/Users/kamat/Desktop/College/run.bat)**.
2. It compiles `Bankmanagement.c` (if needed) and launches your web browser to:
   👉 **`http://127.0.0.1:8080`**

---

## 💻 Manual Terminal Start

If you prefer using the terminal or PowerShell:

### 1. Compile with GCC:
```powershell
gcc -std=c11 -O2 -Wall -Wextra -o Bankmanagement.exe Bankmanagement.c -lm -lws2_32
```
*(On Linux/macOS omit `-lws2_32`: `gcc -std=c11 -O2 -Wall -Wextra -o Bankmanagement Bankmanagement.c -lm`).*

### 2. Run the Server:
```powershell
.\Bankmanagement.exe
```

### 3. Open in Browser:
Open Chrome, Edge, Firefox, or Safari and navigate to:
👉 **`http://127.0.0.1:8080`**

---

## 🔑 Default Login Credentials

### 1. Customer Accounts (Pre-Loaded for Testing)
| Account Number | PIN | Customer Name | Account Type | Balance |
| :--- | :--- | :--- | :--- | :--- |
| **`1000000001`** | **`1234`** | Rahul Sharma | Savings | ₹15,000.00 |
| **`1000000002`** | **`1234`** | Priya Patel | Current | ₹25,000.00 |

### 2. Administrator Console
- **Admin Password**: **`Admin@123`**

---

## 📱 Mobile Access & Public Sharing

### Option A: Open on Your Phone (Same Wi-Fi)
1. Find your computer's IP address:
   - On Windows: run `ipconfig` (look for IPv4 Address, e.g. `192.168.1.9`).
2. On your smartphone's browser, open:
   👉 **`http://192.168.1.9:8080`**

### Option B: Share Anywhere in the World (Public Link)
1. Double-click **[`start_tunnel.bat`](file:///c:/Users/kamat/Desktop/College/start_tunnel.bat)** or run in a terminal:
   ```powershell
   npx localtunnel --port 8080 --subdomain wicked-candies-knock
   ```
2. Open the public URL on any phone or computer:
   👉 **`https://wicked-candies-knock.loca.lt`**
3. If prompted for a tunnel password, enter: **`223.181.61.24`**.

---

## 🎯 Step-by-Step Project Demo Walkthrough (For Teachers / Examiners)

Follow this 5-step checklist to give an impressive 3-minute live demonstration:

### Step 1: Customer Login & Dashboard
1. Log in with Account **`1000000001`** and PIN **`1234`**.
2. Show the live available balance (**₹15,000.00**), account type, and passbook transaction history.

### Step 2: Deposit & Withdrawal
1. Click **"Deposit"**, enter `2000`, and submit.
   - *Notice: Balance instantly updates to ₹17,000.00, and a new transaction row is added.*
2. Click **"Withdraw"**, enter `1000`, input PIN `1234`, and submit.
   - *Notice: Balance updates to ₹16,000.00.*

### Step 3: Fund Transfer Between Accounts
1. Click **"Transfer"**.
2. Enter Target Account: **`1000000002`**, Amount: `3000`, PIN: `1234`.
3. Submit the transfer.
4. Log out, then log in as Customer 2 (**`1000000002`** / `1234`).
   - *Notice: Priya's balance has increased by ₹3,000 (from ₹25,000 to ₹28,000), with a "Transfer In from #1000000001" entry!*

### Step 4: Fixed Deposit & Loan
1. While logged in as Customer 2, click **"Fixed Deposits"**.
2. Book an FD for `5000` for 12 months at 6.50% p.a.
   - *Notice: Compounded maturity amount is calculated automatically.*
3. Click **"Loans"**, apply for a `50000` loan for 12 months.
   - *Notice: Monthly EMI is calculated and application is sent to the Admin queue.*

### Step 5: Administrator Console
1. Log out and log in to the **Admin Portal** using password **`Admin@123`**.
2. Show the bank-wide liquidity stats: Total customer deposits, loans, active accounts.
3. Switch to the **"Pending Loans"** tab:
   - Click **"Approve"** on the loan application.
4. Switch to **"Bank Controls"**:
   - Click **"Post Monthly Interest"** (credits 4% p.a. interest to all savings accounts).
5. Switch to **"Audit Trail"**:
   - Show the security logs recording every action with exact timestamps.

---

## 📁 File Structure Summary

```
College/
├── Bankmanagement.c     # ~670 lines of clean C backend code
├── Bankmanagement.exe   # Compiled native Windows executable
├── index.html           # Modern, responsive single-file web interface
├── run.bat              # 1-click launcher for Windows
├── start_tunnel.bat     # 1-click public tunnel for mobile sharing
├── README.md            # Comprehensive technical manual & viva guide
├── instructions.md      # This quick-start guide
└── Dockerfile           # Optional cloud deployment configuration
```
