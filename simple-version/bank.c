/*
 * ============================================================================
 * College Mini-Project: Bank Management System
 * Developed by: College Student
 * Language: C (C99 / C11)
 *
 * A simple, beginner-friendly bank management system in pure C:
 * 1. Account Management (Savings and Current accounts)
 * 2. Cash Deposits and Withdrawals (with minimum balance checks)
 * 3. Fund Transfers between customer accounts
 * 4. Fixed Deposits with compound interest
 * 5. Loan Applications with Monthly EMI calculation
 * 6. Admin Panel with Account Approval, PIN Reset, and Monthly Interest
 * 7. File Storage using standard C fopen(), fwrite(), and fread()
 * 8. Built-in socket web server that serves index.html to any web browser
 * ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

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

// Maximum capacities for simple array storage
#define MAX_ACCOUNTS 100
#define MAX_TRANSACTIONS 500
#define MAX_FDS 100
#define MAX_LOANS 50
#define MAX_AUDIT 200
#define DATA_FILE "bank_records.dat"
#define DEFAULT_PORT 8081

// -------------------------------------------------------------
// Data Structures (Simple structs that any student can explain)
// -------------------------------------------------------------

// Customer Account
typedef struct {
    long long account_number; // e.g. 1000000001
    char name[60];
    char phone[20];
    char pin[10];             // 4-digit PIN stored simply
    double balance;           // Current account balance
    int account_type;         // 0 = Savings, 1 = Current
    int is_locked;            // 1 if account is locked after 3 wrong tries
    int is_frozen;            // 1 if frozen by admin
    int is_closed;            // 1 if account closed
    int failed_attempts;      // Counts incorrect PIN attempts
} Account;

// Transaction Record (Passbook / Ledger)
typedef struct {
    int id;
    long long account_number;
    long long target_account;
    char type[30];            // "Deposit", "Withdrawal", "Transfer", "Interest", "EMI"
    double amount;
    double balance_after;
    char note[100];
    char timestamp[30];
} Transaction;

// Fixed Deposit
typedef struct {
    int id;
    long long account_number;
    double principal;
    int term_months;
    double interest_rate;     // e.g. 6.5 for 6.5%
    double maturity_amount;
    int is_active;            // 1 = Active, 0 = Closed
    char opened_date[30];
} FixedDeposit;

// Loan Application & Schedule
typedef struct {
    int id;
    long long account_number;
    char applicant_name[60];
    double principal;
    double remaining_amount;
    int tenor_months;
    double interest_rate;     // e.g. 10.5%
    double monthly_emi;
    int status;               // 0 = Pending, 1 = Approved, 2 = Rejected, 3 = Closed
} Loan;

// Global Data Storage in RAM
static Account accounts[MAX_ACCOUNTS];
static int total_accounts = 0;

static Transaction transactions[MAX_TRANSACTIONS];
static int total_transactions = 0;

static FixedDeposit fds[MAX_FDS];
static int total_fds = 0;

static Loan loans[MAX_LOANS];
static int total_loans = 0;

static char audit_logs[MAX_AUDIT][100];
static int total_audit = 0;

static int system_offset_days = 0;
static const char *ADMIN_PASSWORD = "Admin@123";

// -------------------------------------------------------------
// Helper Functions (Time, Formatting, Simple JSON Parsing)
// -------------------------------------------------------------

// Get current date string
static void get_current_time_str(char *buffer, size_t sz) {
    time_t now = time(NULL) + (system_offset_days * 86400);
    struct tm *t = localtime(&now);
    if (t) {
        strftime(buffer, sz, "%Y-%m-%d %H:%M:%S", t);
    } else {
        snprintf(buffer, sz, "2026-10-17 12:00:00");
    }
}

// Add an entry to the audit log
static void log_audit(const char *action) {
    if (total_audit >= MAX_AUDIT) {
        // Shift old logs
        for (int i = 0; i < MAX_AUDIT - 1; i++) {
            strcpy(audit_logs[i], audit_logs[i + 1]);
        }
        total_audit = MAX_AUDIT - 1;
    }
    char time_buf[30];
    get_current_time_str(time_buf, sizeof(time_buf));
    snprintf(audit_logs[total_audit++], 100, "[%s] %s", time_buf, action);
}

// Format currency as a string (e.g. 1500.50 -> "1,500.50")
static void format_money(double amount, char *out, size_t sz) {
    snprintf(out, sz, "%.2f", amount);
}

// Simple JSON extraction: finds a string value for a key in JSON body
static int get_json_string(const char *json, const char *key, char *output, size_t max_len) {
    if (!json || !key || !output) return 0;
    char search[80];
    snprintf(search, sizeof(search), "\"%s\"", key);
    char *pos = strstr(json, search);
    if (!pos) return 0;

    pos = strchr(pos + strlen(search), ':');
    if (!pos) return 0;
    pos++;

    while (*pos == ' ' || *pos == '\t' || *pos == '\r' || *pos == '\n') pos++;

    if (*pos == '\"') {
        pos++;
        size_t idx = 0;
        while (*pos && *pos != '\"' && idx < max_len - 1) {
            output[idx++] = *pos++;
        }
        output[idx] = '\0';
        return 1;
    } else {
        // Unquoted value (number or boolean)
        size_t idx = 0;
        while (*pos && *pos != ',' && *pos != '}' && *pos != ' ' && *pos != '\r' && *pos != '\n' && idx < max_len - 1) {
            output[idx++] = *pos++;
        }
        output[idx] = '\0';
        return 1;
    }
}

static double get_json_double(const char *json, const char *key, double default_val) {
    char buf[64];
    if (get_json_string(json, key, buf, sizeof(buf))) {
        return atof(buf);
    }
    return default_val;
}

static int get_json_int(const char *json, const char *key, int default_val) {
    char buf[64];
    if (get_json_string(json, key, buf, sizeof(buf))) {
        return atoi(buf);
    }
    return default_val;
}

static long long get_json_long(const char *json, const char *key, long long default_val) {
    char buf[64];
    if (get_json_string(json, key, buf, sizeof(buf))) {
        return atoll(buf);
    }
    return default_val;
}

// -------------------------------------------------------------
// File Persistence (Simple binary read & write with stdio)
// -------------------------------------------------------------

static void save_all_data() {
    FILE *fp = fopen(DATA_FILE, "wb");
    if (!fp) {
        printf("Error: Could not open %s for saving.\n", DATA_FILE);
        return;
    }
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
    printf(">> All bank data saved to %s successfully.\n", DATA_FILE);
}

static void load_all_data() {
    FILE *fp = fopen(DATA_FILE, "rb");
    if (!fp) {
        printf(">> No existing database found. Creating initial sample accounts...\n");
        // Create 2 default accounts for easy testing by teachers / evaluators
        total_accounts = 2;

        accounts[0].account_number = 1000000001LL;
        strcpy(accounts[0].name, "Rahul Sharma");
        strcpy(accounts[0].phone, "9876543210");
        strcpy(accounts[0].pin, "1234");
        accounts[0].balance = 15000.00;
        accounts[0].account_type = 0; // Savings
        accounts[0].is_locked = 0;
        accounts[0].is_frozen = 0;
        accounts[0].is_closed = 0;
        accounts[0].failed_attempts = 0;

        accounts[1].account_number = 1000000002LL;
        strcpy(accounts[1].name, "Priya Patel");
        strcpy(accounts[1].phone, "9812345678");
        strcpy(accounts[1].pin, "1234");
        accounts[1].balance = 25000.00;
        accounts[1].account_type = 1; // Current
        accounts[1].is_locked = 0;
        accounts[1].is_frozen = 0;
        accounts[1].is_closed = 0;
        accounts[1].failed_attempts = 0;

        // Add initial opening transactions
        transactions[0].id = 1;
        transactions[0].account_number = 1000000001LL;
        transactions[0].target_account = 0;
        strcpy(transactions[0].type, "Opening Deposit");
        transactions[0].amount = 15000.00;
        transactions[0].balance_after = 15000.00;
        strcpy(transactions[0].note, "Account opened");
        get_current_time_str(transactions[0].timestamp, sizeof(transactions[0].timestamp));

        transactions[1].id = 2;
        transactions[1].account_number = 1000000002LL;
        transactions[1].target_account = 0;
        strcpy(transactions[1].type, "Opening Deposit");
        transactions[1].amount = 25000.00;
        transactions[1].balance_after = 25000.00;
        strcpy(transactions[1].note, "Account opened");
        get_current_time_str(transactions[1].timestamp, sizeof(transactions[1].timestamp));
        total_transactions = 2;

        log_audit("Bank system initialized with sample accounts.");
        save_all_data();
        return;
    }

    fread(&total_accounts, sizeof(int), 1, fp);
    fread(accounts, sizeof(Account), total_accounts, fp);

    fread(&total_transactions, sizeof(int), 1, fp);
    fread(transactions, sizeof(Transaction), total_transactions, fp);

    fread(&total_fds, sizeof(int), 1, fp);
    fread(fds, sizeof(FixedDeposit), total_fds, fp);

    fread(&total_loans, sizeof(int), 1, fp);
    fread(loans, sizeof(Loan), total_loans, fp);

    fread(&system_offset_days, sizeof(int), 1, fp);
    fclose(fp);
    printf(">> Successfully loaded %d accounts and %d transactions from %s.\n",
           total_accounts, total_transactions, DATA_FILE);
}

// -------------------------------------------------------------
// Core Banking Operations
// -------------------------------------------------------------

// Helper to find an account index by account number
static int find_account(long long acc_no) {
    for (int i = 0; i < total_accounts; i++) {
        if (accounts[i].account_number == acc_no) {
            return i;
        }
    }
    return -1; // Not found
}

// Record a new transaction in the ledger
static void record_transaction(long long acc_no, long long target_acc, const char *type,
                               double amount, double bal_after, const char *note) {
    if (total_transactions >= MAX_TRANSACTIONS) return;
    Transaction *t = &transactions[total_transactions++];
    t->id = total_transactions;
    t->account_number = acc_no;
    t->target_account = target_acc;
    strncpy(t->type, type, sizeof(t->type) - 1);
    t->amount = amount;
    t->balance_after = bal_after;
    strncpy(t->note, note, sizeof(t->note) - 1);
    get_current_time_str(t->timestamp, sizeof(t->timestamp));
}

// Deposit Money
static int deposit_money(long long acc_no, double amount, char *err_msg, size_t err_sz) {
    if (amount <= 0) {
        snprintf(err_msg, err_sz, "Deposit amount must be greater than zero.");
        return 0;
    }
    int idx = find_account(acc_no);
    if (idx < 0) {
        snprintf(err_msg, err_sz, "Account not found.");
        return 0;
    }
    if (accounts[idx].is_closed) {
        snprintf(err_msg, err_sz, "Account is closed.");
        return 0;
    }
    if (accounts[idx].is_frozen) {
        snprintf(err_msg, err_sz, "Account is frozen by administrator.");
        return 0;
    }

    accounts[idx].balance += amount;
    record_transaction(acc_no, 0, "Deposit", amount, accounts[idx].balance, "Cash Deposit");
    save_all_data();

    char audit_buf[100];
    snprintf(audit_buf, sizeof(audit_buf), "Deposited INR %.2f to Account #%lld", amount, acc_no);
    log_audit(audit_buf);
    return 1;
}

// Withdraw Money
static int withdraw_money(long long acc_no, double amount, const char *pin, char *err_msg, size_t err_sz) {
    if (amount <= 0) {
        snprintf(err_msg, err_sz, "Withdrawal amount must be greater than zero.");
        return 0;
    }
    int idx = find_account(acc_no);
    if (idx < 0) {
        snprintf(err_msg, err_sz, "Account not found.");
        return 0;
    }
    if (accounts[idx].is_locked) {
        snprintf(err_msg, err_sz, "Account is locked due to 3 failed PIN attempts. Contact Admin.");
        return 0;
    }
    if (accounts[idx].is_closed) {
        snprintf(err_msg, err_sz, "Account is closed.");
        return 0;
    }
    if (accounts[idx].is_frozen) {
        snprintf(err_msg, err_sz, "Account is frozen by administrator.");
        return 0;
    }

    // Verify PIN
    if (strcmp(accounts[idx].pin, pin) != 0) {
        accounts[idx].failed_attempts++;
        if (accounts[idx].failed_attempts >= 3) {
            accounts[idx].is_locked = 1;
            save_all_data();
            snprintf(err_msg, err_sz, "Invalid PIN. Account has been LOCKED after 3 failed tries.");
        } else {
            save_all_data();
            snprintf(err_msg, err_sz, "Invalid PIN. Attempts remaining: %d", 3 - accounts[idx].failed_attempts);
        }
        return 0;
    }
    accounts[idx].failed_attempts = 0; // Reset counter on correct PIN

    // Check minimum balance rule (Savings minimum balance is Rs 1,000)
    double min_balance = (accounts[idx].account_type == 0) ? 1000.00 : -25000.00;
    if (accounts[idx].balance - amount < min_balance) {
        snprintf(err_msg, err_sz, "Insufficient funds. Savings accounts must maintain INR 1,000 minimum balance.");
        return 0;
    }

    accounts[idx].balance -= amount;
    record_transaction(acc_no, 0, "Withdrawal", -amount, accounts[idx].balance, "ATM/Cash Withdrawal");
    save_all_data();

    char audit_buf[100];
    snprintf(audit_buf, sizeof(audit_buf), "Withdrew INR %.2f from Account #%lld", amount, acc_no);
    log_audit(audit_buf);
    return 1;
}

// Transfer Money
static int transfer_money(long long from_acc, long long to_acc, double amount, const char *pin, char *err_msg, size_t err_sz) {
    if (from_acc == to_acc) {
        snprintf(err_msg, err_sz, "Cannot transfer funds to the same account.");
        return 0;
    }
    if (amount <= 0) {
        snprintf(err_msg, err_sz, "Transfer amount must be greater than zero.");
        return 0;
    }
    int src = find_account(from_acc);
    int dst = find_account(to_acc);
    if (src < 0) {
        snprintf(err_msg, err_sz, "Sender account not found.");
        return 0;
    }
    if (dst < 0) {
        snprintf(err_msg, err_sz, "Beneficiary account #%lld does not exist.", to_acc);
        return 0;
    }
    if (accounts[src].is_locked || accounts[src].is_frozen || accounts[src].is_closed) {
        snprintf(err_msg, err_sz, "Sender account is not active.");
        return 0;
    }
    if (accounts[dst].is_closed) {
        snprintf(err_msg, err_sz, "Beneficiary account is closed.");
        return 0;
    }

    // Verify PIN
    if (strcmp(accounts[src].pin, pin) != 0) {
        accounts[src].failed_attempts++;
        if (accounts[src].failed_attempts >= 3) {
            accounts[src].is_locked = 1;
            save_all_data();
            snprintf(err_msg, err_sz, "Incorrect PIN. Account has been LOCKED.");
        } else {
            save_all_data();
            snprintf(err_msg, err_sz, "Incorrect PIN. Remaining attempts: %d", 3 - accounts[src].failed_attempts);
        }
        return 0;
    }
    accounts[src].failed_attempts = 0;

    double min_balance = (accounts[src].account_type == 0) ? 1000.00 : -25000.00;
    if (accounts[src].balance - amount < min_balance) {
        snprintf(err_msg, err_sz, "Insufficient balance for this transfer.");
        return 0;
    }

    // Atomic Transfer: Debit sender, credit receiver
    accounts[src].balance -= amount;
    accounts[dst].balance += amount;

    char note_out[100], note_in[100];
    snprintf(note_out, sizeof(note_out), "Transfer to #%lld (%s)", to_acc, accounts[dst].name);
    snprintf(note_in, sizeof(note_in), "Transfer from #%lld (%s)", from_acc, accounts[src].name);

    record_transaction(from_acc, to_acc, "Transfer Out", -amount, accounts[src].balance, note_out);
    record_transaction(to_acc, from_acc, "Transfer In", amount, accounts[dst].balance, note_in);
    save_all_data();

    char audit_buf[100];
    snprintf(audit_buf, sizeof(audit_buf), "Transferred INR %.2f from #%lld to #%lld", amount, from_acc, to_acc);
    log_audit(audit_buf);
    return 1;
}

// Book Fixed Deposit
static int book_fd(long long acc_no, double amount, int term_months, char *err_msg, size_t err_sz) {
    if (amount < 5000.00) {
        snprintf(err_msg, err_sz, "Minimum Fixed Deposit amount is INR 5,000.");
        return 0;
    }
    int idx = find_account(acc_no);
    if (idx < 0) {
        snprintf(err_msg, err_sz, "Account not found.");
        return 0;
    }
    if (accounts[idx].balance - amount < 1000.00) {
        snprintf(err_msg, err_sz, "Insufficient funds to book this Fixed Deposit.");
        return 0;
    }
    if (total_fds >= MAX_FDS) {
        snprintf(err_msg, err_sz, "System FD capacity reached.");
        return 0;
    }

    // Determine interest rate
    double rate = 5.50;
    if (term_months >= 60) rate = 7.50;
    else if (term_months >= 36) rate = 7.25;
    else if (term_months >= 24) rate = 7.00;
    else if (term_months >= 12) rate = 6.50;

    // Quarterly compound interest formula: A = P * (1 + r/4)^(4*t)
    double t = (double)term_months / 12.0;
    double maturity = amount * pow(1.0 + (rate / 400.0), 4.0 * t);

    // Deduct from account balance
    accounts[idx].balance -= amount;
    record_transaction(acc_no, 0, "FD Opened", -amount, accounts[idx].balance, "Fixed Deposit Created");

    FixedDeposit *f = &fds[total_fds++];
    f->id = total_fds;
    f->account_number = acc_no;
    f->principal = amount;
    f->term_months = term_months;
    f->interest_rate = rate;
    f->maturity_amount = maturity;
    f->is_active = 1;
    get_current_time_str(f->opened_date, sizeof(f->opened_date));

    save_all_data();
    log_audit("Fixed Deposit booked successfully.");
    return 1;
}

// Premature / Regular FD Closure
static int close_fd(int fd_id, long long acc_no, char *err_msg, size_t err_sz) {
    int found = -1;
    for (int i = 0; i < total_fds; i++) {
        if (fds[i].id == fd_id && fds[i].account_number == acc_no && fds[i].is_active) {
            found = i;
            break;
        }
    }
    if (found < 0) {
        snprintf(err_msg, err_sz, "Active Fixed Deposit not found.");
        return 0;
    }

    int acc_idx = find_account(acc_no);
    if (acc_idx < 0) {
        snprintf(err_msg, err_sz, "Account not found.");
        return 0;
    }

    // Premature closure penalty: 1% reduction in interest rate
    double penalized_rate = fds[found].interest_rate - 1.0;
    if (penalized_rate < 0) penalized_rate = 0;
    double payout = fds[found].principal * (1.0 + (penalized_rate / 100.0) * (fds[found].term_months / 12.0));

    fds[found].is_active = 0;
    accounts[acc_idx].balance += payout;
    record_transaction(acc_no, 0, "FD Payout", payout, accounts[acc_idx].balance, "FD Premature Closure");

    save_all_data();
    log_audit("Fixed Deposit closed early with penalty.");
    return 1;
}

// Apply for Loan
static int apply_loan(long long acc_no, double amount, int tenor_months, char *err_msg, size_t err_sz) {
    if (amount < 10000.00 || amount > 5000000.00) {
        snprintf(err_msg, err_sz, "Loan amount must be between INR 10,000 and INR 50,00,000.");
        return 0;
    }
    if (tenor_months < 6 || tenor_months > 60) {
        snprintf(err_msg, err_sz, "Loan tenor must be between 6 and 60 months.");
        return 0;
    }
    int idx = find_account(acc_no);
    if (idx < 0) {
        snprintf(err_msg, err_sz, "Account not found.");
        return 0;
    }
    if (total_loans >= MAX_LOANS) {
        snprintf(err_msg, err_sz, "Loan queue capacity reached.");
        return 0;
    }

    // Compound Interest EMI Formula: EMI = P * r * (1+r)^n / ((1+r)^n - 1)
    double annual_rate = 10.50; // 10.5% p.a.
    double r = (annual_rate / 12.0) / 100.0;
    double emi = amount * r * pow(1.0 + r, tenor_months) / (pow(1.0 + r, tenor_months) - 1.0);

    Loan *l = &loans[total_loans++];
    l->id = total_loans;
    l->account_number = acc_no;
    strncpy(l->applicant_name, accounts[idx].name, sizeof(l->applicant_name) - 1);
    l->principal = amount;
    l->remaining_amount = amount;
    l->tenor_months = tenor_months;
    l->interest_rate = annual_rate;
    l->monthly_emi = emi;
    l->status = 0; // Pending Admin Review

    save_all_data();
    log_audit("Customer applied for new loan.");
    return 1;
}

// Pay Monthly Loan EMI
static int pay_loan_emi(long long acc_no, char *err_msg, size_t err_sz) {
    int loan_idx = -1;
    for (int i = 0; i < total_loans; i++) {
        if (loans[i].account_number == acc_no && loans[i].status == 1) { // Active loan
            loan_idx = i;
            break;
        }
    }
    if (loan_idx < 0) {
        snprintf(err_msg, err_sz, "No active approved loan found for this account.");
        return 0;
    }
    int acc_idx = find_account(acc_no);
    if (acc_idx < 0) {
        snprintf(err_msg, err_sz, "Account not found.");
        return 0;
    }

    double emi = loans[loan_idx].monthly_emi;
    if (accounts[acc_idx].balance - emi < 1000.00) {
        snprintf(err_msg, err_sz, "Insufficient balance to pay monthly EMI of INR %.2f", emi);
        return 0;
    }

    accounts[acc_idx].balance -= emi;
    loans[loan_idx].remaining_amount -= (loans[loan_idx].principal / loans[loan_idx].tenor_months);
    if (loans[loan_idx].remaining_amount <= 0) {
        loans[loan_idx].remaining_amount = 0;
        loans[loan_idx].status = 3; // Fully Repaid
    }

    record_transaction(acc_no, 0, "Loan EMI", -emi, accounts[acc_idx].balance, "Monthly Loan EMI Paid");
    save_all_data();
    log_audit("Loan EMI payment processed.");
    return 1;
}

// Admin: Open New Account
static long long admin_open_account(const char *name, const char *phone, int type, double initial_dep, char *temp_pin_out) {
    if (total_accounts >= MAX_ACCOUNTS) return 0;
    long long new_acc = 1000000001LL + total_accounts;

    Account *a = &accounts[total_accounts++];
    a->account_number = new_acc;
    strncpy(a->name, name, sizeof(a->name) - 1);
    strncpy(a->phone, phone, sizeof(a->phone) - 1);
    strcpy(a->pin, "1234"); // Default initial PIN
    strcpy(temp_pin_out, "1234");
    a->balance = initial_dep;
    a->account_type = type;
    a->is_locked = 0;
    a->is_frozen = 0;
    a->is_closed = 0;
    a->failed_attempts = 0;

    record_transaction(new_acc, 0, "Opening Deposit", initial_dep, initial_dep, "Account Created");
    save_all_data();

    char buf[100];
    snprintf(buf, sizeof(buf), "Admin created Account #%lld for %s", new_acc, name);
    log_audit(buf);
    return new_acc;
}

// -------------------------------------------------------------
// Embedded HTTP Socket Web Server (Clean & Beginner Friendly)
// -------------------------------------------------------------

// Send HTTP JSON Response
static void send_json_response(SOCKET client, int status_code, const char *json_body) {
    char header[512];
    int body_len = (int)strlen(json_body);
    snprintf(header, sizeof(header),
             "HTTP/1.1 %d OK\r\n"
             "Content-Type: application/json; charset=utf-8\r\n"
             "Content-Length: %d\r\n"
             "Access-Control-Allow-Origin: *\r\n"
             "Access-Control-Allow-Headers: Content-Type, X-Session-Token, Bypass-Tunnel-Reminder\r\n"
             "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
             "Connection: close\r\n\r\n",
             status_code, body_len);
    send(client, header, (int)strlen(header), 0);
    send(client, json_body, body_len, 0);
}

// Serve index.html static webpage
static void serve_index_html(SOCKET client) {
    FILE *fp = fopen("index.html", "rb");
    if (!fp) {
        // Fallback message if index.html is missing
        const char *err = "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n\r\nError: index.html not found in current directory.";
        send(client, err, (int)strlen(err), 0);
        return;
    }

    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char *buf = (char *)malloc(file_size);
    if (!buf) {
        fclose(fp);
        return;
    }
    fread(buf, 1, file_size, fp);
    fclose(fp);

    char header[256];
    snprintf(header, sizeof(header),
             "HTTP/1.1 200 OK\r\n"
             "Content-Type: text/html; charset=utf-8\r\n"
             "Content-Length: %ld\r\n"
             "Connection: close\r\n\r\n",
             file_size);
    send(client, header, (int)strlen(header), 0);
    send(client, buf, file_size, 0);
    free(buf);
}

// Process incoming browser requests and map them to C functions
static void handle_client_request(SOCKET client, const char *raw_request) {
    char method[16] = {0};
    char path[128] = {0};
    sscanf(raw_request, "%15s %127s", method, path);

    // Handle CORS preflight options
    if (strcmp(method, "OPTIONS") == 0) {
        const char *cors = "HTTP/1.1 204 No Content\r\n"
                           "Access-Control-Allow-Origin: *\r\n"
                           "Access-Control-Allow-Headers: Content-Type, X-Session-Token, Bypass-Tunnel-Reminder\r\n"
                           "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
                           "Connection: close\r\n\r\n";
        send(client, cors, (int)strlen(cors), 0);
        return;
    }

    // Serve Frontend
    if (strcmp(path, "/") == 0 || strcmp(path, "/index.html") == 0) {
        serve_index_html(client);
        return;
    }

    // Locate JSON Body
    const char *body = strstr(raw_request, "\r\n\r\n");
    if (body) body += 4;
    else body = "";

    // Extract Session Token from headers if present
    long long session_acc = 0;
    int is_admin_session = 0;
    char *token_hdr = strstr(raw_request, "X-Session-Token:");
    if (!token_hdr) token_hdr = strstr(raw_request, "x-session-token:");
    if (token_hdr) {
        token_hdr += 16;
        while (*token_hdr == ' ') token_hdr++;
        if (strncmp(token_hdr, "admin_session", 13) == 0) {
            is_admin_session = 1;
        } else if (strncmp(token_hdr, "cust_", 5) == 0) {
            session_acc = atoll(token_hdr + 5);
        }
    }

    char resp[8192];
    resp[0] = '\0';

    // ---------------- AUTHENTICATION ENDPOINTS ----------------
    if (strcmp(path, "/api/auth/customer-login") == 0) {
        long long acc_no = get_json_long(body, "account_number", 0);
        char pin[16];
        get_json_string(body, "pin", pin, sizeof(pin));

        int idx = find_account(acc_no);
        if (idx < 0) {
            send_json_response(client, 401, "{\"success\":false,\"error\":\"Account number not found.\"}");
            return;
        }
        if (accounts[idx].is_locked) {
            send_json_response(client, 401, "{\"success\":false,\"error\":\"Account is locked due to 3 wrong PIN attempts. Contact Admin.\"}");
            return;
        }
        if (strcmp(accounts[idx].pin, pin) != 0) {
            accounts[idx].failed_attempts++;
            if (accounts[idx].failed_attempts >= 3) {
                accounts[idx].is_locked = 1;
            }
            save_all_data();
            send_json_response(client, 401, "{\"success\":false,\"error\":\"Invalid PIN. Attempts remaining: 3\"}");
            return;
        }
        accounts[idx].failed_attempts = 0;

        char token[64];
        snprintf(token, sizeof(token), "cust_%lld", acc_no);
        snprintf(resp, sizeof(resp),
                 "{\"success\":true,\"token\":\"%s\",\"account_number\":%lld,\"must_change_pin\":false}",
                 token, acc_no);
        send_json_response(client, 200, resp);
        return;
    }

    if (strcmp(path, "/api/auth/admin-login") == 0) {
        char pw[64];
        get_json_string(body, "password", pw, sizeof(pw));
        if (strcmp(pw, ADMIN_PASSWORD) == 0) {
            send_json_response(client, 200, "{\"success\":true,\"token\":\"admin_session\"}");
        } else {
            send_json_response(client, 401, "{\"success\":false,\"error\":\"Incorrect admin password. Default is Admin@123\"}");
        }
        return;
    }

    if (strcmp(path, "/api/auth/session") == 0) {
        if (is_admin_session) {
            send_json_response(client, 200, "{\"authenticated\":true,\"role\":\"admin\"}");
        } else if (session_acc > 0) {
            snprintf(resp, sizeof(resp), "{\"authenticated\":true,\"role\":\"customer\",\"account_number\":%lld}", session_acc);
            send_json_response(client, 200, resp);
        } else {
            send_json_response(client, 200, "{\"authenticated\":false}");
        }
        return;
    }

    if (strcmp(path, "/api/auth/logout") == 0) {
        send_json_response(client, 200, "{\"success\":true}");
        return;
    }

    // ---------------- CUSTOMER OPERATIONS ----------------
    if (strcmp(path, "/api/customer/dashboard") == 0) {
        if (session_acc <= 0) {
            send_json_response(client, 401, "{\"error\":\"Please log in.\"}");
            return;
        }
        int idx = find_account(session_acc);
        if (idx < 0) {
            send_json_response(client, 404, "{\"error\":\"Account not found.\"}");
            return;
        }

        char bal_str[32];
        format_money(accounts[idx].balance, bal_str, sizeof(bal_str));

        // Build recent transactions JSON
        char tx_list[4096] = "[";
        int count = 0;
        for (int i = total_transactions - 1; i >= 0 && count < 10; i--) {
            if (transactions[i].account_number == session_acc) {
                if (count > 0) strcat(tx_list, ",");
                char item[512];
                snprintf(item, sizeof(item),
                         "{\"id\":%d,\"datetime\":\"%s\",\"type\":\"%s\",\"counterparty\":\"%lld\",\"amount\":\"%.2f\",\"amount_cents\":%ld,\"balance_after\":\"%.2f\",\"note\":\"%s\"}",
                         transactions[i].id, transactions[i].timestamp, transactions[i].type,
                         transactions[i].target_account, transactions[i].amount,
                         (long)(transactions[i].amount * 100), transactions[i].balance_after, transactions[i].note);
                strcat(tx_list, item);
                count++;
            }
        }
        strcat(tx_list, "]");

        snprintf(resp, sizeof(resp),
                 "{\"success\":true,\"account\":{\"number\":%lld,\"name\":\"%s\",\"phone\":\"%s\",\"type\":\"%s\",\"balance_formatted\":\"%s\",\"status\":\"%s\"},\"recent_transactions\":%s}",
                 accounts[idx].account_number, accounts[idx].name, accounts[idx].phone,
                 accounts[idx].account_type == 0 ? "Savings" : "Current",
                 bal_str,
                 accounts[idx].is_closed ? "Closed" : (accounts[idx].is_frozen ? "Frozen" : (accounts[idx].is_locked ? "Locked" : "Active")),
                 tx_list);
        send_json_response(client, 200, resp);
        return;
    }

    if (strcmp(path, "/api/customer/deposit") == 0) {
        double amt = get_json_double(body, "amount", 0.0);
        char err[100];
        if (deposit_money(session_acc, amt, err, sizeof(err))) {
            send_json_response(client, 200, "{\"success\":true}");
        } else {
            snprintf(resp, sizeof(resp), "{\"success\":false,\"error\":\"%s\"}", err);
            send_json_response(client, 400, resp);
        }
        return;
    }

    if (strcmp(path, "/api/customer/withdraw") == 0) {
        double amt = get_json_double(body, "amount", 0.0);
        char pin[16];
        get_json_string(body, "pin", pin, sizeof(pin));
        char err[100];
        if (withdraw_money(session_acc, amt, pin, err, sizeof(err))) {
            send_json_response(client, 200, "{\"success\":true}");
        } else {
            snprintf(resp, sizeof(resp), "{\"success\":false,\"error\":\"%s\"}", err);
            send_json_response(client, 400, resp);
        }
        return;
    }

    if (strcmp(path, "/api/customer/transfer") == 0) {
        long long target = get_json_long(body, "target_account", 0);
        double amt = get_json_double(body, "amount", 0.0);
        char pin[16];
        get_json_string(body, "pin", pin, sizeof(pin));
        char err[100];
        if (transfer_money(session_acc, target, amt, pin, err, sizeof(err))) {
            send_json_response(client, 200, "{\"success\":true}");
        } else {
            snprintf(resp, sizeof(resp), "{\"success\":false,\"error\":\"%s\"}", err);
            send_json_response(client, 400, resp);
        }
        return;
    }

    if (strcmp(path, "/api/customer/fd/list") == 0) {
        char list[4096] = "[";
        int count = 0;
        for (int i = 0; i < total_fds; i++) {
            if (fds[i].account_number == session_acc) {
                if (count > 0) strcat(list, ",");
                char item[256];
                snprintf(item, sizeof(item),
                         "{\"id\":%d,\"principal_formatted\":\"%.2f\",\"term_months\":%d,\"rate_formatted\":\"%.2f%%\",\"maturity_amount_formatted\":\"%.2f\",\"status\":\"%s\"}",
                         fds[i].id, fds[i].principal, fds[i].term_months, fds[i].interest_rate, fds[i].maturity_amount,
                         fds[i].is_active ? "Active" : "Closed");
                strcat(list, item);
                count++;
            }
        }
        strcat(list, "]");
        snprintf(resp, sizeof(resp), "{\"success\":true,\"fds\":%s}", list);
        send_json_response(client, 200, resp);
        return;
    }

    if (strcmp(path, "/api/customer/fd/book") == 0) {
        double amt = get_json_double(body, "amount", 0.0);
        int term = get_json_int(body, "term_months", 12);
        char err[100];
        if (book_fd(session_acc, amt, term, err, sizeof(err))) {
            send_json_response(client, 200, "{\"success\":true}");
        } else {
            snprintf(resp, sizeof(resp), "{\"success\":false,\"error\":\"%s\"}", err);
            send_json_response(client, 400, resp);
        }
        return;
    }

    if (strcmp(path, "/api/customer/fd/close") == 0) {
        int fd_id = get_json_int(body, "fd_id", 0);
        char err[100];
        if (close_fd(fd_id, session_acc, err, sizeof(err))) {
            send_json_response(client, 200, "{\"success\":true}");
        } else {
            snprintf(resp, sizeof(resp), "{\"success\":false,\"error\":\"%s\"}", err);
            send_json_response(client, 400, resp);
        }
        return;
    }

    if (strcmp(path, "/api/customer/loan/active") == 0) {
        int found = -1;
        for (int i = 0; i < total_loans; i++) {
            if (loans[i].account_number == session_acc && loans[i].status == 1) {
                found = i;
                break;
            }
        }
        if (found >= 0) {
            snprintf(resp, sizeof(resp),
                     "{\"has_loan\":true,\"loan\":{\"id\":%d,\"principal_formatted\":\"%.2f\",\"emi_formatted\":\"%.2f\",\"remaining_tenor_months\":%d}}",
                     loans[found].id, loans[found].principal, loans[found].monthly_emi, loans[found].tenor_months);
        } else {
            snprintf(resp, sizeof(resp), "{\"has_loan\":false}");
        }
        send_json_response(client, 200, resp);
        return;
    }

    if (strcmp(path, "/api/customer/loan/apply") == 0) {
        double amt = get_json_double(body, "principal", 0.0);
        int tenor = get_json_int(body, "tenor", 12);
        char err[100];
        if (apply_loan(session_acc, amt, tenor, err, sizeof(err))) {
            send_json_response(client, 200, "{\"success\":true}");
        } else {
            snprintf(resp, sizeof(resp), "{\"success\":false,\"error\":\"%s\"}", err);
            send_json_response(client, 400, resp);
        }
        return;
    }

    if (strcmp(path, "/api/customer/loan/pay-emi") == 0) {
        char err[100];
        if (pay_loan_emi(session_acc, err, sizeof(err))) {
            send_json_response(client, 200, "{\"success\":true}");
        } else {
            snprintf(resp, sizeof(resp), "{\"success\":false,\"error\":\"%s\"}", err);
            send_json_response(client, 400, resp);
        }
        return;
    }

    if (strcmp(path, "/api/customer/change-pin") == 0) {
        char cur_pin[16], new_pin[16];
        get_json_string(body, "current_pin", cur_pin, sizeof(cur_pin));
        get_json_string(body, "new_pin", new_pin, sizeof(new_pin));
        int idx = find_account(session_acc);
        if (idx >= 0 && (strlen(cur_pin) == 0 || strcmp(accounts[idx].pin, cur_pin) == 0)) {
            strncpy(accounts[idx].pin, new_pin, sizeof(accounts[idx].pin) - 1);
            save_all_data();
            send_json_response(client, 200, "{\"success\":true}");
        } else {
            send_json_response(client, 400, "{\"success\":false,\"error\":\"Current PIN is incorrect.\"}");
        }
        return;
    }

    // ---------------- ADMINISTRATOR OPERATIONS ----------------
    if (strncmp(path, "/api/admin/", 11) == 0) {
        if (!is_admin_session) {
            send_json_response(client, 401, "{\"error\":\"Administrator login required.\"}");
            return;
        }

        if (strcmp(path, "/api/admin/summary") == 0) {
            double total_dep = 0, total_loan_amt = 0, total_fd_amt = 0;
            int active_acc = 0, active_loans_cnt = 0, pending_loans_cnt = 0, active_fds_cnt = 0;

            for (int i = 0; i < total_accounts; i++) {
                if (!accounts[i].is_closed) {
                    active_acc++;
                    total_dep += accounts[i].balance;
                }
            }
            for (int i = 0; i < total_loans; i++) {
                if (loans[i].status == 1) {
                    active_loans_cnt++;
                    total_loan_amt += loans[i].remaining_amount;
                } else if (loans[i].status == 0) {
                    pending_loans_cnt++;
                }
            }
            for (int i = 0; i < total_fds; i++) {
                if (fds[i].is_active) {
                    active_fds_cnt++;
                    total_fd_amt += fds[i].principal;
                }
            }

            snprintf(resp, sizeof(resp),
                     "{\"success\":true,\"summary\":{\"accounts\":{\"total\":%d,\"active\":%d},\"financials\":{\"customer_deposits_formatted\":\"%.2f\",\"loans_outstanding_formatted\":\"%.2f\",\"loans_count\":%d,\"loans_pending_count\":%d,\"fixed_deposits_total_formatted\":\"%.2f\",\"fixed_deposits_count\":%d}}}",
                     total_accounts, active_acc, total_dep, total_loan_amt, active_loans_cnt, pending_loans_cnt, total_fd_amt, active_fds_cnt);
            send_json_response(client, 200, resp);
            return;
        }

        if (strncmp(path, "/api/admin/accounts", 19) == 0 && strcmp(path, "/api/admin/accounts/open") != 0 &&
            strcmp(path, "/api/admin/accounts/freeze") != 0 && strcmp(path, "/api/admin/accounts/close") != 0 &&
            strcmp(path, "/api/admin/accounts/reset-pin") != 0) {
            char list[6144] = "[";
            for (int i = 0; i < total_accounts; i++) {
                if (i > 0) strcat(list, ",");
                char item[256];
                snprintf(item, sizeof(item),
                         "{\"number\":%lld,\"name\":\"%s\",\"phone\":\"%s\",\"type\":\"%s\",\"status\":\"%s\",\"balance_formatted\":\"%.2f\"}",
                         accounts[i].account_number, accounts[i].name, accounts[i].phone,
                         accounts[i].account_type == 0 ? "Savings" : "Current",
                         accounts[i].is_closed ? "Closed" : (accounts[i].is_frozen ? "Frozen" : (accounts[i].is_locked ? "Locked" : "Active")),
                         accounts[i].balance);
                strcat(list, item);
            }
            strcat(list, "]");
            snprintf(resp, sizeof(resp), "{\"success\":true,\"accounts\":%s}", list);
            send_json_response(client, 200, resp);
            return;
        }

        if (strcmp(path, "/api/admin/accounts/open") == 0) {
            char name[60], phone[20];
            get_json_string(body, "name", name, sizeof(name));
            get_json_string(body, "phone", phone, sizeof(phone));
            int type = get_json_int(body, "type", 0);
            double dep = get_json_double(body, "opening_deposit", 1000.0);
            char temp_pin[10];

            long long new_acc = admin_open_account(name, phone, type, dep, temp_pin);
            if (new_acc > 0) {
                snprintf(resp, sizeof(resp),
                         "{\"success\":true,\"account\":{\"number\":%lld,\"name\":\"%s\",\"balance_formatted\":\"%.2f\"},\"temp_pin\":\"%s\"}",
                         new_acc, name, dep, temp_pin);
                send_json_response(client, 200, resp);
            } else {
                send_json_response(client, 400, "{\"success\":false,\"error\":\"Maximum account capacity reached.\"}");
            }
            return;
        }

        if (strcmp(path, "/api/admin/accounts/freeze") == 0) {
            long long acc = get_json_long(body, "number", 0);
            int idx = find_account(acc);
            if (idx >= 0) {
                accounts[idx].is_frozen = !accounts[idx].is_frozen;
                save_all_data();
                send_json_response(client, 200, "{\"success\":true}");
            } else {
                send_json_response(client, 404, "{\"error\":\"Account not found\"}");
            }
            return;
        }

        if (strcmp(path, "/api/admin/accounts/reset-pin") == 0) {
            long long acc = get_json_long(body, "number", 0);
            int idx = find_account(acc);
            if (idx >= 0) {
                strcpy(accounts[idx].pin, "1234");
                accounts[idx].is_locked = 0;
                accounts[idx].failed_attempts = 0;
                save_all_data();
                send_json_response(client, 200, "{\"success\":true,\"temp_pin\":\"1234\"}");
            } else {
                send_json_response(client, 404, "{\"error\":\"Account not found\"}");
            }
            return;
        }

        if (strcmp(path, "/api/admin/accounts/close") == 0) {
            long long acc = get_json_long(body, "number", 0);
            int idx = find_account(acc);
            if (idx >= 0) {
                accounts[idx].is_closed = 1;
                save_all_data();
                send_json_response(client, 200, "{\"success\":true}");
            } else {
                send_json_response(client, 404, "{\"error\":\"Account not found\"}");
            }
            return;
        }

        if (strcmp(path, "/api/admin/loans/pending") == 0) {
            char list[4096] = "[";
            int count = 0;
            for (int i = 0; i < total_loans; i++) {
                if (loans[i].status == 0) { // Pending
                    if (count > 0) strcat(list, ",");
                    char item[256];
                    snprintf(item, sizeof(item),
                             "{\"id\":%d,\"account\":%lld,\"applicant_name\":\"%s\",\"principal_formatted\":\"%.2f\",\"tenor\":%d,\"rate_formatted\":\"%.2f%%\",\"emi_formatted\":\"%.2f\"}",
                             loans[i].id, loans[i].account_number, loans[i].applicant_name,
                             loans[i].principal, loans[i].tenor_months, loans[i].interest_rate, loans[i].monthly_emi);
                    strcat(list, item);
                    count++;
                }
            }
            strcat(list, "]");
            snprintf(resp, sizeof(resp), "{\"success\":true,\"loans\":%s}", list);
            send_json_response(client, 200, resp);
            return;
        }

        if (strcmp(path, "/api/admin/loans/review") == 0) {
            int loan_id = get_json_int(body, "loan_id", 0);
            char decision[16];
            get_json_string(body, "decision", decision, sizeof(decision));

            for (int i = 0; i < total_loans; i++) {
                if (loans[i].id == loan_id && loans[i].status == 0) {
                    if (strcmp(decision, "approve") == 0) {
                        loans[i].status = 1; // Approved
                        int acc_idx = find_account(loans[i].account_number);
                        if (acc_idx >= 0) {
                            accounts[acc_idx].balance += loans[i].principal;
                            record_transaction(loans[i].account_number, 0, "Loan Credit", loans[i].principal,
                                               accounts[acc_idx].balance, "Loan Disbursed");
                        }
                    } else {
                        loans[i].status = 2; // Rejected
                    }
                    save_all_data();
                    send_json_response(client, 200, "{\"success\":true}");
                    return;
                }
            }
            send_json_response(client, 404, "{\"error\":\"Loan application not found\"}");
            return;
        }

        if (strcmp(path, "/api/admin/interest/post") == 0) {
            // Calculate 4.0% p.a. monthly interest on savings accounts
            double total_credited = 0;
            int count = 0;
            for (int i = 0; i < total_accounts; i++) {
                if (accounts[i].account_type == 0 && !accounts[i].is_closed && accounts[i].balance > 0) {
                    double interest = (accounts[i].balance * 0.04) / 12.0;
                    accounts[i].balance += interest;
                    record_transaction(accounts[i].account_number, 0, "Interest Credit", interest,
                                       accounts[i].balance, "Monthly Savings Interest (4% p.a.)");
                    total_credited += interest;
                    count++;
                }
            }
            save_all_data();
            snprintf(resp, sizeof(resp), "{\"success\":true,\"total_credited\":\"%.2f\",\"accounts_updated\":%d}", total_credited, count);
            send_json_response(client, 200, resp);
            return;
        }

        if (strcmp(path, "/api/admin/clock/advance") == 0) {
            int days = get_json_int(body, "days", 1);
            system_offset_days += days;
            char date_str[30];
            get_current_time_str(date_str, sizeof(date_str));
            snprintf(resp, sizeof(resp), "{\"success\":true,\"offset_days\":%d,\"system_date\":\"%s\"}", system_offset_days, date_str);
            send_json_response(client, 200, resp);
            return;
        }

        if (strcmp(path, "/api/admin/audit") == 0) {
            char list[6144] = "[";
            for (int i = total_audit - 1; i >= 0 && i >= total_audit - 20; i--) {
                if (i < total_audit - 1) strcat(list, ",");
                char item[256];
                snprintf(item, sizeof(item), "\"%s\"", audit_logs[i]);
                strcat(list, item);
            }
            strcat(list, "]");
            snprintf(resp, sizeof(resp), "{\"success\":true,\"entries\":%s}", list);
            send_json_response(client, 200, resp);
            return;
        }
    }

    // Default 404
    send_json_response(client, 404, "{\"error\":\"Route not found\"}");
}

// -------------------------------------------------------------
// Program Entry Point (main)
// -------------------------------------------------------------

int main(int argc, char *argv[]) {
    int port = DEFAULT_PORT;
    if (argc > 1) {
        port = atoi(argv[1]);
        if (port <= 0) port = DEFAULT_PORT;
    }

    printf("========================================================\n");
    printf("   College Bank Management System (Beginner Version)    \n");
    printf("========================================================\n");

    load_all_data();

#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("Error: WinSock initialization failed.\n");
        return 1;
    }
#endif

    SOCKET server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock == INVALID_SOCKET) {
        printf("Error: Could not create socket.\n");
        return 1;
    }

    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons((unsigned short)port);

    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        printf("Error: Could not bind to port %d. Is another server running?\n", port);
        close_socket(server_sock);
        return 1;
    }

    if (listen(server_sock, 10) == SOCKET_ERROR) {
        printf("Error: Listen failed.\n");
        close_socket(server_sock);
        return 1;
    }

    printf("\n>> Bank Server running successfully!\n");
    printf(">> Open in your web browser: http://127.0.0.1:%d\n", port);
    printf(">> Press Ctrl+C in this terminal to stop the server.\n\n");
    fflush(stdout);

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        SOCKET client = accept(server_sock, (struct sockaddr *)&client_addr, &client_len);
        if (client == INVALID_SOCKET) {
            continue;
        }

#ifdef _WIN32
        DWORD sock_to = 3000;
        setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, (const char *)&sock_to, sizeof(sock_to));
        setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, (const char *)&sock_to, sizeof(sock_to));
#else
        struct timeval sock_tv;
        sock_tv.tv_sec = 3;
        sock_tv.tv_usec = 0;
        setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, (const char *)&sock_tv, sizeof(sock_tv));
        setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, (const char *)&sock_tv, sizeof(sock_tv));
#endif

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
                    if (cl) {
                        expected_len = atoi(cl + 15);
                    } else {
                        expected_len = 0;
                    }
                }
                int body_len = total_read - (int)(hdr_end + 4 - buffer);
                if (body_len >= expected_len) {
                    break;
                }
            }
        }

        if (total_read > 0) {
            handle_client_request(client, buffer);
        }
        close_socket(client);
    }

#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
