/*
 * ============================================================================
 *  SecureBank Management System  -  v1.0.0
 *  Pure C11 / POSIX.  No third-party libraries.
 *
 *  Build:  gcc -std=c11 -O2 -Wall -Wextra -o bank_system bank_system.c -lm
 *  Run:    ./bank_system [-f data_file] [--no-color]
 *
 *  First run: admin password is "Admin@123" (you are warned to change it).
 *
 *  FEATURES
 *  --------
 *  Security   SHA-256 salted + stretched PIN/password hashing, hidden input,
 *             3-strike customer lockout, forced PIN change on first login,
 *             weak-PIN rejection, PIN re-entry for transfers, full audit log.
 *  Accounts   Savings (min balance, interest) and Current (overdraft).
 *             Luhn check digit on account numbers, daily withdrawal and
 *             transfer limits, freeze / unfreeze / close, masked numbers.
 *  Ledger     Immutable, append-only transaction ledger with running
 *             balances, receipts, mini and full statements, CSV export.
 *  Deposits   Fixed deposits with quarterly compounding, maturity payout
 *             and premature-closure penalty.
 *  Loans      EMI calculation, application -> admin approval workflow,
 *             processing fee, amortisation schedule, EMI payment, foreclosure.
 *  Admin      Open accounts, search, review loans, post monthly interest,
 *             bank-wide summary, audit log viewer, simulated clock.
 *  Storage    Binary file, CRC-32 integrity check, atomic save, .bak backup.
 *  Money      Integer cents everywhere (no floating-point balances).
 * ============================================================================
 */

#ifdef _WIN32
  #define WIN32_LEAN_AND_MEAN
  #define _CRT_SECURE_NO_WARNINGS
  #define __USE_MINGW_ANSI_STDIO 1
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <windows.h>
  #include <wincrypt.h>
  #include <process.h>
  #include <io.h>
  #define isatty _isatty
  #define STDIN_FILENO 0
  #define STDOUT_FILENO 1
  #define strcasecmp _stricmp
  #define strncasecmp _strnicmp
  #define fsync _commit
  #define fileno _fileno
  typedef int socklen_t;
  #define close_socket closesocket
  #define getpid _getpid
  #define sleep_sec(s) Sleep((s) * 1000)
#else
  #define _POSIX_C_SOURCE 200809L
  #include <termios.h>
  #include <unistd.h>
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <strings.h>
  typedef int SOCKET;
  #define INVALID_SOCKET (-1)
  #define SOCKET_ERROR (-1)
  #define close_socket close
  #define sleep_sec(s) sleep(s)
#endif

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <math.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
static struct tm *my_localtime_r(const time_t *t, struct tm *tmv) {
    if (!tmv) return NULL;
    memset(tmv, 0, sizeof(*tmv));
    struct tm *p = localtime(t);
    if (p) *tmv = *p;
    return tmv;
}
#define localtime_r my_localtime_r
#endif

/* ------------------------------------------------------------------------- */
/*  Constants and business rules                                             */
/* ------------------------------------------------------------------------- */

#define APP_NAME          "SecureBank Management System"
#define APP_VERSION       "1.0.0"
#define DEFAULT_DATA_FILE "bank.dat"
#define CURRENCY          "INR"

#define NAME_LEN          48
#define PHONE_LEN         16
#define NOTE_LEN          32
#define MAX_RECORDS       4000000u
#define DAY_SECONDS       86400
#define LOCK_THRESHOLD    3
#define ADMIN_MAX_TRIES   5
#define ACC_SEQ_START     UINT64_C(100000000)       /* -> 10-digit numbers   */
#define MAX_AMOUNT        INT64_C(99999999999)      /* 999,999,999.99        */
#define MAX_DEPOSIT       INT64_C(1000000000)       /* 10,000,000.00 per txn */
#define LARGE_DEPOSIT     INT64_C(50000000)         /* 500,000.00 flagged    */
#define FD_MIN_AMOUNT     INT64_C(500000)           /* 5,000.00              */
#define LOAN_MIN          INT64_C(1000000)          /* 10,000.00             */
#define LOAN_MAX          INT64_C(500000000)        /* 5,000,000.00          */
#define LOAN_FEE_MIN      INT64_C(50000)            /* 500.00                */
#define LOAN_FEE_MAX      INT64_C(2500000)          /* 25,000.00             */
#define DEFAULT_ADMIN_PW  "Admin@123"

#define FILE_MAGIC        "SBANK01"
#define FILE_VERSION      1u

typedef enum { ACC_SAVINGS, ACC_CURRENT, ACC_TYPE_COUNT } AccType;
typedef enum { ST_ACTIVE, ST_FROZEN, ST_LOCKED, ST_CLOSED } AccStatus;
typedef enum { LN_PENDING, LN_ACTIVE, LN_CLOSED, LN_REJECTED } LoanStatus;
typedef enum { FD_ACTIVE, FD_MATURED, FD_BROKEN } FdStatus;

typedef enum {
    TX_OPENING, TX_DEPOSIT, TX_WITHDRAW, TX_TRANSFER_OUT, TX_TRANSFER_IN,
    TX_INTEREST, TX_FEE, TX_LOAN_DISBURSE, TX_EMI, TX_LOAN_CLOSE,
    TX_FD_OPEN, TX_FD_CLOSE, TX_TYPE_COUNT
} TxType;

typedef struct {
    const char *name;
    int64_t min_open;       /* minimum opening deposit              */
    int64_t floor;          /* lowest permitted balance             */
    uint32_t rate_bp;       /* annual interest in basis points      */
    int64_t withdraw_limit; /* per day                              */
    int64_t transfer_limit; /* per day                              */
} AccTypeInfo;

static const AccTypeInfo ACC_INFO[ACC_TYPE_COUNT] = {
    {"Savings", INT64_C(100000), INT64_C(100000), 350, INT64_C(5000000), INT64_C(20000000)},
    {"Current", INT64_C(500000), INT64_C(-2500000), 0, INT64_C(20000000), INT64_C(50000000)},
};

static const char *const STATUS_NAMES[] = {"Active", "Frozen", "Locked", "Closed"};
static const char *const LOAN_STATUS_NAMES[] = {"Pending", "Active", "Closed", "Rejected"};
static const char *const FD_STATUS_NAMES[] = {"Active", "Matured", "Broken"};
static const char *const TX_NAMES[TX_TYPE_COUNT] = {
    "Opening", "Deposit", "Withdrawal", "Transfer Out", "Transfer In",
    "Interest", "Fee", "Loan Credit", "EMI", "Loan Payoff", "FD Opened", "FD Payout"
};

typedef struct { int months; uint32_t rate_bp; } FdRate;
static const FdRate FD_RATES[] = {{6, 550}, {12, 650}, {24, 700}, {36, 725}, {60, 750}};
#define FD_RATE_COUNT ((int)(sizeof FD_RATES / sizeof FD_RATES[0]))

/* ------------------------------------------------------------------------- */
/*  Data model (fixed layout, no implicit padding)                           */
/* ------------------------------------------------------------------------- */

typedef struct {
    uint64_t number;
    uint8_t  type, status, failed_attempts, pin_temp;
    uint32_t limit_day;
    int64_t  balance;
    int64_t  withdrawn_today, transferred_today;
    int64_t  created;
    char     name[NAME_LEN];
    char     phone[PHONE_LEN];
    uint8_t  salt[8];
    uint8_t  pin_hash[32];
} Account;                                   /* 152 bytes */

typedef struct {
    uint64_t id;
    int64_t  timestamp;
    uint64_t account;
    uint64_t counterparty;
    int64_t  amount;                         /* signed: + credit, - debit */
    int64_t  balance_after;
    uint8_t  type, pad[7];
    char     note[NOTE_LEN];
} Txn;                                       /* 88 bytes */

typedef struct {
    uint32_t id;
    uint8_t  status, pad[3];
    uint64_t account;
    int64_t  principal, outstanding, emi;
    uint32_t rate_bp;
    uint16_t tenor, paid;
    int64_t  applied_at, approved_at;
} Loan;                                      /* 64 bytes */

typedef struct {
    uint32_t id;
    uint8_t  status, pad[3];
    uint64_t account;
    int64_t  principal;
    uint32_t rate_bp;
    uint16_t months, pad2;
    int64_t  opened_at, maturity_at;
} Fd;                                        /* 48 bytes */

typedef struct {
    char     magic[8];
    uint32_t version, crc;
    uint32_t n_acc, n_txn, n_loan, n_fd;
    uint64_t next_acc_seq, next_txn_id;
    uint32_t next_loan_id, next_fd_id;
    int32_t  offset_days;
    uint32_t last_interest_ym;
    uint8_t  admin_salt[8];
    uint8_t  admin_hash[32];
} FileHeader;                                /* 104 bytes */

typedef struct {
    Account *acc;  size_t n_acc,  cap_acc;
    Txn     *txn;  size_t n_txn,  cap_txn;
    Loan    *loan; size_t n_loan, cap_loan;
    Fd      *fd;   size_t n_fd,   cap_fd;
    uint64_t next_acc_seq, next_txn_id;
    uint32_t next_loan_id, next_fd_id;
    int32_t  offset_days;
    uint32_t last_interest_ym;
    uint8_t  admin_salt[8], admin_hash[32];
    bool     dirty;
} Bank;

/* ------------------------------------------------------------------------- */
/*  Globals                                                                  */
/* ------------------------------------------------------------------------- */

static bool        g_color = false;
static int32_t     g_offset_days = 0;
static const char *g_data_path = DEFAULT_DATA_FILE;
static char        g_audit_path[1100];
#ifndef _WIN32
static struct termios g_old_term;
#endif
static volatile sig_atomic_t g_echo_off = 0;

#define C_RESET  "\033[0m"
#define C_BOLD   "\033[1m"
#define C_RED    "\033[31m"
#define C_GREEN  "\033[32m"
#define C_YELLOW "\033[33m"
#define C_CYAN   "\033[36m"
#define CLR(c)   (g_color ? (c) : "")

#if defined(__GNUC__)
#if defined(_WIN32)
#define PRINTF_FMT(a, b) __attribute__((format(gnu_printf, a, b)))
#else
#define PRINTF_FMT(a, b) __attribute__((format(printf, a, b)))
#endif
#else
#define PRINTF_FMT(a, b)
#endif

static void say(const char *color, const char *fmt, ...) PRINTF_FMT(2, 3);
static void say(const char *color, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fputs(CLR(color), stdout);
    vprintf(fmt, ap);
    fputs(CLR(C_RESET), stdout);
    putchar('\n');
    va_end(ap);
}
#define OK(...)   say(C_GREEN, __VA_ARGS__)
#define ERR(...)  say(C_RED, __VA_ARGS__)
#define WARN(...) say(C_YELLOW, __VA_ARGS__)

/* ------------------------------------------------------------------------- */
/*  Generic utilities                                                        */
/* ------------------------------------------------------------------------- */

static void *xrealloc(void *p, size_t n)
{
    void *q = realloc(p, n ? n : 1);
    if (!q) { fputs("fatal: out of memory\n", stderr); exit(EXIT_FAILURE); }
    return q;
}

static void *array_push(void **arr, size_t *n, size_t *cap, size_t elem, const void *item)
{
    if (*n >= *cap) {
        size_t nc = *cap ? *cap * 2 : 16;
        *arr = xrealloc(*arr, nc * elem);
        *cap = nc;
    }
    char *slot = (char *)*arr + (*n) * elem;
    memcpy(slot, item, elem);
    (*n)++;
    return slot;
}

static void str_trim(char *s)
{
    char *start = s;
    while (isspace((unsigned char)*start)) start++;
    size_t n = strlen(start);
    while (n > 0 && isspace((unsigned char)start[n - 1])) n--;
    memmove(s, start, n);
    s[n] = '\0';
}

static void str_copy(char *dst, size_t size, const char *src)
{
    size_t n = strlen(src);
    if (n >= size) n = size - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

static bool contains_ci(const char *hay, const char *needle)
{
    size_t nl = strlen(needle);
    if (!nl) return true;
    for (; *hay; hay++)
        if (strncasecmp(hay, needle, nl) == 0) return true;
    return false;
}

static uint32_t crc32_update(uint32_t crc, const void *data, size_t len)
{
    static uint32_t table[256];
    static bool ready = false;
    if (!ready) {
        for (uint32_t i = 0; i < 256; i++) {
            uint32_t c = i;
            for (int k = 0; k < 8; k++) c = (c & 1u) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            table[i] = c;
        }
        ready = true;
    }
    const uint8_t *p = data;
    crc = ~crc;
    for (size_t i = 0; i < len; i++) crc = table[(crc ^ p[i]) & 0xFFu] ^ (crc >> 8);
    return ~crc;
}

/* ------------------------------------------------------------------------- */
/*  SHA-256 and credential hashing                                           */
/* ------------------------------------------------------------------------- */

static const uint32_t SHA_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static uint32_t rotr32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static void sha256_block(uint32_t h[8], const uint8_t *p)
{
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t)p[4 * i] << 24 | (uint32_t)p[4 * i + 1] << 16 |
               (uint32_t)p[4 * i + 2] << 8 | (uint32_t)p[4 * i + 3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = hh + S1 + ch + SHA_K[i] + w[i];
        uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + mj;
        hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

static void sha256(const uint8_t *msg, size_t len, uint8_t out[32])
{
    uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                     0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    size_t i;
    for (i = 0; i + 64 <= len; i += 64) sha256_block(h, msg + i);
    uint8_t tail[128];
    memset(tail, 0, sizeof tail);
    size_t rem = len - i;
    memcpy(tail, msg + i, rem);
    tail[rem] = 0x80;
    size_t tl = rem < 56 ? 64 : 128;
    uint64_t bits = (uint64_t)len * 8;
    for (int k = 0; k < 8; k++) tail[tl - 1 - (size_t)k] = (uint8_t)(bits >> (8 * k));
    sha256_block(h, tail);
    if (tl == 128) sha256_block(h, tail + 64);
    for (int k = 0; k < 8; k++) {
        out[4 * k]     = (uint8_t)(h[k] >> 24);
        out[4 * k + 1] = (uint8_t)(h[k] >> 16);
        out[4 * k + 2] = (uint8_t)(h[k] >> 8);
        out[4 * k + 3] = (uint8_t)h[k];
    }
}

/* Salted, stretched hash: slows brute-force attacks on short PINs. */
static void hash_secret(const uint8_t salt[8], const char *secret, uint8_t out[32])
{
    uint8_t buf[8 + 64];
    size_t sl = strlen(secret);
    if (sl > 64) sl = 64;
    memcpy(buf, salt, 8);
    memcpy(buf + 8, secret, sl);
    sha256(buf, 8 + sl, out);
    uint8_t tmp[40];
    for (int i = 0; i < 5000; i++) {
        memcpy(tmp, out, 32);
        memcpy(tmp + 32, salt, 8);
        sha256(tmp, 40, out);
    }
}

static bool ct_equal(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) diff |= (uint8_t)(a[i] ^ b[i]);
    return diff == 0;
}

static void random_bytes(void *buf, size_t n)
{
    FILE *f = fopen("/dev/urandom", "rb");
    if (f && fread(buf, 1, n, f) == n) { fclose(f); return; }
    if (f) fclose(f);
#ifdef _WIN32
    HCRYPTPROV hCryptProv;
    if (CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
        if (CryptGenRandom(hCryptProv, (DWORD)n, (BYTE *)buf)) {
            CryptReleaseContext(hCryptProv, 0);
            return;
        }
        CryptReleaseContext(hCryptProv, 0);
    }
#endif
    uint8_t *p = buf;                       /* fallback */
    srand((unsigned)time(NULL) ^ (unsigned)getpid());
    for (size_t i = 0; i < n; i++) p[i] = (uint8_t)(rand() & 0xFF);
}

/* ------------------------------------------------------------------------- */
/*  Time and date helpers (system clock + simulated offset)                  */
/* ------------------------------------------------------------------------- */

static int64_t now_ts(void) { return (int64_t)time(NULL) + (int64_t)g_offset_days * DAY_SECONDS; }

static int ymd_of(int64_t ts)
{
    time_t t = (time_t)ts;
    struct tm tmv;
    localtime_r(&t, &tmv);
    return (tmv.tm_year + 1900) * 10000 + (tmv.tm_mon + 1) * 100 + tmv.tm_mday;
}

static const char *fmt_datetime(int64_t ts)
{
    static char bufs[4][24];
    static unsigned idx;
    char *out = bufs[idx++ & 3u];
    time_t t = (time_t)ts;
    struct tm tmv;
    localtime_r(&t, &tmv);
    strftime(out, 24, "%Y-%m-%d %H:%M", &tmv);
    return out;
}

static const char *fmt_date_ts(int64_t ts)
{
    static char bufs[4][16];
    static unsigned idx;
    char *out = bufs[idx++ & 3u];
    int d = ymd_of(ts);
    snprintf(out, 16, "%04d-%02d-%02d", d / 10000, (d / 100) % 100, d % 100);
    return out;
}

static bool parse_date(const char *s, int *out)
{
    int y, m, d, n = 0;
    if (sscanf(s, "%d-%d-%d%n", &y, &m, &d, &n) != 3 || s[n] != '\0') return false;
    static const int dim[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    bool leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    if (y < 1970 || y > 2100 || m < 1 || m > 12) return false;
    if (d < 1 || d > dim[m - 1] + (m == 2 && leap ? 1 : 0)) return false;
    *out = y * 10000 + m * 100 + d;
    return true;
}

/* ------------------------------------------------------------------------- */
/*  Money, account numbers                                                   */
/* ------------------------------------------------------------------------- */

static const char *fmt_money(int64_t cents)
{
    static char bufs[12][64];
    static unsigned idx;
    char *out = bufs[idx++ % 12u];
    bool neg = cents < 0;
    uint64_t v = neg ? (uint64_t)(-cents) : (uint64_t)cents;
    char digits[32], grouped[48];
    snprintf(digits, sizeof digits, "%" PRIu64, v / 100);
    int dl = (int)strlen(digits), gi = 0;
    for (int i = 0; i < dl; i++) {
        if (i > 0 && (dl - i) % 3 == 0) grouped[gi++] = ',';
        grouped[gi++] = digits[i];
    }
    grouped[gi] = '\0';
    snprintf(out, 64, "%s%s.%02u", neg ? "-" : "", grouped, (unsigned)(v % 100));
    return out;
}

static bool parse_amount(const char *s, int64_t *out)
{
    int64_t whole = 0, frac = 0;
    int fd = 0;
    bool any = false, dot = false;
    for (const char *p = s; *p; p++) {
        if (isdigit((unsigned char)*p)) {
            int d = *p - '0';
            if (dot) { if (fd >= 2) return false; frac = frac * 10 + d; fd++; }
            else { whole = whole * 10 + d; if (whole > MAX_AMOUNT / 100) return false; }
            any = true;
        } else if (*p == '.' && !dot) dot = true;
        else if (*p == ',') continue;
        else return false;
    }
    if (!any) return false;
    if (fd == 1) frac *= 10;
    int64_t total = whole * 100 + frac;
    if (total <= 0 || total > MAX_AMOUNT) return false;
    *out = total;
    return true;
}

static int luhn_check_digit(uint64_t payload)
{
    int sum = 0;
    bool dbl = true;
    while (payload > 0) {
        int d = (int)(payload % 10);
        payload /= 10;
        if (dbl) { d *= 2; if (d > 9) d -= 9; }
        sum += d;
        dbl = !dbl;
    }
    return (10 - (sum % 10)) % 10;
}

static bool account_number_valid(uint64_t n)
{
    return n >= UINT64_C(1000000000) && n <= UINT64_C(9999999999) &&
           luhn_check_digit(n / 10) == (int)(n % 10);
}

static const char *mask_acct(uint64_t n)
{
    static char bufs[4][16];
    static unsigned idx;
    char *out = bufs[idx++ & 3u];
    snprintf(out, 16, "XXXXXX%04u", (unsigned)(n % 10000));
    return out;
}

static const char *fmt_rate(uint32_t bp)
{
    static char bufs[4][16];
    static unsigned idx;
    char *out = bufs[idx++ & 3u];
    snprintf(out, 16, "%u.%02u%%", bp / 100, bp % 100);
    return out;
}

/* ------------------------------------------------------------------------- */
/*  Terminal input                                                           */
/* ------------------------------------------------------------------------- */

static void restore_terminal_and_exit(int sig)
{
    (void)sig;
#ifndef _WIN32
    if (g_echo_off) tcsetattr(STDIN_FILENO, TCSANOW, &g_old_term);
    const char nl = '\n';
    if (write(STDOUT_FILENO, &nl, 1) < 0) { /* ignore */ }
    _exit(130);
#else
    exit(130);
#endif
}

static bool read_line(const char *prompt, char *buf, size_t size)
{
    if (prompt) { fputs(prompt, stdout); fflush(stdout); }
    if (!fgets(buf, (int)size, stdin)) return false;
    size_t n = strlen(buf);
    if (n > 0 && buf[n - 1] == '\n') buf[--n] = '\0';
    else if (n == size - 1) { int c; while ((c = getchar()) != '\n' && c != EOF) { } }
    str_trim(buf);
    return true;
}

static bool read_secret(const char *prompt, char *buf, size_t size)
{
#ifndef _WIN32
    bool tty = isatty(STDIN_FILENO) && tcgetattr(STDIN_FILENO, &g_old_term) == 0;
    if (tty) {
        struct termios nw = g_old_term;
        nw.c_lflag &= ~(tcflag_t)ECHO;
        tcsetattr(STDIN_FILENO, TCSANOW, &nw);
        g_echo_off = 1;
    }
    bool ok = read_line(prompt, buf, size);
    if (tty) {
        tcsetattr(STDIN_FILENO, TCSANOW, &g_old_term);
        g_echo_off = 0;
        putchar('\n');
    }
    return ok;
#else
    if (prompt) { fputs(prompt, stdout); fflush(stdout); }
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    bool tty = GetConsoleMode(hStdin, &mode);
    if (tty) SetConsoleMode(hStdin, mode & (~ENABLE_ECHO_INPUT));
    bool ok = read_line(NULL, buf, size);
    if (tty) {
        SetConsoleMode(hStdin, mode);
        putchar('\n');
    }
    return ok;
#endif
}

static bool is_cancel(const char *s) { return strcasecmp(s, "cancel") == 0 || strcasecmp(s, "q") == 0; }

static bool prompt_yesno(const char *prompt, bool def)
{
    char buf[16], full[200];
    snprintf(full, sizeof full, "%s [%s]: ", prompt, def ? "Y/n" : "y/N");
    if (!read_line(full, buf, sizeof buf)) return false;
    if (!buf[0]) return def;
    return buf[0] == 'y' || buf[0] == 'Y';
}

static bool prompt_amount(const char *label, int64_t min, int64_t max, int64_t *out)
{
    char buf[64], prompt[128];
    for (;;) {
        snprintf(prompt, sizeof prompt, "%s (%s): ", label, CURRENCY);
        if (!read_line(prompt, buf, sizeof buf) || !buf[0] || is_cancel(buf)) return false;
        int64_t v;
        if (!parse_amount(buf, &v)) { ERR("  Invalid amount (positive, max 2 decimals)."); continue; }
        if (v < min) { ERR("  Minimum is %s %s.", CURRENCY, fmt_money(min)); continue; }
        if (v > max) { ERR("  Maximum is %s %s.", CURRENCY, fmt_money(max)); continue; }
        *out = v;
        return true;
    }
}

static bool prompt_choice(const char *title, const char *const *names, int n, int *out)
{
    char buf[32];
    printf("%s\n", title);
    for (int i = 0; i < n; i++) printf("  %d) %s\n", i + 1, names[i]);
    for (;;) {
        if (!read_line("Choice: ", buf, sizeof buf) || !buf[0] || is_cancel(buf)) return false;
        char *end;
        long v = strtol(buf, &end, 10);
        if (*end == '\0' && v >= 1 && v <= n) { *out = (int)v - 1; return true; }
        ERR("  Invalid choice.");
    }
}

static bool prompt_account_number(const char *label, uint64_t *out)
{
    char buf[32];
    if (!read_line(label, buf, sizeof buf) || !buf[0] || is_cancel(buf)) return false;
    char *end;
    errno = 0;
    unsigned long long v = strtoull(buf, &end, 10);
    if (errno || *end != '\0' || !account_number_valid(v)) {
        ERR("  Invalid account number (format or check digit is wrong).");
        return false;
    }
    *out = v;
    return true;
}

static bool valid_name(const char *s)
{
    size_t n = strlen(s);
    if (n < 2 || n >= NAME_LEN) return false;
    for (; *s; s++)
        if (!isalpha((unsigned char)*s) && *s != ' ' && *s != '.' && *s != '\'' && *s != '-') return false;
    return true;
}

static bool valid_phone(const char *s)
{
    if (strlen(s) != 10 || s[0] == '0') return false;
    for (; *s; s++) if (!isdigit((unsigned char)*s)) return false;
    return true;
}

static bool pin_strong(const char *pin)
{
    size_t n = strlen(pin);
    if (n < 4 || n > 6) return false;
    bool same = true, asc = true, desc = true;
    for (size_t i = 0; i < n; i++) {
        if (!isdigit((unsigned char)pin[i])) return false;
        if (i > 0) {
            if (pin[i] != pin[0]) same = false;
            if (pin[i] != pin[i - 1] + 1) asc = false;
            if (pin[i] != pin[i - 1] - 1) desc = false;
        }
    }
    return !(same || asc || desc);
}

static void make_temp_pin(char out[8])
{
    do {
        uint32_t r;
        random_bytes(&r, sizeof r);
        snprintf(out, 8, "%04u", r % 10000u);
    } while (!pin_strong(out));
}

/* ------------------------------------------------------------------------- */
/*  Audit log                                                                */
/* ------------------------------------------------------------------------- */

static void audit(const char *actor, const char *fmt, ...) PRINTF_FMT(2, 3);
static void audit(const char *actor, const char *fmt, ...)
{
    FILE *f = fopen(g_audit_path, "a");
    if (!f) return;
    char msg[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);
    fprintf(f, "%s | %-12s | %s\n", fmt_datetime(now_ts()), actor, msg);
    fclose(f);
}

/* ------------------------------------------------------------------------- */
/*  Bank store                                                               */
/* ------------------------------------------------------------------------- */

static void set_admin_password(Bank *b, const char *pw)
{
    random_bytes(b->admin_salt, sizeof b->admin_salt);
    hash_secret(b->admin_salt, pw, b->admin_hash);
    b->dirty = true;
}

static bool verify_admin_password(const Bank *b, const char *pw)
{
    uint8_t h[32];
    hash_secret(b->admin_salt, pw, h);
    return ct_equal(h, b->admin_hash, 32);
}

static void bank_init(Bank *b)
{
    memset(b, 0, sizeof *b);
    b->next_acc_seq = ACC_SEQ_START;
    b->next_txn_id = 100001;
    b->next_loan_id = 1;
    b->next_fd_id = 1;
}

static void bank_free(Bank *b)
{
    free(b->acc); free(b->txn); free(b->loan); free(b->fd);
    b->acc = NULL; b->txn = NULL; b->loan = NULL; b->fd = NULL;
}

static int cmp_acc_key(const void *k, const void *e)
{
    uint64_t key = *(const uint64_t *)k, n = ((const Account *)e)->number;
    return (key > n) - (key < n);
}

static Account *find_account(const Bank *b, uint64_t number)
{
    if (!b->n_acc) return NULL;
    return bsearch(&number, b->acc, b->n_acc, sizeof(Account), cmp_acc_key);
}

static uint32_t bank_crc(const Bank *b)
{
    uint32_t crc = 0;
    crc = crc32_update(crc, b->acc, b->n_acc * sizeof(Account));
    crc = crc32_update(crc, b->txn, b->n_txn * sizeof(Txn));
    crc = crc32_update(crc, b->loan, b->n_loan * sizeof(Loan));
    crc = crc32_update(crc, b->fd, b->n_fd * sizeof(Fd));
    return crc;
}

static bool copy_file(const char *src, const char *dst)
{
    FILE *in = fopen(src, "rb");
    if (!in) return false;
    FILE *out = fopen(dst, "wb");
    if (!out) { fclose(in); return false; }
    char buf[8192];
    size_t n;
    bool ok = true;
    while ((n = fread(buf, 1, sizeof buf, in)) > 0)
        if (fwrite(buf, 1, n, out) != n) { ok = false; break; }
    fclose(in);
    if (fclose(out) != 0) ok = false;
    return ok;
}

static bool bank_save(Bank *b, const char *path)
{
    char tmp[1100], bak[1100];
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    snprintf(bak, sizeof bak, "%s.bak", path);
    if (access(path, F_OK) == 0) (void)copy_file(path, bak);

    FileHeader h;
    memset(&h, 0, sizeof h);
    memcpy(h.magic, FILE_MAGIC, sizeof FILE_MAGIC);
    h.version = FILE_VERSION;
    h.crc = bank_crc(b);
    h.n_acc = (uint32_t)b->n_acc; h.n_txn = (uint32_t)b->n_txn;
    h.n_loan = (uint32_t)b->n_loan; h.n_fd = (uint32_t)b->n_fd;
    h.next_acc_seq = b->next_acc_seq; h.next_txn_id = b->next_txn_id;
    h.next_loan_id = b->next_loan_id; h.next_fd_id = b->next_fd_id;
    h.offset_days = b->offset_days; h.last_interest_ym = b->last_interest_ym;
    memcpy(h.admin_salt, b->admin_salt, 8);
    memcpy(h.admin_hash, b->admin_hash, 32);

    FILE *f = fopen(tmp, "wb");
    if (!f) return false;
    bool ok = fwrite(&h, sizeof h, 1, f) == 1;
    if (ok && b->n_acc)  ok = fwrite(b->acc,  sizeof(Account), b->n_acc,  f) == b->n_acc;
    if (ok && b->n_txn)  ok = fwrite(b->txn,  sizeof(Txn),     b->n_txn,  f) == b->n_txn;
    if (ok && b->n_loan) ok = fwrite(b->loan, sizeof(Loan),    b->n_loan, f) == b->n_loan;
    if (ok && b->n_fd)   ok = fwrite(b->fd,   sizeof(Fd),      b->n_fd,   f) == b->n_fd;
    if (ok) ok = fflush(f) == 0 && fsync(fileno(f)) == 0;
    if (fclose(f) != 0) ok = false;
#ifdef _WIN32
    if (ok) ok = MoveFileExA(tmp, path, MOVEFILE_REPLACE_EXISTING) != 0;
#else
    if (ok) ok = rename(tmp, path) == 0;
#endif
    if (!ok) remove(tmp); else b->dirty = false;
    return ok;
}

typedef enum { LOAD_OK, LOAD_NEW, LOAD_ERR } LoadResult;

static bool read_array(FILE *f, void **arr, size_t *n, size_t *cap, size_t count, size_t elem)
{
    *arr = xrealloc(NULL, (count ? count : 1) * elem);
    *n = 0;
    *cap = count ? count : 1;
    if (count && fread(*arr, elem, count, f) != count) return false;
    *n = count;
    return true;
}

static LoadResult bank_load(Bank *b, const char *path, char *err, size_t errsz)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        if (errno == ENOENT) return LOAD_NEW;
        snprintf(err, errsz, "cannot open '%s': %s", path, strerror(errno));
        return LOAD_ERR;
    }
    FileHeader h;
    Bank t;
    bank_init(&t);
    if (fread(&h, sizeof h, 1, f) != 1) { snprintf(err, errsz, "file truncated (header)"); goto fail; }
    if (memcmp(h.magic, FILE_MAGIC, sizeof FILE_MAGIC) != 0) { snprintf(err, errsz, "not a bank data file"); goto fail; }
    if (h.version != FILE_VERSION) { snprintf(err, errsz, "unsupported version %u", h.version); goto fail; }
    if (h.n_acc > MAX_RECORDS || h.n_txn > MAX_RECORDS || h.n_loan > MAX_RECORDS || h.n_fd > MAX_RECORDS) {
        snprintf(err, errsz, "implausible record counts");
        goto fail;
    }
    if (!read_array(f, (void **)&t.acc, &t.n_acc, &t.cap_acc, h.n_acc, sizeof(Account)) ||
        !read_array(f, (void **)&t.txn, &t.n_txn, &t.cap_txn, h.n_txn, sizeof(Txn)) ||
        !read_array(f, (void **)&t.loan, &t.n_loan, &t.cap_loan, h.n_loan, sizeof(Loan)) ||
        !read_array(f, (void **)&t.fd, &t.n_fd, &t.cap_fd, h.n_fd, sizeof(Fd))) {
        snprintf(err, errsz, "file truncated (records)");
        goto fail;
    }
    if (bank_crc(&t) != h.crc) { snprintf(err, errsz, "checksum mismatch - data is corrupted"); goto fail; }

    for (size_t i = 0; i < t.n_acc; i++) {
        Account *a = &t.acc[i];
        a->name[NAME_LEN - 1] = '\0';
        a->phone[PHONE_LEN - 1] = '\0';
        if (!account_number_valid(a->number) || a->type >= ACC_TYPE_COUNT || a->status > ST_CLOSED ||
            (i > 0 && a->number <= t.acc[i - 1].number)) {
            snprintf(err, errsz, "account record %zu failed validation", i + 1);
            goto fail;
        }
    }
    for (size_t i = 0; i < t.n_txn; i++) {
        t.txn[i].note[NOTE_LEN - 1] = '\0';
        if (t.txn[i].type >= TX_TYPE_COUNT) { snprintf(err, errsz, "ledger entry %zu invalid", i + 1); goto fail; }
    }
    for (size_t i = 0; i < t.n_loan; i++)
        if (t.loan[i].status > LN_REJECTED) { snprintf(err, errsz, "loan record %zu invalid", i + 1); goto fail; }
    for (size_t i = 0; i < t.n_fd; i++)
        if (t.fd[i].status > FD_BROKEN) { snprintf(err, errsz, "deposit record %zu invalid", i + 1); goto fail; }

    fclose(f);
    bank_free(b);
    *b = t;
    b->next_acc_seq = h.next_acc_seq; b->next_txn_id = h.next_txn_id;
    b->next_loan_id = h.next_loan_id; b->next_fd_id = h.next_fd_id;
    b->offset_days = h.offset_days; b->last_interest_ym = h.last_interest_ym;
    memcpy(b->admin_salt, h.admin_salt, 8);
    memcpy(b->admin_hash, h.admin_hash, 32);
    b->dirty = false;
    g_offset_days = b->offset_days;
    return LOAD_OK;

fail:
    fclose(f);
    bank_free(&t);
    return LOAD_ERR;
}

static void persist(Bank *b)
{
    if (b->dirty && !bank_save(b, g_data_path))
        ERR("CRITICAL: could not save data to '%s': %s", g_data_path, strerror(errno));
}

/* ------------------------------------------------------------------------- */
/*  Core banking operations                                                  */
/* ------------------------------------------------------------------------- */

static const AccTypeInfo *info_of(const Account *a) { return &ACC_INFO[a->type]; }

static Txn *post_txn(Bank *b, Account *a, TxType type, int64_t delta, uint64_t counterparty, const char *note)
{
    a->balance += delta;
    Txn t;
    memset(&t, 0, sizeof t);
    t.id = b->next_txn_id++;
    t.timestamp = now_ts();
    t.account = a->number;
    t.counterparty = counterparty;
    t.amount = delta;
    t.balance_after = a->balance;
    t.type = (uint8_t)type;
    str_copy(t.note, sizeof t.note, note ? note : "");
    b->dirty = true;
    return array_push((void **)&b->txn, &b->n_txn, &b->cap_txn, sizeof(Txn), &t);
}

static void roll_limits(Account *a)
{
    uint32_t today = (uint32_t)ymd_of(now_ts());
    if (a->limit_day != today) { a->limit_day = today; a->withdrawn_today = 0; a->transferred_today = 0; }
}

static const char *check_debit(const Account *a, int64_t amt)
{
    if (a->status == ST_FROZEN) return "Account is frozen: debits are blocked.";
    if (a->status != ST_ACTIVE) return "Account is not active.";
    if (a->balance - amt < info_of(a)->floor)
        return a->type == ACC_SAVINGS ? "Insufficient funds (minimum balance must be maintained)."
                                      : "Insufficient funds (overdraft limit exceeded).";
    return NULL;
}

static const char *limit_msg(const char *what, int64_t limit, int64_t used)
{
    static char msg[160];
    snprintf(msg, sizeof msg, "Daily %s limit exceeded. Remaining today: %s %s.", what, CURRENCY,
             fmt_money(limit > used ? limit - used : 0));
    return msg;
}

static const char *op_deposit(Bank *b, Account *a, int64_t amt, Txn **out)
{
    if (a->status == ST_CLOSED) return "Account is closed.";
    if (amt > MAX_DEPOSIT) return "Single deposit limit exceeded.";
    Txn *t = post_txn(b, a, TX_DEPOSIT, amt, 0, "Cash deposit");
    if (amt >= LARGE_DEPOSIT)
        audit("SYSTEM", "LARGE DEPOSIT %s %s to account %" PRIu64, CURRENCY, fmt_money(amt), a->number);
    *out = t;
    return NULL;
}

static const char *op_withdraw(Bank *b, Account *a, int64_t amt, Txn **out)
{
    const char *e = check_debit(a, amt);
    if (e) return e;
    roll_limits(a);
    if (a->withdrawn_today + amt > info_of(a)->withdraw_limit)
        return limit_msg("withdrawal", info_of(a)->withdraw_limit, a->withdrawn_today);
    a->withdrawn_today += amt;
    *out = post_txn(b, a, TX_WITHDRAW, -amt, 0, "Cash withdrawal");
    return NULL;
}

static const char *op_transfer(Bank *b, Account *from, Account *to, int64_t amt, const char *note, Txn **out)
{
    if (from == to) return "Cannot transfer to the same account.";
    if (to->status != ST_ACTIVE) return "Beneficiary account cannot receive funds.";
    const char *e = check_debit(from, amt);
    if (e) return e;
    roll_limits(from);
    if (from->transferred_today + amt > info_of(from)->transfer_limit)
        return limit_msg("transfer", info_of(from)->transfer_limit, from->transferred_today);
    from->transferred_today += amt;
    *out = post_txn(b, from, TX_TRANSFER_OUT, -amt, to->number, note);
    post_txn(b, to, TX_TRANSFER_IN, amt, from->number, note);
    /* post_txn may relocate the ledger; *out must be re-resolved. */
    *out = &b->txn[b->n_txn - 2];
    return NULL;
}

static void print_receipt(const Txn *t)
{
    puts("\n  +----------------------------------------------+");
    printf("  |  %sTRANSACTION RECEIPT%s                          |\n", CLR(C_BOLD), CLR(C_RESET));
    puts("  +----------------------------------------------+");
    printf("   Txn ID     : %" PRIu64 "\n", t->id);
    printf("   Date       : %s\n", fmt_datetime(t->timestamp));
    printf("   Account    : %s\n", mask_acct(t->account));
    printf("   Type       : %s\n", TX_NAMES[t->type]);
    if (t->counterparty) printf("   Counterparty: %s\n", mask_acct(t->counterparty));
    printf("   Amount     : %s %s\n", CURRENCY, fmt_money(t->amount < 0 ? -t->amount : t->amount));
    printf("   Balance    : %s %s\n", CURRENCY, fmt_money(t->balance_after));
    if (t->note[0]) printf("   Note       : %s\n", t->note);
    puts("  +----------------------------------------------+");
}

/* ----- Fixed deposits ----- */

static int64_t fd_maturity_amount(int64_t principal, uint32_t rate_bp, int months)
{
    double r = rate_bp / 10000.0 / 4.0;                  /* quarterly compounding */
    double v = (double)principal * pow(1.0 + r, months / 3.0);
    return (int64_t)(v + 0.5);
}

static int64_t fd_premature_payout(const Fd *d, int64_t now)
{
    int elapsed = (int)((now - d->opened_at) / (30 * DAY_SECONDS));
    if (elapsed < 0) elapsed = 0;
    if (elapsed > d->months) elapsed = d->months;
    uint32_t pen_rate = d->rate_bp > 100 ? d->rate_bp - 100 : 0; /* 1% penalty */
    int64_t interest = d->principal * (int64_t)pen_rate * elapsed / (10000 * 12);
    return d->principal + interest;
}

/* ----- Loans ----- */

static uint32_t loan_rate_bp(int tenor)
{
    if (tenor <= 12) return 1050;
    if (tenor <= 36) return 1150;
    if (tenor <= 60) return 1250;
    return 1350;
}

static int64_t calc_emi(int64_t principal, uint32_t rate_bp, int n)
{
    double r = rate_bp / 10000.0 / 12.0;
    double f = pow(1.0 + r, n);
    return (int64_t)ceil((double)principal * r * f / (f - 1.0) - 1e-9);
}

static int64_t month_interest(int64_t outstanding, uint32_t rate_bp)
{
    return (outstanding * (int64_t)rate_bp + 60000) / 120000;   /* rounded */
}

static Loan *find_open_loan(const Bank *b, uint64_t acc)
{
    for (size_t i = 0; i < b->n_loan; i++)
        if (b->loan[i].account == acc && (b->loan[i].status == LN_PENDING || b->loan[i].status == LN_ACTIVE))
            return &b->loan[i];
    return NULL;
}

static Loan *find_loan_by_id(const Bank *b, uint32_t id)
{
    for (size_t i = 0; i < b->n_loan; i++) if (b->loan[i].id == id) return &b->loan[i];
    return NULL;
}

static int active_fd_count(const Bank *b, uint64_t acc)
{
    int n = 0;
    for (size_t i = 0; i < b->n_fd; i++)
        if (b->fd[i].account == acc && b->fd[i].status == FD_ACTIVE) n++;
    return n;
}

/* ------------------------------------------------------------------------- */
/*  Statements                                                               */
/* ------------------------------------------------------------------------- */

static size_t collect_txns(const Bank *b, uint64_t acc, int from, int to, const Txn ***out)
{
    const Txn **arr = xrealloc(NULL, (b->n_txn ? b->n_txn : 1) * sizeof *arr);
    size_t n = 0;
    for (size_t i = 0; i < b->n_txn; i++) {
        const Txn *t = &b->txn[i];
        if (t->account != acc) continue;
        int d = ymd_of(t->timestamp);
        if (d >= from && d <= to) arr[n++] = t;
    }
    *out = arr;
    return n;
}

static void print_statement(const Account *a, const Txn **arr, size_t n, size_t last_n)
{
    printf("\n%sSTATEMENT - %s  (%s, %s)%s\n", CLR(C_BOLD), mask_acct(a->number), a->name,
           ACC_INFO[a->type].name, CLR(C_RESET));
    if (n == 0) { puts("No transactions found for this period."); return; }
    size_t start = (last_n && n > last_n) ? n - last_n : 0;
    puts("------------------------------------------------------------------------------------------");
    printf("%-16s %-7s %-13s %-10s %14s %14s  %s\n", "Date", "TxnID", "Type", "Counterp.", "Amount", "Balance", "Note");
    puts("------------------------------------------------------------------------------------------");
    printf("%-16s %-7s %-13s %-10s %14s %14s\n", "", "", "Opening balance", "", "",
           fmt_money(arr[start]->balance_after - arr[start]->amount));
    int64_t credits = 0, debits = 0;
    for (size_t i = start; i < n; i++) {
        const Txn *t = arr[i];
        printf("%-16s %-7" PRIu64 " %-13s %-10s %14s %14s  %s\n", fmt_datetime(t->timestamp), t->id, TX_NAMES[t->type],
               t->counterparty ? mask_acct(t->counterparty) : "-", fmt_money(t->amount), fmt_money(t->balance_after), t->note);
        if (t->amount > 0) credits += t->amount; else debits += -t->amount;
    }
    puts("------------------------------------------------------------------------------------------");
    printf("Total credits: %s %s   Total debits: %s %s   Closing balance: %s %s\n", CURRENCY, fmt_money(credits),
           CURRENCY, fmt_money(debits), CURRENCY, fmt_money(arr[n - 1]->balance_after));
}

static void export_statement_csv(const Account *a, const Txn **arr, size_t n)
{
    char path[128];
    snprintf(path, sizeof path, "statement_%" PRIu64 ".csv", a->number);
    FILE *f = fopen(path, "w");
    if (!f) { ERR("  Cannot write %s: %s", path, strerror(errno)); return; }
    fputs("txn_id,datetime,type,counterparty,amount,balance_after,note\n", f);
    for (size_t i = 0; i < n; i++) {
        const Txn *t = arr[i];
        fprintf(f, "%" PRIu64 ",%s,%s,%" PRIu64 ",%s,%s,\"", t->id, fmt_datetime(t->timestamp), TX_NAMES[t->type],
                t->counterparty, fmt_money(t->amount), fmt_money(t->balance_after));
        for (const char *p = t->note; *p; p++) { if (*p == '"') fputc('"', f); fputc(*p, f); }
        fputs("\"\n", f);
    }
    fclose(f);
    OK("  Exported %zu row(s) to %s", n, path);
}

static void statement_dialog(const Bank *b, const Account *a)
{
    char buf[32];
    int from = 0, to = 99999999;
    if (!read_line("From date (YYYY-MM-DD, Enter = beginning): ", buf, sizeof buf)) return;
    if (buf[0] && !parse_date(buf, &from)) { ERR("  Invalid date."); return; }
    if (!read_line("To date   (YYYY-MM-DD, Enter = today): ", buf, sizeof buf)) return;
    if (buf[0] && !parse_date(buf, &to)) { ERR("  Invalid date."); return; }
    const Txn **arr;
    size_t n = collect_txns(b, a->number, from, to, &arr);
    print_statement(a, arr, n, 0);
    if (n && prompt_yesno("Export this statement to CSV?", false)) export_statement_csv(a, arr, n);
    free(arr);
}

/* ------------------------------------------------------------------------- */
/*  Display helpers                                                          */
/* ------------------------------------------------------------------------- */

static void print_rule(char c)
{
    for (int i = 0; i < 80; i++) putchar(c);
    putchar('\n');
}

static void print_title(const char *t)
{
    printf("\n%s%s%s\n", CLR(C_BOLD), t, CLR(C_RESET));
    print_rule('=');
}

static int64_t available_funds(const Account *a) { return a->balance - info_of(a)->floor; }

static void show_account(const Bank *b, const Account *a, bool full_number)
{
    Account tmp = *a;
    roll_limits(&tmp);
    print_title("ACCOUNT DETAILS");
    printf("Account No.   : ");
    if (full_number) printf("%" PRIu64 "\n", a->number); else printf("%s\n", mask_acct(a->number));
    printf("Holder        : %s\n", a->name);
    printf("Phone         : %s\n", a->phone);
    printf("Type          : %s\n", info_of(a)->name);
    printf("Status        : %s\n", STATUS_NAMES[a->status]);
    printf("Opened        : %s\n", fmt_date_ts(a->created));
    printf("Balance       : %s %s\n", CURRENCY, fmt_money(a->balance));
    printf("Available     : %s %s\n", CURRENCY, fmt_money(available_funds(a) > 0 ? available_funds(a) : 0));
    if (a->type == ACC_SAVINGS)
        printf("Interest rate : %s p.a. (min balance %s %s)\n", fmt_rate(info_of(a)->rate_bp), CURRENCY, fmt_money(info_of(a)->floor));
    else
        printf("Overdraft     : %s %s\n", CURRENCY, fmt_money(-info_of(a)->floor));
    printf("Withdraw left : %s %s / day\n", CURRENCY, fmt_money(info_of(a)->withdraw_limit - tmp.withdrawn_today));
    printf("Transfer left : %s %s / day\n", CURRENCY, fmt_money(info_of(a)->transfer_limit - tmp.transferred_today));
    printf("Fixed deposits: %d active\n", active_fd_count(b, a->number));
    Loan *l = find_open_loan(b, a->number);
    if (l) printf("Loan          : #%u %s, outstanding %s %s\n", l->id, LOAN_STATUS_NAMES[l->status], CURRENCY,
                  fmt_money(l->status == LN_PENDING ? l->principal : l->outstanding));
}

/* ------------------------------------------------------------------------- */
/*  Customer features                                                        */
/* ------------------------------------------------------------------------- */

static bool verify_pin(const Account *a, const char *pin)
{
    uint8_t h[32];
    hash_secret(a->salt, pin, h);
    return ct_equal(h, a->pin_hash, 32);
}

static void set_pin(Account *a, const char *pin)
{
    random_bytes(a->salt, sizeof a->salt);
    hash_secret(a->salt, pin, a->pin_hash);
}

static bool reauth(const Account *a)
{
    char pin[32];
    if (!read_secret("Re-enter your PIN to authorise: ", pin, sizeof pin)) return false;
    if (!verify_pin(a, pin)) { ERR("  Incorrect PIN. Operation cancelled."); return false; }
    return true;
}

static bool change_pin_flow(Bank *b, Account *a, bool require_current)
{
    char cur[32], p1[32], p2[32];
    if (require_current) {
        if (!read_secret("Current PIN: ", cur, sizeof cur)) return false;
        if (!verify_pin(a, cur)) { ERR("  Incorrect PIN."); return false; }
    }
    puts("PIN rules: 4-6 digits, not all identical, not sequential (e.g. 1234).");
    if (!read_secret("New PIN: ", p1, sizeof p1)) return false;
    if (!pin_strong(p1)) { ERR("  PIN is too weak or malformed."); return false; }
    if (!read_secret("Confirm new PIN: ", p2, sizeof p2)) return false;
    if (strcmp(p1, p2) != 0) { ERR("  PINs do not match."); return false; }
    set_pin(a, p1);
    a->pin_temp = 0;
    b->dirty = true;
    audit("CUSTOMER", "PIN changed for account %" PRIu64, a->number);
    OK("  PIN changed successfully.");
    return true;
}

static void cust_deposit(Bank *b, Account *a)
{
    int64_t amt;
    if (!prompt_amount("Deposit amount", 1, MAX_AMOUNT, &amt)) return;
    Txn *t;
    const char *e = op_deposit(b, a, amt, &t);
    if (e) ERR("  %s", e); else { OK("  Deposit successful."); print_receipt(t); }
}

static void cust_withdraw(Bank *b, Account *a)
{
    int64_t amt;
    if (!prompt_amount("Withdrawal amount", 1, MAX_AMOUNT, &amt)) return;
    Txn *t;
    const char *e = op_withdraw(b, a, amt, &t);
    if (e) ERR("  %s", e); else { OK("  Please collect your cash."); print_receipt(t); }
}

static void cust_transfer(Bank *b, Account *a)
{
    uint64_t to_no;
    if (!prompt_account_number("Beneficiary account number: ", &to_no)) return;
    Account *to = find_account(b, to_no);
    if (!to || to->status == ST_CLOSED) { ERR("  Beneficiary account not found."); return; }
    char first[NAME_LEN];
    str_copy(first, sizeof first, to->name);
    char *sp = strchr(first, ' ');
    if (sp) *sp = '\0';
    printf("  Beneficiary: %s *** (%s)\n", first, mask_acct(to->number));
    int64_t amt;
    if (!prompt_amount("Transfer amount", 1, MAX_AMOUNT, &amt)) return;
    char note[NOTE_LEN + 8];
    if (!read_line("Remark (optional, max 31 chars): ", note, sizeof note)) return;
    for (char *p = note; *p; p++) if ((unsigned char)*p < 32) *p = ' ';
    printf("  You are sending %s %s to %s ***.\n", CURRENCY, fmt_money(amt), first);
    if (!prompt_yesno("Confirm transfer?", false)) { puts("  Cancelled."); return; }
    if (!reauth(a)) return;
    Txn *t;
    const char *e = op_transfer(b, a, to, amt, note, &t);
    if (e) { ERR("  %s", e); return; }
    audit("CUSTOMER", "TRANSFER %s %s from %" PRIu64 " to %" PRIu64, CURRENCY, fmt_money(amt), a->number, to_no);
    OK("  Transfer successful.");
    print_receipt(t);
}

static void cust_fd_menu(Bank *b, Account *a)
{
    for (;;) {
        print_title("FIXED DEPOSITS");
        puts("1) Open a fixed deposit\n2) View my deposits\n3) Close a deposit\n0) Back");
        char buf[32];
        if (!read_line("Choice: ", buf, sizeof buf) || strcmp(buf, "0") == 0) return;
        if (strcmp(buf, "1") == 0) {
            puts("\nAvailable terms:");
            for (int i = 0; i < FD_RATE_COUNT; i++)
                printf("  %d) %2d months @ %s p.a.\n", i + 1, FD_RATES[i].months, fmt_rate(FD_RATES[i].rate_bp));
            if (!read_line("Choose term: ", buf, sizeof buf)) return;
            int idx = atoi(buf) - 1;
            if (idx < 0 || idx >= FD_RATE_COUNT) { ERR("  Invalid choice."); continue; }
            int64_t amt;
            if (!prompt_amount("Deposit amount", FD_MIN_AMOUNT, MAX_AMOUNT, &amt)) continue;
            int64_t mat = fd_maturity_amount(amt, FD_RATES[idx].rate_bp, FD_RATES[idx].months);
            printf("  Maturity value: %s %s (interest %s)\n", CURRENCY, fmt_money(mat), fmt_money(mat - amt));
            if (!prompt_yesno("Open this deposit?", true)) continue;
            const char *e = check_debit(a, amt);
            if (e) { ERR("  %s", e); continue; }
            Fd d;
            memset(&d, 0, sizeof d);
            d.id = b->next_fd_id++;
            d.status = FD_ACTIVE;
            d.account = a->number;
            d.principal = amt;
            d.rate_bp = FD_RATES[idx].rate_bp;
            d.months = (uint16_t)FD_RATES[idx].months;
            d.opened_at = now_ts();
            d.maturity_at = d.opened_at + (int64_t)d.months * 30 * DAY_SECONDS;
            array_push((void **)&b->fd, &b->n_fd, &b->cap_fd, sizeof(Fd), &d);
            char note[NOTE_LEN];
            snprintf(note, sizeof note, "FD #%u opened", d.id);
            Txn *t = post_txn(b, a, TX_FD_OPEN, -amt, 0, note);
            audit("CUSTOMER", "FD #%u opened on %" PRIu64 " for %s", d.id, a->number, fmt_money(amt));
            OK("  Fixed deposit #%u opened.", d.id);
            print_receipt(t);
        } else if (strcmp(buf, "2") == 0) {
            bool any = false;
            printf("\n%-5s %-14s %-7s %-6s %-11s %-11s %-8s %14s\n", "ID", "Principal", "Rate", "Term", "Opened", "Matures", "Status", "Maturity value");
            print_rule('-');
            for (size_t i = 0; i < b->n_fd; i++) {
                const Fd *d = &b->fd[i];
                if (d->account != a->number) continue;
                any = true;
                printf("%-5u %-14s %-7s %-3dmo  %-11s %-11s %-8s %14s\n", d->id, fmt_money(d->principal), fmt_rate(d->rate_bp),
                       d->months, fmt_date_ts(d->opened_at), fmt_date_ts(d->maturity_at), FD_STATUS_NAMES[d->status],
                       fmt_money(fd_maturity_amount(d->principal, d->rate_bp, d->months)));
            }
            if (!any) puts("You have no fixed deposits.");
        } else if (strcmp(buf, "3") == 0) {
            if (!read_line("Deposit ID to close: ", buf, sizeof buf)) return;
            uint32_t id = (uint32_t)strtoul(buf, NULL, 10);
            Fd *d = NULL;
            for (size_t i = 0; i < b->n_fd; i++)
                if (b->fd[i].id == id && b->fd[i].account == a->number && b->fd[i].status == FD_ACTIVE) d = &b->fd[i];
            if (!d) { ERR("  No active deposit with that ID."); continue; }
            bool mature = now_ts() >= d->maturity_at;
            int64_t payout = mature ? fd_maturity_amount(d->principal, d->rate_bp, d->months) : fd_premature_payout(d, now_ts());
            if (mature) printf("  Deposit has matured. Payout: %s %s\n", CURRENCY, fmt_money(payout));
            else WARN("  PREMATURE CLOSURE: 1%% rate penalty applies. Payout: %s %s (vs %s at maturity).", CURRENCY,
                      fmt_money(payout), fmt_money(fd_maturity_amount(d->principal, d->rate_bp, d->months)));
            if (a->status == ST_CLOSED) { ERR("  Account closed."); continue; }
            if (!prompt_yesno("Proceed?", false)) continue;
            d->status = mature ? FD_MATURED : FD_BROKEN;
            char note[NOTE_LEN];
            snprintf(note, sizeof note, "FD #%u payout", d->id);
            Txn *t = post_txn(b, a, TX_FD_CLOSE, payout, 0, note);
            audit("CUSTOMER", "FD #%u closed (%s) payout %s", d->id, mature ? "matured" : "premature", fmt_money(payout));
            OK("  Deposit closed.");
            print_receipt(t);
        }
        persist(b);
    }
}

static void print_schedule(const Loan *l)
{
    int64_t out = l->outstanding;
    printf("\n%-6s %14s %14s %14s %14s\n", "EMI #", "Payment", "Interest", "Principal", "Balance");
    print_rule('-');
    for (int m = l->paid + 1; m <= l->tenor && out > 0; m++) {
        int64_t interest = month_interest(out, l->rate_bp);
        int64_t pay = l->emi;
        if (m == l->tenor || pay >= out + interest) pay = out + interest;
        int64_t princ = pay - interest;
        out -= princ;
        printf("%-6d %14s %14s %14s %14s\n", m, fmt_money(pay), fmt_money(interest), fmt_money(princ), fmt_money(out));
    }
}

static void cust_loan_menu(Bank *b, Account *a)
{
    for (;;) {
        print_title("LOANS");
        puts("1) Apply for a loan\n2) View my loan\n3) Pay EMI\n4) Repayment schedule\n5) Foreclose (pay off in full)\n0) Back");
        char buf[32];
        if (!read_line("Choice: ", buf, sizeof buf) || strcmp(buf, "0") == 0) return;
        Loan *l = find_open_loan(b, a->number);

        if (strcmp(buf, "1") == 0) {
            if (l) { ERR("  You already have a pending or active loan."); continue; }
            if (a->status != ST_ACTIVE) { ERR("  Account must be active."); continue; }
            int64_t p;
            printf("Loan amount between %s and %s.\n", fmt_money(LOAN_MIN), fmt_money(LOAN_MAX));
            if (!prompt_amount("Loan amount", LOAN_MIN, LOAN_MAX, &p)) continue;
            if (!read_line("Tenor in months (6-84): ", buf, sizeof buf)) return;
            int n = atoi(buf);
            if (n < 6 || n > 84) { ERR("  Tenor must be 6-84 months."); continue; }
            uint32_t rate = loan_rate_bp(n);
            int64_t emi = calc_emi(p, rate, n);
            int64_t fee = p / 100;
            if (fee < LOAN_FEE_MIN) fee = LOAN_FEE_MIN;
            if (fee > LOAN_FEE_MAX) fee = LOAN_FEE_MAX;
            printf("\n  Rate           : %s p.a. (reducing balance)\n", fmt_rate(rate));
            printf("  Monthly EMI    : %s %s\n", CURRENCY, fmt_money(emi));
            printf("  Total interest : %s %s (approx.)\n", CURRENCY, fmt_money(emi * n - p));
            printf("  Processing fee : %s %s (deducted at disbursal)\n", CURRENCY, fmt_money(fee));
            if (!prompt_yesno("Submit application?", true)) continue;
            Loan ln;
            memset(&ln, 0, sizeof ln);
            ln.id = b->next_loan_id++;
            ln.status = LN_PENDING;
            ln.account = a->number;
            ln.principal = ln.outstanding = p;
            ln.emi = emi;
            ln.rate_bp = rate;
            ln.tenor = (uint16_t)n;
            ln.applied_at = now_ts();
            array_push((void **)&b->loan, &b->n_loan, &b->cap_loan, sizeof(Loan), &ln);
            b->dirty = true;
            audit("CUSTOMER", "Loan #%u applied: %s for %d months by %" PRIu64, ln.id, fmt_money(p), n, a->number);
            OK("  Application #%u submitted. The bank will review it shortly.", ln.id);
        } else if (!l) {
            puts("  You have no pending or active loan.");
        } else if (strcmp(buf, "2") == 0) {
            printf("\nLoan #%u   Status: %s\n", l->id, LOAN_STATUS_NAMES[l->status]);
            printf("Principal   : %s %s\nRate        : %s p.a.\nTenor       : %u months (%u paid)\nEMI         : %s %s\n",
                   CURRENCY, fmt_money(l->principal), fmt_rate(l->rate_bp), l->tenor, l->paid, CURRENCY, fmt_money(l->emi));
            if (l->status == LN_ACTIVE) printf("Outstanding : %s %s\n", CURRENCY, fmt_money(l->outstanding));
        } else if (l->status != LN_ACTIVE) {
            puts("  Your loan is awaiting approval.");
        } else if (strcmp(buf, "3") == 0) {
            int64_t interest = month_interest(l->outstanding, l->rate_bp);
            int64_t pay = l->emi;
            if (l->paid + 1 >= l->tenor || pay >= l->outstanding + interest) pay = l->outstanding + interest;
            printf("  EMI %u of %u: %s %s (interest %s, principal %s)\n", l->paid + 1, l->tenor, CURRENCY, fmt_money(pay),
                   fmt_money(interest), fmt_money(pay - interest));
            const char *e = check_debit(a, pay);
            if (e) { ERR("  %s", e); continue; }
            if (!prompt_yesno("Pay now?", true)) continue;
            l->outstanding -= pay - interest;
            l->paid++;
            char note[NOTE_LEN];
            snprintf(note, sizeof note, "Loan #%u EMI %u/%u", l->id, l->paid, l->tenor);
            Txn *t = post_txn(b, a, TX_EMI, -pay, 0, note);
            if (l->outstanding <= 0) { l->outstanding = 0; l->status = LN_CLOSED; OK("  Congratulations - your loan is fully repaid!"); }
            audit("CUSTOMER", "Loan #%u EMI %u/%u paid", l->id, l->paid, l->tenor);
            print_receipt(t);
        } else if (strcmp(buf, "4") == 0) {
            print_schedule(l);
        } else if (strcmp(buf, "5") == 0) {
            int64_t pay = l->outstanding + month_interest(l->outstanding, l->rate_bp);
            printf("  Foreclosure amount (outstanding + this month's interest): %s %s\n", CURRENCY, fmt_money(pay));
            const char *e = check_debit(a, pay);
            if (e) { ERR("  %s", e); continue; }
            if (!prompt_yesno("Pay off the loan in full?", false)) continue;
            if (!reauth(a)) continue;
            char note[NOTE_LEN];
            snprintf(note, sizeof note, "Loan #%u payoff", l->id);
            Txn *t = post_txn(b, a, TX_LOAN_CLOSE, -pay, 0, note);
            l->outstanding = 0;
            l->status = LN_CLOSED;
            audit("CUSTOMER", "Loan #%u foreclosed", l->id);
            OK("  Loan closed.");
            print_receipt(t);
        }
        persist(b);
    }
}

static void customer_session(Bank *b, Account *a)
{
    if (a->pin_temp) {
        WARN("\nYou are using a temporary PIN. You must set a new PIN to continue.");
        while (!change_pin_flow(b, a, false)) {
            if (!prompt_yesno("Try again?", true)) { persist(b); return; }
        }
        persist(b);
    }
    for (;;) {
        printf("\n%sWelcome, %s%s   [%s | %s]\n", CLR(C_BOLD), a->name, CLR(C_RESET), mask_acct(a->number), info_of(a)->name);
        print_rule('=');
        puts(" 1) Account info & balance     6) Full statement / export");
        puts(" 2) Deposit                    7) Fixed deposits");
        puts(" 3) Withdraw                   8) Loans");
        puts(" 4) Transfer                   9) Change PIN");
        puts(" 5) Mini statement (last 10)   0) Logout");
        char buf[16];
        if (!read_line("\nSelect: ", buf, sizeof buf)) return;
        switch (atoi(buf)) {
        case 1: show_account(b, a, false); break;
        case 2: cust_deposit(b, a); break;
        case 3: cust_withdraw(b, a); break;
        case 4: cust_transfer(b, a); break;
        case 5: {
            const Txn **arr;
            size_t n = collect_txns(b, a->number, 0, 99999999, &arr);
            print_statement(a, arr, n, 10);
            free(arr);
            break;
        }
        case 6: statement_dialog(b, a); break;
        case 7: cust_fd_menu(b, a); break;
        case 8: cust_loan_menu(b, a); break;
        case 9: change_pin_flow(b, a, true); break;
        case 0: persist(b); audit("CUSTOMER", "Logout %" PRIu64, a->number); return;
        default: ERR("Unknown option.");
        }
        persist(b);
    }
}

static void customer_login(Bank *b)
{
    print_title("CUSTOMER LOGIN");
    char buf[32], pin[32];
    uint64_t no;
    if (!prompt_account_number("Account number: ", &no)) return;
    if (!read_secret("PIN: ", pin, sizeof pin)) return;
    Account *a = find_account(b, no);
    if (!a || a->status == ST_CLOSED) { ERR("Invalid account number or PIN."); return; }
    if (a->status == ST_LOCKED) { ERR("This account is locked. Please contact the bank."); return; }
    if (!verify_pin(a, pin)) {
        a->failed_attempts++;
        audit("SECURITY", "Failed login for %" PRIu64 " (attempt %u)", no, a->failed_attempts);
        if (a->failed_attempts >= LOCK_THRESHOLD) {
            a->status = ST_LOCKED;
            audit("SECURITY", "Account %" PRIu64 " LOCKED after repeated failures", no);
            ERR("Too many failed attempts. Account locked.");
        } else {
            ERR("Invalid account number or PIN. %d attempt(s) left.", LOCK_THRESHOLD - a->failed_attempts);
        }
        b->dirty = true;
        persist(b);
        if (isatty(STDIN_FILENO)) sleep_sec(1);
        return;
    }
    (void)buf;
    a->failed_attempts = 0;
    b->dirty = true;
    audit("CUSTOMER", "Login %" PRIu64, no);
    persist(b);
    customer_session(b, a);
}

/* ------------------------------------------------------------------------- */
/*  Admin features                                                           */
/* ------------------------------------------------------------------------- */

static void admin_open_account(Bank *b)
{
    print_title("OPEN NEW ACCOUNT");
    char name[NAME_LEN + 8], phone[32];
    if (!read_line("Customer full name: ", name, sizeof name) || is_cancel(name)) return;
    if (!valid_name(name)) { ERR("  Invalid name (letters, spaces, . ' - ; 2-47 chars)."); return; }
    if (!read_line("Mobile number (10 digits): ", phone, sizeof phone) || is_cancel(phone)) return;
    if (!valid_phone(phone)) { ERR("  Invalid mobile number."); return; }
    const char *names[ACC_TYPE_COUNT];
    for (int i = 0; i < ACC_TYPE_COUNT; i++) names[i] = ACC_INFO[i].name;
    int type;
    if (!prompt_choice("Account type:", names, ACC_TYPE_COUNT, &type)) return;
    int64_t dep;
    printf("Minimum opening deposit for %s: %s %s\n", names[type], CURRENCY, fmt_money(ACC_INFO[type].min_open));
    if (!prompt_amount("Opening deposit", ACC_INFO[type].min_open, MAX_DEPOSIT, &dep)) return;

    Account a;
    memset(&a, 0, sizeof a);
    uint64_t seq = b->next_acc_seq++;
    a.number = seq * 10 + (uint64_t)luhn_check_digit(seq);
    a.type = (uint8_t)type;
    a.status = ST_ACTIVE;
    a.pin_temp = 1;
    a.created = now_ts();
    str_copy(a.name, sizeof a.name, name);
    str_copy(a.phone, sizeof a.phone, phone);
    char pin[8];
    make_temp_pin(pin);
    set_pin(&a, pin);
    Account *p = array_push((void **)&b->acc, &b->n_acc, &b->cap_acc, sizeof(Account), &a);
    post_txn(b, p, TX_OPENING, dep, 0, "Opening deposit");
    audit("ADMIN", "Opened %s account %" PRIu64 " for %s", names[type], p->number, name);

    OK("\n  Account created successfully!");
    printf("  Account Number : %" PRIu64 "\n  Holder         : %s\n  Type           : %s\n  Balance        : %s %s\n",
           p->number, p->name, names[type], CURRENCY, fmt_money(dep));
    WARN("  Temporary PIN  : %s   (shown once; customer must change it at first login)", pin);
}

static void list_accounts(const Bank *b, const char *filter)
{
    printf("\n%-12s %-24s %-8s %-8s %16s\n", "Account No.", "Holder", "Type", "Status", "Balance");
    print_rule('-');
    size_t n = 0;
    for (size_t i = 0; i < b->n_acc; i++) {
        const Account *a = &b->acc[i];
        char num[24];
        snprintf(num, sizeof num, "%" PRIu64, a->number);
        if (filter && *filter && !contains_ci(a->name, filter) && !contains_ci(a->phone, filter) && !contains_ci(num, filter))
            continue;
        printf("%-12" PRIu64 " %-24.24s %-8s %-8s %16s\n", a->number, a->name, info_of(a)->name, STATUS_NAMES[a->status],
               fmt_money(a->balance));
        n++;
    }
    if (!n) puts("No matching accounts.");
    else printf("%zu account(s)\n", n);
}

static Account *admin_pick_account(Bank *b, const char *label)
{
    uint64_t no;
    if (!prompt_account_number(label, &no)) return NULL;
    Account *a = find_account(b, no);
    if (!a) ERR("  Account not found.");
    return a;
}

static void admin_view_account(Bank *b)
{
    Account *a = admin_pick_account(b, "Account number: ");
    if (!a) return;
    show_account(b, a, true);
    if (prompt_yesno("Show transaction ledger?", true)) {
        const Txn **arr;
        size_t n = collect_txns(b, a->number, 0, 99999999, &arr);
        print_statement(a, arr, n, 25);
        if (n && prompt_yesno("Export full ledger to CSV?", false)) export_statement_csv(a, arr, n);
        free(arr);
    }
}

static void admin_freeze(Bank *b)
{
    Account *a = admin_pick_account(b, "Account number: ");
    if (!a) return;
    if (a->status == ST_ACTIVE) {
        if (!prompt_yesno("Freeze this account (blocks all debits)?", false)) return;
        a->status = ST_FROZEN;
        audit("ADMIN", "Froze account %" PRIu64, a->number);
        OK("  Account frozen.");
    } else if (a->status == ST_FROZEN) {
        a->status = ST_ACTIVE;
        audit("ADMIN", "Unfroze account %" PRIu64, a->number);
        OK("  Account unfrozen.");
    } else {
        ERR("  Only active or frozen accounts can be toggled (status: %s).", STATUS_NAMES[a->status]);
        return;
    }
    b->dirty = true;
}

static void admin_close(Bank *b)
{
    Account *a = admin_pick_account(b, "Account number to close: ");
    if (!a) return;
    if (a->status == ST_CLOSED) { ERR("  Already closed."); return; }
    if (a->balance != 0) { ERR("  Balance must be zero (current: %s %s). Withdraw or settle first.", CURRENCY, fmt_money(a->balance)); return; }
    if (find_open_loan(b, a->number)) { ERR("  Account has a pending/active loan."); return; }
    if (active_fd_count(b, a->number)) { ERR("  Account has active fixed deposits."); return; }
    if (!prompt_yesno("Permanently close this account?", false)) return;
    a->status = ST_CLOSED;
    b->dirty = true;
    audit("ADMIN", "Closed account %" PRIu64, a->number);
    OK("  Account closed.");
}

static void admin_reset_pin(Bank *b)
{
    Account *a = admin_pick_account(b, "Account number: ");
    if (!a || a->status == ST_CLOSED) return;
    if (!prompt_yesno("Issue a new temporary PIN and unlock the account?", false)) return;
    char pin[8];
    make_temp_pin(pin);
    set_pin(a, pin);
    a->pin_temp = 1;
    a->failed_attempts = 0;
    if (a->status == ST_LOCKED) a->status = ST_ACTIVE;
    b->dirty = true;
    audit("ADMIN", "Reset PIN for account %" PRIu64, a->number);
    OK("  PIN reset for %s.", a->name);
    WARN("  Temporary PIN: %s (shown once)", pin);
}

static void admin_review_loans(Bank *b)
{
    print_title("PENDING LOAN APPLICATIONS");
    printf("%-5s %-12s %-20s %14s %-6s %-8s %12s\n", "ID", "Account", "Applicant", "Amount", "Tenor", "Rate", "EMI");
    print_rule('-');
    size_t pending = 0;
    for (size_t i = 0; i < b->n_loan; i++) {
        const Loan *l = &b->loan[i];
        if (l->status != LN_PENDING) continue;
        const Account *a = find_account(b, l->account);
        printf("%-5u %-12" PRIu64 " %-20.20s %14s %-3umo  %-8s %12s\n", l->id, l->account, a ? a->name : "?",
               fmt_money(l->principal), l->tenor, fmt_rate(l->rate_bp), fmt_money(l->emi));
        pending++;
    }
    if (!pending) { puts("No pending applications."); return; }
    char buf[32];
    if (!read_line("\nLoan ID to review (Enter to go back): ", buf, sizeof buf) || !buf[0]) return;
    Loan *l = find_loan_by_id(b, (uint32_t)strtoul(buf, NULL, 10));
    if (!l || l->status != LN_PENDING) { ERR("  No such pending loan."); return; }
    Account *a = find_account(b, l->account);
    if (!a || a->status != ST_ACTIVE) { ERR("  Applicant account is not active."); return; }
    puts("1) Approve and disburse\n2) Reject\n0) Cancel");
    if (!read_line("Decision: ", buf, sizeof buf)) return;
    if (strcmp(buf, "1") == 0) {
        int64_t fee = l->principal / 100;
        if (fee < LOAN_FEE_MIN) fee = LOAN_FEE_MIN;
        if (fee > LOAN_FEE_MAX) fee = LOAN_FEE_MAX;
        char note[NOTE_LEN];
        snprintf(note, sizeof note, "Loan #%u disbursed", l->id);
        post_txn(b, a, TX_LOAN_DISBURSE, l->principal, 0, note);
        snprintf(note, sizeof note, "Loan #%u processing fee", l->id);
        post_txn(b, a, TX_FEE, -fee, 0, note);
        l->status = LN_ACTIVE;
        l->approved_at = now_ts();
        audit("ADMIN", "Approved loan #%u (%s) for account %" PRIu64, l->id, fmt_money(l->principal), a->number);
        OK("  Loan approved. %s %s credited, fee %s deducted.", CURRENCY, fmt_money(l->principal), fmt_money(fee));
    } else if (strcmp(buf, "2") == 0) {
        l->status = LN_REJECTED;
        b->dirty = true;
        audit("ADMIN", "Rejected loan #%u", l->id);
        OK("  Loan rejected.");
    }
}

static void admin_post_interest(Bank *b)
{
    uint32_t ym = (uint32_t)(ymd_of(now_ts()) / 100);
    if (b->last_interest_ym == ym) {
        ERR("  Interest for %u-%02u has already been posted.", ym / 100, ym % 100);
        return;
    }
    if (!prompt_yesno("Post this month's interest to all active savings accounts?", false)) return;
    size_t count = 0;
    int64_t total = 0;
    for (size_t i = 0; i < b->n_acc; i++) {
        Account *a = &b->acc[i];
        if (a->status != ST_ACTIVE || a->type != ACC_SAVINGS || a->balance <= 0) continue;
        int64_t interest = (a->balance * (int64_t)info_of(a)->rate_bp + 60000) / 120000;
        if (interest <= 0) continue;
        post_txn(b, a, TX_INTEREST, interest, 0, "Monthly interest");
        total += interest;
        count++;
    }
    b->last_interest_ym = ym;
    b->dirty = true;
    audit("ADMIN", "Posted interest %u-%02u: %zu accounts, total %s", ym / 100, ym % 100, count, fmt_money(total));
    OK("  Interest credited to %zu account(s); total %s %s.", count, CURRENCY, fmt_money(total));
}

static void admin_summary(const Bank *b)
{
    size_t by_type[ACC_TYPE_COUNT] = {0}, by_status[4] = {0};
    int64_t deposits = 0, overdrawn = 0, fd_total = 0, loan_out = 0, loan_pending = 0;
    size_t fd_n = 0, loan_n = 0, pend_n = 0;
    for (size_t i = 0; i < b->n_acc; i++) {
        const Account *a = &b->acc[i];
        by_type[a->type]++;
        by_status[a->status]++;
        if (a->balance > 0) deposits += a->balance; else overdrawn += -a->balance;
    }
    for (size_t i = 0; i < b->n_fd; i++)
        if (b->fd[i].status == FD_ACTIVE) { fd_total += b->fd[i].principal; fd_n++; }
    for (size_t i = 0; i < b->n_loan; i++) {
        if (b->loan[i].status == LN_ACTIVE) { loan_out += b->loan[i].outstanding; loan_n++; }
        if (b->loan[i].status == LN_PENDING) { loan_pending += b->loan[i].principal; pend_n++; }
    }
    int today = ymd_of(now_ts());
    size_t tx_today = 0;
    int64_t volume = 0;
    for (size_t i = b->n_txn; i-- > 0;) {
        if (ymd_of(b->txn[i].timestamp) != today) break;
        tx_today++;
        volume += b->txn[i].amount < 0 ? -b->txn[i].amount : b->txn[i].amount;
    }
    print_title("BANK SUMMARY");
    printf("System date            : %s%s\n", fmt_date_ts(now_ts()), b->offset_days ? "  (simulated clock)" : "");
    printf("Accounts               : %zu  (Savings %zu, Current %zu)\n", b->n_acc, by_type[0], by_type[1]);
    printf("  Active %zu | Frozen %zu | Locked %zu | Closed %zu\n", by_status[0], by_status[1], by_status[2], by_status[3]);
    printf("Customer deposits      : %s %s\n", CURRENCY, fmt_money(deposits));
    printf("Overdrawn balances     : %s %s\n", CURRENCY, fmt_money(overdrawn));
    printf("Fixed deposits (%zu)    : %s %s\n", fd_n, CURRENCY, fmt_money(fd_total));
    printf("Loans outstanding (%zu) : %s %s\n", loan_n, CURRENCY, fmt_money(loan_out));
    printf("Loans pending (%zu)     : %s %s\n", pend_n, CURRENCY, fmt_money(loan_pending));
    printf("Ledger entries         : %zu total, %zu today (volume %s %s)\n", b->n_txn, tx_today, CURRENCY, fmt_money(volume));
    /* Integrity check: replay the ledger and compare with stored balances. */
    size_t bad = 0;
    for (size_t i = 0; i < b->n_acc; i++) {
        int64_t sum = 0;
        for (size_t j = 0; j < b->n_txn; j++) if (b->txn[j].account == b->acc[i].number) sum += b->txn[j].amount;
        if (sum != b->acc[i].balance) bad++;
    }
    if (bad) ERR("Ledger reconciliation  : %zu account(s) MISMATCH!", bad);
    else OK("Ledger reconciliation  : all balances match the ledger");
}

static void admin_audit_view(void)
{
    FILE *f = fopen(g_audit_path, "r");
    if (!f) { puts("Audit log is empty."); return; }
    enum { KEEP = 40 };
    static char ring[KEEP][256];
    size_t n = 0;
    while (fgets(ring[n % KEEP], sizeof ring[0], f)) n++;
    fclose(f);
    print_title("AUDIT LOG (most recent entries)");
    size_t start = n > KEEP ? n - KEEP : 0;
    for (size_t i = start; i < n; i++) fputs(ring[i % KEEP], stdout);
    printf("(%zu total entries)\n", n);
}

static void admin_advance_clock(Bank *b)
{
    WARN("SIMULATION: advances the bank's internal date (for testing FDs, loans, interest).");
    char buf[16];
    if (!read_line("Days to advance (1-3650): ", buf, sizeof buf)) return;
    int d = atoi(buf);
    if (d < 1 || d > 3650) { ERR("  Invalid number of days."); return; }
    b->offset_days += d;
    g_offset_days = b->offset_days;
    b->dirty = true;
    audit("ADMIN", "Advanced system clock by %d day(s); date is now %s", d, fmt_date_ts(now_ts()));
    OK("  System date is now %s.", fmt_date_ts(now_ts()));
}

static void admin_change_password(Bank *b)
{
    char cur[64], p1[64], p2[64];
    if (!read_secret("Current admin password: ", cur, sizeof cur)) return;
    if (!verify_admin_password(b, cur)) { ERR("  Incorrect password."); return; }
    if (!read_secret("New password (min 8 chars, letters and digits): ", p1, sizeof p1)) return;
    bool letter = false, digit = false;
    for (const char *p = p1; *p; p++) { if (isalpha((unsigned char)*p)) letter = true; if (isdigit((unsigned char)*p)) digit = true; }
    if (strlen(p1) < 8 || !letter || !digit || strcmp(p1, DEFAULT_ADMIN_PW) == 0) { ERR("  Password does not meet the policy."); return; }
    if (!read_secret("Confirm new password: ", p2, sizeof p2)) return;
    if (strcmp(p1, p2) != 0) { ERR("  Passwords do not match."); return; }
    set_admin_password(b, p1);
    audit("ADMIN", "Admin password changed");
    OK("  Admin password updated.");
}

static void admin_session(Bank *b)
{
    for (;;) {
        printf("\n%sADMINISTRATOR CONSOLE%s   [system date %s]\n", CLR(C_BOLD), CLR(C_RESET), fmt_date_ts(now_ts()));
        print_rule('=');
        puts(" 1) Open new account           8) Review loan applications");
        puts(" 2) List all accounts          9) Post monthly interest");
        puts(" 3) Search accounts           10) Bank summary & reconciliation");
        puts(" 4) View account & ledger     11) Audit log");
        puts(" 5) Freeze / unfreeze         12) Advance system clock (simulation)");
        puts(" 6) Close account             13) Change admin password");
        puts(" 7) Reset PIN / unlock         0) Logout");
        char buf[64];
        if (!read_line("\nSelect: ", buf, sizeof buf)) return;
        switch (atoi(buf)) {
        case 1: admin_open_account(b); break;
        case 2: list_accounts(b, NULL); break;
        case 3: if (read_line("Search (name / phone / number): ", buf, sizeof buf)) list_accounts(b, buf); break;
        case 4: admin_view_account(b); break;
        case 5: admin_freeze(b); break;
        case 6: admin_close(b); break;
        case 7: admin_reset_pin(b); break;
        case 8: admin_review_loans(b); break;
        case 9: admin_post_interest(b); break;
        case 10: admin_summary(b); break;
        case 11: admin_audit_view(); break;
        case 12: admin_advance_clock(b); break;
        case 13: admin_change_password(b); break;
        case 0: audit("ADMIN", "Logout"); persist(b); return;
        default: ERR("Unknown option.");
        }
        persist(b);
    }
}

static void admin_login(Bank *b)
{
    print_title("ADMINISTRATOR LOGIN");
    for (int tries = 0; tries < ADMIN_MAX_TRIES; tries++) {
        char pw[64];
        if (!read_secret("Admin password: ", pw, sizeof pw)) return;
        if (verify_admin_password(b, pw)) {
            audit("ADMIN", "Login");
            if (strcmp(pw, DEFAULT_ADMIN_PW) == 0)
                WARN("\n! You are using the DEFAULT admin password. Change it now (option 13).");
            admin_session(b);
            return;
        }
        audit("SECURITY", "Failed admin login (%d/%d)", tries + 1, ADMIN_MAX_TRIES);
        ERR("Incorrect password (%d/%d).", tries + 1, ADMIN_MAX_TRIES);
        if (isatty(STDIN_FILENO)) sleep_sec(1);
    }
    ERR("Too many failed attempts. Returning to main menu.");
}


/* ------------------------------------------------------------------------- */
/*  Embedded HTTP Server & REST API                                          */
/* ------------------------------------------------------------------------- */

typedef struct {
    char *data;
    size_t len;
    size_t cap;
} HttpBuffer;

static void buf_init(HttpBuffer *b) {
    b->cap = 2048;
    b->len = 0;
    b->data = (char *)malloc(b->cap);
    if (b->data) b->data[0] = '\0';
}

static void buf_free(HttpBuffer *b) {
    if (b->data) free(b->data);
    b->data = NULL;
    b->len = b->cap = 0;
}

static void buf_append_len(HttpBuffer *b, const char *s, size_t n) {
    if (!s || !n) return;
    if (b->len + n + 1 >= b->cap) {
        size_t ncap = (b->cap * 2 > b->len + n + 1) ? b->cap * 2 : (b->len + n + 2048);
        char *p = (char *)realloc(b->data, ncap);
        if (!p) return;
        b->data = p;
        b->cap = ncap;
    }
    memcpy(b->data + b->len, s, n);
    b->len += n;
    b->data[b->len] = '\0';
}

static void buf_append(HttpBuffer *b, const char *s) {
    if (s) buf_append_len(b, s, strlen(s));
}

static void buf_printf(HttpBuffer *b, const char *fmt, ...) PRINTF_FMT(2, 3);
static void buf_printf(HttpBuffer *b, const char *fmt, ...) {
    char tmp[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if ((size_t)n < sizeof(tmp)) {
        buf_append_len(b, tmp, (size_t)n);
    } else {
        char *heap = (char *)malloc(n + 1);
        if (heap) {
            va_start(ap, fmt);
            vsnprintf(heap, n + 1, fmt, ap);
            va_end(ap);
            buf_append_len(b, heap, (size_t)n);
            free(heap);
        }
    }
}

static void buf_append_json_str(HttpBuffer *b, const char *s) {
    if (!s) { buf_append(b, "\"\""); return; }
    buf_append(b, "\"");
    for (const char *p = s; *p; p++) {
        switch (*p) {
            case '"':  buf_append(b, "\\\""); break;
            case '\\': buf_append(b, "\\\\"); break;
            case '\b': buf_append(b, "\\b"); break;
            case '\f': buf_append(b, "\\f"); break;
            case '\n': buf_append(b, "\\n"); break;
            case '\r': buf_append(b, "\\r"); break;
            case '\t': buf_append(b, "\\t"); break;
            default:
                if ((unsigned char)*p < 0x20) {
                    buf_printf(b, "\\u%04x", (unsigned char)*p);
                } else {
                    char ch[2] = {*p, '\0'};
                    buf_append_len(b, ch, 1);
                }
                break;
        }
    }
    buf_append(b, "\"");
}

/* --- JSON Request Parsing Helpers --- */

static bool json_find_key(const char *json, const char *key, const char **val_start) {
    if (!json || !key) return false;
    char pat[128];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(json, pat);
    while (p) {
        const char *after = p + strlen(pat);
        while (*after && isspace((unsigned char)*after)) after++;
        if (*after == ':') {
            after++;
            while (*after && isspace((unsigned char)*after)) after++;
            *val_start = after;
            return true;
        }
        p = strstr(after, pat);
    }
    return false;
}

static bool json_get_str(const char *json, const char *key, char *out, size_t out_sz) {
    const char *v;
    if (!json_find_key(json, key, &v)) return false;
    if (*v != '"') {
        size_t i = 0;
        while (*v && !isspace((unsigned char)*v) && *v != ',' && *v != '}' && *v != ']' && i + 1 < out_sz) {
            out[i++] = *v++;
        }
        out[i] = '\0';
        return i > 0;
    }
    v++;
    size_t i = 0;
    while (*v && *v != '"' && i + 1 < out_sz) {
        if (*v == '\\' && *(v + 1)) {
            v++;
            if (*v == 'n') out[i++] = '\n';
            else if (*v == 't') out[i++] = '\t';
            else if (*v == 'r') out[i++] = '\r';
            else out[i++] = *v;
        } else {
            out[i++] = *v;
        }
        v++;
    }
    out[i] = '\0';
    return true;
}

static bool json_get_int64(const char *json, const char *key, int64_t *out) {
    char buf[64];
    if (!json_get_str(json, key, buf, sizeof(buf))) return false;
    char *end = NULL;
    *out = (int64_t)strtoll(buf, &end, 10);
    return end != buf;
}

static bool json_get_uint64(const char *json, const char *key, uint64_t *out) {
    char buf[64];
    if (!json_get_str(json, key, buf, sizeof(buf))) return false;
    char *end = NULL;
    *out = (uint64_t)strtoull(buf, &end, 10);
    return end != buf;
}

static bool json_get_int(const char *json, const char *key, int *out) {
    int64_t v;
    if (!json_get_int64(json, key, &v)) return false;
    *out = (int)v;
    return true;
}

static bool json_get_amount(const char *json, const char *key, int64_t *out) {
    char buf[64];
    if (!json_get_str(json, key, buf, sizeof(buf))) return false;
    return parse_amount(buf, out);
}

/* --- Session Management --- */

#define MAX_SESSIONS 128
#define SESSION_TOKEN_LEN 32

typedef struct {
    char token[SESSION_TOKEN_LEN * 2 + 1];
    int role; /* 1 = CUSTOMER, 2 = ADMIN */
    uint64_t account_number;
    int64_t expires_at;
} AppSession;

static AppSession g_sessions[MAX_SESSIONS];
static size_t g_num_sessions = 0;

static const char *session_create(int role, uint64_t account_number) {
    int64_t now = (int64_t)time(NULL);
    int slot = -1;
    for (size_t i = 0; i < g_num_sessions; i++) {
        if (g_sessions[i].expires_at < now || g_sessions[i].token[0] == '\0') {
            slot = (int)i;
            break;
        }
    }
    if (slot < 0) {
        if (g_num_sessions < MAX_SESSIONS) {
            slot = (int)g_num_sessions++;
        } else {
            slot = 0;
        }
    }
    uint8_t rand_raw[SESSION_TOKEN_LEN];
    random_bytes(rand_raw, SESSION_TOKEN_LEN);
    for (int i = 0; i < SESSION_TOKEN_LEN; i++) {
        snprintf(g_sessions[slot].token + i * 2, 3, "%02x", rand_raw[i]);
    }
    g_sessions[slot].token[SESSION_TOKEN_LEN * 2] = '\0';
    g_sessions[slot].role = role;
    g_sessions[slot].account_number = account_number;
    g_sessions[slot].expires_at = now + 7200; /* 2 hours */
    return g_sessions[slot].token;
}

static AppSession *session_lookup(const char *token) {
    if (!token || !*token) return NULL;
    int64_t now = (int64_t)time(NULL);
    for (size_t i = 0; i < g_num_sessions; i++) {
        if (g_sessions[i].token[0] && g_sessions[i].expires_at >= now && strcmp(g_sessions[i].token, token) == 0) {
            g_sessions[i].expires_at = now + 7200;
            return &g_sessions[i];
        }
    }
    return NULL;
}

static void session_destroy(const char *token) {
    if (!token || !*token) return;
    for (size_t i = 0; i < g_num_sessions; i++) {
        if (strcmp(g_sessions[i].token, token) == 0) {
            g_sessions[i].expires_at = 0;
            g_sessions[i].token[0] = '\0';
            break;
        }
    }
}

/* --- HTTP Request Data & Helpers --- */

typedef struct {
    char method[16];
    char path[256];
    char query[512];
    char token[128];
    char *body;
    size_t body_len;
    AppSession *session;
} HttpRequest;

static void http_url_decode(char *dst, const char *src, size_t dst_sz) {
    size_t d = 0;
    while (*src && d + 1 < dst_sz) {
        if (*src == '%' && isxdigit((unsigned char)*(src + 1)) && isxdigit((unsigned char)*(src + 2))) {
            char hex[3] = {*(src + 1), *(src + 2), '\0'};
            dst[d++] = (char)strtol(hex, NULL, 16);
            src += 3;
        } else if (*src == '+') {
            dst[d++] = ' ';
            src++;
        } else {
            dst[d++] = *src++;
        }
    }
    dst[d] = '\0';
}

static bool http_get_param(const char *query, const char *key, char *out, size_t out_sz) {
    if (!query || !key || !out || out_sz == 0) return false;
    size_t klen = strlen(key);
    const char *p = query;
    while (*p) {
        if (strncmp(p, key, klen) == 0 && p[klen] == '=') {
            const char *val = p + klen + 1;
            const char *end = strchr(val, '&');
            size_t vlen = end ? (size_t)(end - val) : strlen(val);
            char enc[256];
            if (vlen >= sizeof(enc)) vlen = sizeof(enc) - 1;
            memcpy(enc, val, vlen);
            enc[vlen] = '\0';
            http_url_decode(out, enc, out_sz);
            return true;
        }
        p = strchr(p, '&');
        if (!p) break;
        p++;
    }
    return false;
}

static void http_send_raw(SOCKET client, int status, const char *status_text, const char *content_type, const char *extra_headers, const void *data, size_t data_len) {
    char header[1024];
    int hlen = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
        "Access-Control-Allow-Headers: Content-Type, Authorization, X-Session-Token, X-Requested-With\r\n"
        "Connection: close\r\n"
        "%s"
        "\r\n",
        status, status_text, content_type, data_len, extra_headers ? extra_headers : "");
    send(client, header, hlen, 0);
    if (data && data_len > 0) {
        const char *ptr = (const char *)data;
        size_t remaining = data_len;
        while (remaining > 0) {
            int sent = send(client, ptr, (int)remaining, 0);
            if (sent <= 0) break;
            ptr += sent;
            remaining -= (size_t)sent;
        }
    }
}

static void http_send_json(SOCKET client, int status, const char *json) {
    const char *status_text = (status == 200) ? "OK" :
                              (status == 400) ? "Bad Request" :
                              (status == 401) ? "Unauthorized" :
                              (status == 403) ? "Forbidden" :
                              (status == 404) ? "Not Found" : "Internal Error";
    http_send_raw(client, status, status_text, "application/json; charset=utf-8", NULL, json, json ? strlen(json) : 0);
}

static void http_send_file(SOCKET client, const char *filepath, const char *content_type) {
    FILE *f = fopen(filepath, "rb");
    if (!f) {
        http_send_json(client, 404, "{\"error\":\"File not found\"}");
        return;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0) {
        fclose(f);
        http_send_json(client, 500, "{\"error\":\"Cannot read file\"}");
        return;
    }
    char *buf = sz > 0 ? (char *)malloc((size_t)sz) : NULL;
    if (!buf && sz > 0) {
        fclose(f);
        http_send_json(client, 500, "{\"error\":\"Out of memory\"}");
        return;
    }
    if (sz > 0) {
        size_t rd = fread(buf, 1, (size_t)sz, f);
        (void)rd;
    }
    fclose(f);
    http_send_raw(client, 200, "OK", content_type, NULL, buf, (size_t)sz);
    if (buf) free(buf);
}

/* --- JSON Serializer Helpers --- */

static void json_append_receipt(HttpBuffer *b, const Txn *t) {
    buf_append(b, "{\"id\":");
    buf_printf(b, "%" PRIu64, t->id);
    buf_append(b, ",\"timestamp\":");
    buf_printf(b, "%" PRId64, t->timestamp);
    buf_append(b, ",\"datetime\":");
    buf_append_json_str(b, fmt_datetime(t->timestamp));
    buf_append(b, ",\"account\":");
    buf_append_json_str(b, mask_acct(t->account));
    buf_append(b, ",\"type\":");
    buf_append_json_str(b, TX_NAMES[t->type]);
    buf_append(b, ",\"amount\":");
    buf_append_json_str(b, fmt_money(t->amount < 0 ? -t->amount : t->amount));
    buf_append(b, ",\"amount_cents\":");
    buf_printf(b, "%" PRId64, t->amount);
    buf_append(b, ",\"balance_after\":");
    buf_append_json_str(b, fmt_money(t->balance_after));
    buf_append(b, ",\"balance_after_cents\":");
    buf_printf(b, "%" PRId64, t->balance_after);
    buf_append(b, ",\"counterparty\":");
    if (t->counterparty) buf_append_json_str(b, mask_acct(t->counterparty));
    else buf_append(b, "null");
    buf_append(b, ",\"note\":");
    buf_append_json_str(b, t->note);
    buf_append(b, "}");
}

static void json_append_account(HttpBuffer *b, const Bank *bank, const Account *a, bool admin_view) {
    Account tmp = *a;
    roll_limits(&tmp);
    buf_append(b, "{");
    buf_append(b, "\"number\":");
    buf_printf(b, "%" PRIu64, a->number);
    buf_append(b, ",\"number_str\":");
    char num_str[32];
    snprintf(num_str, sizeof(num_str), "%" PRIu64, a->number);
    buf_append_json_str(b, num_str);
    buf_append(b, ",\"masked_account\":");
    buf_append_json_str(b, mask_acct(a->number));
    buf_append(b, ",\"name\":");
    buf_append_json_str(b, a->name);
    buf_append(b, ",\"phone\":");
    buf_append_json_str(b, a->phone);
    buf_append(b, ",\"type\":");
    buf_append_json_str(b, info_of(a)->name);
    buf_append(b, ",\"type_id\":");
    buf_printf(b, "%u", (unsigned)a->type);
    buf_append(b, ",\"status\":");
    buf_append_json_str(b, STATUS_NAMES[a->status]);
    buf_append(b, ",\"status_id\":");
    buf_printf(b, "%u", (unsigned)a->status);
    buf_append(b, ",\"pin_temp\":");
    buf_append(b, a->pin_temp ? "true" : "false");
    buf_append(b, ",\"balance\":");
    buf_printf(b, "%" PRId64, a->balance);
    buf_append(b, ",\"balance_formatted\":");
    buf_append_json_str(b, fmt_money(a->balance));
    buf_append(b, ",\"available_funds\":");
    int64_t avail = available_funds(a);
    buf_printf(b, "%" PRId64, avail > 0 ? avail : 0);
    buf_append(b, ",\"available_formatted\":");
    buf_append_json_str(b, fmt_money(avail > 0 ? avail : 0));
    buf_append(b, ",\"floor\":");
    buf_printf(b, "%" PRId64, info_of(a)->floor);
    buf_append(b, ",\"floor_formatted\":");
    buf_append_json_str(b, fmt_money(info_of(a)->floor));
    buf_append(b, ",\"rate_bp\":");
    buf_printf(b, "%u", info_of(a)->rate_bp);
    buf_append(b, ",\"rate_formatted\":");
    buf_append_json_str(b, fmt_rate(info_of(a)->rate_bp));
    buf_append(b, ",\"withdraw_limit\":");
    buf_printf(b, "%" PRId64, info_of(a)->withdraw_limit);
    buf_append(b, ",\"withdrawn_today\":");
    buf_printf(b, "%" PRId64, tmp.withdrawn_today);
    buf_append(b, ",\"withdraw_remaining\":");
    int64_t w_rem = info_of(a)->withdraw_limit > tmp.withdrawn_today ? info_of(a)->withdraw_limit - tmp.withdrawn_today : 0;
    buf_printf(b, "%" PRId64, w_rem);
    buf_append(b, ",\"withdraw_remaining_formatted\":");
    buf_append_json_str(b, fmt_money(w_rem));
    buf_append(b, ",\"transfer_limit\":");
    buf_printf(b, "%" PRId64, info_of(a)->transfer_limit);
    buf_append(b, ",\"transferred_today\":");
    buf_printf(b, "%" PRId64, tmp.transferred_today);
    buf_append(b, ",\"transfer_remaining\":");
    int64_t t_rem = info_of(a)->transfer_limit > tmp.transferred_today ? info_of(a)->transfer_limit - tmp.transferred_today : 0;
    buf_printf(b, "%" PRId64, t_rem);
    buf_append(b, ",\"transfer_remaining_formatted\":");
    buf_append_json_str(b, fmt_money(t_rem));
    buf_append(b, ",\"created\":");
    buf_printf(b, "%" PRId64, a->created);
    buf_append(b, ",\"created_date_formatted\":");
    buf_append_json_str(b, fmt_date_ts(a->created));
    if (admin_view) {
        buf_append(b, ",\"failed_attempts\":");
        buf_printf(b, "%u", (unsigned)a->failed_attempts);
        buf_append(b, ",\"active_fd_count\":");
        buf_printf(b, "%d", active_fd_count(bank, a->number));
        Loan *ol = find_open_loan(bank, a->number);
        buf_append(b, ",\"has_open_loan\":");
        buf_append(b, ol ? "true" : "false");
    }
    buf_append(b, "}");
}

/* --- API Endpoints --- */

/* 1. Customer Login */
static void api_auth_customer_login(Bank *b, const HttpRequest *req, HttpBuffer *resp, int *status) {
    uint64_t acc_no = 0;
    char pin[32] = {0};
    if (!json_get_uint64(req->body, "account_number", &acc_no)) {
        char s_acc[32];
        if (json_get_str(req->body, "account_number", s_acc, sizeof(s_acc))) {
            acc_no = (uint64_t)strtoull(s_acc, NULL, 10);
        }
    }
    json_get_str(req->body, "pin", pin, sizeof(pin));

    if (!acc_no || !pin[0]) {
        *status = 400;
        buf_append(resp, "{\"success\":false,\"error\":\"Account number and PIN are required.\"}");
        return;
    }

    Account *a = find_account(b, acc_no);
    if (!a || a->status == ST_CLOSED) {
        *status = 401;
        buf_append(resp, "{\"success\":false,\"error\":\"Invalid account number or PIN.\"}");
        return;
    }
    if (a->status == ST_LOCKED) {
        *status = 401;
        buf_append(resp, "{\"success\":false,\"error\":\"This account is locked. Please contact the bank.\",\"locked\":true}");
        return;
    }

    if (!verify_pin(a, pin)) {
        a->failed_attempts++;
        audit("SECURITY", "Failed login for %" PRIu64 " (attempt %u)", acc_no, a->failed_attempts);
        if (a->failed_attempts >= LOCK_THRESHOLD) {
            a->status = ST_LOCKED;
            audit("SECURITY", "Account %" PRIu64 " LOCKED after repeated failures", acc_no);
            b->dirty = true;
            persist(b);
            *status = 401;
            buf_append(resp, "{\"success\":false,\"error\":\"Too many failed attempts. Account locked.\",\"locked\":true,\"attempts_left\":0}");
        } else {
            b->dirty = true;
            persist(b);
            *status = 401;
            buf_printf(resp, "{\"success\":false,\"error\":\"Invalid account number or PIN. %d attempt(s) left.\",\"locked\":false,\"attempts_left\":%d}",
                       LOCK_THRESHOLD - a->failed_attempts, LOCK_THRESHOLD - a->failed_attempts);
        }
        return;
    }

    a->failed_attempts = 0;
    b->dirty = true;
    audit("CUSTOMER", "Login %" PRIu64, acc_no);
    persist(b);

    const char *tok = session_create(1, a->number);
    *status = 200;
    buf_append(resp, "{\"success\":true,\"token\":");
    buf_append_json_str(resp, tok);
    buf_append(resp, ",\"role\":\"customer\",\"account_number\":");
    buf_printf(resp, "%" PRIu64, a->number);
    buf_append(resp, ",\"masked_account\":");
    buf_append_json_str(resp, mask_acct(a->number));
    buf_append(resp, ",\"name\":");
    buf_append_json_str(resp, a->name);
    buf_append(resp, ",\"type\":");
    buf_append_json_str(resp, info_of(a)->name);
    buf_append(resp, ",\"pin_temp\":");
    buf_append(resp, a->pin_temp ? "true" : "false");
    buf_append(resp, "}");
}

/* 2. Admin Login */
static void api_auth_admin_login(Bank *b, const HttpRequest *req, HttpBuffer *resp, int *status) {
    char pw[64] = {0};
    json_get_str(req->body, "password", pw, sizeof(pw));
    if (!pw[0]) {
        *status = 400;
        buf_append(resp, "{\"success\":false,\"error\":\"Password is required.\"}");
        return;
    }

    if (verify_admin_password(b, pw)) {
        audit("ADMIN", "Login");
        const char *tok = session_create(2, 0);
        bool is_default = (strcmp(pw, DEFAULT_ADMIN_PW) == 0);
        *status = 200;
        buf_append(resp, "{\"success\":true,\"token\":");
        buf_append_json_str(resp, tok);
        buf_append(resp, ",\"role\":\"admin\",\"is_default_password\":");
        buf_append(resp, is_default ? "true" : "false");
        buf_append(resp, "}");
        return;
    }

    audit("SECURITY", "Failed admin login");
    *status = 401;
    buf_append(resp, "{\"success\":false,\"error\":\"Incorrect administrator password.\"}");
}

/* 3. Session Check */
static void api_auth_session(Bank *b, const HttpRequest *req, HttpBuffer *resp, int *status) {
    *status = 200;
    if (!req->session) {
        buf_append(resp, "{\"authenticated\":false}");
        return;
    }
    if (req->session->role == 1) {
        Account *a = find_account(b, req->session->account_number);
        if (!a) {
            buf_append(resp, "{\"authenticated\":false}");
            return;
        }
        buf_append(resp, "{\"authenticated\":true,\"role\":\"customer\",\"account_number\":");
        buf_printf(resp, "%" PRIu64, a->number);
        buf_append(resp, ",\"masked_account\":");
        buf_append_json_str(resp, mask_acct(a->number));
        buf_append(resp, ",\"name\":");
        buf_append_json_str(resp, a->name);
        buf_append(resp, ",\"type\":");
        buf_append_json_str(resp, info_of(a)->name);
        buf_append(resp, ",\"status\":");
        buf_append_json_str(resp, STATUS_NAMES[a->status]);
        buf_append(resp, ",\"pin_temp\":");
        buf_append(resp, a->pin_temp ? "true" : "false");
        buf_append(resp, "}");
    } else if (req->session->role == 2) {
        buf_append(resp, "{\"authenticated\":true,\"role\":\"admin\"}");
    } else {
        buf_append(resp, "{\"authenticated\":false}");
    }
}

/* 4. Logout */
static void api_auth_logout(const HttpRequest *req, HttpBuffer *resp, int *status) {
    if (req->token[0]) {
        session_destroy(req->token);
    }
    *status = 200;
    buf_append(resp, "{\"success\":true}");
}

/* 5. Customer Dashboard */
static void api_customer_dashboard(Bank *b, const HttpRequest *req, HttpBuffer *resp, int *status) {
    if (!req->session || req->session->role != 1) {
        *status = 401;
        buf_append(resp, "{\"error\":\"Unauthorized\"}");
        return;
    }
    Account *a = find_account(b, req->session->account_number);
    if (!a) {
        *status = 404;
        buf_append(resp, "{\"error\":\"Account not found\"}");
        return;
    }
    roll_limits(a);

    /* Collect active FDs */
    int fd_cnt = 0;
    int64_t fd_principal_sum = 0;
    for (size_t i = 0; i < b->n_fd; i++) {
        if (b->fd[i].account == a->number && b->fd[i].status == FD_ACTIVE) {
            fd_cnt++;
            fd_principal_sum += b->fd[i].principal;
        }
    }

    /* Open Loan */
    Loan *ln = find_open_loan(b, a->number);

    /* Last 10 Transactions */
    const Txn **arr = NULL;
    size_t n_tx = collect_txns(b, a->number, 0, 99999999, &arr);
    size_t start_tx = (n_tx > 10) ? n_tx - 10 : 0;

    *status = 200;
    buf_append(resp, "{\"success\":true,\"account\":");
    json_append_account(resp, b, a, false);
    buf_append(resp, ",\"currency\":\"" CURRENCY "\"");
    buf_append(resp, ",\"system_date\":");
    buf_append_json_str(resp, fmt_date_ts(now_ts()));
    buf_append(resp, ",\"is_simulated_clock\":");
    buf_append(resp, b->offset_days ? "true" : "false");
    buf_append(resp, ",\"fd_summary\":{\"count\":");
    buf_printf(resp, "%d", fd_cnt);
    buf_append(resp, ",\"total_principal\":");
    buf_printf(resp, "%" PRId64, fd_principal_sum);
    buf_append(resp, ",\"total_principal_formatted\":");
    buf_append_json_str(resp, fmt_money(fd_principal_sum));
    buf_append(resp, "}");

    buf_append(resp, ",\"loan_summary\":");
    if (ln) {
        buf_append(resp, "{\"id\":");
        buf_printf(resp, "%u", ln->id);
        buf_append(resp, ",\"status\":");
        buf_append_json_str(resp, LOAN_STATUS_NAMES[ln->status]);
        buf_append(resp, ",\"principal\":");
        buf_printf(resp, "%" PRId64, ln->principal);
        buf_append(resp, ",\"principal_formatted\":");
        buf_append_json_str(resp, fmt_money(ln->principal));
        buf_append(resp, ",\"outstanding\":");
        buf_printf(resp, "%" PRId64, ln->outstanding);
        buf_append(resp, ",\"outstanding_formatted\":");
        buf_append_json_str(resp, fmt_money(ln->outstanding));
        buf_append(resp, ",\"emi\":");
        buf_printf(resp, "%" PRId64, ln->emi);
        buf_append(resp, ",\"emi_formatted\":");
        buf_append_json_str(resp, fmt_money(ln->emi));
        buf_append(resp, ",\"rate_bp\":");
        buf_printf(resp, "%u", ln->rate_bp);
        buf_append(resp, ",\"rate_formatted\":");
        buf_append_json_str(resp, fmt_rate(ln->rate_bp));
        buf_append(resp, ",\"tenor\":");
        buf_printf(resp, "%u", ln->tenor);
        buf_append(resp, ",\"paid\":");
        buf_printf(resp, "%u", ln->paid);
        buf_append(resp, "}");
    } else {
        buf_append(resp, "null");
    }

    buf_append(resp, ",\"recent_transactions\":[");
    for (size_t i = n_tx; i > start_tx; i--) {
        const Txn *t = arr[i - 1];
        if (i < n_tx) buf_append(resp, ",");
        json_append_receipt(resp, t);
    }
    buf_append(resp, "]}");
    free(arr);
}

/* 6. Customer Deposit */
static void api_customer_deposit(Bank *b, const HttpRequest *req, HttpBuffer *resp, int *status) {
    if (!req->session || req->session->role != 1) {
        *status = 401;
        buf_append(resp, "{\"error\":\"Unauthorized\"}");
        return;
    }
    Account *a = find_account(b, req->session->account_number);
    if (!a) { *status = 404; buf_append(resp, "{\"error\":\"Account not found\"}"); return; }

    int64_t amt = 0;
    if (!json_get_amount(req->body, "amount", &amt)) {
        *status = 400;
        buf_append(resp, "{\"success\":false,\"error\":\"Invalid deposit amount.\"}");
        return;
    }

    Txn *t = NULL;
    const char *e = op_deposit(b, a, amt, &t);
    if (e) {
        *status = 400;
        buf_printf(resp, "{\"success\":false,\"error\":\"%s\"}", e);
        return;
    }
    persist(b);

    *status = 200;
    buf_append(resp, "{\"success\":true,\"message\":\"Deposit successful.\",\"new_balance\":");
    buf_printf(resp, "%" PRId64, a->balance);
    buf_append(resp, ",\"new_balance_formatted\":");
    buf_append_json_str(resp, fmt_money(a->balance));
    buf_append(resp, ",\"receipt\":");
    json_append_receipt(resp, t);
    buf_append(resp, "}");
}

/* 7. Customer Withdraw */
static void api_customer_withdraw(Bank *b, const HttpRequest *req, HttpBuffer *resp, int *status) {
    if (!req->session || req->session->role != 1) {
        *status = 401;
        buf_append(resp, "{\"error\":\"Unauthorized\"}");
        return;
    }
    Account *a = find_account(b, req->session->account_number);
    if (!a) { *status = 404; buf_append(resp, "{\"error\":\"Account not found\"}"); return; }

    int64_t amt = 0;
    if (!json_get_amount(req->body, "amount", &amt)) {
        *status = 400;
        buf_append(resp, "{\"success\":false,\"error\":\"Invalid withdrawal amount.\"}");
        return;
    }

    Txn *t = NULL;
    const char *e = op_withdraw(b, a, amt, &t);
    if (e) {
        *status = 400;
        buf_printf(resp, "{\"success\":false,\"error\":\"%s\"}", e);
        return;
    }
    persist(b);

    *status = 200;
    buf_append(resp, "{\"success\":true,\"message\":\"Please collect your cash.\",\"new_balance\":");
    buf_printf(resp, "%" PRId64, a->balance);
    buf_append(resp, ",\"new_balance_formatted\":");
    buf_append_json_str(resp, fmt_money(a->balance));
    buf_append(resp, ",\"receipt\":");
    json_append_receipt(resp, t);
    buf_append(resp, "}");
}

/* 8. Customer Transfer Preview */
static void api_customer_transfer_preview(Bank *b, const HttpRequest *req, HttpBuffer *resp, int *status) {
    if (!req->session || req->session->role != 1) {
        *status = 401;
        buf_append(resp, "{\"error\":\"Unauthorized\"}");
        return;
    }
    Account *from = find_account(b, req->session->account_number);
    if (!from) { *status = 404; buf_append(resp, "{\"error\":\"Account not found\"}"); return; }

    uint64_t to_no = 0;
    if (!json_get_uint64(req->body, "beneficiary_account", &to_no) && !json_get_uint64(req->body, "to_account", &to_no)) {
        char s_acc[32];
        if (json_get_str(req->body, "beneficiary_account", s_acc, sizeof(s_acc)) || json_get_str(req->body, "to_account", s_acc, sizeof(s_acc))) {
            to_no = (uint64_t)strtoull(s_acc, NULL, 10);
        }
    }
    int64_t amt = 0;
    json_get_amount(req->body, "amount", &amt);

    if (to_no == from->number) {
        *status = 400;
        buf_append(resp, "{\"success\":false,\"error\":\"Cannot transfer to your own account.\"}");
        return;
    }

    Account *to = find_account(b, to_no);
    if (!to || to->status == ST_CLOSED) {
        *status = 400;
        buf_append(resp, "{\"success\":false,\"error\":\"Beneficiary account not found or closed.\"}");
        return;
    }
    if (to->status != ST_ACTIVE) {
        *status = 400;
        buf_append(resp, "{\"success\":false,\"error\":\"Beneficiary account cannot receive funds (not active).\"}");
        return;
    }

    if (amt > 0) {
        const char *chk = check_debit(from, amt);
        if (chk) {
            *status = 400;
            buf_printf(resp, "{\"success\":false,\"error\":\"%s\"}", chk);
            return;
        }
        roll_limits(from);
        if (from->transferred_today + amt > info_of(from)->transfer_limit) {
            *status = 400;
            buf_printf(resp, "{\"success\":false,\"error\":\"%s\"}", limit_msg("transfer", info_of(from)->transfer_limit, from->transferred_today));
            return;
        }
    }

    char first[NAME_LEN];
    str_copy(first, sizeof(first), to->name);
    char *sp = strchr(first, ' ');
    if (sp) *sp = '\0';

    *status = 200;
    buf_append(resp, "{\"success\":true,\"beneficiary\":{");
    buf_append(resp, "\"name_masked\":");
    char name_masked[NAME_LEN + 8];
    snprintf(name_masked, sizeof(name_masked), "%s ***", first);
    buf_append_json_str(resp, name_masked);
    buf_append(resp, ",\"account_masked\":");
    buf_append_json_str(resp, mask_acct(to->number));
    buf_append(resp, ",\"type\":");
    buf_append_json_str(resp, info_of(to)->name);
    buf_append(resp, "}}");
}

/* 9. Customer Transfer Execution */
static void api_customer_transfer(Bank *b, const HttpRequest *req, HttpBuffer *resp, int *status) {
    if (!req->session || req->session->role != 1) {
        *status = 401;
        buf_append(resp, "{\"error\":\"Unauthorized\"}");
        return;
    }
    Account *from = find_account(b, req->session->account_number);
    if (!from) { *status = 404; buf_append(resp, "{\"error\":\"Account not found\"}"); return; }

    uint64_t to_no = 0;
    if (!json_get_uint64(req->body, "beneficiary_account", &to_no) && !json_get_uint64(req->body, "to_account", &to_no)) {
        char s_acc[32];
        if (json_get_str(req->body, "beneficiary_account", s_acc, sizeof(s_acc)) || json_get_str(req->body, "to_account", s_acc, sizeof(s_acc))) {
            to_no = (uint64_t)strtoull(s_acc, NULL, 10);
        }
    }
    int64_t amt = 0;
    if (!json_get_amount(req->body, "amount", &amt)) {
        *status = 400;
        buf_append(resp, "{\"success\":false,\"error\":\"Invalid transfer amount.\"}");
        return;
    }

    char pin[32] = {0};
    json_get_str(req->body, "pin", pin, sizeof(pin));
    if (!pin[0] || !verify_pin(from, pin)) {
        *status = 401;
        buf_append(resp, "{\"success\":false,\"error\":\"Incorrect PIN. Transfer cancelled.\"}");
        return;
    }

    Account *to = find_account(b, to_no);
    if (!to || to->status == ST_CLOSED) {
        *status = 400;
        buf_append(resp, "{\"success\":false,\"error\":\"Beneficiary account not found.\"}");
        return;
    }

    char note[NOTE_LEN] = {0};
    json_get_str(req->body, "note", note, sizeof(note));
    for (char *p = note; *p; p++) if ((unsigned char)*p < 32) *p = ' ';

    Txn *t = NULL;
    const char *e = op_transfer(b, from, to, amt, note, &t);
    if (e) {
        *status = 400;
        buf_printf(resp, "{\"success\":false,\"error\":\"%s\"}", e);
        return;
    }

    audit("CUSTOMER", "TRANSFER %s %s from %" PRIu64 " to %" PRIu64, CURRENCY, fmt_money(amt), from->number, to_no);
    persist(b);

    *status = 200;
    buf_append(resp, "{\"success\":true,\"message\":\"Transfer completed successfully.\",\"new_balance\":");
    buf_printf(resp, "%" PRId64, from->balance);
    buf_append(resp, ",\"new_balance_formatted\":");
    buf_append_json_str(resp, fmt_money(from->balance));
    buf_append(resp, ",\"receipt\":");
    json_append_receipt(resp, t);
    buf_append(resp, "}");
}

/* 10. Statement & Transactions */
static void api_customer_statement(Bank *b, const HttpRequest *req, HttpBuffer *resp, int *status) {
    if (!req->session || req->session->role != 1) {
        *status = 401;
        buf_append(resp, "{\"error\":\"Unauthorized\"}");
        return;
    }
    Account *a = find_account(b, req->session->account_number);
    if (!a) { *status = 404; buf_append(resp, "{\"error\":\"Account not found\"}"); return; }

    int from = 0, to = 99999999;
    char s_from[32], s_to[32];
    if (http_get_param(req->query, "from", s_from, sizeof(s_from)) && s_from[0]) {
        parse_date(s_from, &from);
    }
    if (http_get_param(req->query, "to", s_to, sizeof(s_to)) && s_to[0]) {
        parse_date(s_to, &to);
    }

    const Txn **arr = NULL;
    size_t n = collect_txns(b, a->number, from, to, &arr);

    int64_t opening_bal = 0;
    if (n > 0) {
        opening_bal = arr[0]->balance_after - arr[0]->amount;
    } else {
        opening_bal = a->balance;
    }
    int64_t credits = 0, debits = 0;

    *status = 200;
    buf_append(resp, "{\"success\":true,\"account\":");
    json_append_account(resp, b, a, false);
    buf_append(resp, ",\"opening_balance\":");
    buf_printf(resp, "%" PRId64, opening_bal);
    buf_append(resp, ",\"opening_balance_formatted\":");
    buf_append_json_str(resp, fmt_money(opening_bal));
    buf_append(resp, ",\"closing_balance\":");
    buf_printf(resp, "%" PRId64, n > 0 ? arr[n - 1]->balance_after : opening_bal);
    buf_append(resp, ",\"closing_balance_formatted\":");
    buf_append_json_str(resp, fmt_money(n > 0 ? arr[n - 1]->balance_after : opening_bal));

    buf_append(resp, ",\"transactions\":[");
    for (size_t i = 0; i < n; i++) {
        const Txn *t = arr[i];
        if (i > 0) buf_append(resp, ",");
        json_append_receipt(resp, t);
        if (t->amount > 0) credits += t->amount; else debits += -t->amount;
    }
    buf_append(resp, "],\"total_credits\":");
    buf_printf(resp, "%" PRId64, credits);
    buf_append(resp, ",\"total_credits_formatted\":");
    buf_append_json_str(resp, fmt_money(credits));
    buf_append(resp, ",\"total_debits\":");
    buf_printf(resp, "%" PRId64, debits);
    buf_append(resp, ",\"total_debits_formatted\":");
    buf_append_json_str(resp, fmt_money(debits));
    buf_append(resp, ",\"count\":");
    buf_printf(resp, "%zu", n);
    buf_append(resp, "}");
    free(arr);
}

/* 11. Customer Statement CSV Stream */
static void api_customer_statement_csv(Bank *b, const HttpRequest *req, SOCKET client) {
    if (!req->session || req->session->role != 1) {
        http_send_json(client, 401, "{\"error\":\"Unauthorized\"}");
        return;
    }
    Account *a = find_account(b, req->session->account_number);
    if (!a) { http_send_json(client, 404, "{\"error\":\"Account not found\"}"); return; }

    int from = 0, to = 99999999;
    char s_from[32], s_to[32];
    if (http_get_param(req->query, "from", s_from, sizeof(s_from)) && s_from[0]) parse_date(s_from, &from);
    if (http_get_param(req->query, "to", s_to, sizeof(s_to)) && s_to[0]) parse_date(s_to, &to);

    const Txn **arr = NULL;
    size_t n = collect_txns(b, a->number, from, to, &arr);

    HttpBuffer csv;
    buf_init(&csv);
    buf_append(&csv, "txn_id,datetime,type,counterparty,amount,balance_after,note\r\n");
    for (size_t i = 0; i < n; i++) {
        const Txn *t = arr[i];
        buf_printf(&csv, "%" PRIu64 ",%s,%s,%" PRIu64 ",%s,%s,\"",
                   t->id, fmt_datetime(t->timestamp), TX_NAMES[t->type],
                   t->counterparty, fmt_money(t->amount), fmt_money(t->balance_after));
        for (const char *p = t->note; *p; p++) {
            if (*p == '"') buf_append_len(&csv, "\"\"", 2);
            else buf_append_len(&csv, p, 1);
        }
        buf_append(&csv, "\"\r\n");
    }
    free(arr);

    char extra[256];
    snprintf(extra, sizeof(extra), "Content-Disposition: attachment; filename=\"statement_%" PRIu64 ".csv\"\r\n", a->number);
    http_send_raw(client, 200, "OK", "text/csv; charset=utf-8", extra, csv.data, csv.len);
    buf_free(&csv);
}

/* 12. Customer Change PIN */
static void api_customer_change_pin(Bank *b, const HttpRequest *req, HttpBuffer *resp, int *status) {
    if (!req->session || req->session->role != 1) {
        *status = 401;
        buf_append(resp, "{\"error\":\"Unauthorized\"}");
        return;
    }
    Account *a = find_account(b, req->session->account_number);
    if (!a) { *status = 404; buf_append(resp, "{\"error\":\"Account not found\"}"); return; }

    char cur_pin[32] = {0}, new_pin[32] = {0};
    json_get_str(req->body, "current_pin", cur_pin, sizeof(cur_pin));
    json_get_str(req->body, "new_pin", new_pin, sizeof(new_pin));

    if (!a->pin_temp) {
        if (!cur_pin[0] || !verify_pin(a, cur_pin)) {
            *status = 400;
            buf_append(resp, "{\"success\":false,\"error\":\"Current PIN is incorrect.\"}");
            return;
        }
    }

    if (!pin_strong(new_pin)) {
        *status = 400;
        buf_append(resp, "{\"success\":false,\"error\":\"New PIN is too weak (must be 4-6 digits, not sequential, repeated or common pattern).\"}");
        return;
    }

    set_pin(a, new_pin);
    a->pin_temp = 0;
    a->failed_attempts = 0;
    b->dirty = true;
    audit("CUSTOMER", "Changed PIN for %" PRIu64, a->number);
    persist(b);

    *status = 200;
    buf_append(resp, "{\"success\":true,\"message\":\"PIN updated successfully.\"}");
}

/* 13. FD Rates */
static void api_fd_rates(HttpBuffer *resp, int *status) {
    *status = 200;
    buf_append(resp, "{\"success\":true,\"rates\":[");
    for (int i = 0; i < FD_RATE_COUNT; i++) {
        if (i > 0) buf_append(resp, ",");
        buf_printf(resp, "{\"months\":%d,\"rate_bp\":%u,\"rate_formatted\":", FD_RATES[i].months, FD_RATES[i].rate_bp);
        buf_append_json_str(resp, fmt_rate(FD_RATES[i].rate_bp));
        buf_append(resp, "}");
    }
    buf_append(resp, "],\"min_amount\":");
    buf_printf(resp, "%" PRId64, FD_MIN_AMOUNT);
    buf_append(resp, ",\"min_amount_formatted\":");
    buf_append_json_str(resp, fmt_money(FD_MIN_AMOUNT));
    buf_append(resp, "}");
}

/* 14. FD Calculate */
static void api_fd_calculate(const HttpRequest *req, HttpBuffer *resp, int *status) {
    int64_t principal = 0;
    int months = 0;
    json_get_amount(req->body, "principal", &principal);
    if (!json_get_int(req->body, "months", &months)) {
        json_get_int(req->body, "term_months", &months);
    }

    if (principal < FD_MIN_AMOUNT || principal > MAX_AMOUNT) {
        *status = 400;
        buf_printf(resp, "{\"success\":false,\"error\":\"Principal must be between %s and %s.\"}", fmt_money(FD_MIN_AMOUNT), fmt_money(MAX_AMOUNT));
        return;
    }

    uint32_t rate_bp = 0;
    for (int i = 0; i < FD_RATE_COUNT; i++) {
        if (FD_RATES[i].months == months) {
            rate_bp = FD_RATES[i].rate_bp;
            break;
        }
    }
    if (!rate_bp) {
        *status = 400;
        buf_append(resp, "{\"success\":false,\"error\":\"Invalid deposit term.\"}");
        return;
    }

    int64_t maturity = fd_maturity_amount(principal, rate_bp, months);
    int64_t interest = maturity - principal;

    *status = 200;
    buf_append(resp, "{\"success\":true,\"principal\":");
    buf_printf(resp, "%" PRId64, principal);
    buf_append(resp, ",\"principal_formatted\":");
    buf_append_json_str(resp, fmt_money(principal));
    buf_append(resp, ",\"rate_bp\":");
    buf_printf(resp, "%u", rate_bp);
    buf_append(resp, ",\"rate_formatted\":");
    buf_append_json_str(resp, fmt_rate(rate_bp));
    buf_append(resp, ",\"months\":");
    buf_printf(resp, "%d", months);
    buf_append(resp, ",\"maturity_amount\":");
    buf_printf(resp, "%" PRId64, maturity);
    buf_append(resp, ",\"maturity_amount_formatted\":");
    buf_append_json_str(resp, fmt_money(maturity));
    buf_append(resp, ",\"interest\":");
    buf_printf(resp, "%" PRId64, interest);
    buf_append(resp, ",\"interest_formatted\":");
    buf_append_json_str(resp, fmt_money(interest));
    buf_append(resp, "}");
}

/* 15. FD Open */
static void api_fd_open(Bank *b, const HttpRequest *req, HttpBuffer *resp, int *status) {
    if (!req->session || req->session->role != 1) {
        *status = 401;
        buf_append(resp, "{\"error\":\"Unauthorized\"}");
        return;
    }
    Account *a = find_account(b, req->session->account_number);
    if (!a) { *status = 404; buf_append(resp, "{\"error\":\"Account not found\"}"); return; }

    int64_t principal = 0;
    int months = 0;
    if (!json_get_amount(req->body, "principal", &principal)) {
        *status = 400;
        buf_append(resp, "{\"success\":false,\"error\":\"Invalid principal amount.\"}");
        return;
    }
    if (principal < FD_MIN_AMOUNT) {
        *status = 400;
        buf_printf(resp, "{\"success\":false,\"error\":\"Minimum deposit amount is %s %s.\"}", CURRENCY, fmt_money(FD_MIN_AMOUNT));
        return;
    }
    if (!json_get_int(req->body, "months", &months)) {
        json_get_int(req->body, "term_months", &months);
    }
    uint32_t rate_bp = 0;
    for (int i = 0; i < FD_RATE_COUNT; i++) {
        if (FD_RATES[i].months == months) { rate_bp = FD_RATES[i].rate_bp; break; }
    }
    if (!rate_bp) {
        *status = 400;
        buf_append(resp, "{\"success\":false,\"error\":\"Invalid term selected.\"}");
        return;
    }

    const char *e = check_debit(a, principal);
    if (e) {
        *status = 400;
        buf_printf(resp, "{\"success\":false,\"error\":\"%s\"}", e);
        return;
    }

    Fd d;
    memset(&d, 0, sizeof(d));
    d.id = b->next_fd_id++;
    d.status = FD_ACTIVE;
    d.account = a->number;
    d.principal = principal;
    d.rate_bp = rate_bp;
    d.months = (uint16_t)months;
    d.opened_at = now_ts();
    d.maturity_at = d.opened_at + (int64_t)d.months * 30 * DAY_SECONDS;
    array_push((void **)&b->fd, &b->n_fd, &b->cap_fd, sizeof(Fd), &d);

    char note[NOTE_LEN];
    snprintf(note, sizeof(note), "FD #%u opened", d.id);
    Txn *t = post_txn(b, a, TX_FD_OPEN, -principal, 0, note);
    audit("CUSTOMER", "FD #%u opened on %" PRIu64 " for %s", d.id, a->number, fmt_money(principal));
    persist(b);

    *status = 200;
    buf_append(resp, "{\"success\":true,\"message\":\"Fixed deposit opened successfully.\",\"new_balance\":");
    buf_printf(resp, "%" PRId64, a->balance);
    buf_append(resp, ",\"new_balance_formatted\":");
    buf_append_json_str(resp, fmt_money(a->balance));
    buf_append(resp, ",\"receipt\":");
    json_append_receipt(resp, t);
    buf_append(resp, ",\"fd\":{\"id\":");
    buf_printf(resp, "%u", d.id);
    buf_append(resp, ",\"principal\":");
    buf_printf(resp, "%" PRId64, d.principal);
    buf_append(resp, ",\"rate_bp\":");
    buf_printf(resp, "%u", d.rate_bp);
    buf_append(resp, ",\"rate_formatted\":");
    buf_append_json_str(resp, fmt_rate(d.rate_bp));
    buf_append(resp, ",\"months\":");
    buf_printf(resp, "%u", d.months);
    buf_append(resp, ",\"maturity_amount\":");
    int64_t mat = fd_maturity_amount(d.principal, d.rate_bp, d.months);
    buf_printf(resp, "%" PRId64, mat);
    buf_append(resp, ",\"maturity_formatted\":");
    buf_append_json_str(resp, fmt_money(mat));
    buf_append(resp, "}}");
}

/* 16. FD List */
static void api_fd_list(Bank *b, const HttpRequest *req, HttpBuffer *resp, int *status) {
    if (!req->session || req->session->role != 1) {
        *status = 401;
        buf_append(resp, "{\"error\":\"Unauthorized\"}");
        return;
    }
    int64_t now = now_ts();
    *status = 200;
    buf_append(resp, "{\"success\":true,\"deposits\":[");
    size_t count = 0;
    for (size_t i = 0; i < b->n_fd; i++) {
        const Fd *d = &b->fd[i];
        if (d->account != req->session->account_number) continue;
        if (count > 0) buf_append(resp, ",");
        bool mature = (now >= d->maturity_at);
        int64_t mat_amt = fd_maturity_amount(d->principal, d->rate_bp, d->months);
        int64_t cur_val = (d->status == FD_ACTIVE) ? (mature ? mat_amt : fd_premature_payout(d, now)) : 0;
        buf_append(resp, "{\"id\":");
        buf_printf(resp, "%u", d->id);
        buf_append(resp, ",\"principal\":");
        buf_printf(resp, "%" PRId64, d->principal);
        buf_append(resp, ",\"principal_formatted\":");
        buf_append_json_str(resp, fmt_money(d->principal));
        buf_append(resp, ",\"rate_bp\":");
        buf_printf(resp, "%u", d->rate_bp);
        buf_append(resp, ",\"rate_formatted\":");
        buf_append_json_str(resp, fmt_rate(d->rate_bp));
        buf_append(resp, ",\"months\":");
        buf_printf(resp, "%u", d->months);
        buf_append(resp, ",\"opened_at\":");
        buf_printf(resp, "%" PRId64, d->opened_at);
        buf_append(resp, ",\"opened_date_formatted\":");
        buf_append_json_str(resp, fmt_date_ts(d->opened_at));
        buf_append(resp, ",\"maturity_at\":");
        buf_printf(resp, "%" PRId64, d->maturity_at);
        buf_append(resp, ",\"maturity_date_formatted\":");
        buf_append_json_str(resp, fmt_date_ts(d->maturity_at));
        buf_append(resp, ",\"status\":");
        buf_append_json_str(resp, FD_STATUS_NAMES[d->status]);
        buf_append(resp, ",\"status_id\":");
        buf_printf(resp, "%u", (unsigned)d->status);
        buf_append(resp, ",\"is_mature\":");
        buf_append(resp, mature ? "true" : "false");
        buf_append(resp, ",\"maturity_amount\":");
        buf_printf(resp, "%" PRId64, mat_amt);
        buf_append(resp, ",\"maturity_amount_formatted\":");
        buf_append_json_str(resp, fmt_money(mat_amt));
        buf_append(resp, ",\"current_payout\":");
        buf_printf(resp, "%" PRId64, cur_val);
        buf_append(resp, ",\"current_payout_formatted\":");
        buf_append_json_str(resp, fmt_money(cur_val));
        buf_append(resp, "}");
        count++;
    }
    buf_append(resp, "]}");
}

/* 17. FD Close Preview */
static void api_fd_close_preview(Bank *b, const HttpRequest *req, HttpBuffer *resp, int *status) {
    if (!req->session || req->session->role != 1) {
        *status = 401;
        buf_append(resp, "{\"error\":\"Unauthorized\"}");
        return;
    }
    uint32_t fd_id = 0;
    int id_int = 0;
    if (json_get_int(req->body, "fd_id", &id_int)) fd_id = (uint32_t)id_int;

    Fd *d = NULL;
    for (size_t i = 0; i < b->n_fd; i++) {
        if (b->fd[i].id == fd_id && b->fd[i].account == req->session->account_number && b->fd[i].status == FD_ACTIVE) {
            d = &b->fd[i];
            break;
        }
    }
    if (!d) {
        *status = 404;
        buf_append(resp, "{\"success\":false,\"error\":\"Active deposit with that ID not found.\"}");
        return;
    }

    int64_t now = now_ts();
    bool mature = (now >= d->maturity_at);
    int64_t full_mat = fd_maturity_amount(d->principal, d->rate_bp, d->months);
    int64_t payout = mature ? full_mat : fd_premature_payout(d, now);

    *status = 200;
    buf_append(resp, "{\"success\":true,\"id\":");
    buf_printf(resp, "%u", d->id);
    buf_append(resp, ",\"is_mature\":");
    buf_append(resp, mature ? "true" : "false");
    buf_append(resp, ",\"payout\":");
    buf_printf(resp, "%" PRId64, payout);
    buf_append(resp, ",\"payout_formatted\":");
    buf_append_json_str(resp, fmt_money(payout));
    buf_append(resp, ",\"maturity_amount\":");
    buf_printf(resp, "%" PRId64, full_mat);
    buf_append(resp, ",\"maturity_amount_formatted\":");
    buf_append_json_str(resp, fmt_money(full_mat));
    buf_append(resp, ",\"principal\":");
    buf_printf(resp, "%" PRId64, d->principal);
    buf_append(resp, ",\"principal_formatted\":");
    buf_append_json_str(resp, fmt_money(d->principal));
    buf_append(resp, ",\"penalty_applied\":");
    buf_append(resp, mature ? "false" : "true");
    buf_append(resp, "}");
}

/* 18. FD Close Execution */
static void api_fd_close(Bank *b, const HttpRequest *req, HttpBuffer *resp, int *status) {
    if (!req->session || req->session->role != 1) {
        *status = 401;
        buf_append(resp, "{\"error\":\"Unauthorized\"}");
        return;
    }
    Account *a = find_account(b, req->session->account_number);
    if (!a || a->status == ST_CLOSED) {
        *status = 400;
        buf_append(resp, "{\"success\":false,\"error\":\"Account closed or not found.\"}");
        return;
    }

    uint32_t fd_id = 0;
    int id_int = 0;
    if (json_get_int(req->body, "fd_id", &id_int)) fd_id = (uint32_t)id_int;

    Fd *d = NULL;
    for (size_t i = 0; i < b->n_fd; i++) {
        if (b->fd[i].id == fd_id && b->fd[i].account == a->number && b->fd[i].status == FD_ACTIVE) {
            d = &b->fd[i];
            break;
        }
    }
    if (!d) {
        *status = 404;
        buf_append(resp, "{\"success\":false,\"error\":\"No active deposit with that ID found.\"}");
        return;
    }

    int64_t now = now_ts();
    bool mature = (now >= d->maturity_at);
    int64_t payout = mature ? fd_maturity_amount(d->principal, d->rate_bp, d->months) : fd_premature_payout(d, now);

    d->status = mature ? FD_MATURED : FD_BROKEN;
    char note[NOTE_LEN];
    snprintf(note, sizeof(note), "FD #%u payout", d->id);
    Txn *t = post_txn(b, a, TX_FD_CLOSE, payout, 0, note);
    audit("CUSTOMER", "FD #%u closed (%s) payout %s", d->id, mature ? "matured" : "premature", fmt_money(payout));
    persist(b);

    *status = 200;
    buf_append(resp, "{\"success\":true,\"message\":\"Deposit closed successfully.\",\"payout\":");
    buf_printf(resp, "%" PRId64, payout);
    buf_append(resp, ",\"payout_formatted\":");
    buf_append_json_str(resp, fmt_money(payout));
    buf_append(resp, ",\"new_balance\":");
    buf_printf(resp, "%" PRId64, a->balance);
    buf_append(resp, ",\"new_balance_formatted\":");
    buf_append_json_str(resp, fmt_money(a->balance));
    buf_append(resp, ",\"receipt\":");
    json_append_receipt(resp, t);
    buf_append(resp, "}");
}

/* 19. Loan Calculate */
static void api_loan_calculate(const HttpRequest *req, HttpBuffer *resp, int *status) {
    int64_t principal = 0;
    int tenor = 0;
    json_get_amount(req->body, "principal", &principal);
    if (!json_get_int(req->body, "tenor", &tenor)) {
        json_get_int(req->body, "term_months", &tenor);
    }

    if (principal < LOAN_MIN || principal > LOAN_MAX) {
        *status = 400;
        buf_printf(resp, "{\"success\":false,\"error\":\"Loan principal must be between %s and %s.\"}", fmt_money(LOAN_MIN), fmt_money(LOAN_MAX));
        return;
    }
    if (tenor < 6 || tenor > 84) {
        *status = 400;
        buf_append(resp, "{\"success\":false,\"error\":\"Loan tenor must be between 6 and 84 months.\"}");
        return;
    }

    uint32_t rate = loan_rate_bp(tenor);
    int64_t emi = calc_emi(principal, rate, tenor);
    int64_t fee = principal / 100;
    if (fee < LOAN_FEE_MIN) fee = LOAN_FEE_MIN;
    if (fee > LOAN_FEE_MAX) fee = LOAN_FEE_MAX;
    int64_t total_interest = emi * tenor - principal;

    *status = 200;
    buf_append(resp, "{\"success\":true,\"principal\":");
    buf_printf(resp, "%" PRId64, principal);
    buf_append(resp, ",\"principal_formatted\":");
    buf_append_json_str(resp, fmt_money(principal));
    buf_append(resp, ",\"tenor\":");
    buf_printf(resp, "%d", tenor);
    buf_append(resp, ",\"rate_bp\":");
    buf_printf(resp, "%u", rate);
    buf_append(resp, ",\"rate_formatted\":");
    buf_append_json_str(resp, fmt_rate(rate));
    buf_append(resp, ",\"emi\":");
    buf_printf(resp, "%" PRId64, emi);
    buf_append(resp, ",\"emi_formatted\":");
    buf_append_json_str(resp, fmt_money(emi));
    buf_append(resp, ",\"total_interest\":");
    buf_printf(resp, "%" PRId64, total_interest);
    buf_append(resp, ",\"total_interest_formatted\":");
    buf_append_json_str(resp, fmt_money(total_interest));
    buf_append(resp, ",\"processing_fee\":");
    buf_printf(resp, "%" PRId64, fee);
    buf_append(resp, ",\"processing_fee_formatted\":");
    buf_append_json_str(resp, fmt_money(fee));
    buf_append(resp, "}");
}

/* 20. Loan Apply */
static void api_loan_apply(Bank *b, const HttpRequest *req, HttpBuffer *resp, int *status) {
    if (!req->session || req->session->role != 1) {
        *status = 401;
        buf_append(resp, "{\"error\":\"Unauthorized\"}");
        return;
    }
    Account *a = find_account(b, req->session->account_number);
    if (!a || a->status != ST_ACTIVE) {
        *status = 400;
        buf_append(resp, "{\"success\":false,\"error\":\"Account must be active to apply for a loan.\"}");
        return;
    }
    Loan *ex = find_open_loan(b, a->number);
    if (ex) {
        *status = 400;
        buf_append(resp, "{\"success\":false,\"error\":\"You already have a pending or active loan.\"}");
        return;
    }

    int64_t principal = 0;
    int tenor = 0;
    if (!json_get_amount(req->body, "principal", &principal) || principal < LOAN_MIN || principal > LOAN_MAX) {
        *status = 400;
        buf_printf(resp, "{\"success\":false,\"error\":\"Principal must be between %s and %s.\"}", fmt_money(LOAN_MIN), fmt_money(LOAN_MAX));
        return;
    }
    if (!json_get_int(req->body, "tenor", &tenor)) {
        json_get_int(req->body, "term_months", &tenor);
    }
    if (tenor < 6 || tenor > 84) {
        *status = 400;
        buf_append(resp, "{\"success\":false,\"error\":\"Tenor must be between 6 and 84 months.\"}");
        return;
    }

    uint32_t rate = loan_rate_bp(tenor);
    int64_t emi = calc_emi(principal, rate, tenor);

    Loan ln;
    memset(&ln, 0, sizeof(ln));
    ln.id = b->next_loan_id++;
    ln.status = LN_PENDING;
    ln.account = a->number;
    ln.principal = ln.outstanding = principal;
    ln.emi = emi;
    ln.rate_bp = rate;
    ln.tenor = (uint16_t)tenor;
    ln.applied_at = now_ts();
    array_push((void **)&b->loan, &b->n_loan, &b->cap_loan, sizeof(Loan), &ln);
    b->dirty = true;
    audit("CUSTOMER", "Loan #%u applied: %s for %d months by %" PRIu64, ln.id, fmt_money(principal), tenor, a->number);
    persist(b);

    *status = 200;
    buf_printf(resp, "{\"success\":true,\"message\":\"Application #%u submitted for review.\",\"loan_id\":%u}", ln.id, ln.id);
}

/* 21. Loan Details */
static void api_loan_details(Bank *b, const HttpRequest *req, HttpBuffer *resp, int *status) {
    if (!req->session || req->session->role != 1) {
        *status = 401;
        buf_append(resp, "{\"error\":\"Unauthorized\"}");
        return;
    }
    Loan *l = find_open_loan(b, req->session->account_number);
    *status = 200;
    if (!l) {
        buf_append(resp, "{\"success\":true,\"has_loan\":false}");
        return;
    }
    buf_append(resp, "{\"success\":true,\"has_loan\":true,\"loan\":{\"id\":");
    buf_printf(resp, "%u", l->id);
    buf_append(resp, ",\"status\":");
    buf_append_json_str(resp, LOAN_STATUS_NAMES[l->status]);
    buf_append(resp, ",\"status_id\":");
    buf_printf(resp, "%u", (unsigned)l->status);
    buf_append(resp, ",\"principal\":");
    buf_printf(resp, "%" PRId64, l->principal);
    buf_append(resp, ",\"principal_formatted\":");
    buf_append_json_str(resp, fmt_money(l->principal));
    buf_append(resp, ",\"outstanding\":");
    buf_printf(resp, "%" PRId64, l->outstanding);
    buf_append(resp, ",\"outstanding_formatted\":");
    buf_append_json_str(resp, fmt_money(l->outstanding));
    buf_append(resp, ",\"emi\":");
    buf_printf(resp, "%" PRId64, l->emi);
    buf_append(resp, ",\"emi_formatted\":");
    buf_append_json_str(resp, fmt_money(l->emi));
    buf_append(resp, ",\"rate_bp\":");
    buf_printf(resp, "%u", l->rate_bp);
    buf_append(resp, ",\"rate_formatted\":");
    buf_append_json_str(resp, fmt_rate(l->rate_bp));
    buf_append(resp, ",\"tenor\":");
    buf_printf(resp, "%u", l->tenor);
    buf_append(resp, ",\"paid\":");
    buf_printf(resp, "%u", l->paid);
    buf_append(resp, ",\"applied_at\":");
    buf_printf(resp, "%" PRId64, l->applied_at);
    buf_append(resp, ",\"applied_date_formatted\":");
    buf_append_json_str(resp, fmt_date_ts(l->applied_at));
    buf_append(resp, ",\"approved_at\":");
    buf_printf(resp, "%" PRId64, l->approved_at);
    buf_append(resp, "}}");
}

/* 22. Loan Repayment Schedule */
static void api_loan_schedule(Bank *b, const HttpRequest *req, HttpBuffer *resp, int *status) {
    if (!req->session || req->session->role != 1) {
        *status = 401;
        buf_append(resp, "{\"error\":\"Unauthorized\"}");
        return;
    }
    Loan *l = find_open_loan(b, req->session->account_number);
    if (!l || l->status != LN_ACTIVE) {
        *status = 400;
        buf_append(resp, "{\"success\":false,\"error\":\"No active loan found.\"}");
        return;
    }

    int64_t out = l->outstanding;
    *status = 200;
    buf_append(resp, "{\"success\":true,\"schedule\":[");
    bool first = true;
    for (int m = l->paid + 1; m <= l->tenor && out > 0; m++) {
        int64_t interest = month_interest(out, l->rate_bp);
        int64_t pay = l->emi;
        if (m == l->tenor || pay >= out + interest) pay = out + interest;
        int64_t princ = pay - interest;
        out -= princ;
        if (!first) buf_append(resp, ",");
        first = false;
        buf_printf(resp, "{\"emi_no\":%d,\"payment\":%" PRId64 ",\"payment_formatted\":", m, pay);
        buf_append_json_str(resp, fmt_money(pay));
        buf_printf(resp, ",\"interest\":%" PRId64 ",\"interest_formatted\":", interest);
        buf_append_json_str(resp, fmt_money(interest));
        buf_printf(resp, ",\"principal\":%" PRId64 ",\"principal_formatted\":", princ);
        buf_append_json_str(resp, fmt_money(princ));
        buf_printf(resp, ",\"balance\":%" PRId64 ",\"balance_formatted\":", out);
        buf_append_json_str(resp, fmt_money(out));
        buf_append(resp, "}");
    }
    buf_append(resp, "]}");
}

/* 23. Loan Pay EMI */
static void api_loan_pay_emi(Bank *b, const HttpRequest *req, HttpBuffer *resp, int *status) {
    if (!req->session || req->session->role != 1) {
        *status = 401;
        buf_append(resp, "{\"error\":\"Unauthorized\"}");
        return;
    }
    Account *a = find_account(b, req->session->account_number);
    if (!a) { *status = 404; buf_append(resp, "{\"error\":\"Account not found\"}"); return; }

    Loan *l = find_open_loan(b, a->number);
    if (!l || l->status != LN_ACTIVE) {
        *status = 400;
        buf_append(resp, "{\"success\":false,\"error\":\"No active loan found to service.\"}");
        return;
    }

    int64_t interest = month_interest(l->outstanding, l->rate_bp);
    int64_t pay = l->emi;
    if (l->paid + 1 >= l->tenor || pay >= l->outstanding + interest) {
        pay = l->outstanding + interest;
    }

    const char *e = check_debit(a, pay);
    if (e) {
        *status = 400;
        buf_printf(resp, "{\"success\":false,\"error\":\"%s\"}", e);
        return;
    }

    l->outstanding -= (pay - interest);
    l->paid++;
    char note[NOTE_LEN];
    snprintf(note, sizeof(note), "Loan #%u EMI %u/%u", l->id, l->paid, l->tenor);
    Txn *t = post_txn(b, a, TX_EMI, -pay, 0, note);
    bool closed = false;
    if (l->outstanding <= 0) {
        l->outstanding = 0;
        l->status = LN_CLOSED;
        closed = true;
    }
    audit("CUSTOMER", "Loan #%u EMI %u/%u paid", l->id, l->paid, l->tenor);
    persist(b);

    *status = 200;
    buf_append(resp, "{\"success\":true,\"message\":");
    buf_append_json_str(resp, closed ? "Congratulations! Your loan is fully repaid." : "EMI payment successful.");
    buf_append(resp, ",\"closed\":");
    buf_append(resp, closed ? "true" : "false");
    buf_append(resp, ",\"receipt\":");
    json_append_receipt(resp, t);
    buf_append(resp, "}");
}

/* 24. Loan Foreclose Preview */
static void api_loan_foreclose_preview(Bank *b, const HttpRequest *req, HttpBuffer *resp, int *status) {
    if (!req->session || req->session->role != 1) {
        *status = 401;
        buf_append(resp, "{\"error\":\"Unauthorized\"}");
        return;
    }
    Loan *l = find_open_loan(b, req->session->account_number);
    if (!l || l->status != LN_ACTIVE) {
        *status = 400;
        buf_append(resp, "{\"success\":false,\"error\":\"No active loan found.\"}");
        return;
    }

    int64_t interest = month_interest(l->outstanding, l->rate_bp);
    int64_t pay = l->outstanding + interest;

    *status = 200;
    buf_append(resp, "{\"success\":true,\"outstanding\":");
    buf_printf(resp, "%" PRId64, l->outstanding);
    buf_append(resp, ",\"outstanding_formatted\":");
    buf_append_json_str(resp, fmt_money(l->outstanding));
    buf_append(resp, ",\"interest\":");
    buf_printf(resp, "%" PRId64, interest);
    buf_append(resp, ",\"interest_formatted\":");
    buf_append_json_str(resp, fmt_money(interest));
    buf_append(resp, ",\"payoff_amount\":");
    buf_printf(resp, "%" PRId64, pay);
    buf_append(resp, ",\"payoff_amount_formatted\":");
    buf_append_json_str(resp, fmt_money(pay));
    buf_append(resp, "}");
}

/* 25. Loan Foreclose Execution */
static void api_loan_foreclose(Bank *b, const HttpRequest *req, HttpBuffer *resp, int *status) {
    if (!req->session || req->session->role != 1) {
        *status = 401;
        buf_append(resp, "{\"error\":\"Unauthorized\"}");
        return;
    }
    Account *a = find_account(b, req->session->account_number);
    if (!a) { *status = 404; buf_append(resp, "{\"error\":\"Account not found\"}"); return; }

    Loan *l = find_open_loan(b, a->number);
    if (!l || l->status != LN_ACTIVE) {
        *status = 400;
        buf_append(resp, "{\"success\":false,\"error\":\"No active loan found.\"}");
        return;
    }

    char pin[32] = {0};
    json_get_str(req->body, "pin", pin, sizeof(pin));
    if (!pin[0] || !verify_pin(a, pin)) {
        *status = 401;
        buf_append(resp, "{\"success\":false,\"error\":\"PIN verification failed. Foreclosure cancelled.\"}");
        return;
    }

    int64_t interest = month_interest(l->outstanding, l->rate_bp);
    int64_t pay = l->outstanding + interest;

    const char *e = check_debit(a, pay);
    if (e) {
        *status = 400;
        buf_printf(resp, "{\"success\":false,\"error\":\"%s\"}", e);
        return;
    }

    char note[NOTE_LEN];
    snprintf(note, sizeof(note), "Loan #%u payoff", l->id);
    Txn *t = post_txn(b, a, TX_LOAN_CLOSE, -pay, 0, note);
    l->outstanding = 0;
    l->status = LN_CLOSED;
    audit("CUSTOMER", "Loan #%u foreclosed", l->id);
    persist(b);

    *status = 200;
    buf_append(resp, "{\"success\":true,\"message\":\"Loan fully repaid and closed.\",\"receipt\":");
    json_append_receipt(resp, t);
    buf_append(resp, "}");
}

/* 26. Admin Summary */
static void api_admin_summary(const Bank *b, HttpBuffer *resp, int *status) {
    size_t by_type[ACC_TYPE_COUNT] = {0}, by_status[4] = {0};
    int64_t deposits = 0, overdrawn = 0, fd_total = 0, loan_out = 0, loan_pending = 0;
    size_t fd_n = 0, loan_n = 0, pend_n = 0;

    for (size_t i = 0; i < b->n_acc; i++) {
        const Account *a = &b->acc[i];
        by_type[a->type]++;
        by_status[a->status]++;
        if (a->balance > 0) deposits += a->balance; else overdrawn += -a->balance;
    }
    for (size_t i = 0; i < b->n_fd; i++) {
        if (b->fd[i].status == FD_ACTIVE) { fd_total += b->fd[i].principal; fd_n++; }
    }
    for (size_t i = 0; i < b->n_loan; i++) {
        if (b->loan[i].status == LN_ACTIVE) { loan_out += b->loan[i].outstanding; loan_n++; }
        if (b->loan[i].status == LN_PENDING) { loan_pending += b->loan[i].principal; pend_n++; }
    }

    int today = ymd_of(now_ts());
    size_t tx_today = 0;
    int64_t volume = 0;
    for (size_t i = b->n_txn; i-- > 0;) {
        if (ymd_of(b->txn[i].timestamp) != today) break;
        tx_today++;
        volume += (b->txn[i].amount < 0 ? -b->txn[i].amount : b->txn[i].amount);
    }

    /* Ledger integrity check */
    size_t bad = 0;
    for (size_t i = 0; i < b->n_acc; i++) {
        int64_t sum = 0;
        for (size_t j = 0; j < b->n_txn; j++) {
            if (b->txn[j].account == b->acc[i].number) sum += b->txn[j].amount;
        }
        if (sum != b->acc[i].balance) bad++;
    }

    *status = 200;
    buf_append(resp, "{\"success\":true,\"summary\":{");
    buf_append(resp, "\"system_date\":");
    buf_append_json_str(resp, fmt_date_ts(now_ts()));
    buf_append(resp, ",\"simulated_offset_days\":");
    buf_printf(resp, "%d", b->offset_days);
    buf_append(resp, ",\"accounts\":{\"total\":");
    buf_printf(resp, "%zu", b->n_acc);
    buf_append(resp, ",\"savings\":");
    buf_printf(resp, "%zu", by_type[0]);
    buf_append(resp, ",\"current\":");
    buf_printf(resp, "%zu", by_type[1]);
    buf_append(resp, ",\"active\":");
    buf_printf(resp, "%zu", by_status[0]);
    buf_append(resp, ",\"frozen\":");
    buf_printf(resp, "%zu", by_status[1]);
    buf_append(resp, ",\"locked\":");
    buf_printf(resp, "%zu", by_status[2]);
    buf_append(resp, ",\"closed\":");
    buf_printf(resp, "%zu", by_status[3]);
    buf_append(resp, "},\"financials\":{");
    buf_append(resp, "\"customer_deposits\":");
    buf_printf(resp, "%" PRId64, deposits);
    buf_append(resp, ",\"customer_deposits_formatted\":");
    buf_append_json_str(resp, fmt_money(deposits));
    buf_append(resp, ",\"overdrawn\":");
    buf_printf(resp, "%" PRId64, overdrawn);
    buf_append(resp, ",\"overdrawn_formatted\":");
    buf_append_json_str(resp, fmt_money(overdrawn));
    buf_append(resp, ",\"fixed_deposits_total\":");
    buf_printf(resp, "%" PRId64, fd_total);
    buf_append(resp, ",\"fixed_deposits_total_formatted\":");
    buf_append_json_str(resp, fmt_money(fd_total));
    buf_append(resp, ",\"fixed_deposits_count\":");
    buf_printf(resp, "%zu", fd_n);
    buf_append(resp, ",\"loans_outstanding\":");
    buf_printf(resp, "%" PRId64, loan_out);
    buf_append(resp, ",\"loans_outstanding_formatted\":");
    buf_append_json_str(resp, fmt_money(loan_out));
    buf_append(resp, ",\"loans_count\":");
    buf_printf(resp, "%zu", loan_n);
    buf_append(resp, ",\"loans_pending_amount\":");
    buf_printf(resp, "%" PRId64, loan_pending);
    buf_append(resp, ",\"loans_pending_count\":");
    buf_printf(resp, "%zu", pend_n);
    buf_append(resp, "},\"ledger\":{");
    buf_append(resp, "\"total_entries\":");
    buf_printf(resp, "%zu", b->n_txn);
    buf_append(resp, ",\"today_entries\":");
    buf_printf(resp, "%zu", tx_today);
    buf_append(resp, ",\"today_volume\":");
    buf_printf(resp, "%" PRId64, volume);
    buf_append(resp, ",\"today_volume_formatted\":");
    buf_append_json_str(resp, fmt_money(volume));
    buf_append(resp, ",\"reconciliation_ok\":");
    buf_append(resp, bad == 0 ? "true" : "false");
    buf_append(resp, ",\"reconciliation_mismatches\":");
    buf_printf(resp, "%zu", bad);
    buf_append(resp, "}}}");
}

/* 27. Admin Open Account */
static void api_admin_open_account(Bank *b, const HttpRequest *req, HttpBuffer *resp, int *status) {
    char name[NAME_LEN + 8] = {0}, phone[32] = {0};
    int type = 0;
    int64_t dep = 0;

    json_get_str(req->body, "name", name, sizeof(name));
    json_get_str(req->body, "phone", phone, sizeof(phone));
    json_get_int(req->body, "type", &type);
    json_get_amount(req->body, "opening_deposit", &dep);

    str_trim(name);
    str_trim(phone);

    if (!valid_name(name)) {
        *status = 400;
        buf_append(resp, "{\"success\":false,\"error\":\"Invalid name. Letters, spaces, dots, hyphens (2-47 chars).\"}");
        return;
    }
    if (!valid_phone(phone)) {
        *status = 400;
        buf_append(resp, "{\"success\":false,\"error\":\"Invalid mobile number. 10 digits required.\"}");
        return;
    }
    if (type < 0 || type >= ACC_TYPE_COUNT) {
        *status = 400;
        buf_append(resp, "{\"success\":false,\"error\":\"Invalid account type (0=Savings, 1=Current).\"}");
        return;
    }
    if (dep < ACC_INFO[type].min_open) {
        *status = 400;
        buf_printf(resp, "{\"success\":false,\"error\":\"Minimum opening deposit for %s is %s %s.\"}",
                   ACC_INFO[type].name, CURRENCY, fmt_money(ACC_INFO[type].min_open));
        return;
    }
    if (dep > MAX_DEPOSIT) {
        *status = 400;
        buf_append(resp, "{\"success\":false,\"error\":\"Maximum single deposit limit exceeded.\"}");
        return;
    }

    Account a;
    memset(&a, 0, sizeof(a));
    uint64_t seq = b->next_acc_seq++;
    a.number = seq * 10 + (uint64_t)luhn_check_digit(seq);
    a.type = (uint8_t)type;
    a.status = ST_ACTIVE;
    a.pin_temp = 1;
    a.created = now_ts();
    str_copy(a.name, sizeof(a.name), name);
    str_copy(a.phone, sizeof(a.phone), phone);

    char temp_pin[8];
    make_temp_pin(temp_pin);
    set_pin(&a, temp_pin);

    Account *p = array_push((void **)&b->acc, &b->n_acc, &b->cap_acc, sizeof(Account), &a);
    Txn *t = post_txn(b, p, TX_OPENING, dep, 0, "Opening deposit");
    audit("ADMIN", "Opened %s account %" PRIu64 " for %s", ACC_INFO[type].name, p->number, name);
    persist(b);

    *status = 200;
    buf_append(resp, "{\"success\":true,\"message\":\"Account created successfully.\",\"account\":");
    json_append_account(resp, b, p, true);
    buf_append(resp, ",\"temp_pin\":");
    buf_append_json_str(resp, temp_pin);
    buf_append(resp, ",\"receipt\":");
    json_append_receipt(resp, t);
    buf_append(resp, "}");
}

/* 28. Admin Accounts List */
static void api_admin_accounts(const Bank *b, const HttpRequest *req, HttpBuffer *resp, int *status) {
    char filter[128] = {0};
    http_get_param(req->query, "search", filter, sizeof(filter));

    *status = 200;
    buf_append(resp, "{\"success\":true,\"accounts\":[");
    size_t count = 0;
    for (size_t i = 0; i < b->n_acc; i++) {
        const Account *a = &b->acc[i];
        char num[32];
        snprintf(num, sizeof(num), "%" PRIu64, a->number);
        if (filter[0] && !contains_ci(a->name, filter) && !contains_ci(a->phone, filter) && !contains_ci(num, filter)) {
            continue;
        }
        if (count > 0) buf_append(resp, ",");
        json_append_account(resp, b, a, true);
        count++;
    }
    buf_append(resp, "],\"count\":");
    buf_printf(resp, "%zu", count);
    buf_append(resp, "}");
}

/* 29. Admin Account Detail & Ledger */
static void api_admin_account_detail(const Bank *b, const HttpRequest *req, HttpBuffer *resp, int *status) {
    char s_num[32] = {0};
    if (!http_get_param(req->query, "number", s_num, sizeof(s_num))) {
        http_get_param(req->query, "account_number", s_num, sizeof(s_num));
    }
    uint64_t num = (uint64_t)strtoull(s_num, NULL, 10);

    const Account *a = find_account(b, num);
    if (!a) {
        *status = 404;
        buf_append(resp, "{\"success\":false,\"error\":\"Account not found\"}");
        return;
    }

    const Txn **arr = NULL;
    size_t n = collect_txns(b, a->number, 0, 99999999, &arr);

    *status = 200;
    buf_append(resp, "{\"success\":true,\"account\":");
    json_append_account(resp, b, a, true);
    buf_append(resp, ",\"transactions\":[");
    for (size_t i = 0; i < n; i++) {
        if (i > 0) buf_append(resp, ",");
        json_append_receipt(resp, arr[i]);
    }
    buf_append(resp, "]}");
    free(arr);
}

/* 30. Admin Freeze/Unfreeze */
static void api_admin_freeze(Bank *b, const HttpRequest *req, HttpBuffer *resp, int *status) {
    uint64_t num = 0;
    if (!json_get_uint64(req->body, "number", &num)) {
        char s_num[32];
        if (json_get_str(req->body, "number", s_num, sizeof(s_num))) num = (uint64_t)strtoull(s_num, NULL, 10);
    }
    Account *a = find_account(b, num);
    if (!a) { *status = 404; buf_append(resp, "{\"success\":false,\"error\":\"Account not found\"}"); return; }

    if (a->status == ST_ACTIVE) {
        a->status = ST_FROZEN;
        audit("ADMIN", "Froze account %" PRIu64, a->number);
        b->dirty = true;
        persist(b);
        *status = 200;
        buf_append(resp, "{\"success\":true,\"status\":\"Frozen\",\"message\":\"Account frozen (debits blocked).\"}");
    } else if (a->status == ST_FROZEN) {
        a->status = ST_ACTIVE;
        audit("ADMIN", "Unfroze account %" PRIu64, a->number);
        b->dirty = true;
        persist(b);
        *status = 200;
        buf_append(resp, "{\"success\":true,\"status\":\"Active\",\"message\":\"Account unfrozen.\" }");
    } else {
        *status = 400;
        buf_printf(resp, "{\"success\":false,\"error\":\"Only Active or Frozen accounts can be toggled (current status: %s).\"}", STATUS_NAMES[a->status]);
    }
}

/* 31. Admin Close Account */
static void api_admin_close_account(Bank *b, const HttpRequest *req, HttpBuffer *resp, int *status) {
    uint64_t num = 0;
    if (!json_get_uint64(req->body, "number", &num)) {
        char s_num[32];
        if (json_get_str(req->body, "number", s_num, sizeof(s_num))) num = (uint64_t)strtoull(s_num, NULL, 10);
    }
    Account *a = find_account(b, num);
    if (!a) { *status = 404; buf_append(resp, "{\"success\":false,\"error\":\"Account not found\"}"); return; }

    if (a->status == ST_CLOSED) {
        *status = 400;
        buf_append(resp, "{\"success\":false,\"error\":\"Account is already closed.\"}");
        return;
    }
    if (a->balance != 0) {
        *status = 400;
        buf_printf(resp, "{\"success\":false,\"error\":\"Account balance must be zero before closing (current: %s %s).\"}", CURRENCY, fmt_money(a->balance));
        return;
    }
    if (find_open_loan(b, a->number)) {
        *status = 400;
        buf_append(resp, "{\"success\":false,\"error\":\"Account has an active or pending loan.\"}");
        return;
    }
    if (active_fd_count(b, a->number)) {
        *status = 400;
        buf_append(resp, "{\"success\":false,\"error\":\"Account has active fixed deposits.\"}");
        return;
    }

    a->status = ST_CLOSED;
    b->dirty = true;
    audit("ADMIN", "Closed account %" PRIu64, a->number);
    persist(b);

    *status = 200;
    buf_append(resp, "{\"success\":true,\"message\":\"Account closed successfully.\"}");
}

/* 32. Admin Reset PIN */
static void api_admin_reset_pin(Bank *b, const HttpRequest *req, HttpBuffer *resp, int *status) {
    uint64_t num = 0;
    if (!json_get_uint64(req->body, "number", &num) && !json_get_uint64(req->body, "account_number", &num)) {
        char s_num[32];
        if (json_get_str(req->body, "number", s_num, sizeof(s_num)) || json_get_str(req->body, "account_number", s_num, sizeof(s_num))) {
            num = (uint64_t)strtoull(s_num, NULL, 10);
        }
    }
    Account *a = find_account(b, num);
    if (!a || a->status == ST_CLOSED) {
        *status = 400;
        buf_append(resp, "{\"success\":false,\"error\":\"Account not found or closed.\"}");
        return;
    }

    char pin[8];
    make_temp_pin(pin);
    set_pin(a, pin);
    a->pin_temp = 1;
    a->failed_attempts = 0;
    if (a->status == ST_LOCKED) a->status = ST_ACTIVE;
    b->dirty = true;
    audit("ADMIN", "Reset PIN for account %" PRIu64, a->number);
    persist(b);

    *status = 200;
    buf_append(resp, "{\"success\":true,\"message\":\"PIN reset and account unlocked.\",\"temp_pin\":");
    buf_append_json_str(resp, pin);
    buf_append(resp, ",\"temporary_pin\":");
    buf_append_json_str(resp, pin);
    buf_append(resp, "}");
}

/* 33. Admin Pending Loans */
static void api_admin_pending_loans(const Bank *b, HttpBuffer *resp, int *status) {
    *status = 200;
    buf_append(resp, "{\"success\":true,\"loans\":[");
    size_t count = 0;
    for (size_t i = 0; i < b->n_loan; i++) {
        const Loan *l = &b->loan[i];
        if (l->status != LN_PENDING) continue;
        const Account *a = find_account(b, l->account);
        if (count > 0) buf_append(resp, ",");
        buf_append(resp, "{\"id\":");
        buf_printf(resp, "%u", l->id);
        buf_append(resp, ",\"account\":");
        buf_printf(resp, "%" PRIu64, l->account);
        buf_append(resp, ",\"applicant_name\":");
        buf_append_json_str(resp, a ? a->name : "Unknown");
        buf_append(resp, ",\"principal\":");
        buf_printf(resp, "%" PRId64, l->principal);
        buf_append(resp, ",\"principal_formatted\":");
        buf_append_json_str(resp, fmt_money(l->principal));
        buf_append(resp, ",\"tenor\":");
        buf_printf(resp, "%u", l->tenor);
        buf_append(resp, ",\"rate_bp\":");
        buf_printf(resp, "%u", l->rate_bp);
        buf_append(resp, ",\"rate_formatted\":");
        buf_append_json_str(resp, fmt_rate(l->rate_bp));
        buf_append(resp, ",\"emi\":");
        buf_printf(resp, "%" PRId64, l->emi);
        buf_append(resp, ",\"emi_formatted\":");
        buf_append_json_str(resp, fmt_money(l->emi));
        buf_append(resp, ",\"applied_at\":");
        buf_printf(resp, "%" PRId64, l->applied_at);
        buf_append(resp, ",\"applied_date_formatted\":");
        buf_append_json_str(resp, fmt_date_ts(l->applied_at));
        buf_append(resp, "}");
        count++;
    }
    buf_append(resp, "],\"count\":");
    buf_printf(resp, "%zu", count);
    buf_append(resp, "}");
}

/* 34. Admin Review Loan */
static void api_admin_review_loan(Bank *b, const HttpRequest *req, HttpBuffer *resp, int *status) {
    uint32_t id = 0;
    int id_int = 0;
    if (json_get_int(req->body, "loan_id", &id_int)) id = (uint32_t)id_int;

    char action[32] = {0};
    json_get_str(req->body, "action", action, sizeof(action));

    Loan *l = find_loan_by_id(b, id);
    if (!l || l->status != LN_PENDING) {
        *status = 404;
        buf_append(resp, "{\"success\":false,\"error\":\"Pending loan application not found.\"}");
        return;
    }

    Account *a = find_account(b, l->account);
    if (!a || a->status != ST_ACTIVE) {
        *status = 400;
        buf_append(resp, "{\"success\":false,\"error\":\"Applicant account is not active.\"}");
        return;
    }

    if (strcmp(action, "approve") == 0) {
        int64_t fee = l->principal / 100;
        if (fee < LOAN_FEE_MIN) fee = LOAN_FEE_MIN;
        if (fee > LOAN_FEE_MAX) fee = LOAN_FEE_MAX;

        char note[NOTE_LEN];
        snprintf(note, sizeof(note), "Loan #%u disbursed", l->id);
        post_txn(b, a, TX_LOAN_DISBURSE, l->principal, 0, note);
        snprintf(note, sizeof(note), "Loan #%u fee", l->id);
        post_txn(b, a, TX_FEE, -fee, 0, note);

        l->status = LN_ACTIVE;
        l->approved_at = now_ts();
        audit("ADMIN", "Approved loan #%u (%s) for account %" PRIu64, l->id, fmt_money(l->principal), a->number);
        persist(b);

        *status = 200;
        buf_printf(resp, "{\"success\":true,\"message\":\"Loan #%u approved and disbursed. Fee %s %s deducted.\"}", l->id, CURRENCY, fmt_money(fee));
    } else if (strcmp(action, "reject") == 0) {
        l->status = LN_REJECTED;
        b->dirty = true;
        audit("ADMIN", "Rejected loan #%u", l->id);
        persist(b);

        *status = 200;
        buf_printf(resp, "{\"success\":true,\"message\":\"Loan #%u rejected.\"}", l->id);
    } else {
        *status = 400;
        buf_append(resp, "{\"success\":false,\"error\":\"Action must be 'approve' or 'reject'.\"}");
    }
}

/* 35. Admin Post Monthly Interest */
static void api_admin_post_interest(Bank *b, HttpBuffer *resp, int *status) {
    uint32_t ym = (uint32_t)(ymd_of(now_ts()) / 100);
    if (b->last_interest_ym == ym) {
        *status = 400;
        buf_printf(resp, "{\"success\":false,\"error\":\"Interest for %u-%02u has already been posted.\"}", ym / 100, ym % 100);
        return;
    }

    size_t count = 0;
    int64_t total = 0;
    for (size_t i = 0; i < b->n_acc; i++) {
        Account *a = &b->acc[i];
        if (a->status != ST_ACTIVE || a->type != ACC_SAVINGS || a->balance <= 0) continue;
        int64_t interest = (a->balance * (int64_t)info_of(a)->rate_bp + 60000) / 120000;
        if (interest <= 0) continue;
        post_txn(b, a, TX_INTEREST, interest, 0, "Monthly interest");
        total += interest;
        count++;
    }
    b->last_interest_ym = ym;
    b->dirty = true;
    audit("ADMIN", "Posted interest %u-%02u: %zu accounts, total %s", ym / 100, ym % 100, count, fmt_money(total));
    persist(b);

    *status = 200;
    buf_append(resp, "{\"success\":true,\"accounts_credited\":");
    buf_printf(resp, "%zu", count);
    buf_append(resp, ",\"total_amount\":");
    buf_printf(resp, "%" PRId64, total);
    buf_append(resp, ",\"total_amount_formatted\":");
    buf_append_json_str(resp, fmt_money(total));
    buf_append(resp, ",\"year_month\":");
    buf_printf(resp, "\"%u-%02u\"", ym / 100, ym % 100);
    buf_append(resp, "}");
}

/* 36. Admin Audit Log */
static void api_admin_audit(HttpBuffer *resp, int *status) {
    FILE *f = fopen(g_audit_path, "r");
    if (!f) {
        *status = 200;
        buf_append(resp, "{\"success\":true,\"entries\":[],\"total\":0}");
        return;
    }
    enum { KEEP = 60 };
    static char ring[KEEP][256];
    size_t n = 0;
    while (fgets(ring[n % KEEP], sizeof(ring[0]), f)) n++;
    fclose(f);

    *status = 200;
    buf_append(resp, "{\"success\":true,\"entries\":[");
    size_t start = n > KEEP ? n - KEEP : 0;
    for (size_t i = start; i < n; i++) {
        if (i > start) buf_append(resp, ",");
        char line[256];
        str_copy(line, sizeof(line), ring[i % KEEP]);
        str_trim(line);
        buf_append_json_str(resp, line);
    }
    buf_append(resp, "],\"total\":");
    buf_printf(resp, "%zu", n);
    buf_append(resp, "}");
}

/* 37. Admin Advance Clock */
static void api_admin_advance_clock(Bank *b, const HttpRequest *req, HttpBuffer *resp, int *status) {
    int days = 0;
    json_get_int(req->body, "days", &days);
    if (days < 1 || days > 3650) {
        *status = 400;
        buf_append(resp, "{\"success\":false,\"error\":\"Days to advance must be between 1 and 3650.\"}");
        return;
    }

    b->offset_days += days;
    g_offset_days = b->offset_days;
    b->dirty = true;
    audit("ADMIN", "Advanced system clock by %d day(s); date is now %s", days, fmt_date_ts(now_ts()));
    persist(b);

    *status = 200;
    buf_append(resp, "{\"success\":true,\"offset_days\":");
    buf_printf(resp, "%d", b->offset_days);
    buf_append(resp, ",\"system_date\":");
    buf_append_json_str(resp, fmt_date_ts(now_ts()));
    buf_append(resp, "}");
}

/* 38. Admin Change Password */
static void api_admin_change_password(Bank *b, const HttpRequest *req, HttpBuffer *resp, int *status) {
    char cur[64] = {0}, p1[64] = {0}, p2[64] = {0};
    json_get_str(req->body, "current_password", cur, sizeof(cur));
    json_get_str(req->body, "new_password", p1, sizeof(p1));
    json_get_str(req->body, "confirm_password", p2, sizeof(p2));

    if (!verify_admin_password(b, cur)) {
        *status = 400;
        buf_append(resp, "{\"success\":false,\"error\":\"Current admin password is incorrect.\"}");
        return;
    }
    if (p2[0] && strcmp(p1, p2) != 0) {
        *status = 400;
        buf_append(resp, "{\"success\":false,\"error\":\"New passwords do not match.\"}");
        return;
    }

    bool letter = false, digit = false;
    for (const char *p = p1; *p; p++) {
        if (isalpha((unsigned char)*p)) letter = true;
        if (isdigit((unsigned char)*p)) digit = true;
    }
    if (strlen(p1) < 8 || !letter || !digit || strcmp(p1, DEFAULT_ADMIN_PW) == 0) {
        *status = 400;
        buf_append(resp, "{\"success\":false,\"error\":\"New password must be at least 8 characters with both letters and digits, and cannot be default.\"}");
        return;
    }

    set_admin_password(b, p1);
    audit("ADMIN", "Admin password changed");
    persist(b);

    *status = 200;
    buf_append(resp, "{\"success\":true,\"message\":\"Administrator password updated successfully.\"}");
}

/* --- HTTP Request Router --- */

static void handle_http_request(Bank *b, SOCKET client, const char *raw_req, size_t raw_len) {
    HttpRequest req;
    memset(&req, 0, sizeof(req));

    /* Parse request line */
    const char *sp1 = strchr(raw_req, ' ');
    if (!sp1) { http_send_json(client, 400, "{\"error\":\"Malformed request\"}"); return; }
    size_t mlen = (size_t)(sp1 - raw_req);
    if (mlen >= sizeof(req.method)) mlen = sizeof(req.method) - 1;
    memcpy(req.method, raw_req, mlen);
    req.method[mlen] = '\0';

    const char *pstart = sp1 + 1;
    while (*pstart == ' ') pstart++;
    const char *sp2 = strchr(pstart, ' ');
    if (!sp2) { http_send_json(client, 400, "{\"error\":\"Malformed path\"}"); return; }
    size_t plen = (size_t)(sp2 - pstart);
    char full_path[512];
    if (plen >= sizeof(full_path)) plen = sizeof(full_path) - 1;
    memcpy(full_path, pstart, plen);
    full_path[plen] = '\0';

    char *qmark = strchr(full_path, '?');
    if (qmark) {
        *qmark = '\0';
        str_copy(req.query, sizeof(req.query), qmark + 1);
    }
    str_copy(req.path, sizeof(req.path), full_path);

    /* Headers scan */
    const char *hdr_end = strstr(raw_req, "\r\n\r\n");
    size_t content_len = 0;
    if (hdr_end) {
        const char *p = raw_req;
        while (p < hdr_end) {
            const char *eol = strstr(p, "\r\n");
            if (!eol || eol > hdr_end) break;
            if (strncasecmp(p, "Content-Length:", 15) == 0) {
                content_len = (size_t)strtoul(p + 15, NULL, 10);
            } else if (strncasecmp(p, "Authorization:", 14) == 0) {
                const char *val = p + 14;
                while (*val == ' ') val++;
                if (strncasecmp(val, "Bearer ", 7) == 0) {
                    val += 7;
                    while (*val == ' ') val++;
                    size_t tlen = (size_t)(eol - val);
                    if (tlen >= sizeof(req.token)) tlen = sizeof(req.token) - 1;
                    memcpy(req.token, val, tlen);
                    req.token[tlen] = '\0';
                    str_trim(req.token);
                }
            } else if (strncasecmp(p, "X-Session-Token:", 16) == 0) {
                const char *val = p + 16;
                while (*val == ' ') val++;
                size_t tlen = (size_t)(eol - val);
                if (tlen >= sizeof(req.token)) tlen = sizeof(req.token) - 1;
                memcpy(req.token, val, tlen);
                req.token[tlen] = '\0';
                str_trim(req.token);
            }
            p = eol + 2;
        }

        const char *body_start = hdr_end + 4;
        size_t b_avail = raw_len - (size_t)(body_start - raw_req);
        if (content_len > 0 && b_avail > content_len) b_avail = content_len;
        req.body_len = b_avail;
        req.body = (char *)malloc(b_avail + 1);
        if (req.body) {
            memcpy(req.body, body_start, b_avail);
            req.body[b_avail] = '\0';
        }
    }

    if (req.token[0]) req.session = session_lookup(req.token);

    /* Handle OPTIONS */
    if (strcmp(req.method, "OPTIONS") == 0) {
        http_send_raw(client, 204, "No Content", "text/plain", NULL, NULL, 0);
        if (req.body) free(req.body);
        return;
    }

    /* Handle Static Files */
    if (strcmp(req.method, "GET") == 0) {
        if (strcmp(req.path, "/") == 0 || strcmp(req.path, "/index.html") == 0) {
            http_send_file(client, "index.html", "text/html; charset=utf-8");
            if (req.body) free(req.body);
            return;
        }
        if (strcmp(req.path, "/style.css") == 0) {
            http_send_file(client, "style.css", "text/css; charset=utf-8");
            if (req.body) free(req.body);
            return;
        }
        if (strcmp(req.path, "/app.js") == 0) {
            http_send_file(client, "app.js", "application/javascript; charset=utf-8");
            if (req.body) free(req.body);
            return;
        }
        if (strcmp(req.path, "/favicon.ico") == 0) {
            http_send_raw(client, 204, "No Content", "image/x-icon", NULL, NULL, 0);
            if (req.body) free(req.body);
            return;
        }
    }

    /* API Router */
    HttpBuffer resp;
    buf_init(&resp);
    int status = 404;

    if (strcmp(req.method, "POST") == 0 && strcmp(req.path, "/api/auth/customer-login") == 0) {
        api_auth_customer_login(b, &req, &resp, &status);
    } else if (strcmp(req.method, "POST") == 0 && strcmp(req.path, "/api/auth/admin-login") == 0) {
        api_auth_admin_login(b, &req, &resp, &status);
    } else if (strcmp(req.method, "GET") == 0 && strcmp(req.path, "/api/auth/session") == 0) {
        api_auth_session(b, &req, &resp, &status);
    } else if (strcmp(req.method, "POST") == 0 && strcmp(req.path, "/api/auth/logout") == 0) {
        api_auth_logout(&req, &resp, &status);
    }
    /* Customer Endpoints */
    else if (strcmp(req.method, "GET") == 0 && strcmp(req.path, "/api/customer/dashboard") == 0) {
        api_customer_dashboard(b, &req, &resp, &status);
    } else if (strcmp(req.method, "POST") == 0 && strcmp(req.path, "/api/customer/deposit") == 0) {
        api_customer_deposit(b, &req, &resp, &status);
    } else if (strcmp(req.method, "POST") == 0 && strcmp(req.path, "/api/customer/withdraw") == 0) {
        api_customer_withdraw(b, &req, &resp, &status);
    } else if (strcmp(req.method, "POST") == 0 && strcmp(req.path, "/api/customer/transfer/preview") == 0) {
        api_customer_transfer_preview(b, &req, &resp, &status);
    } else if (strcmp(req.method, "POST") == 0 && strcmp(req.path, "/api/customer/transfer") == 0) {
        api_customer_transfer(b, &req, &resp, &status);
    } else if (strcmp(req.method, "GET") == 0 && strcmp(req.path, "/api/customer/statement") == 0) {
        api_customer_statement(b, &req, &resp, &status);
    } else if (strcmp(req.method, "GET") == 0 && strcmp(req.path, "/api/customer/statement/csv") == 0) {
        api_customer_statement_csv(b, &req, client);
        buf_free(&resp);
        if (req.body) free(req.body);
        return;
    } else if (strcmp(req.method, "POST") == 0 && strcmp(req.path, "/api/customer/change-pin") == 0) {
        api_customer_change_pin(b, &req, &resp, &status);
    } else if (strcmp(req.method, "GET") == 0 && strcmp(req.path, "/api/customer/fd/rates") == 0) {
        api_fd_rates(&resp, &status);
    } else if (strcmp(req.method, "POST") == 0 && strcmp(req.path, "/api/customer/fd/calculate") == 0) {
        api_fd_calculate(&req, &resp, &status);
    } else if (strcmp(req.method, "POST") == 0 && strcmp(req.path, "/api/customer/fd/open") == 0) {
        api_fd_open(b, &req, &resp, &status);
    } else if (strcmp(req.method, "GET") == 0 && strcmp(req.path, "/api/customer/fd/list") == 0) {
        api_fd_list(b, &req, &resp, &status);
    } else if (strcmp(req.method, "POST") == 0 && strcmp(req.path, "/api/customer/fd/close-preview") == 0) {
        api_fd_close_preview(b, &req, &resp, &status);
    } else if (strcmp(req.method, "POST") == 0 && strcmp(req.path, "/api/customer/fd/close") == 0) {
        api_fd_close(b, &req, &resp, &status);
    } else if (strcmp(req.method, "POST") == 0 && strcmp(req.path, "/api/customer/loan/calculate") == 0) {
        api_loan_calculate(&req, &resp, &status);
    } else if (strcmp(req.method, "POST") == 0 && strcmp(req.path, "/api/customer/loan/apply") == 0) {
        api_loan_apply(b, &req, &resp, &status);
    } else if (strcmp(req.method, "GET") == 0 && strcmp(req.path, "/api/customer/loan/details") == 0) {
        api_loan_details(b, &req, &resp, &status);
    } else if (strcmp(req.method, "GET") == 0 && strcmp(req.path, "/api/customer/loan/schedule") == 0) {
        api_loan_schedule(b, &req, &resp, &status);
    } else if (strcmp(req.method, "POST") == 0 && strcmp(req.path, "/api/customer/loan/pay-emi") == 0) {
        api_loan_pay_emi(b, &req, &resp, &status);
    } else if (strcmp(req.method, "POST") == 0 && strcmp(req.path, "/api/customer/loan/foreclose-preview") == 0) {
        api_loan_foreclose_preview(b, &req, &resp, &status);
    } else if (strcmp(req.method, "POST") == 0 && strcmp(req.path, "/api/customer/loan/foreclose") == 0) {
        api_loan_foreclose(b, &req, &resp, &status);
    }
    /* Admin Endpoints (Require Admin Session) */
    else if (strncmp(req.path, "/api/admin/", 11) == 0) {
        if (!req.session || req.session->role != 2) {
            status = 401;
            buf_append(&resp, "{\"error\":\"Administrator authorization required.\"}");
        } else if (strcmp(req.method, "GET") == 0 && strcmp(req.path, "/api/admin/summary") == 0) {
            api_admin_summary(b, &resp, &status);
        } else if (strcmp(req.method, "POST") == 0 && strcmp(req.path, "/api/admin/accounts/open") == 0) {
            api_admin_open_account(b, &req, &resp, &status);
        } else if (strcmp(req.method, "GET") == 0 && strcmp(req.path, "/api/admin/accounts") == 0) {
            api_admin_accounts(b, &req, &resp, &status);
        } else if (strcmp(req.method, "GET") == 0 && strcmp(req.path, "/api/admin/accounts/detail") == 0) {
            api_admin_account_detail(b, &req, &resp, &status);
        } else if (strcmp(req.method, "POST") == 0 && strcmp(req.path, "/api/admin/accounts/freeze") == 0) {
            api_admin_freeze(b, &req, &resp, &status);
        } else if (strcmp(req.method, "POST") == 0 && strcmp(req.path, "/api/admin/accounts/close") == 0) {
            api_admin_close_account(b, &req, &resp, &status);
        } else if (strcmp(req.method, "POST") == 0 && strcmp(req.path, "/api/admin/accounts/reset-pin") == 0) {
            api_admin_reset_pin(b, &req, &resp, &status);
        } else if (strcmp(req.method, "GET") == 0 && strcmp(req.path, "/api/admin/loans/pending") == 0) {
            api_admin_pending_loans(b, &resp, &status);
        } else if (strcmp(req.method, "POST") == 0 && strcmp(req.path, "/api/admin/loans/review") == 0) {
            api_admin_review_loan(b, &req, &resp, &status);
        } else if (strcmp(req.method, "POST") == 0 && strcmp(req.path, "/api/admin/interest/post") == 0) {
            api_admin_post_interest(b, &resp, &status);
        } else if (strcmp(req.method, "GET") == 0 && strcmp(req.path, "/api/admin/audit") == 0) {
            api_admin_audit(&resp, &status);
        } else if (strcmp(req.method, "POST") == 0 && strcmp(req.path, "/api/admin/clock/advance") == 0) {
            api_admin_advance_clock(b, &req, &resp, &status);
        } else if (strcmp(req.method, "POST") == 0 && strcmp(req.path, "/api/admin/change-password") == 0) {
            api_admin_change_password(b, &req, &resp, &status);
        } else {
            status = 404;
            buf_append(&resp, "{\"error\":\"Unknown admin endpoint\"}");
        }
    } else {
        status = 404;
        buf_append(&resp, "{\"error\":\"Endpoint not found\"}");
    }

    http_send_json(client, status, resp.data ? resp.data : "{}");
    buf_free(&resp);
    if (req.body) free(req.body);
}

/* --- Server Main Loop --- */

static volatile sig_atomic_t g_server_running = 1;

static void server_sigint_handler(int sig) {
    (void)sig;
    g_server_running = 0;
}

static void run_http_server(Bank *b, const char *host, int port) {
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        ERR("WSAStartup failed: %d", WSAGetLastError());
        return;
    }
#endif

    SOCKET server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock == INVALID_SOCKET) {
        ERR("Failed to create socket");
#ifdef _WIN32
        WSACleanup();
#endif
        return;
    }

    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons((uint16_t)port);
    sin.sin_addr.s_addr = inet_addr(host);

    if (bind(server_sock, (struct sockaddr *)&sin, sizeof(sin)) == SOCKET_ERROR) {
        ERR("Failed to bind to %s:%d: %s", host, port, strerror(errno));
        close_socket(server_sock);
#ifdef _WIN32
        WSACleanup();
#endif
        return;
    }

    if (listen(server_sock, 16) == SOCKET_ERROR) {
        ERR("Failed to listen on socket");
        close_socket(server_sock);
#ifdef _WIN32
        WSACleanup();
#endif
        return;
    }

    signal(SIGINT, server_sigint_handler);
    signal(SIGTERM, server_sigint_handler);

    printf("\n");
    print_rule('=');
    printf("   %s  v%s  [Web Engine Active]\n", APP_NAME, APP_VERSION);
    print_rule('=');
    printf("  Listening on : http://%s:%d\n", host, port);
    printf("  Data file    : %s\n", g_data_path);
    printf("  Audit log    : %s\n", g_audit_path);
    printf("  Status       : Ready for browser requests\n");
    print_rule('-');
    printf("  Open http://%s:%d in your web browser.\n", host, port);
    printf("  (Press Ctrl+C to stop the server)\n\n");
    fflush(stdout);

#ifdef _WIN32
    system("start http://127.0.0.1:8080");
#elif defined(__APPLE__)
    system("open http://127.0.0.1:8080");
#else
    system("xdg-open http://127.0.0.1:8080 >/dev/null 2>&1 &");
#endif

    while (g_server_running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        SOCKET client = accept(server_sock, (struct sockaddr *)&client_addr, &client_len);
        if (client == INVALID_SOCKET) {
            if (!g_server_running) break;
            continue;
        }

        /* Read complete HTTP request including body */
        char req_buf[65536];
        int total_read = 0;
        int expected_len = -1;

        while (total_read < (int)sizeof(req_buf) - 1) {
            int n_read = recv(client, req_buf + total_read, (int)sizeof(req_buf) - 1 - total_read, 0);
            if (n_read <= 0) break;
            total_read += n_read;
            req_buf[total_read] = '\0';

            char *hdr_end = strstr(req_buf, "\r\n\r\n");
            if (hdr_end) {
                if (expected_len < 0) {
                    char *cl = strstr(req_buf, "Content-Length:");
                    if (!cl) cl = strstr(req_buf, "content-length:");
                    if (cl) {
                        expected_len = atoi(cl + 15);
                    } else {
                        expected_len = 0;
                    }
                }
                int body_len = total_read - (int)(hdr_end + 4 - req_buf);
                if (body_len >= expected_len) {
                    break;
                }
            }
        }

        if (total_read > 0) {
            handle_http_request(b, client, req_buf, (size_t)total_read);
        }
        close_socket(client);
    }

    printf("\nShutting down server and persisting data...\n");
    persist(b);
    close_socket(server_sock);
#ifdef _WIN32
    WSACleanup();
#endif
    printf("Server stopped cleanly.\n");
}


/* ------------------------------------------------------------------------- */
/*  Main                                                                     */
/* ------------------------------------------------------------------------- */

static void usage(const char *prog)
{
    printf("%s v%s\n\nUsage: %s [options]\n"
           "  -f, --file PATH   Data file (default %s)\n"
           "  -p, --port PORT   HTTP server port (default 8080)\n"
           "      --cli         Run interactive terminal menu instead of HTTP server\n"
           "      --no-color    Disable ANSI colours\n"
           "  -h, --help        Show this help\n",
           APP_NAME, APP_VERSION, prog, DEFAULT_DATA_FILE);
}

int main(int argc, char **argv)
{
    bool want_color = true;
    bool force_cli = false;
    int port = 8080;
    const char *env_port = getenv("PORT");
    if (env_port) {
        int p = atoi(env_port);
        if (p > 0 && p <= 65535) port = p;
    }
    const char *host = "0.0.0.0";

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) { usage(argv[0]); return 0; }
        if (!strcmp(argv[i], "--no-color")) { want_color = false; continue; }
        if (!strcmp(argv[i], "--cli") || !strcmp(argv[i], "--terminal")) { force_cli = true; continue; }
        if ((!strcmp(argv[i], "-p") || !strcmp(argv[i], "--port")) && i + 1 < argc) {
            port = atoi(argv[++i]);
            if (port <= 0 || port > 65535) port = 8080;
            continue;
        }
        if ((!strcmp(argv[i], "-f") || !strcmp(argv[i], "--file")) && i + 1 < argc) {
            g_data_path = argv[++i];
            continue;
        }
        fprintf(stderr, "Unknown or incomplete option: %s\n", argv[i]);
        usage(argv[0]);
        return 2;
    }
    g_color = want_color && isatty(STDOUT_FILENO) && !getenv("NO_COLOR");
    snprintf(g_audit_path, sizeof(g_audit_path), "%s.audit.log", g_data_path);
    signal(SIGINT, restore_terminal_and_exit);
    signal(SIGTERM, restore_terminal_and_exit);

    Bank bank;
    bank_init(&bank);
    char err[160];
    LoadResult lr = bank_load(&bank, g_data_path, err, sizeof(err));
    if (lr == LOAD_ERR) {
        fprintf(stderr, "Error: %s\nThe file was NOT modified. A backup may exist at %s.bak\n", err, g_data_path);
        bank_free(&bank);
        return 1;
    }
    if (lr == LOAD_NEW) {
        printf("No data file found - creating a new bank at '%s'.\n", g_data_path);
        set_admin_password(&bank, DEFAULT_ADMIN_PW);
        audit("SYSTEM", "New bank database initialised");
        persist(&bank);
    }

    if (!force_cli) {
        run_http_server(&bank, host, port);
    } else {
        for (;;) {
            printf("\n%s", CLR(C_CYAN));
            print_rule('=');
            printf("   %s  v%s\n", APP_NAME, APP_VERSION);
            print_rule('=');
            printf("%s 1) Customer login\n 2) Administrator login\n 0) Exit\n", CLR(C_RESET));
            char buf[16];
            if (!read_line("\nSelect: ", buf, sizeof(buf))) break;
            int c = atoi(buf);
            if (c == 1) customer_login(&bank);
            else if (c == 2) admin_login(&bank);
            else if (c == 0 && buf[0] == '0') break;
            else ERR("Please choose 1, 2 or 0.");
            persist(&bank);
        }
    }

    persist(&bank);
    bank_free(&bank);
    puts("\nThank you for banking with us. Goodbye!");
    return 0;
}
