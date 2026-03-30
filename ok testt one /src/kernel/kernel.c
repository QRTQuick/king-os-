typedef unsigned char  uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int   uint32_t;
typedef unsigned int   size_t;

#define VGA_WIDTH 80
#define VGA_HEIGHT 25
#define INPUT_MAX 220
#define MAX_FINDINGS 10

static uint16_t* const VGA = (uint16_t*)0xB8000;
static uint8_t color = 0x02; /* green on black */
static size_t row = 0;
static size_t col = 0;

static char input_buf[INPUT_MAX];
static size_t input_len = 0;
static int mode_api = 0;
static int risk_score = 0;
static const char* verdict = "READY";
static char findings[MAX_FINDINGS][72];
static int finding_count = 0;

static inline uint8_t inb(uint16_t port) {
    uint8_t value;
    __asm__ volatile ("inb %1, %0" : "=a"(value) : "Nd"(port));
    return value;
}

static void outb(uint16_t port, uint8_t value) {
    __asm__ volatile ("outb %0, %1" : : "a"(value), "Nd"(port));
}

static size_t strlen(const char* s) {
    size_t n = 0;
    while (s[n]) n++;
    return n;
}

static int strncmp(const char* a, const char* b, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) {
        if (a[i] != b[i] || a[i] == 0 || b[i] == 0) return (unsigned char)a[i] - (unsigned char)b[i];
    }
    return 0;
}

static int starts_with(const char* s, const char* pfx) {
    return strncmp(s, pfx, strlen(pfx)) == 0;
}

static int is_digit(char c) {
    return c >= '0' && c <= '9';
}

static const char* strchr(const char* s, char c) {
    while (*s) {
        if (*s == c) return s;
        s++;
    }
    return 0;
}

static char* strstr(const char* haystack, const char* needle) {
    size_t i;
    size_t j;
    if (!*needle) return (char*)haystack;
    for (i = 0; haystack[i]; i++) {
        for (j = 0; needle[j] && haystack[i + j] == needle[j]; j++) { }
        if (!needle[j]) return (char*)&haystack[i];
    }
    return 0;
}

static int ends_with(const char* s, const char* suf) {
    size_t a = strlen(s);
    size_t b = strlen(suf);
    if (b > a) return 0;
    return strncmp(s + (a - b), suf, b) == 0;
}

static void clear_screen(void) {
    size_t y;
    size_t x;
    for (y = 0; y < VGA_HEIGHT; y++) {
        for (x = 0; x < VGA_WIDTH; x++) {
            VGA[y * VGA_WIDTH + x] = (uint16_t)' ' | ((uint16_t)color << 8);
        }
    }
    row = 0;
    col = 0;
}

static void putc(char c) {
    if (c == '\n') {
        col = 0;
        row++;
        if (row >= VGA_HEIGHT) row = VGA_HEIGHT - 1;
        return;
    }

    VGA[row * VGA_WIDTH + col] = (uint16_t)c | ((uint16_t)color << 8);
    col++;
    if (col >= VGA_WIDTH) {
        col = 0;
        row++;
        if (row >= VGA_HEIGHT) row = VGA_HEIGHT - 1;
    }
}

static void putsn(const char* s) {
    size_t i;
    for (i = 0; s[i]; i++) putc(s[i]);
}

static void put_dec(uint32_t n) {
    char buf[16];
    int i = 0;
    if (n == 0) {
        putc('0');
        return;
    }
    while (n > 0) {
        buf[i++] = (char)('0' + (n % 10));
        n /= 10;
    }
    while (i > 0) putc(buf[--i]);
}

static void clear_input(void) {
    size_t i;
    for (i = 0; i < INPUT_MAX; i++) input_buf[i] = 0;
    input_len = 0;
}

static void clear_findings(void) {
    int i;
    int j;
    for (i = 0; i < MAX_FINDINGS; i++) {
        for (j = 0; j < 72; j++) findings[i][j] = 0;
    }
    finding_count = 0;
    risk_score = 0;
    verdict = "READY";
}

static void push_finding(const char* s) {
    size_t i;
    if (finding_count >= MAX_FINDINGS) return;
    for (i = 0; i < 71 && s[i]; i++) findings[finding_count][i] = s[i];
    findings[finding_count][i] = 0;
    finding_count++;
}

static int host_is_ip(const char* host) {
    int dots = 0;
    int saw_digit = 0;
    while (*host && *host != '/' && *host != ':') {
        if (*host == '.') dots++;
        else if (is_digit(*host)) saw_digit = 1;
        else return 0;
        host++;
    }
    return saw_digit && dots == 3;
}

static const char* extract_host(const char* url) {
    if (starts_with(url, "https://")) return url + 8;
    if (starts_with(url, "http://")) return url + 7;
    return url;
}

static void analyze(void) {
    const char* host;

    clear_findings();

    if (!input_buf[0]) {
        verdict = "NO INPUT";
        push_finding("[!] INPUT EMPTY");
        return;
    }

    if (starts_with(input_buf, "https://")) push_finding("[+] HTTPS DETECTED");
    else if (starts_with(input_buf, "http://")) { push_finding("[!] HTTP ONLY"); risk_score += 30; }
    else { push_finding("[!] MISSING URL SCHEME"); risk_score += 20; }

    if (strchr(input_buf, '@')) { push_finding("[!] AT-SIGN FOUND"); risk_score += 20; }
    if (strchr(input_buf, ' ')) { push_finding("[!] WHITESPACE IN URL"); risk_score += 10; }
    if (strlen(input_buf) > 130) { push_finding("[!] VERY LONG URL"); risk_score += 10; }
    if (strchr(input_buf, '%')) { push_finding("[!] ENCODED CHARS PRESENT"); risk_score += 8; }

    host = extract_host(input_buf);
    if (host_is_ip(host)) { push_finding("[!] DIRECT IP HOST"); risk_score += 10; }

    if (ends_with(host, ".zip") || ends_with(host, ".click") || ends_with(host, ".top")) {
        push_finding("[!] SUSPICIOUS TLD");
        risk_score += 12;
    }

    if (strstr(input_buf, "login") || strstr(input_buf, "verify") || strstr(input_buf, "wallet")) {
        push_finding("[!] PHISHING KEYWORDS");
        risk_score += 12;
    }

    if (mode_api) {
        if (strstr(input_buf, "/api") || strstr(input_buf, "/v1") || strstr(input_buf, "/v2")) {
            push_finding("[+] API PATH FOUND");
        } else {
            push_finding("[i] API MARKERS NOT FOUND");
            risk_score += 5;
        }

        if (strstr(input_buf, "token=") || strstr(input_buf, "apikey=") || strstr(input_buf, "key=")) {
            push_finding("[!] TOKEN IN QUERY STRING");
            risk_score += 15;
        }
    }

    if (risk_score > 100) risk_score = 100;

    if (risk_score >= 50) verdict = "HIGH RISK";
    else if (risk_score >= 20) verdict = "MEDIUM RISK";
    else verdict = "LOW RISK";
}

static void draw_ui(void) {
    int i;
    clear_screen();

    putsn("+------------------------------------------------------------------------------+\n");
    putsn("| KOROLI SIMPLE UI (TEXT MODE) - WEBSITE/API SAFETY SCANNER                  |\n");
    putsn("+------------------------------------------------------------------------------+\n");

    putsn(" MODE: ");
    if (mode_api) putsn("API TEST\n");
    else putsn("WEBSITE SCAN\n");

    putsn(" KEYS: [1]=WEB [2]=API [TAB]=SWITCH [ENTER]=SCAN [ESC]=CLEAR\n");
    putsn(" TARGET: ");
    putsn(input_buf);
    putsn("\n\n");

    putsn(" RISK SCORE: ");
    put_dec((uint32_t)risk_score);
    putsn(" / 100\n");
    putsn(" VERDICT: ");
    putsn(verdict);
    putsn("\n\n");

    putsn(" FINDINGS:\n");
    for (i = 0; i < finding_count && i < 9; i++) {
        putsn("  - ");
        putsn(findings[i]);
        putsn("\n");
    }

    putsn("\n NOTE: For real live internet probing use tools/net_audit.sh on host Kali.\n");
}

static uint8_t shift_down = 0;

static char key_normal(uint8_t sc) {
    static const char map[128] = {
        0, 27, '1','2','3','4','5','6','7','8','9','0','-','=', '\b','\t',
        'q','w','e','r','t','y','u','i','o','p','[',']','\n', 0,
        'a','s','d','f','g','h','j','k','l',';','\'', '`', 0,
        '\\','z','x','c','v','b','n','m',',','.','/', 0,'*',0,' ',0
    };
    if (sc < 128) return map[sc];
    return 0;
}

static char key_shift(uint8_t sc) {
    static const char map[128] = {
        0, 27, '!','@','#','$','%','^','&','*','(',')','_','+', '\b','\t',
        'Q','W','E','R','T','Y','U','I','O','P','{','}','\n', 0,
        'A','S','D','F','G','H','J','K','L',':','"', '~', 0,
        '|','Z','X','C','V','B','N','M','<','>','?', 0,'*',0,' ',0
    };
    if (sc < 128) return map[sc];
    return 0;
}

static char read_key(void) {
    uint8_t sc;
    while ((inb(0x64) & 1) == 0) { }
    sc = inb(0x60);

    if (sc == 42 || sc == 54) { shift_down = 1; return 0; }
    if (sc == 170 || sc == 182) { shift_down = 0; return 0; }
    if (sc & 0x80) return 0;

    if (shift_down) return key_shift(sc);
    return key_normal(sc);
}

static void loop(void) {
    clear_input();
    clear_findings();
    push_finding("[i] READY. TYPE TARGET AND PRESS ENTER");
    draw_ui();

    while (1) {
        char c = read_key();
        if (!c) continue;

        if (c == '\t') {
            mode_api = !mode_api;
            draw_ui();
            continue;
        }

        if (c == '1') {
            mode_api = 0;
            draw_ui();
            continue;
        }

        if (c == '2') {
            mode_api = 1;
            draw_ui();
            continue;
        }

        if (c == 27) {
            clear_input();
            clear_findings();
            push_finding("[i] CLEARED");
            draw_ui();
            continue;
        }

        if (c == '\b') {
            if (input_len > 0) {
                input_len--;
                input_buf[input_len] = 0;
                draw_ui();
            }
            continue;
        }

        if (c == '\n') {
            analyze();
            draw_ui();
            continue;
        }

        if (input_len < INPUT_MAX - 1) {
            input_buf[input_len++] = c;
            input_buf[input_len] = 0;
            draw_ui();
        }
    }
}

void kmain(uint32_t mb_magic, uint32_t mb_info_addr) {
    (void)mb_magic;
    (void)mb_info_addr;

    outb(0x3D4, 0x0A);
    outb(0x3D5, 0x20);

    loop();
}
