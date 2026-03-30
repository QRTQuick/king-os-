typedef unsigned char  uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int   uint32_t;
typedef unsigned long long uint64_t;
typedef unsigned int   size_t;

#define VGA_WIDTH 80
#define VGA_HEIGHT 25
#define INPUT_MAX 220
#define MAX_FINDINGS 10
#define KBD_QUEUE_SIZE 256
#define MULTIBOOT_BOOTLOADER_MAGIC 0x2BADB002

struct multiboot_info {
    uint32_t flags;
    uint32_t mem_lower;
    uint32_t mem_upper;
    uint32_t boot_device;
    uint32_t cmdline;
    uint32_t mods_count;
    uint32_t mods_addr;
    uint32_t syms[4];
    uint32_t mmap_length;
    uint32_t mmap_addr;
    uint32_t drives_length;
    uint32_t drives_addr;
    uint32_t config_table;
    uint32_t boot_loader_name;
    uint32_t apm_table;
    uint32_t vbe_control_info;
    uint32_t vbe_mode_info;
    uint16_t vbe_mode;
    uint16_t vbe_interface_seg;
    uint16_t vbe_interface_off;
    uint16_t vbe_interface_len;
    uint64_t framebuffer_addr;
    uint32_t framebuffer_pitch;
    uint32_t framebuffer_width;
    uint32_t framebuffer_height;
    uint8_t framebuffer_bpp;
    uint8_t framebuffer_type;
    uint16_t framebuffer_reserved;
} __attribute__((packed));

struct idt_entry {
    uint16_t offset_low;
    uint16_t selector;
    uint8_t zero;
    uint8_t type_attr;
    uint16_t offset_high;
} __attribute__((packed));

struct idt_ptr {
    uint16_t limit;
    uint32_t base;
} __attribute__((packed));

/* Shared scanner state */
static char input_buf[INPUT_MAX];
static size_t input_len = 0;
static int mode_api = 0;
static int risk_score = 0;
static const char* verdict = "READY";
static char findings[MAX_FINDINGS][72];
static int finding_count = 0;

/* VGA text mode state */
static uint16_t* const VGA = (uint16_t*)0xB8000;
static uint8_t vga_color = 0x02;
static size_t vga_row = 0;
static size_t vga_col = 0;

/* framebuffer state */
static uint8_t* fb_addr = (uint8_t*)0;
static uint32_t fb_pitch = 0;
static uint32_t fb_width = 0;
static uint32_t fb_height = 0;
static uint32_t fb_bpp = 0;

/* Assembly-optimized memory fill routines */
extern void asm_fill32(uint32_t* dst, uint32_t value, uint32_t count);
extern void asm_fill16(uint16_t* dst, uint16_t value, uint32_t count);

/* Assembly interrupt helpers */
extern void load_idt(const struct idt_ptr* idtr);
extern void enable_interrupts(void);
extern void disable_interrupts(void);
extern void hlt_cpu(void);
extern void irq0_stub(void);
extern void irq1_stub(void);
extern void irq_ignore_stub(void);

/* keyboard state */
static volatile uint8_t shift_down = 0;
static volatile uint8_t kbd_queue[KBD_QUEUE_SIZE];
static volatile uint32_t kbd_head = 0;
static volatile uint32_t kbd_tail = 0;
static volatile uint32_t timer_ticks = 0;

/* IDT */
static struct idt_entry idt[256];
static struct idt_ptr idtr;

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

/* Forward declarations for keyboard map helpers used in IRQ handler */
static char key_normal(uint8_t sc);
static char key_shift(uint8_t sc);

/* Interrupt + PIC setup */
static void pic_send_eoi(uint8_t irq) {
    if (irq >= 8) outb(0xA0, 0x20);
    outb(0x20, 0x20);
}

static void idt_set_gate(uint8_t vec, uint32_t handler) {
    idt[vec].offset_low = (uint16_t)(handler & 0xFFFF);
    idt[vec].selector = 0x08;
    idt[vec].zero = 0;
    idt[vec].type_attr = 0x8E;
    idt[vec].offset_high = (uint16_t)((handler >> 16) & 0xFFFF);
}

static void pic_remap(uint8_t offset1, uint8_t offset2) {
    uint8_t a1 = inb(0x21);
    uint8_t a2 = inb(0xA1);

    outb(0x20, 0x11);
    outb(0xA0, 0x11);
    outb(0x21, offset1);
    outb(0xA1, offset2);
    outb(0x21, 4);
    outb(0xA1, 2);
    outb(0x21, 0x01);
    outb(0xA1, 0x01);
    outb(0x21, a1);
    outb(0xA1, a2);
}

static void pit_init(uint32_t hz) {
    uint32_t divisor = 1193182u / hz;
    outb(0x43, 0x36);
    outb(0x40, (uint8_t)(divisor & 0xFF));
    outb(0x40, (uint8_t)((divisor >> 8) & 0xFF));
}

static void kbd_push(char c) {
    uint32_t next = (kbd_head + 1) & (KBD_QUEUE_SIZE - 1);
    if (next == kbd_tail) return;
    kbd_queue[kbd_head] = (uint8_t)c;
    kbd_head = next;
}

static int kbd_pop(char* out) {
    if (kbd_tail == kbd_head) return 0;
    *out = (char)kbd_queue[kbd_tail];
    kbd_tail = (kbd_tail + 1) & (KBD_QUEUE_SIZE - 1);
    return 1;
}

void irq0_handler(void) {
    timer_ticks++;
    pic_send_eoi(0);
}

void irq1_handler(void) {
    uint8_t sc = inb(0x60);

    if (sc == 42 || sc == 54) shift_down = 1;
    else if (sc == 170 || sc == 182) shift_down = 0;
    else if ((sc & 0x80) == 0) {
        char c = shift_down ? key_shift(sc) : key_normal(sc);
        if (c) kbd_push(c);
    }

    pic_send_eoi(1);
}

static void setup_interrupts(void) {
    uint32_t i;

    disable_interrupts();
    for (i = 0; i < 256; i++) {
        idt_set_gate((uint8_t)i, (uint32_t)irq_ignore_stub);
    }
    idt_set_gate(32, (uint32_t)irq0_stub);
    idt_set_gate(33, (uint32_t)irq1_stub);

    idtr.limit = (uint16_t)(sizeof(idt) - 1);
    idtr.base = (uint32_t)&idt[0];
    load_idt(&idtr);

    pic_remap(32, 40);
    pit_init(100);
    outb(0x21, 0xFC); /* unmask IRQ0(timer) + IRQ1(keyboard) */
    outb(0xA1, 0xFF); /* mask all slave IRQs */

    enable_interrupts();
}

/* Keyboard */
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
    char c;
    for (;;) {
        disable_interrupts();
        if (kbd_pop(&c)) {
            enable_interrupts();
            return c;
        }
        enable_interrupts();
        hlt_cpu();
    }
}

/* TEXT UI */
static void vga_clear(void) {
    uint16_t value = (uint16_t)' ' | ((uint16_t)vga_color << 8);
    asm_fill16(VGA, value, (uint32_t)(VGA_WIDTH * VGA_HEIGHT));
    vga_row = 0;
    vga_col = 0;
}

static void vga_putc(char c) {
    if (c == '\n') {
        vga_col = 0;
        vga_row++;
        if (vga_row >= VGA_HEIGHT) vga_row = VGA_HEIGHT - 1;
        return;
    }

    VGA[vga_row * VGA_WIDTH + vga_col] = (uint16_t)c | ((uint16_t)vga_color << 8);
    vga_col++;
    if (vga_col >= VGA_WIDTH) {
        vga_col = 0;
        vga_row++;
        if (vga_row >= VGA_HEIGHT) vga_row = VGA_HEIGHT - 1;
    }
}

static void vga_puts(const char* s) {
    size_t i;
    for (i = 0; s[i]; i++) vga_putc(s[i]);
}

static void vga_put_dec(uint32_t n) {
    char buf[16];
    int i = 0;
    if (n == 0) { vga_putc('0'); return; }
    while (n > 0) { buf[i++] = (char)('0' + (n % 10)); n /= 10; }
    while (i > 0) vga_putc(buf[--i]);
}

static void draw_text_ui(void) {
    int i;
    vga_clear();

    vga_puts("+------------------------------------------------------------------------------+\n");
    vga_puts("| KOROLI SIMPLE UI (TEXT MODE)                                                 |\n");
    vga_puts("+------------------------------------------------------------------------------+\n");
    vga_puts(" MODE: ");
    if (mode_api) vga_puts("API TEST\n");
    else vga_puts("WEBSITE SCAN\n");
    vga_puts(" KEYS: [1]=WEB [2]=API [TAB]=SWITCH [ENTER]=SCAN [ESC]=CLEAR\n");
    vga_puts(" TARGET: ");
    if (input_buf[0]) vga_puts(input_buf);
    else vga_puts("<type target here>");
    vga_puts("\n\n RISK: ");
    vga_put_dec((uint32_t)risk_score);
    vga_puts(" / 100\n VERDICT: ");
    vga_puts(verdict);
    vga_puts("\n FINDINGS:\n");

    for (i = 0; i < finding_count && i < 8; i++) {
        vga_puts("  - ");
        vga_puts(findings[i]);
        vga_puts("\n");
    }
}

static void text_loop(void) {
    clear_input();
    clear_findings();
    push_finding("[i] READY. TYPE TARGET AND PRESS ENTER");
    draw_text_ui();

    while (1) {
        char c = read_key();
        if (!c) continue;

        if (c == '\t') { mode_api = !mode_api; draw_text_ui(); continue; }
        if (c == '1') { mode_api = 0; draw_text_ui(); continue; }
        if (c == '2') { mode_api = 1; draw_text_ui(); continue; }
        if (c == 27) { clear_input(); clear_findings(); push_finding("[i] CLEARED"); draw_text_ui(); continue; }

        if (c == '\b') {
            if (input_len > 0) { input_len--; input_buf[input_len] = 0; draw_text_ui(); }
            continue;
        }

        if (c == '\n') { analyze(); draw_text_ui(); continue; }

        if (input_len < INPUT_MAX - 1) {
            input_buf[input_len++] = c;
            input_buf[input_len] = 0;
            draw_text_ui();
        }
    }
}

/* SIMPLE GUI */
static uint32_t rgb(uint8_t r, uint8_t g, uint8_t b) {
    return ((uint32_t)r << 16) | ((uint32_t)g << 8) | (uint32_t)b;
}

static void putpixel(uint32_t x, uint32_t y, uint32_t color) {
    uint8_t* p;
    uint16_t c16;
    if (!fb_addr) return;
    if (x >= fb_width || y >= fb_height) return;

    p = fb_addr + y * fb_pitch + x * (fb_bpp / 8);
    if (fb_bpp == 32) {
        p[0] = (uint8_t)(color & 0xFF);
        p[1] = (uint8_t)((color >> 8) & 0xFF);
        p[2] = (uint8_t)((color >> 16) & 0xFF);
        p[3] = 0;
    } else if (fb_bpp == 16) {
        c16 = (uint16_t)((((color >> 19) & 0x1F) << 11) |
                         (((color >> 10) & 0x3F) << 5)  |
                         (((color >> 3)  & 0x1F)));
        p[0] = (uint8_t)(c16 & 0xFF);
        p[1] = (uint8_t)((c16 >> 8) & 0xFF);
    } else if (fb_bpp == 24) {
        p[0] = (uint8_t)(color & 0xFF);
        p[1] = (uint8_t)((color >> 8) & 0xFF);
        p[2] = (uint8_t)((color >> 16) & 0xFF);
    }
}

static void fill_rect(uint32_t x, uint32_t y, uint32_t w, uint32_t h, uint32_t color) {
    uint32_t yy;
    uint32_t xx;
    for (yy = y; yy < y + h && yy < fb_height; yy++) {
        if (fb_bpp == 32 && x < fb_width) {
            uint32_t run = w;
            if (x + run > fb_width) run = fb_width - x;
            if (run > 0) {
                uint32_t* rowp = (uint32_t*)(fb_addr + yy * fb_pitch) + x;
                asm_fill32(rowp, color, run);
            }
        } else {
            for (xx = x; xx < x + w && xx < fb_width; xx++) putpixel(xx, yy, color);
        }
    }
}

static void draw_rect(uint32_t x, uint32_t y, uint32_t w, uint32_t h, uint32_t color) {
    uint32_t i;
    for (i = 0; i < w; i++) {
        putpixel(x + i, y, color);
        if (h > 0) putpixel(x + i, y + h - 1, color);
    }
    for (i = 0; i < h; i++) {
        putpixel(x, y + i, color);
        if (w > 0) putpixel(x + w - 1, y + i, color);
    }
}

static char up(char c) {
    if (c >= 'a' && c <= 'z') return (char)(c - 32);
    return c;
}

static const uint8_t* glyph(char c) {
    static const uint8_t B[7] = {0,0,0,0,0,0,0};
    static const uint8_t D[7] = {0,0,0,0,0,0x0C,0x0C};
    static const uint8_t H[7] = {0,0,0,0x1F,0,0,0};
    static const uint8_t C[7] = {0,0x0C,0x0C,0,0x0C,0x0C,0};
    static const uint8_t S[7] = {0x01,0x02,0x04,0x08,0x10,0,0};

    static const uint8_t A0[7]={0x0E,0x11,0x13,0x15,0x19,0x11,0x0E};
    static const uint8_t A1[7]={0x04,0x0C,0x04,0x04,0x04,0x04,0x0E};
    static const uint8_t A2[7]={0x0E,0x11,0x01,0x06,0x08,0x10,0x1F};
    static const uint8_t A3[7]={0x1E,0x01,0x01,0x06,0x01,0x01,0x1E};
    static const uint8_t A4[7]={0x02,0x06,0x0A,0x12,0x1F,0x02,0x02};
    static const uint8_t A5[7]={0x1F,0x10,0x10,0x1E,0x01,0x01,0x1E};
    static const uint8_t A6[7]={0x0E,0x10,0x10,0x1E,0x11,0x11,0x0E};
    static const uint8_t A7[7]={0x1F,0x01,0x02,0x04,0x08,0x08,0x08};
    static const uint8_t A8[7]={0x0E,0x11,0x11,0x0E,0x11,0x11,0x0E};
    static const uint8_t A9[7]={0x0E,0x11,0x11,0x0F,0x01,0x01,0x0E};

    static const uint8_t A[7]={0x0E,0x11,0x11,0x1F,0x11,0x11,0x11};
    static const uint8_t B2[7]={0x1E,0x11,0x11,0x1E,0x11,0x11,0x1E};
    static const uint8_t C2[7]={0x0F,0x10,0x10,0x10,0x10,0x10,0x0F};
    static const uint8_t D2[7]={0x1E,0x11,0x11,0x11,0x11,0x11,0x1E};
    static const uint8_t E[7]={0x1F,0x10,0x10,0x1E,0x10,0x10,0x1F};
    static const uint8_t F[7]={0x1F,0x10,0x10,0x1E,0x10,0x10,0x10};
    static const uint8_t G[7]={0x0F,0x10,0x10,0x17,0x11,0x11,0x0F};
    static const uint8_t Hh[7]={0x11,0x11,0x11,0x1F,0x11,0x11,0x11};
    static const uint8_t I[7]={0x1F,0x04,0x04,0x04,0x04,0x04,0x1F};
    static const uint8_t J2[7]={0x1F,0x01,0x01,0x01,0x11,0x11,0x0E};
    static const uint8_t K[7]={0x11,0x12,0x14,0x18,0x14,0x12,0x11};
    static const uint8_t L[7]={0x10,0x10,0x10,0x10,0x10,0x10,0x1F};
    static const uint8_t M[7]={0x11,0x1B,0x15,0x15,0x11,0x11,0x11};
    static const uint8_t N[7]={0x11,0x19,0x15,0x13,0x11,0x11,0x11};
    static const uint8_t O[7]={0x0E,0x11,0x11,0x11,0x11,0x11,0x0E};
    static const uint8_t P[7]={0x1E,0x11,0x11,0x1E,0x10,0x10,0x10};
    static const uint8_t Q2[7]={0x0E,0x11,0x11,0x11,0x15,0x12,0x0D};
    static const uint8_t R[7]={0x1E,0x11,0x11,0x1E,0x14,0x12,0x11};
    static const uint8_t S2[7]={0x0F,0x10,0x10,0x0E,0x01,0x01,0x1E};
    static const uint8_t T[7]={0x1F,0x04,0x04,0x04,0x04,0x04,0x04};
    static const uint8_t U[7]={0x11,0x11,0x11,0x11,0x11,0x11,0x0E};
    static const uint8_t V[7]={0x11,0x11,0x11,0x11,0x0A,0x0A,0x04};
    static const uint8_t W[7]={0x11,0x11,0x11,0x15,0x15,0x1B,0x11};
    static const uint8_t X2[7]={0x11,0x11,0x0A,0x04,0x0A,0x11,0x11};
    static const uint8_t Y[7]={0x11,0x11,0x0A,0x04,0x04,0x04,0x04};
    static const uint8_t Z2[7]={0x1F,0x01,0x02,0x04,0x08,0x10,0x1F};

    c = up(c);
    switch (c) {
        case 'A': return A; case 'B': return B2; case 'C': return C2; case 'D': return D2;
        case 'E': return E; case 'F': return F; case 'G': return G; case 'H': return Hh;
        case 'I': return I; case 'J': return J2; case 'K': return K; case 'L': return L;
        case 'M': return M; case 'N': return N; case 'O': return O; case 'P': return P;
        case 'Q': return Q2; case 'R': return R; case 'S': return S2; case 'T': return T;
        case 'U': return U; case 'V': return V; case 'W': return W; case 'X': return X2;
        case 'Y': return Y; case 'Z': return Z2;
        case '0': return A0; case '1': return A1; case '2': return A2; case '3': return A3;
        case '4': return A4; case '5': return A5; case '6': return A6; case '7': return A7;
        case '8': return A8; case '9': return A9;
        case '.': return D; case '-': return H; case ':': return C; case '/': return S;
        case ' ': return B;
        default: return B;
    }
}

static void draw_char(uint32_t x, uint32_t y, char c, uint32_t color, uint32_t scale) {
    uint32_t row;
    uint32_t col;
    uint32_t dx;
    uint32_t dy;
    const uint8_t* g = glyph(c);

    for (row = 0; row < 7; row++) {
        for (col = 0; col < 5; col++) {
            if ((g[row] >> (4 - col)) & 1) {
                for (dy = 0; dy < scale; dy++) {
                    for (dx = 0; dx < scale; dx++) {
                        putpixel(x + col * scale + dx, y + row * scale + dy, color);
                    }
                }
            }
        }
    }
}

static void draw_text(uint32_t x, uint32_t y, const char* s, uint32_t color, uint32_t scale, uint32_t max_chars) {
    size_t i;
    uint32_t cx = x;
    for (i = 0; s[i] && i < max_chars; i++) {
        draw_char(cx, y, s[i], color, scale);
        cx += 6 * scale;
    }
}

static void draw_gui(void) {
    uint32_t desk = rgb(33, 115, 70);
    uint32_t title_blue = rgb(12, 80, 170);
    uint32_t win_bg = rgb(236, 239, 244);
    uint32_t win_border = rgb(40, 40, 40);
    uint32_t text_dark = rgb(25, 25, 25);
    uint32_t taskbar = rgb(190, 194, 202);
    uint32_t btn_bg = rgb(210, 214, 220);
    uint32_t good = rgb(60, 170, 90);
    uint32_t warn = rgb(210, 155, 45);
    uint32_t bad = rgb(200, 70, 65);
    uint32_t score_color = good;
    uint32_t win_x = 90;
    uint32_t win_y = 55;
    uint32_t win_w = (fb_width > 180) ? fb_width - 180 : fb_width;
    uint32_t win_h = (fb_height > 130) ? fb_height - 130 : fb_height;
    uint32_t bar_w;
    int i;

    if (risk_score >= 50) score_color = bad;
    else if (risk_score >= 20) score_color = warn;

    fill_rect(0, 0, fb_width, fb_height, desk);

    /* desktop icons (simple blocks) */
    fill_rect(20, 30, 46, 46, rgb(250, 245, 210));
    draw_rect(20, 30, 46, 46, rgb(60, 60, 60));
    draw_text(22, 82, "SCAN", rgb(235, 245, 240), 1, 8);

    /* main app window */
    fill_rect(win_x, win_y, win_w, win_h, win_bg);
    draw_rect(win_x, win_y, win_w, win_h, win_border);
    fill_rect(win_x + 1, win_y + 1, win_w - 2, 28, title_blue);
    draw_text(win_x + 10, win_y + 10, "KOROLI SCANNER", rgb(255, 255, 255), 1, 22);
    fill_rect(win_x + win_w - 70, win_y + 6, 16, 16, rgb(250, 220, 80));
    fill_rect(win_x + win_w - 48, win_y + 6, 16, 16, rgb(110, 180, 255));
    fill_rect(win_x + win_w - 26, win_y + 6, 16, 16, rgb(230, 90, 90));

    draw_text(win_x + 18, win_y + 44, "MODE", text_dark, 1, 8);
    if (mode_api) draw_text(win_x + 70, win_y + 44, "API TEST", rgb(20, 95, 200), 1, 16);
    else draw_text(win_x + 70, win_y + 44, "WEB SCAN", rgb(20, 95, 200), 1, 16);

    draw_text(win_x + 18, win_y + 62, "CTRL 1 WEB 2 API TAB SWITCH ENTER SCAN ESC CLEAR", rgb(70, 70, 70), 1, 56);

    draw_text(win_x + 18, win_y + 86, "TARGET URL", text_dark, 1, 12);
    fill_rect(win_x + 16, win_y + 98, win_w - 32, 28, rgb(255, 255, 255));
    draw_rect(win_x + 16, win_y + 98, win_w - 32, 28, rgb(120, 120, 120));
    if (input_buf[0]) draw_text(win_x + 22, win_y + 108, input_buf, text_dark, 1, 64);
    else draw_text(win_x + 22, win_y + 108, "TYPE URL HERE", rgb(125, 125, 125), 1, 20);

    draw_text(win_x + 18, win_y + 140, "RISK", text_dark, 1, 8);
    bar_w = (uint32_t)((risk_score * (int)(win_w - 170)) / 100);
    fill_rect(win_x + 70, win_y + 142, win_w - 170, 14, rgb(220, 220, 220));
    fill_rect(win_x + 70, win_y + 142, bar_w, 14, score_color);
    draw_rect(win_x + 70, win_y + 142, win_w - 170, 14, rgb(90, 90, 90));

    draw_text(win_x + 18, win_y + 166, "VERDICT", text_dark, 1, 10);
    draw_text(win_x + 86, win_y + 166, verdict, score_color, 1, 16);

    draw_text(win_x + 18, win_y + 188, "FINDINGS", text_dark, 1, 10);
    for (i = 0; i < finding_count && i < 7; i++) {
        draw_text(win_x + 26, win_y + 206 + (uint32_t)i * 16, findings[i], rgb(40, 40, 40), 1, 66);
    }

    /* taskbar */
    fill_rect(0, fb_height - 34, fb_width, 34, taskbar);
    draw_rect(0, fb_height - 34, fb_width, 34, rgb(110, 110, 110));
    fill_rect(8, fb_height - 28, 84, 22, btn_bg);
    draw_rect(8, fb_height - 28, 84, 22, rgb(100, 100, 100));
    draw_text(28, fb_height - 20, "START", text_dark, 1, 8);
    draw_text(112, fb_height - 20, "KOROLI GUI", text_dark, 1, 14);
}

static int init_gui(uint32_t mb_magic, const struct multiboot_info* mbi) {
    if (mb_magic != MULTIBOOT_BOOTLOADER_MAGIC) return 0;
    if (!mbi) return 0;
    if ((mbi->flags & (1u << 12)) == 0) return 0;
    if (mbi->framebuffer_type != 1) return 0;
    if (mbi->framebuffer_bpp != 16 && mbi->framebuffer_bpp != 24 && mbi->framebuffer_bpp != 32) return 0;

    fb_addr = (uint8_t*)(uint32_t)(mbi->framebuffer_addr & 0xFFFFFFFFu);
    fb_pitch = mbi->framebuffer_pitch;
    fb_width = mbi->framebuffer_width;
    fb_height = mbi->framebuffer_height;
    fb_bpp = mbi->framebuffer_bpp;

    if (fb_width < 640 || fb_height < 480) return 0;
    return 1;
}

static void gui_loop(void) {
    clear_input();
    clear_findings();
    push_finding("READY. TYPE TARGET AND PRESS ENTER");
    draw_gui();

    while (1) {
        char c = read_key();
        if (!c) continue;

        if (c == '\t') { mode_api = !mode_api; draw_gui(); continue; }
        if (c == '1') { mode_api = 0; draw_gui(); continue; }
        if (c == '2') { mode_api = 1; draw_gui(); continue; }
        if (c == 27) { clear_input(); clear_findings(); push_finding("CLEARED"); draw_gui(); continue; }

        if (c == '\b') {
            if (input_len > 0) { input_len--; input_buf[input_len] = 0; draw_gui(); }
            continue;
        }

        if (c == '\n') { analyze(); draw_gui(); continue; }

        if (input_len < INPUT_MAX - 1) {
            input_buf[input_len++] = c;
            input_buf[input_len] = 0;
            draw_gui();
        }
    }
}

void kmain(uint32_t mb_magic, uint32_t mb_info_addr) {
    const struct multiboot_info* mbi = (const struct multiboot_info*)mb_info_addr;

    outb(0x3D4, 0x0A);
    outb(0x3D5, 0x20);
    setup_interrupts();

    if (init_gui(mb_magic, mbi)) {
        gui_loop();
    } else {
        text_loop();
    }
}
