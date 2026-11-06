/*
 * ps5-tls-verify — toggleable TLS verifier override for PS5
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * A standalone pldmgr payload. For every process on the system that
 * has one of the four PS5 TLS libraries loaded, it toggles the
 * primary certificate-chain verifier:
 *
 *   - libSceSsl             → four inner-site patches inside the
 *                              chain verifier (FUN_801e6d020 on 13.20)
 *                              that force the UNKNOWN_CA (bit 0x20)
 *                              error path to never fire. Shared .rx
 *                              mapping: one write per site covers
 *                              every process.
 *   - libSceLibreSsl.sprx   → X509_verify_cert entry stub (per-proc).
 *   - libSceLibreSsl3.sprx  → X509_verify_cert entry stub (per-proc).
 *   - libmono-btls-shared   → BoringSSL X509_verify_cert entry stub,
 *                              reached by decoding the Mono wrapper
 *                              thunk's rel32 (per-proc).
 *
 * The entry-stub form (B8 01 00 00 00 C3 = MOV EAX, 1 ; RET) is
 * sufficient for the LibreSSL / BoringSSL variants, which observe
 * their return value as the sole trust-decision gate. It is NOT
 * sufficient for libSceSsl, whose chain verifier mutates error-bit
 * state in a struct that its caller inspects independently of the
 * return value — hence the inner 4-site patch for that library.
 *
 * Toggle: on each run, the payload surveys every covered target and
 * picks the first non-UNKNOWN state as the reference. If reference
 * is PRISTINE the run patches everything; if reference is PATCHED
 * the run restores. State drift between runs (new processes spawning
 * unpatched) is handled by the WATCH LOOP after a patch pass — the
 * payload stays resident and re-patches freshly-spawned candidates.
 *
 * All cross-process memory R/W goes through the SDK's
 * kernel_proc_copyout / kernel_proc_copyin, which operate directly
 * via the kernel (proc_rwmem on the target proc's vmspace). No
 * PT_ATTACH, no target stop.
 *
 * SECURITY: while patched, the covered processes accept any
 * certificate chain. Use only on an isolated network.
 */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <ps5/kernel.h>
#include <ps5/klog.h>

/* Per-event lines go to klog (visible on TCP 3232).
   The overall per-run summary is also sent as an on-screen PS5
   notification so the user sees it without tailing klog. */
#define klog(...)  klog_printf(__VA_ARGS__)

typedef struct notify_request {
    char useless1[45];
    char message[3075];
} notify_request_t;
int sceKernelSendNotificationRequest(int, notify_request_t*, size_t, int);

static void toast(const char *fmt, ...) {
    notify_request_t req;
    memset(&req, 0, sizeof(req));
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(req.message, sizeof(req.message), fmt, ap);
    va_end(ap);
    sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
}

/* ────────────────── byte patterns ────────────────────────────────── */

/* LibreSSL / mono-btls entry stub: MOV EAX, 1 ; RET. */
static const uint8_t ENTRY_PATCH[6]    = { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3 };
static const uint8_t ENTRY_PRISTINE[6] = { 0x55, 0x48, 0x89, 0xe5, 0x41, 0x57 };

/* UNKNOWN_CA error immediate (0x8095F00C, little-endian). The byte
   immediately before it must be 0xB8 (MOV EAX, imm32). Unique in
   libSceSsl.rx, inside the chain verifier. */
static const uint8_t UNKNOWN_CA_IMM[5] = { 0xB8, 0x0C, 0xF0, 0x95, 0x80 };

/* ────────────────── scan bounds ──────────────────────────────────── */

#define SCAN_CHUNK      0x10000     /* 64 KiB chunk reads */
#define RX_SCAN_MAX     0x200000    /* 2 MiB upper bound for libSceSsl.rx */
#define BACKSCAN_MAX    0x4000      /* backscan from imm to function prologue */
#define FUNC_BODY_MAX   0x2000      /* forward scan window from prologue */
#define OR_TARGET_SLOP  64          /* P1/P3 jump target must land ≤N bytes
                                       from the OR-0x20 instruction */

/* ────────────────── runtime state ────────────────────────────────── */

static volatile sig_atomic_t g_should_exit = 0;
static void on_signal(int sig) { (void)sig; g_should_exit = 1; }

/* Single-instance / state file paths. /data is writable from a
   pldmgr-launched payload on this console. */
#define PID_PATH    "/data/ps5-tls-verify.pid"
#define STATE_PATH  "/data/ps5-tls-verify.state"

/* State file carries the libSceSsl P1/P3 pristine 12 bytes so we can
   restore the JZ/JNZ rel32 after they've been overwritten with a NOP
   sled. Keyed by libSceSsl.rx offsets (shared mapping → stable per
   boot). Little-endian. */
#define STATE_MAGIC   0x56534C54u    /* "TLSV" */
#define STATE_VERSION 2u

struct state_file {
    uint32_t magic;
    uint32_t version;
    uint32_t p1_rx_offset;
    uint32_t p3_rx_offset;
    uint8_t  p1_pristine[6];
    uint8_t  p3_pristine[6];
};

/* ────────────────── proc helpers ─────────────────────────────────── */

/* Look up a single pid by exact proc name. Scans allproc for a
   null-terminated byte run equal to `name` inside each struct proc,
   avoiding any dependency on the exact p_comm offset. Returns 0 if
   not found or if the proc list walk fails. */
static pid_t find_pid_by_name(const char *name) {
    intptr_t kproc = 0;
    if (kernel_copyout((intptr_t)KERNEL_ADDRESS_ALLPROC, &kproc, sizeof(kproc)) != 0) return 0;
    size_t nlen = strlen(name);
    if (!nlen || nlen > 64) return 0;
    uint8_t buf[0x800];
    for (int c = 0; kproc && c < 0x1000; c++) {
        if (kernel_copyout(kproc, buf, sizeof(buf)) != 0) return 0;
        for (size_t i = 0; i + nlen <= sizeof(buf); i++) {
            if (memcmp(buf + i, name, nlen) == 0 && buf[i + nlen] == 0) {
                int32_t pid = 0;
                if (kernel_copyout(kproc + KERNEL_OFFSET_PROC_P_PID, &pid, sizeof(pid)) != 0) return 0;
                if (pid > 0) return (pid_t)pid;
                break;
            }
        }
        intptr_t next = 0;
        if (kernel_copyout(kproc, &next, sizeof(next)) != 0) return 0;
        kproc = next;
    }
    return 0;
}

/* ────────────────── candidate list ───────────────────────────────── */

static const char *CANDIDATE_PROCS[] = {
    "SceShellCore",
    "SceShellUI",
    "SceJSCd",
    "SceNKNetworkProcess",
    "SceNKUIProcess",
    "SceNKWebProcess",
    "ScePartyDaemon",
    "ScePsNowClientDaemon",
    "SceVideoCore2K",
    "SceRemotePlay",
    "SceDiscordDaemon",
    "SceGameLiveStreaming",
    "SceVoiceAndAgent",
    "SceSystemLogger2",
    "SceMediaCoreServer",
    "SceUpdatePupUtil",
    "SceCloudMessaging",
    "orbis_audiod.elf",
    "webrtc_daemon.self",
    NULL
};

/* ────────────────── target table ─────────────────────────────────── */

enum { KIND_ENTRY_STUB, KIND_P1, KIND_P2, KIND_P3, KIND_P4 };
enum { STATE_PRISTINE = 0, STATE_PATCHED = 1, STATE_UNKNOWN = -1 };

struct target {
    pid_t       pid;
    const char *procname;
    const char *lib;        /* for logging */
    int         kind;
    intptr_t    va;
    int         state;
    uint8_t     saved_pristine[6]; /* P1/P3: original rel32 bytes (set at
                                      patch time; later persisted to STATE_PATH) */
    int         saved_valid;
};

#define MAX_TARGETS 256
static struct target g_targets[MAX_TARGETS];
static int g_ntargets = 0;
/* libSceSsl.rx is COPY-ON-WRITE under kernel_proc_copyin (not shared as
   PT_IO would suggest), so every process that has libSceSsl loaded
   needs its own 4-site patch. The locator pattern-search is expensive
   so it only runs once (in the first pid that has libSceSsl loaded);
   the resulting .rx offsets are then reused for every other process. */
static int g_libscessl_located = 0;
static uint32_t g_libscessl_off_p1 = 0;
static uint32_t g_libscessl_off_p2 = 0;
static uint32_t g_libscessl_off_p3 = 0;
static uint32_t g_libscessl_off_p4 = 0;

static struct target *push_target(pid_t pid, const char *procname,
                                  const char *lib, int kind, intptr_t va) {
    if (g_ntargets >= MAX_TARGETS) return NULL;
    struct target *t = &g_targets[g_ntargets++];
    *t = (struct target){ pid, procname, lib, kind, va, STATE_UNKNOWN, {0}, 0 };
    return t;
}

/* ────────────────── state file I/O ───────────────────────────────── */

static int state_file_read(struct state_file *s) {
    int fd = open(STATE_PATH, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read(fd, s, sizeof(*s));
    close(fd);
    if (n != (ssize_t)sizeof(*s)) return -1;
    if (s->magic != STATE_MAGIC || s->version != STATE_VERSION) return -1;
    return 0;
}

static int state_file_write(const struct state_file *s) {
    int fd = open(STATE_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return -1;
    ssize_t n = write(fd, s, sizeof(*s));
    close(fd);
    return (n == (ssize_t)sizeof(*s)) ? 0 : -1;
}

/* ────────────────── libSceSsl 4-site locator (firmware-agnostic) ───
 *
 * The chain verifier function (FUN_801e6d020 on fw 13.20) emits
 * UNKNOWN_CA via a 32-bit error-flag field whose "0x20" bit is OR'd
 * in from multiple places. The 4 proven sites are:
 *
 *   P1 — forward JZ (0f 84) that would skip the trust walk entirely
 *        when a verifyctx flag is clear. Preceded by:
 *            41 8b 44 24 ??      MOV EAX, [R12+disp8]
 *            a8 01               TEST AL, 0x01
 *        We NOP-sled it so the trust walk always runs.
 *
 *   P2 — short JZ (74 06) that would skip an inline
 *            41 80 4c 24 ?? 20   OR BYTE [R12+disp8], 0x20
 *        We flip 74→eb so the OR is unconditionally skipped.
 *
 *   P3 — backward JNZ (0f 85 … ff ff) that routes into a second
 *        error-set site (an OR r/m32, r32 using EAX=0x20). Preceded by:
 *            b8 20 00 00 00      MOV EAX, 0x20
 *            0f 85 ?? ?? ff ff   JNZ long (backward)
 *        We NOP-sled it so the backward jump never happens; the
 *        unconditional JMP that follows then routes past both error
 *        sites.
 *
 *   P4 — short JZ (74 ??) that skips a custom-callback-error block.
 *        Followed by:
 *            41 83 7c 24 ?? ??   CMP DWORD [R12+disp8], imm8
 *        We flip 74→eb so the whole block is unconditionally skipped.
 *
 * Pipeline:
 *   1. Resolve libSceSsl.rx base.
 *   2. Scan .rx for the UNKNOWN_CA anchor (B8 0C F0 95 80, unique).
 *   3. Backscan to the function prologue (55 48 89 e5 41 57).
 *   4. Read FUNC_BODY_MAX bytes forward from the prologue.
 *   5. For each of P1/P2/P3/P4, scan the body for its semantic
 *      prefix. Each site is required to match exactly once (counting
 *      both pristine and patched forms as a match). If any site has
 *      hits != 1 we bail — a firmware change that moved any site
 *      should surface loudly rather than silently patch wrong bytes.
 */

static intptr_t find_unknown_ca_anchor(pid_t pid, intptr_t rx_base) {
    static uint8_t chunk[SCAN_CHUNK];
    for (size_t off = 0; off < RX_SCAN_MAX; off += SCAN_CHUNK) {
        if (kernel_proc_copyout(pid, rx_base + off, chunk, SCAN_CHUNK) != 0) break;
        for (size_t i = 0; i + 5 <= SCAN_CHUNK; i++) {
            if (memcmp(chunk + i, UNKNOWN_CA_IMM, 5) == 0)
                return rx_base + off + i;
        }
    }
    return 0;
}

static intptr_t backscan_to_prologue(pid_t pid, intptr_t anchor_va) {
    static uint8_t prebuf[BACKSCAN_MAX];
    size_t win = BACKSCAN_MAX;
    if (kernel_proc_copyout(pid, anchor_va - win, prebuf, win) != 0) return 0;
    for (size_t j = win; j >= 6; j--) {
        if (memcmp(prebuf + j - 6, ENTRY_PRISTINE, 6) == 0 ||
            memcmp(prebuf + j - 6, ENTRY_PATCH,    6) == 0) {
            return anchor_va - (win - (j - 6));
        }
    }
    return 0;
}

/* Return 1 if the 6 bytes at p are a NOP sled (90 90 90 90 90 90). */
static int is_nop_sled6(const uint8_t *p) {
    return p[0]==0x90 && p[1]==0x90 && p[2]==0x90 && p[3]==0x90 && p[4]==0x90 && p[5]==0x90;
}

/* Pass 1 — survey libSceSsl: locate P1/P2/P3/P4 by semantic prefix,
   push them as targets. Returns 1 on success, 0 if any site couldn't
   be identified unambiguously. */
static int survey_libscessl(pid_t pid, const char *procname,
                            intptr_t rx_base) {
    intptr_t anchor = find_unknown_ca_anchor(pid, rx_base);
    if (!anchor) {
        klog("[ps5-tls-verify] libSceSsl: UNKNOWN_CA anchor not located in pid=%d\n", pid);
        return 0;
    }
    intptr_t prologue = backscan_to_prologue(pid, anchor);
    if (!prologue) {
        klog("[ps5-tls-verify] libSceSsl: function prologue not located from anchor %#lx\n", (long)anchor);
        return 0;
    }

    static uint8_t body[FUNC_BODY_MAX];
    if (kernel_proc_copyout(pid, prologue, body, FUNC_BODY_MAX) != 0) {
        klog("[ps5-tls-verify] libSceSsl: body read failed @ %#lx\n", (long)prologue);
        return 0;
    }

    intptr_t p1_va = 0, p2_va = 0, p3_va = 0, p4_va = 0;
    int p1_hits = 0, p2_hits = 0, p3_hits = 0, p4_hits = 0;

    /* P1 prefix: 41 8b 44 24 ?? a8 01 { 0f 84 r r r r | 90 90 90 90 90 90 }
       → P1 site = index + 7. */
    for (size_t i = 0; i + 13 <= FUNC_BODY_MAX; i++) {
        if (body[i]!=0x41 || body[i+1]!=0x8b || body[i+2]!=0x44 || body[i+3]!=0x24
            || body[i+5]!=0xa8 || body[i+6]!=0x01) continue;
        const uint8_t *site = body + i + 7;
        int pristine = (site[0]==0x0f && site[1]==0x84);
        int patched  = is_nop_sled6(site);
        if (!(pristine || patched)) continue;
        p1_va = prologue + i + 7;
        p1_hits++;
    }

    /* P2 prefix: { 74 06 | eb 06 } 41 80 4c 24 ?? 20
       → P2 site = index. */
    for (size_t i = 0; i + 8 <= FUNC_BODY_MAX; i++) {
        if (!((body[i]==0x74 || body[i]==0xeb) && body[i+1]==0x06)) continue;
        if (body[i+2]!=0x41 || body[i+3]!=0x80 || body[i+4]!=0x4c || body[i+5]!=0x24 || body[i+7]!=0x20) continue;
        p2_va = prologue + i;
        p2_hits++;
    }

    /* P3 prefix: b8 20 00 00 00 { 0f 85 r r r r | 90 90 90 90 90 90 }
       → P3 site = index + 5. */
    for (size_t i = 0; i + 11 <= FUNC_BODY_MAX; i++) {
        if (body[i]!=0xb8 || body[i+1]!=0x20 || body[i+2]!=0x00 ||
            body[i+3]!=0x00 || body[i+4]!=0x00) continue;
        const uint8_t *site = body + i + 5;
        int pristine = (site[0]==0x0f && site[1]==0x85);
        int patched  = is_nop_sled6(site);
        if (!(pristine || patched)) continue;
        p3_va = prologue + i + 5;
        p3_hits++;
    }

    /* P4 prefix: { 74 r | eb r } 41 83 7c 24 ?? ??
       → P4 site = index. */
    for (size_t i = 0; i + 8 <= FUNC_BODY_MAX; i++) {
        if (!(body[i]==0x74 || body[i]==0xeb)) continue;
        if (body[i+2]!=0x41 || body[i+3]!=0x83 || body[i+4]!=0x7c || body[i+5]!=0x24) continue;
        p4_va = prologue + i;
        p4_hits++;
    }

    klog("[ps5-tls-verify] libSceSsl: prologue=%#lx  P1 hits=%d P2 hits=%d P3 hits=%d P4 hits=%d\n",
         (long)prologue, p1_hits, p2_hits, p3_hits, p4_hits);
    if (p1_hits != 1 || p2_hits != 1 || p3_hits != 1 || p4_hits != 1) {
        klog("[ps5-tls-verify] libSceSsl: ambiguous site count — bailing (no writes)\n");
        return 0;
    }

    g_libscessl_off_p1 = (uint32_t)(p1_va - rx_base);
    g_libscessl_off_p2 = (uint32_t)(p2_va - rx_base);
    g_libscessl_off_p3 = (uint32_t)(p3_va - rx_base);
    g_libscessl_off_p4 = (uint32_t)(p4_va - rx_base);
    (void)procname; (void)pid; /* pattern-search pid only — targets added by caller */
    klog("[ps5-tls-verify] libSceSsl offsets: P1=+%#x P2=+%#x P3=+%#x P4=+%#x\n",
         g_libscessl_off_p1, g_libscessl_off_p2, g_libscessl_off_p3, g_libscessl_off_p4);
    return 1;
}

/* Push the 4 libSceSsl inner-site targets for a pid using the cached
   offsets. Caller must have ensured g_libscessl_located == 1. */
static void push_libscessl_targets(pid_t pid, const char *procname, intptr_t rx_base) {
    push_target(pid, procname, "libSceSsl P1", KIND_P1, rx_base + g_libscessl_off_p1);
    push_target(pid, procname, "libSceSsl P2", KIND_P2, rx_base + g_libscessl_off_p2);
    push_target(pid, procname, "libSceSsl P3", KIND_P3, rx_base + g_libscessl_off_p3);
    push_target(pid, procname, "libSceSsl P4", KIND_P4, rx_base + g_libscessl_off_p4);
}

/* Classify every target's current state. Also captures P1/P3 pristine
   bytes into the target's saved_pristine slot (used later when
   persisting to STATE_PATH). */
static void classify(struct target *t) {
    uint8_t cur[6] = {0};
    switch (t->kind) {
    case KIND_ENTRY_STUB:
        if (kernel_proc_copyout(t->pid, t->va, cur, 6) != 0) { t->state = STATE_UNKNOWN; return; }
        if (!memcmp(cur, ENTRY_PATCH, 6))      t->state = STATE_PATCHED;
        else if (!memcmp(cur, ENTRY_PRISTINE, 6)) t->state = STATE_PRISTINE;
        else t->state = STATE_UNKNOWN;
        return;
    case KIND_P2: case KIND_P4: {
        if (kernel_proc_copyout(t->pid, t->va, cur, 2) != 0) { t->state = STATE_UNKNOWN; return; }
        if (cur[0] == 0x74)      t->state = STATE_PRISTINE;
        else if (cur[0] == 0xeb) t->state = STATE_PATCHED;
        else t->state = STATE_UNKNOWN;
        return;
    }
    case KIND_P1: case KIND_P3: {
        if (kernel_proc_copyout(t->pid, t->va, cur, 6) != 0) { t->state = STATE_UNKNOWN; return; }
        /* Patched: 6× 0x90. Pristine: 0f 84/85 rel32. */
        int all_nop = 1;
        for (int i = 0; i < 6; i++) if (cur[i] != 0x90) { all_nop = 0; break; }
        if (all_nop) { t->state = STATE_PATCHED; return; }
        uint8_t want = (t->kind == KIND_P1) ? 0x84 : 0x85;
        if (cur[0] == 0x0f && cur[1] == want) {
            t->state = STATE_PRISTINE;
            memcpy(t->saved_pristine, cur, 6);
            t->saved_valid = 1;
        } else {
            t->state = STATE_UNKNOWN;
        }
        return;
    }
    }
}

/* Write the configured target state. For P1/P3 restore we need the
   pristine bytes from the state file. Returns 0 on success. */
static int apply(struct target *t, int target_state, const struct state_file *sf) {
    uint8_t bytes[6] = {0};
    size_t  n = 0;
    switch (t->kind) {
    case KIND_ENTRY_STUB:
        memcpy(bytes, (target_state == STATE_PATCHED) ? ENTRY_PATCH : ENTRY_PRISTINE, 6);
        n = 6;
        break;
    case KIND_P2: case KIND_P4: {
        /* Keep existing rel8; just flip the opcode byte. */
        uint8_t cur[2];
        if (kernel_proc_copyout(t->pid, t->va, cur, 2) != 0) return -1;
        bytes[0] = (target_state == STATE_PATCHED) ? 0xeb : 0x74;
        bytes[1] = cur[1];
        n = 2;
        break;
    }
    case KIND_P1: case KIND_P3: {
        if (target_state == STATE_PATCHED) {
            memset(bytes, 0x90, 6);
        } else {
            /* Restore. Prefer the pristine we captured during classify.
               If this run is only ever seeing the patched form, fall
               back to the state-file-provided bytes. */
            const uint8_t *src = NULL;
            if (t->saved_valid) src = t->saved_pristine;
            else if (sf) {
                if (t->kind == KIND_P1) src = sf->p1_pristine;
                else                     src = sf->p3_pristine;
            }
            if (!src) return -2;
            memcpy(bytes, src, 6);
        }
        n = 6;
        break;
    }
    }
    return kernel_proc_copyin(t->pid, bytes, t->va, n);
}

/* ────────────────── per-process surveyor ─────────────────────────── */

/* Push all targets (libSceSsl + per-process LibreSSL/mono-btls) for pid.
   libSceSsl inner-site locations are pattern-searched once in the first
   pid that has it loaded, then reused for every other pid. */
static void survey_one(pid_t pid, const char *procname) {
    uint32_t h = 0;
    if (kernel_dynlib_handle(pid, "libSceSsl.sprx", &h) == 0 && h != 0) {
        intptr_t base = kernel_dynlib_mapbase_addr(pid, h);
        if (base) {
            if (!g_libscessl_located) {
                if (survey_libscessl(pid, procname, base)) {
                    g_libscessl_located = 1;
                }
            }
            if (g_libscessl_located) push_libscessl_targets(pid, procname, base);
        }
    }

    /* libSceLibreSsl: dlsym X509_verify_cert, entry stub target. */
    {
        uint32_t h = 0;
        if (kernel_dynlib_handle(pid, "libSceLibreSsl.sprx", &h) == 0 && h != 0) {
            intptr_t va = kernel_dynlib_dlsym(pid, h, "X509_verify_cert");
            if (va) push_target(pid, procname, "libSceLibreSsl.sprx", KIND_ENTRY_STUB, va);
        }
    }

    /* libSceLibreSsl3: same pattern. */
    {
        uint32_t h = 0;
        if (kernel_dynlib_handle(pid, "libSceLibreSsl3.sprx", &h) == 0 && h != 0) {
            intptr_t va = kernel_dynlib_dlsym(pid, h, "X509_verify_cert");
            if (va) push_target(pid, procname, "libSceLibreSsl3.sprx", KIND_ENTRY_STUB, va);
        }
    }

    /* libmono-btls-shared: decode the exported thunk. */
    {
        uint32_t h = 0;
        if (kernel_dynlib_handle(pid, "libmono-btls-shared.sprx", &h) == 0 && h != 0) {
            intptr_t thunk = kernel_dynlib_dlsym(pid, h, "mono_btls_x509_store_ctx_verify_cert");
            if (thunk) {
                uint8_t t[9];
                if (kernel_proc_copyout(pid, thunk, t, sizeof(t)) == 0 &&
                    t[0] == 0x48 && t[1] == 0x8b && t[2] == 0x7f && t[3] == 0x08 && t[4] == 0xe9) {
                    int32_t rel = (int32_t)(t[5] | (t[6] << 8) | (t[7] << 16) | (t[8] << 24));
                    intptr_t real_va = thunk + 9 + rel;
                    push_target(pid, procname, "libmono-btls-shared.sprx", KIND_ENTRY_STUB, real_va);
                }
            }
        }
    }
}

/* ────────────────── single-instance guard ────────────────────────── */

/* On startup: SIGTERM any previous watcher so we can take over. */
static void kill_prior_instance(void) {
    int fd = open(PID_PATH, O_RDONLY);
    if (fd < 0) return;
    char buf[32] = {0};
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return;
    pid_t prev = (pid_t)atoi(buf);
    if (prev <= 0 || prev == getpid()) return;
    if (kill(prev, 0) != 0) return;             /* already gone */
    klog("[ps5-tls-verify] signalling previous instance pid=%d to exit\n", prev);
    kill(prev, SIGTERM);
    for (int i = 0; i < 50; i++) {              /* up to 5s */
        usleep(100 * 1000);
        if (kill(prev, 0) != 0) break;
    }
}

static void write_pid_file(void) {
    int fd = open(PID_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return;
    char buf[32];
    int n = snprintf(buf, sizeof(buf), "%d\n", getpid());
    if (n > 0) (void)!write(fd, buf, n);
    close(fd);
}

static void remove_pid_file(void) { unlink(PID_PATH); }

/* ────────────────── watch loop ───────────────────────────────────── */

/* After an initial patch pass, keep polling allproc to catch newly-
   spawned candidate processes and patch their per-process TLS libs.
   libSceSsl is shared .rx so its patch sticks across new processes. */

#define SEEN_MAX 256
struct seen_entry { pid_t pid; };
static struct seen_entry g_seen[SEEN_MAX];
static int g_nseen = 0;

static int seen_has(pid_t pid) {
    for (int i = 0; i < g_nseen; i++) if (g_seen[i].pid == pid) return 1;
    return 0;
}
static void seen_add(pid_t pid) {
    if (g_nseen < SEEN_MAX) g_seen[g_nseen++] = (struct seen_entry){ pid };
}

/* Patch every covered TLS library in `pid` to the PATCHED state. Uses
   a local target array so the global g_targets stays bounded over the
   lifetime of the watch loop. libSceSsl is per-process COW under
   kernel_proc_copyin, so each new pid needs its own 4-site write. */
static void patch_new_pid(pid_t pid, const char *procname) {
    struct target local[8];
    int n = 0;
    uint32_t h;

    if (g_libscessl_located) {
        h = 0;
        if (kernel_dynlib_handle(pid, "libSceSsl.sprx", &h) == 0 && h != 0) {
            intptr_t base = kernel_dynlib_mapbase_addr(pid, h);
            if (base) {
                local[n++] = (struct target){ pid, procname, "libSceSsl P1",
                        KIND_P1, base + g_libscessl_off_p1, STATE_UNKNOWN, {0}, 0 };
                local[n++] = (struct target){ pid, procname, "libSceSsl P2",
                        KIND_P2, base + g_libscessl_off_p2, STATE_UNKNOWN, {0}, 0 };
                local[n++] = (struct target){ pid, procname, "libSceSsl P3",
                        KIND_P3, base + g_libscessl_off_p3, STATE_UNKNOWN, {0}, 0 };
                local[n++] = (struct target){ pid, procname, "libSceSsl P4",
                        KIND_P4, base + g_libscessl_off_p4, STATE_UNKNOWN, {0}, 0 };
            }
        }
    }
    h = 0;
    if (kernel_dynlib_handle(pid, "libSceLibreSsl.sprx", &h) == 0 && h != 0) {
        intptr_t va = kernel_dynlib_dlsym(pid, h, "X509_verify_cert");
        if (va) local[n++] = (struct target){ pid, procname, "libSceLibreSsl.sprx",
                                              KIND_ENTRY_STUB, va, STATE_UNKNOWN, {0}, 0 };
    }
    h = 0;
    if (kernel_dynlib_handle(pid, "libSceLibreSsl3.sprx", &h) == 0 && h != 0) {
        intptr_t va = kernel_dynlib_dlsym(pid, h, "X509_verify_cert");
        if (va) local[n++] = (struct target){ pid, procname, "libSceLibreSsl3.sprx",
                                              KIND_ENTRY_STUB, va, STATE_UNKNOWN, {0}, 0 };
    }
    h = 0;
    if (kernel_dynlib_handle(pid, "libmono-btls-shared.sprx", &h) == 0 && h != 0) {
        intptr_t thunk = kernel_dynlib_dlsym(pid, h, "mono_btls_x509_store_ctx_verify_cert");
        if (thunk) {
            uint8_t t[9];
            if (kernel_proc_copyout(pid, thunk, t, sizeof(t)) == 0 &&
                t[0] == 0x48 && t[1] == 0x8b && t[2] == 0x7f && t[3] == 0x08 && t[4] == 0xe9) {
                int32_t rel = (int32_t)(t[5] | (t[6] << 8) | (t[7] << 16) | (t[8] << 24));
                intptr_t real_va = thunk + 9 + rel;
                local[n++] = (struct target){ pid, procname, "libmono-btls-shared.sprx",
                                              KIND_ENTRY_STUB, real_va, STATE_UNKNOWN, {0}, 0 };
            }
        }
    }

    /* We need the state file's P1/P3 pristine bytes for CLASSIFY of a
       patched target (so saved_pristine is populated) — but in the
       watch path we only ever flip PRISTINE→PATCHED, never the other
       way, so the state file isn't strictly needed here. */
    for (int i = 0; i < n; i++) {
        classify(&local[i]);
        if (local[i].state == STATE_PRISTINE) {
            if (apply(&local[i], STATE_PATCHED, NULL) == 0) {
                klog("[ps5-tls-verify] watch: %s @ pid=%d (%s) %#lx -> OFF\n",
                     local[i].lib, pid, procname, (long)local[i].va);
            }
        }
    }
}

static void run_watch_loop(void) {
    klog("[ps5-tls-verify] entering watch loop (1s poll, SIGTERM/reboot to exit)\n");
    while (!g_should_exit) {
        for (int i = 0; CANDIDATE_PROCS[i] && !g_should_exit; i++) {
            pid_t pid = find_pid_by_name(CANDIDATE_PROCS[i]);
            if (pid <= 0 || seen_has(pid)) continue;
            seen_add(pid);
            patch_new_pid(pid, CANDIDATE_PROCS[i]);
        }
        for (int i = 0; i < 10 && !g_should_exit; i++) usleep(100 * 1000);
    }
    klog("[ps5-tls-verify] watch loop exiting (signal received)\n");
}

/* ────────────────── main ─────────────────────────────────────────── */

int main(void) {
    signal(SIGTERM, on_signal);
    signal(SIGINT,  on_signal);

    kill_prior_instance();
    write_pid_file();

    klog("[ps5-tls-verify] starting (4-site libSceSsl + watch mode)\n");

    /* Pass 1: survey all current candidates. */
    for (int i = 0; CANDIDATE_PROCS[i]; i++) {
        pid_t pid = find_pid_by_name(CANDIDATE_PROCS[i]);
        if (pid > 0) {
            survey_one(pid, CANDIDATE_PROCS[i]);
            seen_add(pid);
        }
    }
    if (g_ntargets == 0) {
        klog("[ps5-tls-verify] no targets found\n");
        toast("TLS verifier: no targets found");
        remove_pid_file();
        return 1;
    }

    /* Classify. Target state is picked by MAJORITY RULE across all
       targets: whichever side is larger loses (we flip toward the
       smaller one). Ties flip toward PATCHED (verify-off). This
       absorbs drift from stale partial-patch states left by prior
       runs — a mostly-pristine survey still flips to patched. */
    int n_off = 0, n_on = 0, n_unknown = 0;
    for (int i = 0; i < g_ntargets; i++) {
        classify(&g_targets[i]);
        if      (g_targets[i].state == STATE_PATCHED)  n_off++;
        else if (g_targets[i].state == STATE_PRISTINE) n_on++;
        else                                            n_unknown++;
    }
    if (n_off == 0 && n_on == 0) {
        klog("[ps5-tls-verify] no classifiable target — aborting\n");
        toast("TLS verifier: unrecognized state everywhere; aborting");
        remove_pid_file();
        return 1;
    }
    int target_state = (n_off > n_on) ? STATE_PRISTINE : STATE_PATCHED;
    const char *tgt_label = (target_state == STATE_PATCHED) ? "OFF" : "ON";
    klog("[ps5-tls-verify] SURVEY: %d OFF, %d ON, %d unknown (of %d targets) — flipping ALL to %s (majority rule)\n",
         n_off, n_on, n_unknown, g_ntargets, tgt_label);

    /* Load state file if we're restoring (needed for P1/P3 rel32). */
    struct state_file sf_in;
    struct state_file *sf_ptr = NULL;
    if (target_state == STATE_PRISTINE) {
        if (state_file_read(&sf_in) == 0) sf_ptr = &sf_in;
        else klog("[ps5-tls-verify] state file missing/mismatched — P1/P3 restore skipped (reboot to fully revert)\n");
    }

    /* Capture P1/P3 pristine bytes BEFORE patching, so a later restore
       run can use them. Only persist if we actually have pristine
       bytes for both sites. */
    if (target_state == STATE_PATCHED) {
        struct state_file sf = { .magic = STATE_MAGIC, .version = STATE_VERSION };
        int ok = 1;
        for (int i = 0; i < g_ntargets; i++) {
            if (g_targets[i].kind == KIND_P1 && g_targets[i].saved_valid) {
                sf.p1_rx_offset = g_libscessl_off_p1;
                memcpy(sf.p1_pristine, g_targets[i].saved_pristine, 6);
            } else if (g_targets[i].kind == KIND_P3 && g_targets[i].saved_valid) {
                sf.p3_rx_offset = g_libscessl_off_p3;
                memcpy(sf.p3_pristine, g_targets[i].saved_pristine, 6);
            }
        }
        if (!sf.p1_rx_offset || !sf.p3_rx_offset) {
            /* No fresh pristine captures — the pre-patch state must have
               been already-patched for P1/P3. Merge with existing file
               if any, else leave as-is. */
            struct state_file prior;
            if (state_file_read(&prior) == 0) {
                if (!sf.p1_rx_offset) { sf.p1_rx_offset = prior.p1_rx_offset; memcpy(sf.p1_pristine, prior.p1_pristine, 6); }
                if (!sf.p3_rx_offset) { sf.p3_rx_offset = prior.p3_rx_offset; memcpy(sf.p3_pristine, prior.p3_pristine, 6); }
            }
        }
        if (sf.p1_rx_offset && sf.p3_rx_offset) {
            if (state_file_write(&sf) != 0) {
                klog("[ps5-tls-verify] WARN: could not persist state file\n");
            } else {
                klog("[ps5-tls-verify] state file saved (P1@+%#x P3@+%#x)\n",
                     sf.p1_rx_offset, sf.p3_rx_offset);
            }
        }
        (void)ok;
    }

    /* Pass 2 — apply. */
    int flipped = 0, already = 0, errors = 0;
    for (int i = 0; i < g_ntargets; i++) {
        if (g_targets[i].state == STATE_UNKNOWN) { errors++; continue; }
        if (g_targets[i].state == target_state)  { already++; continue; }
        int rc = apply(&g_targets[i], target_state, sf_ptr);
        if (rc == 0) {
            klog("[ps5-tls-verify] %s @ pid=%d (%s) %#lx -> %s\n",
                 g_targets[i].lib, g_targets[i].pid, g_targets[i].procname,
                 (long)g_targets[i].va, tgt_label);
            flipped++;
        } else if (rc == -2) {
            klog("[ps5-tls-verify] %s @ pid=%d (%s) %#lx -> %s SKIPPED (no pristine bytes)\n",
                 g_targets[i].lib, g_targets[i].pid, g_targets[i].procname,
                 (long)g_targets[i].va, tgt_label);
            errors++;
        } else {
            klog("[ps5-tls-verify] %s @ pid=%d (%s) %#lx -> %s FAILED\n",
                 g_targets[i].lib, g_targets[i].pid, g_targets[i].procname,
                 (long)g_targets[i].va, tgt_label);
            errors++;
        }
    }

    klog("[ps5-tls-verify] DONE  flipped=%d already=%s=%d errors=%d\n",
         flipped, tgt_label, already, errors);
    toast("TLS verifier: ALL %s\nflipped %d, already %s %d, errors %d",
          tgt_label, flipped, tgt_label, already, errors);

    /* Only enter the watch loop if we patched (verify-off). On a
       restore run we exit so the watcher doesn't keep re-patching. */
    if (target_state == STATE_PATCHED) {
        run_watch_loop();
    }

    remove_pid_file();
    return 0;
}
