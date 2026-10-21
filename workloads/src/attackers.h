/* attackers.h - reference cache-access *pattern* kernels.
 *
 * Each attacker exposes:  void attacker_init(uint64_t seed);
 *                         void attacker_run(void);
 * These reproduce the characteristic microarchitectural footprint of a
 * class of cache attack (the signal a detector must learn), running in a
 * simulated single process. They monitor cache state over a probe buffer;
 * they do not target another process and recover no key.
 */
#ifndef JCEN_ATTACKERS_H
#define JCEN_ATTACKERS_H
#include "common.h"

#define PROBE_PAGES 24
#define LINE 64

/* ---- none: benign control, no cache manipulation ------------------- */
#ifdef ATTACKER_NONE
static void attacker_init(uint64_t seed) { (void)seed; }
static void attacker_run(void) { /* nothing */ }
#endif

/* ---- Flush+Reload pattern -----------------------------------------
 * Flush a monitored line, let the victim run, time the reload. The
 * low-latency reloads form the F+R signature (flush + timed access). */
#ifdef ATTACKER_FLUSH_RELOAD
static volatile char *fr_buf;
static int fr_npages, fr_start;   /* fixed per run (from seed) */
static void attacker_init(uint64_t seed) {
    (void)seed;
    fr_buf = aligned_alloc(4096, PROBE_PAGES * 4096);
    memset((void*)fr_buf, 1, PROBE_PAGES * 4096);
    fr_npages = (int)jitter(16, PROBE_PAGES - 16 + 1);  /* 16..24 */
    fr_start  = (int)jitter(0, PROBE_PAGES);
}
static void attacker_run(void) {
    int npages = fr_npages;
    int start  = fr_start + (int)jitter(0, 3);   /* small per-call drift */
    for (int k = 0; k < npages; k++) {
        int p = (start + k) % PROBE_PAGES;
        const void *line = (const void *)(fr_buf + p * 4096);
        flush_line(line);                       /* evict monitored line */
        uint64_t t0 = rdtsc_begin();
        sink(*(volatile char *)line);           /* timed reload */
        uint64_t t1 = rdtsc_end();
        sink(t1 - t0);                          /* latency = the signal */
    }
}
#endif

/* ---- Prime+Probe pattern ------------------------------------------
 * Prime a set by walking an eviction buffer, then re-walk (probe) and
 * time it. Repeated set traversal is the P+P signature. */
#ifdef ATTACKER_PRIME_PROBE
static volatile char *pp_buf;
#define PP_SET (192*1024)   /* ~1.5x L2 (128kB) to force eviction */
static int pp_rounds, pp_span; static long pp_idle;  /* fixed per run */
static void attacker_init(uint64_t seed) {
    (void)seed;
    pp_buf = aligned_alloc(4096, PP_SET);
    memset((void*)pp_buf, 2, PP_SET);
    pp_rounds = (int)jitter(2, 4);                  /* 2..5 passes, fixed */
    pp_span   = (int)jitter(PP_SET*3/4, PP_SET/4);  /* set coverage, fixed */
    pp_idle   = (long)jitter(0, 5) * 20000L;  /* 0..80k: mild probe-rate axis */
}
static void attacker_run(void) {
    int rounds = pp_rounds;
    int span = pp_span;
    for (int r = 0; r < rounds; r++) {
        for (int i = 0; i < span; i += LINE)        /* prime */
            sink(pp_buf[i]);
        uint64_t t0 = rdtsc_begin();
        for (int i = 0; i < span; i += LINE)        /* probe (timed) */
            sink(pp_buf[i]);
        uint64_t t1 = rdtsc_end();
        sink(t1 - t0);
    }
    idle_spin(pp_idle);          /* per-run idle dilutes cache pressure */
}
#endif

/* ---- Spectre v1 pattern (canonical bounds-check-bypass gadget) -----
 * The textbook gadget: train the branch predictor, then a transient
 * out-of-bounds index touches a probe line, revealed by reload timing.
 * Self-contained; the "secret" is this process's own array. */
#ifdef ATTACKER_SPECTRE_V1
static uint8_t  sp_array1[16];
static size_t   sp_size = 16;
static uint8_t  sp_secret[8];
static volatile char *sp_probe;
static int sp_iters, sp_ntrain; static long sp_idle;  /* fixed per run */
#define SP_STRIDE 4096
static void attacker_init(uint64_t seed) {
    uint64_t s = seed;
    for (int i = 0; i < 16; i++) sp_array1[i] = (uint8_t)i;
    for (int i = 0; i < 8; i++)  sp_secret[i] = (uint8_t)sm64(&s);
    sp_probe = aligned_alloc(4096, 256 * SP_STRIDE);
    memset((void*)sp_probe, 1, 256 * SP_STRIDE);
    sp_iters = (int)jitter(16, 17);   /* 16..32 internal, fixed per run */
    sp_ntrain = (int)jitter(6, 7);
    sp_idle = (long)jitter(0, 5) * 20000L;  /* 0..80k: mild probe-rate axis */
}
static inline void sp_gadget(size_t x) {
    if (x < sp_size) {                           /* mistrained branch */
        uint8_t v = sp_array1[x];
        sink(sp_probe[v * SP_STRIDE]);           /* transient leak into cache */
    }
}
static void attacker_run(void) {
    for (int it = 0; it < sp_iters; it++) {
        for (int t = 0; t < sp_ntrain; t++) sp_gadget(t & 0xf); /* train in-bounds */
        _mm_mfence();
        size_t mal = (size_t)((uint8_t*)sp_secret - sp_array1); /* OOB index */
        sp_gadget(mal);                                   /* transient access */
        for (int g = 0; g < 256; g++) {                   /* reload probe */
            const void *l = (const void*)(sp_probe + g * SP_STRIDE);
            uint64_t t0 = rdtsc_begin(); sink(*(volatile char*)l);
            uint64_t t1 = rdtsc_end();   sink(t1 - t0);
            flush_line(l);
        }
    }
    idle_spin(sp_idle);          /* per-run idle dilutes cache pressure */
}
#endif

#endif /* JCEN_ATTACKERS_H */
