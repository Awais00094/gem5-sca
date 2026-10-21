/* common.h - shared helpers for the JCEN trace-generation workloads.
 *
 * These kernels run under gem5 SE mode to PRODUCE microarchitectural
 * traces for a side-channel *detector*. They are deliberately simple
 * reference patterns, not optimised attack tools; no secret is printed
 * and nothing leaves the simulated process.
 *
 * A per-run seed (argv[1]) selects the secret key / inputs so that each
 * of the N runs in a class is independent.
 */
#ifndef JCEN_COMMON_H
#define JCEN_COMMON_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- optional gem5 ROI markers -------------------------------------
 * If you build the m5 op library (util/m5) and link it, define USE_M5OPS
 * to bracket the region of interest. Otherwise these are no-ops and we
 * rely on the interval sampling in se_run.py. */
#ifdef USE_M5OPS
#include <gem5/m5ops.h>
#define ROI_BEGIN() m5_work_begin(0, 0)
#define ROI_END()   m5_work_end(0, 0)
#else
#define ROI_BEGIN() do {} while (0)
#define ROI_END()   do {} while (0)
#endif

/* ---- tiny deterministic PRNG (SplitMix64) --------------------------
 * Keeps runs reproducible from the seed without libc rand() state. */
static inline uint64_t sm64(uint64_t *s) {
    uint64_t z = (*s += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

static inline uint64_t seed_from_argv(int argc, char **argv) {
    return (argc > 1) ? strtoull(argv[1], NULL, 10) : 0xA5A5A5A5ULL;
}

/* ---- per-run randomization ----------------------------------------
 * Deterministic sim has no measurement noise, so run-to-run variation
 * must be injected: the attacker tunes its parameters and the victim's
 * activity varies. g_rng is seeded once per run; jitter(base,span)
 * returns base..base+span-1. This gives each seed a distinct trace
 * while keeping the class-characteristic pattern intact. */
static uint64_t g_rng = 0x1234;
static inline void rng_seed(uint64_t s) { g_rng = s ? s : 1; }
static inline uint64_t jitter(uint64_t base, uint64_t span) {
    return base + (span ? (sm64(&g_rng) % span) : 0);
}

/* x86 timing + flush primitives, used by the attack-pattern kernels. */
#if defined(__x86_64__)
#include <x86intrin.h>
static inline uint64_t rdtsc_begin(void) {
    unsigned a; _mm_mfence(); return __rdtscp(&a);
}
static inline uint64_t rdtsc_end(void) {
    unsigned a; uint64_t t = __rdtscp(&a); _mm_lfence(); return t;
}
static inline void flush_line(const void *p) { _mm_clflush(p); }
#else
static inline uint64_t rdtsc_begin(void) { return 0; }
static inline uint64_t rdtsc_end(void) { return 0; }
static inline void flush_line(const void *p) { (void)p; }
#endif

/* Consume a value so the compiler cannot optimise the work away. */
static volatile uint64_t g_sink;
static inline void sink(uint64_t v) { g_sink ^= v; }

/* Benign compute-only spin (no memory traffic): used to set a per-run
 * attacker PROBE RATE. A larger idle lowers the cache pressure per time
 * unit, modelling a stealthier / lower-rate attacker and giving
 * bandwidth-saturated (interval-capped) runs genuine per-run variation. */
static inline void idle_spin(long n) {
    volatile long a = 0;
    for (long i = 0; i < n; i++) a += i * 0x9E37L + 1;
    sink((uint64_t)a);
}

#endif /* JCEN_COMMON_H */
