/* driver.c - combines one victim + one attacker (chosen at build time via
 * -D macros in the Makefile) into a single SE-mode trace-generation run.
 *
 * Flow per run:   victim_init ; attacker_init ; ROI ; loop { victim ; attacker }
 * The interleaving over many iterations is what the simulator samples into
 * a temporal feature series. A side-channel log (secret,index) is written to
 * stderr-free stdout for the Stage-4 leakage analysis; it never contains a
 * recovered key, only the victim's own ground-truth, used to MEASURE leakage.
 */
#include "common.h"
#include "victims.h"
#include "attackers.h"

#ifndef RUN_ITERS
#define RUN_ITERS 25   /* per-binary via Makefile -D */
#endif

int main(int argc, char **argv) {
    uint64_t seed = seed_from_argv(argc, argv);
    rng_seed(seed);                 /* drives per-run parameter jitter */
    victim_init(seed);
    attacker_init(seed);

    uint64_t secret = 0, idx = 0;

    /* Capture ground truth BEFORE the (possibly interval-capped) loop, and
     * flush immediately so the write syscall completes early in simulation.
     * The secret is fixed by the seed, so one pre-run read is exact. This
     * guarantees Stage 4 has (secret, idx) even when gem5 stops at the cap. */
    victim_run(&secret, &idx);
    printf("SECRET=%llu IDX=%llu\n",
           (unsigned long long)secret, (unsigned long long)idx);
    fflush(stdout);

    /* Per-run jitter: vary total iterations (+/-~20%) and how many times
     * the victim runs between attacker passes. This gives each seed a
     * distinct trace, as real measurements have, without changing the
     * class-characteristic pattern. */
    int iters = (int)jitter(RUN_ITERS - RUN_ITERS/4, RUN_ITERS/2 + 1);
    ROI_BEGIN();
    for (int i = 0; i < iters; i++) {
        int nvic = (int)jitter(1, 3);           /* 1..3 victim calls */
        for (int v = 0; v < nvic; v++) victim_run(&secret, &idx);
        attacker_run();
    }
    ROI_END();
    return 0;
}
