/* victims.h - cryptographic and benign victim kernels.
 *
 * Each victim exposes:  void victim_init(uint64_t seed);
 *                       void victim_run(uint64_t *secret_out, uint64_t *idx_out);
 * `idx_out` records a secret-dependent memory index (e.g. an S-box lookup
 * offset). It is NOT leaked anywhere; the Stage-4 leakage script uses it,
 * together with the cache trace, to measure mutual information between the
 * secret and the observable access pattern. This is how we quantify how
 * much a given implementation leaks.
 */
#ifndef JCEN_VICTIMS_H
#define JCEN_VICTIMS_H
#include "common.h"

/* =====================================================================
 * AES T-table (LEAKY reference): secret-dependent table indices.
 * Standard textbook T-table structure; one round is enough to exhibit
 * the key-dependent cache-line access pattern we want to study.
 * ===================================================================== */
#ifdef VICTIM_AES_TTABLE
#define AES_TTABLE
static uint32_t Te0[256];
static uint8_t  aes_key[16];
static uint8_t  aes_pt[16];

static void aes_tables_init(void) {
    /* Fill a stand-in T-table; the exact values are irrelevant for the
     * *access pattern*, which is what leaks. Each entry maps to a distinct
     * cache line region spread over 1 KiB (256*4 B). */
    for (int i = 0; i < 256; i++) Te0[i] = 0x01010101u * (uint32_t)i;
}
static void victim_init(uint64_t seed) {
    uint64_t s = seed;
    for (int i = 0; i < 16; i++) aes_key[i] = (uint8_t)sm64(&s);
    for (int i = 0; i < 16; i++) aes_pt[i]  = (uint8_t)sm64(&s);
    aes_tables_init();
}
static void victim_run(uint64_t *secret_out, uint64_t *idx_out) {
    /* AddRoundKey then a table lookup: the index = pt ^ key is the
     * classic secret-dependent offset exploited by cache attacks. */
    uint8_t x0 = aes_pt[0] ^ aes_key[0];
    uint32_t t = Te0[x0];              /* secret-dependent cache access */
    sink(t);
    *secret_out = aes_key[0];
    *idx_out = x0;                     /* the accessed table index */
}
#endif

/* =====================================================================
 * AES constant-time (SAFE reference): S-box computed with arithmetic,
 * no secret-dependent memory index. Same secret, but idx_out is fixed,
 * so leakage quantification should report ~0 bits.
 * ===================================================================== */
#ifdef VICTIM_AES_CT
static uint8_t aes_key[16], aes_pt[16];
/* GF(2^8) inverse-free affine stand-in: a data-oblivious byte transform.
 * (Representative of a bitsliced/arith S-box: no table, constant flow.) */
static inline uint8_t ct_sbox(uint8_t x) {
    uint8_t y = x;
    y ^= (uint8_t)((y << 1) | (y >> 7));
    y ^= (uint8_t)((y << 2) | (y >> 6));
    y ^= 0x63;
    return y;
}
static void victim_init(uint64_t seed) {
    uint64_t s = seed;
    for (int i = 0; i < 16; i++) aes_key[i] = (uint8_t)sm64(&s);
    for (int i = 0; i < 16; i++) aes_pt[i]  = (uint8_t)sm64(&s);
}
static void victim_run(uint64_t *secret_out, uint64_t *idx_out) {
    uint8_t x0 = aes_pt[0] ^ aes_key[0];
    sink(ct_sbox(x0));                 /* no memory index depends on secret */
    *secret_out = aes_key[0];
    *idx_out = 0;                      /* constant: no data-dependent access */
}
#endif

/* =====================================================================
 * RSA square-and-multiply (LEAKY reference): branch + multiply depends
 * on each secret exponent bit (classic timing/F+R pattern on the
 * multiply routine). Small modulus: we only need the access pattern.
 * ===================================================================== */
#ifdef VICTIM_RSA_SQMUL
static uint64_t rsa_exp, rsa_base, rsa_mod;
static uint64_t mulmod(uint64_t a, uint64_t b, uint64_t m) {
    unsigned __int128 r = (unsigned __int128)a * b; return (uint64_t)(r % m);
}
static void victim_init(uint64_t seed) {
    uint64_t s = seed;
    rsa_exp  = sm64(&s) | 1ULL;        /* odd exponent */
    rsa_base = (sm64(&s) % 100000) + 2;
    rsa_mod  = 0xFFFFFFFBULL;          /* fixed prime-ish modulus */
}
static void victim_run(uint64_t *secret_out, uint64_t *idx_out) {
    uint64_t r = 1, b = rsa_base % rsa_mod;
    uint64_t ones = 0;
    for (int i = 0; i < 32; i++) {
        r = mulmod(r, r, rsa_mod);                 /* square every bit */
        if ((rsa_exp >> i) & 1ULL) {               /* multiply iff bit=1 */
            r = mulmod(r, b, rsa_mod);
            ones++;                                 /* secret-dependent */
        }
    }
    sink(r);
    *secret_out = rsa_exp;
    *idx_out = ones;                   /* Hamming weight proxy of exponent */
}
#endif

/* =====================================================================
 * ChaCha20 quarter-round (SAFE reference): ARX, no tables, no branches.
 * ===================================================================== */
#ifdef VICTIM_CHACHA20
static uint32_t cc_state[16];
#define ROTL(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#define QR(a,b,c,d) ( \
    a+=b, d^=a, d=ROTL(d,16), c+=d, b^=c, b=ROTL(b,12), \
    a+=b, d^=a, d=ROTL(d,8),  c+=d, b^=c, b=ROTL(b,7))
static void victim_init(uint64_t seed) {
    uint64_t s = seed;
    for (int i = 0; i < 16; i++) cc_state[i] = (uint32_t)sm64(&s);
}
static void victim_run(uint64_t *secret_out, uint64_t *idx_out) {
    uint32_t x[16]; memcpy(x, cc_state, sizeof x);
    for (int i = 0; i < 10; i++) {     /* 20 rounds = 10 double rounds */
        QR(x[0], x[4], x[8],  x[12]);
        QR(x[1], x[5], x[9],  x[13]);
        QR(x[5], x[9], x[13], x[1]);
        QR(x[0], x[5], x[10], x[15]);
    }
    uint64_t acc = 0; for (int i = 0; i < 16; i++) acc ^= x[i];
    sink(acc);
    *secret_out = cc_state[4];
    *idx_out = 0;                      /* data-oblivious */
}
#endif

/* =====================================================================
 * Benign: dense matmul and streaming memcpy (no attack behaviour).
 * ===================================================================== */
#ifdef VICTIM_MATMUL
#define N 32
static double A[N*N], B[N*N], C[N*N];
static void victim_init(uint64_t seed) {
    uint64_t s = seed;
    for (int i = 0; i < N*N; i++) { A[i] = (double)(sm64(&s)&0xffff);
                                    B[i] = (double)(sm64(&s)&0xffff); }
}
static void victim_run(uint64_t *secret_out, uint64_t *idx_out) {
    for (int i = 0; i < N; i++)
      for (int j = 0; j < N; j++) {
        double acc = 0;
        for (int k = 0; k < N; k++) acc += A[i*N+k]*B[k*N+j];
        C[i*N+j] = acc;
      }
    sink((uint64_t)C[0]);
    *secret_out = 0; *idx_out = 0;
}
#endif

/* Light bounds-check victim for the Spectre workload: a tiny array sum,
 * so the trace is dominated by the Spectre gadget's probe pattern, not by
 * a heavy memcpy (which made spectre look like benign_memcpy). */
#ifdef VICTIM_BOUNDS
static uint32_t bc_arr[256];
static void victim_init(uint64_t seed) {
    uint64_t s = seed;
    for (int i = 0; i < 256; i++) bc_arr[i] = (uint32_t)sm64(&s);
}
static void victim_run(uint64_t *secret_out, uint64_t *idx_out) {
    uint32_t acc = 0; for (int i = 0; i < 256; i++) acc += bc_arr[i];
    sink(acc);
    *secret_out = bc_arr[0]; *idx_out = 0;
}
#endif

#ifdef VICTIM_MEMCPY
#define BUF (64*1024)
static char *src_buf, *dst_buf;
static void victim_init(uint64_t seed) {
    src_buf = malloc(BUF); dst_buf = malloc(BUF);
    uint64_t s = seed; for (int i = 0; i < BUF; i++) src_buf[i] = (char)sm64(&s);
}
static void victim_run(uint64_t *secret_out, uint64_t *idx_out) {
    memcpy(dst_buf, src_buf, BUF); sink((uint64_t)dst_buf[7]);
    *secret_out = 0; *idx_out = 0;
}
#endif

#endif /* JCEN_VICTIMS_H */
