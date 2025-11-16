#include <assert.h>
#include <sodium.h>
#include <sodium/core.h>
#include <sodium/crypto_core_ed25519.h>
#include <sodium/crypto_hash_sha512.h>
#include <sodium/crypto_scalarmult_ed25519.h>
#include <sodium/crypto_sign_ed25519.h>
#include <sodium/randombytes.h>
#include <sodium/utils.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

#define KEY_LEN 32

int keygen(uint8_t *priv_key, uint8_t *pub_key) {
    uint8_t h[64];
    uint8_t s[32];

    if (crypto_hash_sha512(h, priv_key, KEY_LEN)) {
        fprintf(stderr, "crypto_hash_sha512 error, keygen");
        return 1;
    }

    memcpy(s, h, KEY_LEN);
    s[0] &= 248;
    s[31] &= 63;
    s[31] |= 64;

    // Can use the clamp version if omitting the 3 instructions up here ^
    if (crypto_scalarmult_ed25519_base_noclamp(pub_key, s)) {
        fprintf(stderr, "crypto_scalarmult_ed25519_base_noclamp error, keygen");
        return 1;
    }

    return 0;
}

int sign(uint8_t *priv_key, uint8_t *M, size_t M_len, uint8_t *signature) {
    // 1.
    uint8_t h[64];
    if (crypto_hash_sha512(h, priv_key, KEY_LEN)) {
        fprintf(stderr, "crypto_hash_sha512 error, sign 1");
        return 1;
    }

    uint8_t s[32], prefix[32], a[32];
    memcpy(s, h, KEY_LEN);
    memcpy(prefix, h + 32, KEY_LEN);
    s[0] &= 248;
    s[31] &= 63;
    s[31] |= 64;

    // 2.
    if (crypto_scalarmult_ed25519_base_noclamp(a, s)) {
        fprintf(stderr, "crypto_scalarmult_ed25519_base_noclamp error, sign");
        return 1;
    }

    uint8_t r[64];
    uint8_t *concatenation = (uint8_t *)malloc(KEY_LEN + M_len);
    memcpy(concatenation, prefix, KEY_LEN);
    memcpy(concatenation + KEY_LEN, M, M_len);
    if (crypto_hash_sha512(r, concatenation, KEY_LEN + M_len)) {
        fprintf(stderr, "crypto_hash_sha512 error, sign 2");
        return 1;
    }
    free(concatenation);

    // 3.
    uint8_t r_mod_l[32];
    // Apparently this does not return anything, can't check
    crypto_core_ed25519_scalar_reduce(r_mod_l, r);
    uint8_t R[32];
    if (crypto_scalarmult_ed25519_base_noclamp(R, r_mod_l)) {
        fprintf(stderr, "crypto_scalarmult_ed25519_base_noclamp error, sign 3");
        return 1;
    }

    // 4.
    uint8_t k[64];
    uint8_t *concatenation2 = (uint8_t *)malloc(2 * KEY_LEN + M_len);
    memcpy(concatenation2, R, 32);
    memcpy(concatenation2 + 32, a, 32);
    memcpy(concatenation2 + 64, M, M_len);
    if (crypto_hash_sha512(k, concatenation2, 2 * KEY_LEN + M_len)) {
        fprintf(stderr, "crypto_hash_sha512 error, sign 4");
        return 1;
    }
    free(concatenation2);

    // 5.
    uint8_t k_mod_l[32];
    uint8_t S[32];
    uint8_t ks[32];
    crypto_core_ed25519_scalar_reduce(k_mod_l, k);
    crypto_core_ed25519_scalar_mul(ks, k_mod_l, s);
    crypto_core_ed25519_scalar_add(S, r_mod_l, ks);

    // 6.
    memcpy(signature, R, 32);
    memcpy(signature + 32, S, 32);

    return 0;
}

static const uint8_t ED25519_L[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10};

static int compare_32_le(const uint8_t a[32], const uint8_t b[32]) {
    for (int i = 31; i >= 0; --i) {
        if (a[i] < b[i])
            return -1;
        if (a[i] > b[i])
            return 1;
    }

    return 0;
}

static int scalar_is_canonical(const uint8_t s[32]) { return (compare_32_le(s, ED25519_L) < 0); }

static const uint8_t ED25519_NEUTRAL[32] = {
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

static void add_LE_32(uint8_t out[32], const uint8_t a[32], const uint8_t b[32]) {
    // out = a + b (little-endian 32-byte addition, discard overflow)
    unsigned int carry = 0;
    for (size_t i = 0; i < 32; i++) {
        unsigned int s = (unsigned int)a[i] + (unsigned int)b[i] + carry;
        out[i] = (uint8_t)(s & 0xffu);
        carry = (s >> 8) & 0xffu;
    }
}

// RFC8032 compliant
int verify1(const uint8_t *signature, const uint8_t *M, size_t M_len, const uint8_t *pub_key) {
    const uint8_t *R_bytes = signature;
    const uint8_t *S_bytes = signature + 32;
    uint8_t k_hash[64];
    uint8_t k_mod_l[32];
    uint8_t R_plus_kA[32];
    uint8_t SB[32];

    if (!scalar_is_canonical(S_bytes)) {
#ifdef DEBUG
        fprintf(stderr, "Non canonical S (>= L)\n");
#endif
        return 1;
    }

    uint8_t cofactor[32] = {8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    uint8_t A_mul8[32];
    if (crypto_scalarmult_ed25519_noclamp(A_mul8, cofactor, pub_key) != 0) {
#ifdef DEBUG
        fprintf(stderr, "Public key A: invalid encoding\n");
#endif
        return 1;
    }

    if (sodium_memcmp(A_mul8, ED25519_NEUTRAL, 32) == 0) {
#ifdef DEBUG
        fprintf(stderr, "Public key A: small order (rejected)\n");
#endif
        return 1;
    }

    uint8_t R_mul8[32];
    if (crypto_scalarmult_ed25519_noclamp(R_mul8, cofactor, R_bytes) != 0) {
#ifdef DEBUG
        fprintf(stderr, "R: invalid encoding\n");
#endif
        return 1;
    }

    if (sodium_memcmp(R_mul8, ED25519_NEUTRAL, 32) == 0) {
#ifdef DEBUG
        fprintf(stderr, "R: small order (rejected)\n");
#endif
        return 1;
    }

    size_t concat_len = 32 + 32 + M_len;
    uint8_t *concat = (uint8_t *)malloc(concat_len);
    memcpy(concat, R_bytes, 32);
    memcpy(concat + +32, pub_key, 32);
    memcpy(concat + 64, M, M_len);
    crypto_hash_sha512(k_hash, concat, concat_len);
    sodium_memzero(concat, concat_len);
    free(concat);

    crypto_core_ed25519_scalar_reduce(k_mod_l, k_hash);

    if (crypto_scalarmult_ed25519_base_noclamp(SB, S_bytes) != 0) {
#ifdef DEBUG
        fprintf(stderr, "[S]B failed\n");
#endif
        return 1;
    }

    uint8_t kA[32];
    if (crypto_scalarmult_ed25519_noclamp(kA, k_mod_l, pub_key) != 0) {
#ifdef DEBUG
        fprintf(stderr, "[k]A failed (invalid A?)\n");
#endif
        return 1;
    }

    if (crypto_core_ed25519_add(R_plus_kA, R_bytes, kA) != 0) {
#ifdef DEBUG
        fprintf(stderr, "Point addition failed\n");
#endif
        return 1;
    }

    // Step 5: check equality
    if (sodium_memcmp(SB, R_plus_kA, 32) == 0) {
        return 0;
    } else {
#ifdef DEBUG
        fprintf(stderr, "Signature mismatch\n");
#endif
        return 1;
    }
}

// accepts non canonical S
int verify2(const uint8_t *signature, const uint8_t *M, size_t M_len, const uint8_t *pub_key) {
    const uint8_t *R_bytes = signature;
    const uint8_t *S_bytes = signature + 32;
    uint8_t k_hash[64];
    uint8_t k_mod_l[32];
    uint8_t R_plus_kA[32];
    uint8_t SB[32];

    size_t concat_len = 32 + 32 + M_len;
    uint8_t *concat = malloc(concat_len);
    if (!concat)
        return 1;
    memcpy(concat, R_bytes, 32);
    memcpy(concat + 32, pub_key, 32);
    memcpy(concat + 64, M, M_len);
    crypto_hash_sha512(k_hash, concat, concat_len);
    sodium_memzero(concat, concat_len);
    free(concat);

    crypto_core_ed25519_scalar_reduce(k_mod_l, k_hash);

    if (crypto_scalarmult_ed25519_base_noclamp(SB, S_bytes) != 0) {
#ifdef DEBUG
        fprintf(stderr, "[S]B failed\n");
#endif
        return 1;
    }

    uint8_t kA[32];
    if (crypto_scalarmult_ed25519_noclamp(kA, k_mod_l, pub_key) != 0) {
#ifdef DEBUG
        fprintf(stderr, "[k]A failed\n");
#endif
        return 1;
    }

    crypto_core_ed25519_add(R_plus_kA, R_bytes, kA);

    if (sodium_memcmp(SB, R_plus_kA, 32) == 0)
        return 0;
#ifdef DEBUG
    fprintf(stderr, "Signature mismatch\n");
#endif
    return 1;
}

// does not validate pubkey
int verify3(const uint8_t *signature, const uint8_t *M, size_t M_len, const uint8_t *pub_key) {
    const uint8_t *R_bytes = signature;
    const uint8_t *S_bytes = signature + 32;
    uint8_t k_hash[64];
    uint8_t k_mod_l[32];
    uint8_t R_plus_kA[32];
    uint8_t SB[32];
    size_t concat_len = 32 + 32 + M_len;
    uint8_t *concat = malloc(concat_len);
    if (!concat)
        return 1;
    memcpy(concat, R_bytes, 32);
    memcpy(concat + 32, pub_key, 32);
    memcpy(concat + 64, M, M_len);
    crypto_hash_sha512(k_hash, concat, concat_len);
    sodium_memzero(concat, concat_len);
    free(concat);

    crypto_core_ed25519_scalar_reduce(k_mod_l, k_hash);

    if (crypto_scalarmult_ed25519_base_noclamp(SB, S_bytes) != 0) {
#ifdef DEBUG
        fprintf(stderr, "[S]B failed\n");
#endif
        return 1;
    }

    uint8_t kA[32];
    if (crypto_scalarmult_ed25519_noclamp(kA, k_mod_l, pub_key) != 0) {
#ifdef DEBUG
        fprintf(stderr, "[k]A failed (but we didn't validate A earlier)\n");
#endif
        return 1;
    }

    crypto_core_ed25519_add(R_plus_kA, R_bytes, kA);
    if (sodium_memcmp(SB, R_plus_kA, 32) == 0)
        return 0;
#ifdef DEBUG
    fprintf(stderr, "Signature mismatch\n");
#endif
    return 1;
}

// does not validate R
int verify4(const uint8_t *signature, const uint8_t *M, size_t M_len, const uint8_t *pub_key) {
    const uint8_t *R_bytes = signature;
    const uint8_t *S_bytes = signature + 32;
    uint8_t k_hash[64];
    uint8_t k_mod_l[32];
    uint8_t R_plus_kA[32];
    uint8_t SB[32];

    size_t concat_len = 32 + 32 + M_len;
    uint8_t *concat = malloc(concat_len);
    if (!concat)
        return 1;
    memcpy(concat, R_bytes, 32);
    memcpy(concat + 32, pub_key, 32);
    memcpy(concat + 64, M, M_len);
    crypto_hash_sha512(k_hash, concat, concat_len);
    sodium_memzero(concat, concat_len);
    free(concat);

    crypto_core_ed25519_scalar_reduce(k_mod_l, k_hash);

    if (crypto_scalarmult_ed25519_base_noclamp(SB, S_bytes) != 0) {
#ifdef DEBUG
        fprintf(stderr, "[S]B failed\n");
#endif
        return 1;
    }

    uint8_t kA[32];
    if (crypto_scalarmult_ed25519_noclamp(kA, k_mod_l, pub_key) != 0) {
#ifdef DEBUG
        fprintf(stderr, "[k]A failed\n");
#endif
        return 1;
    }

    crypto_core_ed25519_add(R_plus_kA, R_bytes, kA);

    if (sodium_memcmp(SB, R_plus_kA, 32) == 0)
        return 0;
#ifdef DEBUG
    fprintf(stderr, "Signature mismatch\n");
#endif
    return 1;
}

// validates that A decodes, but does NOT check for small order
int verify5(const uint8_t *signature, const uint8_t *M, size_t M_len,
                const uint8_t *pub_key)
{
    const uint8_t *R_bytes = signature;
    const uint8_t *S_bytes = signature + 32;
    uint8_t k_hash[64];
    uint8_t k_mod_l[32];
    uint8_t R_plus_kA[32];
    uint8_t SB[32];

    if (!scalar_is_canonical(S_bytes)) {
#ifdef DEBUG
        fprintf(stderr, "Non canonical S\n");
#endif
        return 1;
    }

    // ONLY check that pub_key has valid encoding, NOT whether it's small order
    uint8_t dummy[32];
    uint8_t one[32] = {1};
    if (crypto_scalarmult_ed25519_noclamp(dummy, one, pub_key) != 0) {
#ifdef DEBUG
        fprintf(stderr, "Invalid pubkey encoding\n");
#endif
        return 1;
    }

    size_t concat_len = 32 + 32 + M_len;
    uint8_t *concat = malloc(concat_len);
    memcpy(concat, R_bytes, 32);
    memcpy(concat + 32, pub_key, 32);
    memcpy(concat + 64, M, M_len);
    crypto_hash_sha512(k_hash, concat, concat_len);
    free(concat);

    crypto_core_ed25519_scalar_reduce(k_mod_l, k_hash);

    if (crypto_scalarmult_ed25519_base_noclamp(SB, S_bytes) != 0)
        return 1;

    uint8_t kA[32];
    if (crypto_scalarmult_ed25519_noclamp(kA, k_mod_l, pub_key) != 0)
        return 1;

    crypto_core_ed25519_add(R_plus_kA, R_bytes, kA);
    return sodium_memcmp(SB, R_plus_kA, 32) == 0 ? 0 : 1;
}

// boh onestamente
int verify6(const uint8_t *signature, const uint8_t *M, size_t M_len,
                const uint8_t *pub_key)
{
    const uint8_t *R = signature;
    const uint8_t *S = signature + 32;

    uint8_t k_hash[64];
    uint8_t k_mod_l[32];
    uint8_t SB[32];
    uint8_t kA[32];
    uint8_t rhs[32];

    /* === NEW: Validate public key A (but NOT R) === */
    uint8_t A8[32];
    uint8_t cof[32] = {8};
    int aret = crypto_scalarmult_ed25519_noclamp(A8, cof, pub_key);

    if (aret != 0 || sodium_memcmp(A8, ED25519_NEUTRAL, 32) == 0) {
#ifdef DEBUG
        fprintf(stderr, "Public key A rejected (invalid or small order)\n");
#endif
        return 1;
    }

    /* === Correct k hash: R || A || M === */
    size_t clen = 64 + M_len;
    uint8_t *c = malloc(clen);
    memcpy(c, R, 32);
    memcpy(c + 32, pub_key, 32);
    memcpy(c + 64, M, M_len);

    int hret = crypto_hash_sha512(k_hash, c, clen);
    free(c);

    crypto_core_ed25519_scalar_reduce(k_mod_l, k_hash);

    int sbret = crypto_scalarmult_ed25519_base_noclamp(SB, S);

    int karet = crypto_scalarmult_ed25519_noclamp(kA, k_mod_l, pub_key);

    int addret = crypto_core_ed25519_add(rhs, R, kA);

    int eq = (sodium_memcmp(SB, rhs, 32) == 0);

    return eq ? 0 : 1;
}

typedef struct {
    uint8_t signature[64];
    uint8_t pub_key[32];
    uint8_t *M;
    size_t M_len;
} InputCase;

int main(void) {
    if (sodium_init() < 0) {
#ifdef DEBUG
        fprintf(stderr, "Sodium bad");
#endif
        return 1;
    }

    const char *pkey_string = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
    uint8_t priv_key[32];
    for (size_t i = 0; i < 32; i++) {
        sscanf(pkey_string + 2 * i, "%2hhx", &priv_key[i]);
    }

    uint8_t pub_key_val[32];
    if (keygen(priv_key, pub_key_val)) {
#ifdef DEBUG
        fprintf(stderr, "keygen error\n");
#endif
        return 1;
    }

    uint8_t M_val[] = {0x72};
    size_t M_val_len = 1;

    uint8_t sig_valid[64];
    if (sign(priv_key, M_val, M_val_len, sig_valid)) {
#ifdef DEBUG
        fprintf(stderr, "sign error\n");
#endif
        return 1;
    }

    // Clean one, will use wrong message later
    uint8_t in1_sig[64];
    memcpy(in1_sig, sig_valid, 64);
    uint8_t in1_pub[32];
    memcpy(in1_pub, pub_key_val, 32);

    // small order public key
    uint8_t in2_sig[64];
    memcpy(in2_sig, sig_valid, 64);
    uint8_t in2_pub[32];
    memcpy(in2_pub, ED25519_NEUTRAL, 32);
    
    // small order R
    uint8_t in3_sig[64];
    memcpy(in3_sig, sig_valid, 64);
    uint8_t in3_pub[32];
    memcpy(in3_pub, pub_key_val, 32);
    memcpy(in3_sig, ED25519_NEUTRAL, 32);

    // non canonical S (S += L)
    uint8_t in4_sig[64];
    memcpy(in4_sig, sig_valid, 64);
    uint8_t in4_pub[32];
    memcpy(in4_pub, pub_key_val, 32);
    {
        uint8_t newS[32];
        add_LE_32(newS, in4_sig + 32, ED25519_L);
        memcpy(in4_sig + 32, newS, 32);
    }

    // S non-canonical, A invalid, R invalid, but keep k calculation of signer canonical
    uint8_t in5_sig[64];
    memcpy(in5_sig, sig_valid, 64);
    uint8_t in5_pub[32];
    memcpy(in5_pub, ED25519_NEUTRAL, 32);
    memcpy(in5_sig, ED25519_NEUTRAL, 32);
    {
        uint8_t newS[32];
        add_LE_32(newS, in5_sig + 32, ED25519_L);
        memcpy(in5_sig + 32, newS, 32);
    }

    // A nice, non edge, valid, canonical signature
    uint8_t in6_sig[64];
    memcpy(in6_sig, sig_valid, 64);
    uint8_t in6_pub[32];
    memcpy(in6_pub, pub_key_val, 32);

    uint8_t M_alt[] = {0x73};
    size_t M_alt_len = sizeof(M_alt) / sizeof(M_alt[0]);

    uint8_t *sigs[6] = { in1_sig, in2_sig, in3_sig, in4_sig, in5_sig, in6_sig};
    uint8_t *pks[6] = {in1_pub, in2_pub, in3_pub, in4_pub, in5_pub, in6_pub};
    uint8_t *msgs[6] = {M_alt, M_val, M_val, M_val, M_val, M_val};
    size_t msglens[6] = { M_alt_len, M_val_len, M_val_len, M_val_len, M_val_len, M_val_len };
    
    int (*verifiers[])(const uint8_t *, const uint8_t *, size_t,
                       const uint8_t *) = {verify1, verify2, verify3, verify4, verify5, verify6};

    for (int i = 0; i < 6; i++) {
        for (int j = 0; j < 6; j++) {
            int res = verifiers[j](sigs[i], msgs[i], msglens[i], pks[i]);
            int accept = (res == 0) ? 1 : 0;
            printf("%d", accept);
        }
        printf("\n");
    }
    
    return 0;
}
