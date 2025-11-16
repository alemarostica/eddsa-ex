#include "variations.h"
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

void add_LE_32(uint8_t out[32], const uint8_t a[32], const uint8_t b[32]) {
    unsigned int carry = 0;
    for (size_t i = 0; i < 32; i++) {
        unsigned int s = (unsigned int)a[i] + (unsigned int)b[i] + carry;
        out[i] = (uint8_t)(s & 0xffu);
        carry = (s >> 8) & 0xffu;
    }
}

// ---------- All verify functions ----------

// normal
int verify1(const uint8_t *signature, const uint8_t *M, size_t M_len, const uint8_t *pub_key) {
    const uint8_t *R_bytes = signature;
    const uint8_t *S_bytes = signature + 32;
    uint8_t k_hash[64], k_mod_l[32], R_plus_kA[32], SB[32];

    if (!scalar_is_canonical(S_bytes)) {
#ifdef DEBUG
        fprintf(stderr, "Non canonical S (>= L)\n");
#endif
        return 1;
    }

    uint8_t cofactor[32] = {8};
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

    if (sodium_memcmp(SB, R_plus_kA, 32) == 0)
        return 0;
#ifdef DEBUG
    fprintf(stderr, "Signature mismatch\n");
#endif
    return 1;
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
int verify5(const uint8_t *signature, const uint8_t *M, size_t M_len, const uint8_t *pub_key) {
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
int verify6(const uint8_t *signature, const uint8_t *M, size_t M_len, const uint8_t *pub_key) {
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

    crypto_hash_sha512(k_hash, c, clen);
    free(c);

    crypto_core_ed25519_scalar_reduce(k_mod_l, k_hash);

    crypto_scalarmult_ed25519_base_noclamp(SB, S);

    if (crypto_scalarmult_ed25519_noclamp(kA, k_mod_l, pub_key) != 0) {
#ifdef DEBUG
        fprintf(stderr, "Public key A: invalid encoding\n");
#endif
        return 1;
    }


    crypto_core_ed25519_add(rhs, R, kA);

    int eq = (sodium_memcmp(SB, rhs, 32) == 0);

    return eq ? 0 : 1;
}
