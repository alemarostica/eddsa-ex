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

int verify_var(uint8_t *signature, uint8_t *M, size_t M_len, uint8_t *pub_key, uint8_t variation) {
    const uint8_t *R_bytes = signature;
    const uint8_t *S_bytes = signature + 32;
    uint8_t k_hash[64];
    uint8_t k_mod_l[32];
    uint8_t R_plus_kA[32];
    uint8_t SB[32];


    // Step 1: hash R||A||M -> k
    uint8_t *concat = malloc(32 + 32 + M_len);
    memcpy(concat, R_bytes, 32);
    memcpy(concat + 32, pub_key, 32);
    memcpy(concat + 64, M, M_len);
    crypto_hash_sha512(k_hash, concat, 64 + M_len);
    free(concat);

    crypto_core_ed25519_scalar_reduce(k_mod_l, k_hash);

    // Step 2: compute [S]B
    if (crypto_scalarmult_ed25519_base_noclamp(SB, S_bytes) != 0) {
        fprintf(stderr, "[S]B failed\n");
        return 1;
    }

    // Step 3: compute [k]A
    uint8_t kA[32];
    if (crypto_scalarmult_ed25519_noclamp(kA, k_mod_l, pub_key) != 0) {
        fprintf(stderr, "[k]A failed\n");
        return 1;
    }

    // Step 4: compute R + [k]A
    crypto_core_ed25519_add(R_plus_kA, R_bytes, kA);

    // Step 5: check equality
    if (sodium_memcmp(SB, R_plus_kA, 32) == 0) {
        return 0;
    } else {
        fprintf(stderr, "Signature mismatch\n");
        return 1;
    }
}

int verify(uint8_t *signature, uint8_t *M, size_t M_len, uint8_t *pub_key) {
    return verify_var(signature, M, M_len, pub_key, 1);
}

typedef struct {
    uint8_t signature[64];
    uint8_t pub_key[32];
    uint8_t *M;
    size_t M_len;
} InputCase;

int main(void) {
    if (sodium_init() < 0) {
        fprintf(stderr, "Sodium bad");
        return 1;
    }

    const char *pkey_string = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
    uint8_t M_val[] = {0x72};
    size_t M_val_len = sizeof(M_val) / sizeof(M_val[0]);
    uint8_t M_alt[] = {0x73};
    size_t M_alt_len = sizeof(M_alt) / sizeof(M_alt[0]);

    uint8_t priv_key[KEY_LEN];
    for (size_t i = 0; i < KEY_LEN; i++) {
        sscanf(pkey_string + 2 * i, "%2hhx", &priv_key[i]);
    }
    uint8_t pub_key_val[KEY_LEN];
    if (keygen(priv_key, pub_key_val)) {
        fprintf(stderr, "keygen error");
        return 1;
    }

    uint8_t signature_val[64];
    if (sign(priv_key, M_val, M_val_len, signature_val)) {
        fprintf(stderr, "sign error");
        return 1;
    }

    // --- 2. INPUT COMPONENTS ---
    uint8_t zero_32[32] = {0};
    uint8_t R_val[32], S_val[32];
    memcpy(R_val, signature_val, 32);
    memcpy(S_val, signature_val + 32, 32);

    // R_bad: R_val with the highest bit of the 31st byte set (for v4 failure)
    uint8_t R_bad[32];
    memcpy(R_bad, R_val, 32);
    R_bad[31] |= 0x80;

    // --- 3. DEFINE 6 INPUTS ---
    InputCase inputs[6];

    // i1: R_bad, S_val, A_val, M_alt (Invalid M, R bad bit)
    memcpy(inputs[0].signature, R_bad, 32);
    memcpy(inputs[0].signature + 32, S_val, 32);
    memcpy(inputs[0].pub_key, pub_key_val, 32);
    inputs[0].M = M_alt;
    inputs[0].M_len = M_alt_len;

    // i2: R_val, S_val, A_zero, M_val (Invalid A: zero key)
    memcpy(inputs[1].signature, R_val, 32);
    memcpy(inputs[1].signature + 32, S_val, 32);
    memcpy(inputs[1].pub_key, zero_32, 32); // A = 0
    inputs[1].M = M_val;
    inputs[1].M_len = M_val_len;

    // i3: R_bad, S_val, A_val, M_val (Valid M, R bad bit)
    memcpy(inputs[2].signature, R_bad, 32);
    memcpy(inputs[2].signature + 32, S_val, 32);
    memcpy(inputs[2].pub_key, pub_key_val, 32);
    inputs[2].M = M_val;
    inputs[2].M_len = M_val_len;

    // i4: R_val, S_zero, A_val, M_val (Invalid S: zero scalar)
    memcpy(inputs[3].signature, R_val, 32);
    memcpy(inputs[3].signature + 32, zero_32, 32); // S = 0
    memcpy(inputs[3].pub_key, pub_key_val, 32);
    inputs[3].M = M_val;
    inputs[3].M_len = M_val_len;

    // i5: R_zero, S_val, A_val, M_val (Invalid R: zero point)
    memcpy(inputs[4].signature, zero_32, 32); // R = 0
    memcpy(inputs[4].signature + 32, S_val, 32);
    memcpy(inputs[4].pub_key, pub_key_val, 32);
    inputs[4].M = M_val;
    inputs[4].M_len = M_val_len;

    // i6: R_val, S_val, A_val, M_val (Standard Valid Signature)
    memcpy(inputs[5].signature, signature_val, 64);
    memcpy(inputs[5].pub_key, pub_key_val, 32);
    inputs[5].M = M_val;
    inputs[5].M_len = M_val_len;

    for (int i = 0; i < 6; i++) {     
        for (int j = 0; j < 6; j++) {
            int result = verify_var(inputs[i].signature, inputs[i].M, inputs[i].M_len,
                                    inputs[i].pub_key, j);
            // Print 1 for PASS, 0 for FAIL, space-separated
            printf("%d%s", result ? 0 : 1, (j == 5) ? "" : " ");
        }
        printf("\n"); // Newline for next row
    }

    return 0;
}
