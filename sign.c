#include "sign.h"
#include <sodium.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int keygen(uint8_t *priv_key, uint8_t *pub_key) {
    uint8_t h[64], s[32];

    if (crypto_hash_sha512(h, priv_key, KEY_LEN)) {
        fprintf(stderr, "crypto_hash_sha512 error, keygen\n");
        return 1;
    }

    memcpy(s, h, KEY_LEN);
    s[0] &= 248;
    s[31] &= 63;
    s[31] |= 64;

    if (crypto_scalarmult_ed25519_base_noclamp(pub_key, s)) {
        fprintf(stderr, "crypto_scalarmult_ed25519_base_noclamp error, keygen\n");
        return 1;
    }

    return 0;
}

int sign(uint8_t *priv_key, uint8_t *M, size_t M_len, uint8_t *signature) {
    uint8_t h[64], s[32], prefix[32], a[32];

    if (crypto_hash_sha512(h, priv_key, KEY_LEN)) {
        fprintf(stderr, "crypto_hash_sha512 error, sign 1\n");
        return 1;
    }

    memcpy(s, h, KEY_LEN);
    memcpy(prefix, h + 32, KEY_LEN);
    s[0] &= 248;
    s[31] &= 63;
    s[31] |= 64;

    if (crypto_scalarmult_ed25519_base_noclamp(a, s)) {
        fprintf(stderr, "crypto_scalarmult_ed25519_base_noclamp error, sign\n");
        return 1;
    }

    uint8_t r[64];
    uint8_t *concat = malloc(KEY_LEN + M_len);
    memcpy(concat, prefix, KEY_LEN);
    memcpy(concat + KEY_LEN, M, M_len);
    crypto_hash_sha512(r, concat, KEY_LEN + M_len);
    free(concat);

    uint8_t r_mod_l[32], R[32];
    crypto_core_ed25519_scalar_reduce(r_mod_l, r);
    crypto_scalarmult_ed25519_base_noclamp(R, r_mod_l);

    uint8_t k[64], k_mod_l[32], S[32], ks[32];
    uint8_t *concat2 = malloc(2*KEY_LEN + M_len);
    memcpy(concat2, R, 32);
    memcpy(concat2 + 32, a, 32);
    memcpy(concat2 + 64, M, M_len);
    crypto_hash_sha512(k, concat2, 2*KEY_LEN + M_len);
    free(concat2);

    crypto_core_ed25519_scalar_reduce(k_mod_l, k);
    crypto_core_ed25519_scalar_mul(ks, k_mod_l, s);
    crypto_core_ed25519_scalar_add(S, r_mod_l, ks);

    memcpy(signature, R, 32);
    memcpy(signature + 32, S, 32);

    return 0;
}
