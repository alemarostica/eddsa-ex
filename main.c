#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>

#include "sign.h"
#include "variations.h"

int main(void) {
    if (sodium_init() < 0) return 1;

    const char *pkey_string = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
    uint8_t priv_key[32];
    for (size_t i = 0; i < 32; i++)
        sscanf(pkey_string + 2*i, "%2hhx", &priv_key[i]);

    uint8_t pub_key_val[32];
    if (keygen(priv_key, pub_key_val)) return 1;

    uint8_t M_val[] = {0x72};
    uint8_t sig_valid[64];
    if (sign(priv_key, M_val, 1, sig_valid)) return 1;

    uint8_t in1_sig[64], in1_pub[32];
    memcpy(in1_sig, sig_valid, 64);
    memcpy(in1_pub, pub_key_val, 32);

    uint8_t in2_sig[64], in2_pub[32];
    memcpy(in2_sig, sig_valid, 64);
    memcpy(in2_pub, ED25519_NEUTRAL, 32);

    uint8_t in3_sig[64], in3_pub[32];
    memcpy(in3_sig, sig_valid, 64);
    memcpy(in3_pub, pub_key_val, 32);
    memcpy(in3_sig, ED25519_NEUTRAL, 32);

    uint8_t in4_sig[64], in4_pub[32];
    memcpy(in4_sig, sig_valid, 64);
    memcpy(in4_pub, pub_key_val, 32);
    {
        uint8_t newS[32];
        add_LE_32(newS, in4_sig + 32, ED25519_L);
        memcpy(in4_sig + 32, newS, 32);
    }

    uint8_t in5_sig[64], in5_pub[32];
    memcpy(in5_sig, sig_valid, 64);
    memcpy(in5_pub, ED25519_NEUTRAL, 32);
    memcpy(in5_sig, ED25519_NEUTRAL, 32);
    {
        uint8_t newS[32];
        add_LE_32(newS, in5_sig + 32, ED25519_L);
        memcpy(in5_sig + 32, newS, 32);
    }

    uint8_t in6_sig[64], in6_pub[32];
    memcpy(in6_sig, sig_valid, 64);
    memcpy(in6_pub, pub_key_val, 32);

    uint8_t M_alt[] = {0x73};

    uint8_t *sigs[6] = {in1_sig, in2_sig, in3_sig, in4_sig, in5_sig, in6_sig};
    uint8_t *pks[6]  = {in1_pub, in2_pub, in3_pub, in4_pub, in5_pub, in6_pub};
    uint8_t *msgs[6] = {M_alt, M_val, M_val, M_val, M_val, M_val};
    size_t msglens[6] = {1, 1, 1, 1, 1, 1};

    int (*verifiers[])(const uint8_t*, const uint8_t*, size_t, const uint8_t*) =
        {verify1, verify2, verify3, verify4, verify5, verify6};

    for (int i = 0; i < 6; i++) {
        for (int j = 0; j < 6; j++) {
            int res = verifiers[j](sigs[i], msgs[i], msglens[i], pks[i]);
            printf("%d", res == 0 ? 1 : 0);
        }
        printf("\n");
    }

    return 0;
}
