#ifndef SIGN_H
#define SIGN_H

#include <stdint.h>
#include <stddef.h>

#define KEY_LEN 32

int keygen(uint8_t *priv_key, uint8_t *pub_key);
int sign(uint8_t *priv_key, uint8_t *M, size_t M_len, uint8_t *signature);

#endif // SIGN_H
