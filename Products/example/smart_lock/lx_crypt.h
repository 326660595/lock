#ifndef _lx_CRYPT_H_
#define _lx_CRYPT_H_

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
// #include "aes.h"
#include "business.h"

#define _OU_
#define _IN_
#define _IO_

uint8_t aes_check_sum(void *data, uint32_t len);

void generate_aes_key(uint8_t *admin);

void lx_aes_encrypt(_IO_ uint8_t *plain);

void lx_aes_decrypt(_IO_ uint8_t *cipher);

#endif //#ifndef _lx_CRYPT_H_