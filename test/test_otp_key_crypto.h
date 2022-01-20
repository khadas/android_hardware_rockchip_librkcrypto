/*
 * Copyright (c) 2022 Rockchip Electronics Co. Ltd.
 */
#ifndef _TEST_KEYLAD_CRYPTO_H_
#define _TEST_KEYLAD_CRYPTO_H_

#include <stdint.h>

void test_write_otp_key(void);
int test_func_otp_key_cipher(void);
int test_speed_otp_key_cipher(uint32_t count);

#endif /*_TEST_KEYLAD_CRYPTO_H_*/
