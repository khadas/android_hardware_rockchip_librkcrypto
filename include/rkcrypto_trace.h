/*
 * Copyright (c) 2022 Rockchip Electronics Co. Ltd.
 */
#ifndef _RKCRYPTO_TRACE_H_
#define _RKCRYPTO_TRACE_H_

#include <stdio.h>
#include "rkcrypto_common.h"

#define RKCRYPTO_LOG_TAG	"rkcrypto"

#ifdef ANDROID
#include <android/log.h>

#if DEBUG
#define D_TRACE(fmt,...) \
	__android_log_print(ANDROID_LOG_DEBUG, RKCRYPTO_LOG_TAG,\
			"[%s, %d]: "fmt, __func__, __LINE__, ##__VA_ARGS__)
#else
#define D_TRACE(fmt,...)		(void)0
#endif

#define I_TRACE(fmt,...) \
	__android_log_print(ANDROID_LOG_INFO, RKCRYPTO_LOG_TAG,\
			"[%s, %d]: "fmt, __func__, __LINE__, ##__VA_ARGS__)

#define E_TRACE(fmt,...) \
	__android_log_print(ANDROID_LOG_ERROR, RKCRYPTO_LOG_TAG,\
			"[%s, %d]: "fmt, __func__, __LINE__, ##__VA_ARGS__)

#else /* LINUX */
#if DEBUG
#define D_TRACE(fmt,...) \
	printf("D %s: [%s, %d]: "fmt"\n", RKCRYPTO_LOG_TAG, __func__, __LINE__, ##__VA_ARGS__)
#else
#define D_TRACE(fmt,...)		(void)0
#endif

#define I_TRACE(fmt,...) \
	printf("I %s: [%s, %d]: "fmt"\n", RKCRYPTO_LOG_TAG, __func__, __LINE__, ##__VA_ARGS__)

#define E_TRACE(fmt,...) \
	printf("E %s: [%s, %d]: "fmt"\n", RKCRYPTO_LOG_TAG, __func__, __LINE__, ##__VA_ARGS__)
#endif /* ANDROID */

#define RK_CRYPTO_CHECK_PARAM(_val)\
	do {\
		if (_val) {\
			E_TRACE("RK_CRYPTO_CHECK_PARAM ERR! 0x%08x", RK_CRYPTO_ERR_PARAMETER);\
			return RK_CRYPTO_ERR_PARAMETER;\
		}\
	} while (0)

#endif /* _RKCRYPTO_TRACE_H_ */
