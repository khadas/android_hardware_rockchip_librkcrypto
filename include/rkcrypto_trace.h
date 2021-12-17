/*
 * Copyright (c) 2022 Rockchip Electronics Co. Ltd.
 */
#ifndef _RKCRYPTO_TRACE_H_
#define _RKCRYPTO_TRACE_H_

#include <stdio.h>
#include "rkcrypto_common.h"

#if DEBUG
#define D_TRACE(fmt,...) \
	printf("%s(%d)-<%s>: "fmt, "\n", __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__)
#else
#define D_TRACE(fmt,...)		(void)0
#endif

#define E_TRACE(fmt,...) \
	printf("%s(%d)-<%s>: "fmt"\n", __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__)

#define RK_ALG_CHECK_PARAM(_val)\
	do {\
		if (_val) {\
			E_TRACE("RK_ALG_CHECK_PARAM ERR! 0x%08x", RK_ALG_ERR_PARAMETER);\
			return RK_ALG_ERR_PARAMETER;\
		}\
	} while (0)

#endif /* _RKCRYPTO_TRACE_H_ */