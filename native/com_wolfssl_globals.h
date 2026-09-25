/* com_wolfssl_globals.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#include <jni.h>

#ifndef _Included_com_wolfssl_globals
#define _Included_com_wolfssl_globals

/* global JavaVM reference for JNIEnv lookup */
extern JavaVM* g_vm;

/* Cache static jmethodIDs for performance, since they are guaranteed to be the
 * same across all threads once cached. Initialized in JNI_OnLoad() and freed in
 * JNI_OnUnload(). */

/* WolfSSLSession methods
 *     internalIOSSLRecvCallback
 *     internalIOSSLRecvCallback_BB
 *     internalIOSSLSendCallback
 *     internalIOSSLSendCallback_BB
 *     isArrayIORecvCallbackSet
 *     isArrayIOSendCallbackSet
 *     isByteBufferIORecvCallbackSet
 *     isByteBufferIOSendCallbackSet
 */
extern jmethodID g_sslIORecvMethodId;
extern jmethodID g_sslIORecvMethodId_BB;
extern jmethodID g_sslIOSendMethodId;
extern jmethodID g_sslIOSendMethodId_BB;
extern jmethodID g_isArrayIORecvCallbackSet;
extern jmethodID g_isArrayIOSendCallbackSet;
extern jmethodID g_isByteBufferIORecvCallbackSet;
extern jmethodID g_isByteBufferIOSendCallbackSet;

/* ByteBuffer methods */
extern jmethodID g_bufferPositionMethodId;      /* position() */
extern jmethodID g_bufferLimitMethodId;         /* limit() */
extern jmethodID g_bufferHasArrayMethodId;      /* hasArray() */
extern jmethodID g_bufferArrayMethodId;         /* array() */
extern jmethodID g_bufferArrayOffsetMethodId;   /* arrayOffset() */
extern jmethodID g_bufferSetPositionMethodId;   /* position(int) */

/* WolfSSLVerifyCallback methods */
extern jmethodID g_verifyCallbackMethodId;      /* verifyCallback */

/* WOLFSSL_CTX ex_data index used to store the per-WolfSSLContext jobject ref
 * to the user WolfSSLVerifyCallback. Allocated once in
 * Java_com_wolfssl_WolfSSL_init via wolfSSL_CTX_get_ex_new_index(). A
 * negative value means the slot has not yet been allocated. */
extern int g_verifyCbCtxExDataIdx;

/* struct to hold I/O class, object refs */
typedef struct {
    int active;
    jobject obj;
} internCtx;

unsigned int NativePskClientCb(WOLFSSL* ssl, const char* hint, char* identity,
        unsigned int id_max_len, unsigned char* key, unsigned int max_key_len);
unsigned int NativePskServerCb(WOLFSSL* ssl, const char* identity,
        unsigned char* key, unsigned int max_key_len);

/* Helper functions to throw exceptions */
void throwWolfSSLJNIException(JNIEnv* jenv, const char* msg);
void throwWolfSSLException(JNIEnv* jenv, const char* msg);

/* Release process-global jobject refs. Called from JNI_OnUnload() */
void NativeWolfSSLContextCleanup(JNIEnv* jenv);
void NativeWolfSSLSessionCleanup(JNIEnv* jenv);

/* Initialize/free the process-global mutex around verify callback */
int  NativeVerifyCbMutexInit(void);
void NativeVerifyCbMutexFree(void);

/* Lock/unlock the verify callback mutex. Logs on failure. */
int NativeVerifyCbLock(void);
int NativeVerifyCbUnlock(void);

/* Ensure verify callback slot is allocated */
int NativeVerifyCbSlotEnsure(void);

/* Initialize/free the process-global mutex around missing-CRL callback */
int NativeCrlCbMutexInit(void);
void NativeCrlCbMutexFree(void);

/* Lock/unlock the missing-CRL callback mutex. */
int NativeCrlCbLock(void);
int NativeCrlCbUnlock(void);

#endif
