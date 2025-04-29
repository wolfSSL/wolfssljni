/* com_wolfssl_globals.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
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
extern jmethodID g_sslIORecvMethodId;              /* WolfSSLSession.internalIOSSLRecvCallback */
extern jmethodID g_sslIORecvMethodId_BB;           /* WolfSSLSession.internalIOSSLRecvCallback_BB */
extern jmethodID g_sslIOSendMethodId;              /* WolfSSLSession.internalIOSSLSendCallback */
extern jmethodID g_sslIOSendMethodId_BB;           /* WolfSSLSession.internalIOSSLSendCallback_BB */
extern jmethodID g_isArrayIORecvCallbackSet;       /* WolfSSL.isArrayIORecvCallbackSet */
extern jmethodID g_isArrayIOSendCallbackSet;       /* WolfSSL.isArrayIOSendCallbackSet */
extern jmethodID g_isByteBufferIORecvCallbackSet;  /* WolfSSL.isByteBufferIORecvCallbackSet */
extern jmethodID g_isByteBufferIOSendCallbackSet;  /* WolfSSL.isByteBufferIOSendCallbackSet */
extern jmethodID g_bufferPositionMethodId;         /* ByteBuffer.position() */
extern jmethodID g_bufferLimitMethodId;            /* ByteBuffer.limit() */
extern jmethodID g_bufferHasArrayMethodId;         /* ByteBuffer.hasArray() */
extern jmethodID g_bufferArrayMethodId;            /* ByteBuffer.array() */
extern jmethodID g_bufferSetPositionMethodId;      /* ByteBuffer.position(int) */
extern jmethodID g_verifyCallbackMethodId;         /* WolfSSLVerifyCallback.verifyCallback */

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

#endif
