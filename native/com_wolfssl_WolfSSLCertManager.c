/* com_wolfssl_WolfSSLCertManager.c
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <stdio.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>

#include "com_wolfssl_globals.h"
#include "com_wolfssl_WolfSSLCertManager.h"

JNIEXPORT jlong JNICALL Java_com_wolfssl_WolfSSLCertManager_CertManagerNew
  (JNIEnv* jenv, jclass jcl)
{
    (void)jenv;
    (void)jcl;

    return (jlong)(uintptr_t)wolfSSL_CertManagerNew();
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLCertManager_CertManagerFree
  (JNIEnv* jenv, jclass jcl, jlong cm)
{
    (void)jenv;
    (void)jcl;

    wolfSSL_CertManagerFree((WOLFSSL_CERT_MANAGER*)(uintptr_t)cm);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLCertManager_CertManagerLoadCA
  (JNIEnv* jenv, jclass jcl, jlong cm, jstring f, jstring d)
{
    int ret;
    const char* certFile = NULL;
    const char* certPath = NULL;
    (void)jcl;

    if (jenv == NULL || cm == 0) {
        return (jint)BAD_FUNC_ARG;
    }

    certFile = (*jenv)->GetStringUTFChars(jenv, f, 0);
    certPath = (*jenv)->GetStringUTFChars(jenv, d, 0);

    ret = wolfSSL_CertManagerLoadCA((WOLFSSL_CERT_MANAGER*)(uintptr_t)cm,
                                    certFile, certPath);

    (*jenv)->ReleaseStringUTFChars(jenv, f, certFile);
    (*jenv)->ReleaseStringUTFChars(jenv, d, certPath);

    return (jint)ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLCertManager_CertManagerLoadCABuffer
  (JNIEnv* jenv, jclass jcl, jlong cm, jbyteArray in, jlong sz, jint format)
{
    int ret = 0;
    word32 buffSz = 0;
    byte* buff = NULL;
    (void)jcl;

    if (jenv == NULL || in == NULL || (sz < 0)) {
        return BAD_FUNC_ARG;
    }

    buff = (byte*)(*jenv)->GetByteArrayElements(jenv, in, NULL);
    buffSz = (*jenv)->GetArrayLength(jenv, in);

    ret = wolfSSL_CertManagerLoadCABuffer((WOLFSSL_CERT_MANAGER*)(uintptr_t)cm,
                                          buff, buffSz, format);

    (*jenv)->ReleaseByteArrayElements(jenv, in, (jbyte*)buff, JNI_ABORT);

    return (jint)ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLCertManager_CertManagerVerifyBuffer
  (JNIEnv* jenv, jclass jcl, jlong cm, jbyteArray in, jlong sz, jint format)
{
    int ret = 0;
    word32 buffSz = 0;
    byte* buff = NULL;
    (void)jcl;

    if (jenv == NULL || in == NULL || (sz < 0))
        return BAD_FUNC_ARG;

    buff = (byte*)(*jenv)->GetByteArrayElements(jenv, in, NULL);
    buffSz = (*jenv)->GetArrayLength(jenv, in);

    ret = wolfSSL_CertManagerVerifyBuffer((WOLFSSL_CERT_MANAGER*)(uintptr_t)cm,
                                          buff, buffSz, format);

    (*jenv)->ReleaseByteArrayElements(jenv, in, (jbyte*)buff, JNI_ABORT);

    return (jint)ret;
}

