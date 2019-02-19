/* com_wolfssl_WolfSSLCertManager.c
 *
 * Copyright (C) 2006-2018 wolfSSL Inc.
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
    return (jlong)wolfSSL_CertManagerNew();
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLCertManager_CertManagerFree
  (JNIEnv* jenv, jclass jcl, jlong cm)
{
    wolfSSL_CertManagerFree((WOLFSSL_CERT_MANAGER*)cm);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLCertManager_CertManagerLoadCA
  (JNIEnv* jenv, jclass jcl, jlong cm, jstring f, jstring d)
{
    const char* certFile;
    const char* certPath;

    certFile = (*jenv)->GetStringUTFChars(jenv, f, 0);
    certPath = (*jenv)->GetStringUTFChars(jenv, d, 0);
    return (jint)wolfSSL_CertManagerLoadCA((WOLFSSL_CERT_MANAGER*)cm,
            certFile, certPath);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLCertManager_CertManagerLoadCABuffer
  (JNIEnv* jenv, jclass jcl, jlong cm, jbyteArray in, jlong sz, jint format)
{
    unsigned char buff[sz];

    if (!jenv || !in || (sz < 0))
        return BAD_FUNC_ARG;

    /* find exception class */
    jclass excClass = (*jenv)->FindClass(jenv,
            "com/wolfssl/WolfSSLJNIException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return SSL_FAILURE;
    }

    (*jenv)->GetByteArrayRegion(jenv, in, 0, sz, (jbyte*)buff);
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);

        (*jenv)->ThrowNew(jenv, excClass,
                "Failed to get byte region in native useCertificateBuffer");
        return SSL_FAILURE;
    }

    return (jint)wolfSSL_CertManagerLoadCABuffer((WOLFSSL_CERT_MANAGER*)cm,
            buff, sz, format);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLCertManager_CertManagerVerifyBuffer
  (JNIEnv* jenv, jclass jcl, jlong cm, jbyteArray in, jlong sz, jint format)
{
    unsigned char buff[sz];

    if (!jenv || !in || (sz < 0))
        return BAD_FUNC_ARG;

    /* find exception class */
    jclass excClass = (*jenv)->FindClass(jenv,
            "com/wolfssl/WolfSSLJNIException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return SSL_FAILURE;
    }

    (*jenv)->GetByteArrayRegion(jenv, in, 0, sz, (jbyte*)buff);
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);

        (*jenv)->ThrowNew(jenv, excClass,
                "Failed to get byte region in native useCertificateBuffer");
        return SSL_FAILURE;
    }

    return (jint)wolfSSL_CertManagerVerifyBuffer((WOLFSSL_CERT_MANAGER*)cm,
            buff, sz, format);
}
