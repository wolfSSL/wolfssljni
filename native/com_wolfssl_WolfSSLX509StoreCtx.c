/* com_wolfssl_WolfSSLX509StoreCtx.c
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

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#include "com_wolfssl_globals.h"
#include "com_wolfssl_WolfSSLX509StoreCtx.h"

JNIEXPORT jobjectArray JNICALL Java_com_wolfssl_WolfSSLX509StoreCtx_X509_1STORE_1CTX_1getDerCerts
  (JNIEnv* jenv, jclass jcl, jlong ctx)
{
#ifdef OPENSSL_EXTRA
    jclass arrType;
    X509* x509 = NULL;
    WOLFSSL_STACK* sk = NULL;
    WOLFSSL_X509_STORE_CTX* store = (WOLFSSL_X509_STORE_CTX*)(uintptr_t)ctx;
    const unsigned char* der = NULL;
    int derSz = 0, skNum = 0, i = 0;
    (void)jcl;

    if (!jenv || !ctx) {
        return NULL;
    }

    /* find exception class */
    jclass excClass = (*jenv)->FindClass(jenv,
            "com/wolfssl/WolfSSLJNIException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return NULL;
    }

    /* get WOLFSSL_STACK of WOLFSSL_X509 certs */
    sk = wolfSSL_X509_STORE_GetCerts(store);
    skNum = wolfSSL_sk_X509_num(sk);

    if (sk == NULL || skNum == 0) {
        return NULL;
    }

    /* create new array of byte arrays, of size skNum */
    arrType = (*jenv)->FindClass(jenv, "[B");
    jobjectArray certArr = (*jenv)->NewObjectArray(jenv, skNum, arrType,
                                        (*jenv)->NewByteArray(jenv, 1));
    for (i = 0; i < skNum; i++) {
        x509 = wolfSSL_sk_X509_value(sk, i);
        der = wolfSSL_X509_get_der(x509, &derSz);

        if (der != NULL) {
            /* create byte[] per WOLFSSL_X509 der, add to certArr[] */
            jbyteArray derArr = (*jenv)->NewByteArray(jenv, derSz);
            if (!derArr) {
                (*jenv)->ThrowNew(jenv, excClass,
                    "Failed to create byte array in native getDerCerts()");
                wolfSSL_sk_X509_free(sk);
                return NULL;
            }

            jbyte* buf = (*jenv)->GetByteArrayElements(jenv, derArr, NULL);
            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
                wolfSSL_sk_X509_free(sk);
                return NULL;
            }
            XMEMCPY(buf, der, derSz);
            (*jenv)->ReleaseByteArrayElements(jenv, derArr, buf, 0);
            (*jenv)->SetObjectArrayElement(jenv, certArr, i, derArr);
            (*jenv)->DeleteLocalRef(jenv, derArr);
        }
    }
    wolfSSL_sk_X509_free(sk);

    (*jenv)->DeleteLocalRef(jenv, arrType);

    return certArr;
#else
    (void)jenv;
    (void)jcl;
    (void)ctx;
    return NULL;
#endif
}

