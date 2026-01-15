/* com_wolfssl_WolfSSLCRL.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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

#include <stdio.h>
#include <stdint.h>

#ifdef WOLFSSL_USER_SETTINGS
    #include <wolfssl/wolfcrypt/settings.h>
#else
    #include <wolfssl/options.h>
#endif
#include <wolfssl/version.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/openssl/evp.h>
#include <wolfssl/openssl/x509.h>
#include <wolfssl/error-ssl.h>

#include "com_wolfssl_globals.h"
#include "com_wolfssl_WolfSSLCRL.h"

JNIEXPORT jlong JNICALL Java_com_wolfssl_WolfSSLCRL_X509_1CRL_1new
  (JNIEnv* jenv, jclass jcl)
{
#if defined(HAVE_CRL) && defined(OPENSSL_EXTRA) && defined(WOLFSSL_CERT_GEN)
    WOLFSSL_X509_CRL* crl = NULL;
    (void)jcl;

    if (jenv == NULL) {
        return 0;
    }

    crl = wolfSSL_X509_CRL_new();
    if (crl == NULL) {
        return 0;
    }

    return (jlong)(uintptr_t)crl;
#else
    (void)jenv;
    (void)jcl;
    return 0;
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLCRL_X509_1CRL_1free
  (JNIEnv* jenv, jclass jcl, jlong crlPtr)
{
#if defined(HAVE_CRL) && defined(OPENSSL_EXTRA) && defined(WOLFSSL_CERT_GEN)
    WOLFSSL_X509_CRL* crl = (WOLFSSL_X509_CRL*)(uintptr_t)crlPtr;
    (void)jcl;

    if (jenv == NULL || crl == NULL) {
        return;
    }

    wolfSSL_X509_CRL_free(crl);
#else
    (void)jenv;
    (void)jcl;
    (void)crlPtr;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLCRL_X509_1CRL_1set_1version
  (JNIEnv* jenv, jclass jcl, jlong crlPtr, jint version)
{
#if defined(HAVE_CRL) && defined(OPENSSL_EXTRA) && defined(WOLFSSL_CERT_GEN)
    WOLFSSL_X509_CRL* crl = (WOLFSSL_X509_CRL*)(uintptr_t)crlPtr;
    (void)jcl;

    if (jenv == NULL || crl == NULL) {
        return WOLFSSL_FAILURE;
    }

    return wolfSSL_X509_CRL_set_version(crl, version);
#else
    (void)jenv;
    (void)jcl;
    (void)crlPtr;
    (void)version;
    return (jint)NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLCRL_X509_1CRL_1set_1issuer_1name
  (JNIEnv* jenv, jclass jcl, jlong crlPtr, jlong x509NamePtr)
{
#if defined(HAVE_CRL) && defined(OPENSSL_EXTRA) && defined(WOLFSSL_CERT_GEN)
    WOLFSSL_X509_CRL* crl = (WOLFSSL_X509_CRL*)(uintptr_t)crlPtr;
    WOLFSSL_X509_NAME* name = (WOLFSSL_X509_NAME*)(uintptr_t)x509NamePtr;
    (void)jcl;

    if (jenv == NULL || crl == NULL || name == NULL) {
        return WOLFSSL_FAILURE;
    }

    return wolfSSL_X509_CRL_set_issuer_name(crl, name);
#else
    (void)jenv;
    (void)jcl;
    (void)crlPtr;
    (void)x509NamePtr;
    return (jint)NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLCRL_X509_1CRL_1set_1lastUpdate
  (JNIEnv* jenv, jclass jcl, jlong crlPtr, jbyteArray time)
{
#if defined(HAVE_CRL) && defined(OPENSSL_EXTRA) && defined(WOLFSSL_CERT_GEN)
    WOLFSSL_X509_CRL* crl = (WOLFSSL_X509_CRL*)(uintptr_t)crlPtr;
    byte* timeBuf = NULL;
    int timeSz = 0;
    int ret = 0;
    WOLFSSL_ASN1_TIME asnTime;
    char timeStr[CTC_DATE_SIZE + 1];
    int timeLen = 0;
    (void)jcl;

    if (jenv == NULL || crl == NULL || time == NULL) {
        return 0;
    }

    timeBuf = (byte*)(*jenv)->GetByteArrayElements(jenv, time, NULL);
    timeSz = (*jenv)->GetArrayLength(jenv, time);
    /* Ensure there is enough room for date string (32 bytes) 
       plus 4 bytes of length and 4 bytes for type. */
    if (timeBuf == NULL || timeSz < (CTC_DATE_SIZE + 8)) {
        ret = 0;
    }
    else {
        /* Extract length from bytes 32-35 (assuming native byte order) */
        timeLen = *((int*)(timeBuf + CTC_DATE_SIZE));
        if (timeLen <= 0 || timeLen > CTC_DATE_SIZE) {
            ret = 0;
        }
        else {
            /* Copy time string and null-terminate */
            XMEMCPY(timeStr, timeBuf, timeLen);
            timeStr[timeLen] = '\0';
            /* Create ASN1_TIME object and set string */
            if (wolfSSL_ASN1_TIME_set_string(&asnTime, timeStr) == 1) {
                ret = wolfSSL_X509_CRL_set_lastUpdate(crl, &asnTime);
            }
            else {
                ret = 0;
            }
        }
    }

    (*jenv)->ReleaseByteArrayElements(jenv, time, (jbyte*)timeBuf, JNI_ABORT);

    return (jint)ret;
#else
    (void)jenv;
    (void)jcl;
    (void)crlPtr;
    (void)time;
    return 0;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLCRL_X509_1CRL_1set_1nextUpdate
  (JNIEnv* jenv, jclass jcl, jlong crlPtr, jbyteArray time)
{
#if defined(HAVE_CRL) && defined(OPENSSL_EXTRA) && defined(WOLFSSL_CERT_GEN)
    WOLFSSL_X509_CRL* crl = (WOLFSSL_X509_CRL*)(uintptr_t)crlPtr;
    byte* timeBuf = NULL;
    int timeSz = 0;
    int ret = 0;
    WOLFSSL_ASN1_TIME asnTime;
    char timeStr[CTC_DATE_SIZE + 1];
    int timeLen = 0;
    (void)jcl;

    if (jenv == NULL || crl == NULL || time == NULL) {
        return 0;
    }

    timeBuf = (byte*)(*jenv)->GetByteArrayElements(jenv, time, NULL);
    timeSz = (*jenv)->GetArrayLength(jenv, time);
    /* Ensure there is enough room for date string (32 bytes) 
       plus 4 bytes of length and 4 bytes for type. */
    if (timeBuf == NULL || timeSz < (CTC_DATE_SIZE + 8)) {
        ret = 0;
    }
    else {
        /* Extract length from bytes 32-35 (assuming native byte order) */
        timeLen = *((int*)(timeBuf + CTC_DATE_SIZE));
        if (timeLen <= 0 || timeLen > CTC_DATE_SIZE) {
            ret = 0;
        }
        else {
            /* Copy time string and null-terminate */
            XMEMCPY(timeStr, timeBuf, timeLen);
            timeStr[timeLen] = '\0';
            /* Create ASN1_TIME object and set string */
            if (wolfSSL_ASN1_TIME_set_string(&asnTime, timeStr) == 1) {
                ret = wolfSSL_X509_CRL_set_nextUpdate(crl, &asnTime);
            }
            else {
                ret = 0;
            }
        }
    }

    (*jenv)->ReleaseByteArrayElements(jenv, time, (jbyte*)timeBuf, JNI_ABORT);

    return (jint)ret;
#else
    (void)jenv;
    (void)jcl;
    (void)crlPtr;
    (void)time;
    return 0;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLCRL_X509_1CRL_1add_1revoked
  (JNIEnv* jenv, jclass jcl, jlong crlPtr, jbyteArray serial,
   jbyteArray revDate, jint dateFmt)
{
#if defined(HAVE_CRL) && defined(OPENSSL_EXTRA) && defined(WOLFSSL_CERT_GEN)
    WOLFSSL_X509_CRL* crl = (WOLFSSL_X509_CRL*)(uintptr_t)crlPtr;
    byte* serialBuf = NULL;
    byte* dateBuf = NULL;
    int serialSz = 0;
    int ret = WOLFSSL_SUCCESS;
    (void)jcl;

    if (jenv == NULL || crl == NULL || serial == NULL) {
        return WOLFSSL_FAILURE;
    }

    serialBuf = (byte*)(*jenv)->GetByteArrayElements(jenv, serial, NULL);
    serialSz = (*jenv)->GetArrayLength(jenv, serial);
    if (serialBuf == NULL || serialSz == 0) {
        ret = WOLFSSL_FAILURE;
    }
    else {
        if (revDate != NULL) {
            dateBuf = (byte*)(*jenv)->GetByteArrayElements(jenv, revDate, NULL);
            if (dateBuf == NULL) {
                ret = WOLFSSL_FAILURE;
            }
        }
        if (ret != WOLFSSL_FAILURE) {
            ret = wolfSSL_X509_CRL_add_revoked(crl, serialBuf, serialSz,
                dateBuf, (unsigned char)dateFmt);
        }
        if (dateBuf != NULL) {
            (*jenv)->ReleaseByteArrayElements(jenv, revDate, (jbyte*)dateBuf,
                JNI_ABORT);
        }
    }

    (*jenv)->ReleaseByteArrayElements(jenv, serial, (jbyte*)serialBuf,
        JNI_ABORT);

    return ret;
#else
    (void)jenv;
    (void)jcl;
    (void)crlPtr;
    (void)serial;
    (void)revDate;
    (void)dateFmt;
    return (jint)NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLCRL_X509_1CRL_1add_1revoked_1cert
  (JNIEnv* jenv, jclass jcl, jlong crlPtr, jbyteArray certDer,
   jbyteArray revDate, jint dateFmt)
{
#if defined(HAVE_CRL) && defined(OPENSSL_EXTRA) && defined(WOLFSSL_CERT_GEN)
    WOLFSSL_X509_CRL* crl = (WOLFSSL_X509_CRL*)(uintptr_t)crlPtr;
    byte* certBuf = NULL;
    byte* dateBuf = NULL;
    int certSz = 0;
    int ret = WOLFSSL_SUCCESS;
    (void)jcl;

    if (jenv == NULL || crl == NULL || certDer == NULL) {
        return WOLFSSL_FAILURE;
    }

    certBuf = (byte*)(*jenv)->GetByteArrayElements(jenv, certDer, NULL);
    certSz = (*jenv)->GetArrayLength(jenv, certDer);
    if (certBuf == NULL || certSz == 0) {
        ret = WOLFSSL_FAILURE;
    }
    else {
        if (revDate != NULL) {
            dateBuf = (byte*)(*jenv)->GetByteArrayElements(jenv, revDate, NULL);
            if (dateBuf == NULL) {
                ret = WOLFSSL_FAILURE;
            }
        }
        if (ret != WOLFSSL_FAILURE) {
            ret = wolfSSL_X509_CRL_add_revoked_cert(crl, certBuf, certSz,
                dateBuf, (unsigned char)dateFmt);
        }
        if (dateBuf != NULL) {
            (*jenv)->ReleaseByteArrayElements(jenv, revDate, (jbyte*)dateBuf,
                JNI_ABORT);
        }
    }

    (*jenv)->ReleaseByteArrayElements(jenv, certDer, (jbyte*)certBuf,
        JNI_ABORT);

    return ret;
#else
    (void)jenv;
    (void)jcl;
    (void)crlPtr;
    (void)certDer;
    (void)revDate;
    (void)dateFmt;
    return (jint)NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLCRL_X509_1CRL_1sign
  (JNIEnv* jenv, jclass jcl, jlong crlPtr, jint keyType, jbyteArray keyBytes,
   jint format, jstring digestAlg)
{
#if defined(HAVE_CRL) && defined(OPENSSL_EXTRA) && defined(WOLFSSL_CERT_GEN)
    WOLFSSL_X509_CRL* crl = (WOLFSSL_X509_CRL*)(uintptr_t)crlPtr;
    byte* keyBuf = NULL;
    int keySz = 0;
    byte* derBuf = NULL;
    int derSz = 0;
    WOLFSSL_EVP_PKEY* priv = NULL;
    const WOLFSSL_EVP_MD* md = NULL;
    unsigned char* rsaPrivBuf = NULL;
    const char* mdName = NULL;
    int ret = WOLFSSL_SUCCESS;
    (void)jcl;

    if (jenv == NULL || crl == NULL || keyBytes == NULL) {
        return WOLFSSL_FAILURE;
    }

    keyBuf = (byte*)(*jenv)->GetByteArrayElements(jenv, keyBytes, NULL);
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionClear(jenv);
        return WOLFSSL_FAILURE;
    }
    keySz = (*jenv)->GetArrayLength(jenv, keyBytes);

    if (keyBuf == NULL || keySz == 0) {
        ret = WOLFSSL_FAILURE;
    }

    if (ret == WOLFSSL_SUCCESS) {
        if (digestAlg != NULL) {
            mdName = (*jenv)->GetStringUTFChars(jenv, digestAlg, 0);
            if (mdName == NULL) {
                ret = WOLFSSL_FAILURE;
            }
            else {
                md = wolfSSL_EVP_get_digestbyname(mdName);
                if (md == NULL) {
                    ret = WOLFSSL_FAILURE;
                }
            }
        }
    }

    /* convert PEM to DER if needed */
    if (ret == WOLFSSL_SUCCESS) {
        if ((int)format == WOLFSSL_FILETYPE_ASN1) {
            /* already in DER */
            derBuf = keyBuf;
            derSz = keySz;
        }
        else {
            /* get needed buffer size */
            ret = wc_KeyPemToDer(keyBuf, keySz, NULL, 0, NULL);
            if (ret <= 0) {
                ret = WOLFSSL_FAILURE;
            }
            else {
                derSz = ret;
                derBuf = (byte*)XMALLOC(derSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                if (derBuf == NULL) {
                    ret = WOLFSSL_FAILURE;
                }
                else {
                    XMEMSET(derBuf, 0, derSz);
                }
            }
            /* convert PEM to DER */
            if (derBuf != NULL && ret == WOLFSSL_SUCCESS) {
                ret = wc_KeyPemToDer(keyBuf, keySz, derBuf, derSz, NULL);
                if (ret <= 0 || ret != derSz) {
                    ret = WOLFSSL_FAILURE;
                }
            }
        }
    }

    /* convert buffer into WOLFSSL_EVP_PKEY */
    if (ret == WOLFSSL_SUCCESS) {
        /* Use temp pointer since d2i_PrivateKey() modifies the buffer */
        rsaPrivBuf = derBuf;

        priv = wolfSSL_d2i_PrivateKey((int)keyType, NULL,
                (const unsigned char**)&rsaPrivBuf, derSz);
        if (priv == NULL) {
            ret = WOLFSSL_FAILURE;
        }
    }

    /* sign WOLFSSL_X509_CRL with WOLFSSL_EVP_PKEY, returns size of signature
     * on success or negative on error */
    if (ret == WOLFSSL_SUCCESS) {
        ret = wolfSSL_X509_CRL_sign(crl, priv, md);
        if (ret >= 0) {
            ret = WOLFSSL_SUCCESS;
        }
    }

    if (priv != NULL) {
        wolfSSL_EVP_PKEY_free(priv);
    }
    if (derBuf != NULL && derBuf != keyBuf) {
        XMEMSET(derBuf, 0, derSz);
        XFREE(derBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        derBuf = NULL;
    }
    if (mdName != NULL) {
        (*jenv)->ReleaseStringUTFChars(jenv, digestAlg, mdName);
    }
    if (keyBuf != NULL) {
        (*jenv)->ReleaseByteArrayElements(jenv, keyBytes, (jbyte*)keyBuf,
            JNI_ABORT);
    }

    return ret;
#else
    (void)jenv;
    (void)jcl;
    (void)crlPtr;
    (void)keyType;
    (void)keyBytes;
    (void)format;
    (void)digestAlg;
    return (jint)NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLCRL_write_1X509_1CRL
  (JNIEnv* jenv, jclass jcl, jlong crlPtr, jstring path, jint format)
{
#if defined(HAVE_CRL) && defined(OPENSSL_EXTRA) && defined(WOLFSSL_CERT_GEN)
    WOLFSSL_X509_CRL* crl = (WOLFSSL_X509_CRL*)(uintptr_t)crlPtr;
    const char* cPath = NULL;
    int ret = WOLFSSL_FAILURE;
    (void)jcl;

    if (jenv == NULL || crl == NULL || path == NULL) {
        return WOLFSSL_FAILURE;
    }

    cPath = (*jenv)->GetStringUTFChars(jenv, path, NULL);
    if (cPath == NULL) {
        return WOLFSSL_FAILURE;
    }

    ret = wolfSSL_write_X509_CRL(crl, cPath, format);

    (*jenv)->ReleaseStringUTFChars(jenv, path, cPath);

    return ret;
#else
    (void)jenv;
    (void)jcl;
    (void)crlPtr;
    (void)path;
    (void)format;
    return (jint)NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLCRL_X509_1CRL_1version
  (JNIEnv* jenv, jclass jcl, jlong crlPtr)
{
#if defined(HAVE_CRL) && defined(OPENSSL_EXTRA) && defined(WOLFSSL_CERT_GEN)
    WOLFSSL_X509_CRL* crl = (WOLFSSL_X509_CRL*)(uintptr_t)crlPtr;
    (void)jcl;

    if (jenv == NULL || crl == NULL) {
        return 0;
    }

    return (jint)wolfSSL_X509_CRL_version(crl);
#else
    (void)jenv;
    (void)jcl;
    (void)crlPtr;
    return 0;
#endif
}

JNIEXPORT jstring JNICALL Java_com_wolfssl_WolfSSLCRL_X509_1CRL_1get_1lastUpdate
  (JNIEnv* jenv, jclass jcl, jlong crlPtr)
{
#if defined(HAVE_CRL) && defined(OPENSSL_EXTRA) && \
    defined(WOLFSSL_CERT_GEN) && !defined(NO_ASN_TIME)
    WOLFSSL_X509_CRL* crl = (WOLFSSL_X509_CRL*)(uintptr_t)crlPtr;
    WOLFSSL_ASN1_TIME* date = NULL;
    char timeStr[CTC_DATE_SIZE];
    (void)jcl;

    if (jenv == NULL || crl == NULL) {
        return NULL;
    }

    date = wolfSSL_X509_CRL_get_lastUpdate(crl);
    if (date != NULL) {
        return (*jenv)->NewStringUTF(jenv,
            wolfSSL_ASN1_TIME_to_string(date, timeStr, sizeof(timeStr)));
    }

    return NULL;
#else
    (void)jenv;
    (void)jcl;
    (void)crlPtr;
    return NULL;
#endif
}

JNIEXPORT jstring JNICALL Java_com_wolfssl_WolfSSLCRL_X509_1CRL_1get_1nextUpdate
  (JNIEnv* jenv, jclass jcl, jlong crlPtr)
{
#if defined(HAVE_CRL) && defined(OPENSSL_EXTRA) && \
    defined(WOLFSSL_CERT_GEN) && !defined(NO_ASN_TIME)
    WOLFSSL_X509_CRL* crl = (WOLFSSL_X509_CRL*)(uintptr_t)crlPtr;
    WOLFSSL_ASN1_TIME* date = NULL;
    char timeStr[CTC_DATE_SIZE];
    (void)jcl;

    if (jenv == NULL || crl == NULL) {
        return NULL;
    }

    date = wolfSSL_X509_CRL_get_nextUpdate(crl);
    if (date != NULL) {
        return (*jenv)->NewStringUTF(jenv,
            wolfSSL_ASN1_TIME_to_string(date, timeStr, sizeof(timeStr)));
    }

    return NULL;
#else
    (void)jenv;
    (void)jcl;
    (void)crlPtr;
    return NULL;
#endif
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_WolfSSLCRL_X509_1CRL_1print
  (JNIEnv* jenv, jclass jcl, jlong crlPtr)
{
#if defined(HAVE_CRL) && defined(OPENSSL_EXTRA) && defined(WOLFSSL_CERT_GEN)
    WOLFSSL_BIO* bio;
    int sz = 0;
    char* mem = NULL;
    jbyteArray memArr = NULL;
    WOLFSSL_X509_CRL* crl = (WOLFSSL_X509_CRL*)(uintptr_t)crlPtr;
    (void)jcl;

    if (jenv == NULL || crl == NULL) {
        return NULL;
    }

    bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    if (bio == NULL) {
        return NULL;
    }

    if (wolfSSL_X509_CRL_print(bio, crl) != WOLFSSL_SUCCESS) {
        wolfSSL_BIO_free(bio);
        return NULL;
    }

    sz = wolfSSL_BIO_get_mem_data(bio, &mem);
    if (sz > 0 && mem != NULL) {
        memArr = (*jenv)->NewByteArray(jenv, sz);
        if (memArr == NULL) {
            wolfSSL_BIO_free(bio);
            return NULL;
        }

        (*jenv)->SetByteArrayRegion(jenv, memArr, 0, sz, (jbyte*)mem);
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->DeleteLocalRef(jenv, memArr);
            wolfSSL_BIO_free(bio);
            return NULL;
        }
    }

    wolfSSL_BIO_free(bio);
    return memArr;
#else
    (void)jenv;
    (void)jcl;
    (void)crlPtr;
    return NULL;
#endif
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_WolfSSLCRL_X509_1CRL_1get_1der
  (JNIEnv* jenv, jclass jcl, jlong crlPtr)
{
#if defined(HAVE_CRL) && defined(OPENSSL_EXTRA) && defined(WOLFSSL_CERT_GEN)
    WOLFSSL_X509_CRL* crl = (WOLFSSL_X509_CRL*)(uintptr_t)crlPtr;
    unsigned char* der = NULL;
    jbyteArray derArr = NULL;
    jclass excClass = NULL;
    int sz = 0;
    (void)jcl;

    if (jenv == NULL || crl == NULL) {
        return NULL;
    }

    sz = wolfSSL_i2d_X509_CRL(crl, &der);
    if (sz <= 0) {
        return NULL;
    }

    derArr = (*jenv)->NewByteArray(jenv, sz);
    if (derArr == NULL) {
        (*jenv)->ThrowNew(jenv, jcl,
            "Failed to create byte array in native X509_CRL_get_der");
        XFREE(der, NULL, DYNAMIC_TYPE_OPENSSL);
        return NULL;
    }

    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLJNIException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        (*jenv)->DeleteLocalRef(jenv, derArr);
        XFREE(der, NULL, DYNAMIC_TYPE_OPENSSL);
        return NULL;
    }

    (*jenv)->SetByteArrayRegion(jenv, derArr, 0, sz, (jbyte*)der);
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        (*jenv)->DeleteLocalRef(jenv, derArr);
        XFREE(der, NULL, DYNAMIC_TYPE_OPENSSL);
        (*jenv)->ThrowNew(jenv, excClass,
            "Failed to set byte region in native X509_CRL_get_der");
        return NULL;
    }

    XFREE(der, NULL, DYNAMIC_TYPE_OPENSSL);

    return derArr;
#else
    (void)jenv;
    (void)jcl;
    (void)crlPtr;
    return NULL;
#endif
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_WolfSSLCRL_X509_1CRL_1get_1pem
  (JNIEnv* jenv, jclass jcl, jlong crlPtr)
{
#if defined(HAVE_CRL) && defined(OPENSSL_EXTRA) && defined(WOLFSSL_CERT_GEN)
    WOLFSSL_X509_CRL* crl = (WOLFSSL_X509_CRL*)(uintptr_t)crlPtr;
    unsigned char* der = NULL;
    unsigned char* pem = NULL;
    int sz = 0;
    int pemSz = 0;
    jbyteArray pemArr = NULL;
    jclass excClass = NULL;
    (void)jcl;

    if (jenv == NULL || crl == NULL) {
        return NULL;
    }

    sz = wolfSSL_i2d_X509_CRL(crl, &der);
    if (sz <= 0) {
        return NULL;
    }

    pemSz = wc_DerToPem(der, sz, NULL, 0, CRL_TYPE);
    if (pemSz < 0) {
        XFREE(der, NULL, DYNAMIC_TYPE_OPENSSL);
        return NULL;
    }

    pem = (byte*)XMALLOC(pemSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (pem == NULL) {
        XFREE(der, NULL, DYNAMIC_TYPE_OPENSSL);
        return NULL;
    }
    XMEMSET(pem, 0, pemSz);

    pemSz = wc_DerToPem(der, sz, pem, pemSz, CRL_TYPE);
    if (pemSz < 0) {
        XFREE(der, NULL, DYNAMIC_TYPE_OPENSSL);
        XFREE(pem, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return NULL;
    }
    XFREE(der, NULL, DYNAMIC_TYPE_OPENSSL);

    pemArr = (*jenv)->NewByteArray(jenv, pemSz);
    if (pemArr == NULL) {
        (*jenv)->ThrowNew(jenv, jcl,
            "Failed to create byte array in native X509_CRL_get_pem");
        XFREE(pem, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return NULL;
    }

    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLJNIException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        (*jenv)->DeleteLocalRef(jenv, pemArr);
        XFREE(pem, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return NULL;
    }

    (*jenv)->SetByteArrayRegion(jenv, pemArr, 0, pemSz, (jbyte*)pem);
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        (*jenv)->DeleteLocalRef(jenv, pemArr);
        XFREE(pem, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        (*jenv)->ThrowNew(jenv, excClass,
            "Failed to set byte region in native X509_CRL_get_pem");
        return NULL;
    }

    XFREE(pem, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return pemArr;
#else
    (void)jenv;
    (void)jcl;
    (void)crlPtr;
    return NULL;
#endif
}
