/* com_wolfssl_WolfSSLCertificate.c
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
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/openssl/evp.h>    /* for EVP_PKEY functions */
#include <wolfssl/openssl/x509v3.h> /* for WOLFSSL_X509_EXTENSION */
#include <wolfssl/error-ssl.h>

#include "com_wolfssl_globals.h"
#include "com_wolfssl_WolfSSLCertificate.h"

JNIEXPORT jlong JNICALL Java_com_wolfssl_WolfSSLCertificate_X509_1new
  (JNIEnv* jenv, jclass jcl)
{
    WOLFSSL_X509* x509 = NULL;
    (void)jcl;

    if (jenv == NULL) {
        return 0;
    }

    x509 = wolfSSL_X509_new();
    if (x509 == NULL) {
        return 0;
    }

    return (jlong)(uintptr_t)x509;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLCertificate_X509_1set_1subject_1name
  (JNIEnv* jenv, jclass jcl, jlong x509Ptr, jlong x509NamePtr)
{
#if !defined(WOLFCRYPT_ONLY) && !defined(NO_CERTS) && \
    (defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL))
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)(uintptr_t)x509Ptr;
    WOLFSSL_X509_NAME* x509Name = (WOLFSSL_X509_NAME*)(uintptr_t)x509NamePtr;
    int ret = WOLFSSL_FAILURE;
    (void)jcl;

    if (jenv == NULL || x509 == NULL || x509Name == NULL) {
        return ret;
    }

    ret = wolfSSL_X509_set_subject_name(x509, x509Name);

    return ret;
#else
    (void)jenv;
    (void)jcl;
    (void)x509Ptr;
    (void)x509NamePtr;
    return (jint)NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLCertificate_X509_1set_1issuer_1name
  (JNIEnv* jenv, jclass jcl, jlong x509Ptr, jlong x509NamePtr)
{
#if !defined(WOLFCRYPT_ONLY) && !defined(NO_CERTS) && \
    (defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL))
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)(uintptr_t)x509Ptr;
    WOLFSSL_X509_NAME* x509Name = (WOLFSSL_X509_NAME*)(uintptr_t)x509NamePtr;
    int ret = WOLFSSL_FAILURE;
    (void)jcl;

    if (jenv == NULL || x509 == NULL || x509Name == NULL) {
        return ret;
    }

    ret = wolfSSL_X509_set_issuer_name(x509, x509Name);

    return ret;
#else
    (void)jenv;
    (void)jcl;
    (void)x509Ptr;
    (void)x509NamePtr;
    return (jint)NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLCertificate_X509_1set_1issuer_1name_1from_1der
  (JNIEnv* jenv, jclass jcl, jlong x509Ptr, jbyteArray certDer)
{
#if !defined(WOLFCRYPT_ONLY) && !defined(NO_CERTS) && \
    (defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL))
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)(uintptr_t)x509Ptr;
    WOLFSSL_X509* x509In = NULL;
    WOLFSSL_X509_NAME* name = NULL;
    byte* der = NULL;
    int derSz = 0;
    int ret = WOLFSSL_SUCCESS;
    (void)jcl;

    if (jenv == NULL || x509 == NULL || certDer == NULL) {
        return WOLFSSL_FAILURE;
    }

    der = (byte*)(*jenv)->GetByteArrayElements(jenv, certDer, NULL);
    derSz = (*jenv)->GetArrayLength(jenv, certDer);

    if (der == NULL || derSz <= 0) {
        ret = WOLFSSL_FAILURE;
    }

    if (ret == WOLFSSL_SUCCESS) {
        x509In = wolfSSL_X509_load_certificate_buffer(der, derSz,
                    SSL_FILETYPE_ASN1);
        if (x509In == NULL) {
            ret = WOLFSSL_FAILURE;
        }
    }

    if (ret == WOLFSSL_SUCCESS) {
        /* Returns pointer into WOLFSSL_X509, no free needed on name */
        name = wolfSSL_X509_get_issuer_name(x509In);
        if (name == NULL) {
            ret = WOLFSSL_FAILURE;
        }
    }

    if (ret == WOLFSSL_SUCCESS) {
        ret = wolfSSL_X509_set_issuer_name(x509, name);
    }

    if (x509In != NULL) {
        wolfSSL_X509_free(x509In);
    }

    (*jenv)->ReleaseByteArrayElements(jenv, certDer, (jbyte*)der, JNI_ABORT);

    return ret;
#else
    (void)jenv;
    (void)jcl;
    (void)x509Ptr;
    (void)certDer;
    return (jint)NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLCertificate_X509_1set_1pubkey_1native_1open
  (JNIEnv* jenv, jclass jcl, jlong x509Ptr, jint keyType, jbyteArray fileBytes, jint fileFormat)
{
#if !defined(WOLFCRYPT_ONLY) && !defined(NO_CERTS) && \
    (defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL))
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)(uintptr_t)x509Ptr;

    byte* fileBuf = NULL;
    int fileSz = 0;
    byte* derBuf = NULL;
    int derSz = 0;
    byte derAllocated = 0;
    WOLFSSL_EVP_PKEY* pub = NULL;
    unsigned char* rsaPubBuf = NULL;

    int ret = WOLFSSL_SUCCESS;
    (void)jcl;

    if (jenv == NULL || x509 == NULL) {
        return WOLFSSL_FAILURE;
    }

    fileBuf = (byte*)(*jenv)->GetByteArrayElements(jenv, fileBytes, NULL);
    fileSz = (*jenv)->GetArrayLength(jenv, fileBytes);

    if (fileBuf == NULL || fileSz == 0) {
        ret = WOLFSSL_FAILURE;
    }

    /* convert PEM to DER if needed */
    if (ret == WOLFSSL_SUCCESS) {
        if ((int)fileFormat == WOLFSSL_FILETYPE_ASN1) {
            /* already in DER */
            derBuf = fileBuf;
            derSz = fileSz;
        }
        else {
            /* get needed buffer size */
            ret = wc_KeyPemToDer(fileBuf, fileSz, NULL, 0, NULL);
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
                    ret = WOLFSSL_SUCCESS;
                    derAllocated = 1;
                    XMEMSET(derBuf, 0, derSz);
                }
            }
        }
    }

    /* convert PEM to DER if derBuf has been allocated */
    if (derAllocated == 1 && ret == WOLFSSL_SUCCESS) {
        ret = wc_KeyPemToDer(fileBuf, fileSz, derBuf, derSz, NULL);
        if (ret <= 0 || ret != derSz) {
            ret = WOLFSSL_FAILURE;
        }
        else {
            ret = WOLFSSL_SUCCESS;
        }
    }

    /* convert buffer into WOLFSSL_EVP_PKEY */
    if (ret == WOLFSSL_SUCCESS) {
        rsaPubBuf = derBuf;

        pub = wolfSSL_d2i_PUBKEY(NULL, (const unsigned char**)&rsaPubBuf, derSz);
        if (pub == NULL) {
            ret = WOLFSSL_FAILURE;
        }
    }

    /* set WOLFSSL_EVP_PKEY into WOLFSSL_X509 */
    if (ret == WOLFSSL_SUCCESS) {
        ret = wolfSSL_X509_set_pubkey(x509, pub);
    }

    if (pub != NULL) {
        /* free WOLFSSL_EVP_PKEY, since X509_set_pubkey() makes copy */
        wolfSSL_EVP_PKEY_free(pub);
    }
    if (derAllocated == 1 && derBuf != NULL) {
        XMEMSET(derBuf, 0, derSz);
        XFREE(derBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    (*jenv)->ReleaseByteArrayElements(jenv, fileBytes, (jbyte*)fileBuf,
                                      JNI_ABORT);

    return (jint)ret;
#else
    (void)jenv;
    (void)jcl;
    (void)x509Ptr;
    (void)keyType;
    (void)filePath;
    (void)fileFormat;
    return (jint)NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLCertificate_X509_1add_1altname
  (JNIEnv* jenv, jclass jcl, jlong x509Ptr, jstring altName, jint type)
{
#if !defined(WOLFCRYPT_ONLY) && !defined(NO_CERTS) && defined(OPENSSL_EXTRA)
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)(uintptr_t)x509Ptr;
    const char* name = NULL;
    int ret = WOLFSSL_SUCCESS;
    (void)jcl;

    if (jenv == NULL || x509 == NULL) {
        return WOLFSSL_FAILURE;
    }

    name = (*jenv)->GetStringUTFChars(jenv, altName, 0);

    if (name == NULL) {
        ret = WOLFSSL_FAILURE;
    }
    else {
        ret = wolfSSL_X509_add_altname(x509, name, (int)type);
    }

    (*jenv)->ReleaseStringUTFChars(jenv, altName, name);

    return (jint)ret;
#else
    (void)jenv;
    (void)jcl;
    (void)x509Ptr;
    (void)altName;
    (void)type;
    return (jint)NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLCertificate_X509_1add_1ext_1via_1nconf_1nid
  (JNIEnv* jenv, jclass jcl, jlong x509Ptr, jint nid, jstring extValue, jboolean isCritical)
{
#if !defined(WOLFCRYPT_ONLY) && !defined(NO_CERTS) && defined(OPENSSL_EXTRA)
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)(uintptr_t)x509Ptr;
    WOLFSSL_X509_EXTENSION* ext = NULL;
    const char* value = NULL;
    int ret = WOLFSSL_SUCCESS;
    (void)jcl;

    if (jenv == NULL || x509 == NULL) {
        return WOLFSSL_FAILURE;
    }

    value = (*jenv)->GetStringUTFChars(jenv, extValue, 0);
    if (value == NULL) {
        ret = WOLFSSL_FAILURE;
    }

    if (ret == WOLFSSL_SUCCESS) {
        ext = wolfSSL_X509V3_EXT_nconf_nid(NULL, NULL, (int)nid, value);
        if (ext == NULL) {
            ret = WOLFSSL_FAILURE;
        }
    }

    if (ret == WOLFSSL_SUCCESS) {
        if (isCritical == JNI_TRUE) {
            ret = wolfSSL_X509_EXTENSION_set_critical(ext, 1);
        }
    }

    if (ret == WOLFSSL_SUCCESS) {
        ret = wolfSSL_X509_add_ext(x509, ext, -1);
    }

    if (ext != NULL) {
        wolfSSL_X509_EXTENSION_free(ext);
    }

    (*jenv)->ReleaseStringUTFChars(jenv, extValue, value);

    return (jint)ret;
#else
    (void)jenv;
    (void)jcl;
    (void)x509Ptr;
    (void)nid;
    (void)extValue;
    (void)isCritical;
    return (jint)NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLCertificate_X509_1add_1ext_1via_1set_1object_1boolean
  (JNIEnv* jenv, jclass jcl, jlong x509Ptr, jint nid, jboolean extValue, jboolean isCritical)
{
#if !defined(WOLFCRYPT_ONLY) && !defined(NO_CERTS) && defined(OPENSSL_EXTRA)
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)(uintptr_t)x509Ptr;
    WOLFSSL_X509_EXTENSION* ext = NULL;
    WOLFSSL_ASN1_OBJECT* obj = NULL;
    int ret = WOLFSSL_SUCCESS;
    (void)jcl;

    if (jenv == NULL || x509 == NULL) {
        return WOLFSSL_FAILURE;
    }

    ext = wolfSSL_X509_EXTENSION_new();
    if (ext == NULL) {
        ret = WOLFSSL_FAILURE;
    }

    if (ret == WOLFSSL_SUCCESS) {
        if (isCritical == JNI_TRUE) {
            ret = wolfSSL_X509_EXTENSION_set_critical(ext, 1);
        }
    }

    if (ret == WOLFSSL_SUCCESS) {
        obj = wolfSSL_OBJ_nid2obj((int)nid);
        if (obj == NULL) {
            ret = WOLFSSL_FAILURE;
        }
    }

    if (ret == WOLFSSL_SUCCESS) {
        if (extValue == JNI_TRUE) {
            obj->ca = 1;
        }
        else {
            obj->ca = 0;
        }
    }

    if (ret == WOLFSSL_SUCCESS) {
        ret = wolfSSL_X509_EXTENSION_set_object(ext, obj);
    }

    if (ret == WOLFSSL_SUCCESS) {
        ret = wolfSSL_X509_add_ext(x509, ext, -1);
    }


    if (obj != NULL) {
        wolfSSL_ASN1_OBJECT_free(obj);
    }
    if (ext != NULL) {
        wolfSSL_X509_EXTENSION_free(ext);
    }

    return (jint)ret;
#else
    (void)jenv;
    (void)jcl;
    (void)x509Ptr;
    (void)nid;
    (void)extValue;
    (void)isCritical;
    return (jint)NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLCertificate_X509_1set_1notBefore
  (JNIEnv* jenv, jclass jcl, jlong x509Ptr, jlong notBefore)
{
#if !defined(WOLFCRYPT_ONLY) && !defined(NO_CERTS) && \
    (defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL))

    WOLFSSL_X509* x509 = (WOLFSSL_X509*)(uintptr_t)x509Ptr;
    WOLFSSL_ASN1_TIME* asnBefore = NULL;
    int ret = WOLFSSL_SUCCESS;
    time_t notBeforeTime = (time_t)(long)notBefore;
    (void)jcl;

    if (jenv == NULL || x509 == NULL) {
        return WOLFSSL_FAILURE;
    }

    /* set time_t value into WOLFSSL_ASN1_TIME struct, no adjustment */
    asnBefore = wolfSSL_ASN1_TIME_adj(NULL, notBeforeTime, 0, 0);
    if (asnBefore == NULL) {
        ret = WOLFSSL_FAILURE;
    }

    if (ret == WOLFSSL_SUCCESS) {
        ret = wolfSSL_X509_set_notBefore(x509, asnBefore);
    }

    if (asnBefore != NULL) {
        wolfSSL_ASN1_TIME_free(asnBefore);
    }

    return ret;
#else
    (void)jenv;
    (void)jcl;
    (void)x509Ptr;
    (void)notBefore;
    return (jint)NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLCertificate_X509_1set_1notAfter
  (JNIEnv* jenv, jclass jcl, jlong x509Ptr, jlong notAfter)
{
#if !defined(WOLFCRYPT_ONLY) && !defined(NO_CERTS) && \
    (defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL))

    WOLFSSL_X509* x509 = (WOLFSSL_X509*)(uintptr_t)x509Ptr;
    WOLFSSL_ASN1_TIME* asnAfter = NULL;
    int ret = WOLFSSL_SUCCESS;
    time_t notAfterTime = (time_t)(long)notAfter;
    (void)jcl;

    if (jenv == NULL || x509 == NULL) {
        return WOLFSSL_FAILURE;
    }

    /* set time_t value into WOLFSSL_ASN1_TIME struct, no adjustment */
    asnAfter = wolfSSL_ASN1_TIME_adj(NULL, notAfterTime, 0, 0);
    if (asnAfter == NULL) {
        ret = WOLFSSL_FAILURE;
    }

    if (ret == WOLFSSL_SUCCESS) {
        ret = wolfSSL_X509_set_notAfter(x509, asnAfter);
    }

    if (asnAfter != NULL) {
        wolfSSL_ASN1_TIME_free(asnAfter);
    }

    return ret;
#else
    (void)jenv;
    (void)jcl;
    (void)x509Ptr;
    (void)notAfter;
    return (jint)NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLCertificate_X509_1set_1serialNumber
  (JNIEnv* jenv, jclass jcl, jlong x509Ptr, jbyteArray serialBytes)
{
#if !defined(WOLFCRYPT_ONLY) && !defined(NO_CERTS) && \
    (defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL))
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)(uintptr_t)x509Ptr;
    WOLFSSL_ASN1_INTEGER* serial = NULL;
    byte* serialBuf = NULL;
    int serialSz = 0;
    int ret = WOLFSSL_SUCCESS;
    (void)jcl;

    if (jenv == NULL || x509 == NULL) {
        return WOLFSSL_FAILURE;
    }

    serialBuf = (byte*)(*jenv)->GetByteArrayElements(jenv, serialBytes, NULL);
    serialSz = (*jenv)->GetArrayLength(jenv, serialBytes);

    if (serialBuf == NULL || serialSz == 0) {
        ret = WOLFSSL_FAILURE;
    }

    if (ret == WOLFSSL_SUCCESS) {
        serial = wolfSSL_ASN1_INTEGER_new();
        if (serial == NULL) {
            ret = WOLFSSL_FAILURE;
        }
        else {
            serial->data[0] = ASN_INTEGER;
            serial->data[1] = serialSz;
            XMEMCPY(&serial->data[2], serialBuf, serialSz);
            serial->length = serialSz + 2;
        }
    }

    if (ret == WOLFSSL_SUCCESS) {
        /* copies contents of ASN1_INTEGER, we can free below */
        ret = wolfSSL_X509_set_serialNumber(x509, serial);
    }

    if (serial != NULL) {
        wolfSSL_ASN1_INTEGER_free(serial);
    }

    (*jenv)->ReleaseByteArrayElements(jenv, serialBytes, (jbyte*)serialBuf,
                                      JNI_ABORT);

    return ret;
#else
    (void)jenv;
    (void)jcl;
    (void)x509Ptr;
    (void)serialBytes;
    return (jint)NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLCertificate_X509_1sign
  (JNIEnv* jenv, jclass jcl, jlong x509Ptr, jint keyType, jbyteArray fileBytes, jint fileFormat, jstring digestAlg)
{
#if !defined(WOLFCRYPT_ONLY) && !defined(NO_CERTS) && \
    (defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)) && \
    defined(WOLFSSL_CERT_GEN)
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)(uintptr_t)x509Ptr;

    byte* fileBuf = NULL;
    int fileSz = 0;
    byte* derBuf = NULL;
    int derSz = 0;
    byte derAllocated = 0;
    WOLFSSL_EVP_PKEY* priv = NULL;
    const WOLFSSL_EVP_MD* md = NULL;
    unsigned char* rsaPrivBuf = NULL;
    const char* mdName = NULL;

    int ret = WOLFSSL_SUCCESS;
    (void)jcl;

    if (jenv == NULL || x509 == NULL) {
        return WOLFSSL_FAILURE;
    }

    fileBuf = (byte*)(*jenv)->GetByteArrayElements(jenv, fileBytes, NULL);
    fileSz = (*jenv)->GetArrayLength(jenv, fileBytes);

    if (fileBuf == NULL || fileSz == 0) {
        ret = WOLFSSL_FAILURE;
    }

    /* Set correct WOLFSSL_EVP_MD, does not need to be freed */
    if (ret == WOLFSSL_SUCCESS) {
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

    /* convert PEM to DER if needed */
    if (ret == WOLFSSL_SUCCESS) {
        if ((int)fileFormat == WOLFSSL_FILETYPE_ASN1) {
            /* already in DER */
            derBuf = fileBuf;
            derSz = fileSz;
        }
        else {
            /* get needed buffer size */
            ret = wc_KeyPemToDer(fileBuf, fileSz, NULL, 0, NULL);
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
                    ret = WOLFSSL_SUCCESS;
                    derAllocated = 1;
                    XMEMSET(derBuf, 0, derSz);
                }
            }
        }
    }

    /* convert PEM to DER if derBuf has been allocated */
    if (derAllocated == 1 && ret == WOLFSSL_SUCCESS) {
        ret = wc_KeyPemToDer(fileBuf, fileSz, derBuf, derSz, NULL);
        if (ret <= 0 || ret != derSz) {
            ret = WOLFSSL_FAILURE;
        }
        else {
            ret = WOLFSSL_SUCCESS;
        }
    }

    /* convert buffer into WOLFSSL_EVP_PKEY */
    if (ret == WOLFSSL_SUCCESS) {
        rsaPrivBuf = derBuf;

        priv = wolfSSL_d2i_PrivateKey((int)keyType, NULL,
                (const unsigned char**)&rsaPrivBuf, derSz);
        if (priv == NULL) {
            ret = WOLFSSL_FAILURE;
        }
    }

    /* set version to v3 (only supported currently */
    if (ret == WOLFSSL_SUCCESS) {
        ret = wolfSSL_X509_set_version(x509, 2L);
    }

    /* sign WOLFSSL_X509 with WOLFSSL_EVP_PKEY, returns size of signature
     * on success or negative on error */
    if (ret == WOLFSSL_SUCCESS) {
        ret = wolfSSL_X509_sign(x509, priv, md);
        if (ret >= 0) {
            ret = WOLFSSL_SUCCESS;
        }
    }

    if (priv != NULL) {
        wolfSSL_EVP_PKEY_free(priv);
    }
    if (derAllocated == 1 && derBuf != NULL) {
        XMEMSET(derBuf, 0, derSz);
        XFREE(derBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    (*jenv)->ReleaseByteArrayElements(jenv, fileBytes, (jbyte*)fileBuf,
                                      JNI_ABORT);
    (*jenv)->ReleaseStringUTFChars(jenv, digestAlg, mdName);

    return (jint)ret;
#else
    (void)jenv;
    (void)jcl;
    (void)x509Ptr;
    (void)keyType;
    (void)fileBytes;
    (void)fileFormat;
    (void)digestAlg;
    return (jint)NOT_COMPILED_IN;
#endif
}

JNIEXPORT jlong JNICALL Java_com_wolfssl_WolfSSLCertificate_X509_1load_1certificate_1buffer
  (JNIEnv* jenv, jclass jcl, jbyteArray in, jint format)
{
    WOLFSSL_X509* x509 = NULL;
    byte* certBuf = NULL;
    word32 certBufSz = 0;
    (void)jcl;

    if (jenv == NULL || in == NULL) {
        return 0;
    }

    /* get array, might be copy or direct depending on implementation */
    certBuf = (byte*)(*jenv)->GetByteArrayElements(jenv, in, NULL);
    certBufSz = (*jenv)->GetArrayLength(jenv, in);

    if (certBuf != NULL && certBufSz > 0) {
        x509 = wolfSSL_X509_load_certificate_buffer(certBuf, certBufSz, format);
    }

    /* release array, don't copy back contents */
    (*jenv)->ReleaseByteArrayElements(jenv, in, (jbyte*)certBuf, JNI_ABORT);

    return (jlong)(uintptr_t)x509;
}

JNIEXPORT jlong JNICALL Java_com_wolfssl_WolfSSLCertificate_X509_1load_1certificate_1file
  (JNIEnv* jenv, jclass jcl, jstring filename, jint format)
{
#ifndef NO_FILESYSTEM
    WOLFSSL_X509* x509 = NULL;
    const char* path = NULL;
    (void)jcl;

    if (jenv == NULL || filename == NULL) {
        return 0;
    }

    path = (*jenv)->GetStringUTFChars(jenv, filename, 0);

    if (path != NULL) {
        x509 = wolfSSL_X509_load_certificate_file(path, format);
    }

    (*jenv)->ReleaseStringUTFChars(jenv, filename, path);

    return (jlong)(uintptr_t)x509;
#else
    (void)jenv;
    (void)jcl;
    (void)filename;
    (void)format;
    return 0;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLCertificate_X509_1check_1host
  (JNIEnv* jenv, jclass jcl, jlong x509Ptr, jstring chk, jlong flags, jlong peerNamePtr)
{
#ifndef NO_ASN
    int ret = WOLFSSL_FAILURE;
    const char* hostname = NULL;
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)(uintptr_t)x509Ptr;
    (void)jcl;
    (void)peerNamePtr;

    if (jenv == NULL || chk == NULL) {
        return WOLFSSL_FAILURE;
    }

    hostname = (*jenv)->GetStringUTFChars(jenv, chk, 0);
    if (hostname != NULL) {
        /* peerNamePtr not used */
        ret = wolfSSL_X509_check_host(x509, hostname,
            XSTRLEN(hostname), (unsigned int)flags, NULL);
    }

    (*jenv)->ReleaseStringUTFChars(jenv, chk, hostname);

    return (jint)ret;

#else
    (void)jenv;
    (void)jcl;
    (void)x509Ptr;
    (void)chk;
    (void)flags;
    (void)peerNamePtr;
    return (jint)NOT_COMPILED_IN;
#endif
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_WolfSSLCertificate_X509_1get_1der
  (JNIEnv* jenv, jclass jcl, jlong x509Ptr)
{
    int sz = 0;
    const byte* der = NULL;
    jbyteArray  derArr = NULL;
    jclass excClass = NULL;
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)(uintptr_t)x509Ptr;

    if (jenv == NULL || x509 == NULL) {
        return NULL;
    }

    der = wolfSSL_X509_get_der(x509, &sz);
    if (der == NULL || sz == 0) {
        return NULL;
    }

    derArr = (*jenv)->NewByteArray(jenv, sz);
    if (derArr == NULL) {
        (*jenv)->ThrowNew(jenv, jcl,
            "Failed to create byte array in native X509_get_der");
        return NULL;
    }

    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLJNIException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        (*jenv)->DeleteLocalRef(jenv, derArr);
        return NULL;
    }

    (*jenv)->SetByteArrayRegion(jenv, derArr, 0, sz, (jbyte*)der);
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        (*jenv)->DeleteLocalRef(jenv, derArr);
        (*jenv)->ThrowNew(jenv, excClass,
                "Failed to set byte region in native X509_get_der");
        return NULL;
    }
    return derArr;
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_WolfSSLCertificate_X509_1get_1pem
  (JNIEnv* jenv, jclass jcl, jlong x509Ptr)
{
#ifdef WOLFSSL_DER_TO_PEM
    int sz = 0;
    const byte* der = NULL;
    byte* pem = NULL;
    int pemSz = 0;
    jbyteArray pemArr = NULL;
    jclass excClass = NULL;
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)(uintptr_t)x509Ptr;

    if (jenv == NULL || x509 == NULL) {
        return NULL;
    }

    der = wolfSSL_X509_get_der(x509, &sz);
    if (der == NULL || sz == 0) {
        return NULL;
    }

    pemSz = wc_DerToPem(der, sz, NULL, 0, CERT_TYPE);
    if (pemSz < 0) {
        return NULL;
    }

    pem = (byte*)XMALLOC(pemSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (pem == NULL) {
        return NULL;
    }
    XMEMSET(pem, 0, pemSz);

    pemSz = wc_DerToPem(der, sz, pem, pemSz, CERT_TYPE);
    if (pemSz < 0) {
        XFREE(pem, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return NULL;
    }

    pemArr = (*jenv)->NewByteArray(jenv, pemSz);
    if (pemArr == NULL) {
        (*jenv)->ThrowNew(jenv, jcl,
            "Failed to create byte array in native X509_get_pem");
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
        (*jenv)->ThrowNew(jenv, excClass,
                "Failed to set byte region in native X509_get_pem");
        XFREE(pem, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return NULL;
    }

    XFREE(pem, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return pemArr;
#else
    (void)jenv;
    (void)jcl;
    (void)x509Ptr;
    return NULL;
#endif
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_WolfSSLCertificate_X509_1get_1tbs
  (JNIEnv* jenv, jclass jcl, jlong x509Ptr)
{
    jbyteArray tbsArr;
    int sz;
    const unsigned char* tbs;
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)(uintptr_t)x509Ptr;
    jclass excClass = NULL;

    if (jenv == NULL || x509 == NULL) {
        return NULL;
    }

    tbs = wolfSSL_X509_get_tbs(x509, &sz);
    if (tbs == NULL) {
        return NULL;
    }

    tbsArr = (*jenv)->NewByteArray(jenv, sz);
    if (tbsArr == NULL) {
        (*jenv)->ThrowNew(jenv, jcl,
            "Failed to create byte array in native X509_get_tbs");
        return NULL;
    }

    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLJNIException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        (*jenv)->DeleteLocalRef(jenv, tbsArr);
        return NULL;
    }

    (*jenv)->SetByteArrayRegion(jenv, tbsArr, 0, sz, (jbyte*)tbs);
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        (*jenv)->DeleteLocalRef(jenv, tbsArr);
        (*jenv)->ThrowNew(jenv, excClass,
                "Failed to set byte region in native X509_get_tbs");
        return NULL;
    }
    return tbsArr;
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLCertificate_X509_1free
  (JNIEnv* jenv, jclass jcl, jlong x509Ptr)
{
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)(uintptr_t)x509Ptr;
    (void)jcl;

    if (jenv == NULL || x509 == NULL) {
        return;
    }

    wolfSSL_X509_free(x509);
}

#define MAX_SERIAL_SIZE 32
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLCertificate_X509_1get_1serial_1number
  (JNIEnv* jenv, jclass jcl, jlong x509Ptr, jbyteArray out)
{
    unsigned char s[MAX_SERIAL_SIZE];
    int sz = MAX_SERIAL_SIZE;
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)(uintptr_t)x509Ptr;
    jclass excClass = NULL;
    (void)jcl;

    if (jenv == NULL || x509 == NULL || out == NULL) {
        return BAD_FUNC_ARG;
    }

    if (wolfSSL_X509_get_serial_number(x509, s, &sz) == WOLFSSL_SUCCESS) {
        /* find exception class */
        excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLJNIException");
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return 0;
        }

        (*jenv)->SetByteArrayRegion(jenv, out, 0, sz, (jbyte*)s);
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);

            (*jenv)->ThrowNew(jenv, excClass,
                    "Failed to set byte region in native X509_get_serial_number");
            return 0;
        }
        return sz;
    }
    return 0;
}

JNIEXPORT jstring JNICALL Java_com_wolfssl_WolfSSLCertificate_X509_1notBefore
  (JNIEnv* jenv, jclass jcl, jlong x509Ptr)
{
#if LIBWOLFSSL_VERSION_HEX >= 0x04002000
    WOLFSSL_ASN1_TIME* date = NULL;
#else
    const unsigned char* date = NULL;
#endif
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)(uintptr_t)x509Ptr;
    char ret[32];
    (void)jcl;

    if (jenv == NULL || x509 == NULL) {
        return NULL;
    }

#if LIBWOLFSSL_VERSION_HEX >= 0x04002000
    date = wolfSSL_X509_get_notBefore(x509);
#else
    date = wolfSSL_X509_notBefore(x509);
#endif
    /* returns string holding date i.e. "Thu Jan 07 08:23:09 MST 2021" */
    if (date != NULL) {
        return (*jenv)->NewStringUTF(jenv,
                wolfSSL_ASN1_TIME_to_string((WOLFSSL_ASN1_TIME*)date, ret,
                    sizeof(ret)));
    }
    return NULL;
}

JNIEXPORT jstring JNICALL Java_com_wolfssl_WolfSSLCertificate_X509_1notAfter
  (JNIEnv* jenv, jclass jcl, jlong x509Ptr)
{
#if LIBWOLFSSL_VERSION_HEX >= 0x04002000
    WOLFSSL_ASN1_TIME* date = NULL;
#else
    const unsigned char* date = NULL;
#endif
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)(uintptr_t)x509Ptr;
    char ret[32];
    (void)jcl;

    if (jenv == NULL || x509 == NULL) {
        return NULL;
    }

#if LIBWOLFSSL_VERSION_HEX >= 0x04002000
    date = wolfSSL_X509_get_notAfter(x509);
#else
    date = wolfSSL_X509_notAfter(x509);
#endif
    /* returns string holding date i.e. "Thu Jan 07 08:23:09 MST 2021" */
    if (date != NULL) {
        return (*jenv)->NewStringUTF(jenv,
                wolfSSL_ASN1_TIME_to_string((WOLFSSL_ASN1_TIME*)date,
                    ret, sizeof(ret)));
    }
    return NULL;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLCertificate_X509_1version
  (JNIEnv* jenv, jclass jcl, jlong x509Ptr)
{
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)(uintptr_t)x509Ptr;
    (void)jcl;

    if (jenv == NULL || x509 == NULL) {
        return 0;
    }

    return (jint)wolfSSL_X509_version(x509);
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_WolfSSLCertificate_X509_1get_1signature
  (JNIEnv* jenv, jclass jcl, jlong x509Ptr)
{
    int sz = 0;
    unsigned char* buf = NULL;
    jbyteArray ret = NULL;
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)(uintptr_t)x509Ptr;

    if (jenv == NULL || x509 == NULL) {
        return NULL;
    }

    if (wolfSSL_X509_get_signature(x509, NULL, &sz) != WOLFSSL_SUCCESS) {
        return NULL;
    }

    ret = (*jenv)->NewByteArray(jenv, sz);
    if (!ret) {
        (*jenv)->ThrowNew(jenv, jcl,
            "Failed to create byte array in native X509_get_signature");
        return NULL;
    }

    buf = (unsigned char*)XMALLOC(sz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (buf == NULL) {
        (*jenv)->DeleteLocalRef(jenv, ret);
        return NULL;
    }

    if (wolfSSL_X509_get_signature(x509, buf, &sz) != WOLFSSL_SUCCESS) {
        (*jenv)->DeleteLocalRef(jenv, ret);
        XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return NULL;
    }

    (*jenv)->SetByteArrayRegion(jenv, ret, 0, sz, (jbyte*)buf);
    XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        (*jenv)->DeleteLocalRef(jenv, ret);
        return NULL;
    }

    return ret;
}

JNIEXPORT jstring JNICALL Java_com_wolfssl_WolfSSLCertificate_X509_1get_1signature_1type
  (JNIEnv* jenv, jclass jcl, jlong x509Ptr)
{
    int type;
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)(uintptr_t)x509Ptr;

    if (jenv == NULL || x509 == NULL) {
        return NULL;
    }

    type = wolfSSL_X509_get_signature_type(x509);

    switch (type) {
        case CTC_SHAwDSA:
            return (*jenv)->NewStringUTF(jenv, "SHAwithDSA");
        case CTC_MD2wRSA:
            return (*jenv)->NewStringUTF(jenv, "MD2withRSA");
        case CTC_MD5wRSA:
            return (*jenv)->NewStringUTF(jenv, "MD5withRSA");
        case CTC_SHAwRSA:
            return (*jenv)->NewStringUTF(jenv, "SHAwithRSA");
        case CTC_SHAwECDSA:
            return (*jenv)->NewStringUTF(jenv, "SHAwithECDSA");
        case CTC_SHA224wRSA:
            return (*jenv)->NewStringUTF(jenv, "SHA244withRSA");
        case CTC_SHA224wECDSA:
            return (*jenv)->NewStringUTF(jenv, "SHA244withECDSA");
        case CTC_SHA256wRSA:
            return (*jenv)->NewStringUTF(jenv, "SHA256withRSA");
        case CTC_SHA256wECDSA:
            return (*jenv)->NewStringUTF(jenv, "SHA256withECDSA");
        case CTC_SHA384wRSA:
            return (*jenv)->NewStringUTF(jenv, "SHA384withRSA");
        case CTC_SHA384wECDSA:
            return (*jenv)->NewStringUTF(jenv, "SHA384withECDSA");
        case CTC_SHA512wRSA:
            return (*jenv)->NewStringUTF(jenv, "SHA512withRSA");
        case CTC_SHA512wECDSA:
            return (*jenv)->NewStringUTF(jenv, "SHA512withECDSA");
        case CTC_ED25519:
            return (*jenv)->NewStringUTF(jenv, "ED25519");
        case CTC_RSASSAPSS:
            return (*jenv)->NewStringUTF(jenv, "RSASSA-PSS");

        default:
            (*jenv)->ThrowNew(jenv, jcl, "Unknown signature type");
            return NULL;
    }
}

JNIEXPORT jstring JNICALL Java_com_wolfssl_WolfSSLCertificate_X509_1get_1signature_1OID
  (JNIEnv* jenv, jclass jcl, jlong x509Ptr)
{
    WOLFSSL_ASN1_OBJECT* obj;
    char oid[40];
    int  oidSz = sizeof(oid);
    int  nid;
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)(uintptr_t)x509Ptr;
    (void)jcl;

    if (jenv == NULL || x509 == NULL) {
        return NULL;
    }

    nid = wolfSSL_X509_get_signature_nid(x509);
    obj = wolfSSL_OBJ_nid2obj(nid);
    if (obj == NULL) {
        return NULL;
    }

    oidSz = wolfSSL_OBJ_obj2txt(oid, oidSz, obj, 1);
    if (oidSz <= 0) {
        return NULL;
    }
    wolfSSL_ASN1_OBJECT_free(obj);
    return (*jenv)->NewStringUTF(jenv, oid);
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_WolfSSLCertificate_X509_1print
  (JNIEnv* jenv, jclass jcl, jlong x509Ptr)
{
    WOLFSSL_BIO* bio;
    int sz = 0;
    char* mem = NULL;
    jbyteArray  memArr = NULL;
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)(uintptr_t)x509Ptr;
    (void)jcl;

    if (jenv == NULL || x509 == NULL) {
        return NULL;
    }

    bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    if (bio == NULL) {
        return NULL;
    }

    if (wolfSSL_X509_print(bio, x509) != WOLFSSL_SUCCESS) {
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
            /* failed to set byte region */
            (*jenv)->DeleteLocalRef(jenv, memArr);
            wolfSSL_BIO_free(bio);
            return NULL;
        }
    }
    wolfSSL_BIO_free(bio);
    return memArr;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLCertificate_X509_1get_1isCA
  (JNIEnv* jenv, jclass jcl, jlong x509Ptr)
{
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)(uintptr_t)x509Ptr;
    (void)jcl;

    if (jenv == NULL || x509 == NULL) {
        return 0;
    }

    return (jint)wolfSSL_X509_get_isCA(x509);
}


JNIEXPORT jstring JNICALL Java_com_wolfssl_WolfSSLCertificate_X509_1get_1subject_1name
  (JNIEnv* jenv, jclass jcl, jlong x509Ptr)
{
    WOLFSSL_X509_NAME* name = NULL;
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)(uintptr_t)x509Ptr;
    jstring ret = NULL;
    char* subj = NULL;
    (void)jcl;

    if (jenv == NULL || x509 == NULL) {
        return NULL;
    }

    name = wolfSSL_X509_get_subject_name(x509);
    if (name != NULL) {
        subj = wolfSSL_X509_NAME_oneline(name, NULL, 0);
        if (subj == NULL) {
            return NULL;
        }
        ret = (*jenv)->NewStringUTF(jenv, subj);
        XFREE(subj, NULL, DYNAMIC_TYPE_OPENSSL);
        return ret;
    }
    return NULL;
}

JNIEXPORT jstring JNICALL Java_com_wolfssl_WolfSSLCertificate_X509_1get_1issuer_1name
  (JNIEnv* jenv, jclass jcl, jlong x509Ptr)
{
    WOLFSSL_X509_NAME* name = NULL;
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)(uintptr_t)x509Ptr;
    jstring ret = NULL;
    char* isur = NULL;
    (void)jcl;

    if (jenv == NULL || x509 == NULL) {
        return NULL;
    }

    name = wolfSSL_X509_get_issuer_name(x509);
    if (name != NULL) {
        isur = wolfSSL_X509_NAME_oneline(name, NULL, 0);
        if (isur == NULL) {
            return NULL;
        }
        ret = (*jenv)->NewStringUTF(jenv, isur);
        XFREE(isur, NULL, DYNAMIC_TYPE_OPENSSL);
        return ret;
    }
    return NULL;
}

JNIEXPORT jlong JNICALL Java_com_wolfssl_WolfSSLCertificate_X509_1get_1issuer_1name_1ptr
  (JNIEnv* jenv, jclass jcl, jlong x509Ptr)
{
#if !defined(WOLFCRYPT_ONLY) && !defined(NO_CERTS) && \
    (defined(OPENSSL_EXTRA_X509_SMALL) || defined(KEEP_PEER_CERT) || \
     defined(SESSION_CERTS))
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)(uintptr_t)x509Ptr;
    WOLFSSL_X509_NAME* name = NULL;

    if (jenv == NULL || x509 == NULL) {
        return 0;
    }

    name = wolfSSL_X509_get_issuer_name(x509);
    if (name == NULL) {
        return 0;
    }

    return (jlong)(uintptr_t)name;
#else
    (void)jenv;
    (void)jcl;
    (void)x509Ptr;
    return (jlong)0;
#endif
}

JNIEXPORT jbyteArray JNICALL
Java_com_wolfssl_WolfSSLCertificate_X509_1get_1subject_1name_1DER
  (JNIEnv* jenv, jclass jcl, jlong x509Ptr)
{
#if !defined(WOLFCRYPT_ONLY) && !defined(NO_CERTS) && \
    (defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL))
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)(uintptr_t)x509Ptr;
    WOLFSSL_X509_NAME* name = NULL;
    unsigned char* derBuf = NULL;
    unsigned char* derPtr = NULL;
    int derSz = 0;
    jbyteArray ret = NULL;
    (void)jcl;

    if (jenv == NULL || x509 == NULL) {
        return NULL;
    }

    /* Get subject name */
    name = wolfSSL_X509_get_subject_name(x509);
    if (name == NULL) {
        return NULL;
    }

    /* Convert to DER, first call gets size */
    derSz = wolfSSL_i2d_X509_NAME(name, NULL);
    if (derSz <= 0) {
        return NULL;
    }

    /* Allocate buffer */
    derBuf = (unsigned char*)XMALLOC(derSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (derBuf == NULL) {
        return NULL;
    }

    /* Convert to DER */
    derPtr = derBuf;
    derSz = wolfSSL_i2d_X509_NAME(name, &derPtr);
    if (derSz <= 0) {
        XFREE(derBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return NULL;
    }

    /* Create Java byte array */
    ret = (*jenv)->NewByteArray(jenv, derSz);
    if (ret == NULL) {
        XFREE(derBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return NULL;
    }

    (*jenv)->SetByteArrayRegion(jenv, ret, 0, derSz, (jbyte*)derBuf);
    if ((*jenv)->ExceptionCheck(jenv)) {
        XFREE(derBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return NULL;
    }
    XFREE(derBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
#else
    (void)jenv;
    (void)jcl;
    (void)x509Ptr;
    return NULL;
#endif
}

JNIEXPORT jbyteArray JNICALL
Java_com_wolfssl_WolfSSLCertificate_X509_1get_1issuer_1name_1DER
  (JNIEnv* jenv, jclass jcl, jlong x509Ptr)
{
#if !defined(WOLFCRYPT_ONLY) && !defined(NO_CERTS) && \
    (defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL))
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)(uintptr_t)x509Ptr;
    WOLFSSL_X509_NAME* name = NULL;
    unsigned char* derBuf = NULL;
    unsigned char* derPtr = NULL;
    int derSz = 0;
    jbyteArray ret = NULL;
    (void)jcl;

    if (jenv == NULL || x509 == NULL) {
        return NULL;
    }

    /* Get issuer name */
    name = wolfSSL_X509_get_issuer_name(x509);
    if (name == NULL) {
        return NULL;
    }

    /* Convert to DER, first call gets size */
    derSz = wolfSSL_i2d_X509_NAME(name, NULL);
    if (derSz <= 0) {
        return NULL;
    }

    /* Allocate buffer */
    derBuf = (unsigned char*)XMALLOC(derSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (derBuf == NULL) {
        return NULL;
    }

    /* Convert to DER */
    derPtr = derBuf;
    derSz = wolfSSL_i2d_X509_NAME(name, &derPtr);
    if (derSz <= 0) {
        XFREE(derBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return NULL;
    }

    /* Create Java byte array */
    ret = (*jenv)->NewByteArray(jenv, derSz);
    if (ret == NULL) {
        XFREE(derBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return NULL;
    }

    (*jenv)->SetByteArrayRegion(jenv, ret, 0, derSz, (jbyte*)derBuf);
    if ((*jenv)->ExceptionCheck(jenv)) {
        XFREE(derBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return NULL;
    }
    XFREE(derBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
#else
    (void)jenv;
    (void)jcl;
    (void)x509Ptr;
    return NULL;
#endif
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_WolfSSLCertificate_X509_1get_1pubkey
  (JNIEnv* jenv, jclass jcl, jlong x509Ptr)
{
    int sz = 0;
    unsigned char* buf;
    jbyteArray ret;
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)(uintptr_t)x509Ptr;

    if (jenv == NULL || x509 == NULL) {
        return NULL;
    }

    if (wolfSSL_X509_get_pubkey_buffer(x509, NULL, &sz) != WOLFSSL_SUCCESS) {
        return NULL;
    }

    ret = (*jenv)->NewByteArray(jenv, sz);
    if (!ret) {
        (*jenv)->ThrowNew(jenv, jcl,
            "Failed to create byte array in native X509_get_signature");
        return NULL;
    }

    buf = (unsigned char*)XMALLOC(sz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (buf == NULL) {
        (*jenv)->DeleteLocalRef(jenv, ret);
        return NULL;
    }

    if (wolfSSL_X509_get_pubkey_buffer(x509, buf, &sz) != WOLFSSL_SUCCESS) {
        (*jenv)->DeleteLocalRef(jenv, ret);
        XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return NULL;
    }

    (*jenv)->SetByteArrayRegion(jenv, ret, 0, sz, (jbyte*)buf);
    XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        (*jenv)->DeleteLocalRef(jenv, ret);
        return NULL;
    }

    return ret;
}

JNIEXPORT jstring JNICALL Java_com_wolfssl_WolfSSLCertificate_X509_1get_1pubkey_1type
  (JNIEnv* jenv, jclass jcl, jlong x509Ptr)
{
    int type;
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)(uintptr_t)x509Ptr;

    if (jenv == NULL || x509 == NULL) {
        return NULL;
    }

    type = wolfSSL_X509_get_pubkey_type(x509);
    switch (type) {
        case RSAk:
            return (*jenv)->NewStringUTF(jenv, "RSA");
        case ECDSAk:
            return (*jenv)->NewStringUTF(jenv, "ECC");
        case DSAk:
            return (*jenv)->NewStringUTF(jenv, "DSA");
        case ED25519k:
            return (*jenv)->NewStringUTF(jenv, "EdDSA");
        default:
            (*jenv)->ThrowNew(jenv, jcl, "Unknown public key type");
            return NULL;
    }
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLCertificate_X509_1get_1pathLength
  (JNIEnv* jenv, jclass jcl, jlong x509Ptr)
{
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)(uintptr_t)x509Ptr;
    (void)jcl;

    if (jenv == NULL || x509 == NULL) {
        return 0;
    }

    if (wolfSSL_X509_get_isSet_pathLength(x509)) {
        return (jint)wolfSSL_X509_get_pathLength(x509);
    }
    else {
        return (jint)-1;
    }
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLCertificate_X509_1verify
  (JNIEnv* jenv, jclass jcl, jlong x509Ptr, jbyteArray pubKey, jint pubKeySz)
{
    WOLFSSL_EVP_PKEY* pkey;
    int ret;
    unsigned char* buff = NULL;
#if LIBWOLFSSL_VERSION_HEX >= 0x04004000
    const unsigned char* ptr = NULL;
#else
    unsigned char* ptr = NULL;
#endif
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)(uintptr_t)x509Ptr;

    (void)jcl;

    if (!jenv || !pubKey || ((int)pubKeySz < 0))
        return BAD_FUNC_ARG;

    /* find exception class */
    jclass excClass = (*jenv)->FindClass(jenv,
            "com/wolfssl/WolfSSLJNIException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return WOLFSSL_FAILURE;
    }

    buff = (unsigned char*)XMALLOC(pubKeySz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (buff == NULL) {
        return MEMORY_E;
    }
    XMEMSET(buff, 0, pubKeySz);

    (*jenv)->GetByteArrayRegion(jenv, pubKey, 0, pubKeySz, (jbyte*)buff);
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);

        XFREE(buff, NULL, DYNAMIC_TYPE_TMP_BUFFER);

        (*jenv)->ThrowNew(jenv, excClass,
                "Failed to get byte region in native wolfSSL_X509_verify");

        return WOLFSSL_FAILURE;
    }
    ptr = buff;

    pkey = wolfSSL_d2i_PUBKEY(NULL, &ptr, (int)pubKeySz);
    if (pkey == NULL) {
        XFREE(buff, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return WOLFSSL_FAILURE;
    }

    ret = wolfSSL_X509_verify(x509, pkey);

    wolfSSL_EVP_PKEY_free(pkey);
    XFREE(buff, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;

}

/* getter function for WOLFSSL_ASN1_OBJECT element */
static unsigned char* getOBJData(WOLFSSL_ASN1_OBJECT* obj)
{
    if (obj) {
        return (unsigned char*)obj->obj;
    }
    return NULL;
}

/* getter function for WOLFSSL_ASN1_OBJECT size */
static unsigned int getOBJSize(WOLFSSL_ASN1_OBJECT* obj)
{
    if (obj) {
        return obj->objSz;
    }
    return 0;
}

JNIEXPORT jbooleanArray JNICALL Java_com_wolfssl_WolfSSLCertificate_X509_1get_1key_1usage
  (JNIEnv* jenv, jclass jcl, jlong x509Ptr)
{
    jbooleanArray ret = NULL;
    jboolean values[9];
    unsigned short kuse;
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)(uintptr_t)x509Ptr;

    if (jenv == NULL || x509 == NULL) {
        return NULL;
    }

    kuse = wolfSSL_X509_get_keyUsage(x509);
    if (kuse != 0) {
        ret = (*jenv)->NewBooleanArray(jenv, 9);
        if (!ret) {
            (*jenv)->ThrowNew(jenv, jcl,
                "Failed to create boolean array in native X509_get_key_usage");
            return NULL;
        }

        values[0] = (kuse & KEYUSE_DIGITAL_SIG)? JNI_TRUE : JNI_FALSE;
        values[1] = (kuse & KEYUSE_CONTENT_COMMIT)? JNI_TRUE : JNI_FALSE;
        values[2] = (kuse & KEYUSE_KEY_ENCIPHER)? JNI_TRUE : JNI_FALSE;
        values[3] = (kuse & KEYUSE_DATA_ENCIPHER)? JNI_TRUE : JNI_FALSE;
        values[4] = (kuse & KEYUSE_KEY_AGREE)? JNI_TRUE : JNI_FALSE;
        values[5] = (kuse & KEYUSE_KEY_CERT_SIGN)? JNI_TRUE : JNI_FALSE;
        values[6] = (kuse & KEYUSE_CRL_SIGN)? JNI_TRUE : JNI_FALSE;
        values[7] = (kuse & KEYUSE_ENCIPHER_ONLY)? JNI_TRUE : JNI_FALSE;
        values[8] = (kuse & KEYUSE_DECIPHER_ONLY)? JNI_TRUE : JNI_FALSE;

        (*jenv)->SetBooleanArrayRegion(jenv, ret, 0, 9, values);
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            (*jenv)->DeleteLocalRef(jenv, ret);
            (*jenv)->ThrowNew(jenv, jcl,
                    "Failed to set boolean region getting key usage");
            return NULL;
        }
    }

    return ret;
}

/* Helper function to add an Extended Key Usage (EKU) OID string to the
 * jobjectArray array if the flag is set. Returns updated index in array. */
static int addEkuOid(JNIEnv* jenv, jobjectArray ret, int idx,
    unsigned int ekuBits, unsigned int flag, int nid)
{
    WOLFSSL_ASN1_OBJECT* obj = NULL;
    jstring ekuStr = NULL;
    char oidBuf[128];
    int oidLen = 0;

    if (ekuBits & flag) {

        /* Convert NID to WOLFSSL_ASN1_OBJECT */
        obj = wolfSSL_OBJ_nid2obj(nid);
        if (obj != NULL) {

            /* Convert WOLFSSL_ASN1_OBJECT to OID string */
            oidLen = wolfSSL_OBJ_obj2txt(oidBuf, sizeof(oidBuf), obj, 1);
            if (oidLen > 0) {

                /* Create Java String and add to array */
                ekuStr = (*jenv)->NewStringUTF(jenv, oidBuf);
                if (ekuStr != NULL) {
                    (*jenv)->SetObjectArrayElement(jenv, ret, idx, ekuStr);
                    (*jenv)->DeleteLocalRef(jenv, ekuStr);
                    idx++;
                }
            }

            /* Free WOLFSSL_ASN1_OBJECT */
            wolfSSL_ASN1_OBJECT_free(obj);
        }
    }

    return idx;
}

JNIEXPORT jobjectArray JNICALL Java_com_wolfssl_WolfSSLCertificate_X509_1get_1extended_1key_1usage
  (JNIEnv* jenv, jclass jcl, jlong x509Ptr)
{
    jobjectArray ret = NULL;
    jclass stringClass = NULL;
    unsigned int ekuBits = 0;
    int ekuCount = 0;
    int idx = 0;
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)(uintptr_t)x509Ptr;
    (void)jcl;

    if (jenv == NULL || x509 == NULL) {
        return NULL;
    }

    /* Get extended key usage bitmask from wolfSSL */
    ekuBits = wolfSSL_X509_get_extended_key_usage(x509);
    if (ekuBits == 0) {
        return NULL;
    }

    /* Count how many EKU bits are set */
    if (ekuBits & XKU_SSL_SERVER) ekuCount++;
    if (ekuBits & XKU_SSL_CLIENT) ekuCount++;
    if (ekuBits & XKU_CODE_SIGN)  ekuCount++;
    if (ekuBits & XKU_SMIME)      ekuCount++;
    if (ekuBits & XKU_TIMESTAMP)  ekuCount++;
    if (ekuBits & XKU_OCSP_SIGN)  ekuCount++;

    if (ekuCount == 0) {
        return NULL;
    }

    /* Create String[] array to return */
    stringClass = (*jenv)->FindClass(jenv, "java/lang/String");
    if (stringClass == NULL) {
        return NULL;
    }

    ret = (*jenv)->NewObjectArray(jenv, ekuCount, stringClass, NULL);
    if (ret == NULL) {
        (*jenv)->DeleteLocalRef(jenv, stringClass);
        return NULL;
    }

    /* Add each EKU OID string to array */
    idx = addEkuOid(jenv, ret, idx, ekuBits, XKU_SSL_SERVER,
        EKU_SERVER_AUTH_OID);
    idx = addEkuOid(jenv, ret, idx, ekuBits, XKU_SSL_CLIENT,
        EKU_CLIENT_AUTH_OID);
    idx = addEkuOid(jenv, ret, idx, ekuBits, XKU_CODE_SIGN,
        EKU_CODESIGNING_OID);
    idx = addEkuOid(jenv, ret, idx, ekuBits, XKU_SMIME,
        EKU_EMAILPROTECT_OID);
    idx = addEkuOid(jenv, ret, idx, ekuBits, XKU_TIMESTAMP,
        EKU_TIMESTAMP_OID);
    idx = addEkuOid(jenv, ret, idx, ekuBits, XKU_OCSP_SIGN,
        EKU_OCSP_SIGN_OID);

    (*jenv)->DeleteLocalRef(jenv, stringClass);

    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_WolfSSLCertificate_X509_1get_1extension
  (JNIEnv* jenv, jclass jcl, jlong x509Ptr, jstring oidIn)
{
    int nid = 0;
    jbyteArray ret = NULL;
    const char* oid = NULL;
#if LIBWOLFSSL_VERSION_HEX >= 0x04002000
    int idx = 0;
    WOLFSSL_X509_EXTENSION* ext = NULL;
#endif
    WOLFSSL_ASN1_OBJECT* obj = NULL;
#if LIBWOLFSSL_VERSION_HEX < 0x04002000
    void* sk = NULL;
#endif
    unsigned char* data = NULL;
    unsigned int sz = 0;
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)(uintptr_t)x509Ptr;

    if (jenv == NULL || oidIn == NULL || x509 == NULL) {
        return NULL;
    }

    oid = (*jenv)->GetStringUTFChars(jenv, oidIn, 0);
    nid = wolfSSL_OBJ_txt2nid(oid);
    (*jenv)->ReleaseStringUTFChars(jenv, oidIn, oid);
    if (nid == NID_undef) {
        return NULL;
    }

#if LIBWOLFSSL_VERSION_HEX >= 0x04002000
    /* get extension index, or -1 if not found */
    idx = wolfSSL_X509_get_ext_by_NID(x509, nid, -1);

    if (idx >= 0) {
        /* extension found at idx, get WOLFSSL_ASN1_OBJECT */
        ext = wolfSSL_X509_get_ext(x509, idx);
        if (ext != NULL) {
            obj = ext->obj;
        }
    }
#else
    /* wolfSSL prior to 4.2.0 did not have wolfSSL_X509_get_ext_by_NID */
    sk = wolfSSL_X509_get_ext_d2i(x509, nid, NULL, NULL);
    if (sk == NULL) {
        /* extension was not found or error was encountered */
        return NULL;
    }

    obj = wolfSSL_sk_ASN1_OBJECT_pop((WOLFSSL_STACK*)sk);
#endif

    if (obj != NULL) {
        /* get extension data, set into jbytearray and return */
        data = getOBJData(obj);
        sz = getOBJSize(obj);

        ret = (*jenv)->NewByteArray(jenv, sz);
        if (!ret) {
            (*jenv)->ThrowNew(jenv, jcl,
                "Failed to create byte array in native X509_get_extension");
            return NULL;
        }

        (*jenv)->SetByteArrayRegion(jenv, ret, 0, sz, (jbyte*)data);
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            (*jenv)->DeleteLocalRef(jenv, ret);
            return NULL;
        }
    }
    return ret;
}

/* returns 2 if extension OID is set and is critical
 * returns 1 if extension OID is set but not critical
 * return  0 if not set
 * return negative value on error
 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLCertificate_X509_1is_1extension_1set
  (JNIEnv* jenv, jclass jcl, jlong x509Ptr, jstring oidIn)
{
    int nid;
    const char* oid;
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)(uintptr_t)x509Ptr;
    (void)jcl;

    if (jenv == NULL || x509 == NULL) {
        return 0;
    }

    oid = (*jenv)->GetStringUTFChars(jenv, oidIn, 0);
    nid = wolfSSL_OBJ_txt2nid(oid);
    if (nid == NID_undef) {
        (*jenv)->ReleaseStringUTFChars(jenv, oidIn, oid);
        return -1;
    }
    (*jenv)->ReleaseStringUTFChars(jenv, oidIn, oid);

    if (wolfSSL_X509_ext_isSet_by_NID(x509, nid)) {
        if (wolfSSL_X509_ext_get_critical_by_NID(x509, nid)) {
            return 2;
        }
        return 1;
    }

    return 0;
}

JNIEXPORT jstring JNICALL Java_com_wolfssl_WolfSSLCertificate_X509_1get_1next_1altname
  (JNIEnv* jenv, jclass jcl, jlong x509Ptr)
{
#if defined(KEEP_PEER_CERT) || defined(SESSION_CERTS)
    char* altname;
    jstring retString;
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)(uintptr_t)x509Ptr;
    (void)jcl;

    if (jenv == NULL || x509 == NULL) {
        return NULL;
    }

    altname = wolfSSL_X509_get_next_altname(x509);
    if (altname == NULL) {
        return NULL;
    }
    retString = (*jenv)->NewStringUTF(jenv, altname);
    return retString;

#else
    (void)jenv;
    (void)jcl;
    (void)x509Ptr;
    return NULL;
#endif
}

/* Returns a 2D array (Object[][]) of Subject Alternative Names with type info.
 *
 * Each inner array contains:
 *   - For most types: [Integer type, String value]
 *   - For otherName (type 0): [Integer 0, String oid, byte[] value]
 *   - For iPAddress (type 7): [Integer 7, byte[] value]
 *
 * GeneralName types (from RFC 5280):
 *   0 = otherName
 *   1 = rfc822Name (email)
 *   2 = dNSName
 *   3 = x400Address (not supported)
 *   4 = directoryName
 *   5 = ediPartyName (not supported)
 *   6 = uniformResourceIdentifier
 *   7 = iPAddress
 *   8 = registeredID
 */
JNIEXPORT jobjectArray JNICALL Java_com_wolfssl_WolfSSLCertificate_X509_1get_1subject_1alt_1names_1full
  (JNIEnv* jenv, jclass jcl, jlong x509Ptr)
{
#if !defined(WOLFCRYPT_ONLY) && !defined(NO_CERTS) && defined(OPENSSL_EXTRA)
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)(uintptr_t)x509Ptr;
    WOLFSSL_GENERAL_NAMES* names = NULL;
    WOLFSSL_GENERAL_NAME* entry = NULL;
    jobjectArray outerArray = NULL;
    jclass objectClass = NULL;
    jclass objectArrayClass = NULL;
    jclass integerClass = NULL;
    jmethodID integerInit = NULL;
    int numNames = 0;
    int i = 0;
    int idx = 0;
    (void)jcl;

    if (jenv == NULL || x509 == NULL) {
        return NULL;
    }

    /* Get SAN extension */
    names = (WOLFSSL_GENERAL_NAMES*)wolfSSL_X509_get_ext_d2i(x509,
        NID_subject_alt_name, NULL, NULL);
    if (names == NULL) {
        return NULL;
    }

    /* Get number of SANs */
    numNames = wolfSSL_sk_GENERAL_NAME_num(names);
    if (numNames <= 0) {
        wolfSSL_sk_GENERAL_NAME_pop_free(names, wolfSSL_GENERAL_NAME_free);
        return NULL;
    }

    /* Find java.lang.Object class for inner array elements */
    objectClass = (*jenv)->FindClass(jenv, "java/lang/Object");
    if (objectClass == NULL || (*jenv)->ExceptionCheck(jenv)) {
        wolfSSL_sk_GENERAL_NAME_pop_free(names, wolfSSL_GENERAL_NAME_free);
        return NULL;
    }

    /* Find Object[] class for outer array (to create Object[][]) */
    objectArrayClass = (*jenv)->FindClass(jenv, "[Ljava/lang/Object;");
    if (objectArrayClass == NULL || (*jenv)->ExceptionCheck(jenv)) {
        wolfSSL_sk_GENERAL_NAME_pop_free(names, wolfSSL_GENERAL_NAME_free);
        return NULL;
    }

    /* Find Integer class and constructor */
    integerClass = (*jenv)->FindClass(jenv, "java/lang/Integer");
    if (integerClass == NULL || (*jenv)->ExceptionCheck(jenv)) {
        wolfSSL_sk_GENERAL_NAME_pop_free(names, wolfSSL_GENERAL_NAME_free);
        return NULL;
    }
    integerInit = (*jenv)->GetMethodID(jenv, integerClass, "<init>", "(I)V");
    if (integerInit == NULL || (*jenv)->ExceptionCheck(jenv)) {
        wolfSSL_sk_GENERAL_NAME_pop_free(names, wolfSSL_GENERAL_NAME_free);
        return NULL;
    }

    /* Create outer array (Object[][]) to hold all SAN entries */
    outerArray = (*jenv)->NewObjectArray(jenv, numNames, objectArrayClass,
        NULL);
    if (outerArray == NULL || (*jenv)->ExceptionCheck(jenv)) {
        wolfSSL_sk_GENERAL_NAME_pop_free(names, wolfSSL_GENERAL_NAME_free);
        return NULL;
    }

    for (i = 0; i < numNames; i++) {
        jobjectArray innerArray = NULL;
        jobject typeObj = NULL;
        jstring valueStr = NULL;
        jbyteArray valueBytes = NULL;
        const char* strValue = NULL;
        int innerSize = 2;  /* default: [type, value] */
        int type = 0;

        /* Check for pending exceptions before each iteration */
        if ((*jenv)->ExceptionCheck(jenv)) {
            break;
        }

        entry = wolfSSL_sk_GENERAL_NAME_value(names, i);
        if (entry == NULL) {
            continue;
        }
        type = entry->type;

        switch (type) {
            case GEN_OTHERNAME: /* 0 - otherName */
            {
                /* For otherName: [type, oid_string, value_bytes] */
                int oidLen = 0;
                int derSz = 0;
                unsigned char* derBuf = NULL;
                WOLFSSL_ASN1_OBJECT* oidObj = NULL;
                WOLFSSL_ASN1_TYPE* valueType = NULL;
                char oidBuf[MAX_OID_STRING_SZ];

                innerSize = 3;
                innerArray = (*jenv)->NewObjectArray(jenv, innerSize,
                    objectClass, NULL);
                if ((innerArray == NULL) || (*jenv)->ExceptionCheck(jenv)) {
                    continue;
                }

                /* Set type (Integer 0) */
                typeObj = (*jenv)->NewObject(jenv, integerClass,
                    integerInit, type);

                if ((typeObj == NULL) || (*jenv)->ExceptionCheck(jenv)) {
                    (*jenv)->DeleteLocalRef(jenv, innerArray);
                    continue;
                }
                (*jenv)->SetObjectArrayElement(jenv, innerArray, 0, typeObj);
                (*jenv)->DeleteLocalRef(jenv, typeObj);

                /* Get and set OID string */
                if ((entry->d.otherName != NULL) &&
                    (entry->d.otherName->type_id != NULL)) {

                    oidObj = entry->d.otherName->type_id;
                    oidLen = wolfSSL_OBJ_obj2txt(oidBuf, sizeof(oidBuf),
                        oidObj, 1);

                    if ((oidLen > 0) && (oidLen < (int)sizeof(oidBuf))) {
                        oidBuf[oidLen] = '\0'; /* Ensure null termination */
                        valueStr = (*jenv)->NewStringUTF(jenv, oidBuf);
                        if ((valueStr != NULL) &&
                            !(*jenv)->ExceptionCheck(jenv)) {
                            (*jenv)->SetObjectArrayElement(jenv, innerArray,
                                1, valueStr);
                            (*jenv)->DeleteLocalRef(jenv, valueStr);
                        }
                    }
                }

                /* Get and set value bytes (ASN.1 encoded) */
                if ((entry->d.otherName != NULL) &&
                    (entry->d.otherName->value != NULL)) {

                    valueType = entry->d.otherName->value;

                    /* Get the DER encoding of the value */
                    derSz = wolfSSL_i2d_ASN1_TYPE(valueType, NULL);
                    if (derSz > 0) {
                        derBuf = (unsigned char*)XMALLOC(derSz, NULL,
                            DYNAMIC_TYPE_TMP_BUFFER);

                        if (derBuf != NULL) {
                            unsigned char* derPtr = derBuf;
                            derSz = wolfSSL_i2d_ASN1_TYPE(valueType, &derPtr);

                            if (derSz > 0) {
                                valueBytes = (*jenv)->NewByteArray(jenv, derSz);
                                if ((valueBytes != NULL) &&
                                    !(*jenv)->ExceptionCheck(jenv)) {
                                    (*jenv)->SetByteArrayRegion(jenv,
                                        valueBytes, 0, derSz, (jbyte*)derBuf);
                                    (*jenv)->SetObjectArrayElement(jenv,
                                        innerArray, 2, valueBytes);
                                    (*jenv)->DeleteLocalRef(jenv, valueBytes);
                                }
                            }
                            XFREE(derBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                            derBuf = NULL;
                        }
                    }
                }
                break;
            }

            case GEN_EMAIL: /* 1 - rfc822Name */
            case GEN_DNS:   /* 2 - dNSName */
            case GEN_URI:   /* 6 - uniformResourceIdentifier */
            {
                /* For string types: [type, value_string] */
                int strLen = 0;
                WOLFSSL_ASN1_STRING* asn1Str = NULL;

                innerArray = (*jenv)->NewObjectArray(jenv, innerSize,
                    objectClass, NULL);
                if ((innerArray == NULL) || (*jenv)->ExceptionCheck(jenv)) {
                    continue;
                }

                /* Set type */
                typeObj = (*jenv)->NewObject(jenv, integerClass,
                    integerInit, type);
                if ((typeObj == NULL) || (*jenv)->ExceptionCheck(jenv)) {
                    (*jenv)->DeleteLocalRef(jenv, innerArray);
                    continue;
                }
                (*jenv)->SetObjectArrayElement(jenv, innerArray, 0, typeObj);
                (*jenv)->DeleteLocalRef(jenv, typeObj);

                /* Get string value based on type */
                if (type == GEN_EMAIL) {
                    asn1Str = entry->d.rfc822Name;
                }
                else if (type == GEN_DNS) {
                    asn1Str = entry->d.dNSName;
                }
                else if (type == GEN_URI) {
                    asn1Str = entry->d.uniformResourceIdentifier;
                }

                if (asn1Str != NULL) {
                    strValue = (const char*)wolfSSL_ASN1_STRING_data(asn1Str);
                    strLen = wolfSSL_ASN1_STRING_length(asn1Str);
                    if ((strValue != NULL) && (strLen >= 0)) {
                        valueStr = (*jenv)->NewStringUTF(jenv, strValue);
                        if ((valueStr != NULL) &&
                            !(*jenv)->ExceptionCheck(jenv)) {
                            (*jenv)->SetObjectArrayElement(jenv, innerArray,
                                1, valueStr);
                            (*jenv)->DeleteLocalRef(jenv, valueStr);
                        }
                    }
                }
                break;
            }

            case GEN_DIRNAME: /* 4 - directoryName */
            {
                /* For directoryName: [type, x500_name_string] */
                char* nameStr = NULL;

                innerArray = (*jenv)->NewObjectArray(jenv, innerSize,
                    objectClass, NULL);
                if ((innerArray == NULL) || (*jenv)->ExceptionCheck(jenv)) {
                    continue;
                }

                /* Set type */
                typeObj = (*jenv)->NewObject(jenv, integerClass,
                    integerInit, type);
                if ((typeObj == NULL) || (*jenv)->ExceptionCheck(jenv)) {
                    (*jenv)->DeleteLocalRef(jenv, innerArray);
                    continue;
                }
                (*jenv)->SetObjectArrayElement(jenv, innerArray, 0, typeObj);
                (*jenv)->DeleteLocalRef(jenv, typeObj);

                /* Get directory name as string */
                if (entry->d.directoryName != NULL) {

                    nameStr = wolfSSL_X509_NAME_oneline(
                        entry->d.directoryName, NULL, 0);

                    if (nameStr != NULL) {
                        valueStr = (*jenv)->NewStringUTF(jenv, nameStr);
                        if (valueStr != NULL &&
                            !(*jenv)->ExceptionCheck(jenv)) {
                            (*jenv)->SetObjectArrayElement(jenv, innerArray,
                                1, valueStr);
                            (*jenv)->DeleteLocalRef(jenv, valueStr);
                        }
                        XFREE(nameStr, NULL, DYNAMIC_TYPE_OPENSSL);
                        nameStr = NULL;
                    }
                }
                break;
            }

            case GEN_IPADD: /* 7 - iPAddress */
            {
                /* For iPAddress: [type, ip_bytes] */
                int ipLen = 0;
                WOLFSSL_ASN1_STRING* ipStr = NULL;
                const unsigned char* ipData = NULL;

                innerArray = (*jenv)->NewObjectArray(jenv, innerSize,
                    objectClass, NULL);
                if ((innerArray == NULL) || (*jenv)->ExceptionCheck(jenv)) {
                    continue;
                }

                /* Set type */
                typeObj = (*jenv)->NewObject(jenv, integerClass,
                    integerInit, type);
                if ((typeObj == NULL) || (*jenv)->ExceptionCheck(jenv)) {
                    (*jenv)->DeleteLocalRef(jenv, innerArray);
                    continue;
                }
                (*jenv)->SetObjectArrayElement(jenv, innerArray, 0, typeObj);
                (*jenv)->DeleteLocalRef(jenv, typeObj);

                /* Get IP address bytes */
                ipStr = entry->d.iPAddress;
                if (ipStr != NULL) {

                    ipData = wolfSSL_ASN1_STRING_data(ipStr);
                    ipLen = wolfSSL_ASN1_STRING_length(ipStr);

                    if ((ipData != NULL) && (ipLen > 0)) {
                        valueBytes = (*jenv)->NewByteArray(jenv, ipLen);
                        if ((valueBytes != NULL) &&
                            !(*jenv)->ExceptionCheck(jenv)) {
                            (*jenv)->SetByteArrayRegion(jenv, valueBytes,
                                0, ipLen, (jbyte*)ipData);
                            (*jenv)->SetObjectArrayElement(jenv, innerArray,
                                1, valueBytes);
                            (*jenv)->DeleteLocalRef(jenv, valueBytes);
                        }
                    }
                }
                break;
            }

            case GEN_RID: /* 8 - registeredID */
            {
                /* For registeredID: [type, oid_string] */
                int oidLen = 0;
                char oidBuf[MAX_OID_STRING_SZ];

                innerArray = (*jenv)->NewObjectArray(jenv, innerSize,
                    objectClass, NULL);
                if ((innerArray == NULL) || (*jenv)->ExceptionCheck(jenv)) {
                    continue;
                }

                /* Set type */
                typeObj = (*jenv)->NewObject(jenv, integerClass,
                    integerInit, type);
                if ((typeObj == NULL) || (*jenv)->ExceptionCheck(jenv)) {
                    (*jenv)->DeleteLocalRef(jenv, innerArray);
                    continue;
                }
                (*jenv)->SetObjectArrayElement(jenv, innerArray, 0, typeObj);
                (*jenv)->DeleteLocalRef(jenv, typeObj);

                /* Get OID string */
                if (entry->d.registeredID != NULL) {

                    oidLen = wolfSSL_OBJ_obj2txt(oidBuf, sizeof(oidBuf),
                        entry->d.registeredID, 1);

                    if ((oidLen > 0) && (oidLen < (int)sizeof(oidBuf))) {
                        oidBuf[oidLen] = '\0'; /* Ensure null termination */
                        valueStr = (*jenv)->NewStringUTF(jenv, oidBuf);
                        if ((valueStr != NULL) &&
                            !(*jenv)->ExceptionCheck(jenv)) {
                            (*jenv)->SetObjectArrayElement(jenv, innerArray,
                                1, valueStr);
                            (*jenv)->DeleteLocalRef(jenv, valueStr);
                        }
                    }
                }
                break;
            }

            default:
                /* Unsupported type, skip */
                continue;
        }

        if (innerArray != NULL) {
            (*jenv)->SetObjectArrayElement(jenv, outerArray, idx, innerArray);
            (*jenv)->DeleteLocalRef(jenv, innerArray);
            idx++;
        }
    }

    wolfSSL_sk_GENERAL_NAME_pop_free(names, wolfSSL_GENERAL_NAME_free);

    /* Check for pending exception from loop processing */
    if ((*jenv)->ExceptionCheck(jenv)) {
        (*jenv)->DeleteLocalRef(jenv, outerArray);
        return NULL;
    }

    /* If we didn't get any valid entries, return NULL */
    if (idx == 0) {
        (*jenv)->DeleteLocalRef(jenv, outerArray);
        return NULL;
    }

    /* If we got fewer entries than expected, create a trimmed array */
    if (idx < numNames) {
        jobjectArray trimmedArray = (*jenv)->NewObjectArray(jenv, idx,
            objectClass, NULL);
        if (trimmedArray != NULL && !(*jenv)->ExceptionCheck(jenv)) {
            for (i = 0; i < idx; i++) {
                jobject elem = (*jenv)->GetObjectArrayElement(jenv,
                    outerArray, i);
                (*jenv)->SetObjectArrayElement(jenv, trimmedArray, i, elem);
                (*jenv)->DeleteLocalRef(jenv, elem);
            }
            (*jenv)->DeleteLocalRef(jenv, outerArray);
            return trimmedArray;
        }
        /* If trimming failed, fall through to return outerArray */
    }

    return outerArray;

#else
    (void)jenv;
    (void)jcl;
    (void)x509Ptr;
    return NULL;
#endif /* !WOLFCRYPT_ONLY && !NO_CERTS && OPENSSL_EXTRA */
}

