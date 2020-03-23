/* com_wolfssl_WolfSSLCertificate.c
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
#include <wolfssl/version.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/openssl/evp.h> /* for EVP_PKEY functions */
#include <wolfssl/error-ssl.h>

#include "com_wolfssl_globals.h"
#include "com_wolfssl_WolfSSLCertificate.h"

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
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_WolfSSLCertificate_X509_1get_1der
  (JNIEnv* jenv, jclass jcl, jlong x509)
{
    int sz = 0;
    const byte* der = NULL;
    jbyteArray  derArr = NULL;

    if (jenv == NULL || x509 <= 0) {
        return NULL;
    }

    der = wolfSSL_X509_get_der((WOLFSSL_X509*)(uintptr_t)x509, &sz);
    if (der == NULL || sz == 0) {
        return NULL;
    }

    derArr = (*jenv)->NewByteArray(jenv, sz);
    if (derArr == NULL) {
        (*jenv)->ThrowNew(jenv, jcl,
            "Failed to create byte array in native X509_get_der");
        return NULL;
    }

    jclass excClass = (*jenv)->FindClass(jenv,
            "com/wolfssl/WolfSSLJNIException");
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

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_WolfSSLCertificate_X509_1get_1tbs
  (JNIEnv* jenv, jclass jcl, jlong x509)
{
    jbyteArray tbsArr;
    int sz;
    const unsigned char* tbs;

    if (jenv == NULL || x509 <= 0) {
        return NULL;
    }

    tbs = wolfSSL_X509_get_tbs((WOLFSSL_X509*)(uintptr_t)x509, &sz);
    if (tbs == NULL) {
        return NULL;
    }

    tbsArr = (*jenv)->NewByteArray(jenv, sz);
    if (tbsArr == NULL) {
        (*jenv)->ThrowNew(jenv, jcl,
            "Failed to create byte array in native X509_get_tbs");
        return NULL;
    }

    jclass excClass = (*jenv)->FindClass(jenv,
            "com/wolfssl/WolfSSLJNIException");
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
  (JNIEnv* jenv, jclass jcl, jlong x509)
{
    (void)jcl;

    if (jenv == NULL || x509 <= 0) {
        return;
    }

    wolfSSL_X509_free((WOLFSSL_X509*)(uintptr_t)x509);
}

#define MAX_SERIAL_SIZE 32
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLCertificate_X509_1get_1serial_1number
  (JNIEnv* jenv, jclass jcl, jlong x509, jbyteArray out)
{
    unsigned char s[MAX_SERIAL_SIZE];
    int sz = MAX_SERIAL_SIZE;
    (void)jcl;

    if (jenv == NULL || x509 <= 0 || out == NULL) {
        return BAD_FUNC_ARG;
    }

    if (wolfSSL_X509_get_serial_number((WOLFSSL_X509*)(uintptr_t)x509,
                                       s, &sz) == WOLFSSL_SUCCESS) {

        /* find exception class */
        jclass excClass = (*jenv)->FindClass(jenv,
                "com/wolfssl/WolfSSLJNIException");
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
  (JNIEnv* jenv, jclass jcl, jlong x509)
{
#if LIBWOLFSSL_VERSION_HEX >= 0x04002000
    WOLFSSL_ASN1_TIME* date = NULL;
#else
    const unsigned char* date = NULL;
#endif
    char ret[32];
    (void)jcl;

    if (jenv == NULL || x509 <= 0) {
        return NULL;
    }

#if LIBWOLFSSL_VERSION_HEX >= 0x04002000
    date = wolfSSL_X509_get_notBefore((WOLFSSL_X509*)(uintptr_t)x509);
#else
    date = wolfSSL_X509_notBefore((WOLFSSL_X509*)(uintptr_t)x509);
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
  (JNIEnv* jenv, jclass jcl, jlong x509)
{
#if LIBWOLFSSL_VERSION_HEX >= 0x04002000
    WOLFSSL_ASN1_TIME* date = NULL;
#else
    const unsigned char* date = NULL;
#endif
    char ret[32];
    (void)jcl;

    if (jenv == NULL || x509 <= 0) {
        return NULL;
    }

#if LIBWOLFSSL_VERSION_HEX >= 0x04002000
    date = wolfSSL_X509_get_notAfter((WOLFSSL_X509*)(uintptr_t)x509);
#else
    date = wolfSSL_X509_notAfter((WOLFSSL_X509*)(uintptr_t)x509);
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
  (JNIEnv* jenv, jclass jcl, jlong x509)
{
    (void)jcl;

    if (jenv == NULL || x509 <= 0) {
        return 0;
    }

    return (jint)wolfSSL_X509_version((WOLFSSL_X509*)(uintptr_t)x509);
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_WolfSSLCertificate_X509_1get_1signature
  (JNIEnv* jenv, jclass jcl, jlong x509)
{
    int sz = 0;
    unsigned char* buf = NULL;
    jbyteArray ret = NULL;

    if (jenv == NULL || x509 <= 0) {
        return NULL;
    }

    if (wolfSSL_X509_get_signature((WOLFSSL_X509*)(uintptr_t)x509, NULL, &sz) !=
            WOLFSSL_SUCCESS) {
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

    if (wolfSSL_X509_get_signature((WOLFSSL_X509*)(uintptr_t)x509, buf, &sz) !=
            WOLFSSL_SUCCESS) {
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
        XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return NULL;
    }

    return ret;
}

JNIEXPORT jstring JNICALL Java_com_wolfssl_WolfSSLCertificate_X509_1get_1signature_1type
  (JNIEnv* jenv, jclass jcl, jlong x509)
{
    int type;

    if (jenv == NULL || x509 <= 0) {
        return NULL;
    }

    type = wolfSSL_X509_get_signature_type((WOLFSSL_X509*)(uintptr_t)x509);

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

        default:
            (*jenv)->ThrowNew(jenv, jcl, "Unknown signature type");
            return NULL;
    }
}

JNIEXPORT jstring JNICALL Java_com_wolfssl_WolfSSLCertificate_X509_1get_1signature_1OID
  (JNIEnv* jenv, jclass jcl, jlong x509)
{
    WOLFSSL_ASN1_OBJECT* obj;
    char oid[40];
    int  oidSz = sizeof(oid);
    int  nid;
    (void)jcl;

    if (jenv == NULL || x509 <= 0) {
        return NULL;
    }

    nid = wolfSSL_X509_get_signature_nid((WOLFSSL_X509*)(uintptr_t)x509);
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

JNIEXPORT jstring JNICALL Java_com_wolfssl_WolfSSLCertificate_X509_1print
  (JNIEnv* jenv, jclass jcl, jlong x509)
{
    WOLFSSL_BIO* bio;
    jstring ret = NULL;
    const char* mem = NULL;
    (void)jcl;

    if (jenv == NULL || x509 <= 0) {
        return NULL;
    }

    bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    if (bio == NULL) {
        return NULL;
    }

    if (wolfSSL_X509_print(bio, (WOLFSSL_X509*)(uintptr_t)x509) !=
        WOLFSSL_SUCCESS) {
        wolfSSL_BIO_free(bio);
        return NULL;
    }

    wolfSSL_BIO_get_mem_data(bio, &mem);
    if (mem != NULL) {
        ret = (*jenv)->NewStringUTF(jenv, mem);
    }
    wolfSSL_BIO_free(bio);
    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLCertificate_X509_1get_1isCA
  (JNIEnv* jenv, jclass jcl, jlong x509)
{
    (void)jcl;

    if (jenv == NULL || x509 <= 0) {
        return 0;
    }

    return (jint)wolfSSL_X509_get_isCA((WOLFSSL_X509*)(uintptr_t)x509);
}


JNIEXPORT jstring JNICALL Java_com_wolfssl_WolfSSLCertificate_X509_1get_1subject_1name
  (JNIEnv* jenv, jclass jcl, jlong x509)
{
    WOLFSSL_X509_NAME* name = NULL;
    (void)jcl;

    if (jenv == NULL || x509 <= 0) {
        return NULL;
    }

    name = wolfSSL_X509_get_subject_name((WOLFSSL_X509*)(uintptr_t)x509);
    if (name != NULL) {
        jstring ret = NULL;
        char* subj = wolfSSL_X509_NAME_oneline(name, NULL, 0);
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
  (JNIEnv* jenv, jclass jcl, jlong x509)
{
    WOLFSSL_X509_NAME* name = NULL;
    (void)jcl;

    if (jenv == NULL || x509 <= 0) {
        return NULL;
    }

    name = wolfSSL_X509_get_issuer_name((WOLFSSL_X509*)(uintptr_t)x509);
    if (name != NULL) {
        jstring ret = NULL;
        char* isur = wolfSSL_X509_NAME_oneline(name, NULL, 0);
        if (isur == NULL) {
            return NULL;
        }
        ret = (*jenv)->NewStringUTF(jenv, isur);
        XFREE(isur, NULL, DYNAMIC_TYPE_OPENSSL);
        return ret;
    }
    return NULL;
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_WolfSSLCertificate_X509_1get_1pubkey
  (JNIEnv* jenv, jclass jcl, jlong x509)
{
    int sz = 0;
    unsigned char* buf;
    jbyteArray ret;

    if (jenv == NULL || x509 <= 0) {
        return NULL;
    }

    if (wolfSSL_X509_get_pubkey_buffer((WOLFSSL_X509*)(uintptr_t)x509, NULL,
                                       &sz) != WOLFSSL_SUCCESS) {
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

    if (wolfSSL_X509_get_pubkey_buffer((WOLFSSL_X509*)(uintptr_t)x509, buf,
                                       &sz) != WOLFSSL_SUCCESS) {
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
        XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return NULL;
    }

    return ret;
}

JNIEXPORT jstring JNICALL Java_com_wolfssl_WolfSSLCertificate_X509_1get_1pubkey_1type
  (JNIEnv* jenv, jclass jcl, jlong x509)
{
    int type;

    if (jenv == NULL || x509 <= 0) {
        return NULL;
    }

    type = wolfSSL_X509_get_pubkey_type((WOLFSSL_X509*)(uintptr_t)x509);
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
  (JNIEnv* jenv, jclass jcl, jlong x509)
{
    (void)jcl;

    if (jenv == NULL || x509 <= 0) {
        return 0;
    }

    if (wolfSSL_X509_get_isSet_pathLength((WOLFSSL_X509*)(uintptr_t)x509)) {
        return (jint)wolfSSL_X509_get_pathLength(
                        (WOLFSSL_X509*)(uintptr_t)x509);
    }
    else {
        return (jint)-1;
    }
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLCertificate_X509_1verify
  (JNIEnv* jenv, jclass jcl, jlong x509, jbyteArray pubKey, jint pubKeySz)
{
    WOLFSSL_EVP_PKEY* pkey;
    int sz = (int)pubKeySz;
    int ret;
    unsigned char buff[sz];
    unsigned char* ptr = buff;

    (void)jcl;

    if (!jenv || !pubKey || (sz < 0))
        return BAD_FUNC_ARG;

    /* find exception class */
    jclass excClass = (*jenv)->FindClass(jenv,
            "com/wolfssl/WolfSSLJNIException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return WOLFSSL_FAILURE;
    }

    (*jenv)->GetByteArrayRegion(jenv, pubKey, 0, sz, (jbyte*)buff);
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);

        (*jenv)->ThrowNew(jenv, excClass,
                "Failed to get byte region in native wolfSSL_X509_verify");
        return WOLFSSL_FAILURE;
    }

    pkey = wolfSSL_d2i_PUBKEY(NULL, &ptr, sz);
    if (pkey == NULL) {
        return WOLFSSL_FAILURE;
    }

    ret = wolfSSL_X509_verify((WOLFSSL_X509*)(uintptr_t)x509, pkey);
    wolfSSL_EVP_PKEY_free(pkey);
    return ret;

}

/* getter function for WOLFSSL_ASN1_OBJECT element */
static unsigned char* getOBJData(WOLFSSL_ASN1_OBJECT* obj)
{
    if (obj) return (unsigned char*)obj->obj;
    return NULL;
}

/* getter function for WOLFSSL_ASN1_OBJECT size */
static unsigned int getOBJSize(WOLFSSL_ASN1_OBJECT* obj)
{
    if (obj) return obj->objSz;
    return 0;
}

JNIEXPORT jbooleanArray JNICALL Java_com_wolfssl_WolfSSLCertificate_X509_1get_1key_1usage
  (JNIEnv* jenv, jclass jcl, jlong x509)
{
    jbooleanArray ret = NULL;
    jboolean values[9];
    unsigned short kuse;

    if (jenv == NULL || x509 <= 0) {
        return NULL;
    }

    kuse = wolfSSL_X509_get_keyUsage((WOLFSSL_X509*)(uintptr_t)x509);

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

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_WolfSSLCertificate_X509_1get_1extension
  (JNIEnv* jenv, jclass jcl, jlong x509, jstring oidIn)
{
    int nid;
    void* sk;
    WOLFSSL_ASN1_OBJECT* obj;
    jbyteArray ret = NULL;
    const char* oid;

    if (jenv == NULL || x509 <= 0) {
        return NULL;
    }

    oid = (*jenv)->GetStringUTFChars(jenv, oidIn, 0);
    nid = wolfSSL_OBJ_txt2nid(oid);
    if (nid == NID_undef) {
        (*jenv)->ReleaseStringUTFChars(jenv, oidIn, oid);
        return NULL;
    }
    (*jenv)->ReleaseStringUTFChars(jenv, oidIn, oid);

    sk = wolfSSL_X509_get_ext_d2i((WOLFSSL_X509*)(uintptr_t)x509, nid, NULL,
                                  NULL);
    if (sk == NULL) {
        /* extension was not found or error was encountered */
        return NULL;
    }

#if LIBWOLFSSL_VERSION_HEX >= 0x04002000
    if (nid == BASIC_CA_OID) {
        obj = (WOLFSSL_ASN1_OBJECT*)sk;
    }
    else
#endif
        obj = wolfSSL_sk_ASN1_OBJECT_pop((WOLFSSL_STACK*)sk);

    if (obj != NULL) {
        unsigned char* data = getOBJData(obj);
        unsigned int sz = getOBJSize(obj);

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
  (JNIEnv* jenv, jclass jcl, jlong x509, jstring oidIn)
{
    int nid;
    const char* oid;
    (void)jcl;

    if (jenv == NULL || x509 <= 0) {
        return 0;
    }

    oid = (*jenv)->GetStringUTFChars(jenv, oidIn, 0);
    nid = wolfSSL_OBJ_txt2nid(oid);
    if (nid == NID_undef) {
        (*jenv)->ReleaseStringUTFChars(jenv, oidIn, oid);
        return -1;
    }
    (*jenv)->ReleaseStringUTFChars(jenv, oidIn, oid);

    if (wolfSSL_X509_ext_isSet_by_NID((WOLFSSL_X509*)(uintptr_t)x509, nid)) {
        if (wolfSSL_X509_ext_get_critical_by_NID((WOLFSSL_X509*)(uintptr_t)x509,
            nid)) {
            return 2;
        }
        return 1;
    }

    return 0;
}

JNIEXPORT jstring JNICALL Java_com_wolfssl_WolfSSLCertificate_X509_1get_1next_1altname
  (JNIEnv* jenv, jclass jcl, jlong x509)
{
#if defined(KEEP_PEER_CERT) || defined(SESSION_CERTS)
    char* altname;
    jstring retString;
    (void)jcl;

    if (!jenv || !x509)
        return NULL;

    altname = wolfSSL_X509_get_next_altname((WOLFSSL_X509*)(uintptr_t)x509);
    if (altname == NULL) {
        return NULL;
    }
    retString = (*jenv)->NewStringUTF(jenv, altname);
    return retString;

#else
    (void)jenv;
    (void)jcl;
    (void)x509;
    return NULL;
#endif
}

