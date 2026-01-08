/* com_wolfssl_WolfSSLCertManager.c
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
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/ocsp.h>

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
  (JNIEnv* jenv, jclass jcl, jlong cmPtr, jstring f, jstring d)
{
#ifndef NO_FILESYSTEM
    int ret;
    const char* certFile = NULL;
    const char* certPath = NULL;
    WOLFSSL_CERT_MANAGER* cm = (WOLFSSL_CERT_MANAGER*)(uintptr_t)cmPtr;
    (void)jcl;

    if (jenv == NULL || cm == NULL) {
        return (jint)BAD_FUNC_ARG;
    }

    certFile = (*jenv)->GetStringUTFChars(jenv, f, 0);
    certPath = (*jenv)->GetStringUTFChars(jenv, d, 0);

    ret = wolfSSL_CertManagerLoadCA(cm, certFile, certPath);

    (*jenv)->ReleaseStringUTFChars(jenv, f, certFile);
    (*jenv)->ReleaseStringUTFChars(jenv, d, certPath);

    return (jint)ret;
#else
    (void)jenv;
    (void)jcl;
    (void)cmPtr;
    (void)f;
    (void)d;
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLCertManager_CertManagerLoadCABuffer
  (JNIEnv* jenv, jclass jcl, jlong cmPtr, jbyteArray in, jlong sz, jint format)
{
    int ret = 0;
    word32 buffSz = 0;
    byte* buff = NULL;
    WOLFSSL_CERT_MANAGER* cm = (WOLFSSL_CERT_MANAGER*)(uintptr_t)cmPtr;
    (void)jcl;

    if (jenv == NULL || in == NULL || (sz < 0)) {
        return BAD_FUNC_ARG;
    }

    buff = (byte*)(*jenv)->GetByteArrayElements(jenv, in, NULL);
    buffSz = (*jenv)->GetArrayLength(jenv, in);

    ret = wolfSSL_CertManagerLoadCABuffer(cm, buff, buffSz, format);

    (*jenv)->ReleaseByteArrayElements(jenv, in, (jbyte*)buff, JNI_ABORT);

    return (jint)ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLCertManager_CertManagerUnloadCAs
  (JNIEnv* jenv, jclass jcl, jlong cmPtr)
{
    int ret = 0;
    WOLFSSL_CERT_MANAGER* cm = (WOLFSSL_CERT_MANAGER*)(uintptr_t)cmPtr;
    (void)jcl;

    if (jenv == NULL) {
        return BAD_FUNC_ARG;
    }

    ret = wolfSSL_CertManagerUnloadCAs(cm);

    return (jint)ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLCertManager_CertManagerVerifyBuffer
  (JNIEnv* jenv, jclass jcl, jlong cmPtr, jbyteArray in, jlong sz, jint format)
{
    int ret = 0;
    word32 buffSz = 0;
    byte* buff = NULL;
    WOLFSSL_CERT_MANAGER* cm = (WOLFSSL_CERT_MANAGER*)(uintptr_t)cmPtr;
    (void)jcl;

    if (jenv == NULL || in == NULL || (sz < 0))
        return BAD_FUNC_ARG;

    buff = (byte*)(*jenv)->GetByteArrayElements(jenv, in, NULL);
    buffSz = (*jenv)->GetArrayLength(jenv, in);

    ret = wolfSSL_CertManagerVerifyBuffer(cm, buff, buffSz, format);

    (*jenv)->ReleaseByteArrayElements(jenv, in, (jbyte*)buff, JNI_ABORT);

    return (jint)ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLCertManager_CertManagerCheckOCSPResponse
  (JNIEnv* jenv, jclass jcl, jlong cmPtr, jbyteArray response,
   jbyteArray cert, jbyteArray issuerCert)
{
#ifdef HAVE_OCSP
    int ret = 0;
    int decodedCertInit = 0;
    int decodedIssuerInit = 0;
    jint certSz = 0;
    jint responseSz = 0;
    jint issuerCertSz = 0;
    byte* certBuffer = NULL;
    byte* responseBuffer = NULL;
    byte* issuerCertBuffer = NULL;
    OcspEntry ocspEntry;
    CertStatus certStatus;
    DecodedCert decodedCert;
    DecodedCert decodedIssuer;
    OcspRequest* ocspRequest = NULL;
    WOLFSSL_CERT_MANAGER* cm = (WOLFSSL_CERT_MANAGER*)(uintptr_t)cmPtr;
    (void)jcl;

    XMEMSET(&decodedCert, 0, sizeof(DecodedCert));
    XMEMSET(&decodedIssuer, 0, sizeof(DecodedCert));
    XMEMSET(&certStatus, 0, sizeof(CertStatus));
    XMEMSET(&ocspEntry, 0, sizeof(OcspEntry));

    if (jenv == NULL || response == NULL || cert == NULL || cm == NULL) {
        ret = BAD_FUNC_ARG;
    }

    /* Get OCSP response buffer */
    if (ret == 0) {
        responseSz = (*jenv)->GetArrayLength(jenv, response);
        responseBuffer = (byte*)(*jenv)->GetByteArrayElements(jenv,
            response, NULL);
        if (responseBuffer == NULL) {
            ret = MEMORY_E;
        }
    }

    /* Get certificate buffer */
    if (ret == 0) {
        certSz = (*jenv)->GetArrayLength(jenv, cert);
        certBuffer = (byte*)(*jenv)->GetByteArrayElements(jenv, cert, NULL);
        if (certBuffer == NULL) {
            ret = MEMORY_E;
        }
    }

    /* Get issuer certificate buffer if provided */
    if (ret == 0 && issuerCert != NULL) {
        issuerCertSz = (*jenv)->GetArrayLength(jenv, issuerCert);
        issuerCertBuffer = (byte*)(*jenv)->GetByteArrayElements(jenv,
            issuerCert, NULL);
        if (issuerCertBuffer == NULL) {
            ret = MEMORY_E;
        }
    }

    /* Parse DER certificate into DecodedCert */
    if (ret == 0) {
        InitDecodedCert(&decodedCert, certBuffer, certSz, NULL);
        decodedCertInit = 1;
        ret = ParseCert(&decodedCert, CERT_TYPE, NO_VERIFY, NULL);
    }

    /* Parse issuer cert DER if provided, needed for OCSP request init
     * with issuer key hash */
    if (ret == 0 && issuerCertBuffer != NULL) {
        InitDecodedCert(&decodedIssuer, issuerCertBuffer, issuerCertSz, NULL);
        decodedIssuerInit = 1;
        ret = ParseCert(&decodedIssuer, CERT_TYPE, NO_VERIFY, NULL);
    }

    /* Enable OCSP in CertManager */
    if (ret == 0) {
        ret = wolfSSL_CertManagerEnableOCSP(cm, 0);
        if (ret != WOLFSSL_SUCCESS) {
            ret = WOLFSSL_FAILURE;
        }
        else {
            ret = 0;
        }
    }

    /* Create OCSP request and populate with cert info. */
    if (ret == 0) {
        ocspRequest = wolfSSL_OCSP_REQUEST_new();
        if (ocspRequest == NULL) {
            ret = MEMORY_E;
        }
    }

    /* Copy certificate info to OCSP request for matching, needs
     * issuerHash, issuerKeyHash, and serial number. */
    if (ret == 0) {
        /* Copy issuer name hash */
        XMEMCPY(ocspRequest->issuerHash, decodedCert.issuerHash, KEYID_SIZE);

        /* Copy issuer key hash: use issuer cert if provided, otherwise
         * try to use the one from the cert being validated */
        if (decodedIssuerInit) {
            XMEMCPY(ocspRequest->issuerKeyHash, decodedIssuer.subjectKeyHash,
                KEYID_SIZE);
        }
        else {
            XMEMCPY(ocspRequest->issuerKeyHash, decodedCert.issuerKeyHash,
                KEYID_SIZE);
        }

        /* Copy serial number, OcspRequest owns it */
        ocspRequest->serial = (byte*)XMALLOC(decodedCert.serialSz, NULL,
            DYNAMIC_TYPE_OCSP_REQUEST);
        if (ocspRequest->serial == NULL) {
            ret = MEMORY_E;
        }
        else {
            XMEMCPY(ocspRequest->serial, decodedCert.serial,
                decodedCert.serialSz);
            ocspRequest->serialSz = decodedCert.serialSz;
        }
    }

    /* Check OCSP response */
    if (ret == 0) {
        ret = wolfSSL_CertManagerCheckOCSPResponse(cm, responseBuffer,
            responseSz, NULL, &certStatus, &ocspEntry, ocspRequest);
    }

    /* Check certificate status from OCSP response */
    if (ret == WOLFSSL_SUCCESS) {
        /* certStatus.status: 0 = good, 1 = revoked, 2 = unknown */
        if (certStatus.status == 1) {
            ret = OCSP_CERT_REVOKED;
        }
        else if (certStatus.status == 2) {
            ret = OCSP_CERT_UNKNOWN;
        }
    }

    if (ocspRequest != NULL) {
        wolfSSL_OCSP_REQUEST_free(ocspRequest);
    }
    if (decodedIssuerInit) {
        FreeDecodedCert(&decodedIssuer);
    }
    if (decodedCertInit) {
        FreeDecodedCert(&decodedCert);
    }
    if (issuerCertBuffer != NULL) {
        (*jenv)->ReleaseByteArrayElements(jenv, issuerCert,
            (jbyte*)issuerCertBuffer, JNI_ABORT);
    }
    if (certBuffer != NULL) {
        (*jenv)->ReleaseByteArrayElements(jenv, cert,
            (jbyte*)certBuffer, JNI_ABORT);
    }
    if (responseBuffer != NULL) {
        (*jenv)->ReleaseByteArrayElements(jenv, response,
            (jbyte*)responseBuffer, JNI_ABORT);
    }

    return (jint)ret;
#else
    (void)jenv;
    (void)jcl;
    (void)cmPtr;
    (void)response;
    (void)cert;
    (void)issuerCert;
    return (jint)NOT_COMPILED_IN;
#endif
}

