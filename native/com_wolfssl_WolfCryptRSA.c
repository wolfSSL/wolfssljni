/* com_wolfssl_WolfCryptRSA.c
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

#ifdef WOLFSSL_USER_SETTINGS
    #include <wolfssl/wolfcrypt/settings.h>
#else
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include "com_wolfssl_WolfCryptRSA.h"

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfCryptRSA_doSign
  (JNIEnv* jenv, jobject jcl, jobject in, jlong inSz, jobject out,
   jintArray outSz, jobject keyDer, jlong keySz)
{
    int     ret;
    WC_RNG  rng;
    RsaKey  myKey;
    unsigned int idx;
    unsigned int tmpOut;
    unsigned char* inBuf = NULL;
    unsigned char* outBuf = NULL;
    unsigned char* keyBuf = NULL;
    (void)jcl;

    /* check in and key sz */
    if ((inSz  < 0) || (keySz < 0)) {
        return -1;
    }

    /* get pointers to our buffers */
    inBuf = (*jenv)->GetDirectBufferAddress(jenv, in);
    if (inBuf == NULL) {
        printf("problem getting in buffer address\n");
        return -1;
    }

    outBuf = (*jenv)->GetDirectBufferAddress(jenv, out);
    if (outBuf == NULL) {
        printf("problem getting out buffer address\n");
        return -1;
    }

    keyBuf = (*jenv)->GetDirectBufferAddress(jenv, keyDer);
    if (keyBuf == NULL) {
        printf("problem getting key buffer address\n");
        return -1;
    }

    /* get output buffer size */
    (*jenv)->GetIntArrayRegion(jenv, outSz, 0, 1, (jint*)&tmpOut);

    wc_InitRng(&rng);
    wc_InitRsaKey(&myKey, NULL);

    idx = 0;

    ret = wc_RsaPrivateKeyDecode(keyBuf, &idx, &myKey, (unsigned int)keySz);
    if (ret == 0) {
        ret = wc_RsaSSL_Sign(inBuf, (unsigned int)inSz, outBuf, tmpOut,
                &myKey, &rng);
        if (ret > 0) {
            /* save and convert to 0 for success */
            tmpOut = ret;
            (*jenv)->SetIntArrayRegion(jenv, outSz, 0, 1, (jint*)&tmpOut);
            ret = 0;
        }
    } else {
        printf("wc_RsaPrivateKeyDecode failed, ret = %d\n", ret);
    }

    wc_FreeRsaKey(&myKey);
    wc_FreeRng(&rng);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfCryptRSA_doVerify
  (JNIEnv* jenv, jobject jcl, jobject sig, jlong sigSz, jobject out,
   jlong outSz, jobject keyDer, jlong keySz)
{
    int     ret;
    RsaKey  myKey;
    unsigned int idx;
    unsigned char* sigBuf = NULL;
    unsigned char* outBuf = NULL;
    unsigned char* keyBuf = NULL;
    (void)jcl;

    /* check in and key sz */
    if ((sigSz < 0) || (keySz < 0) || (outSz < 0)) {
        return -1;
    }

    /* get pointers to our buffers */
    sigBuf = (*jenv)->GetDirectBufferAddress(jenv, sig);
    if (sigBuf == NULL) {
        printf("problem getting sig buffer address\n");
        return -1;
    }

    outBuf = (*jenv)->GetDirectBufferAddress(jenv, out);
    if (outBuf == NULL) {
        printf("problem getting out buffer address\n");
        return -1;
    }

    keyBuf = (*jenv)->GetDirectBufferAddress(jenv, keyDer);
    if (keyBuf == NULL) {
        printf("problem getting key buffer address\n");
        return -1;
    }

    wc_InitRsaKey(&myKey, NULL);
    idx = 0;

    ret = wc_RsaPublicKeyDecode(keyBuf, &idx, &myKey, (unsigned int)keySz);
    if (ret == 0) {
        ret = wc_RsaSSL_Verify(sigBuf, (unsigned int)sigSz, outBuf,
                (unsigned int)outSz, &myKey);
        if (ret < 0) {
            printf("wc_RsaSSL_Verify failed, ret = %d\n", ret);
        }
    } else {
        printf("wc_RsaPublicKeyDecode failed, ret = %d\n", ret);
    }

    wc_FreeRsaKey(&myKey);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfCryptRSA_doEnc
  (JNIEnv* jenv, jobject jcl, jobject in, jlong inSz, jobject out,
   jintArray outSz, jobject keyDer, jlong keySz)
{
    int     ret;
    RsaKey  myKey;
    WC_RNG  rng;
    unsigned int idx;
    unsigned int tmpOut;
    unsigned char* inBuf = NULL;
    unsigned char* outBuf = NULL;
    unsigned char* keyBuf = NULL;
    (void)jcl;

    /* check in and key sz */
    if ((inSz  < 0) || (keySz < 0)) {
        return -1;
    }

    /* get pointers to our buffers */
    inBuf = (*jenv)->GetDirectBufferAddress(jenv, in);
    if (inBuf == NULL) {
        printf("problem getting in buffer address\n");
        return -1;
    }

    outBuf = (*jenv)->GetDirectBufferAddress(jenv, out);
    if (outBuf == NULL) {
        printf("problem getting out buffer address\n");
        return -1;
    }

    keyBuf = (*jenv)->GetDirectBufferAddress(jenv, keyDer);
    if (keyBuf == NULL) {
        printf("problem getting key buffer address\n");
        return -1;
    }

    /* get output buffer size */
    (*jenv)->GetIntArrayRegion(jenv, outSz, 0, 1, (jint*)&tmpOut);

    wc_InitRng(&rng);
    wc_InitRsaKey(&myKey, NULL);

    idx = 0;

    ret = wc_RsaPublicKeyDecode(keyBuf, &idx, &myKey, (unsigned int)keySz);
    if (ret == 0) {
        ret = wc_RsaPublicEncrypt(inBuf, (unsigned int)inSz, outBuf, tmpOut,
                &myKey, &rng);
        if (ret > 0) {
            /* save and convert to 0 for success */
            (*jenv)->SetIntArrayRegion(jenv, outSz, 0, 1, (jint*)&ret);
            ret = 0;
        }
    } else {
        printf("wc_RsaPublicKeyDecode failed, ret = %d\n", ret);
    }

    wc_FreeRsaKey(&myKey);
    wc_FreeRng(&rng);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfCryptRSA_doPssSign
  (JNIEnv* jenv, jobject jcl, jobject in, jlong inSz, jobject out, jintArray outSz, jint hash, jint mgf, jobject keyDer, jlong keySz)
{
#ifdef WC_RSA_PSS
    int     ret;
    WC_RNG  rng;
    RsaKey  myKey;
    int     rngInit = 0;
    int     keyInit = 0;
    unsigned int idx = 0;
    unsigned int tmpOut;
    unsigned char* inBuf = NULL;
    unsigned char* outBuf = NULL;
    unsigned char* keyBuf = NULL;
    enum wc_HashType hashType;
    (void)jcl;

    if ((inSz  < 0) || (keySz < 0)) {
        return -1;
    }

    inBuf = (*jenv)->GetDirectBufferAddress(jenv, in);
    if (inBuf == NULL) {
        printf("problem getting in buffer address\n");
        return -1;
    }

    outBuf = (*jenv)->GetDirectBufferAddress(jenv, out);
    if (outBuf == NULL) {
        printf("problem getting out buffer address\n");
        return -1;
    }

    keyBuf = (*jenv)->GetDirectBufferAddress(jenv, keyDer);
    if (keyBuf == NULL) {
        printf("problem getting key buffer address\n");
        return -1;
    }

    hashType = wc_OidGetHash(hash);
    if (hashType == WC_HASH_TYPE_NONE) {
        printf("doPssSign: unsupported hash OID %d\n", hash);
        return -1;
    }

    /* get output buffer size */
    (*jenv)->GetIntArrayRegion(jenv, outSz, 0, 1, (jint*)&tmpOut);

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        printf("wc_InitRng failed, ret = %d\n", ret);
        return ret;
    }
    rngInit = 1;

    ret = wc_InitRsaKey(&myKey, NULL);
    if (ret != 0) {
        printf("wc_InitRsaKey failed, ret = %d\n", ret);
        wc_FreeRng(&rng);
        return ret;
    }
    keyInit = 1;

    ret = wc_RsaPrivateKeyDecode(keyBuf, &idx, &myKey, (unsigned int)keySz);
    if (ret == 0) {

        ret = wc_RsaPSS_Sign(inBuf, (unsigned int)inSz, outBuf, tmpOut,
            hashType, mgf, &myKey, &rng);
        if (ret > 0) {
            tmpOut = ret;
            (*jenv)->SetIntArrayRegion(jenv, outSz, 0, 1, (jint*)&tmpOut);
            ret = 0;
        }
    } else {
        printf("wc_RsaPrivateKeyDecode failed, ret = %d\n", ret);
    }

    if (keyInit) {
        wc_FreeRsaKey(&myKey);
    }
    if (rngInit) {
        wc_FreeRng(&rng);
    }

    return ret;
#else
    (void)jenv;
    (void)jcl;
    (void)in;
    (void)inSz;
    (void)out;
    (void)outSz;
    (void)hash;
    (void)mgf;
    (void)keyDer;
    (void)keySz;
    return (jint)NOT_COMPILED_IN;
#endif /* WC_RSA_PSS */
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfCryptRSA_doPssVerify
  (JNIEnv* jenv, jobject jcl, jobject sig, jlong sigSz, jobject out, jlong outSz, jint hash, jint mgf, jobject keyDer, jlong keySz)
{
#ifdef WC_RSA_PSS
    int     ret;
    RsaKey  myKey;
    unsigned int idx = 0;
    unsigned char* sigBuf = NULL;
    unsigned char* outBuf = NULL;
    unsigned char* keyBuf = NULL;
    enum wc_HashType hashType;
    (void)jcl;

    if ((sigSz < 0) || (keySz < 0) || (outSz < 0)) {
        return -1;
    }

    sigBuf = (*jenv)->GetDirectBufferAddress(jenv, sig);
    if (sigBuf == NULL) {
        printf("problem getting sig buffer address\n");
        return -1;
    }

    outBuf = (*jenv)->GetDirectBufferAddress(jenv, out);
    if (outBuf == NULL) {
        printf("problem getting out buffer address\n");
        return -1;
    }

    keyBuf = (*jenv)->GetDirectBufferAddress(jenv, keyDer);
    if (keyBuf == NULL) {
        printf("problem getting key buffer address\n");
        return -1;
    }

    hashType = wc_OidGetHash(hash);
    if (hashType == WC_HASH_TYPE_NONE) {
        printf("doPssVerify: unsupported hash OID %d\n", hash);
        return -1;
    }

    ret = wc_InitRsaKey(&myKey, NULL);
    if (ret != 0) {
        printf("wc_InitRsaKey failed, ret = %d\n", ret);
        return ret;
    }

    /* Try private key decode first (sign check receives the server private),
     * fall back to public key decode (verify receives the peer public) */
    ret = wc_RsaPrivateKeyDecode(keyBuf, &idx, &myKey, (unsigned int)keySz);
    if (ret != 0) {
        idx = 0;
        ret = wc_RsaPublicKeyDecode(keyBuf, &idx, &myKey, (unsigned int)keySz);
    }

    if (ret == 0) {
        ret = wc_RsaPSS_Verify(sigBuf, (unsigned int)sigSz, outBuf,
            (unsigned int)outSz, hashType, mgf, &myKey);
        if (ret < 0) {
            printf("wc_RsaPSS_Verify failed, ret = %d\n", ret);
        }
    } else {
        printf("RSA key decode failed, ret = %d\n", ret);
    }

    wc_FreeRsaKey(&myKey);

    return ret;
#else
    (void)jenv;
    (void)jcl;
    (void)sig;
    (void)sigSz;
    (void)out;
    (void)outSz;
    (void)hash;
    (void)mgf;
    (void)keyDer;
    (void)keySz;
    return (jint)NOT_COMPILED_IN;
#endif /* WC_RSA_PSS */
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfCryptRSA_doDec
  (JNIEnv* jenv, jobject jcl, jobject in, jlong inSz, jobject out,
   jlong outSz, jobject keyDer, jlong keySz)
{
    int     ret;
    RsaKey  myKey;
    unsigned int idx;
    unsigned char* inBuf = NULL;
    unsigned char* outBuf = NULL;
    unsigned char* keyBuf = NULL;
    (void)jcl;

    /* check in and key sz */
    if ((inSz < 0) || (keySz < 0) || (outSz < 0)) {
        return -1;
    }

    /* get pointers to our buffers */
    inBuf = (*jenv)->GetDirectBufferAddress(jenv, in);
    if (inBuf == NULL) {
        printf("problem getting in buffer address\n");
        return -1;
    }

    outBuf = (*jenv)->GetDirectBufferAddress(jenv, out);
    if (outBuf == NULL) {
        printf("problem getting out buffer address\n");
        return -1;
    }

    keyBuf = (*jenv)->GetDirectBufferAddress(jenv, keyDer);
    if (keyBuf == NULL) {
        printf("problem getting key buffer address\n");
        return -1;
    }

    wc_InitRsaKey(&myKey, NULL);
    idx = 0;

    ret = wc_RsaPrivateKeyDecode(keyBuf, &idx, &myKey, (unsigned int)keySz);
    if (ret == 0) {
        ret = wc_RsaPrivateDecrypt(inBuf, (unsigned int)inSz, outBuf,
                (unsigned int)outSz, &myKey);
        if (ret < 0) {
            printf("wc_RsaPrivateDecrypt failed, ret = %d\n", ret);
        }
    } else {
        printf("wc_RsaPrivateKeyDecode failed, ret = %d\n", ret);
    }

    wc_FreeRsaKey(&myKey);

    return ret;
}

