/* com_wolfssl_WolfSSLContext.c
 *
 * Copyright (C) 2006-2015 wolfSSL Inc.
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
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>

#include "com_wolfssl_globals.h"
#include "com_wolfssl_WolfSSLContext.h"

/* global object refs for verify, CRL callbacks */
static jobject g_verifyCbIfaceObj;
static jobject g_crlCtxCbIfaceObj;

/* custom I/O native fn prototypes */
int  NativeIORecvCb(WOLFSSL *ssl, char *buf, int sz, void *ctx);
int  NativeIOSendCb(WOLFSSL *ssl, char *buf, int sz, void *ctx);
int  NativeGenCookieCb(WOLFSSL *ssl, unsigned char *buf, int sz, void *ctx);
int  NativeVerifyCallback(int preverify_ok, WOLFSSL_X509_STORE_CTX* store);
void NativeCtxMissingCRLCallback(const char* url);
int  NativeMacEncryptCb(WOLFSSL* ssl, unsigned char* macOut,
        const unsigned char* macIn, unsigned int macInSz, int macContent,
        int macVerify, unsigned char* encOut, const unsigned char* encIn,
        unsigned int encSz, void* ctx);
int  NativeDecryptVerifyCb(WOLFSSL* ssl, unsigned char* decOut,
        const unsigned char* decIn, unsigned int decSz, int content,
        int verify, unsigned int* padSz, void* ctx);
int  NativeEccSignCb(WOLFSSL* ssl, const unsigned char* in, unsigned int inSz,
        unsigned char* out, unsigned int* outSz, const unsigned char* keyDer,
        unsigned int keySz, void* ctx);
int  NativeEccVerifyCb(WOLFSSL* ssl, const unsigned char* sig,
        unsigned int sigSz, const unsigned char* hash, unsigned int hashSz,
        const unsigned char* keyDer, unsigned int keySz, int* result,
        void* ctx);
int  NativeRsaSignCb(WOLFSSL* ssl, const unsigned char* in, unsigned int inSz,
        unsigned char* out, unsigned int* outSz, const unsigned char* keyDer,
        unsigned int keySz, void* ctx);
int  NativeRsaVerifyCb(WOLFSSL* ssl, unsigned char* sig, unsigned int sigSz,
        unsigned char** out, const unsigned char* keyDer, unsigned int keySz,
        void* ctx);
int  NativeRsaEncCb(WOLFSSL* ssl, const unsigned char* in, unsigned int inSz,
        unsigned char* out, unsigned int* outSz, const unsigned char* keyDer,
        unsigned int keySz, void* ctx);
int  NativeRsaDecCb(WOLFSSL* ssl, unsigned char* in, unsigned int inSz,
        unsigned char** out, const unsigned char* keyDer, unsigned int keySz,
        void* ctx);

JNIEXPORT jlong JNICALL Java_com_wolfssl_WolfSSLContext_newContext(JNIEnv* jenv,
        jclass jcl, jlong method)
{
    return (jlong)wolfSSL_CTX_new((WOLFSSL_METHOD*)method);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLContext_useCertificateFile
  (JNIEnv* jenv, jobject jcl, jlong ctx, jstring file, jint format)
{
    jint ret = 0;
    jclass excClass;
    const char* certFile;

    if (!file)
    {
        excClass = (*jenv)->FindClass(jenv, "java/lang/NullPointerException");
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
        }

        /* throw NullPointerException */
        (*jenv)->ThrowNew(jenv, excClass,
                "Input certificate file is NULL");

        return SSL_FAILURE;
    }

    certFile = (*jenv)->GetStringUTFChars(jenv, file, 0);

    ret = (jint) wolfSSL_CTX_use_certificate_file((WOLFSSL_CTX*)ctx, certFile,
            (int)format);

    (*jenv)->ReleaseStringUTFChars(jenv, file, certFile);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLContext_usePrivateKeyFile
  (JNIEnv* jenv, jobject jcl, jlong ctx, jstring file, jint format)
{
    jint ret = 0;
    jclass excClass;
    const char* keyFile;

    if (!file)
    {
        excClass = (*jenv)->FindClass(jenv, "java/lang/NullPointerException");

        /* clear out previous exception */
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
        }

        /* throw NullPointerException */
        (*jenv)->ThrowNew(jenv, excClass,
                "Input private key file is NULL");

        return SSL_FAILURE;
    }

    keyFile = (*jenv)->GetStringUTFChars(jenv, file, 0);

    ret = (jint) wolfSSL_CTX_use_PrivateKey_file((WOLFSSL_CTX*)ctx, keyFile,
            (int)format);

    (*jenv)->ReleaseStringUTFChars(jenv, file, keyFile);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLContext_loadVerifyLocations
  (JNIEnv* jenv, jobject jcl, jlong ctx, jstring file, jstring path)
{
    jint ret = 0;
    jclass excClass;
    const char* caFile;
    const char* caPath;

    if (!file && !path)
    {
        excClass = (*jenv)->FindClass(jenv, "java/lang/NullPointerException");

        /* clear out previous exception */
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
        }

        /* throw NullPointerException */
        (*jenv)->ThrowNew(jenv, excClass,
                "Input file and path are both NULL");

        return SSL_FAILURE;
    }

    if (file) {
        caFile = (*jenv)->GetStringUTFChars(jenv, file, 0);
    } else {
        caFile = NULL;
    }

    if (path) {
        caPath = (*jenv)->GetStringUTFChars(jenv, path, 0);
    } else {
        caPath = NULL;
    }

    ret = (jint) wolfSSL_CTX_load_verify_locations((WOLFSSL_CTX*)ctx, caFile,
            caPath);

    if (caFile)
        (*jenv)->ReleaseStringUTFChars(jenv, file, caFile);
    if (caPath)
        (*jenv)->ReleaseStringUTFChars(jenv, path, caPath);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLContext_useCertificateChainFile
  (JNIEnv* jenv, jobject jcl, jlong ctx, jstring file)
{
    jint ret = 0;
    jclass excClass;
    const char* chainFile;

    /* throw exception if no input file */
    if (!file)
    {
        excClass = (*jenv)->FindClass(jenv, "java/lang/NullPointerException");

        /* clear out previous exception */
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
        }

        /* throw NullPointerException */
        (*jenv)->ThrowNew(jenv, excClass,
                "Input certificate chain file is NULL");

        return SSL_FAILURE;
    }

    chainFile = (*jenv)->GetStringUTFChars(jenv, file, 0);

    ret = (jint) wolfSSL_CTX_use_certificate_chain_file((WOLFSSL_CTX*)ctx,
            chainFile);

    (*jenv)->ReleaseStringUTFChars(jenv, file, chainFile);

    return ret;
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLContext_freeContext
  (JNIEnv* jenv, jobject jcl, jlong ctx)
{
    /* wolfSSL checks for null pointer */
    wolfSSL_CTX_free((WOLFSSL_CTX*)ctx);
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLContext_setVerify(JNIEnv* jenv,
    jobject jcl, jlong ctx, jint mode, jobject callbackIface)
{
    if (!callbackIface) {
        wolfSSL_CTX_set_verify((WOLFSSL_CTX*)ctx, mode, NULL);
    } else {

        /* store Java verify Interface object */
        g_verifyCbIfaceObj = (*jenv)->NewGlobalRef(jenv, callbackIface);
        if (!g_verifyCbIfaceObj) {
            printf("error storing global callback interface\n");
        }

        /* set verify mode, register Java callback with wolfSSL */
        wolfSSL_CTX_set_verify((WOLFSSL_CTX*)ctx, mode, NativeVerifyCallback);
    }
}

int NativeVerifyCallback(int preverify_ok, WOLFSSL_X509_STORE_CTX* store)
{
    JNIEnv*   jenv;
    jint      vmret  = 0;
    jint      retval = -1;
    jclass    excClass;
    jmethodID verifyMethod;
    jobjectRefType refcheck;

    if (!g_vm) {
        /* we can't throw an exception yet, so just return 0 (failure) */
        return 0;
    }

    /* get JNIEnv from JavaVM */
    vmret = (int)((*g_vm)->GetEnv(g_vm, (void**) &jenv, JNI_VERSION_1_6));
    if (vmret == JNI_EDETACHED) {
#ifdef __ANDROID__
        vmret = (*g_vm)->AttachCurrentThread(g_vm, &jenv, NULL);
#else
        vmret = (*g_vm)->AttachCurrentThread(g_vm, (void**) &jenv, NULL);
#endif
        if (vmret) {
            return -101;    /* failed to attach JNIEnv to thread */
        }
    } else if (vmret != JNI_OK) {
        return -102;        /* unable to get JNIEnv from JavaVM */
    }

    /* find exception class */
    excClass = (*jenv)->FindClass(jenv, "java/lang/Exception");
    if( (*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return -103;
    }

    /* check if our stored object reference is valid */
    refcheck = (*jenv)->GetObjectRefType(jenv, g_verifyCbIfaceObj);
    if (refcheck == 2) {

        /* lookup WolfSSLVerifyCallback class from global object ref */
        jclass verifyClass = (*jenv)->GetObjectClass(jenv, g_verifyCbIfaceObj);
        if (!verifyClass) {
            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
            }

            (*jenv)->ThrowNew(jenv, excClass,
                "Can't get native WolfSSLVerifyCallback class reference");
            return -104;
        }

        verifyMethod = (*jenv)->GetMethodID(jenv, verifyClass,
                                            "verifyCallback", "(IJ)I");
        if (verifyMethod == 0) {
            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
            }

            (*jenv)->ThrowNew(jenv, excClass,
                "Error getting verifyCallback method from JNI");
            return -105;
        }

        retval = (*jenv)->CallIntMethod(jenv, g_verifyCbIfaceObj,
                verifyMethod, preverify_ok, (jlong) store);

        if ((*jenv)->ExceptionOccurred(jenv)) {
            /* exception occurred on the Java side during method call */
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return -106;
        }

    } else {
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
        }

        (*jenv)->ThrowNew(jenv, excClass,
                "Object reference invalid in NativeVerifyCallback");
        return -1;
    }

    return retval;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLContext_memsaveCertCache
  (JNIEnv* jenv, jobject jcl, jlong ctx, jbyteArray mem, jint sz,
    jintArray used)
{
    int ret;
    int usedTmp;
    char memBuf[sz];

    if (!jenv || !ctx || !mem || (sz <= 0))
        return BAD_FUNC_ARG;

    /* find exception class */
    jclass excClass = (*jenv)->FindClass(jenv, "java/lang/Exception");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return SSL_FAILURE;
    }

    ret = wolfSSL_CTX_memsave_cert_cache((WOLFSSL_CTX*)ctx, memBuf, sz, &usedTmp);

    /* set used value for return */
    (*jenv)->SetIntArrayRegion(jenv, used, 0, 1, &usedTmp);
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);

        (*jenv)->ThrowNew(jenv, excClass,
                "Failed to set array region in native memsaveCertCache");
        return SSL_FAILURE;
    }

    /* set jbyteArray for return */
    if (usedTmp >= 0) {
        (*jenv)->SetByteArrayRegion(jenv, mem, 0, usedTmp, (jbyte*)memBuf);
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            (*jenv)->ThrowNew(jenv, excClass,
                    "Failed to set byte region in native memsaveCertCache");
            return SSL_FAILURE;
        }
    }

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLContext_memrestoreCertCache
  (JNIEnv* jenv, jobject jcl, jlong ctx, jbyteArray mem, jint sz)
{
    int ret;
    char memBuf[sz];

    if (!jenv || !ctx || !mem || (sz <= 0))
        return BAD_FUNC_ARG;

    /* find exception class */
    jclass excClass = (*jenv)->FindClass(jenv, "java/lang/Exception");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return SSL_FAILURE;
    }

    (*jenv)->GetByteArrayRegion(jenv, mem, 0, sz, (jbyte*)memBuf);
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);

        (*jenv)->ThrowNew(jenv, excClass,
                "Failed to get byte region in native memrestoreCertCache");
        return SSL_FAILURE;
    }

    ret = wolfSSL_CTX_memrestore_cert_cache((WOLFSSL_CTX*)ctx, memBuf, sz);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLContext_getCertCacheMemsize
  (JNIEnv* jenv, jobject jcl, jlong ctx)
{
    /* wolfSSL checks for null pointer */
    return wolfSSL_CTX_get_cert_cache_memsize((WOLFSSL_CTX*)ctx);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLContext_setCipherList
  (JNIEnv* jenv, jobject jcl, jlong ctx, jstring list)
{
    jint ret = 0;
    jclass excClass;
    const char* cipherList;

    if (!list)
    {
        excClass = (*jenv)->FindClass(jenv, "java/lang/NullPointerException");
        /* clear out previous exception */
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
        }

        /* throw NullPointerException */
        (*jenv)->ThrowNew(jenv, excClass,
                "Input cipher list is NULL");

        return SSL_FAILURE;
    }

    cipherList = (*jenv)->GetStringUTFChars(jenv, list, 0);

    ret = (jint) wolfSSL_CTX_set_cipher_list((WOLFSSL_CTX*)ctx,
            cipherList);

    (*jenv)->ReleaseStringUTFChars(jenv, list, cipherList);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLContext_loadVerifyBuffer
  (JNIEnv* jenv, jobject jcl, jlong ctx, jbyteArray in, jlong sz, jint format)
{
    unsigned char buff[sz];

    if (!jenv || !ctx || !in || (sz < 0))
        return BAD_FUNC_ARG;

    /* find exception class */
    jclass excClass = (*jenv)->FindClass(jenv, "java/lang/Exception");
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
                "Failed to get byte region in native loadVerifyBuffer");
        return SSL_FAILURE;
    }

    return wolfSSL_CTX_load_verify_buffer((WOLFSSL_CTX*)ctx, buff, sz, format);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLContext_useCertificateBuffer
  (JNIEnv* jenv, jobject jcl, jlong ctx, jbyteArray in, jlong sz, jint format)
{
    unsigned char buff[sz];

    if (!jenv || !ctx || !in || (sz < 0))
        return BAD_FUNC_ARG;

    /* find exception class */
    jclass excClass = (*jenv)->FindClass(jenv, "java/lang/Exception");
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

    return wolfSSL_CTX_use_certificate_buffer((WOLFSSL_CTX*)ctx, buff, sz,
            format);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLContext_usePrivateKeyBuffer
  (JNIEnv* jenv, jobject jcl, jlong ctx, jbyteArray in, jlong sz, jint format)
{
    unsigned char buff[sz];

    if (!jenv || !ctx || !in || (sz < 0))
        return BAD_FUNC_ARG;

    /* find exception class */
    jclass excClass = (*jenv)->FindClass(jenv, "java/lang/Exception");
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
                "Failed to get byte region in native usePrivateKeyBuffer");
        return SSL_FAILURE;
    }

    return wolfSSL_CTX_use_PrivateKey_buffer((WOLFSSL_CTX*)ctx, buff, sz,
            format);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLContext_useCertificateChainBuffer
  (JNIEnv* jenv, jobject jcl, jlong ctx, jbyteArray in, jlong sz)
{
    unsigned char buff[sz];

    if (!jenv || !ctx || !in || (sz < 0))
        return BAD_FUNC_ARG;

    /* find exception class */
    jclass excClass = (*jenv)->FindClass(jenv, "java/lang/Exception");
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
                "Failed to get byte region in native "
                "useCertificateChainBuffer");
        return SSL_FAILURE;
    }

    return wolfSSL_CTX_use_certificate_chain_buffer((WOLFSSL_CTX*)ctx, buff, sz);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLContext_setGroupMessages
  (JNIEnv* jenv, jobject jcl, jlong ctx)
{
    if (!jenv || !ctx)
        return BAD_FUNC_ARG;

    return wolfSSL_CTX_set_group_messages((WOLFSSL_CTX*)ctx);
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLContext_setIORecv(JNIEnv* jenv,
        jobject jcl, jlong ctx)
{
    /* find exception class */
    jclass excClass = (*jenv)->FindClass(jenv, "java/lang/Exception");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return;
    }

    if(ctx) {
        /* set I/O recv callback */
        wolfSSL_SetIORecv((WOLFSSL_CTX*)ctx, NativeIORecvCb);

    } else {
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLContext object was null when setting IORecv");
    }
}

int NativeIORecvCb(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    JNIEnv*    jenv;
    jint       retval = 0;
    jint       vmret  = 0;
    jmethodID  recvCbMethodId;
    jbyteArray inData;
    jclass     excClass;
    jobjectRefType refcheck;
    internCtx*   myCtx = ctx;

    if (!g_vm) {
        printf("Global JavaVM reference is null!\n");
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    /* get JavaEnv from JavaVM */
    vmret = (int)((*g_vm)->GetEnv(g_vm, (void**) &jenv, JNI_VERSION_1_6));
    if (vmret == JNI_EDETACHED) {
#ifdef __ANDROID__
        vmret = (*g_vm)->AttachCurrentThread(g_vm, &jenv, NULL);
#else
        vmret = (*g_vm)->AttachCurrentThread(g_vm, (void**) &jenv, NULL);
#endif
        if (vmret) {
            printf("Failed to attach JNIEnv to thread\n");
        } else {
            printf("Attached JNIEnv to thread\n");
        }
    } else if (vmret != JNI_OK) {
        printf("Error getting JNIEnv from JavaVM, ret = %d\n", vmret);
    }

    /* find exception class in case we need it */
    excClass = (*jenv)->FindClass(jenv, "java/lang/Exception");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    /* check if our stored object reference is valid */
    refcheck = (*jenv)->GetObjectRefType(jenv, myCtx->obj);
    if (refcheck == 2) {

        /* lookup WolfSSLSession class from global object ref */
        jclass sessClass = (*jenv)->GetObjectClass(jenv, myCtx->obj);
        if (!sessClass) {
            (*jenv)->ThrowNew(jenv, excClass,
                "Can't get native WolfSSLSession class reference in "
                "NativeIORecvCb");
            return WOLFSSL_CBIO_ERR_GENERAL;
        }

        /* lookup WolfSSLContext private member fieldID */
        jfieldID ctxFid = (*jenv)->GetFieldID(jenv, sessClass, "ctx",
                "Lcom/wolfssl/WolfSSLContext;");
                //"Lcom/wolfssl/WolfSSLSession$WolfSSLContext;");
        if (!ctxFid) {
            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
            }

            (*jenv)->ThrowNew(jenv, excClass,
                "Can't get native WolfSSLContext field ID in NativeIORecvCb");
            return WOLFSSL_CBIO_ERR_GENERAL;
        }

        /* find getContextPtr() method */
        jmethodID getCtxMethodId = (*jenv)->GetMethodID(jenv, sessClass,
            "getAssociatedContextPtr",
            "()Lcom/wolfssl/WolfSSLContext;");
        if (!getCtxMethodId) {
            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
            }

            (*jenv)->ThrowNew(jenv, excClass,
                "Can't get getAssociatedContextPtr() method ID in "
                "NativeIORecvCb");
            return WOLFSSL_CBIO_ERR_GENERAL;
        }

        /* get WolfSSLContext ctx object from Java land */
        jobject ctxref = (*jenv)->CallObjectMethod(jenv, myCtx->obj,
                getCtxMethodId);
        if (!ctxref) {
            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
            }

            (*jenv)->ThrowNew(jenv, excClass,
                "Can't get WolfSSLContext object in NativeIORecvCb");
            return WOLFSSL_CBIO_ERR_GENERAL;
        }

        /* get WolfSSLContext class reference from Java land */
        jclass innerCtxClass = (*jenv)->GetObjectClass(jenv, ctxref);
        if (!innerCtxClass) {
            (*jenv)->ThrowNew(jenv, excClass,
                "Can't get native WolfSSLContext class reference in "
                "NativeIORecvCb");
            return WOLFSSL_CBIO_ERR_GENERAL;
        }

        /* call internal I/O recv callback */
        recvCbMethodId = (*jenv)->GetMethodID(jenv, innerCtxClass,
                "internalIORecvCallback",
                "(Lcom/wolfssl/WolfSSLSession;[BI)I");

        if (!recvCbMethodId) {
            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
            }

            printf("Error getting internalIORecvCallback method from JNI\n");
            retval = WOLFSSL_CBIO_ERR_GENERAL;
        }

        if (!retval)
        {
            /* create jbyteArray to hold received data */
            inData = (*jenv)->NewByteArray(jenv, sz);
            if (!inData) {
                return WOLFSSL_CBIO_ERR_GENERAL;
            }

            /* call Java send callback, ignore native ctx since Java
             * handles it */
            retval = (*jenv)->CallIntMethod(jenv, ctxref, recvCbMethodId,
                                        myCtx->obj, inData, (jint)sz);

            if ((*jenv)->ExceptionOccurred(jenv)) {
                /* an exception occurred on the Java side, how to
                 * handle it? */
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
                retval = WOLFSSL_CBIO_ERR_GENERAL;
            }

            /* copy jbyteArray into char array */
            if (retval >= 0) {
                (*jenv)->GetByteArrayRegion(jenv, inData, 0, retval,
                        (jbyte*)buf);
                if ((*jenv)->ExceptionOccurred(jenv)) {
                    (*jenv)->ExceptionDescribe(jenv);
                    (*jenv)->ExceptionClear(jenv);
                    retval = WOLFSSL_CBIO_ERR_GENERAL;
                }
            }

            /* delete local refs */
            (*jenv)->DeleteLocalRef(jenv, inData);
        }

        /* detach JNIEnv from thread */
        (*g_vm)->DetachCurrentThread(g_vm);

    } else {
        /* clear any existing exception before we throw another */
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
        }

        (*jenv)->ThrowNew(jenv, excClass,
                "Object reference invalid in NativeIORecvCb");

        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    return retval;
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLContext_setIOSend
  (JNIEnv* jenv, jobject jcl, jlong ctx)
{
    /* find exception class in case we need it */
    jclass excClass = (*jenv)->FindClass(jenv, "java/lang/Exception");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
    }

    if (ctx) {
        /* set I/O send callback */
        wolfSSL_SetIOSend((WOLFSSL_CTX*)ctx, NativeIOSendCb);

    } else {
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLContext object was null when setting IOSend");
    }
}

int NativeIOSendCb(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    JNIEnv*    jenv;
    jint       retval = 0;
    jint       vmret  = 0;
    jmethodID  sendCbMethodId;
    jbyteArray outData;
    jclass     excClass;
    jobjectRefType refcheck;
    internCtx*     myCtx = ctx;

    if (!g_vm) {
        printf("Global JavaVM reference is null!\n");
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    /* get JavaEnv from JavaVM */
    vmret = (int)((*g_vm)->GetEnv(g_vm, (void**) &jenv, JNI_VERSION_1_6));
    if (vmret == JNI_EDETACHED) {
#ifdef __ANDROID__
        vmret = (*g_vm)->AttachCurrentThread(g_vm, &jenv, NULL);
#else
        vmret = (*g_vm)->AttachCurrentThread(g_vm, (void**) &jenv, NULL);
#endif
        if (vmret) {
            printf("Failed to attach JNIEnv to thread\n");
        } else {
            printf("Attached JNIEnv to thread\n");
        }
    } else if (vmret != JNI_OK) {
        printf("Error getting JNIEnv from JavaVM, ret = %d\n", vmret);
    }

    /* find exception class in case we need it */
    excClass = (*jenv)->FindClass(jenv, "java/lang/Exception");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    /* check if our stored object reference is valid */
    refcheck = (*jenv)->GetObjectRefType(jenv, myCtx->obj);
    if (refcheck == 2) {

        /* lookup WolfSSLSession class from global object ref */
        jclass sessClass = (*jenv)->GetObjectClass(jenv, myCtx->obj);
        if (!sessClass) {
            (*jenv)->ThrowNew(jenv, excClass,
                "Can't get native WolfSSLSession class reference");
            return WOLFSSL_CBIO_ERR_GENERAL;
        }

        /* lookup WolfSSLContext private member fieldID */
        jfieldID ctxFid = (*jenv)->GetFieldID(jenv, sessClass, "ctx",
                "Lcom/wolfssl/WolfSSLContext;");
        if (!ctxFid) {
            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
            }

            (*jenv)->ThrowNew(jenv, excClass,
                "Can't get native WolfSSLContext field ID in NativeIOSendCb");
            return WOLFSSL_CBIO_ERR_GENERAL;
        }

        /* find getContextPtr() method */
        jmethodID getCtxMethodId = (*jenv)->GetMethodID(jenv, sessClass,
            "getAssociatedContextPtr",
            "()Lcom/wolfssl/WolfSSLContext;");
        if (!getCtxMethodId) {
            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
            }

            (*jenv)->ThrowNew(jenv, excClass,
                "Can't get getAssociatedContextPtr() method ID in "
                "NativeIOSendCb");
            return WOLFSSL_CBIO_ERR_GENERAL;
        }

        /* get WolfSSLContext ctx object from Java land */
        jobject ctxref = (*jenv)->CallObjectMethod(jenv, myCtx->obj,
                getCtxMethodId);
        if (!ctxref) {
            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
            }

            (*jenv)->ThrowNew(jenv, excClass,
                "Can't get WolfSSLContext object in NativeIOSendCb");
            return WOLFSSL_CBIO_ERR_GENERAL;
        }

        /* get WolfSSLContext class reference from Java land */
        jclass innerCtxClass = (*jenv)->GetObjectClass(jenv, ctxref);
        if (!innerCtxClass) {
            (*jenv)->ThrowNew(jenv, excClass,
                "Can't get native WolfSSLContext class reference in "
                "NativeIOSendCb");
            return WOLFSSL_CBIO_ERR_GENERAL;
        }

        /* call internal I/O recv callback */
        sendCbMethodId = (*jenv)->GetMethodID(jenv, innerCtxClass,
                "internalIOSendCallback",
                "(Lcom/wolfssl/WolfSSLSession;[BI)I");

        if (!sendCbMethodId) {
            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
            }

            printf("Error getting internalIOSendCallback method from JNI\n");
            retval = WOLFSSL_CBIO_ERR_GENERAL;
        }

        if (!retval && sz >= 0)
        {
            /* create jbyteArray to hold received data */
            outData = (*jenv)->NewByteArray(jenv, sz);
            if (!outData) {
                return WOLFSSL_CBIO_ERR_GENERAL;
            }

            (*jenv)->SetByteArrayRegion(jenv, outData, 0, sz, (jbyte*)buf);
            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
                return WOLFSSL_CBIO_ERR_GENERAL;
            }

            /* call Java send callback, ignore native ctx since Java
             * handles it */
            retval = (*jenv)->CallIntMethod(jenv, ctxref, sendCbMethodId,
                                        myCtx->obj, outData, (jint)sz);

            if ((*jenv)->ExceptionOccurred(jenv)) {
                /* an exception occurred on the Java side, how to
                 * handle it? */
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
                retval = WOLFSSL_CBIO_ERR_GENERAL;
            }

            /* delete local refs */
            (*jenv)->DeleteLocalRef(jenv, outData);
        }

        /* detach JNIEnv from thread */
        (*g_vm)->DetachCurrentThread(g_vm);

    } else {
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
        }

        (*jenv)->ThrowNew(jenv, excClass,
                "Object reference invalid in NativeIOSendCb");

        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    return retval;
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLContext_setGenCookie
  (JNIEnv* jenv, jobject jcl, jlong ctx)
{
    /* find exception class in case we need it */
    jclass excClass = (*jenv)->FindClass(jenv, "java/lang/Exception");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
    }

    if (ctx) {
        /* set gen cookie callback */
        wolfSSL_CTX_SetGenCookie((WOLFSSL_CTX*)ctx, NativeGenCookieCb);

    } else {
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLContext object was null when setting "
                "genCookieCb");
    }
}

int NativeGenCookieCb(WOLFSSL *ssl, unsigned char *buf, int sz, void *ctx)
{
    JNIEnv*    jenv;
    jint       retval = 0;
    jint       vmret  = 0;
    jmethodID  cookieCbMethodId;
    jbyteArray inData;
    jclass     excClass;
    jobjectRefType refcheck;
    internCtx*   myCtx = ctx;

    if (!g_vm) {
        printf("Global JavaVM reference is null!\n");
        return GEN_COOKIE_E;
    }

    /* get JavaEnv from JavaVM */
    vmret = (int)((*g_vm)->GetEnv(g_vm, (void**) &jenv, JNI_VERSION_1_6));
    if (vmret == JNI_EDETACHED) {
#ifdef __ANDROID__
        vmret = (*g_vm)->AttachCurrentThread(g_vm, &jenv, NULL);
#else
        vmret = (*g_vm)->AttachCurrentThread(g_vm, (void**) &jenv, NULL);
#endif
        if (vmret) {
            printf("Failed to attach JNIEnv to thread\n");
        } else {
            printf("Attached JNIEnv to thread\n");
        }
    } else if (vmret != JNI_OK) {
        printf("Error getting JNIEnv from JavaVM, ret = %d\n", vmret);
    }

    /* find exception class in case we need it */
    excClass = (*jenv)->FindClass(jenv, "java/lang/Exception");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return GEN_COOKIE_E;
    }

    /* check if our stored object reference is valid */
    refcheck = (*jenv)->GetObjectRefType(jenv, myCtx->obj);
    if (refcheck == 2) {

        /* lookup WolfSSLSession class from global object ref */
        jclass sessClass = (*jenv)->GetObjectClass(jenv, myCtx->obj);
        if (!sessClass) {
            (*jenv)->ThrowNew(jenv, excClass,
                "Can't get native WolfSSLSession class reference");
            return GEN_COOKIE_E;
        }

        /* lookup WolfSSLContext private member fieldID */
        jfieldID ctxFid = (*jenv)->GetFieldID(jenv, sessClass, "ctx",
                "Lcom/wolfssl/WolfSSLContext;");
        if (!ctxFid) {
            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
            }

            (*jenv)->ThrowNew(jenv, excClass,
                "Can't get native WolfSSLContext field ID in "
                "NativeGenCookieCb");
            return GEN_COOKIE_E;
        }

        /* find getContextPtr() method */
        jmethodID getCtxMethodId = (*jenv)->GetMethodID(jenv, sessClass,
            "getAssociatedContextPtr",
            "()Lcom/wolfssl/WolfSSLContext;");
        if (!getCtxMethodId) {
            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
            }

            (*jenv)->ThrowNew(jenv, excClass,
                "Can't get getAssociatedContextPtr() method ID in "
                "NativeGenCookieCb");
            return GEN_COOKIE_E;
        }

        /* get WolfSSLContext ctx object from Java land */
        jobject ctxref = (*jenv)->CallObjectMethod(jenv, myCtx->obj,
                getCtxMethodId);
        if (!ctxref) {
            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
            }

            (*jenv)->ThrowNew(jenv, excClass,
                "Can't get WolfSSLContext object in NativeGenCookieCb");
            return GEN_COOKIE_E;
        }

        /* get WolfSSLContext class reference from Java land */
        jclass innerCtxClass = (*jenv)->GetObjectClass(jenv, ctxref);
        if (!innerCtxClass) {
            (*jenv)->ThrowNew(jenv, excClass,
                "Can't get native WolfSSLContext class reference in "
                "NativeGenCookieCb");
            return GEN_COOKIE_E;
        }

        /* call internal gen cookie callback */
        cookieCbMethodId = (*jenv)->GetMethodID(jenv, innerCtxClass,
                "internalGenCookieCallback",
                "(Lcom/wolfssl/WolfSSLSession;[BI)I");

        if (!cookieCbMethodId) {
            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
            }

            printf("Error getting internalGenCookieCallback method from JNI\n");
            retval = GEN_COOKIE_E;
        }

        if (!retval && sz >= 0)
        {
            /* create jbyteArray to hold cookie data */
            inData = (*jenv)->NewByteArray(jenv, sz);
            if (!inData) {
                return GEN_COOKIE_E;
            }

            /* call Java cookie callback */
            retval = (*jenv)->CallIntMethod(jenv, ctxref, cookieCbMethodId,
                                        myCtx->obj, inData, (jint)sz);

            if ((*jenv)->ExceptionOccurred(jenv)) {
                /* an exception occurred on the Java side, how to handle it? */
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
                retval = GEN_COOKIE_E;
            }

            /* copy jbyteArray into char array */
            if (retval >= 0) {
                (*jenv)->GetByteArrayRegion(jenv, inData, 0, retval,
                        (jbyte*)buf);
                if ((*jenv)->ExceptionOccurred(jenv)) {
                    (*jenv)->ExceptionDescribe(jenv);
                    (*jenv)->ExceptionClear(jenv);
                    retval = GEN_COOKIE_E;
                }
            }

            /* delete local refs */
            (*jenv)->DeleteLocalRef(jenv, inData);
        }

        /* detach JNIEnv from thread */
        (*g_vm)->DetachCurrentThread(g_vm);

    } else {
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
        }

        (*jenv)->ThrowNew(jenv, excClass,
                "Object reference invalid in NativeGenCookieCb");

        return GEN_COOKIE_E;
    }

    return retval;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLContext_enableCRL
  (JNIEnv* jenv, jobject jcl, jlong ctx, jint options)
{
    if (!jenv || !ctx)
        return BAD_FUNC_ARG;

    return wolfSSL_CTX_EnableCRL((WOLFSSL_CTX*)ctx, options);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLContext_disableCRL
  (JNIEnv* jenv, jobject jcl, jlong ctx)
{
    if (!jenv || !ctx)
        return BAD_FUNC_ARG;

    return wolfSSL_CTX_DisableCRL((WOLFSSL_CTX*)ctx);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLContext_loadCRL
  (JNIEnv* jenv, jobject jcl, jlong ctx, jstring path, jint type, jint monitor)
{
    int ret;
    const char* crlPath;

    if (!jenv || !ctx || !path)
        return BAD_FUNC_ARG;

    crlPath = (*jenv)->GetStringUTFChars(jenv, path, 0);

    ret = wolfSSL_CTX_LoadCRL((WOLFSSL_CTX*)ctx, crlPath, type, monitor);

    (*jenv)->ReleaseStringUTFChars(jenv, path, crlPath);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLContext_setCRLCb
  (JNIEnv* jenv, jobject jcl, jlong ctx, jobject cb)
{
    int ret = 0;

    if (!jenv || !ctx || !cb) {
        return BAD_FUNC_ARG;
    }

    /* store Java CRL callback Interface object */
    g_crlCtxCbIfaceObj = (*jenv)->NewGlobalRef(jenv, cb);
    if (!g_crlCtxCbIfaceObj) {
        printf("error storing global missing CTX CRL callback interface\n");
    }

    ret = wolfSSL_CTX_SetCRL_Cb((WOLFSSL_CTX*)ctx, NativeCtxMissingCRLCallback);

    return ret;
}

void NativeCtxMissingCRLCallback(const char* url)
{
    JNIEnv*   jenv;
    jint      vmret  = 0;
    jclass    excClass;
    jmethodID crlMethod;
    jobjectRefType refcheck;

    /* get JNIEnv from JavaVM */
    vmret = (int)((*g_vm)->GetEnv(g_vm, (void**) &jenv, JNI_VERSION_1_6));
    if (vmret == JNI_EDETACHED) {
#ifdef __ANDROID__
        vmret = (*g_vm)->AttachCurrentThread(g_vm, &jenv, NULL);
#else
        vmret = (*g_vm)->AttachCurrentThread(g_vm, (void**) &jenv, NULL);
#endif
        if (vmret) {
            printf("Failed to attach JNIEnv to thread\n");
        }
    } else if (vmret != JNI_OK) {
        printf("Unable to get JNIEnv from JavaVM\n");
    }

    /* find exception class */
    excClass = (*jenv)->FindClass(jenv, "java/lang/Exception");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return;
    }

    /* check if our stored object reference is valid */
    refcheck = (*jenv)->GetObjectRefType(jenv, g_crlCtxCbIfaceObj);
    if (refcheck == 2) {

        /* lookup WolfSSLMissingCRLCallback class from global object ref */
        jclass crlClass = (*jenv)->GetObjectClass(jenv, g_crlCtxCbIfaceObj);
        if (!crlClass) {
            (*jenv)->ThrowNew(jenv, excClass,
                "Can't get native WolfSSLMissingCRLCallback class reference");
            return;
        }

        crlMethod = (*jenv)->GetMethodID(jenv, crlClass,
                                            "missingCRLCallback",
                                            "(Ljava/lang/String;)V");
        if (crlMethod == 0) {
            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
            }

            (*jenv)->ThrowNew(jenv, excClass,
                "Error getting missingCRLCallback method from JNI");
            return;
        }

        /* create jstring from char* */
        jstring missingUrl = (*jenv)->NewStringUTF(jenv, url);

        (*jenv)->CallVoidMethod(jenv, g_crlCtxCbIfaceObj, crlMethod,
                missingUrl);

        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return;
        }

    } else {
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
        }

        (*jenv)->ThrowNew(jenv, excClass,
                "Object reference invalid in NativeMissingCRLCallback");
    }
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLContext_enableOCSP
  (JNIEnv* jenv, jobject jcl, jlong ctx, jlong options)
{
    return wolfSSL_CTX_EnableOCSP((WOLFSSL_CTX*)ctx, options);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLContext_disableOCSP
  (JNIEnv* jenv, jobject jcl, jlong ctx)
{
    return wolfSSL_CTX_DisableOCSP((WOLFSSL_CTX*)ctx);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLContext_setOCSPOverrideUrl
  (JNIEnv* jenv, jobject jcl, jlong ctx, jstring urlString)
{
    jint ret = 0;
    jclass excClass;
    const char* url;

    if (urlString == NULL)
    {
        excClass = (*jenv)->FindClass(jenv, "java/lang/NullPointerException");
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
        }

        /* throw NullPointerException */
        (*jenv)->ThrowNew(jenv, excClass,
                "Input URL is NULL in setOCSPOverrideUrl()");

        return SSL_FAILURE;
    }

    url = (*jenv)->GetStringUTFChars(jenv, urlString, 0);

    ret = (jint) wolfSSL_CTX_SetOCSP_OverrideURL((WOLFSSL_CTX*)ctx, url);

    (*jenv)->ReleaseStringUTFChars(jenv, urlString, url);

    return ret;
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLContext_setMacEncryptCb
  (JNIEnv* jenv, jobject jcl, jlong ctx)
{
    /* find exception class */
    jclass excClass = (*jenv)->FindClass(jenv, "java/lang/Exception");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return;
    }

    if(ctx) {
        /* set MAC encrypt callback */
        wolfSSL_CTX_SetMacEncryptCb((WOLFSSL_CTX*)ctx, NativeMacEncryptCb);

    } else {
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLContext object was null when setting MacEncrypt");
    }
}

int NativeMacEncryptCb(WOLFSSL* ssl, unsigned char* macOut,
        const unsigned char* macIn, unsigned int macInSz, int macContent,
        int macVerify, unsigned char* encOut, const unsigned char* encIn,
        unsigned int encSz, void* ctx)
{
    JNIEnv*    jenv;
    int        hmacSize;
    jint       retval = 0;
    jint       vmret  = 0;
    jmethodID  macEncryptMethodId;
    jclass     excClass;
    jbyteArray j_macIn;

    jobjectRefType refcheck;
    internCtx*     myCtx = ctx;

    if (!g_vm) {
        printf("Global JavaVM reference is null!\n");
        return -1;
    }

    /* get JavaEnv from JavaVM */
    vmret = (int)((*g_vm)->GetEnv(g_vm, (void**) &jenv, JNI_VERSION_1_6));
    if (vmret == JNI_EDETACHED) {
#ifdef __ANDROID__
        vmret = (*g_vm)->AttachCurrentThread(g_vm, &jenv, NULL);
#else
        vmret = (*g_vm)->AttachCurrentThread(g_vm, (void**) &jenv, NULL);
#endif
        if (vmret) {
            printf("Failed to attach JNIEnv to thread\n");
        } else {
            printf("Attached JNIEnv to thread\n");
        }
    } else if (vmret != JNI_OK) {
        printf("Error getting JNIEnv from JavaVM, ret = %d\n", vmret);
    }

    /* find exception class in case we need it */
    excClass = (*jenv)->FindClass(jenv, "java/lang/Exception");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return -1;
    }

    /* check if our stored object reference is valid */
    refcheck = (*jenv)->GetObjectRefType(jenv, myCtx->obj);
    if (refcheck == 2) {

        /* lookup WolfSSLSession class from global object ref */
        jclass sessClass = (*jenv)->GetObjectClass(jenv, myCtx->obj);
        if (!sessClass) {
            (*jenv)->ThrowNew(jenv, excClass,
                "Can't get native WolfSSLSession class reference "
                "in NativeMacEncryptCb");
            return -1;
        }

        /* lookup WolfSSLContext private member fieldID */
        jfieldID ctxFid = (*jenv)->GetFieldID(jenv, sessClass, "ctx",
                "Lcom/wolfssl/WolfSSLContext;");
        if (!ctxFid) {
            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
            }

            (*jenv)->ThrowNew(jenv, excClass,
                "Can't get native WolfSSLContext field ID in "
                "NativeMacEncryptCb");
            return -1;
        }

        /* find getContextPtr() method */
        jmethodID getCtxMethodId = (*jenv)->GetMethodID(jenv, sessClass,
            "getAssociatedContextPtr",
            "()Lcom/wolfssl/WolfSSLContext;");
        if (!getCtxMethodId) {
            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
            }

            (*jenv)->ThrowNew(jenv, excClass,
                "Can't get getAssociatedContextPtr() method ID in "
                "NativeMacEncryptCb");
            return -1;
        }

        /* get WolfSSLContext ctx object from Java land */
        jobject ctxref = (*jenv)->CallObjectMethod(jenv, myCtx->obj,
                getCtxMethodId);
        if (!ctxref) {
            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
            }

            (*jenv)->ThrowNew(jenv, excClass,
                "Can't get WolfSSLContext object in NativeMacEncryptCb");
            return -1;
        }

        /* get WolfSSLContext class reference from Java land */
        jclass innerCtxClass = (*jenv)->GetObjectClass(jenv, ctxref);
        if (!innerCtxClass) {
            (*jenv)->ThrowNew(jenv, excClass,
                "Can't get native WolfSSLContext class reference in "
                "NativeMacEncryptCb");
            return -1;
        }

        /* get ref to internal MAC encrypt callback */
        macEncryptMethodId = (*jenv)->GetMethodID(jenv, innerCtxClass,
                "internalMacEncryptCallback",
                "(Lcom/wolfssl/WolfSSLSession;Ljava/nio/ByteBuffer;"
                "[BJIILjava/nio/ByteBuffer;Ljava/nio/ByteBuffer;J)I");

        if (!macEncryptMethodId) {
            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
            }

            printf("Error getting internalMacEncryptCallback method "
                    "from JNI\n");
            retval = -1;
        }

        if (retval == 0)
        {
            hmacSize = wolfSSL_GetHmacSize((WOLFSSL*)ssl);

            /* create ByteBuffer to wrap macOut */
            jobject macOutBB = (*jenv)->NewDirectByteBuffer(jenv, macOut,
                    hmacSize);
            if (!macOutBB) {
                printf("failed to create macOut ByteBuffer\n");
                return -1;
            }

            /* create jbyteArray to hold macIn, since macIn is read-only */
            j_macIn = (*jenv)->NewByteArray(jenv, macInSz);
            if (!j_macIn)
                return -1;

            (*jenv)->SetByteArrayRegion(jenv, j_macIn, 0, macInSz,
                    (jbyte*)macIn);
            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
                return -1;
            }

            /* create ByteBuffer to wrap encOut */
            jobject encOutBB = (*jenv)->NewDirectByteBuffer(jenv, encOut,
                    encSz);
            if (!encOutBB) {
                printf("failed to create encOut ByteBuffer\n");
                return -1;
            }

            /* create ByteBuffer to wrap encIn - use encOut b/c it's not a
             * const, but points to same memory. This will be important
             * in Java-land in order to have an updated encIn array after
             * doing the MAC operation. */
            jobject encInBB = (*jenv)->NewDirectByteBuffer(jenv, encOut,
                    encSz);
            if (!encInBB) {
                printf("failed to create encIn ByteBuffer\n");
                return -1;
            }

            /* call Java MAC/encrypt callback */
            retval = (*jenv)->CallIntMethod(jenv, ctxref, macEncryptMethodId,
                    myCtx->obj, macOutBB, j_macIn, (jlong)macInSz, macContent,
                    macVerify, encOutBB, encInBB, (jlong)encSz);

            if ((*jenv)->ExceptionOccurred(jenv) || retval != 0) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
                (*jenv)->ThrowNew(jenv, excClass,
                    "Call to Java callback failed in NativeMacEncryptCb");
                return -1;
            }

            /* delete local refs */
            (*jenv)->DeleteLocalRef(jenv, j_macIn);
        }

        /* detach JNIEnv from thread */
        (*g_vm)->DetachCurrentThread(g_vm);

    } else {
        /* clear any existing exception before we throw another */
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
        }

        (*jenv)->ThrowNew(jenv, excClass,
                "Object reference invalid in NativeMacEncryptCb");

        return -1;
    }

    return retval;
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLContext_setDecryptVerifyCb
  (JNIEnv* jenv, jobject jcl, jlong ctx)
{
    /* find exception class */
    jclass excClass = (*jenv)->FindClass(jenv, "java/lang/Exception");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return;
    }

    if(ctx) {
        /* set decrypt/verify callback */
        wolfSSL_CTX_SetDecryptVerifyCb((WOLFSSL_CTX*)ctx, NativeDecryptVerifyCb);

    } else {
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLContext object was null when setting MacDecrypt");
    }
}

int  NativeDecryptVerifyCb(WOLFSSL* ssl, unsigned char* decOut,
        const unsigned char* decIn, unsigned int decSz, int content,
        int verify, unsigned int* padSz, void* ctx)
{
    JNIEnv*    jenv;
    jint       retval = 0;
    jint       vmret  = 0;
    jmethodID  decryptVerifyMethodId;
    jclass     excClass;

    jobjectRefType refcheck;
    internCtx*     myCtx = ctx;

    jbyteArray j_decIn;
    jlongArray j_padSz;

    if (!g_vm) {
        printf("Global JavaVM reference is null!\n");
        return -1;
    }

    /* get JavaEnv from JavaVM */
    vmret = (int)((*g_vm)->GetEnv(g_vm, (void**) &jenv, JNI_VERSION_1_6));
    if (vmret == JNI_EDETACHED) {
#ifdef __ANDROID__
        vmret = (*g_vm)->AttachCurrentThread(g_vm, &jenv, NULL);
#else
        vmret = (*g_vm)->AttachCurrentThread(g_vm, (void**) &jenv, NULL);
#endif
        if (vmret) {
            printf("Failed to attach JNIEnv to thread\n");
        } else {
            printf("Attached JNIEnv to thread\n");
        }
    } else if (vmret != JNI_OK) {
        printf("Error getting JNIEnv from JavaVM, ret = %d\n", vmret);
    }

    /* find exception class in case we need it */
    excClass = (*jenv)->FindClass(jenv, "java/lang/Exception");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return -1;
    }

    /* check if our stored object reference is valid */
    refcheck = (*jenv)->GetObjectRefType(jenv, myCtx->obj);
    if (refcheck == 2) {

        /* lookup WolfSSLSession class from global object ref */
        jclass sessClass = (*jenv)->GetObjectClass(jenv, myCtx->obj);
        if (!sessClass) {
            (*jenv)->ThrowNew(jenv, excClass,
                "Can't get native WolfSSLSession class reference "
                "in NativeDecryptVerifyCb");
            return -1;
        }

        /* lookup WolfSSLContext private member fieldID */
        jfieldID ctxFid = (*jenv)->GetFieldID(jenv, sessClass, "ctx",
                "Lcom/wolfssl/WolfSSLContext;");
        if (!ctxFid) {
            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
            }

            (*jenv)->ThrowNew(jenv, excClass,
                "Can't get native WolfSSLContext field ID "
                "in NativeDecryptVerifyCb");
            return -1;
        }

        /* find getContextPtr() method */
        jmethodID getCtxMethodId = (*jenv)->GetMethodID(jenv, sessClass,
            "getAssociatedContextPtr",
            "()Lcom/wolfssl/WolfSSLContext;");
        if (!getCtxMethodId) {
            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
            }

            (*jenv)->ThrowNew(jenv, excClass,
                "Can't get getAssociatedContextPtr() method ID "
                "in NativeDecryptVerifyCb");
            return -1;
        }

        /* get WolfSSLContext ctx object from Java land */
        jobject ctxref = (*jenv)->CallObjectMethod(jenv, myCtx->obj,
                getCtxMethodId);
        if (!ctxref) {
            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
            }

            (*jenv)->ThrowNew(jenv, excClass,
                "Can't get WolfSSLContext object in NativeDecryptVerifyCb");
            return -1;
        }

        /* get WolfSSLContext class reference from Java land */
        jclass innerCtxClass = (*jenv)->GetObjectClass(jenv, ctxref);
        if (!innerCtxClass) {
            (*jenv)->ThrowNew(jenv, excClass,
                "Can't get native WolfSSLContext class reference "
                "in NativeDecryptVerifyCb");
            return -1;
        }

        /* call internal decrypt/verify callback */
        decryptVerifyMethodId = (*jenv)->GetMethodID(jenv, innerCtxClass,
                "internalDecryptVerifyCallback",
                "(Lcom/wolfssl/WolfSSLSession;Ljava/nio/ByteBuffer;[BJII[J)I");

        if (!decryptVerifyMethodId) {
            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
            }

            printf("Error getting internalDecryptVerifyCallback method "
                    "from JNI\n");
            retval = -1;
        }

        if (retval == 0)
        {
            /* create ByteBuffer to wrap decOut */
            jobject decOutBB = (*jenv)->NewDirectByteBuffer(jenv, decOut,
                    decSz);
            if (!decOutBB) {
                printf("failed to create decOut ByteBuffer\n");
                return -1;
            }

            /* create jbyteArray to hold decIn */
            j_decIn = (*jenv)->NewByteArray(jenv, decSz);
            if (!j_decIn)
                return -1;

            (*jenv)->SetByteArrayRegion(jenv, j_decIn, 0, decSz, (jbyte*)decIn);
            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
                return -1;
            }

            /* create jlongArray to hold padSz, since we need to use it as
             * an OUTPUT parameter from Java. Only needs to have 1 element */
            j_padSz = (*jenv)->NewLongArray(jenv, 1);
            if (!j_padSz) {
                printf("failed to create padSz longArray\n");
                return -1;
            }

            /* call Java decrypt/verify callback, java layer handles
             * adding decrypt/verify CTX reference */
            retval = (*jenv)->CallIntMethod(jenv, ctxref, decryptVerifyMethodId,
                    myCtx->obj, decOutBB, j_decIn, (jlong)decSz, content,
                    verify, j_padSz);

            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
                retval = -1;
            }

            if (retval == 0) {
                /* copy j_padSz into padSz */
                jlong tmpVal;
                (*jenv)->GetLongArrayRegion(jenv, j_padSz, 0, 1, &tmpVal);
                if ((*jenv)->ExceptionOccurred(jenv)) {
                    (*jenv)->ExceptionDescribe(jenv);
                    (*jenv)->ExceptionClear(jenv);
                    retval = -1;
                }
                *padSz = (unsigned int)tmpVal;
            }

            /* delete local refs */
            (*jenv)->DeleteLocalRef(jenv, j_decIn);
        }

        /* detach JNIEnv from thread */
        (*g_vm)->DetachCurrentThread(g_vm);

    } else {
        /* clear any existing exception before we throw another */
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
        }

        (*jenv)->ThrowNew(jenv, excClass,
                "Object reference invalid in NativeDecryptVerifyCb");

        return -1;
    }

    return retval;
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLContext_setEccSignCb
  (JNIEnv* jenv, jobject jcl, jlong ctx)
{
    /* find exception class */
    jclass excClass = (*jenv)->FindClass(jenv, "java/lang/Exception");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return;
    }

    if(ctx) {
        /* set ECC sign callback */
        wolfSSL_CTX_SetEccSignCb((WOLFSSL_CTX*)ctx, NativeEccSignCb);

    } else {
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLContext object was null when setting "
                "EccSignCb");
    }
}

int  NativeEccSignCb(WOLFSSL* ssl, const unsigned char* in, unsigned int inSz,
        unsigned char* out, unsigned int* outSz, const unsigned char* keyDer,
        unsigned int keySz, void* ctx)
{
    JNIEnv*    jenv;
    jint       retval = 0;
    jint       vmret  = 0;
    jmethodID  eccSignMethodId;
    jclass     excClass;

    jobjectRefType refcheck;
    internCtx*     myCtx = ctx;

    jlongArray j_outSz;

    if (!g_vm) {
        printf("Global JavaVM reference is null!\n");
        return -1;
    }

    printf("Entered NativeEccSignCb\n");

    /* get JavaEnv from JavaVM */
    vmret = (int)((*g_vm)->GetEnv(g_vm, (void**) &jenv, JNI_VERSION_1_6));
    if (vmret == JNI_EDETACHED) {
#ifdef __ANDROID__
        vmret = (*g_vm)->AttachCurrentThread(g_vm, &jenv, NULL);
#else
        vmret = (*g_vm)->AttachCurrentThread(g_vm, (void**) &jenv, NULL);
#endif
        if (vmret) {
            printf("Failed to attach JNIEnv to thread\n");
        } else {
            printf("Attached JNIEnv to thread\n");
        }
    } else if (vmret != JNI_OK) {
        printf("Error getting JNIEnv from JavaVM, ret = %d\n", vmret);
    }

    /* find exception class in case we need it */
    excClass = (*jenv)->FindClass(jenv, "java/lang/Exception");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return -1;
    }

    /* check if our stored object reference is valid */
    refcheck = (*jenv)->GetObjectRefType(jenv, myCtx->obj);
    if (refcheck == 2) {

        /* lookup WolfSSLSession class from global object ref */
        jclass sessClass = (*jenv)->GetObjectClass(jenv, myCtx->obj);
        if (!sessClass) {
            (*jenv)->ThrowNew(jenv, excClass,
                "Can't get native WolfSSLSession class reference "
                "in NativeEccSignCb");
            return -1;
        }

        /* lookup WolfSSLContext private member fieldID */
        jfieldID ctxFid = (*jenv)->GetFieldID(jenv, sessClass, "ctx",
                "Lcom/wolfssl/WolfSSLContext;");
        if (!ctxFid) {
            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
            }

            (*jenv)->ThrowNew(jenv, excClass,
                "Can't get native WolfSSLContext field ID "
                "in NativeEccSignCb");
            return -1;
        }

        /* find getContextPtr() method */
        jmethodID getCtxMethodId = (*jenv)->GetMethodID(jenv, sessClass,
            "getAssociatedContextPtr",
            "()Lcom/wolfssl/WolfSSLContext;");
        if (!getCtxMethodId) {
            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
            }

            (*jenv)->ThrowNew(jenv, excClass,
                "Can't get getAssociatedContextPtr() method ID "
                "in NativeEccSignCb");
            return -1;
        }

        /* get WolfSSLContext ctx object from Java land */
        jobject ctxref = (*jenv)->CallObjectMethod(jenv, myCtx->obj,
                getCtxMethodId);
        if (!ctxref) {
            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
            }

            (*jenv)->ThrowNew(jenv, excClass,
                "Can't get WolfSSLContext object in NativeEccSignCb");
            return -1;
        }

        /* get WolfSSLContext class reference from Java land */
        jclass innerCtxClass = (*jenv)->GetObjectClass(jenv, ctxref);
        if (!innerCtxClass) {
            (*jenv)->ThrowNew(jenv, excClass,
                "Can't get native WolfSSLContext class reference "
                "in NativeEccSignCb");
            return -1;
        }

        /* call internal decrypt/verify callback */
        eccSignMethodId = (*jenv)->GetMethodID(jenv, innerCtxClass,
                "internalEccSignCallback",
                "(Lcom/wolfssl/WolfSSLSession;Ljava/nio/ByteBuffer;"
                "JLjava/nio/ByteBuffer;[JLjava/nio/ByteBuffer;J)I");

        if (!eccSignMethodId) {
            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
            }

            printf("Error getting internalEccSignCallback method "
                    "from JNI\n");
            retval = -1;
        }

        if (retval == 0)
        {
            /* create ByteBuffer to wrap out */
            jobject outBB = (*jenv)->NewDirectByteBuffer(jenv, out, *outSz);
            if (!outBB) {
                printf("failed to create eccSign out ByteBuffer\n");
                return -1;
            }

            /* create ByteBuffer to wrap in */
            jobject inBB = (*jenv)->NewDirectByteBuffer(jenv, (void*)in, inSz);
            if (!inBB) {
                printf("failed to create eccSign in ByteBuffer\n");
                return -1;
            }

            /* create ByteBuffer to wrap keyDer */
            jobject keyDerBB = (*jenv)->NewDirectByteBuffer(jenv, (void*)keyDer,
                    keySz);
            if (!keyDerBB) {
                printf("failed to create eccSign keyDer ByteBuffer\n");
                return -1;
            }

            /* create jlongArray to hold outSz, since we need to use it as
             * an OUTPUT parameter from Java. Only needs to have 1 element */
            j_outSz = (*jenv)->NewLongArray(jenv, 1);
            if (!j_outSz) {
                printf("failed to create outSz longArray\n");
                return -1;
            }

            /* call Java ECC sign callback, java layer handles
             * adding decrypt/verify CTX reference */
            retval = (*jenv)->CallIntMethod(jenv, ctxref, eccSignMethodId,
                    myCtx->obj, inBB, (jlong)inSz, outBB, j_outSz, keyDerBB,
                    (jlong)keySz);

            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
                retval = -1;
            }

            if (retval == 0) {
                /* copy j_outSz into outSz */
                jlong tmpVal;
                (*jenv)->GetLongArrayRegion(jenv, j_outSz, 0, 1, &tmpVal);
                if ((*jenv)->ExceptionOccurred(jenv)) {
                    (*jenv)->ExceptionDescribe(jenv);
                    (*jenv)->ExceptionClear(jenv);
                    retval = -1;
                }
                *outSz = (unsigned int)tmpVal;
            }
        }

        /* detach JNIEnv from thread */
        (*g_vm)->DetachCurrentThread(g_vm);

    } else {
        /* clear any existing exception before we throw another */
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
        }

        (*jenv)->ThrowNew(jenv, excClass,
                "Object reference invalid in NativeEccSignCb");

        return -1;
    }

    return retval;
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLContext_setEccVerifyCb
  (JNIEnv* jenv, jobject jcl, jlong ctx)
{
    /* find exception class */
    jclass excClass = (*jenv)->FindClass(jenv, "java/lang/Exception");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return;
    }

    if(ctx) {
        /* set ECC verify callback */
        wolfSSL_CTX_SetEccVerifyCb((WOLFSSL_CTX*)ctx, NativeEccVerifyCb);

    } else {
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLContext object was null when setting "
                "EccVerifyCb");
    }
}

int  NativeEccVerifyCb(WOLFSSL* ssl, const unsigned char* sig,
        unsigned int sigSz, const unsigned char* hash, unsigned int hashSz,
        const unsigned char* keyDer, unsigned int keySz, int* result,
        void* ctx)
{
    JNIEnv*    jenv;
    jint       retval = 0;
    jint       vmret  = 0;
    jmethodID  eccVerifyMethodId;
    jclass     excClass;

    jobjectRefType refcheck;
    internCtx*     myCtx = ctx;
    jintArray      j_result;

    if (!g_vm) {
        printf("Global JavaVM reference is null!\n");
        return -1;
    }

    /* get JavaEnv from JavaVM */
    vmret = (int)((*g_vm)->GetEnv(g_vm, (void**) &jenv, JNI_VERSION_1_6));
    if (vmret == JNI_EDETACHED) {
#ifdef __ANDROID__
        vmret = (*g_vm)->AttachCurrentThread(g_vm, &jenv, NULL);
#else
        vmret = (*g_vm)->AttachCurrentThread(g_vm, (void**) &jenv, NULL);
#endif
        if (vmret) {
            printf("Failed to attach JNIEnv to thread\n");
        } else {
            printf("Attached JNIEnv to thread\n");
        }
    } else if (vmret != JNI_OK) {
        printf("Error getting JNIEnv from JavaVM, ret = %d\n", vmret);
    }

    /* find exception class in case we need it */
    excClass = (*jenv)->FindClass(jenv, "java/lang/Exception");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        printf("can't find Exception class, NativeEccVerifyCb\n");
        return -1;
    }

    /* check if our stored object reference is valid */
    refcheck = (*jenv)->GetObjectRefType(jenv, myCtx->obj);
    if (refcheck == 2) {

        /* lookup WolfSSLSession class from global object ref */
        jclass sessClass = (*jenv)->GetObjectClass(jenv, myCtx->obj);
        if (!sessClass) {
            (*jenv)->ThrowNew(jenv, excClass,
                "Can't get native WolfSSLSession class reference "
                "in NativeEccVerifyCb");
            return -1;
        }

        /* lookup WolfSSLContext private member fieldID */
        jfieldID ctxFid = (*jenv)->GetFieldID(jenv, sessClass, "ctx",
                "Lcom/wolfssl/WolfSSLContext;");
        if (!ctxFid) {
            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
            }

            (*jenv)->ThrowNew(jenv, excClass,
                "Can't get native WolfSSLContext field ID "
                "in NativeEccVerifyCb");
            return -1;
        }

        /* find getContextPtr() method */
        jmethodID getCtxMethodId = (*jenv)->GetMethodID(jenv, sessClass,
            "getAssociatedContextPtr",
            "()Lcom/wolfssl/WolfSSLContext;");
        if (!getCtxMethodId) {
            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
            }

            (*jenv)->ThrowNew(jenv, excClass,
                "Can't get getAssociatedContextPtr() method ID "
                "in NativeEccVerifyCb");
            return -1;
        }

        /* get WolfSSLContext ctx object from Java land */
        jobject ctxref = (*jenv)->CallObjectMethod(jenv, myCtx->obj,
                getCtxMethodId);
        if (!ctxref) {
            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
            }

            (*jenv)->ThrowNew(jenv, excClass,
                "Can't get WolfSSLContext object in NativeEccVerifyCb");
            return -1;
        }

        /* get WolfSSLContext class reference from Java land */
        jclass innerCtxClass = (*jenv)->GetObjectClass(jenv, ctxref);
        if (!innerCtxClass) {
            (*jenv)->ThrowNew(jenv, excClass,
                "Can't get native WolfSSLContext class reference "
                "in NativeEccVerifyCb");
            return -1;
        }

        /* call internal ECC verify callback */
        eccVerifyMethodId = (*jenv)->GetMethodID(jenv, innerCtxClass,
                "internalEccVerifyCallback",
                "(Lcom/wolfssl/WolfSSLSession;Ljava/nio/ByteBuffer;"
                "JLjava/nio/ByteBuffer;JLjava/nio/ByteBuffer;J[I)I");

        if (!eccVerifyMethodId) {
            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
            }

            printf("Error getting internalEccVerifyCallback method "
                    "from JNI\n");
            retval = -1;
        }

        if (retval == 0)
        {
            /* create ByteBuffer to wrap 'sig' */
            jobject sigBB = (*jenv)->NewDirectByteBuffer(jenv, (void*)sig,
                    sigSz);
            if (!sigBB) {
                printf("failed to create eccVerify out ByteBuffer\n");
                return -1;
            }

            /* create ByteBuffer to wrap 'hash' */
            jobject hashBB = (*jenv)->NewDirectByteBuffer(jenv, (void*)hash,
                    hashSz);
            if (!hashBB) {
                printf("failed to create eccVerify hash ByteBuffer\n");
                return -1;
            }

            /* create ByteBuffer to wrap 'keyDer' */
            jobject keyDerBB = (*jenv)->NewDirectByteBuffer(jenv, (void*)keyDer,
                    keySz);
            if (!keyDerBB) {
                printf("failed to create eccVerify keyDer ByteBuffer\n");
                return -1;
            }

            /* create jintArray to hold result, since we need to use it as
             * an OUTPUT parameter from Java. Only needs to have 1 element */
            j_result = (*jenv)->NewIntArray(jenv, 1);
            if (!j_result) {
                printf("failed to create result intArray\n");
                return -1;
            }

            /* call Java ECC verify callback, java layer handles
             * adding CTX reference */
            retval = (*jenv)->CallIntMethod(jenv, ctxref, eccVerifyMethodId,
                    myCtx->obj, sigBB, (jlong)sigSz, hashBB, (jlong)hashSz,
                    keyDerBB, (jlong)keySz, j_result);

            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
                printf("exception occurred in EccVerifyCb\n");
                retval = -1;
            }

            if (retval == 0) {
                /* copy j_result into result */
                jint tmpVal;
                (*jenv)->GetIntArrayRegion(jenv, j_result, 0, 1, &tmpVal);
                if ((*jenv)->ExceptionOccurred(jenv)) {
                    (*jenv)->ExceptionDescribe(jenv);
                    (*jenv)->ExceptionClear(jenv);
                    printf("failed during j_result copy, NativeEccVerifyCb\n");
                    retval = -1;
                }
                *result = tmpVal;
            }
        }

        /* detach JNIEnv from thread */
        (*g_vm)->DetachCurrentThread(g_vm);

    } else {
        /* clear any existing exception before we throw another */
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
        }

        (*jenv)->ThrowNew(jenv, excClass,
                "Object reference invalid in NativeEccVerifyCb");

        return -1;
    }

    return retval;
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLContext_setRsaSignCb
  (JNIEnv* jenv, jobject jcl, jlong ctx)
{
    /* find exception class */
    jclass excClass = (*jenv)->FindClass(jenv, "java/lang/Exception");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return;
    }

    if(ctx) {
        /* set RSA sign callback */
        wolfSSL_CTX_SetRsaSignCb((WOLFSSL_CTX*)ctx, NativeRsaSignCb);

    } else {
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLContext object was null when setting "
                "RsaSignCb");
    }
}

int  NativeRsaSignCb(WOLFSSL* ssl, const unsigned char* in, unsigned int inSz,
        unsigned char* out, unsigned int* outSz, const unsigned char* keyDer,
        unsigned int keySz, void* ctx)
{
    JNIEnv*    jenv;
    jint       retval = 0;
    jint       vmret  = 0;
    jmethodID  rsaSignMethodId;
    jclass     excClass;

    jobjectRefType refcheck;
    internCtx*     myCtx = ctx;

    jintArray j_outSz;

    if (!g_vm) {
        printf("Global JavaVM reference is null!\n");
        return -1;
    }

    /* get JavaEnv from JavaVM */
    vmret = (int)((*g_vm)->GetEnv(g_vm, (void**) &jenv, JNI_VERSION_1_6));
    if (vmret == JNI_EDETACHED) {
#ifdef __ANDROID__
        vmret = (*g_vm)->AttachCurrentThread(g_vm, &jenv, NULL);
#else
        vmret = (*g_vm)->AttachCurrentThread(g_vm, (void**) &jenv, NULL);
#endif
        if (vmret) {
            printf("Failed to attach JNIEnv to thread\n");
        } else {
            printf("Attached JNIEnv to thread\n");
        }
    } else if (vmret != JNI_OK) {
        printf("Error getting JNIEnv from JavaVM, ret = %d\n", vmret);
    }

    /* find exception class in case we need it */
    excClass = (*jenv)->FindClass(jenv, "java/lang/Exception");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return -1;
    }

    /* check if our stored object reference is valid */
    refcheck = (*jenv)->GetObjectRefType(jenv, myCtx->obj);
    if (refcheck == 2) {

        /* lookup WolfSSLSession class from global object ref */
        jclass sessClass = (*jenv)->GetObjectClass(jenv, myCtx->obj);
        if (!sessClass) {
            (*jenv)->ThrowNew(jenv, excClass,
                "Can't get native WolfSSLSession class reference "
                "in NativeRsaSignCb");
            return -1;
        }

        /* lookup WolfSSLContext private member fieldID */
        jfieldID ctxFid = (*jenv)->GetFieldID(jenv, sessClass, "ctx",
                "Lcom/wolfssl/WolfSSLContext;");
        if (!ctxFid) {
            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
            }

            (*jenv)->ThrowNew(jenv, excClass,
                "Can't get native WolfSSLContext field ID "
                "in NativeRsaSignCb");
            return -1;
        }

        /* find getContextPtr() method */
        jmethodID getCtxMethodId = (*jenv)->GetMethodID(jenv, sessClass,
            "getAssociatedContextPtr",
            "()Lcom/wolfssl/WolfSSLContext;");
        if (!getCtxMethodId) {
            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
            }

            (*jenv)->ThrowNew(jenv, excClass,
                "Can't get getAssociatedContextPtr() method ID "
                "in NativeRsaSignCb");
            return -1;
        }

        /* get WolfSSLContext ctx object from Java land */
        jobject ctxref = (*jenv)->CallObjectMethod(jenv, myCtx->obj,
                getCtxMethodId);
        if (!ctxref) {
            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
            }

            (*jenv)->ThrowNew(jenv, excClass,
                "Can't get WolfSSLContext object in NativeRsaSignCb");
            return -1;
        }

        /* get WolfSSLContext class reference from Java land */
        jclass innerCtxClass = (*jenv)->GetObjectClass(jenv, ctxref);
        if (!innerCtxClass) {
            (*jenv)->ThrowNew(jenv, excClass,
                "Can't get native WolfSSLContext class reference "
                "in NativeRsaSignCb");
            return -1;
        }

        /* call internal RSA sign callback */
        rsaSignMethodId = (*jenv)->GetMethodID(jenv, innerCtxClass,
                "internalRsaSignCallback",
                "(Lcom/wolfssl/WolfSSLSession;Ljava/nio/ByteBuffer;"
                "JLjava/nio/ByteBuffer;[ILjava/nio/ByteBuffer;J)I");

        if (!rsaSignMethodId) {
            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
            }

            printf("Error getting internalRsaSignCallback method "
                    "from JNI\n");
            retval = -1;
        }

        if (retval == 0)
        {
            /* create ByteBuffer to wrap 'in' */
            jobject inBB = (*jenv)->NewDirectByteBuffer(jenv, (void*)in,
                    inSz);
            if (!inBB) {
                printf("failed to create rsaSign in ByteBuffer\n");
                return -1;
            }

            /* create ByteBuffer to wrap 'out' */
            jobject outBB = (*jenv)->NewDirectByteBuffer(jenv, (void*)out,
                    *outSz);
            if (!outBB) {
                printf("failed to create rsaSign out ByteBuffer\n");
                return -1;
            }

            /* create ByteBuffer to wrap 'keyDer' */
            jobject keyDerBB = (*jenv)->NewDirectByteBuffer(jenv, (void*)keyDer,
                    keySz);
            if (!keyDerBB) {
                printf("failed to create rsaSign keyDer ByteBuffer\n");
                return -1;
            }

            /* create jintArray to hold outSz, since we need to use it as
             * an OUTPUT parameter from Java. Only needs to have 1 element */
            j_outSz = (*jenv)->NewIntArray(jenv, 1);
            if (!j_outSz) {
                printf("failed to create result intArray\n");
                return -1;
            }
            (*jenv)->SetIntArrayRegion(jenv, j_outSz, 0, 1, (jint*)outSz);

            /* call Java RSA sign callback, java layer handles
             * adding CTX reference */
            retval = (*jenv)->CallIntMethod(jenv, ctxref, rsaSignMethodId,
                    myCtx->obj, inBB, (jlong)inSz, outBB, j_outSz, keyDerBB,
                    (jlong)keySz);

            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
                retval = -1;
            }

            if (retval == 0) {
                /* copy j_outSz into outSz */
                jint tmpVal;
                (*jenv)->GetIntArrayRegion(jenv, j_outSz, 0, 1, &tmpVal);
                if ((*jenv)->ExceptionOccurred(jenv)) {
                    (*jenv)->ExceptionDescribe(jenv);
                    (*jenv)->ExceptionClear(jenv);
                    retval = -1;
                }
                *outSz = tmpVal;
            }
        }

        /* detach JNIEnv from thread */
        (*g_vm)->DetachCurrentThread(g_vm);

    } else {
        /* clear any existing exception before we throw another */
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
        }

        (*jenv)->ThrowNew(jenv, excClass,
                "Object reference invalid in NativeRsaSignCb");

        return -1;
    }

    return retval;
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLContext_setRsaVerifyCb
  (JNIEnv* jenv, jobject jcl, jlong ctx)
{
    /* find exception class */
    jclass excClass = (*jenv)->FindClass(jenv, "java/lang/Exception");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return;
    }

    if(ctx) {
        /* set RSA verify callback */
        wolfSSL_CTX_SetRsaVerifyCb((WOLFSSL_CTX*)ctx, NativeRsaVerifyCb);

    } else {
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLContext object was null when setting "
                "RsaVerifyCb");
    }
}

int  NativeRsaVerifyCb(WOLFSSL* ssl, unsigned char* sig, unsigned int sigSz,
        unsigned char** out, const unsigned char* keyDer, unsigned int keySz,
        void* ctx)
{
    JNIEnv*    jenv;
    jint       retval = 0;
    jint       vmret  = 0;
    jmethodID  rsaVerifyMethodId;
    jclass     excClass;

    jobjectRefType refcheck;
    internCtx*     myCtx = ctx;

    if (!g_vm) {
        printf("Global JavaVM reference is null!\n");
        return -1;
    }

    /* get JavaEnv from JavaVM */
    vmret = (int)((*g_vm)->GetEnv(g_vm, (void**) &jenv, JNI_VERSION_1_6));
    if (vmret == JNI_EDETACHED) {
#ifdef __ANDROID__
        vmret = (*g_vm)->AttachCurrentThread(g_vm, &jenv, NULL);
#else
        vmret = (*g_vm)->AttachCurrentThread(g_vm, (void**) &jenv, NULL);
#endif
        if (vmret) {
            printf("Failed to attach JNIEnv to thread\n");
        } else {
            printf("Attached JNIEnv to thread\n");
        }
    } else if (vmret != JNI_OK) {
        printf("Error getting JNIEnv from JavaVM, ret = %d\n", vmret);
    }

    /* find exception class in case we need it */
    excClass = (*jenv)->FindClass(jenv, "java/lang/Exception");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return -1;
    }

    /* check if our stored object reference is valid */
    refcheck = (*jenv)->GetObjectRefType(jenv, myCtx->obj);
    if (refcheck == 2) {

        /* lookup WolfSSLSession class from global object ref */
        jclass sessClass = (*jenv)->GetObjectClass(jenv, myCtx->obj);
        if (!sessClass) {
            (*jenv)->ThrowNew(jenv, excClass,
                "Can't get native WolfSSLSession class reference "
                "in NativeRsaVerifyCb");
            return -1;
        }

        /* lookup WolfSSLContext private member fieldID */
        jfieldID ctxFid = (*jenv)->GetFieldID(jenv, sessClass, "ctx",
                "Lcom/wolfssl/WolfSSLContext;");
        if (!ctxFid) {
            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
            }

            (*jenv)->ThrowNew(jenv, excClass,
                "Can't get native WolfSSLContext field ID "
                "in NativeRsaVerifyCb");
            return -1;
        }

        /* find getContextPtr() method */
        jmethodID getCtxMethodId = (*jenv)->GetMethodID(jenv, sessClass,
            "getAssociatedContextPtr",
            "()Lcom/wolfssl/WolfSSLContext;");
        if (!getCtxMethodId) {
            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
            }

            (*jenv)->ThrowNew(jenv, excClass,
                "Can't get getAssociatedContextPtr() method ID "
                "in NativeRsaVerifyCb");
            return -1;
        }

        /* get WolfSSLContext ctx object from Java land */
        jobject ctxref = (*jenv)->CallObjectMethod(jenv, myCtx->obj,
                getCtxMethodId);
        if (!ctxref) {
            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
            }

            (*jenv)->ThrowNew(jenv, excClass,
                "Can't get WolfSSLContext object in NativeRsaVerifyCb");
            return -1;
        }

        /* get WolfSSLContext class reference from Java land */
        jclass innerCtxClass = (*jenv)->GetObjectClass(jenv, ctxref);
        if (!innerCtxClass) {
            (*jenv)->ThrowNew(jenv, excClass,
                "Can't get native WolfSSLContext class reference "
                "in NativeRsaVerifyCb");
            return -1;
        }

        /* call internal ECC verify callback */
        rsaVerifyMethodId = (*jenv)->GetMethodID(jenv, innerCtxClass,
                "internalRsaVerifyCallback",
                "(Lcom/wolfssl/WolfSSLSession;Ljava/nio/ByteBuffer;"
                "JLjava/nio/ByteBuffer;JLjava/nio/ByteBuffer;J)I");

        if (!rsaVerifyMethodId) {
            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
            }

            printf("Error getting internalRsaVerifyCallback method "
                    "from JNI\n");
            retval = -1;
        }

        if (retval == 0)
        {
            /* create ByteBuffer to wrap 'sig' */
            jobject sigBB = (*jenv)->NewDirectByteBuffer(jenv, sig,
                    sigSz);
            if (!sigBB) {
                printf("failed to create rsaVerify sig ByteBuffer\n");
                return -1;
            }

            /* create ByteBuffer to wrap 'out', since we're actually
             * doing this inline, outBB points to the same address as
             * sigBB */
            jobject outBB = (*jenv)->NewDirectByteBuffer(jenv, sig,
                    sigSz);
            if (!outBB) {
                printf("failed to create rsaVerify out ByteBuffer\n");
                return -1;
            }

            /* create ByteBuffer to wrap 'keyDer' */
            jobject keyDerBB = (*jenv)->NewDirectByteBuffer(jenv, (void*)keyDer,
                    keySz);
            if (!keyDerBB) {
                printf("failed to create rsaVerify keyDer ByteBuffer\n");
                return -1;
            }

            /* call Java RSA verify callback, java layer handles
             * adding CTX reference */
            retval = (*jenv)->CallIntMethod(jenv, ctxref, rsaVerifyMethodId,
                    myCtx->obj, sigBB, (jlong)sigSz, outBB, (jlong)sigSz,
                    keyDerBB, (jlong)keySz);

            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
                retval = -1;
            }
        }

        /* detach JNIEnv from thread */
        (*g_vm)->DetachCurrentThread(g_vm);

    } else {
        /* clear any existing exception before we throw another */
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
        }

        (*jenv)->ThrowNew(jenv, excClass,
                "Object reference invalid in NativeRsaVerifyCb");

        return -1;
    }

    /* point out* to the beginning of our decrypted buffer */
    if (retval > 0)
        *out = sig;

    return retval;
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLContext_setRsaEncCb
  (JNIEnv* jenv, jobject jcl, jlong ctx)
{
    /* find exception class */
    jclass excClass = (*jenv)->FindClass(jenv, "java/lang/Exception");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return;
    }

    if(ctx) {
        /* set RSA encrypt callback */
        wolfSSL_CTX_SetRsaEncCb((WOLFSSL_CTX*)ctx, NativeRsaEncCb);

    } else {
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLContext object was null when setting "
                "RsaEncCb");
    }
}

int  NativeRsaEncCb(WOLFSSL* ssl, const unsigned char* in, unsigned int inSz,
        unsigned char* out, unsigned int* outSz, const unsigned char* keyDer,
        unsigned int keySz, void* ctx)
{
    JNIEnv*    jenv;
    jint       retval = 0;
    jint       vmret  = 0;
    jmethodID  rsaEncMethodId;
    jclass     excClass;

    jobjectRefType refcheck;
    internCtx*     myCtx = ctx;

    jintArray j_outSz;

    if (!g_vm) {
        printf("Global JavaVM reference is null!\n");
        return -1;
    }

    /* get JavaEnv from JavaVM */
    vmret = (int)((*g_vm)->GetEnv(g_vm, (void**) &jenv, JNI_VERSION_1_6));
    if (vmret == JNI_EDETACHED) {
#ifdef __ANDROID__
        vmret = (*g_vm)->AttachCurrentThread(g_vm, &jenv, NULL);
#else
        vmret = (*g_vm)->AttachCurrentThread(g_vm, (void**) &jenv, NULL);
#endif
        if (vmret) {
            printf("Failed to attach JNIEnv to thread\n");
        } else {
            printf("Attached JNIEnv to thread\n");
        }
    } else if (vmret != JNI_OK) {
        printf("Error getting JNIEnv from JavaVM, ret = %d\n", vmret);
    }

    /* find exception class in case we need it */
    excClass = (*jenv)->FindClass(jenv, "java/lang/Exception");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return -1;
    }

    /* check if our stored object reference is valid */
    refcheck = (*jenv)->GetObjectRefType(jenv, myCtx->obj);
    if (refcheck == 2) {

        /* lookup WolfSSLSession class from global object ref */
        jclass sessClass = (*jenv)->GetObjectClass(jenv, myCtx->obj);
        if (!sessClass) {
            (*jenv)->ThrowNew(jenv, excClass,
                "Can't get native WolfSSLSession class reference "
                "in NativeRsaEncCb");
            return -1;
        }

        /* lookup WolfSSLContext private member fieldID */
        jfieldID ctxFid = (*jenv)->GetFieldID(jenv, sessClass, "ctx",
                "Lcom/wolfssl/WolfSSLContext;");
        if (!ctxFid) {
            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
            }

            (*jenv)->ThrowNew(jenv, excClass,
                "Can't get native WolfSSLContext field ID "
                "in NativeRsaEncCb");
            return -1;
        }

        /* find getContextPtr() method */
        jmethodID getCtxMethodId = (*jenv)->GetMethodID(jenv, sessClass,
            "getAssociatedContextPtr",
            "()Lcom/wolfssl/WolfSSLContext;");
        if (!getCtxMethodId) {
            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
            }

            (*jenv)->ThrowNew(jenv, excClass,
                "Can't get getAssociatedContextPtr() method ID "
                "in NativeRsaEncCb");
            return -1;
        }

        /* get WolfSSLContext ctx object from Java land */
        jobject ctxref = (*jenv)->CallObjectMethod(jenv, myCtx->obj,
                getCtxMethodId);
        if (!ctxref) {
            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
            }

            (*jenv)->ThrowNew(jenv, excClass,
                "Can't get WolfSSLContext object in NativeRsaEncCb");
            return -1;
        }

        /* get WolfSSLContext class reference from Java land */
        jclass innerCtxClass = (*jenv)->GetObjectClass(jenv, ctxref);
        if (!innerCtxClass) {
            (*jenv)->ThrowNew(jenv, excClass,
                "Can't get native WolfSSLContext class reference "
                "in NativeRsaEncCb");
            return -1;
        }

        /* call internal RSA enc callback */
        rsaEncMethodId = (*jenv)->GetMethodID(jenv, innerCtxClass,
                "internalRsaEncCallback",
                "(Lcom/wolfssl/WolfSSLSession;Ljava/nio/ByteBuffer;"
                "JLjava/nio/ByteBuffer;[ILjava/nio/ByteBuffer;J)I");

        if (!rsaEncMethodId) {
            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
            }

            printf("Error getting internalRsaEncCallback method "
                    "from JNI\n");
            retval = -1;
        }

        if (retval == 0)
        {
            /* create ByteBuffer to wrap 'in' */
            jobject inBB = (*jenv)->NewDirectByteBuffer(jenv, (void*)in,
                    inSz);
            if (!inBB) {
                printf("failed to create rsaEnc in ByteBuffer\n");
                return -1;
            }

            /* create ByteBuffer to wrap 'out' */
            jobject outBB = (*jenv)->NewDirectByteBuffer(jenv, (void*)out,
                    *outSz);
            if (!outBB) {
                printf("failed to create rsaEnc out ByteBuffer\n");
                return -1;
            }

            /* create ByteBuffer to wrap 'keyDer' */
            jobject keyDerBB = (*jenv)->NewDirectByteBuffer(jenv, (void*)keyDer,
                    keySz);
            if (!keyDerBB) {
                printf("failed to create rsaEnc keyDer ByteBuffer\n");
                return -1;
            }

            /* create jintArray to hold outSz, since we need to use it as
             * an OUTPUT parameter from Java. Only needs to have 1 element */
            j_outSz = (*jenv)->NewIntArray(jenv, 1);
            if (!j_outSz) {
                printf("failed to create result intArray\n");
                return -1;
            }
            (*jenv)->SetIntArrayRegion(jenv, j_outSz, 0, 1, (jint*)outSz);

            /* call Java RSA enc callback, java layer handles
             * adding CTX reference */
            retval = (*jenv)->CallIntMethod(jenv, ctxref, rsaEncMethodId,
                    myCtx->obj, inBB, (jlong)inSz, outBB, j_outSz, keyDerBB,
                    (jlong)keySz);

            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
                retval = -1;
            }

            if (retval == 0) {
                /* copy j_outSz into outSz */
                jint tmpVal;
                (*jenv)->GetIntArrayRegion(jenv, j_outSz, 0, 1, &tmpVal);
                if ((*jenv)->ExceptionOccurred(jenv)) {
                    (*jenv)->ExceptionDescribe(jenv);
                    (*jenv)->ExceptionClear(jenv);
                    retval = -1;
                }
                *outSz = tmpVal;
            }
        }

        /* detach JNIEnv from thread */
        (*g_vm)->DetachCurrentThread(g_vm);

    } else {
        /* clear any existing exception before we throw another */
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
        }

        (*jenv)->ThrowNew(jenv, excClass,
                "Object reference invalid in NativeRsaEncCb");

        return -1;
    }

    return retval;
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLContext_setRsaDecCb
  (JNIEnv* jenv, jobject jcl, jlong ctx)
{
    /* find exception class */
    jclass excClass = (*jenv)->FindClass(jenv, "java/lang/Exception");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return;
    }

    if(ctx) {
        /* set RSA encrypt callback */
        wolfSSL_CTX_SetRsaDecCb((WOLFSSL_CTX*)ctx, NativeRsaDecCb);

    } else {
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLContext object was null when setting "
                "RsaDecCb");
    }
}

int  NativeRsaDecCb(WOLFSSL* ssl, unsigned char* in, unsigned int inSz,
        unsigned char** out, const unsigned char* keyDer, unsigned int keySz,
        void* ctx)
{
    JNIEnv*    jenv;
    jint       retval = 0;
    jint       vmret  = 0;
    jmethodID  rsaDecMethodId;
    jclass     excClass;

    jobjectRefType refcheck;
    internCtx*     myCtx = ctx;

    if (!g_vm) {
        printf("Global JavaVM reference is null!\n");
        return -1;
    }

    /* get JavaEnv from JavaVM */
    vmret = (int)((*g_vm)->GetEnv(g_vm, (void**) &jenv, JNI_VERSION_1_6));
    if (vmret == JNI_EDETACHED) {
#ifdef __ANDROID__
        vmret = (*g_vm)->AttachCurrentThread(g_vm, &jenv, NULL);
#else
        vmret = (*g_vm)->AttachCurrentThread(g_vm, (void**) &jenv, NULL);
#endif
        if (vmret) {
            printf("Failed to attach JNIEnv to thread\n");
        } else {
            printf("Attached JNIEnv to thread\n");
        }
    } else if (vmret != JNI_OK) {
        printf("Error getting JNIEnv from JavaVM, ret = %d\n", vmret);
    }

    /* find exception class in case we need it */
    excClass = (*jenv)->FindClass(jenv, "java/lang/Exception");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return -1;
    }

    /* check if our stored object reference is valid */
    refcheck = (*jenv)->GetObjectRefType(jenv, myCtx->obj);
    if (refcheck == 2) {

        /* lookup WolfSSLSession class from global object ref */
        jclass sessClass = (*jenv)->GetObjectClass(jenv, myCtx->obj);
        if (!sessClass) {
            (*jenv)->ThrowNew(jenv, excClass,
                "Can't get native WolfSSLSession class reference "
                "in NativeRsaDecCb");
            return -1;
        }

        /* lookup WolfSSLContext private member fieldID */
        jfieldID ctxFid = (*jenv)->GetFieldID(jenv, sessClass, "ctx",
                "Lcom/wolfssl/WolfSSLContext;");
        if (!ctxFid) {
            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
            }

            (*jenv)->ThrowNew(jenv, excClass,
                "Can't get native WolfSSLContext field ID "
                "in NativeRsaDecCb");
            return -1;
        }

        /* find getContextPtr() method */
        jmethodID getCtxMethodId = (*jenv)->GetMethodID(jenv, sessClass,
            "getAssociatedContextPtr",
            "()Lcom/wolfssl/WolfSSLContext;");
        if (!getCtxMethodId) {
            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
            }

            (*jenv)->ThrowNew(jenv, excClass,
                "Can't get getAssociatedContextPtr() method ID "
                "in NativeRsaDecCb");
            return -1;
        }

        /* get WolfSSLContext ctx object from Java land */
        jobject ctxref = (*jenv)->CallObjectMethod(jenv, myCtx->obj,
                getCtxMethodId);
        if (!ctxref) {
            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
            }

            (*jenv)->ThrowNew(jenv, excClass,
                "Can't get WolfSSLContext object in NativeRsaDecCb");
            return -1;
        }

        /* get WolfSSLContext class reference from Java land */
        jclass innerCtxClass = (*jenv)->GetObjectClass(jenv, ctxref);
        if (!innerCtxClass) {
            (*jenv)->ThrowNew(jenv, excClass,
                "Can't get native WolfSSLContext class reference "
                "in NativeRsaDecCb");
            return -1;
        }

        /* call internal ECC verify callback */
        rsaDecMethodId = (*jenv)->GetMethodID(jenv, innerCtxClass,
                "internalRsaDecCallback",
                "(Lcom/wolfssl/WolfSSLSession;Ljava/nio/ByteBuffer;"
                "JLjava/nio/ByteBuffer;JLjava/nio/ByteBuffer;J)I");

        if (!rsaDecMethodId) {
            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
            }

            printf("Error getting internalRsaDecCallback method "
                    "from JNI\n");
            retval = -1;
        }

        if (retval == 0)
        {
            /* create ByteBuffer to wrap 'in' */
            jobject inBB = (*jenv)->NewDirectByteBuffer(jenv, in,
                    inSz);
            if (!inBB) {
                printf("failed to create rsaDec in ByteBuffer\n");
                return -1;
            }

            /* create ByteBuffer to wrap 'out', since we're actually
             * doing this inline, outBB points to the same address as
             * inBB */
            jobject outBB = (*jenv)->NewDirectByteBuffer(jenv, in,
                    inSz);
            if (!outBB) {
                printf("failed to create rsaDec out ByteBuffer\n");
                return -1;
            }

            /* create ByteBuffer to wrap 'keyDer' */
            jobject keyDerBB = (*jenv)->NewDirectByteBuffer(jenv, (void*)keyDer,
                    keySz);
            if (!keyDerBB) {
                printf("failed to create rsaDec keyDer ByteBuffer\n");
                return -1;
            }

            /* call Java RSA decrypt callback, java layer handles
             * adding CTX reference */
            retval = (*jenv)->CallIntMethod(jenv, ctxref, rsaDecMethodId,
                    myCtx->obj, inBB, (jlong)inSz, outBB, (jlong)inSz,
                    keyDerBB, (jlong)keySz);

            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
                retval = -1;
            }
        }

        /* detach JNIEnv from thread */
        (*g_vm)->DetachCurrentThread(g_vm);

    } else {
        /* clear any existing exception before we throw another */
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
        }

        (*jenv)->ThrowNew(jenv, excClass,
                "Object reference invalid in NativeRsaDecCb");

        return -1;
    }

    /* point out* to the beginning of our decrypted buffer */
    if (retval > 0)
        *out = in;

    return retval;
}

