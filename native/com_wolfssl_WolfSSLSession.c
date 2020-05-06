/* com_wolfssl_WolfSSLSession.c
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
#include <arpa/inet.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>

#include "com_wolfssl_globals.h"
#include "com_wolfssl_WolfSSL.h"

/* custom I/O native fn prototypes */
int  NativeSSLIORecvCb(WOLFSSL *ssl, char *buf, int sz, void *ctx);
int  NativeSSLIOSendCb(WOLFSSL *ssl, char *buf, int sz, void *ctx);
static jobject g_verifySSLCbIfaceObj;
#ifdef HAVE_CRL
/* global object refs for CRL callback */
static jobject g_crlCbIfaceObj;
#endif

/* custom native fn prototypes */
void NativeMissingCRLCallback(const char* url);
int  NativeSSLVerifyCallback(int preverify_ok, WOLFSSL_X509_STORE_CTX* store);

int NativeSSLVerifyCallback(int preverify_ok, WOLFSSL_X509_STORE_CTX* store)
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
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    if( (*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return -103;
    }

    /* check if our stored object reference is valid */
    refcheck = (*jenv)->GetObjectRefType(jenv, g_verifySSLCbIfaceObj);
    if (refcheck == 2) {

        /* lookup WolfSSLVerifyCallback class from global object ref */
        jclass verifyClass = (*jenv)->GetObjectClass(jenv, g_verifySSLCbIfaceObj);
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

        retval = (*jenv)->CallIntMethod(jenv, g_verifySSLCbIfaceObj,
                verifyMethod, preverify_ok, (jlong)(uintptr_t)store);

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
                "Object reference invalid in NativeSSLVerifyCallback");
        return -1;
    }

    return retval;
}


/* jni functions */

JNIEXPORT jlong JNICALL Java_com_wolfssl_WolfSSLSession_newSSL
  (JNIEnv* jenv, jobject jcl, jlong ctx)
{
    int ret;
    jlong sslPtr;
    jobject* g_cachedObj;

    if (!jenv)
        return SSL_FAILURE;

    /* wolfSSL java caller checks for null pointer */
    sslPtr = (jlong)(uintptr_t)wolfSSL_new((WOLFSSL_CTX*)(uintptr_t)ctx);

    if (sslPtr != 0) {
        /* create global reference to WolfSSLSession jobject */
        g_cachedObj = (jobject*)XMALLOC(sizeof(jobject), NULL,
                                        DYNAMIC_TYPE_TMP_BUFFER);
        if (!g_cachedObj) {
            printf("error mallocing memory in newSSL\n");
            wolfSSL_free((WOLFSSL*)(uintptr_t)sslPtr);
            return SSL_FAILURE;
        }
        *g_cachedObj = (*jenv)->NewGlobalRef(jenv, jcl);
        if (!*g_cachedObj) {
            printf("error storing global WolfSSLSession object\n");
            wolfSSL_free((WOLFSSL*)(uintptr_t)sslPtr);
            return SSL_FAILURE;
        }
        /* cache associated WolfSSLSession jobject in native WOLFSSL */
        ret = wolfSSL_set_jobject((WOLFSSL*)(uintptr_t)sslPtr, g_cachedObj);
        if (ret != SSL_SUCCESS) {
            printf("error storing jobject in wolfSSL native session\n");
            wolfSSL_free((WOLFSSL*)(uintptr_t)sslPtr);
            return SSL_FAILURE;
        }
    }

    return sslPtr;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_setFd(JNIEnv* jenv,
    jobject jcl, jlong ssl, jobject jsock, jint type)
{
    int fd;
    jclass jcls;
    jfieldID fid;
    jobject impl;
    jobject fdesc;

    (void)jcl;

    if (!jenv || !ssl || !jsock)
        return SSL_FAILURE;

    /* get SocketImpl or DatagramSocketImpl from Java Socket */
    jcls = (*jenv)->GetObjectClass(jenv, jsock);
    if (type == 1) {
        fid = (*jenv)->GetFieldID(jenv, jcls, "impl", "Ljava/net/SocketImpl;");
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return SSL_FAILURE;
        }
        impl = (*jenv)->GetObjectField(jenv, jsock, fid);

    } else if (type == 2) {
        fid = (*jenv)->GetFieldID(jenv, jcls, "impl",
                "Ljava/net/DatagramSocketImpl;");
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return SSL_FAILURE;
        }
        impl = (*jenv)->GetObjectField(jenv, jsock, fid);
    } else {
        return SSL_FAILURE; /* invalid class type */
    }

    if (!jcls || !fid || !impl)
        return SSL_FAILURE;

    /* get FileDescriptor from SocketImpl */
    jcls = (*jenv)->GetObjectClass(jenv, impl);
    fid = (*jenv)->GetFieldID(jenv, jcls, "fd", "Ljava/io/FileDescriptor;");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return SSL_FAILURE;
    }
    fdesc = (*jenv)->GetObjectField(jenv, impl, fid);

    if (!jcls || !fid || !fdesc)
        return SSL_FAILURE;

    /* get fd from FileDescriptor */
    jcls = (*jenv)->GetObjectClass(jenv, fdesc);
#ifdef __ANDROID__
    fid = (*jenv)->GetFieldID(jenv, jcls, "descriptor", "I");
#else
    fid = (*jenv)->GetFieldID(jenv, jcls, "fd", "I");
#endif
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return SSL_FAILURE;
    }

    if (!jcls || !fid )
        return SSL_FAILURE;

    fd = (*jenv)->GetIntField(jenv, fdesc, fid);

    return (jint)wolfSSL_set_fd((WOLFSSL*)(uintptr_t)ssl, fd);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_useCertificateFile
  (JNIEnv* jenv, jobject jcl, jlong ssl, jstring file, jint format)
{
#ifdef OPENSSL_EXTRA
    jint ret = 0;
    const char* certFile;

    (void)jcl;

    if (!jenv || !ssl)
        return SSL_FAILURE;

    if (file == NULL)
        return SSL_BAD_FILE;

    certFile = (*jenv)->GetStringUTFChars(jenv, file, 0);

    ret = (jint) wolfSSL_use_certificate_file((WOLFSSL*)(uintptr_t)ssl, certFile,
            (int)format);

    (*jenv)->ReleaseStringUTFChars(jenv, file, certFile);

    return ret;
#else
    (void)jenv;
    (void)jcl;
    (void)ssl;
    (void)file;
    (void)format;
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_usePrivateKeyFile
  (JNIEnv* jenv, jobject jcl, jlong ssl, jstring file, jint format)
{
#ifdef OPENSSL_EXTRA
    jint ret = 0;
    const char* keyFile;

    (void)jcl;

    if (!jenv || !ssl)
        return SSL_FAILURE;

    if (file == NULL)
        return SSL_BAD_FILE;

    keyFile = (*jenv)->GetStringUTFChars(jenv, file, 0);

    ret = (jint) wolfSSL_use_PrivateKey_file((WOLFSSL*)(uintptr_t)ssl, keyFile,
            (int)format);

    (*jenv)->ReleaseStringUTFChars(jenv, file, keyFile);

    return ret;
#else
    (void)jenv;
    (void)jcl;
    (void)ssl;
    (void)file;
    (void)format;
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_useCertificateChainFile
  (JNIEnv* jenv, jobject jcl, jlong ssl, jstring file)
{
#ifdef OPENSSL_EXTRA
    jint ret = 0;
    const char* chainFile;

    (void)jcl;

    if (!jenv || !ssl)
        return SSL_FAILURE;

    if (file == NULL)
        return SSL_BAD_FILE;

    chainFile = (*jenv)->GetStringUTFChars(jenv, file, 0);

    ret = (jint) wolfSSL_use_certificate_chain_file((WOLFSSL*)(uintptr_t)ssl,
                                                    chainFile);

    (*jenv)->ReleaseStringUTFChars(jenv, file, chainFile);

    return ret;
#else
    (void)jenv;
    (void)jcl;
    (void)ssl;
    (void)file;
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setUsingNonblock
  (JNIEnv* jenv, jobject jcl, jlong ssl, jint nonblock)
{
    jclass excClass;

    (void)jcl;

    if (!jenv)
        return;

    if (!ssl) {
        excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return;
        }
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLSession object was null in setUsingNonblock");
    }

    wolfSSL_set_using_nonblock((WOLFSSL*)(uintptr_t)ssl, nonblock);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_getUsingNonblock
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    jclass excClass;

    (void)jcl;

    if (!jenv)
        return 0;

    if (!ssl) {
        excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return 0;
        }
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLSession object was null in getUsingNonblock");
    }

    return wolfSSL_get_using_nonblock((WOLFSSL*)(uintptr_t)ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_getFd
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    jclass excClass;

    (void)jcl;

    if (!jenv)
        return 0;

    if (!ssl) {
        excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return 0;
        }
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLSession object was null in getFd");
        return 0;
    }

    return wolfSSL_get_fd((WOLFSSL*)(uintptr_t)ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_connect
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    int ret = 0;

    (void)jcl;

    if (!jenv || !ssl)
        return SSL_FATAL_ERROR;

    /* make sure we don't have any outstanding exceptions pending */
    if ((*jenv)->ExceptionCheck(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return SSL_FAILURE;
    }

    ret = wolfSSL_connect((WOLFSSL*)(uintptr_t)ssl);
    if ((*jenv)->ExceptionCheck(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return SSL_FAILURE;
    }

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_write(JNIEnv* jenv,
    jobject jcl, jlong ssl, jbyteArray raw, jint length)
{
    byte* data;
    int ret = SSL_FAILURE;

    (void)jcl;

    if (!jenv || !ssl || !raw)
        return BAD_FUNC_ARG;

    if (length >= 0) {
        data = (byte*)(*jenv)->GetByteArrayElements(jenv, raw, NULL);
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return SSL_FAILURE;
        }
        ret = wolfSSL_write((WOLFSSL*)(uintptr_t)ssl, data, length);

        (*jenv)->ReleaseByteArrayElements(jenv, raw, (jbyte*)data, JNI_ABORT);

        return ret;

    } else {
        return SSL_FAILURE;
    }
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_read(JNIEnv* jenv,
    jobject jcl, jlong ssl, jbyteArray raw, jint length)
{
    byte* data;
    int size = 0;

    (void)jcl;

    if (!jenv || !ssl || !raw)
        return BAD_FUNC_ARG;

    if (length >= 0) {
        data = (byte*)(*jenv)->GetByteArrayElements(jenv, raw, NULL);
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return SSL_FAILURE;
        }

        size = wolfSSL_read((WOLFSSL*)(uintptr_t)ssl, data, length);

        (*jenv)->ReleaseByteArrayElements(jenv, raw, (jbyte*)data, JNI_COMMIT);
    }

    return size;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_accept
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    (void)jcl;

    if (!jenv || !ssl)
        return SSL_FATAL_ERROR;

    return wolfSSL_accept((WOLFSSL*)(uintptr_t)ssl);
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_freeSSL
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    jobject* g_cachedSSLObj;
    jclass excClass;

    (void)jcl;

    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");

    if (!ssl) {
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return;
        }
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLSession object was null in freeSSL");
        return;
    }

    /* delete global WolfSSLSession object reference */
    g_cachedSSLObj = (jobject*) wolfSSL_get_jobject((WOLFSSL*)(uintptr_t)ssl);
    if (g_cachedSSLObj != NULL) {
        (*jenv)->DeleteGlobalRef(jenv, (jobject)(*g_cachedSSLObj));
        XFREE(g_cachedSSLObj, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

    /* reset internal pointer to NULL to prevent accidental usage */
    if (wolfSSL_set_jobject((WOLFSSL*)(uintptr_t)ssl, NULL) != SSL_SUCCESS) {
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return;
        }
        (*jenv)->ThrowNew(jenv, excClass,
                "Error reseting internal wolfSSL JNI pointer to NULL, freeSSL");
        return;
    }

    /* native cleanup */
    wolfSSL_free((WOLFSSL*)(uintptr_t)ssl);
    ssl = 0;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_shutdownSSL
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    (void)jcl;

    if (!jenv)
        return SSL_FAILURE;

    /* wolfSSL checks ssl for NULL */
    return wolfSSL_shutdown((WOLFSSL*)(uintptr_t)ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_getError
  (JNIEnv* jenv, jobject jcl, jlong ssl, jint ret)
{
    (void)jcl;

    if (!jenv)
        return SSL_FAILURE;

    /* wolfSSL checks ssl for NULL */
    return wolfSSL_get_error((WOLFSSL*)(uintptr_t)ssl, ret);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_setSession
  (JNIEnv* jenv, jobject jcl, jlong ssl, jlong session)
{
    (void)jcl;

    if (!jenv || !ssl)
        return SSL_FAILURE;

    /* wolfSSL checks session for NULL, but not ssl */
    return wolfSSL_set_session((WOLFSSL*)(uintptr_t)ssl,
                               (WOLFSSL_SESSION*)(uintptr_t)session);
}

JNIEXPORT jlong JNICALL Java_com_wolfssl_WolfSSLSession_getSession
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    (void)jenv;
    (void)jcl;

    /* wolfSSL checks ssl for NULL */
    return (jlong)(uintptr_t)wolfSSL_get_session((WOLFSSL*)(uintptr_t)ssl);
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_WolfSSLSession_getSessionID
  (JNIEnv* jenv, jobject jcl, jlong session)
{
    unsigned int sz;
    const unsigned char* id;
    jbyteArray ret;

    id = wolfSSL_SESSION_get_id((WOLFSSL_SESSION*)(uintptr_t)session, &sz);
    if (id == NULL) {
        return NULL;
    }

    ret = (*jenv)->NewByteArray(jenv, sz);
    if (!ret) {
        (*jenv)->ThrowNew(jenv, jcl,
            "Failed to create byte array in native getSessionID");
        return NULL;
    }

    (*jenv)->SetByteArrayRegion(jenv, ret, 0, sz, (jbyte*)id);
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return NULL;
    }

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_setTimeout
  (JNIEnv* jenv, jobject jcl, jlong ssl, jlong t)
{
    (void)jenv;
    (void)jcl;

    return wolfSSL_set_timeout((WOLFSSL*)(uintptr_t)ssl, (unsigned int)t);
}

JNIEXPORT jlong JNICALL Java_com_wolfssl_WolfSSLSession_getTimeout
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    (void)jenv;
    (void)jcl;

    return wolfSSL_get_timeout((WOLFSSL*)(uintptr_t)ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_setSessTimeout
  (JNIEnv* jenv, jobject jcl, jlong session, jlong sz)
{
    (void)jenv;
    (void)jcl;

    return wolfSSL_SSL_SESSION_set_timeout((WOLFSSL_SESSION*)(uintptr_t)session,
                                           sz);
}

JNIEXPORT jlong JNICALL Java_com_wolfssl_WolfSSLSession_getSessTimeout
  (JNIEnv* jenv, jobject jcl, jlong session)
{
    (void)jenv;
    (void)jcl;

    return wolfSSL_SESSION_get_timeout((WOLFSSL_SESSION*)(uintptr_t)session);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_setCipherList
  (JNIEnv* jenv, jobject jcl, jlong ssl, jstring list)
{

    jint ret = 0;
    const char* cipherList;

    (void)jcl;

    if (!jenv || !ssl || !list)
        return SSL_FAILURE;

    cipherList= (*jenv)->GetStringUTFChars(jenv, list, 0);

    ret = (jint) wolfSSL_set_cipher_list((WOLFSSL*)(uintptr_t)ssl, cipherList);

    (*jenv)->ReleaseStringUTFChars(jenv, list, cipherList);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_dtlsGetCurrentTimeout
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
#if !defined(WOLFSSL_LEANPSK) && defined(WOLFSSL_DTLS)
    jclass excClass;

    (void)jcl;

    if (!ssl) {
        excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return 0;
        }
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLSession object was null in "
                "dtlsGetCurrentTimeout()");
        return 0;
    }

    return wolfSSL_dtls_get_current_timeout((WOLFSSL*)(uintptr_t)ssl);
#else
    (void)jenv;
    (void)jcl;
    (void)ssl;
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_dtlsGotTimeout
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
#if !defined(WOLFSSL_LEANPSK) && defined(WOLFSSL_DTLS)
    jclass excClass;

    (void)jcl;

    if (!ssl) {
        excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return SSL_FATAL_ERROR;
        }
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLSession object was null in "
                "dtlsGotTimeout()");
        return SSL_FATAL_ERROR;
    }

    return wolfSSL_dtls_got_timeout((WOLFSSL*)(uintptr_t)ssl);
#else
    (void)jenv;
    (void)jcl;
    (void)ssl;
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_dtls
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    jclass excClass;

    (void)jcl;

    if (!ssl) {
        excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return 0;
        }
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLSession object was null in dtls()");
        return 0;
    }

    return wolfSSL_dtls((WOLFSSL*)(uintptr_t)ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_dtlsSetPeer
  (JNIEnv* jenv, jobject jcl, jlong ssl, jobject peer)
{
    int ret;
    jstring ipAddr = NULL;
    struct sockaddr_in sa;
    const char* ipAddress = NULL;

    (void)jcl;

    if (!jenv || !ssl || !peer)
        return SSL_FAILURE;

    /* get class references */
    jclass excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    jclass inetsockaddr = (*jenv)->FindClass(jenv,
            "java/net/InetSocketAddress");
    jclass inetaddr = (*jenv)->FindClass(jenv, "java/net/InetAddress");

    /* get port */
    jmethodID portID = (*jenv)->GetMethodID(jenv, inetsockaddr,
            "getPort", "()I");
    if (!portID) {
        if ((*jenv)->ExceptionOccurred(jenv))
            (*jenv)->ExceptionClear(jenv);

        (*jenv)->ThrowNew(jenv, excClass, "Can't get getPort() method ID");
        return SSL_FAILURE;
    }
    (*jenv)->ExceptionClear(jenv);
    jint port = (*jenv)->CallIntMethod(jenv, peer, portID);
    if ((*jenv)->ExceptionOccurred(jenv)) {
        /* an exception occurred on the Java side, how to handle it? */
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
    }

    /* get InetAddress object */
    jmethodID addrID = (*jenv)->GetMethodID(jenv, inetsockaddr, "getAddress",
            "()Ljava/net/InetAddress;");
    if (!addrID) {
        if ((*jenv)->ExceptionOccurred(jenv))
            (*jenv)->ExceptionClear(jenv);

        (*jenv)->ThrowNew(jenv, excClass, "Can't get getAddress() method ID");
        return SSL_FAILURE;
    }
    (*jenv)->ExceptionClear(jenv);
    jobject addrObj = (*jenv)->CallObjectMethod(jenv, peer, addrID);
    if ((*jenv)->ExceptionOccurred(jenv)) {
        /* an exception occurred on the Java side, how to handle it? */
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
    }

    /* is this a wildcard address, ie: INADDR_ANY? */
    jmethodID isAnyID = (*jenv)->GetMethodID(jenv, inetaddr,
            "isAnyLocalAddress", "()Z");
    if (!isAnyID) {
        if ((*jenv)->ExceptionOccurred(jenv))
            (*jenv)->ExceptionClear(jenv);

        (*jenv)->ThrowNew(jenv, excClass,
                "Can't get isAnyLocalAddress() method ID");
        return SSL_FAILURE;
    }
    (*jenv)->ExceptionClear(jenv);
    jboolean isAny = (*jenv)->CallBooleanMethod(jenv, addrObj, isAnyID);
    if ((*jenv)->ExceptionOccurred(jenv)) {
        /* an exception occurred on the Java side, how to handle it? */
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
    }

    /* get IP address as a String */
    if (!isAny) {
        jmethodID ipAddrID = (*jenv)->GetMethodID(jenv, inetaddr,
                "getHostAddress", "()Ljava/lang/String;");
        if (!ipAddrID) {
            if ((*jenv)->ExceptionOccurred(jenv))
                (*jenv)->ExceptionClear(jenv);

            (*jenv)->ThrowNew(jenv, excClass,
                    "Can't get getHostAddress() method ID");
            return SSL_FAILURE;
        }
        ipAddr = (*jenv)->CallObjectMethod(jenv, addrObj, ipAddrID);
        if ((*jenv)->ExceptionOccurred(jenv)) {
            /* an exception occurred on the Java side, how to handle it? */
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
        }

        /* convert IP string to char* */
        ipAddress = (*jenv)->GetStringUTFChars(jenv, ipAddr, 0);
    }

    /* build sockaddr_in */
    memset(&sa, 0, sizeof(struct sockaddr_in));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    if (isAny) {
        //sa.sin_addr.s_addr = htonl(INADDR_ANY);
        sa.sin_addr.s_addr = INADDR_ANY;
    } else {
        sa.sin_addr.s_addr = inet_addr(ipAddress);
    }

    /* call native wolfSSL function */
    ret = wolfSSL_dtls_set_peer((WOLFSSL*)(uintptr_t)ssl, &sa, sizeof(sa));

    if (!isAny) {
        (*jenv)->ReleaseStringUTFChars(jenv, ipAddr, ipAddress);
    }

    return ret;
}

JNIEXPORT jobject JNICALL Java_com_wolfssl_WolfSSLSession_dtlsGetPeer
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    int ret, port;
    unsigned int peerSz;
    struct sockaddr_in peer;
    char* ipAddrString;

    jmethodID constr;
    jstring ipAddr;

    (void)jcl;

    if (!jenv || !ssl)
        return NULL;

    /* get native sockaddr_in peer */
    memset(&peer, 0, sizeof(peer));
    peerSz = sizeof(peer);
    ret = wolfSSL_dtls_get_peer((WOLFSSL*)(uintptr_t)ssl, &peer, &peerSz);
    if (ret != SSL_SUCCESS) {
        return NULL;
    }
    ipAddrString = inet_ntoa(peer.sin_addr);
    port = ntohs(peer.sin_port);

    /* create new InetSocketAddress with this IP/port info */
    jclass excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    jclass isa = (*jenv)->FindClass(jenv, "java/net/InetSocketAddress");
    if (!isa) {
        if ((*jenv)->ExceptionOccurred(jenv))
            (*jenv)->ExceptionClear(jenv);

        (*jenv)->ThrowNew(jenv, excClass, "Can't find InetSocketAddress class");
        return NULL;
    }

    /* create jstring from char* */
    ipAddr = (*jenv)->NewStringUTF(jenv, ipAddrString);

    /* find correct InetSocketAddress constructor */
    if (peer.sin_addr.s_addr != INADDR_ANY) {

        constr = (*jenv)->GetMethodID(jenv, isa, "<init>",
                "(Ljava/lang/String;I)V");
        if (!constr) {
            if ((*jenv)->ExceptionOccurred(jenv))
                (*jenv)->ExceptionClear(jenv);

            (*jenv)->ThrowNew(jenv, excClass,
                    "Can't find InetSocketAddress(String,port)");
            return NULL;
        }

        return (*jenv)->NewObject(jenv, isa, constr, ipAddr, port);

    } else { /* sockaddr_in was created with INADDR_ANY, use wildcard IP */

        constr = (*jenv)->GetMethodID(jenv, isa, "<init>",
                "(I)V");
        if (!constr) {
            if ((*jenv)->ExceptionOccurred(jenv))
                (*jenv)->ExceptionClear(jenv);

            (*jenv)->ThrowNew(jenv, excClass,
                    "Can't find InetSocketAddress(port)");
            return NULL;
        }

        return (*jenv)->NewObject(jenv, isa, constr, port);
    }
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_sessionReused
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    jclass excClass;

    (void)jcl;

    if (!ssl) {
        excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return SSL_FAILURE;
        }
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLSession object was null in sessionReused()");
        return SSL_FAILURE;
    }

    return wolfSSL_session_reused((WOLFSSL*)(uintptr_t)ssl);
}

JNIEXPORT jlong JNICALL Java_com_wolfssl_WolfSSLSession_getPeerCertificate
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
#ifdef KEEP_PEER_CERT
    WOLFSSL_X509* x509 = NULL;
    (void)jenv;
    (void)jcl;

    if (ssl == 0) {
        return (jlong)0;
    }

    x509 = wolfSSL_get_peer_certificate((WOLFSSL*)(uintptr_t)ssl);

    return (jlong)(uintptr_t)x509;
#else
    (void)jenv;
    (void)jcl;
    (void)ssl;
    return (jlong)0;
#endif
}

JNIEXPORT jstring JNICALL Java_com_wolfssl_WolfSSLSession_getPeerX509Issuer
  (JNIEnv* jenv, jobject jcl, jlong ssl, jlong x509)
{

#if defined(KEEP_PEER_CERT) || defined(SESSION_CERTS)
    jclass excClass;
    char* issuer;
    jstring retString;

    (void)jcl;

    if (!x509)
        return NULL;

    if (!ssl) {
        excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return NULL;
        }
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLSession object was null in "
                "getPeerX509Issuer");
        return NULL;
    }

    issuer = wolfSSL_X509_NAME_oneline(
            wolfSSL_X509_get_issuer_name((WOLFSSL_X509*)(uintptr_t)x509), 0, 0);

    retString = (*jenv)->NewStringUTF(jenv, issuer);
    XFREE(issuer, 0, DYNAMIC_TYPE_OPENSSL);

    return retString;

#else
    (void)jenv;
    (void)jcl;
    (void)ssl;
    (void)x509;
    return NULL;
#endif
}

JNIEXPORT jstring JNICALL Java_com_wolfssl_WolfSSLSession_getPeerX509Subject
  (JNIEnv* jenv, jobject jcl, jlong ssl, jlong x509)
{

#if defined(KEEP_PEER_CERT) || defined(SESSION_CERTS)
    jclass excClass;
    char* subject;
    jstring retString;

    (void)jcl;

    if (!x509)
        return NULL;

    if (!ssl) {
        excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return NULL;
        }
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLSession object was null in "
                "getPeerX509Subject");
        return NULL;
    }

    subject = wolfSSL_X509_NAME_oneline(
            wolfSSL_X509_get_subject_name(
                (WOLFSSL_X509*)(uintptr_t)x509), 0, 0);

    retString = (*jenv)->NewStringUTF(jenv, subject);
    XFREE(subject, 0, DYNAMIC_TYPE_OPENSSL);

    return retString;

#else
    (void)jenv;
    (void)jcl;
    (void)ssl;
    (void)x509;
    return NULL;
#endif
}

JNIEXPORT jstring JNICALL Java_com_wolfssl_WolfSSLSession_getPeerX509AltName
  (JNIEnv* jenv, jobject jcl, jlong ssl, jlong x509)
{
#if defined(KEEP_PEER_CERT) || defined(SESSION_CERTS)
    jclass excClass;
    char* altname;
    jstring retString;

    (void)jcl;

    if (!x509)
        return NULL;

    if (!ssl) {
        excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return NULL;
        }
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLSession object was null in "
                "getPeerX509AltName");
        return NULL;
    }

    altname = wolfSSL_X509_get_next_altname((WOLFSSL_X509*)(uintptr_t)x509);

    retString = (*jenv)->NewStringUTF(jenv, altname);
    return retString;

#else
    (void)jenv;
    (void)jcl;
    (void)ssl;
    (void)x509;
    return NULL;
#endif
}

JNIEXPORT jstring JNICALL Java_com_wolfssl_WolfSSLSession_getVersion
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    jclass excClass;

    (void)jcl;

    if (!ssl) {
        excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return NULL;
        }
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLSession object was null in "
                "getVersion");
        return NULL;
    }

    return (*jenv)->NewStringUTF(jenv,
                                 wolfSSL_get_version((WOLFSSL*)(uintptr_t)ssl));
}

JNIEXPORT jlong JNICALL Java_com_wolfssl_WolfSSLSession_getCurrentCipher
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    jclass excClass;

    (void)jcl;

    if (!ssl) {
        excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return SSL_FAILURE;
        }
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLSession object was null in "
                "getVersion");
        return SSL_FAILURE;
    }

    return (jlong)(uintptr_t)wolfSSL_get_current_cipher(
                                (WOLFSSL*)(uintptr_t)ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_checkDomainName
  (JNIEnv* jenv, jobject jcl, jlong ssl, jstring dn)
{
    int ret;
    const char* dname;
    jclass excClass;

    (void)jcl;

    if(!dn)
        return SSL_FAILURE;

    if (!ssl) {
        excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return SSL_FAILURE;
        }
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLSession object was null in "
                "checkDomainName");
        return SSL_FAILURE;
    }

    dname = (*jenv)->GetStringUTFChars(jenv, dn, 0);

    ret = wolfSSL_check_domain_name((WOLFSSL*)(uintptr_t)ssl, dname);

    (*jenv)->ReleaseStringUTFChars(jenv, dn, dname);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_setTmpDH
  (JNIEnv* jenv, jobject jcl, jlong ssl, jbyteArray p, jint pSz, jbyteArray g,
   jint gSz)
{
    unsigned char pBuf[pSz];
    unsigned char gBuf[gSz];
    jclass excClass;

    (void)jcl;

    if (!jenv || !p || !g) {
        return BAD_FUNC_ARG;
    }

    if (!ssl) {
        excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return SSL_FAILURE;
        }
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLSession object was null in "
                "setTmpDH");
        return SSL_FAILURE;
    }

    (*jenv)->GetByteArrayRegion(jenv, p, 0, pSz, (jbyte*)pBuf);
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return SSL_FAILURE;
    }

    (*jenv)->GetByteArrayRegion(jenv, g, 0, gSz, (jbyte*)gBuf);
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return SSL_FAILURE;
    }

    return wolfSSL_SetTmpDH((WOLFSSL*)(uintptr_t)ssl, pBuf, pSz, gBuf, gSz);

}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_setTmpDHFile
  (JNIEnv* jenv, jobject jcl, jlong ssl, jstring file, jint format)
{
    int ret;
    const char* fname;
    jclass excClass;

    (void)jcl;

    if (!file)
        return SSL_BAD_FILE;

    if (!ssl) {
        excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return SSL_FAILURE;
        }
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLSession object was null in "
                "setTmpDHFile");
        return SSL_FAILURE;
    }

    fname = (*jenv)->GetStringUTFChars(jenv, file, 0);

    ret = wolfSSL_SetTmpDH_file((WOLFSSL*)(uintptr_t)ssl, fname, format);

    (*jenv)->ReleaseStringUTFChars(jenv, file, fname);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_useCertificateBuffer
  (JNIEnv* jenv, jobject jcl, jlong ssl, jbyteArray in, jlong sz, jint format)
{
    unsigned char buff[sz];
    jclass excClass;

    (void)jcl;

    if (!jenv || !in)
        return BAD_FUNC_ARG;

    if (!ssl) {
        excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return SSL_FAILURE;
        }
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLSession object was null in "
                "useCertificateBuffer");
        return SSL_FAILURE;
    }

    (*jenv)->GetByteArrayRegion(jenv, in, 0, sz, (jbyte*)buff);
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return SSL_FAILURE;
    }

    return wolfSSL_use_certificate_buffer((WOLFSSL*)(uintptr_t)ssl, buff, sz,
                                          format);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_usePrivateKeyBuffer
  (JNIEnv* jenv, jobject jcl, jlong ssl, jbyteArray in, jlong sz, jint format)
{
    unsigned char buff[sz];
    jclass excClass;

    (void)jcl;

    if (!jenv || !in)
        return BAD_FUNC_ARG;

    if (!ssl) {
        excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return SSL_FAILURE;
        }
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLSession object was null in "
                "usePrivateKeyBuffer");
        return SSL_FAILURE;
    }

    (*jenv)->GetByteArrayRegion(jenv, in, 0, sz, (jbyte*)buff);
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return SSL_FAILURE;
    }

    return wolfSSL_use_PrivateKey_buffer((WOLFSSL*)(uintptr_t)ssl, buff, sz,
                                         format);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_useCertificateChainBuffer
  (JNIEnv* jenv, jobject jcl, jlong ssl, jbyteArray in, jlong sz)
{
    unsigned char buff[sz];
    jclass excClass;

    (void)jcl;

    if (!jenv || !in)
        return BAD_FUNC_ARG;

    if (!ssl) {
        excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return SSL_FAILURE;
        }
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLSession object was null in "
                "useCertificateChainBuffer");
        return SSL_FAILURE;
    }

    (*jenv)->GetByteArrayRegion(jenv, in, 0, sz, (jbyte*)buff);
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return SSL_FAILURE;
    }

    return wolfSSL_use_certificate_chain_buffer((WOLFSSL*)(uintptr_t)ssl, buff,
                                                sz);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_setGroupMessages
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    jclass excClass;

    (void)jcl;

    if (!ssl) {
        excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return SSL_FAILURE;
        }
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLSession object was null in "
                "setGroupMessages");
        return BAD_FUNC_ARG;
    }
    return wolfSSL_set_group_messages((WOLFSSL*)(uintptr_t)ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_enableCRL
  (JNIEnv* jenv, jobject jcl, jlong ssl, jint options)
{
#ifdef HAVE_CRL
    jclass excClass;

    (void)jcl;

    if (!jenv)
        return BAD_FUNC_ARG;

    if (!ssl) {
        excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return SSL_FAILURE;
        }
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLSession object was null in "
                "enableCRL");
        return SSL_FAILURE;
    }

    return wolfSSL_EnableCRL((WOLFSSL*)(uintptr_t)ssl, options);
#else
    (void)jenv;
    (void)jcl;
    (void)ssl;
    (void)options;
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_disableCRL
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
#ifdef HAVE_CRL
    jclass excClass;

    (void)jcl;

    if (!jenv)
        return BAD_FUNC_ARG;

    if (!ssl) {
        excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return SSL_FAILURE;
        }
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLSession object was null in "
                "disableCRL");
        return SSL_FAILURE;
    }

    return wolfSSL_DisableCRL((WOLFSSL*)(uintptr_t)ssl);
#else
    (void)jenv;
    (void)jcl;
    (void)ssl;
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_loadCRL
  (JNIEnv* jenv, jobject jcl, jlong ssl, jstring path, jint type, jint monitor)
{
#ifdef HAVE_CRL
    int ret;
    const char* crlPath;
    jclass excClass;

    (void)jcl;

    if (!jenv || !path)
        return BAD_FUNC_ARG;

    if (!ssl) {
        excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return SSL_FAILURE;
        }
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLSession object was null in "
                "loadCRL");
        return SSL_FAILURE;
    }

    crlPath = (*jenv)->GetStringUTFChars(jenv, path, 0);

    ret = wolfSSL_LoadCRL((WOLFSSL*)(uintptr_t)ssl, crlPath, type, monitor);

    (*jenv)->ReleaseStringUTFChars(jenv, path, crlPath);

    return ret;
#else
    (void)jenv;
    (void)jcl;
    (void)path;
    (void)type;
    (void)monitor;
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_setCRLCb
  (JNIEnv* jenv, jobject jcl, jlong ssl, jobject cb)
{
#ifdef HAVE_CRL
    int    ret = 0;
    jclass excClass;

    (void)jcl;

    if (!jenv || !cb) {
        return BAD_FUNC_ARG;
    }

    /* find exception class in case we need it */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return SSL_FAILURE;
    }

    if (!ssl) {
        (*jenv)->ThrowNew(jenv, excClass,
            "Input WolfSSLSession object was null in "
            "setCRLCb");
        return SSL_FAILURE;
    }

    /* store Java CRL callback Interface object */
    g_crlCbIfaceObj = (*jenv)->NewGlobalRef(jenv, cb);
    if (!g_crlCbIfaceObj) {
        (*jenv)->ThrowNew(jenv, excClass,
               "Error storing global missingCRLCallback interface");
    }

    ret = wolfSSL_SetCRL_Cb((WOLFSSL*)(uintptr_t)ssl, NativeMissingCRLCallback);

    return ret;
#else
    (void)jenv;
    (void)jcl;
    (void)ssl;
    (void)cb;
    return NOT_COMPILED_IN;
#endif
}

#ifdef HAVE_CRL

void NativeMissingCRLCallback(const char* url)
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
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return;
    }

    /* check if our stored object reference is valid */
    refcheck = (*jenv)->GetObjectRefType(jenv, g_crlCbIfaceObj);
    if (refcheck == 2) {

        /* lookup WolfSSLMissingCRLCallback class from global object ref */
        jclass crlClass = (*jenv)->GetObjectClass(jenv, g_crlCbIfaceObj);
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

        (*jenv)->CallVoidMethod(jenv, g_crlCbIfaceObj, crlMethod, missingUrl);

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

#endif /* HAVE_CRL */

JNIEXPORT jstring JNICALL Java_com_wolfssl_WolfSSLSession_cipherGetName
  (JNIEnv* jenv, jclass jcl, jlong ssl)
{
    const char* cipherName;
    WOLFSSL_CIPHER* cipher;
    jclass excClass;

    (void)jcl;

    if (!ssl) {
        excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return NULL;
        }
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLSession object was null in "
                "cipherGetName");
        return NULL;
    }

    cipher = wolfSSL_get_current_cipher((WOLFSSL*)(uintptr_t)ssl);

    if (cipher != NULL) {
        cipherName = wolfSSL_CIPHER_get_name(cipher);
        return (*jenv)->NewStringUTF(jenv, cipherName);
    } else {
        return (*jenv)->NewStringUTF(jenv, "NONE");
    }
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_WolfSSLSession_getMacSecret
  (JNIEnv* jenv, jobject jcl, jlong ssl, jint verify)
{
    jclass excClass;
#ifdef ATOMIC_USER
    int macLength;
    jbyteArray retSecret;
    const unsigned char* secret;
#endif

    (void)jcl;

    /* find exception class */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return NULL;
    }

#ifdef ATOMIC_USER

    if (!ssl) {
        (*jenv)->ThrowNew(jenv, excClass,
            "Input WolfSSLSession object was null in "
            "getMacSecret");
        return NULL;
    }

    secret = wolfSSL_GetMacSecret((WOLFSSL*)(uintptr_t)ssl, (int)verify);

    if (secret != NULL) {

        /* get mac size */
        macLength = wolfSSL_GetHmacSize((WOLFSSL*)(uintptr_t)ssl);

        /* create byte array to return */
        retSecret = (*jenv)->NewByteArray(jenv, macLength);
        if (!retSecret) {
            (*jenv)->ThrowNew(jenv, excClass,
                "Failed to create byte array in native getMacSecret");
            return NULL;
        }

        (*jenv)->SetByteArrayRegion(jenv, retSecret, 0, macLength,
                (jbyte*)secret);
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return NULL;
        }

        return retSecret;

    } else {
        return NULL;
    }
#else
    (*jenv)->ThrowNew(jenv, excClass,
        "wolfSSL not compiled with ATOMIC_USER");
    return NULL;
#endif
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_WolfSSLSession_getClientWriteKey
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    jclass excClass;
#ifdef ATOMIC_USER
    int keyLength;
    jbyteArray retKey;
    const unsigned char* key;
#endif

    (void)jcl;

    /* find exception class */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return NULL;
    }

#ifdef ATOMIC_USER

    if (!ssl) {
        (*jenv)->ThrowNew(jenv, excClass,
            "Input WolfSSLSession object was null in "
            "getClientWriteKey");
        return NULL;
    }

    key = wolfSSL_GetClientWriteKey((WOLFSSL*)(uintptr_t)ssl);

    if (key != NULL) {

        /* get key size */
        keyLength = wolfSSL_GetKeySize((WOLFSSL*)(uintptr_t)ssl);

        /* create byte array to return */
        retKey = (*jenv)->NewByteArray(jenv, keyLength);
        if (!retKey) {
            (*jenv)->ThrowNew(jenv, excClass,
                "Failed to create byte array in native getClientWriteKey");
            return NULL;
        }

        (*jenv)->SetByteArrayRegion(jenv, retKey, 0, keyLength,
                (jbyte*)key);
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return NULL;
        }

        return retKey;

    } else {
        return NULL;
    }
#else
    (*jenv)->ThrowNew(jenv, excClass,
        "wolfSSL not compiled with ATOMIC_USER");
    return NULL;
#endif
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_WolfSSLSession_getClientWriteIV
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    jclass excClass;
#ifdef ATOMIC_USER
    jbyteArray retIV;
    const unsigned char* iv;
    int ivLength;
#endif

    (void)jcl;

    /* find exception class */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return NULL;
    }

#ifdef ATOMIC_USER

    if (!ssl) {
        (*jenv)->ThrowNew(jenv, excClass,
            "Input WolfSSLSession object was null in "
            "getClientWriteIV");
        return NULL;
    }

    iv = wolfSSL_GetClientWriteIV((WOLFSSL*)(uintptr_t)ssl);

    if (iv != NULL) {

        /* get iv size, is block size for what wolfSSL supports */
        ivLength = wolfSSL_GetCipherBlockSize((WOLFSSL*)(uintptr_t)ssl);

        /* create byte array to return */
        retIV = (*jenv)->NewByteArray(jenv, ivLength);
        if (!retIV) {
            (*jenv)->ThrowNew(jenv, excClass,
                "Failed to create byte array in native getClientWriteIV");
            return NULL;
        }

        (*jenv)->SetByteArrayRegion(jenv, retIV, 0, ivLength,
                (jbyte*)iv);
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return NULL;
        }

        return retIV;

    } else {
        return NULL;
    }
#else
    (*jenv)->ThrowNew(jenv, excClass,
        "wolfSSL not compiled with ATOMIC_USER");
    return NULL;
#endif
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_WolfSSLSession_getServerWriteKey
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    jclass excClass;
#ifdef ATOMIC_USER
    jbyteArray retKey;
    const unsigned char* key;
    int keyLength;
#endif

    (void)jcl;

    /* find exception class */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return NULL;
    }

#ifdef ATOMIC_USER

    if (!ssl) {
        (*jenv)->ThrowNew(jenv, excClass,
            "Input WolfSSLSession object was null in "
            "getServerWriteKey");
        return NULL;
    }

    key = wolfSSL_GetServerWriteKey((WOLFSSL*)(uintptr_t)ssl);

    if (key != NULL) {

        /* get key size */
        keyLength = wolfSSL_GetKeySize((WOLFSSL*)(uintptr_t)ssl);

        /* create byte array to return */
        retKey = (*jenv)->NewByteArray(jenv, keyLength);
        if (!retKey) {
            (*jenv)->ThrowNew(jenv, excClass,
                "Failed to create byte array in native getServerWriteKey");
            return NULL;
        }

        (*jenv)->SetByteArrayRegion(jenv, retKey, 0, keyLength,
                (jbyte*)key);
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return NULL;
        }

        return retKey;

    } else {
        return NULL;
    }
#else
    (*jenv)->ThrowNew(jenv, excClass,
        "wolfSSL not compiled with ATOMIC_USER");
    return NULL;
#endif
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_WolfSSLSession_getServerWriteIV
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    jclass excClass;
#ifdef ATOMIC_USER
    jbyteArray retIV;
    const unsigned char* iv;
    int ivLength;
#endif

    (void)jcl;

    /* find exception class */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return NULL;
    }

#ifdef ATOMIC_USER

    if (!ssl) {
        (*jenv)->ThrowNew(jenv, excClass,
            "Input WolfSSLSession object was null in "
            "getServerWriteIV");
        return NULL;
    }

    iv = wolfSSL_GetServerWriteIV((WOLFSSL*)(uintptr_t)ssl);

    if (iv != NULL) {

        /* get iv size, is block size for what wolfSSL supports */
        ivLength = wolfSSL_GetCipherBlockSize((WOLFSSL*)(uintptr_t)ssl);

        /* create byte array to return */
        retIV = (*jenv)->NewByteArray(jenv, ivLength);
        if (!retIV) {
            (*jenv)->ThrowNew(jenv, excClass,
                "Failed to create byte array in native getServerWriteIV");
            return NULL;
        }

        (*jenv)->SetByteArrayRegion(jenv, retIV, 0, ivLength,
                (jbyte*)iv);
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return NULL;
        }

        return retIV;

    } else {
        return NULL;
    }
#else
    (*jenv)->ThrowNew(jenv, excClass,
        "wolfSSL not compiled with ATOMIC_USER");
    return NULL;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_getKeySize
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    (void)jenv;
    (void)jcl;

#ifdef ATOMIC_USER
    /* wolfSSL checks ssl for NULL */
    return wolfSSL_GetKeySize((WOLFSSL*)(uintptr_t)ssl);
#else
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_getSide
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    (void)jenv;
    (void)jcl;

#ifdef ATOMIC_USER
    /* wolfSSL checks ssl for NULL */
    return wolfSSL_GetSide((WOLFSSL*)(uintptr_t)ssl);
#else
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_isTLSv1_11
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    (void)jenv;
    (void)jcl;

#ifdef ATOMIC_USER
    /* wolfSSL checks ssl for NULL */
    return wolfSSL_IsTLSv1_1((WOLFSSL*)(uintptr_t)ssl);
#else
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_getBulkCipher
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    (void)jenv;
    (void)jcl;

#ifdef ATOMIC_USER
    /* wolfSSL checks ssl for NULL */
    return wolfSSL_GetBulkCipher((WOLFSSL*)(uintptr_t)ssl);
#else
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_getCipherBlockSize
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    (void)jenv;
    (void)jcl;

#ifdef ATOMIC_USER
    /* wolfSSL checks ssl for NULL */
    return wolfSSL_GetCipherBlockSize((WOLFSSL*)(uintptr_t)ssl);
#else
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_getAeadMacSize
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    (void)jenv;
    (void)jcl;

#ifdef ATOMIC_USER
    /* wolfSSL checks ssl for NULL */
    return wolfSSL_GetAeadMacSize((WOLFSSL*)(uintptr_t)ssl);
#else
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_getHmacSize
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    (void)jenv;
    (void)jcl;

#ifdef ATOMIC_USER
    /* wolfSSL checks ssl for NULL */
    return wolfSSL_GetHmacSize((WOLFSSL*)(uintptr_t)ssl);
#else
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_getHmacType
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    (void)jenv;
    (void)jcl;

    /* wolfSSL checks ssl for NULL */
    return wolfSSL_GetHmacType((WOLFSSL*)(uintptr_t)ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_getCipherType
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    (void)jenv;
    (void)jcl;

#ifdef ATOMIC_USER
    /* wolfSSL checks ssl for NULL */
    return wolfSSL_GetCipherType((WOLFSSL*)(uintptr_t)ssl);
#else
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_setTlsHmacInner
  (JNIEnv* jenv, jobject jcl, jlong ssl, jbyteArray inner, jlong sz,
   jint content, jint verify)
{
    int ret = 0;
    unsigned char hmacInner[WOLFSSL_TLS_HMAC_INNER_SZ];

    (void)jcl;

    if (!jenv || inner == NULL || !ssl) {
        return BAD_FUNC_ARG;
    }

    /* find exception class */
    jclass excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return -1;
    }

    ret = wolfSSL_SetTlsHmacInner((WOLFSSL*)(uintptr_t)ssl, hmacInner, sz,
            content, verify);

    /* copy hmacInner back into inner jbyteArray */
    (*jenv)->SetByteArrayRegion(jenv, inner, 0, WOLFSSL_TLS_HMAC_INNER_SZ,
            (jbyte*)hmacInner);
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        (*jenv)->ThrowNew(jenv, excClass,
            "Failed to set byte region in native setTlsHmacInner");
        return -1;
    }

    return ret;
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setEccSignCtx
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    jclass         excClass;
#if defined(HAVE_PK_CALLBACKS) && defined(HAVE_ECC)
    jclass         sslClass;

    void*          eccSignCtx;
    internCtx*     myCtx;
#endif

    /* find exception class in case we need it */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return;
    }

#if defined(HAVE_PK_CALLBACKS) && defined(HAVE_ECC)

    if (!ssl) {
        (*jenv)->ThrowNew(jenv, excClass,
            "Input WolfSSLSession object was null in "
            "setEccSignCtx");
        return;
    }

    /* get WolfSSLSession class from object ref */
    sslClass = (*jenv)->GetObjectClass(jenv, jcl);
    if (!sslClass) {
        (*jenv)->ThrowNew(jenv, excClass,
                "Can't get WolfSSLSession object class");
        return;
    }

    /* free existing memory if it already exists, before we malloc again */
    eccSignCtx = (internCtx*) wolfSSL_GetEccSignCtx((WOLFSSL*)(uintptr_t)ssl);

    /* note: if CTX has not been set up yet, wolfSSL defaults to NULL */
    if (eccSignCtx != NULL) {
        myCtx = (internCtx*)eccSignCtx;
        if (myCtx->active == 1) {
            (*jenv)->DeleteGlobalRef(jenv, myCtx->obj);
            XFREE(myCtx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }
    }

    /* allocate memory for internal JNI object reference */
    myCtx = XMALLOC(sizeof(internCtx), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (!myCtx) {
        (*jenv)->ThrowNew(jenv, excClass,
                "Unable to allocate memory for ECC sign context\n");
        return;
    }

    /* set CTX as active */
    myCtx->active = 1;

    /* store global ref to WolfSSLSession object */
    myCtx->obj = (*jenv)->NewGlobalRef(jenv, jcl);
    if (!myCtx->obj) {
        (*jenv)->ThrowNew(jenv, excClass,
               "Unable to store WolfSSLSession object as global reference");
        return;
    }

    wolfSSL_SetEccSignCtx((WOLFSSL*)(uintptr_t)ssl, myCtx);
#else
    (*jenv)->ThrowNew(jenv, excClass,
        "wolfSSL not compiled with PK Callbacks and/or ECC");
    return;
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setEccVerifyCtx
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    jclass         excClass;
#if defined(HAVE_PK_CALLBACKS) && defined(HAVE_ECC)
    jclass         sslClass;

    void*          eccVerifyCtx;
    internCtx*     myCtx;
#endif

    /* find exception class in case we need it */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return;
    }

#if defined(HAVE_PK_CALLBACKS) && defined(HAVE_ECC)

    if (!ssl) {
        (*jenv)->ThrowNew(jenv, excClass,
            "Input WolfSSLSession object was null in "
            "setEccVerifyCtx");
        return;
    }

    /* get WolfSSLSession class from object ref */
    sslClass = (*jenv)->GetObjectClass(jenv, jcl);
    if (!sslClass) {
        (*jenv)->ThrowNew(jenv, excClass,
                "Can't get WolfSSLSession object class");
        return;
    }

    /* free existing memory if it already exists, before we malloc again */
    eccVerifyCtx = (internCtx*)wolfSSL_GetEccVerifyCtx(
                                (WOLFSSL*)(uintptr_t)ssl);

    /* note: if CTX has not been set up yet, wolfSSL defaults to NULL */
    if (eccVerifyCtx != NULL) {
        myCtx = (internCtx*)eccVerifyCtx;
        if (myCtx->active == 1) {
            (*jenv)->DeleteGlobalRef(jenv, myCtx->obj);
            XFREE(myCtx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }
    }

    /* allocate memory for internal JNI object reference */
    myCtx = XMALLOC(sizeof(internCtx), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (!myCtx) {
        (*jenv)->ThrowNew(jenv, excClass,
                "Unable to allocate memory for ECC verify context\n");
        return;
    }

    /* set CTX as active */
    myCtx->active = 1;

    /* store global ref to WolfSSLSession object */
    myCtx->obj = (*jenv)->NewGlobalRef(jenv, jcl);
    if (!myCtx->obj) {
        (*jenv)->ThrowNew(jenv, excClass,
               "Unable to store WolfSSLSession object as global reference");
        return;
    }

    wolfSSL_SetEccVerifyCtx((WOLFSSL*)(uintptr_t)ssl, myCtx);
#else
    (*jenv)->ThrowNew(jenv, excClass,
        "wolfSSL not compiled with PK Callbacks and/or ECC");
    return;
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setEccSharedSecretCtx
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    jclass         excClass;
#if defined(HAVE_PK_CALLBACKS) && defined(HAVE_ECC)
    jclass         sslClass;

    void*          eccSharedSecretCtx;
    internCtx*     myCtx;
#endif

    /* find exception class in case we need it */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return;
    }

#if defined(HAVE_PK_CALLBACKS) && defined(HAVE_ECC)

    if (!ssl) {
        (*jenv)->ThrowNew(jenv, excClass,
            "Input WolfSSLSession object was null in "
            "setEccSharedSecretCtx");
        return;
    }

    /* get WolfSSLSession class from object ref */
    sslClass = (*jenv)->GetObjectClass(jenv, jcl);
    if (!sslClass) {
        (*jenv)->ThrowNew(jenv, excClass,
                "Can't get WolfSSLSession object class");
        return;
    }

    /* free existing memory if it already exists, before we malloc again */
    eccSharedSecretCtx =
        (internCtx*) wolfSSL_GetEccSharedSecretCtx((WOLFSSL*)(uintptr_t)ssl);

    /* note: if CTX has not been set up yet, wolfSSL defaults to NULL */
    if (eccSharedSecretCtx != NULL) {
        myCtx = (internCtx*)eccSharedSecretCtx;
        if (myCtx->active == 1) {
            (*jenv)->DeleteGlobalRef(jenv, myCtx->obj);
            XFREE(myCtx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }
    }

    /* allocate memory for internal JNI object reference */
    myCtx = XMALLOC(sizeof(internCtx), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (!myCtx) {
        (*jenv)->ThrowNew(jenv, excClass,
                "Unable to allocate memory for ECC shared secret context\n");
        return;
    }

    /* set CTX as active */
    myCtx->active = 1;

    /* store global ref to WolfSSLSession object */
    myCtx->obj = (*jenv)->NewGlobalRef(jenv, jcl);
    if (!myCtx->obj) {
        (*jenv)->ThrowNew(jenv, excClass,
               "Unable to store WolfSSLSession object as global reference");
        return;
    }

    wolfSSL_SetEccSharedSecretCtx((WOLFSSL*)(uintptr_t)ssl, myCtx);
#else
    (*jenv)->ThrowNew(jenv, excClass,
        "wolfSSL not compiled with PK Callbacks and/or ECC");
    return;
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setRsaSignCtx
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    jclass         excClass;
#if defined(HAVE_PK_CALLBACKS) && !defined(NO_RSA)
    jclass         sslClass;

    void*          rsaSignCtx;
    internCtx*     myCtx;
#endif

    /* find exception class in case we need it */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return;
    }

#if defined(HAVE_PK_CALLBACKS) && !defined(NO_RSA)

    if (!ssl) {
        (*jenv)->ThrowNew(jenv, excClass,
            "Input WolfSSLSession object was null in "
            "setRsaSignCtx");
        return;
    }

    /* get WolfSSLSession class from object ref */
    sslClass = (*jenv)->GetObjectClass(jenv, jcl);
    if (!sslClass) {
        (*jenv)->ThrowNew(jenv, excClass,
                "Can't get WolfSSLSession object class");
        return;
    }

    /* free existing memory if it already exists, before we malloc again */
    rsaSignCtx = (internCtx*) wolfSSL_GetRsaSignCtx((WOLFSSL*)(uintptr_t)ssl);

    /* note: if CTX has not been set up yet, wolfSSL defaults to NULL */
    if (rsaSignCtx != NULL) {
        myCtx = (internCtx*)rsaSignCtx;
        if (myCtx->active == 1) {
            (*jenv)->DeleteGlobalRef(jenv, myCtx->obj);
            XFREE(myCtx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }
    }

    /* allocate memory for internal JNI object reference */
    myCtx = XMALLOC(sizeof(internCtx), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (!myCtx) {
        (*jenv)->ThrowNew(jenv, excClass,
                "Unable to allocate memory for RSA sign context\n");
        return;
    }

    /* set CTX as active */
    myCtx->active = 1;

    /* store global ref to WolfSSLSession object */
    myCtx->obj = (*jenv)->NewGlobalRef(jenv, jcl);
    if (!myCtx->obj) {
        (*jenv)->ThrowNew(jenv, excClass,
               "Unable to store WolfSSLSession object as global reference");
        return;
    }

    wolfSSL_SetRsaSignCtx((WOLFSSL*)(uintptr_t)ssl, myCtx);
#else
    (*jenv)->ThrowNew(jenv, excClass,
        "wolfSSL not compiled with PK Callbacks and/or RSA support");
    return;
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setRsaVerifyCtx
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    jclass         excClass;
#if defined(HAVE_PK_CALLBACKS) && !defined(NO_RSA)
    jclass         sslClass;

    void*          rsaVerifyCtx;
    internCtx*     myCtx;
#endif

    /* find exception class in case we need it */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return;
    }

#if defined(HAVE_PK_CALLBACKS) && !defined(NO_RSA)

    if (!ssl) {
        (*jenv)->ThrowNew(jenv, excClass,
            "Input WolfSSLSession object was null in "
            "setRsaVerifyCtx");
        return;
    }

    /* get WolfSSLSession class from object ref */
    sslClass = (*jenv)->GetObjectClass(jenv, jcl);
    if (!sslClass) {
        (*jenv)->ThrowNew(jenv, excClass,
                "Can't get WolfSSLSession object class");
        return;
    }

    /* free existing memory if it already exists, before we malloc again */
    rsaVerifyCtx = (internCtx*)wolfSSL_GetRsaVerifyCtx(
                                (WOLFSSL*)(uintptr_t)ssl);

    /* note: if CTX has not been set up yet, wolfSSL defaults to NULL */
    if (rsaVerifyCtx != NULL) {
        myCtx = (internCtx*)rsaVerifyCtx;
        if (myCtx->active == 1) {
            (*jenv)->DeleteGlobalRef(jenv, myCtx->obj);
            XFREE(myCtx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }
    }

    /* allocate memory for internal JNI object reference */
    myCtx = XMALLOC(sizeof(internCtx), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (!myCtx) {
        (*jenv)->ThrowNew(jenv, excClass,
                "Unable to allocate memory for RSA verify context\n");
        return;
    }

    /* set CTX as active */
    myCtx->active = 1;

    /* store global ref to WolfSSLSession object */
    myCtx->obj = (*jenv)->NewGlobalRef(jenv, jcl);
    if (!myCtx->obj) {
        (*jenv)->ThrowNew(jenv, excClass,
               "Unable to store WolfSSLSession object as global reference");
        return;
    }

    wolfSSL_SetRsaVerifyCtx((WOLFSSL*)(uintptr_t)ssl, myCtx);
#else
    (*jenv)->ThrowNew(jenv, excClass,
        "wolfSSL not compiled with PK Callbacks and/or RSA support");
    return;
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setRsaEncCtx
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    jclass         excClass;
#if defined(HAVE_PK_CALLBACKS) && !defined(NO_RSA)
    jclass         sslClass;

    void*          rsaEncCtx;
    internCtx*     myCtx;
#endif

    /* find exception class in case we need it */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return;
    }

#if defined(HAVE_PK_CALLBACKS) && !defined(NO_RSA)

    if (!ssl) {
        (*jenv)->ThrowNew(jenv, excClass,
            "Input WolfSSLSession object was null in "
            "setRsaEncCtx");
        return;
    }

    /* get WolfSSLSession class from object ref */
    sslClass = (*jenv)->GetObjectClass(jenv, jcl);
    if (!sslClass) {
        (*jenv)->ThrowNew(jenv, excClass,
                "Can't get WolfSSLSession object class");
        return;
    }

    /* free existing memory if it already exists, before we malloc again */
    rsaEncCtx = (internCtx*) wolfSSL_GetRsaEncCtx((WOLFSSL*)(uintptr_t)ssl);

    /* note: if CTX has not been set up yet, wolfSSL defaults to NULL */
    if (rsaEncCtx != NULL) {
        myCtx = (internCtx*)rsaEncCtx;
        if (myCtx->active == 1) {
            (*jenv)->DeleteGlobalRef(jenv, myCtx->obj);
            XFREE(myCtx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }
    }

    /* allocate memory for internal JNI object reference */
    myCtx = XMALLOC(sizeof(internCtx), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (!myCtx) {
        (*jenv)->ThrowNew(jenv, excClass,
                "Unable to allocate memory for RSA encrypt context\n");
        return;
    }

    /* set CTX as active */
    myCtx->active = 1;

    /* store global ref to WolfSSLSession object */
    myCtx->obj = (*jenv)->NewGlobalRef(jenv, jcl);
    if (!myCtx->obj) {
        (*jenv)->ThrowNew(jenv, excClass,
               "Unable to store WolfSSLSession object as global reference");
        return;
    }

    wolfSSL_SetRsaEncCtx((WOLFSSL*)(uintptr_t)ssl, myCtx);
#else
    (*jenv)->ThrowNew(jenv, excClass,
        "wolfSSL not compiled with PK Callbacks and/or RSA support");
    return;
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setRsaDecCtx
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    jclass         excClass;
#if defined(HAVE_PK_CALLBACKS) && !defined(NO_RSA)
    jclass         sslClass;

    void*          rsaDecCtx;
    internCtx*     myCtx;
#endif

    /* find exception class in case we need it */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return;
    }

#if defined(HAVE_PK_CALLBACKS) && !defined(NO_RSA)

    if (!ssl) {
        (*jenv)->ThrowNew(jenv, excClass,
            "Input WolfSSLSession object was null in "
            "setRsaDecCtx");
        return;
    }

    /* get WolfSSLSession class from object ref */
    sslClass = (*jenv)->GetObjectClass(jenv, jcl);
    if (!sslClass) {
        (*jenv)->ThrowNew(jenv, excClass,
                "Can't get WolfSSLSession object class");
        return;
    }

    /* free existing memory if it already exists, before we malloc again */
    rsaDecCtx = (internCtx*) wolfSSL_GetRsaDecCtx((WOLFSSL*)(uintptr_t)ssl);

    /* note: if CTX has not been set up yet, wolfSSL defaults to NULL */
    if (rsaDecCtx != NULL) {
        myCtx = (internCtx*)rsaDecCtx;
        if (myCtx->active == 1) {
            (*jenv)->DeleteGlobalRef(jenv, myCtx->obj);
            XFREE(myCtx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }
    }

    /* allocate memory for internal JNI object reference */
    myCtx = XMALLOC(sizeof(internCtx), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (!myCtx) {
        (*jenv)->ThrowNew(jenv, excClass,
                "Unable to allocate memory for RSA decrypt context\n");
        return;
    }

    /* set CTX as active */
    myCtx->active = 1;

    /* store global ref to WolfSSLSession object */
    myCtx->obj = (*jenv)->NewGlobalRef(jenv, jcl);
    if (!myCtx->obj) {
        (*jenv)->ThrowNew(jenv, excClass,
               "Unable to store WolfSSLSession object as global reference");
        return;
    }

    wolfSSL_SetRsaDecCtx((WOLFSSL*)(uintptr_t)ssl, myCtx);
#else
    (*jenv)->ThrowNew(jenv, excClass,
        "wolfSSL not compiled with PK Callbacks and/or RSA support");
    return;
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setPskClientCb
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    (void)jcl;

    /* find exception class */
    jclass excClass = (*jenv)->FindClass(jenv,
            "com/wolfssl/WolfSSLJNIException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return;
    }

#ifndef NO_PSK

    if (ssl) {
        /* set PSK client callback */
        wolfSSL_set_psk_client_callback((WOLFSSL*)(uintptr_t)ssl,
                                        NativePskClientCb);
    } else {
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLSession object was null when setting "
                "NativePskClientCb");
        return;
    }

#else
    (*jenv)->ThrowNew(jenv, excClass,
        "wolfSSL not compiled with PSK support");
    return;
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setPskServerCb
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    (void)jcl;

    /* find exception class */
    jclass excClass = (*jenv)->FindClass(jenv,
            "com/wolfssl/WolfSSLJNIException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return;
    }

#ifndef NO_PSK

    if (ssl) {
        /* set PSK server callback */
        wolfSSL_set_psk_server_callback((WOLFSSL*)(uintptr_t)ssl,
                                        NativePskServerCb);
    } else {
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLSession object was null when setting "
                "NativePskServerCb");
        return;
    }

#else
    (*jenv)->ThrowNew(jenv, excClass,
        "wolfSSL not compiled with PSK support");
    return;
#endif
}

JNIEXPORT jstring JNICALL Java_com_wolfssl_WolfSSLSession_getPskIdentityHint
  (JNIEnv* jenv, jobject obj, jlong ssl)
{
    (void)obj;
#ifndef NO_PSK
    if (!jenv || !ssl)
        return NULL;

    return (*jenv)->NewStringUTF(jenv,
            wolfSSL_get_psk_identity_hint((WOLFSSL*)(uintptr_t)ssl));
#else
    (void)jenv;
    (void)ssl;
    return NULL;
#endif
}

JNIEXPORT jstring JNICALL Java_com_wolfssl_WolfSSLSession_getPskIdentity
  (JNIEnv* jenv, jobject obj, jlong ssl)
{
    (void)obj;
#ifndef NO_PSK
    if (!jenv || !ssl)
        return NULL;

    return (*jenv)->NewStringUTF(jenv,
            wolfSSL_get_psk_identity((WOLFSSL*)(uintptr_t)ssl));
#else
    (void)jenv;
    (void)ssl;
    return NULL;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_usePskIdentityHint
  (JNIEnv* jenv, jobject obj, jlong ssl, jstring hint)
{
#ifndef NO_PSK
    jint ret;
    const char* nativeHint;

    (void)obj;

    if (!jenv || !ssl || !hint)
        return SSL_FAILURE;

    nativeHint = (*jenv)->GetStringUTFChars(jenv, hint, 0);

    ret = (jint)wolfSSL_use_psk_identity_hint((WOLFSSL*)(uintptr_t)ssl,
                                              nativeHint);

    (*jenv)->ReleaseStringUTFChars(jenv, hint, nativeHint);

    return ret;
#else
    (void)jenv;
    (void)ssl;
    (void)hint;
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT jboolean JNICALL Java_com_wolfssl_WolfSSLSession_handshakeDone
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    (void)jcl;

    if (!jenv || !ssl)
        return JNI_FALSE;

    if (wolfSSL_is_init_finished((WOLFSSL*)(uintptr_t)ssl)) {
        return JNI_TRUE;
    }
    else {
        return JNI_FALSE;
    }
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setConnectState
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    (void)jcl;

    if (!jenv || !ssl)
        return;

    wolfSSL_set_connect_state((WOLFSSL*)(uintptr_t)ssl);
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setAcceptState
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    (void)jcl;

    if (!jenv || !ssl)
        return;

    wolfSSL_set_accept_state((WOLFSSL*)(uintptr_t)ssl);
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setVerify
  (JNIEnv* jenv, jobject jcl, jlong ssl, jint mode, jobject callbackIface)
{
    (void)jcl;

    if (!jenv || !ssl)
        return;

    if (!callbackIface) {
        wolfSSL_set_verify((WOLFSSL*)(uintptr_t)ssl, mode, NULL);
    } else {

        /* store Java verify Interface object */
        g_verifySSLCbIfaceObj = (*jenv)->NewGlobalRef(jenv, callbackIface);
        if (!g_verifySSLCbIfaceObj) {
            printf("error storing global callback interface\n");
        }

        /* set verify mode, register Java callback with wolfSSL */
        wolfSSL_set_verify((WOLFSSL*)(uintptr_t)ssl, mode,
                           NativeSSLVerifyCallback);
    }
}

JNIEXPORT jlong JNICALL Java_com_wolfssl_WolfSSLSession_setOptions
  (JNIEnv* jenv, jobject jcl, jlong ssl, jlong op)
{
    (void)jcl;

    if (!jenv || !ssl)
        return 0;

    return wolfSSL_set_options((WOLFSSL*)(uintptr_t)ssl, op);
}

JNIEXPORT jlong JNICALL Java_com_wolfssl_WolfSSLSession_getOptions
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    (void)jcl;

    if (!jenv || !ssl)
        return 0;

    return wolfSSL_get_options((WOLFSSL*)(uintptr_t)ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_getShutdown
  (JNIEnv *jenv, jobject jcl, jlong ssl)
{
    (void)jenv;
    (void)jcl;

    return (jint)wolfSSL_get_shutdown((WOLFSSL*)(uintptr_t)ssl);
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setSSLIORecv
    (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    (void)jcl;

    /* find exception class */
    jclass excClass = (*jenv)->FindClass(jenv,
            "com/wolfssl/WolfSSLJNIException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return;
    }

    if (ssl) {
        /* set I/O recv callback */
        wolfSSL_SSLSetIORecv((WOLFSSL*)(uintptr_t)ssl, NativeSSLIORecvCb);

    } else {
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLContext object was null when setting IORecv");
    }
}

int NativeSSLIORecvCb(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    jint       retval = 0;
    jint       vmret  = 0;

    JNIEnv*    jenv;                  /* JNI environment */
    jclass     excClass;              /* WolfSSLJNIException class */
    int        needsDetach = 0;       /* Should we explicitly detach? */

    static jobject* g_cachedSSLObj;   /* WolfSSLSession cached object */
    jclass     sslClass;              /* WolfSSLSession class */
    jmethodID  recvCbMethodId;        /* internalIORecvCallback ID */
    jbyteArray inData;

    if (!g_vm || !ssl || !buf || !ctx) {
        /* can't throw exception yet, just return error */
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
            return WOLFSSL_CBIO_ERR_GENERAL;
        }
        needsDetach = 1;
    } else if (vmret != JNI_OK) {
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    /* find exception class in case we need it */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLJNIException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        if (needsDetach)
            (*g_vm)->DetachCurrentThread(g_vm);
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    /* get stored WolfSSLSession jobject */
    g_cachedSSLObj = (jobject*) wolfSSL_get_jobject((WOLFSSL*)(uintptr_t)ssl);
    if (!g_cachedSSLObj) {
        (*jenv)->ThrowNew(jenv, excClass,
                "Can't get native WolfSSLSession object reference in "
                "NativeSSLIORecvCb");
        if (needsDetach)
            (*g_vm)->DetachCurrentThread(g_vm);
        return 0;
    }

    /* lookup WolfSSLSession class from object */
    sslClass = (*jenv)->GetObjectClass(jenv, (jobject)(*g_cachedSSLObj));
    if (!sslClass) {
        (*jenv)->ThrowNew(jenv, excClass,
            "Can't get native WolfSSLSession class reference in "
            "NativeSSLIORecvCb");
        if (needsDetach)
            (*g_vm)->DetachCurrentThread(g_vm);
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    /* call internal I/O recv callback */
    recvCbMethodId = (*jenv)->GetMethodID(jenv, sslClass,
            "internalIOSSLRecvCallback",
            "(Lcom/wolfssl/WolfSSLSession;[BI)I");
    if (!recvCbMethodId) {
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
        }
        (*jenv)->ThrowNew(jenv, excClass,
            "Error getting internalIORecvCallback method from JNI");
        if (needsDetach)
            (*g_vm)->DetachCurrentThread(g_vm);
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    /* create jbyteArray to hold received data */
    inData = (*jenv)->NewByteArray(jenv, sz);
    if (!inData) {
        (*jenv)->ThrowNew(jenv, excClass,
            "Error getting internalIORecvCallback method from JNI");
        if (needsDetach)
            (*g_vm)->DetachCurrentThread(g_vm);
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    /* call Java send callback, ignore native ctx since Java
     * handles it */
    retval = (*jenv)->CallIntMethod(jenv, (jobject)(*g_cachedSSLObj),
            recvCbMethodId, (jobject)(*g_cachedSSLObj), inData, (jint)sz);

    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        (*jenv)->DeleteLocalRef(jenv, inData);
        if (needsDetach)
            (*g_vm)->DetachCurrentThread(g_vm);
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    /* copy jbyteArray into char array */
    if (retval >= 0) {
        (*jenv)->GetByteArrayRegion(jenv, inData, 0, retval,
                (jbyte*)buf);
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            (*jenv)->DeleteLocalRef(jenv, inData);
            if (needsDetach)
                (*g_vm)->DetachCurrentThread(g_vm);
            return WOLFSSL_CBIO_ERR_GENERAL;
        }
    }

    /* delete local refs, detach JNIEnv from thread */
    (*jenv)->DeleteLocalRef(jenv, inData);
    if (needsDetach)
        (*g_vm)->DetachCurrentThread(g_vm);

    return retval;
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setSSLIOSend
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    (void)jcl;

    /* find exception class in case we need it */
    jclass excClass = (*jenv)->FindClass(jenv,
            "com/wolfssl/WolfSSLJNIException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
    }

    if (ssl) {
        /* set I/O send callback */
        wolfSSL_SSLSetIOSend((WOLFSSL*)(uintptr_t)ssl, NativeSSLIOSendCb);

    } else {
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLContext object was null when setting IOSend");
    }
}

int NativeSSLIOSendCb(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    jint       retval = 0;
    jint       vmret  = 0;

    JNIEnv*    jenv;                  /* JNI environment */
    jclass     excClass;              /* WolfSSLJNIException class */
    int        needsDetach = 0;       /* Should we explicitly detach? */

    static jobject* g_cachedSSLObj;   /* WolfSSLSession cached object */
    jclass     sslClass;              /* WolfSSLSession class */
    jmethodID  sendCbMethodId;        /* internalIOSendCallback ID */
    jbyteArray outData;               /* jbyteArray for data to send */

    if (!g_vm || !ssl || !buf || !ctx) {
        /* can't throw exception yet, just return error */
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
            return WOLFSSL_CBIO_ERR_GENERAL;
        }
        needsDetach = 1;
    } else if (vmret != JNI_OK) {
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    /* find exception class in case we need it */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLJNIException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        if (needsDetach)
            (*g_vm)->DetachCurrentThread(g_vm);
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    /* get stored WolfSSLSession jobject */
    g_cachedSSLObj = (jobject*) wolfSSL_get_jobject((WOLFSSL*)(uintptr_t)ssl);
    if (!g_cachedSSLObj) {
        (*jenv)->ThrowNew(jenv, excClass,
                "Can't get native WolfSSLSession object reference in "
                "NativeSSLIOSendCb");
        if (needsDetach)
            (*g_vm)->DetachCurrentThread(g_vm);
        return 0;
    }

    /* lookup WolfSSLSession class from object */
    sslClass = (*jenv)->GetObjectClass(jenv, (jobject)(*g_cachedSSLObj));
    if (!sslClass) {
        (*jenv)->ThrowNew(jenv, excClass,
            "Can't get native WolfSSLSession class reference");
        if (needsDetach)
            (*g_vm)->DetachCurrentThread(g_vm);
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    /* call internal I/O send callback */
    sendCbMethodId = (*jenv)->GetMethodID(jenv, sslClass,
            "internalIOSSLSendCallback",
            "(Lcom/wolfssl/WolfSSLSession;[BI)I");
    if (!sendCbMethodId) {
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
        }
        (*jenv)->ThrowNew(jenv, excClass,
                "Error getting internalIOSendCallback method from JNI");
        if (needsDetach)
            (*g_vm)->DetachCurrentThread(g_vm);
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    if (sz >= 0)
    {
        /* create jbyteArray to hold received data */
        outData = (*jenv)->NewByteArray(jenv, sz);
        if (!outData) {
            (*jenv)->ThrowNew(jenv, excClass,
                    "Error getting internalIOSendCallback method from JNI");
            if (needsDetach)
                (*g_vm)->DetachCurrentThread(g_vm);
            return WOLFSSL_CBIO_ERR_GENERAL;
        }

        (*jenv)->SetByteArrayRegion(jenv, outData, 0, sz, (jbyte*)buf);
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            (*jenv)->DeleteLocalRef(jenv, outData);
            if (needsDetach)
                (*g_vm)->DetachCurrentThread(g_vm);
            return WOLFSSL_CBIO_ERR_GENERAL;
        }

        /* call Java send callback, ignore native ctx since Java
         * handles it */
        retval = (*jenv)->CallIntMethod(jenv, (jobject)(*g_cachedSSLObj),
            sendCbMethodId, (jobject)(*g_cachedSSLObj), outData, (jint)sz);

        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            (*jenv)->DeleteLocalRef(jenv, outData);
            if (needsDetach)
                (*g_vm)->DetachCurrentThread(g_vm);
            return WOLFSSL_CBIO_ERR_GENERAL;
        }

        /* delete local refs */
        (*jenv)->DeleteLocalRef(jenv, outData);
    }

    /* detach JNIEnv from thread */
    if (needsDetach)
        (*g_vm)->DetachCurrentThread(g_vm);

    return retval;
}


