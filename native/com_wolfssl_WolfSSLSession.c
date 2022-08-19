/* com_wolfssl_WolfSSLSession.c
 *
 * Copyright (C) 2006-2022 wolfSSL Inc.
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
#include <stdint.h>
#include <sys/time.h>

#include <arpa/inet.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>

#include "com_wolfssl_globals.h"
#include "com_wolfssl_WolfSSL.h"

/* custom I/O native fn prototypes */
int  NativeSSLIORecvCb(WOLFSSL *ssl, char *buf, int sz, void *ctx);
int  NativeSSLIOSendCb(WOLFSSL *ssl, char *buf, int sz, void *ctx);
#ifdef HAVE_CRL
/* global object refs for CRL callback */
static jobject g_crlCbIfaceObj;
#endif

/* Data used per-WOLFSSL session that needs to be stored across native
 * function calls. Stored inside WOLFSSL app data, set with
 * wolfSSL_set_app_data(), retrieved with wolfSSL_get_app_data().
 * Global callback objects are created with NewGlobalRef(), then freed
 * inside freeSSL() with DeleteGlobalRef(). */
typedef struct SSLAppData {
    wolfSSL_Mutex* jniSessLock;      /* WOLFSSL session lock */
    jobject* g_verifySSLCbIfaceObj;  /* Java verify callback [global ref] */
} SSLAppData;

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
    SSLAppData* appData;            /* WOLFSSL app data, stored verify cb obj */
    jobject* g_verifySSLCbIfaceObj;  /* Global jobject, stored in app data */

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

    /* get app data to retrieve stored Java jobject callback object */
    appData = (SSLAppData*)wolfSSL_get_app_data(
                wolfSSL_X509_STORE_CTX_get_ex_data(store, 0));
    if (appData == NULL) {
        printf("Error getting app data from WOLFSSL\n");
        return -105;
    }

    /* get global Java verify callback object */
    g_verifySSLCbIfaceObj = appData->g_verifySSLCbIfaceObj;
    if (g_verifySSLCbIfaceObj == NULL || *g_verifySSLCbIfaceObj == NULL) {
        printf("Error getting g_verifySSLCbIfaceObj from appData\n");
        return -106;
    }

    /* check if our stored object reference is valid */
    refcheck = (*jenv)->GetObjectRefType(jenv, *g_verifySSLCbIfaceObj);
    if (refcheck == 2) {

        /* lookup WolfSSLVerifyCallback class from global object ref */
        jclass verifyClass = (*jenv)->GetObjectClass(jenv,
                                                     *g_verifySSLCbIfaceObj);
        if (!verifyClass) {
            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
            }

            (*jenv)->ThrowNew(jenv, excClass,
                "Can't get native WolfSSLVerifyCallback class reference");
            return -107;
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
            return -108;
        }

        retval = (*jenv)->CallIntMethod(jenv, *g_verifySSLCbIfaceObj,
                verifyMethod, preverify_ok, (jlong)(uintptr_t)store);

        if ((*jenv)->ExceptionOccurred(jenv)) {
            /* exception occurred on the Java side during method call */
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return -109;
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
    jlong sslPtr = 0;
    jobject* g_cachedSSLObj = NULL;
    wolfSSL_Mutex* jniSessLock = NULL;
    SSLAppData* appData = NULL;

    if (jenv == NULL) {
        return SSL_FAILURE;
    }

    /* wolfSSL java caller checks for null pointer */
    sslPtr = (jlong)(uintptr_t)wolfSSL_new((WOLFSSL_CTX*)(uintptr_t)ctx);

    if (sslPtr != 0) {
        /* create global reference to WolfSSLSession jobject */
        g_cachedSSLObj = (jobject*)XMALLOC(sizeof(jobject), NULL,
                                        DYNAMIC_TYPE_TMP_BUFFER);
        if (g_cachedSSLObj == NULL) {
            printf("error mallocing memory in newSSL\n");
            wolfSSL_free((WOLFSSL*)(uintptr_t)sslPtr);
            return SSL_FAILURE;
        }
        *g_cachedSSLObj = (*jenv)->NewGlobalRef(jenv, jcl);
        if (*g_cachedSSLObj == NULL) {
            printf("error storing global WolfSSLSession object\n");
            XFREE(g_cachedSSLObj, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            wolfSSL_free((WOLFSSL*)(uintptr_t)sslPtr);
            return SSL_FAILURE;
        }

        appData = (SSLAppData*)XMALLOC(sizeof(SSLAppData), NULL,
                                       DYNAMIC_TYPE_TMP_BUFFER);
        if (appData == NULL) {
            printf("error allocating memory in newSSL for SSLAppData\n");
            (*jenv)->DeleteGlobalRef(jenv, *g_cachedSSLObj);
            XFREE(g_cachedSSLObj, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            wolfSSL_free((WOLFSSL*)(uintptr_t)sslPtr);
            return SSL_FAILURE;
        }
        XMEMSET(appData, 0, sizeof(SSLAppData));

        /* store mutex lock in SSL app data, used for I/O and session lock.
         * This is freed in freeSSL. */
        jniSessLock = (wolfSSL_Mutex*)XMALLOC(sizeof(wolfSSL_Mutex), NULL,
                                              DYNAMIC_TYPE_TMP_BUFFER);
        if (!jniSessLock) {
            printf("error mallocing memory in newSSL for jniSessLock\n");
            (*jenv)->DeleteGlobalRef(jenv, *g_cachedSSLObj);
            XFREE(appData, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(g_cachedSSLObj, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            wolfSSL_free((WOLFSSL*)(uintptr_t)sslPtr);
            return SSL_FAILURE;
        }

        wc_InitMutex(jniSessLock);
        appData->jniSessLock = jniSessLock;

        /* cache associated WolfSSLSession jobject in native WOLFSSL */
        ret = wolfSSL_set_jobject((WOLFSSL*)(uintptr_t)sslPtr, g_cachedSSLObj);
        if (ret != SSL_SUCCESS) {
            printf("error storing jobject in wolfSSL native session\n");
            (*jenv)->DeleteGlobalRef(jenv, *g_cachedSSLObj);
            XFREE(appData, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(g_cachedSSLObj, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            wolfSSL_free((WOLFSSL*)(uintptr_t)sslPtr);
            return SSL_FAILURE;
        }

        /* cache SSLAppData into native WOLFSSL */
        if (wolfSSL_set_app_data(
                (WOLFSSL*)(uintptr_t)sslPtr, appData) != SSL_SUCCESS) {
            printf("error setting WOLFSSL app data in newSSL\n");
            (*jenv)->DeleteGlobalRef(jenv, *g_cachedSSLObj);
            XFREE(jniSessLock, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(appData, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(g_cachedSSLObj, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            wolfSSL_set_jobject((WOLFSSL*)(uintptr_t)sslPtr, NULL);
            wolfSSL_free((WOLFSSL*)(uintptr_t)sslPtr);
            return SSL_FAILURE;
        }
    }

    return sslPtr;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_setFd(JNIEnv* jenv,
    jobject jcl, jlong sslPtr, jobject jsock, jint type)
{
    int fd;
    jclass jcls;
    jfieldID fid;
    jobject impl;
    jobject fdesc;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL || ssl == NULL || jsock == NULL) {
        printf("Error: bad function args, native setFd() wrapper\n");
        return SSL_FAILURE;
    }

    /* get SocketImpl (type 1) or DatagramSocketImpl (2) from Java Socket */
    jcls = (*jenv)->GetObjectClass(jenv, jsock);
    if (type == 1) {
        /* Get SocketImpl field 'impl' from Socket class */
        fid = (*jenv)->GetFieldID(jenv, jcls, "impl", "Ljava/net/SocketImpl;");
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            printf("Error: Failed to get SocketImpl impl FieldID\n");
            return SSL_FAILURE;
        }
        /* Get SocketImpl 'impl' object */
        impl = (*jenv)->GetObjectField(jenv, jsock, fid);

        /* SocketImpl object may hold a delegate object inside on
         * some Java versions. Delegate SocketImpl is held inside 'impl'
         * object in field 'delegate'. Here we try to get the 'delegate'
         * field ID. If NULL, there is no 'delegate' member and we fall back
         * to using 'impl' directly. */
        jcls = (*jenv)->GetObjectClass(jenv, impl);
        fid = (*jenv)->GetFieldID(jenv, jcls, "delegate", "Ljava/net/SocketImpl;");
        if (fid != NULL) {
            /* delegate field exists, try to get object */
            impl = (*jenv)->GetObjectField(jenv, impl, fid);
            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
                /* Exception while getting delegate field, but does exist */
                printf("Error: Exception while getting SocketImpl delegate\n");
                return SSL_FAILURE;
            }
        } else {
            /* if delegate field does not exist, can cause NoSuchFieldError
             * exception. Clear out before continuing, but don't
             * print exception description (we expect it to happen). */
            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionClear(jenv);
            }
        }

    } else if (type == 2) {
        fid = (*jenv)->GetFieldID(jenv, jcls, "impl",
                "Ljava/net/DatagramSocketImpl;");
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            printf("Error: Exception while getting DatagramSocketImpl "
                   "impl FieldID\n");
            return SSL_FAILURE;
        }
        impl = (*jenv)->GetObjectField(jenv, jsock, fid);
    } else {
        printf("Invalid Socket class type, not supported\n");
        return SSL_FAILURE; /* invalid class type */
    }

    if (impl == NULL) {
        printf("Error: SocketImpl impl is NULL! Not valid\n");
        return SSL_FAILURE;
    }

    /* get FileDescriptor from SocketImpl */
    jcls = (*jenv)->GetObjectClass(jenv, impl);
    fid = (*jenv)->GetFieldID(jenv, jcls, "fd", "Ljava/io/FileDescriptor;");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        printf("Error: Exception while getting FileDescriptor fd FieldID\n");
        return SSL_FAILURE;
    }

    fdesc = (*jenv)->GetObjectField(jenv, impl, fid);
    if (fdesc == NULL) {
        printf("Error: FileDescriptor fd object is NULL!\n");
        return SSL_FAILURE;
    }

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
        printf("Error: Exception while getting fd/descriptor FieldID\n");
        return SSL_FAILURE;
    }

    if (jcls == NULL || fid == NULL) {
        printf("Error: jcls or fid NULL while getting fd/descriptor\n");
        return SSL_FAILURE;
    }

    fd = (*jenv)->GetIntField(jenv, fdesc, fid);

    /* set socket to non-blocking so we can use select() to detect
     * WANT_READ / WANT_WRITE */
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);

    return (jint)wolfSSL_set_fd(ssl, fd);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_useCertificateFile
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jstring file, jint format)
{
#if defined(OPENSSL_EXTRA) && !defined(NO_FILESYSTEM)
    jint ret = 0;
    const char* certFile;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL || ssl == NULL) {
        return SSL_FAILURE;
    }

    if (file == NULL) {
        return SSL_BAD_FILE;
    }

    certFile = (*jenv)->GetStringUTFChars(jenv, file, 0);

    ret = (jint) wolfSSL_use_certificate_file(ssl, certFile, (int)format);

    (*jenv)->ReleaseStringUTFChars(jenv, file, certFile);

    return ret;
#else
    (void)jenv;
    (void)jcl;
    (void)sslPtr;
    (void)file;
    (void)format;
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_usePrivateKeyFile
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jstring file, jint format)
{
#if defined(OPENSSL_EXTRA) && !defined(NO_FILESYSTEM)
    jint ret = 0;
    const char* keyFile;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL || ssl == NULL) {
        return SSL_FAILURE;
    }

    if (file == NULL) {
        return SSL_BAD_FILE;
    }

    keyFile = (*jenv)->GetStringUTFChars(jenv, file, 0);

    ret = (jint) wolfSSL_use_PrivateKey_file(ssl, keyFile, (int)format);

    (*jenv)->ReleaseStringUTFChars(jenv, file, keyFile);

    return ret;
#else
    (void)jenv;
    (void)jcl;
    (void)sslPtr;
    (void)file;
    (void)format;
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_useCertificateChainFile
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jstring file)
{
#if defined(OPENSSL_EXTRA) && !defined(NO_FILESYSTEM)
    jint ret = 0;
    const char* chainFile;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL || ssl == NULL) {
        return SSL_FAILURE;
    }

    if (file == NULL) {
        return SSL_BAD_FILE;
    }

    chainFile = (*jenv)->GetStringUTFChars(jenv, file, 0);

    ret = (jint) wolfSSL_use_certificate_chain_file(ssl, chainFile);

    (*jenv)->ReleaseStringUTFChars(jenv, file, chainFile);

    return ret;
#else
    (void)jenv;
    (void)jcl;
    (void)sslPtr;
    (void)file;
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setUsingNonblock
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jint nonblock)
{
    jclass excClass;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL) {
        return;
    }

    if (ssl == NULL) {
        excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return;
        }
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLSession object was null in setUsingNonblock");
    }

    wolfSSL_set_using_nonblock(ssl, nonblock);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_getUsingNonblock
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    jclass excClass;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL) {
        return 0;
    }

    if (ssl == NULL) {
        excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return 0;
        }
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLSession object was null in getUsingNonblock");
    }

    return wolfSSL_get_using_nonblock(ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_getFd
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    jclass excClass;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL) {
        return 0;
    }

    if (ssl == NULL) {
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

    return wolfSSL_get_fd(ssl);
}

/* enum values used in socketSelect() */
enum {
    WOLFJNI_SELECT_FAIL = -10,
    WOLFJNI_TIMEOUT     = -11,  /* also in WolfSSL.java */
    WOLFJNI_RECV_READY  = -12,
    WOLFJNI_SEND_READY  = -13,
    WOLFJNI_ERROR_READY = -14
};

/* perform a select() call on underlying socket to wait for socket to be ready
 * to read/write, or timeout. Note that we explicitly set the underlying
 * socket descriptor to non-blocking so we can select() on it.
 *
 * The Java socket timeout value representing no timeout is NULL, not 0 like
 * C. We adjust for this when handling timeout_ms here. timeout_ms is in
 * milliseconds. */
static int socketSelect(int sockfd, int timeout_ms, int rx)
{
    fd_set fds, errfds;
    fd_set* recvfds = NULL;
    fd_set* sendfds = NULL;
    int nfds = sockfd + 1;
    int result;
    struct timeval timeout;

    timeout.tv_sec = timeout_ms / 1000;
    timeout.tv_usec = (timeout_ms % 1000) * 1000;

    FD_ZERO(&fds);
    FD_SET(sockfd, &fds);
    FD_ZERO(&errfds);
    FD_SET(sockfd, &errfds);

    if (rx) {
        recvfds = &fds;
    } else {
        sendfds = &fds;
    }

    if (timeout_ms == 0) {
        result = select(nfds, recvfds, sendfds, &errfds, NULL);
    } else {
        result = select(nfds, recvfds, sendfds, &errfds, &timeout);
    }

    if (result == 0) {
        return WOLFJNI_TIMEOUT;
    } else if (result > 0) {
        if (FD_ISSET(sockfd, &fds)) {
            if (rx) {
                return WOLFJNI_RECV_READY;
            } else {
                return WOLFJNI_SEND_READY;
            }
        } else if (FD_ISSET(sockfd, &errfds)) {
            return WOLFJNI_ERROR_READY;
        }
    }

    return WOLFJNI_SELECT_FAIL;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_connect
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jint timeout)
{
    int ret = 0, err = 0, sockfd = 0;
    wolfSSL_Mutex* jniSessLock = NULL;
    SSLAppData* appData = NULL;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL || ssl == NULL) {
        return SSL_FAILURE;
    }

    /* make sure we don't have any outstanding exceptions pending */
    if ((*jenv)->ExceptionCheck(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return SSL_FAILURE;
    }

    /* get session mutex from SSL app data */
    appData = (SSLAppData*)wolfSSL_get_app_data(ssl);
    if (appData == NULL) {
        return WOLFSSL_FAILURE;
    }

    jniSessLock = appData->jniSessLock;
    if (jniSessLock == NULL) {
        return WOLFSSL_FAILURE;
    }

    do {
        /* get I/O lock */
        if (wc_LockMutex(jniSessLock) != 0) {
            ret = WOLFSSL_FAILURE;
            break;
        }

        ret = wolfSSL_connect(ssl);
        err = wolfSSL_get_error(ssl, ret);

        /* release I/O lock */
        if (wc_UnLockMutex(jniSessLock) != 0) {
            ret = WOLFSSL_FAILURE;
            break;
        }

        if (ret < 0 && ((err == SSL_ERROR_WANT_READ) ||
                        (err == SSL_ERROR_WANT_WRITE))) {

            sockfd = wolfSSL_get_fd(ssl);
            if (sockfd == -1) {
                /* For I/O that does not use sockets, sockfd may be -1,
                 * skip try to call select() */
                break;
            }

            ret = socketSelect(sockfd, (int)timeout, 1);
            if (ret == WOLFJNI_RECV_READY || ret == WOLFJNI_SEND_READY) {
                /* I/O ready, continue handshake and try again */
                continue;
            } else if (ret == WOLFJNI_TIMEOUT) {
                /* Java will throw SocketTimeoutException */
                break;
            } else {
                /* error */
                ret = SSL_FAILURE;
                break;
            }
        }

    } while (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ);

    /* check for Java exceptions beofre returning */
    if ((*jenv)->ExceptionCheck(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return SSL_FAILURE;
    }

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_write
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jbyteArray raw, jint length,
   jint timeout)
{
    byte* data;
    int ret = SSL_FAILURE, err, sockfd;
    wolfSSL_Mutex* jniSessLock = NULL;
    SSLAppData* appData = NULL;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL || ssl == NULL || raw == NULL) {
        return BAD_FUNC_ARG;
    }

    if (length >= 0) {
        data = (byte*)(*jenv)->GetByteArrayElements(jenv, raw, NULL);
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return SSL_FAILURE;
        }

        /* get session mutex from SSL app data */
        appData = (SSLAppData*)wolfSSL_get_app_data(ssl);
        if (appData == NULL) {
            return WOLFSSL_FAILURE;
        }

        jniSessLock = appData->jniSessLock;
        if (jniSessLock == NULL) {
            (*jenv)->ReleaseByteArrayElements(jenv, raw, (jbyte*)data,
                    JNI_ABORT);
            return SSL_FAILURE;
        }

        do {

            /* lock mutex around session I/O before write attempt */
            if (wc_LockMutex(jniSessLock) != 0) {
                ret = WOLFSSL_FAILURE;
                break;
            }

            ret = wolfSSL_write(ssl, data, length);
            err = wolfSSL_get_error(ssl, ret);

            /* unlock mutex around session I/O after write attempt */
            if (wc_UnLockMutex(jniSessLock) != 0) {
                ret = WOLFSSL_FAILURE;
                break;
            }

            if (ret >= 0) /* return if it is success */
                break;

            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {

                sockfd = wolfSSL_get_fd(ssl);
                if (sockfd == -1) {
                    /* For I/O that does not use sockets, sockfd may be -1,
                     * skip try to call select() */
                    break;
                }

                ret = socketSelect(sockfd, (int)timeout, 0);
                if (ret == WOLFJNI_RECV_READY || ret == WOLFJNI_SEND_READY) {
                    /* loop around and try wolfSSL_write() again */
                    continue;
                } else {
                    /* error or timeout occurred during select */
                    ret = WOLFSSL_FAILURE;
                    break;
                }
            }

        } while (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ);

        (*jenv)->ReleaseByteArrayElements(jenv, raw, (jbyte*)data, JNI_ABORT);

        return ret;

    } else {
        return SSL_FAILURE;
    }
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_read(JNIEnv* jenv,
    jobject jcl, jlong sslPtr, jbyteArray raw, jint length, int timeout)
{
    byte* data;
    int size = 0, ret, err, sockfd;
    wolfSSL_Mutex* jniSessLock = NULL;
    SSLAppData* appData = NULL;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL || ssl == NULL || raw == NULL) {
        return BAD_FUNC_ARG;
    }

    if (length >= 0) {
        data = (byte*)(*jenv)->GetByteArrayElements(jenv, raw, NULL);
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return SSL_FAILURE;
        }

        /* get session mutex from SSL app data */
        appData = (SSLAppData*)wolfSSL_get_app_data(ssl);
        if (appData == NULL) {
            return WOLFSSL_FAILURE;
        }

        jniSessLock = appData->jniSessLock;
        if (jniSessLock == NULL) {
            (*jenv)->ReleaseByteArrayElements(jenv, raw, (jbyte*)data,
                    JNI_ABORT);
            return WOLFSSL_FAILURE;
        }

        do {
            /* lock mutex around session I/O before read attempt */
            if (wc_LockMutex(jniSessLock) != 0) {
                size = WOLFSSL_FAILURE;
                break;
            }

            size = wolfSSL_read(ssl, data, length);
            err = wolfSSL_get_error(ssl, size);

            /* unlock mutex around session I/O after read attempt */
            if (wc_UnLockMutex(jniSessLock) != 0) {
                size = WOLFSSL_FAILURE;
                break;
            }

            if (size < 0 && ((err == SSL_ERROR_WANT_READ) || \
                             (err == SSL_ERROR_WANT_WRITE))) {

                sockfd = wolfSSL_get_fd(ssl);
                if (sockfd == -1) {
                    /* For I/O that does not use sockets, sockfd may be -1,
                     * skip try to call select() */
                    break;
                }

                ret = socketSelect(sockfd, timeout, 1);
                if (ret == WOLFJNI_RECV_READY || ret == WOLFJNI_SEND_READY) {
                    /* loop around and try wolfSSL_read() again */
                    continue;
                } else {
                    /* error or timeout occurred during select */
                    size = ret;
                    break;
                }
            }

        } while (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ);

        /* JNI_COMMIT commits the data but does not free the local array
         * 0 is used here to both commit and free */
        (*jenv)->ReleaseByteArrayElements(jenv, raw, (jbyte*)data, 0);
    }

    return size;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_accept
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    int ret = 0, err, sockfd;
    wolfSSL_Mutex* jniSessLock = NULL;
    SSLAppData* appData = NULL;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL || ssl == NULL) {
        return SSL_FATAL_ERROR;
    }

    /* make sure we don't have any outstanding exceptions pending */
    if ((*jenv)->ExceptionCheck(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return SSL_FAILURE;
    }

    /* get session mutex from SSL app data */
    appData = (SSLAppData*)wolfSSL_get_app_data(ssl);
    if (appData == NULL) {
        return WOLFSSL_FAILURE;
    }

    jniSessLock = appData->jniSessLock;
    if (jniSessLock == NULL) {
        return SSL_FAILURE;
    }

    do {
        /* get I/O lock */
        if (wc_LockMutex(jniSessLock) != 0) {
            ret = WOLFSSL_FAILURE;
            break;
        }

        ret = wolfSSL_accept(ssl);
        err = wolfSSL_get_error(ssl, ret);

        /* release I/O lock */
        if (wc_UnLockMutex(jniSessLock) != 0) {
            ret = WOLFSSL_FAILURE;
            break;
        }

        if (ret < 0 && ((err == SSL_ERROR_WANT_READ) ||
                        (err == SSL_ERROR_WANT_WRITE))) {

            sockfd = wolfSSL_get_fd(ssl);
            if (sockfd == -1) {
                /* For I/O that does not use sockets, sockfd may be -1,
                 * skip try to call select() */
                break;
            }

            ret = socketSelect(sockfd, 0, 1);
            if (ret == WOLFJNI_RECV_READY || ret == WOLFJNI_SEND_READY) {
                /* I/O ready, continue handshake and try again */
                continue;
            } else {
                /* error or timeout */
                break;
            }
        }

    } while (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ);

    /* check for Java exceptions beofre returning */
    if ((*jenv)->ExceptionCheck(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return SSL_FAILURE;
    }

    return ret;
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_freeSSL
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    jobject* g_cachedSSLObj;
    jobject* g_cachedVerifyCb;
    jclass excClass;
    SSLAppData* appData;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;
#if defined(HAVE_PK_CALLBACKS) && (defined(HAVE_ECC) || !defined(NO_RSA))
    internCtx* pkCtx = NULL;
#endif

    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");

    if (ssl == NULL) {
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return;
        }
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLSession object was null in freeSSL");
        return;
    }

    /* free session mutex lock */
    appData = (SSLAppData*)wolfSSL_get_app_data(ssl);
    if (appData != NULL) {
        if (appData->jniSessLock != NULL) {
            wc_FreeMutex(appData->jniSessLock);
            XFREE(appData->jniSessLock, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            appData->jniSessLock = NULL;
        }
        g_cachedVerifyCb = appData->g_verifySSLCbIfaceObj;
        if (g_cachedVerifyCb != NULL) {
            (*jenv)->DeleteGlobalRef(jenv, (jobject)(*g_cachedVerifyCb));
            XFREE(g_cachedVerifyCb, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            g_cachedVerifyCb = NULL;
        }
        /* free appData */
        XFREE(appData, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        appData = NULL;
    }

    /* delete global WolfSSLSession object reference */
    g_cachedSSLObj = (jobject*) wolfSSL_get_jobject(ssl);
    if (g_cachedSSLObj != NULL) {
        (*jenv)->DeleteGlobalRef(jenv, (jobject)(*g_cachedSSLObj));
        XFREE(g_cachedSSLObj, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        g_cachedSSLObj = NULL;
    }

    /* reset internal pointer to NULL to prevent accidental usage */
    if (wolfSSL_set_jobject(ssl, NULL) != SSL_SUCCESS) {
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return;
        }
        (*jenv)->ThrowNew(jenv, excClass,
                "Error reseting internal wolfSSL JNI pointer to NULL, freeSSL");
        return;
    }

#ifdef HAVE_CRL
    /* release global CRL callback ref if registered */
    if (g_crlCbIfaceObj != NULL) {
        (*jenv)->DeleteGlobalRef(jenv, g_crlCbIfaceObj);
        g_crlCbIfaceObj = NULL;
    }
#endif

#if defined(HAVE_PK_CALLBACKS)
    #ifdef HAVE_ECC
        /* free ECC sign callback CTX global reference if set */
        pkCtx = (internCtx*) wolfSSL_GetEccSignCtx(ssl);
        if (pkCtx != NULL) {
            if (pkCtx->obj != NULL) {
                (*jenv)->DeleteGlobalRef(jenv, pkCtx->obj);
            }
            XFREE(pkCtx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }

        /* free ECC verify callback CTX global reference if set */
        pkCtx = (internCtx*)wolfSSL_GetEccVerifyCtx(ssl);
        if (pkCtx != NULL) {
            if (pkCtx->obj != NULL) {
                (*jenv)->DeleteGlobalRef(jenv, pkCtx->obj);
            }
            XFREE(pkCtx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }

        /* free ECC shared secret callback CTX global reference if set */
        pkCtx = (internCtx*)wolfSSL_GetEccSharedSecretCtx(ssl);
        if (pkCtx != NULL) {
            if (pkCtx->obj != NULL) {
                (*jenv)->DeleteGlobalRef(jenv, pkCtx->obj);
            }
            XFREE(pkCtx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }
    #endif /* HAVE_ECC */

    #ifndef NO_RSA
        /* free RSA sign callback CTX global reference if set */
        pkCtx = (internCtx*) wolfSSL_GetRsaSignCtx(ssl);
        if (pkCtx != NULL) {
            if (pkCtx->obj != NULL) {
                (*jenv)->DeleteGlobalRef(jenv, pkCtx->obj);
            }
            XFREE(pkCtx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }

        /* free RSA verify callback CTX global reference if set */
        pkCtx = (internCtx*)wolfSSL_GetRsaVerifyCtx(ssl);
        if (pkCtx != NULL) {
            if (pkCtx->obj != NULL) {
                (*jenv)->DeleteGlobalRef(jenv, pkCtx->obj);
            }
            XFREE(pkCtx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }

        /* free RSA encrypt callback CTX global reference if set */
        pkCtx = (internCtx*) wolfSSL_GetRsaEncCtx(ssl);
        if (pkCtx != NULL) {
            if (pkCtx->obj != NULL) {
                (*jenv)->DeleteGlobalRef(jenv, pkCtx->obj);
            }
            XFREE(pkCtx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }

        /* free RSA decrypt callback CTX global reference if set */
        pkCtx = (internCtx*) wolfSSL_GetRsaDecCtx(ssl);
        if (pkCtx != NULL) {
            if (pkCtx->obj != NULL) {
                (*jenv)->DeleteGlobalRef(jenv, pkCtx->obj);
            }
            XFREE(pkCtx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }
    #endif /* !NO_RSA */
#endif /* HAVE_PK_CALLBACKS */

    /* native cleanup */
    wolfSSL_free(ssl);
    ssl = 0;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_shutdownSSL
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jint timeout)
{
    int ret = 0, err, sockfd;
    wolfSSL_Mutex* jniSessLock;
    SSLAppData* appData = NULL;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL) {
        return SSL_FAILURE;
    }

    /* make sure we don't have any outstanding exceptions pending */
    if ((*jenv)->ExceptionCheck(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return SSL_FAILURE;
    }

    /* get session mutex from SSL app data */
    appData = (SSLAppData*)wolfSSL_get_app_data(ssl);
    if (appData == NULL) {
        return WOLFSSL_FAILURE;
    }

    jniSessLock = appData->jniSessLock;
    if (jniSessLock == NULL) {
        return WOLFSSL_FAILURE;
    }

    do {
        /* get I/O lock */
        if (wc_LockMutex(jniSessLock) != 0) {
            ret = WOLFSSL_FAILURE;
            break;
        }

        ret = wolfSSL_shutdown(ssl);
        err = wolfSSL_get_error(ssl, ret);

        /* release I/O lock */
        if (wc_UnLockMutex(jniSessLock) != 0) {
            ret = WOLFSSL_FAILURE;
            break;
        }

        if (ret < 0 && ((err == SSL_ERROR_WANT_READ) ||
                        (err == SSL_ERROR_WANT_WRITE))) {

            sockfd = wolfSSL_get_fd(ssl);
            if (sockfd == -1) {
                /* For I/O that does not use sockets, sockfd may be -1,
                 * skip try to call select() */
                break;
            }

            ret = socketSelect(sockfd, timeout, 1);
            if (ret == WOLFJNI_RECV_READY || ret == WOLFJNI_SEND_READY) {
                /* I/O ready, continue handshake and try again */
                continue;
            } else {
                /* error or timeout */
                break;
            }
        }

    } while (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ);

    /* check for Java exceptions beofre returning */
    if ((*jenv)->ExceptionCheck(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return SSL_FAILURE;
    }

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_getError
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jint ret)
{
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL) {
        return SSL_FAILURE;
    }

    /* wolfSSL checks ssl for NULL */
    return wolfSSL_get_error(ssl, ret);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_setSession
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jlong sessionPtr)
{
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    WOLFSSL_SESSION* session = (WOLFSSL_SESSION*)(uintptr_t)sessionPtr;
    (void)jcl;

    if (jenv == NULL || ssl == NULL) {
        return SSL_FAILURE;
    }

    /* wolfSSL checks session for NULL, but not ssl */
    return wolfSSL_set_session(ssl, session);
}

JNIEXPORT jlong JNICALL Java_com_wolfssl_WolfSSLSession_getSession
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jenv;
    (void)jcl;

    /* wolfSSL checks ssl for NULL */
    return (jlong)(uintptr_t)wolfSSL_get_session(ssl);
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_WolfSSLSession_getSessionID
  (JNIEnv* jenv, jobject jcl, jlong sessionPtr)
{
    unsigned int sz;
    const unsigned char* id;
    jbyteArray ret;
    WOLFSSL_SESSION* session = (WOLFSSL_SESSION*)(uintptr_t)sessionPtr;

    id = wolfSSL_SESSION_get_id(session, &sz);
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
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jlong t)
{
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jenv;
    (void)jcl;

    return wolfSSL_set_timeout(ssl, (unsigned int)t);
}

JNIEXPORT jlong JNICALL Java_com_wolfssl_WolfSSLSession_getTimeout
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jenv;
    (void)jcl;

    return wolfSSL_get_timeout(ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_setSessTimeout
  (JNIEnv* jenv, jobject jcl, jlong sessionPtr, jlong sz)
{
    WOLFSSL_SESSION* session = (WOLFSSL_SESSION*)(uintptr_t)sessionPtr;
    (void)jenv;
    (void)jcl;

    return wolfSSL_SSL_SESSION_set_timeout(session, sz);
}

JNIEXPORT jlong JNICALL Java_com_wolfssl_WolfSSLSession_getSessTimeout
  (JNIEnv* jenv, jobject jcl, jlong sessionPtr)
{
    WOLFSSL_SESSION* session = (WOLFSSL_SESSION*)(uintptr_t)sessionPtr;
    (void)jenv;
    (void)jcl;

    return wolfSSL_SESSION_get_timeout(session);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_setCipherList
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jstring list)
{

    jint ret = 0;
    const char* cipherList;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL || ssl == NULL || list == NULL) {
        return SSL_FAILURE;
    }

    cipherList= (*jenv)->GetStringUTFChars(jenv, list, 0);

    ret = (jint) wolfSSL_set_cipher_list(ssl, cipherList);

    (*jenv)->ReleaseStringUTFChars(jenv, list, cipherList);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_dtlsGetCurrentTimeout
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
#if !defined(WOLFSSL_LEANPSK) && defined(WOLFSSL_DTLS)
    jclass excClass;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (ssl == NULL) {
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

    return wolfSSL_dtls_get_current_timeout(ssl);
#else
    (void)jenv;
    (void)jcl;
    (void)sslPtr;
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_dtlsGotTimeout
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
#if !defined(WOLFSSL_LEANPSK) && defined(WOLFSSL_DTLS)
    jclass excClass;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (ssl == NULL) {
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

    return wolfSSL_dtls_got_timeout(ssl);
#else
    (void)jenv;
    (void)jcl;
    (void)sslPtr;
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_dtls
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    jclass excClass;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (ssl == NULL) {
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

    return wolfSSL_dtls(ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_dtlsSetPeer
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jobject peer)
{
    int ret;
    jstring ipAddr = NULL;
    struct sockaddr_in sa;
    const char* ipAddress = NULL;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL || ssl == NULL || peer == NULL) {
        return SSL_FAILURE;
    }

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
    ret = wolfSSL_dtls_set_peer(ssl, &sa, sizeof(sa));

    if (!isAny) {
        (*jenv)->ReleaseStringUTFChars(jenv, ipAddr, ipAddress);
    }

    return ret;
}

JNIEXPORT jobject JNICALL Java_com_wolfssl_WolfSSLSession_dtlsGetPeer
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    int ret, port;
    unsigned int peerSz;
    struct sockaddr_in peer;
    char* ipAddrString;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;

    jmethodID constr;
    jstring ipAddr;

    (void)jcl;

    if (jenv == NULL || ssl == NULL) {
        return NULL;
    }

    /* get native sockaddr_in peer */
    memset(&peer, 0, sizeof(peer));
    peerSz = sizeof(peer);
    ret = wolfSSL_dtls_get_peer(ssl, &peer, &peerSz);
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
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    jclass excClass;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (ssl == NULL) {
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

    return wolfSSL_session_reused(ssl);
}

JNIEXPORT jlong JNICALL Java_com_wolfssl_WolfSSLSession_getPeerCertificate
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
#ifdef KEEP_PEER_CERT
    WOLFSSL_X509* x509 = NULL;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jenv;
    (void)jcl;

    if (ssl == NULL) {
        return (jlong)0;
    }

    x509 = wolfSSL_get_peer_certificate(ssl);

    return (jlong)(uintptr_t)x509;
#else
    (void)jenv;
    (void)jcl;
    (void)sslPtr;
    return (jlong)0;
#endif
}

JNIEXPORT jstring JNICALL Java_com_wolfssl_WolfSSLSession_getPeerX509Issuer
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jlong x509Ptr)
{

#if defined(KEEP_PEER_CERT) || defined(SESSION_CERTS)
    char* issuer;
    jstring retString;
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)(uintptr_t)x509Ptr;
    (void)sslPtr;
    (void)jcl;

    if (x509 == NULL) {
        return NULL;
    }

    issuer = wolfSSL_X509_NAME_oneline(
            wolfSSL_X509_get_issuer_name(x509), 0, 0);

    retString = (*jenv)->NewStringUTF(jenv, issuer);
    XFREE(issuer, 0, DYNAMIC_TYPE_OPENSSL);

    return retString;

#else
    (void)jenv;
    (void)jcl;
    (void)sslPtr;
    (void)x509Ptr;
    return NULL;
#endif
}

JNIEXPORT jstring JNICALL Java_com_wolfssl_WolfSSLSession_getPeerX509Subject
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jlong x509Ptr)
{

#if defined(KEEP_PEER_CERT) || defined(SESSION_CERTS)
    char* subject;
    jstring retString;
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)(uintptr_t)x509Ptr;
    (void)sslPtr;
    (void)jcl;

    if (x509 == NULL) {
        return NULL;
    }

    subject = wolfSSL_X509_NAME_oneline(
            wolfSSL_X509_get_subject_name(x509), 0, 0);

    retString = (*jenv)->NewStringUTF(jenv, subject);
    XFREE(subject, 0, DYNAMIC_TYPE_OPENSSL);

    return retString;

#else
    (void)jenv;
    (void)jcl;
    (void)sslPtr;
    (void)x509Ptr;
    return NULL;
#endif
}

JNIEXPORT jstring JNICALL Java_com_wolfssl_WolfSSLSession_getPeerX509AltName
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jlong x509Ptr)
{
#if defined(KEEP_PEER_CERT) || defined(SESSION_CERTS)
    char* altname;
    jstring retString;
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)(uintptr_t)x509Ptr;
    (void)jcl;
    (void)sslPtr;

    if (x509 == NULL) {
        return NULL;
    }

    altname = wolfSSL_X509_get_next_altname(x509);

    retString = (*jenv)->NewStringUTF(jenv, altname);
    return retString;

#else
    (void)jenv;
    (void)jcl;
    (void)sslPtr;
    (void)x509Ptr;
    return NULL;
#endif
}

JNIEXPORT jstring JNICALL Java_com_wolfssl_WolfSSLSession_getVersion
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    jclass excClass;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (ssl == NULL) {
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

    return (*jenv)->NewStringUTF(jenv, wolfSSL_get_version(ssl));
}

JNIEXPORT jlong JNICALL Java_com_wolfssl_WolfSSLSession_getCurrentCipher
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    jclass excClass;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (ssl == NULL) {
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

    return (jlong)(uintptr_t)wolfSSL_get_current_cipher(ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_checkDomainName
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jstring dn)
{
    int ret;
    const char* dname;
    jclass excClass;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if(dn == NULL) {
        return SSL_FAILURE;
    }

    if (ssl == NULL) {
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

    ret = wolfSSL_check_domain_name(ssl, dname);

    (*jenv)->ReleaseStringUTFChars(jenv, dn, dname);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_setTmpDH
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jbyteArray p, jint pSz,
   jbyteArray g, jint gSz)
{
#ifndef NO_DH
    unsigned char pBuf[pSz];
    unsigned char gBuf[gSz];
    jclass excClass;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL || p == NULL || g == NULL) {
        return BAD_FUNC_ARG;
    }

    if (ssl == NULL) {
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

    return wolfSSL_SetTmpDH(ssl, pBuf, pSz, gBuf, gSz);
#else
    (void)jenv;
    (void)jcl;
    (void)sslPtr;
    (void)p;
    (void)pSz;
    (void)g;
    (void)gSz;
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_setTmpDHFile
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jstring file, jint format)
{
#if !defined(NO_DH) && !defined(NO_FILESYSTEM)
    int ret;
    const char* fname;
    jclass excClass;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (file == NULL) {
        return SSL_BAD_FILE;
    }

    if (ssl == NULL) {
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

    ret = wolfSSL_SetTmpDH_file(ssl, fname, format);

    (*jenv)->ReleaseStringUTFChars(jenv, file, fname);

    return ret;
#else
    (void)jenv;
    (void)jcl;
    (void)sslPtr;
    (void)file;
    (void)format;
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_useCertificateBuffer
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jbyteArray in, jlong sz,
   jint format)
{
    unsigned char buff[sz];
    jclass excClass;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL || in == NULL) {
        return BAD_FUNC_ARG;
    }

    if (ssl == NULL) {
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

    return wolfSSL_use_certificate_buffer(ssl, buff, sz, format);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_usePrivateKeyBuffer
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jbyteArray in, jlong sz,
   jint format)
{
    unsigned char buff[sz];
    jclass excClass;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL || in == NULL) {
        return BAD_FUNC_ARG;
    }

    if (ssl == NULL) {
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

    return wolfSSL_use_PrivateKey_buffer(ssl, buff, sz, format);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_useCertificateChainBuffer
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jbyteArray in, jlong sz)
{
    unsigned char buff[sz];
    jclass excClass;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL || in == NULL) {
        return BAD_FUNC_ARG;
    }

    if (ssl == NULL) {
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

    return wolfSSL_use_certificate_chain_buffer(ssl, buff, sz);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_setGroupMessages
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    jclass excClass;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (ssl == NULL) {
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
    return wolfSSL_set_group_messages(ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_enableCRL
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jint options)
{
#ifdef HAVE_CRL
    jclass excClass;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL) {
        return BAD_FUNC_ARG;
    }

    if (ssl == NULL) {
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

    return wolfSSL_EnableCRL(ssl, options);
#else
    (void)jenv;
    (void)jcl;
    (void)sslPtr;
    (void)options;
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_disableCRL
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
#ifdef HAVE_CRL
    jclass excClass;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL) {
        return BAD_FUNC_ARG;
    }

    if (ssl == NULL) {
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

    return wolfSSL_DisableCRL(ssl);
#else
    (void)jenv;
    (void)jcl;
    (void)sslPtr;
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_loadCRL
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jstring path, jint type,
   jint monitor)
{
#if defined(HAVE_CRL) && !defined(NO_FILESYSTEM)
    int ret;
    const char* crlPath;
    jclass excClass;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL || path == NULL) {
        return BAD_FUNC_ARG;
    }

    if (ssl == NULL) {
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

    ret = wolfSSL_LoadCRL(ssl, crlPath, type, monitor);

    (*jenv)->ReleaseStringUTFChars(jenv, path, crlPath);

    return ret;
#else
    (void)jenv;
    (void)jcl;
    (void)sslPtr;
    (void)path;
    (void)type;
    (void)monitor;
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_setCRLCb
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jobject cb)
{
#ifdef HAVE_CRL
    int    ret = 0;
    jclass excClass;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL) {
        return BAD_FUNC_ARG;
    }

    /* find exception class in case we need it */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return SSL_FAILURE;
    }

    if (ssl == NULL) {
        (*jenv)->ThrowNew(jenv, excClass,
            "Input WolfSSLSession object was NULL in "
            "setCRLCb");
        return SSL_FAILURE;
    }

    /* release global CRL callback ref if already registered */
    if (g_crlCbIfaceObj != NULL) {
        (*jenv)->DeleteGlobalRef(jenv, g_crlCbIfaceObj);
        g_crlCbIfaceObj = NULL;
    }

    if (cb != NULL) {
        /* store Java CRL callback Interface object */
        g_crlCbIfaceObj = (*jenv)->NewGlobalRef(jenv, cb);
        if (g_crlCbIfaceObj == NULL) {
            (*jenv)->ThrowNew(jenv, excClass,
                   "Error storing global missingCRLCallback interface");
        }

        ret = wolfSSL_SetCRL_Cb(ssl, NativeMissingCRLCallback);
    }

    return ret;
#else
    (void)jenv;
    (void)jcl;
    (void)sslPtr;
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
  (JNIEnv* jenv, jclass jcl, jlong sslPtr)
{
    const char* cipherName;
    WOLFSSL_CIPHER* cipher;
    jclass excClass;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (ssl == NULL) {
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

    cipher = wolfSSL_get_current_cipher(ssl);

    if (cipher != NULL) {
        cipherName = wolfSSL_CIPHER_get_name(cipher);
        return (*jenv)->NewStringUTF(jenv, cipherName);
    } else {
        return (*jenv)->NewStringUTF(jenv, "NONE");
    }
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_WolfSSLSession_getMacSecret
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jint verify)
{
    jclass excClass;
#ifdef ATOMIC_USER
    int macLength;
    jbyteArray retSecret;
    const unsigned char* secret;
#endif
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    /* find exception class */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return NULL;
    }

#ifdef ATOMIC_USER
    if (ssl == NULL) {
        (*jenv)->ThrowNew(jenv, excClass,
            "Input WolfSSLSession object was null in "
            "getMacSecret");
        return NULL;
    }

    secret = wolfSSL_GetMacSecret(ssl, (int)verify);

    if (secret != NULL) {

        /* get mac size */
        macLength = wolfSSL_GetHmacSize(ssl);

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
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    jclass excClass;
#ifdef ATOMIC_USER
    int keyLength;
    jbyteArray retKey;
    const unsigned char* key;
#endif
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    /* find exception class */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return NULL;
    }

#ifdef ATOMIC_USER
    if (ssl == NULL) {
        (*jenv)->ThrowNew(jenv, excClass,
            "Input WolfSSLSession object was null in "
            "getClientWriteKey");
        return NULL;
    }

    key = wolfSSL_GetClientWriteKey(ssl);
    if (key != NULL) {

        /* get key size */
        keyLength = wolfSSL_GetKeySize(ssl);

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
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    jclass excClass;
#ifdef ATOMIC_USER
    jbyteArray retIV;
    const unsigned char* iv;
    int ivLength;
#endif
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    /* find exception class */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return NULL;
    }

#ifdef ATOMIC_USER
    if (ssl == NULL) {
        (*jenv)->ThrowNew(jenv, excClass,
            "Input WolfSSLSession object was null in "
            "getClientWriteIV");
        return NULL;
    }

    iv = wolfSSL_GetClientWriteIV(ssl);
    if (iv != NULL) {

        /* get iv size, is block size for what wolfSSL supports */
        ivLength = wolfSSL_GetCipherBlockSize(ssl);

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
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    jclass excClass;
#ifdef ATOMIC_USER
    jbyteArray retKey;
    const unsigned char* key;
    int keyLength;
#endif
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    /* find exception class */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return NULL;
    }

#ifdef ATOMIC_USER
    if (ssl == NULL) {
        (*jenv)->ThrowNew(jenv, excClass,
            "Input WolfSSLSession object was null in "
            "getServerWriteKey");
        return NULL;
    }

    key = wolfSSL_GetServerWriteKey(ssl);
    if (key != NULL) {

        /* get key size */
        keyLength = wolfSSL_GetKeySize(ssl);

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
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    jclass excClass;
#ifdef ATOMIC_USER
    jbyteArray retIV;
    const unsigned char* iv;
    int ivLength;
#endif
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    /* find exception class */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return NULL;
    }

#ifdef ATOMIC_USER
    if (ssl == NULL) {
        (*jenv)->ThrowNew(jenv, excClass,
            "Input WolfSSLSession object was null in "
            "getServerWriteIV");
        return NULL;
    }

    iv = wolfSSL_GetServerWriteIV(ssl);
    if (iv != NULL) {

        /* get iv size, is block size for what wolfSSL supports */
        ivLength = wolfSSL_GetCipherBlockSize(ssl);

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
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jbyteArray inner, jlong sz,
   jint content, jint verify)
{
    int ret = 0;
    unsigned char hmacInner[WOLFSSL_TLS_HMAC_INNER_SZ];
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL || inner == NULL || ssl == NULL) {
        return BAD_FUNC_ARG;
    }

    /* find exception class */
    jclass excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return -1;
    }

    ret = wolfSSL_SetTlsHmacInner(ssl, hmacInner, sz, content, verify);

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
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    jclass         excClass;
#if defined(HAVE_PK_CALLBACKS) && defined(HAVE_ECC)
    jclass         sslClass;

    void*          eccSignCtx;
    internCtx*     myCtx;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
#endif

    /* find exception class in case we need it */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return;
    }

#if defined(HAVE_PK_CALLBACKS) && defined(HAVE_ECC)
    if (ssl == NULL) {
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
    eccSignCtx = (internCtx*) wolfSSL_GetEccSignCtx(ssl);

    /* note: if CTX has not been set up yet, wolfSSL defaults to NULL */
    if (eccSignCtx != NULL) {
        myCtx = (internCtx*)eccSignCtx;
        if (myCtx != NULL) {
            if (myCtx->active == 1) {
                (*jenv)->DeleteGlobalRef(jenv, myCtx->obj);
            }
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

    wolfSSL_SetEccSignCtx(ssl, myCtx);
#else
    (void)jcl;
    (void)sslPtr;
    (*jenv)->ThrowNew(jenv, excClass,
        "wolfSSL not compiled with PK Callbacks and/or ECC");
    return;
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setEccVerifyCtx
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    jclass         excClass;
#if defined(HAVE_PK_CALLBACKS) && defined(HAVE_ECC)
    jclass         sslClass;

    void*          eccVerifyCtx;
    internCtx*     myCtx;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
#endif

    /* find exception class in case we need it */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return;
    }

#if defined(HAVE_PK_CALLBACKS) && defined(HAVE_ECC)
    if (ssl == NULL) {
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
    eccVerifyCtx = (internCtx*)wolfSSL_GetEccVerifyCtx(ssl);

    /* note: if CTX has not been set up yet, wolfSSL defaults to NULL */
    if (eccVerifyCtx != NULL) {
        myCtx = (internCtx*)eccVerifyCtx;
        if (myCtx != NULL) {
            if (myCtx->active == 1) {
                (*jenv)->DeleteGlobalRef(jenv, myCtx->obj);
            }
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
    if (myCtx->obj == NULL) {
        (*jenv)->ThrowNew(jenv, excClass,
               "Unable to store WolfSSLSession object as global reference");
        return;
    }

    wolfSSL_SetEccVerifyCtx(ssl, myCtx);
#else
    (void)jcl;
    (void)sslPtr;
    (*jenv)->ThrowNew(jenv, excClass,
        "wolfSSL not compiled with PK Callbacks and/or ECC");
    return;
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setEccSharedSecretCtx
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    jclass         excClass;
#if defined(HAVE_PK_CALLBACKS) && defined(HAVE_ECC)
    jclass         sslClass;

    void*          eccSharedSecretCtx;
    internCtx*     myCtx;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
#endif

    /* find exception class in case we need it */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return;
    }

#if defined(HAVE_PK_CALLBACKS) && defined(HAVE_ECC)
    if (ssl == NULL) {
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
    eccSharedSecretCtx = (internCtx*) wolfSSL_GetEccSharedSecretCtx(ssl);

    /* note: if CTX has not been set up yet, wolfSSL defaults to NULL */
    if (eccSharedSecretCtx != NULL) {
        myCtx = (internCtx*)eccSharedSecretCtx;
        if (myCtx != NULL) {
            if (myCtx->active == 1) {
                (*jenv)->DeleteGlobalRef(jenv, myCtx->obj);
            }
            XFREE(myCtx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }
    }

    /* allocate memory for internal JNI object reference */
    myCtx = XMALLOC(sizeof(internCtx), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (myCtx == NULL) {
        (*jenv)->ThrowNew(jenv, excClass,
                "Unable to allocate memory for ECC shared secret context\n");
        return;
    }

    /* set CTX as active */
    myCtx->active = 1;

    /* store global ref to WolfSSLSession object */
    myCtx->obj = (*jenv)->NewGlobalRef(jenv, jcl);
    if (myCtx->obj == NULL) {
        (*jenv)->ThrowNew(jenv, excClass,
               "Unable to store WolfSSLSession object as global reference");
        return;
    }

    wolfSSL_SetEccSharedSecretCtx(ssl, myCtx);
#else
    (void)jcl;
    (void)sslPtr;
    (*jenv)->ThrowNew(jenv, excClass,
        "wolfSSL not compiled with PK Callbacks and/or ECC");
    return;
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setRsaSignCtx
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    jclass         excClass;
#if defined(HAVE_PK_CALLBACKS) && !defined(NO_RSA)
    jclass         sslClass;

    void*          rsaSignCtx;
    internCtx*     myCtx;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
#endif

    /* find exception class in case we need it */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return;
    }

#if defined(HAVE_PK_CALLBACKS) && !defined(NO_RSA)
    if (ssl == NULL) {
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
    rsaSignCtx = (internCtx*) wolfSSL_GetRsaSignCtx(ssl);

    /* note: if CTX has not been set up yet, wolfSSL defaults to NULL */
    if (rsaSignCtx != NULL) {
        myCtx = (internCtx*)rsaSignCtx;
        if (myCtx != NULL) {
            if (myCtx->active == 1) {
                (*jenv)->DeleteGlobalRef(jenv, myCtx->obj);
            }
            XFREE(myCtx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }
    }

    /* allocate memory for internal JNI object reference */
    myCtx = XMALLOC(sizeof(internCtx), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (myCtx == NULL) {
        (*jenv)->ThrowNew(jenv, excClass,
                "Unable to allocate memory for RSA sign context\n");
        return;
    }

    /* set CTX as active */
    myCtx->active = 1;

    /* store global ref to WolfSSLSession object */
    myCtx->obj = (*jenv)->NewGlobalRef(jenv, jcl);
    if (myCtx->obj == NULL) {
        (*jenv)->ThrowNew(jenv, excClass,
               "Unable to store WolfSSLSession object as global reference");
        return;
    }

    wolfSSL_SetRsaSignCtx(ssl, myCtx);
#else
    (void)jcl;
    (void)sslPtr;
    (*jenv)->ThrowNew(jenv, excClass,
        "wolfSSL not compiled with PK Callbacks and/or RSA support");
    return;
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setRsaVerifyCtx
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    jclass         excClass;
#if defined(HAVE_PK_CALLBACKS) && !defined(NO_RSA)
    jclass         sslClass;

    void*          rsaVerifyCtx;
    internCtx*     myCtx;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
#endif

    /* find exception class in case we need it */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return;
    }

#if defined(HAVE_PK_CALLBACKS) && !defined(NO_RSA)
    if (ssl == NULL) {
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
    rsaVerifyCtx = (internCtx*)wolfSSL_GetRsaVerifyCtx(ssl);

    /* note: if CTX has not been set up yet, wolfSSL defaults to NULL */
    if (rsaVerifyCtx != NULL) {
        myCtx = (internCtx*)rsaVerifyCtx;
        if (myCtx != NULL) {
            if (myCtx->active == 1) {
                (*jenv)->DeleteGlobalRef(jenv, myCtx->obj);
            }
            XFREE(myCtx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }
    }

    /* allocate memory for internal JNI object reference */
    myCtx = XMALLOC(sizeof(internCtx), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (myCtx == NULL) {
        (*jenv)->ThrowNew(jenv, excClass,
                "Unable to allocate memory for RSA verify context\n");
        return;
    }

    /* set CTX as active */
    myCtx->active = 1;

    /* store global ref to WolfSSLSession object */
    myCtx->obj = (*jenv)->NewGlobalRef(jenv, jcl);
    if (myCtx->obj == NULL) {
        (*jenv)->ThrowNew(jenv, excClass,
               "Unable to store WolfSSLSession object as global reference");
        return;
    }

    wolfSSL_SetRsaVerifyCtx(ssl, myCtx);
#else
    (void)jcl;
    (void)sslPtr;
    (*jenv)->ThrowNew(jenv, excClass,
        "wolfSSL not compiled with PK Callbacks and/or RSA support");
    return;
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setRsaEncCtx
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    jclass         excClass;
#if defined(HAVE_PK_CALLBACKS) && !defined(NO_RSA)
    jclass         sslClass;

    void*          rsaEncCtx;
    internCtx*     myCtx;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
#endif

    /* find exception class in case we need it */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return;
    }

#if defined(HAVE_PK_CALLBACKS) && !defined(NO_RSA)

    if (ssl == NULL) {
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
    rsaEncCtx = (internCtx*) wolfSSL_GetRsaEncCtx(ssl);

    /* note: if CTX has not been set up yet, wolfSSL defaults to NULL */
    if (rsaEncCtx != NULL) {
        myCtx = (internCtx*)rsaEncCtx;
        if (myCtx != NULL) {
            if (myCtx->active == 1) {
                (*jenv)->DeleteGlobalRef(jenv, myCtx->obj);
            }
            XFREE(myCtx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }
    }

    /* allocate memory for internal JNI object reference */
    myCtx = XMALLOC(sizeof(internCtx), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (myCtx == NULL) {
        (*jenv)->ThrowNew(jenv, excClass,
                "Unable to allocate memory for RSA encrypt context\n");
        return;
    }

    /* set CTX as active */
    myCtx->active = 1;

    /* store global ref to WolfSSLSession object */
    myCtx->obj = (*jenv)->NewGlobalRef(jenv, jcl);
    if (myCtx->obj == NULL) {
        (*jenv)->ThrowNew(jenv, excClass,
               "Unable to store WolfSSLSession object as global reference");
        return;
    }

    wolfSSL_SetRsaEncCtx(ssl, myCtx);
#else
    (void)jcl;
    (void)sslPtr;
    (*jenv)->ThrowNew(jenv, excClass,
        "wolfSSL not compiled with PK Callbacks and/or RSA support");
    return;
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setRsaDecCtx
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    jclass         excClass;
#if defined(HAVE_PK_CALLBACKS) && !defined(NO_RSA)
    jclass         sslClass;

    void*          rsaDecCtx;
    internCtx*     myCtx;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
#endif

    /* find exception class in case we need it */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return;
    }

#if defined(HAVE_PK_CALLBACKS) && !defined(NO_RSA)
    if (ssl == NULL) {
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
    rsaDecCtx = (internCtx*) wolfSSL_GetRsaDecCtx(ssl);

    /* note: if CTX has not been set up yet, wolfSSL defaults to NULL */
    if (rsaDecCtx != NULL) {
        myCtx = (internCtx*)rsaDecCtx;
        if (myCtx != NULL) {
            if (myCtx->active == 1) {
                (*jenv)->DeleteGlobalRef(jenv, myCtx->obj);
            }
            XFREE(myCtx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }
    }

    /* allocate memory for internal JNI object reference */
    myCtx = XMALLOC(sizeof(internCtx), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (myCtx == NULL) {
        (*jenv)->ThrowNew(jenv, excClass,
                "Unable to allocate memory for RSA decrypt context\n");
        return;
    }

    /* set CTX as active */
    myCtx->active = 1;

    /* store global ref to WolfSSLSession object */
    myCtx->obj = (*jenv)->NewGlobalRef(jenv, jcl);
    if (myCtx->obj == NULL) {
        (*jenv)->ThrowNew(jenv, excClass,
               "Unable to store WolfSSLSession object as global reference");
        return;
    }

    wolfSSL_SetRsaDecCtx(ssl, myCtx);
#else
    (void)jcl;
    (void)sslPtr;
    (*jenv)->ThrowNew(jenv, excClass,
        "wolfSSL not compiled with PK Callbacks and/or RSA support");
    return;
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setPskClientCb
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
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
    if (ssl != NULL) {
        /* set PSK client callback */
        wolfSSL_set_psk_client_callback(ssl, NativePskClientCb);
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
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
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
    if (ssl != NULL) {
        /* set PSK server callback */
        wolfSSL_set_psk_server_callback(ssl, NativePskServerCb);
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
  (JNIEnv* jenv, jobject obj, jlong sslPtr)
{
#ifndef NO_PSK
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)obj;

    if (jenv == NULL || ssl == NULL) {
        return NULL;
    }

    return (*jenv)->NewStringUTF(jenv, wolfSSL_get_psk_identity_hint(ssl));
#else
    (void)jenv;
    (void)obj;
    (void)sslPtr;
    return NULL;
#endif
}

JNIEXPORT jstring JNICALL Java_com_wolfssl_WolfSSLSession_getPskIdentity
  (JNIEnv* jenv, jobject obj, jlong sslPtr)
{
#ifndef NO_PSK
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)obj;

    if (jenv == NULL || ssl == NULL) {
        return NULL;
    }

    return (*jenv)->NewStringUTF(jenv, wolfSSL_get_psk_identity(ssl));
#else
    (void)jenv;
    (void)obj;
    (void)sslPtr;
    return NULL;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_usePskIdentityHint
  (JNIEnv* jenv, jobject obj, jlong sslPtr, jstring hint)
{
#ifndef NO_PSK
    jint ret;
    const char* nativeHint;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)obj;

    if (jenv == NULL || ssl == NULL || hint == NULL) {
        return SSL_FAILURE;
    }

    nativeHint = (*jenv)->GetStringUTFChars(jenv, hint, 0);

    ret = (jint)wolfSSL_use_psk_identity_hint(ssl, nativeHint);

    (*jenv)->ReleaseStringUTFChars(jenv, hint, nativeHint);

    return ret;
#else
    (void)jenv;
    (void)sslPtr;
    (void)hint;
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT jboolean JNICALL Java_com_wolfssl_WolfSSLSession_handshakeDone
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL || ssl == NULL) {
        return JNI_FALSE;
    }

    if (wolfSSL_is_init_finished(ssl)) {
        return JNI_TRUE;
    }
    else {
        return JNI_FALSE;
    }
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setConnectState
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL || ssl == NULL) {
        return;
    }

    wolfSSL_set_connect_state(ssl);
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setAcceptState
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL || ssl == NULL) {
        return;
    }

    wolfSSL_set_accept_state(ssl);
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setVerify
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jint mode, jobject callbackIface)
{
    jobject* verifyCb;
    SSLAppData* appData;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL || ssl == NULL) {
        return;
    }

    if (!callbackIface) {
        wolfSSL_set_verify(ssl, mode, NULL);
    }
    else {
        /* get app data to store verify callback jobject */
        appData = (SSLAppData*)wolfSSL_get_app_data(ssl);
        if (appData == NULL) {
            printf("Error getting app data from WOLFSSL\n");
        }

        if (appData) {
            verifyCb = (jobject*)XMALLOC(sizeof(jobject), NULL,
                                         DYNAMIC_TYPE_TMP_BUFFER);
            if (verifyCb == NULL) {
                printf("Error allocating memory for verifyCb\n");
            }
        }

        if (appData && verifyCb) {
            /* store Java verify Interface object */
            *verifyCb = (*jenv)->NewGlobalRef(jenv, callbackIface);
            if (*verifyCb == NULL) {
                printf("error storing global callback interface\n");
            }
            else {
                appData->g_verifySSLCbIfaceObj = verifyCb;

                /* set verify mode, register Java callback with wolfSSL */
                wolfSSL_set_verify(ssl, mode, NativeSSLVerifyCallback);
            }
        }
    }
}

JNIEXPORT jlong JNICALL Java_com_wolfssl_WolfSSLSession_setOptions
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jlong op)
{
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL || ssl == NULL) {
        return 0;
    }

    return wolfSSL_set_options(ssl, op);
}

JNIEXPORT jlong JNICALL Java_com_wolfssl_WolfSSLSession_getOptions
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL || ssl == NULL) {
        return 0;
    }

    return wolfSSL_get_options(ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_getShutdown
  (JNIEnv *jenv, jobject jcl, jlong sslPtr)
{
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jenv;
    (void)jcl;

    return (jint)wolfSSL_get_shutdown(ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_useSNI
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jbyte type, jbyteArray data)
{
    int ret = SSL_FAILURE;
    (void)jcl;
#ifdef HAVE_SNI
    byte* dataBuf = NULL;
    word32 dataSz = 0;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;

    if (jenv == NULL || ssl == NULL) {
        return BAD_FUNC_ARG;
    }

    dataBuf = (byte*)(*jenv)->GetByteArrayElements(jenv, data, NULL);
    dataSz = (*jenv)->GetArrayLength(jenv, data);

    if (dataBuf != NULL && dataSz > 0) {
        ret = wolfSSL_UseSNI(ssl, (byte)type, dataBuf, (word16)dataSz);
    }

    (*jenv)->ReleaseByteArrayElements(jenv, data, (jbyte*)dataBuf, JNI_ABORT);

#else
    ret = NOT_COMPILED_IN;
    (void)jenv;
    (void)sslPtr;
    (void)type;
    (void)data;
#endif /* HAVE_SNI */

    return (jint)ret;

}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_useSessionTicket
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    int ret = SSL_FAILURE;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;
#ifdef HAVE_SESSION_TICKET
    if (jenv == NULL || ssl == NULL) {
        return BAD_FUNC_ARG;
    }

    ret = wolfSSL_UseSessionTicket(ssl);
#else
    (void)jenv;
    (void)sslPtr;
    ret = NOT_COMPILED_IN;
#endif
    return ret;
}

/* return 1 if last alert received was a close_notify alert, otherwise 0 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_gotCloseNotify
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    int ret, gotCloseNotify = 0;
    WOLFSSL_ALERT_HISTORY alert_history;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL || ssl == NULL) {
        return gotCloseNotify;
    }

    ret = wolfSSL_get_alert_history(ssl, &alert_history);
    if (ret == WOLFSSL_SUCCESS) {
        if (alert_history.last_rx.code == 0) {
            gotCloseNotify = 1;
        }
    }

    return gotCloseNotify;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_sslSetAlpnProtos
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jbyteArray alpnProtos)
{
    int ret = SSL_FAILURE;
    (void)jcl;
#if defined(HAVE_ALPN) && (LIBWOLFSSL_VERSION_HEX >= 0x04002000)
    /* wolfSSL_set_alpn_protos() added as of wolfSSL 4.2.0 */
    byte* buff = NULL;
    word32 buffSz = 0;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL || ssl == NULL || alpnProtos == NULL) {
        return BAD_FUNC_ARG;
    }

    buff = (byte*)(*jenv)->GetByteArrayElements(jenv, alpnProtos, NULL);
    buffSz = (*jenv)->GetArrayLength(jenv, alpnProtos);

    if (buff != NULL && buffSz > 0) {
        ret = wolfSSL_set_alpn_protos(ssl, buff, buffSz);
    }

    (*jenv)->ReleaseByteArrayElements(jenv, alpnProtos,
                                      (jbyte*)buff, JNI_ABORT);
#else
    (void)jenv;
    (void)jcl;
    (void)sslPtr;
    (void)alpnProtos;
    ret = NOT_COMPILED_IN;
#endif
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_WolfSSLSession_sslGet0AlpnSelected
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
#ifdef HAVE_ALPN
    int err = 0;
    char* protocol_name = NULL;
    word16 protocol_nameSz = 0;
    jbyteArray alpnArray;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL || ssl == NULL) {
        return NULL;
    }

    /* get ALPN protocol received from server:
     * WOLFSSL_SUCCESS - on success
     * WOLFSSL_ALPN_NOT_FOUND - no ALPN received (no match with server)
     * other - error case */
    err = wolfSSL_ALPN_GetProtocol(ssl, &protocol_name, &protocol_nameSz);
    if (err != WOLFSSL_SUCCESS) {
        return NULL;
    }

    alpnArray = (*jenv)->NewByteArray(jenv, protocol_nameSz);
    if (alpnArray == NULL) {
        (*jenv)->ThrowNew(jenv, jcl,
            "Failed to create byte array in native sslGet0AlpnSelected");
        return NULL;
    }

    (*jenv)->SetByteArrayRegion(jenv, alpnArray, 0, protocol_nameSz,
                                (jbyte*)protocol_name);
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return NULL;
    }

    return alpnArray;
#else
    (void)jenv;
    (void)jcl;
    (void)sslPtr;
    return NULL;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_useALPN
  (JNIEnv* jenv, jobject jcl, jlong ssl, jstring protocols, jint options)
{
    int ret = SSL_FAILURE;
    (void)jcl;
#ifdef HAVE_ALPN
    const char* protoList;

    if (jenv == NULL || ssl == 0 || protocols == NULL || options < 0) {
        return BAD_FUNC_ARG;
    }

    protoList = (*jenv)->GetStringUTFChars(jenv, protocols, 0);

    ret = (jint) wolfSSL_UseALPN((WOLFSSL*)(uintptr_t)ssl, (char*)protoList,
            XSTRLEN(protoList), (int)options);

    (*jenv)->ReleaseStringUTFChars(jenv, protocols, protoList);
#else
    (void)jenv;
    (void)ssl;
    (void)protocols;
    (void)options;
    ret = NOT_COMPILED_IN;
#endif

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_useSecureRenegotiation
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    (void)jenv;
    (void)jcl;
#ifdef HAVE_SECURE_RENEGOTIATION
    return (jint)wolfSSL_UseSecureRenegotiation((WOLFSSL*)(uintptr_t)ssl);
#else
    (void)ssl;
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_rehandshake
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    (void)jenv;
    (void)jcl;
#ifdef HAVE_SECURE_RENEGOTIATION
    return (jint)wolfSSL_Rehandshake((WOLFSSL*)(uintptr_t)ssl);
#else
    (void)ssl;
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setSSLIORecv
    (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    /* find exception class */
    jclass excClass = (*jenv)->FindClass(jenv,
            "com/wolfssl/WolfSSLJNIException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return;
    }

    if (ssl != NULL) {
        /* set I/O recv callback */
        wolfSSL_SSLSetIORecv(ssl, NativeSSLIORecvCb);

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
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    /* find exception class in case we need it */
    jclass excClass = (*jenv)->FindClass(jenv,
            "com/wolfssl/WolfSSLJNIException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
    }

    if (ssl != NULL) {
        /* set I/O send callback */
        wolfSSL_SSLSetIOSend(ssl, NativeSSLIOSendCb);

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

