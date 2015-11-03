/* com_wolfssl_WolfSSLSession.c
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
#include <arpa/inet.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>

#include "com_wolfssl_globals.h"
#include "com_wolfssl_WolfSSL.h"

/* global object refs for CRL callback */
static jobject g_crlCbIfaceObj;

/* custom native fn prototypes */
void NativeMissingCRLCallback(const char* url);

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
    sslPtr = (jlong)wolfSSL_new((WOLFSSL_CTX*)ctx);

    if (sslPtr != 0) {
        /* create global reference to WolfSSLSession jobject */
        g_cachedObj = (jobject*)malloc(sizeof(jobject));
        if (!g_cachedObj) {
            printf("error mallocing memory in newSSL\n");
            wolfSSL_free((WOLFSSL*)sslPtr);
            return SSL_FAILURE;
        }
        *g_cachedObj = (*jenv)->NewGlobalRef(jenv, jcl);
        if (!*g_cachedObj) {
            printf("error storing global WolfSSLSession object\n");
            wolfSSL_free((WOLFSSL*)sslPtr);
            return SSL_FAILURE;
        }
        /* cache associated WolfSSLSession jobject in native WOLFSSL */
        ret = wolfSSL_set_jobject((WOLFSSL*)sslPtr, g_cachedObj);
        if (ret != SSL_SUCCESS) {
            printf("error storing jobject in wolfSSL native session\n");
            wolfSSL_free((WOLFSSL*)sslPtr);
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

    return (jint)wolfSSL_set_fd((WOLFSSL*)ssl, fd);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_useCertificateFile
  (JNIEnv* jenv, jobject jcl, jlong ssl, jstring file, jint format)
{
    jint ret = 0;
    const char* certFile;

    if (!jenv || !ssl)
        return SSL_FAILURE;

    if (file == NULL)
        return SSL_BAD_FILE;

    certFile = (*jenv)->GetStringUTFChars(jenv, file, 0);

    ret = (jint) wolfSSL_use_certificate_file((WOLFSSL*)ssl, certFile,
            (int)format);

    (*jenv)->ReleaseStringUTFChars(jenv, file, certFile);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_usePrivateKeyFile
  (JNIEnv* jenv, jobject jcl, jlong ssl, jstring file, jint format)
{
    jint ret = 0;
    const char* keyFile;

    if (!jenv || !ssl)
        return SSL_FAILURE;

    if (file == NULL)
        return SSL_BAD_FILE;

    keyFile = (*jenv)->GetStringUTFChars(jenv, file, 0);

    ret = (jint) wolfSSL_use_PrivateKey_file((WOLFSSL*)ssl, keyFile,
            (int)format);

    (*jenv)->ReleaseStringUTFChars(jenv, file, keyFile);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_useCertificateChainFile
  (JNIEnv* jenv, jobject jcl, jlong ssl, jstring file)
{
    jint ret = 0;
    const char* chainFile;

    if (!jenv || !ssl)
        return SSL_FAILURE;

    if (file == NULL)
        return SSL_BAD_FILE;

    chainFile = (*jenv)->GetStringUTFChars(jenv, file, 0);

    ret = (jint) wolfSSL_use_certificate_chain_file((WOLFSSL*)ssl, chainFile);

    (*jenv)->ReleaseStringUTFChars(jenv, file, chainFile);

    return ret;
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setUsingNonblock
  (JNIEnv* jenv, jobject jcl, jlong ssl, jint nonblock)
{
    jclass excClass;

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

    wolfSSL_set_using_nonblock((WOLFSSL*)ssl, nonblock);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_getUsingNonblock
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    jclass excClass;

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

    return wolfSSL_get_using_nonblock((WOLFSSL*)ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_getFd
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    jclass excClass;

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

    return wolfSSL_get_fd((WOLFSSL*)ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_connect
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    int ret = 0;

    if (!jenv || !ssl)
        return SSL_FATAL_ERROR;

    /* make sure we don't have any outstanding exceptions pending */
    if ((*jenv)->ExceptionCheck(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return SSL_FAILURE;
    }

    ret = wolfSSL_connect((WOLFSSL*)ssl);
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
    char data[16384];

    if (!jenv || !ssl || !raw)
        return BAD_FUNC_ARG;

    if (length >= 0) {
        (*jenv)->GetByteArrayRegion(jenv, raw, 0, length, (jbyte*)data);
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return SSL_FAILURE;
        }
        return wolfSSL_write((WOLFSSL*)ssl, data, length);

    } else {
        return SSL_FAILURE;
    }
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_read(JNIEnv* jenv,
    jobject jcl, jlong ssl, jbyteArray raw, jint length)
{
    int size;
    char data[16384];

    if (!jenv || !ssl || !raw)
        return BAD_FUNC_ARG;

    size = wolfSSL_read((WOLFSSL*)ssl, data, length);

    if (size >= 0) {
        (*jenv)->SetByteArrayRegion(jenv, raw, 0, size, (jbyte*)data);
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return SSL_FAILURE;
        }
    }

    return size;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_accept
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    if (!jenv || !ssl)
        return SSL_FATAL_ERROR;

    return wolfSSL_accept((WOLFSSL*)ssl);
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_freeSSL
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    jobject* g_cachedSSLObj;
    jclass excClass;

    if (!ssl) {
        excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
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
    g_cachedSSLObj = (jobject*) wolfSSL_get_jobject((WOLFSSL*)ssl);
    if (g_cachedSSLObj != NULL) {
        (*jenv)->DeleteGlobalRef(jenv, (jobject)(*g_cachedSSLObj));
        free(g_cachedSSLObj);
    }

    /* native cleanup */
    wolfSSL_free((WOLFSSL*)ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_shutdownSSL
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    if (!jenv)
        return SSL_FAILURE;

    /* wolfSSL checks ssl for NULL */
    return wolfSSL_shutdown((WOLFSSL*)ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_getError
  (JNIEnv* jenv, jobject jcl, jlong ssl, jint ret)
{
    if (!jenv)
        return SSL_FAILURE;

    /* wolfSSL checks ssl for NULL */
    return wolfSSL_get_error((WOLFSSL*)ssl, ret);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_setSession
  (JNIEnv* jenv, jobject jcl, jlong ssl, jlong session)
{
    if (!jenv || !ssl)
        return SSL_FAILURE;

    /* wolfSSL checks session for NULL, but not ssl */
    return wolfSSL_set_session((WOLFSSL*)ssl, (WOLFSSL_SESSION*)session);
}

JNIEXPORT jlong JNICALL Java_com_wolfssl_WolfSSLSession_getSession
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    /* wolfSSL checks ssl for NULL */
    return (jlong)wolfSSL_get_session((WOLFSSL*)ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_setCipherList
  (JNIEnv* jenv, jobject jcl, jlong ssl, jstring list)
{

    jint ret = 0;
    const char* cipherList;

    if (!jenv || !ssl || !list)
        return SSL_FAILURE;

    cipherList= (*jenv)->GetStringUTFChars(jenv, list, 0);

    ret = (jint) wolfSSL_set_cipher_list((WOLFSSL*)ssl, cipherList);

    (*jenv)->ReleaseStringUTFChars(jenv, list, cipherList);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_dtlsGetCurrentTimeout
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    jclass excClass;

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

    return wolfSSL_dtls_get_current_timeout((WOLFSSL*)ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_dtlsGotTimeout
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    jclass excClass;

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

    return wolfSSL_dtls_got_timeout((WOLFSSL*)ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_dtls
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    jclass excClass;

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

    return wolfSSL_dtls((WOLFSSL*)ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_dtlsSetPeer
  (JNIEnv* jenv, jobject jcl, jlong ssl, jobject peer)
{
    int ret;
    jstring ipAddr = NULL;
    struct sockaddr_in sa;
    const char* ipAddress = NULL;

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
    ret = wolfSSL_dtls_set_peer((WOLFSSL*)ssl, &sa, sizeof(sa));

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

    if (!jenv || !ssl)
        return NULL;

    /* get native sockaddr_in peer */
    memset(&peer, 0, sizeof(peer));
    peerSz = sizeof(peer);
    ret = wolfSSL_dtls_get_peer((WOLFSSL*)ssl, &peer, &peerSz);
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

    return wolfSSL_session_reused((WOLFSSL*)ssl);
}

JNIEXPORT jlong JNICALL Java_com_wolfssl_WolfSSLSession_getPeerCertificate
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    jclass excClass;

    if (!ssl) {
        excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return SSL_FAILURE;
        }
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLSession object was null in getPeerCertificate");
        return SSL_FAILURE;
    }

    return (long)wolfSSL_get_peer_certificate((WOLFSSL*)ssl);
}

JNIEXPORT jstring JNICALL Java_com_wolfssl_WolfSSLSession_getPeerX509Issuer
  (JNIEnv* jenv, jobject jcl, jlong ssl, jlong x509)
{
    char* issuer;
    jstring retString;
    jclass excClass;

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
            wolfSSL_X509_get_issuer_name((WOLFSSL_X509*)x509), 0, 0);

    retString = (*jenv)->NewStringUTF(jenv, issuer);
    XFREE(issuer, 0, DYNAMIC_TYPE_OPENSSL);

    return retString;
}

JNIEXPORT jstring JNICALL Java_com_wolfssl_WolfSSLSession_getPeerX509Subject
  (JNIEnv* jenv, jobject jcl, jlong ssl, jlong x509)
{
    char* subject;
    jstring retString;
    jclass excClass;

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
            wolfSSL_X509_get_subject_name((WOLFSSL_X509*)x509), 0, 0);

    retString = (*jenv)->NewStringUTF(jenv, subject);
    XFREE(subject, 0, DYNAMIC_TYPE_OPENSSL);

    return retString;
}

JNIEXPORT jstring JNICALL Java_com_wolfssl_WolfSSLSession_getPeerX509AltName
  (JNIEnv* jenv, jobject jcl, jlong ssl, jlong x509)
{
    char* altname;
    jstring retString;
    jclass excClass;

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

    altname = wolfSSL_X509_get_next_altname((WOLFSSL_X509*)x509);

    retString = (*jenv)->NewStringUTF(jenv, altname);
    return retString;
}

JNIEXPORT jstring JNICALL Java_com_wolfssl_WolfSSLSession_getVersion
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    jclass excClass;

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

    return (*jenv)->NewStringUTF(jenv, wolfSSL_get_version((WOLFSSL*)ssl));
}

JNIEXPORT jlong JNICALL Java_com_wolfssl_WolfSSLSession_getCurrentCipher
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    jclass excClass;

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

    return (jlong) wolfSSL_get_current_cipher((WOLFSSL*)ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_checkDomainName
  (JNIEnv* jenv, jobject jcl, jlong ssl, jstring dn)
{
    int ret;
    const char* dname;
    jclass excClass;

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

    ret = wolfSSL_check_domain_name((WOLFSSL*)ssl, dname);

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

    return wolfSSL_SetTmpDH((WOLFSSL*)ssl, pBuf, pSz, gBuf, gSz);

}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_setTmpDHFile
  (JNIEnv* jenv, jobject jcl, jlong ssl, jstring file, jint format)
{
    int ret;
    const char* fname;
    jclass excClass;

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

    ret = wolfSSL_SetTmpDH_file((WOLFSSL*)ssl, fname, format);

    (*jenv)->ReleaseStringUTFChars(jenv, file, fname);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_useCertificateBuffer
  (JNIEnv* jenv, jobject jcl, jlong ssl, jbyteArray in, jlong sz, jint format)
{
    unsigned char buff[sz];
    jclass excClass;

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

    return wolfSSL_use_certificate_buffer((WOLFSSL*)ssl, buff, sz, format);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_usePrivateKeyBuffer
  (JNIEnv* jenv, jobject jcl, jlong ssl, jbyteArray in, jlong sz, jint format)
{
    unsigned char buff[sz];
    jclass excClass;

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

    return wolfSSL_use_PrivateKey_buffer((WOLFSSL*)ssl, buff, sz, format);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_useCertificateChainBuffer
  (JNIEnv* jenv, jobject jcl, jlong ssl, jbyteArray in, jlong sz)
{
    unsigned char buff[sz];
    jclass excClass;

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

    return wolfSSL_use_certificate_chain_buffer((WOLFSSL*)ssl, buff, sz);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_setGroupMessages
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    jclass excClass;

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
    return wolfSSL_set_group_messages((WOLFSSL*)ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_enableCRL
  (JNIEnv* jenv, jobject jcl, jlong ssl, jint options)
{
    jclass excClass;

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

    return wolfSSL_EnableCRL((WOLFSSL*)ssl, options);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_disableCRL
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    jclass excClass;

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

    return wolfSSL_DisableCRL((WOLFSSL*)ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_loadCRL
  (JNIEnv* jenv, jobject jcl, jlong ssl, jstring path, jint type, jint monitor)
{
    int ret;
    const char* crlPath;
    jclass excClass;

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

    ret = wolfSSL_LoadCRL((WOLFSSL*)ssl, crlPath, type, monitor);

    (*jenv)->ReleaseStringUTFChars(jenv, path, crlPath);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_setCRLCb
  (JNIEnv* jenv, jobject jcl, jlong ssl, jobject cb)
{
    int    ret = 0;
    jclass excClass;

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

    ret = wolfSSL_SetCRL_Cb((WOLFSSL*)ssl, NativeMissingCRLCallback);

    return ret;
}

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

JNIEXPORT jstring JNICALL Java_com_wolfssl_WolfSSLSession_cipherGetName
  (JNIEnv* jenv, jclass jcl, jlong ssl)
{
    const char* cipherName;
    WOLFSSL_CIPHER* cipher;
    jclass excClass;

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

    cipher = wolfSSL_get_current_cipher((WOLFSSL*)ssl);

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
    int macLength;
    jbyteArray retSecret;
    jclass excClass;
    const unsigned char* secret;

    /* find exception class */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return NULL;
    }

    if (!ssl) {
        (*jenv)->ThrowNew(jenv, excClass,
            "Input WolfSSLSession object was null in "
            "getMacSecret");
        return NULL;
    }

    secret = wolfSSL_GetMacSecret((WOLFSSL*)ssl, (int)verify);

    if (secret != NULL) {

        /* get mac size */
        macLength = wolfSSL_GetHmacSize((WOLFSSL*)ssl);

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
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_WolfSSLSession_getClientWriteKey
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    int keyLength;
    jbyteArray retKey;
    jclass excClass;
    const unsigned char* key;

    /* find exception class */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return NULL;
    }

    if (!ssl) {
        (*jenv)->ThrowNew(jenv, excClass,
            "Input WolfSSLSession object was null in "
            "getClientWriteKey");
        return NULL;
    }

    key = wolfSSL_GetClientWriteKey((WOLFSSL*)ssl);

    if (key != NULL) {

        /* get key size */
        keyLength = wolfSSL_GetKeySize((WOLFSSL*)ssl);

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
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_WolfSSLSession_getClientWriteIV
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    jbyteArray retIV;
    const unsigned char* iv;
    int ivLength;
    jclass excClass;

    /* find exception class */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return NULL;
    }

    if (!ssl) {
        (*jenv)->ThrowNew(jenv, excClass,
            "Input WolfSSLSession object was null in "
            "getClientWriteIV");
        return NULL;
    }

    iv = wolfSSL_GetClientWriteIV((WOLFSSL*)ssl);

    if (iv != NULL) {

        /* get iv size, is block size for what wolfSSL supports */
        ivLength = wolfSSL_GetCipherBlockSize((WOLFSSL*)ssl);

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
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_WolfSSLSession_getServerWriteKey
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    jbyteArray retKey;
    const unsigned char* key;
    int keyLength;
    jclass excClass;

    /* find exception class */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return NULL;
    }

    if (!ssl) {
        (*jenv)->ThrowNew(jenv, excClass,
            "Input WolfSSLSession object was null in "
            "getServerWriteKey");
        return NULL;
    }

    key = wolfSSL_GetServerWriteKey((WOLFSSL*)ssl);

    if (key != NULL) {

        /* get key size */
        keyLength = wolfSSL_GetKeySize((WOLFSSL*)ssl);

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
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_WolfSSLSession_getServerWriteIV
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    jbyteArray retIV;
    const unsigned char* iv;
    int ivLength;
    jclass excClass;

    /* find exception class */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return NULL;
    }

    if (!ssl) {
        (*jenv)->ThrowNew(jenv, excClass,
            "Input WolfSSLSession object was null in "
            "getServerWriteIV");
        return NULL;
    }

    iv = wolfSSL_GetServerWriteIV((WOLFSSL*)ssl);

    if (iv != NULL) {

        /* get iv size, is block size for what wolfSSL supports */
        ivLength = wolfSSL_GetCipherBlockSize((WOLFSSL*)ssl);

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
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_getKeySize
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    /* wolfSSL checks ssl for NULL */
    return wolfSSL_GetKeySize((WOLFSSL*)ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_getSide
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    /* wolfSSL checks ssl for NULL */
    return wolfSSL_GetSide((WOLFSSL*)ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_isTLSv1_11
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    /* wolfSSL checks ssl for NULL */
    return wolfSSL_IsTLSv1_1((WOLFSSL*)ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_getBulkCipher
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    /* wolfSSL checks ssl for NULL */
    return wolfSSL_GetBulkCipher((WOLFSSL*)ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_getCipherBlockSize
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    /* wolfSSL checks ssl for NULL */
    return wolfSSL_GetCipherBlockSize((WOLFSSL*)ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_getAeadMacSize
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    /* wolfSSL checks ssl for NULL */
    return wolfSSL_GetAeadMacSize((WOLFSSL*)ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_getHmacSize
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    /* wolfSSL checks ssl for NULL */
    return wolfSSL_GetHmacSize((WOLFSSL*)ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_getHmacType
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    /* wolfSSL checks ssl for NULL */
    return wolfSSL_GetHmacType((WOLFSSL*)ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_getCipherType
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    /* wolfSSL checks ssl for NULL */
    return wolfSSL_GetCipherType((WOLFSSL*)ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_setTlsHmacInner
  (JNIEnv* jenv, jobject jcl, jlong ssl, jbyteArray inner, jlong sz,
   jint content, jint verify)
{
    int ret = 0;
    unsigned char hmacInner[WOLFSSL_TLS_HMAC_INNER_SZ];

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

    ret = wolfSSL_SetTlsHmacInner((WOLFSSL*)ssl, hmacInner, sz,
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
    jclass         sslClass;
    jclass         excClass;

    void*          eccSignCtx;
    internCtx*     myCtx;

    /* find exception class in case we need it */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return;
    }

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
    eccSignCtx = (internCtx*) wolfSSL_GetEccSignCtx((WOLFSSL*)ssl);

    /* note: if CTX has not been set up yet, wolfSSL defaults to NULL */
    if (eccSignCtx != NULL) {
        myCtx = (internCtx*)eccSignCtx;
        if (myCtx->active == 1) {
            (*jenv)->DeleteGlobalRef(jenv, myCtx->obj);
            free(myCtx);
        }
    }

    /* allocate memory for internal JNI object reference */
    myCtx = malloc(sizeof(internCtx));
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

    wolfSSL_SetEccSignCtx((WOLFSSL*) ssl, myCtx);
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setEccVerifyCtx
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    jclass         sslClass;
    jclass         excClass;

    void*          eccVerifyCtx;
    internCtx*     myCtx;

    /* find exception class in case we need it */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return;
    }

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
    eccVerifyCtx = (internCtx*) wolfSSL_GetEccVerifyCtx((WOLFSSL*)ssl);

    /* note: if CTX has not been set up yet, wolfSSL defaults to NULL */
    if (eccVerifyCtx != NULL) {
        myCtx = (internCtx*)eccVerifyCtx;
        if (myCtx->active == 1) {
            (*jenv)->DeleteGlobalRef(jenv, myCtx->obj);
            free(myCtx);
        }
    }

    /* allocate memory for internal JNI object reference */
    myCtx = malloc(sizeof(internCtx));
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

    wolfSSL_SetEccVerifyCtx((WOLFSSL*) ssl, myCtx);
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setRsaSignCtx
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    jclass         sslClass;
    jclass         excClass;

    void*          rsaSignCtx;
    internCtx*     myCtx;

    /* find exception class in case we need it */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return;
    }

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
    rsaSignCtx = (internCtx*) wolfSSL_GetRsaSignCtx((WOLFSSL*)ssl);

    /* note: if CTX has not been set up yet, wolfSSL defaults to NULL */
    if (rsaSignCtx != NULL) {
        myCtx = (internCtx*)rsaSignCtx;
        if (myCtx->active == 1) {
            (*jenv)->DeleteGlobalRef(jenv, myCtx->obj);
            free(myCtx);
        }
    }

    /* allocate memory for internal JNI object reference */
    myCtx = malloc(sizeof(internCtx));
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

    wolfSSL_SetRsaSignCtx((WOLFSSL*) ssl, myCtx);
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setRsaVerifyCtx
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    jclass         sslClass;
    jclass         excClass;

    void*          rsaVerifyCtx;
    internCtx*     myCtx;

    /* find exception class in case we need it */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return;
    }

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
    rsaVerifyCtx = (internCtx*) wolfSSL_GetRsaVerifyCtx((WOLFSSL*)ssl);

    /* note: if CTX has not been set up yet, wolfSSL defaults to NULL */
    if (rsaVerifyCtx != NULL) {
        myCtx = (internCtx*)rsaVerifyCtx;
        if (myCtx->active == 1) {
            (*jenv)->DeleteGlobalRef(jenv, myCtx->obj);
            free(myCtx);
        }
    }

    /* allocate memory for internal JNI object reference */
    myCtx = malloc(sizeof(internCtx));
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

    wolfSSL_SetRsaVerifyCtx((WOLFSSL*) ssl, myCtx);
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setRsaEncCtx
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    jclass         sslClass;
    jclass         excClass;

    void*          rsaEncCtx;
    internCtx*     myCtx;

    /* find exception class in case we need it */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return;
    }

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
    rsaEncCtx = (internCtx*) wolfSSL_GetRsaEncCtx((WOLFSSL*)ssl);

    /* note: if CTX has not been set up yet, wolfSSL defaults to NULL */
    if (rsaEncCtx != NULL) {
        myCtx = (internCtx*)rsaEncCtx;
        if (myCtx->active == 1) {
            (*jenv)->DeleteGlobalRef(jenv, myCtx->obj);
            free(myCtx);
        }
    }

    /* allocate memory for internal JNI object reference */
    myCtx = malloc(sizeof(internCtx));
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

    wolfSSL_SetRsaEncCtx((WOLFSSL*) ssl, myCtx);
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setRsaDecCtx
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    jclass         sslClass;
    jclass         excClass;

    void*          rsaDecCtx;
    internCtx*     myCtx;

    /* find exception class in case we need it */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return;
    }

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
    rsaDecCtx = (internCtx*) wolfSSL_GetRsaDecCtx((WOLFSSL*)ssl);

    /* note: if CTX has not been set up yet, wolfSSL defaults to NULL */
    if (rsaDecCtx != NULL) {
        myCtx = (internCtx*)rsaDecCtx;
        if (myCtx->active == 1) {
            (*jenv)->DeleteGlobalRef(jenv, myCtx->obj);
            free(myCtx);
        }
    }

    /* allocate memory for internal JNI object reference */
    myCtx = malloc(sizeof(internCtx));
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

    wolfSSL_SetRsaDecCtx((WOLFSSL*) ssl, myCtx);
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setPskClientCb
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    /* find exception class */
    jclass excClass = (*jenv)->FindClass(jenv,
            "com/wolfssl/WolfSSLJNIException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return;
    }

    if (ssl) {
        /* set PSK client callback */
        wolfSSL_set_psk_client_callback((WOLFSSL*)ssl, NativePskClientCb);
    } else {
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLSession object was null when setting "
                "NativePskClientCb");
        return;
    }
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setPskServerCb
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    /* find exception class */
    jclass excClass = (*jenv)->FindClass(jenv,
            "com/wolfssl/WolfSSLJNIException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return;
    }

    if (ssl) {
        /* set PSK server callback */
        wolfSSL_set_psk_server_callback((WOLFSSL*)ssl, NativePskServerCb);
    } else {
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLSession object was null when setting "
                "NativePskServerCb");
        return;
    }
}

JNIEXPORT jstring JNICALL Java_com_wolfssl_WolfSSLSession_getPskIdentityHint
  (JNIEnv* jenv, jobject obj, jlong ssl)
{
    if (!jenv || !ssl)
        return NULL;

    return (*jenv)->NewStringUTF(jenv,
            wolfSSL_get_psk_identity_hint((WOLFSSL*)ssl));
}

JNIEXPORT jstring JNICALL Java_com_wolfssl_WolfSSLSession_getPskIdentity
  (JNIEnv* jenv, jobject obj, jlong ssl)
{
    if (!jenv || !ssl)
        return NULL;

    return (*jenv)->NewStringUTF(jenv,
            wolfSSL_get_psk_identity((WOLFSSL*)ssl));
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_usePskIdentityHint
  (JNIEnv* jenv, jobject obj, jlong ssl, jstring hint)
{
    jint ret;
    const char* nativeHint;

    if (!jenv || !ssl || !hint)
        return SSL_FAILURE;

    nativeHint = (*jenv)->GetStringUTFChars(jenv, hint, 0);

    ret = (jint)wolfSSL_use_psk_identity_hint((WOLFSSL*)ssl, nativeHint);

    (*jenv)->ReleaseStringUTFChars(jenv, hint, nativeHint);

    return ret;
}

