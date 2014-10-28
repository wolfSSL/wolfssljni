/* com_wolfssl_WolfSSLSession.c
 *
 * Copyright (C) 2006-2014 wolfSSL Inc.
 *
 * This file is part of CyaSSL.
 *
 * CyaSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * CyaSSL is distributed in the hope that it will be useful,
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
#include <cyassl/ssl.h>
#include <cyassl/error-ssl.h>

#include "com_wolfssl_globals.h"
#include "com_wolfssl_WolfSSL.h"

/* global object refs for verify, CRL callbacks */
static jobject g_crlCbIfaceObj;

/* custom native fn prototypes */
void NativeMissingCRLCallback(const char* url);

/* jni functions */

JNIEXPORT jlong JNICALL Java_com_wolfssl_WolfSSLSession_newSSL
  (JNIEnv* jenv, jobject jcl, jlong ctx)
{
    /* CyaSSL checks for null pointer */
    return (jlong)CyaSSL_new((CYASSL_CTX*)ctx);
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

    return (jint)CyaSSL_set_fd((CYASSL*)ssl, fd);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_useCertificateFile
  (JNIEnv* jenv, jobject jcl, jlong ssl, jstring file, jint format)
{
    jint ret = 0;
    const char* certFile;

    if (file == NULL)
        return SSL_BAD_FILE;
    
    certFile = (*jenv)->GetStringUTFChars(jenv, file, 0);

    ret = (jint) CyaSSL_use_certificate_file((CYASSL*)ssl, certFile,
            (int)format);

    (*jenv)->ReleaseStringUTFChars(jenv, file, certFile);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_usePrivateKeyFile
  (JNIEnv* jenv, jobject jcl, jlong ssl, jstring file, jint format)
{
    jint ret = 0;
    const char* keyFile;
    
    if (file == NULL)
        return SSL_BAD_FILE;

    keyFile = (*jenv)->GetStringUTFChars(jenv, file, 0);

    ret = (jint) CyaSSL_use_PrivateKey_file((CYASSL*)ssl, keyFile,
            (int)format);

    (*jenv)->ReleaseStringUTFChars(jenv, file, keyFile);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_useCertificateChainFile
  (JNIEnv* jenv, jobject jcl, jlong ssl, jstring file)
{
    jint ret = 0;
    const char* chainFile;
    
    if (file == NULL)
        return SSL_BAD_FILE;

    chainFile = (*jenv)->GetStringUTFChars(jenv, file, 0);

    ret = (jint) CyaSSL_use_certificate_chain_file((CYASSL*)ssl, chainFile);

    (*jenv)->ReleaseStringUTFChars(jenv, file, chainFile);

    return ret;
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setUsingNonblock
  (JNIEnv* jenv, jobject jcl, jlong ssl, jint nonblock)
{
    CyaSSL_set_using_nonblock((CYASSL*)ssl, nonblock);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_getUsingNonblock
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    return CyaSSL_get_using_nonblock((CYASSL*)ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_getFd
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    return CyaSSL_get_fd((CYASSL*)ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_connect
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    int ret = 0;
    
    /* make sure we don't have any outstanding exceptions pending */    
    if ((*jenv)->ExceptionCheck(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return SSL_FAILURE;
    }

    ret = CyaSSL_connect((CYASSL*)ssl);
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
        return CyaSSL_write((CYASSL*)ssl, data, length);

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

    size = CyaSSL_read((CYASSL*)ssl, data, length);

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
    return CyaSSL_accept((CYASSL*)ssl);
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_freeSSL
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    internCtx*   myCtx;

    /* free internal ioReadCtx */
    myCtx = (internCtx*) CyaSSL_GetIOReadCtx((CYASSL*)ssl);
    if (myCtx != NULL) {
        if (myCtx->active == 1) {
            (*jenv)->DeleteGlobalRef(jenv, myCtx->obj);
            free(myCtx);
        }
    }

    /* free internal ioWriteCtx */
    myCtx = (internCtx*) CyaSSL_GetIOWriteCtx((CYASSL*)ssl);
    if (myCtx != NULL) {
        if (myCtx->active == 1) {
            (*jenv)->DeleteGlobalRef(jenv, myCtx->obj);
            free(myCtx);
        }
    }

    /* free internal genCookieCtx */
    myCtx = (internCtx*) CyaSSL_GetCookieCtx((CYASSL*)ssl);
    if (myCtx != NULL) {
        if (myCtx->active == 1) {
            (*jenv)->DeleteGlobalRef(jenv, myCtx->obj);
            free(myCtx);
        }
    }

    /* native cleanup */
    CyaSSL_free((CYASSL*)ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_shutdownSSL
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    return CyaSSL_shutdown((CYASSL*)ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_getError
  (JNIEnv* jenv, jobject jcl, jlong ssl, jint ret)
{
    return CyaSSL_get_error((CYASSL*)ssl, ret);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_setSession
  (JNIEnv* jenv, jobject jcl, jlong ssl, jlong session)
{
    return CyaSSL_set_session((CYASSL*)ssl, (CYASSL_SESSION*)session);
}

JNIEXPORT jlong JNICALL Java_com_wolfssl_WolfSSLSession_getSession
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    return (jlong)CyaSSL_get_session((CYASSL*)ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_setCipherList
  (JNIEnv* jenv, jobject jcl, jlong ssl, jstring list)
{

    jint ret = 0;
    const char* cipherList;

    cipherList= (*jenv)->GetStringUTFChars(jenv, list, 0);

    ret = (jint) CyaSSL_set_cipher_list((CYASSL*)ssl, cipherList);

    (*jenv)->ReleaseStringUTFChars(jenv, list, cipherList);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_dtlsGetCurrentTimeout
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    return CyaSSL_dtls_get_current_timeout((CYASSL*)ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_dtlsGotTimeout
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    return CyaSSL_dtls_got_timeout((CYASSL*)ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_dtls
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    return CyaSSL_dtls((CYASSL*)ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_dtlsSetPeer
  (JNIEnv* jenv, jobject jcl, jlong ssl, jobject peer)
{
    int ret;
    jstring ipAddr;
    struct sockaddr_in sa;
    const char* ipAddress;

    /* get class references */
    jclass excClass = (*jenv)->FindClass(jenv, "java/lang/Exception");
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
    ret = CyaSSL_dtls_set_peer((CYASSL*)ssl, &sa, sizeof(sa));

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

    /* get native sockaddr_in peer */
    memset(&peer, 0, sizeof(peer));
    peerSz = sizeof(peer);
    ret = CyaSSL_dtls_get_peer((CYASSL*)ssl, &peer, &peerSz);
    if (ret != SSL_SUCCESS) {
        return NULL;
    }
    ipAddrString = inet_ntoa(peer.sin_addr);
    port = ntohs(peer.sin_port);

    /* create new InetSocketAddress with this IP/port info */
    jclass excClass = (*jenv)->FindClass(jenv, "java/lang/Exception");
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
    return CyaSSL_session_reused((CYASSL*)ssl);
}

JNIEXPORT jlong JNICALL Java_com_wolfssl_WolfSSLSession_getPeerCertificate
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    return (long)CyaSSL_get_peer_certificate((CYASSL*)ssl);
}

JNIEXPORT jstring JNICALL Java_com_wolfssl_WolfSSLSession_getPeerX509Issuer
  (JNIEnv* jenv, jobject jcl, jlong ssl, jlong x509)
{
    char* issuer;
    jstring retString;

    issuer = CyaSSL_X509_NAME_oneline(
            CyaSSL_X509_get_issuer_name((CYASSL_X509*)x509), 0, 0);
    
    retString = (*jenv)->NewStringUTF(jenv, issuer);
    XFREE(issuer, 0, DYNAMIC_TYPE_OPENSSL);

    return retString;
}

JNIEXPORT jstring JNICALL Java_com_wolfssl_WolfSSLSession_getPeerX509Subject
  (JNIEnv* jenv, jobject jcl, jlong ssl, jlong x509)
{
    char* subject;
    jstring retString;

    subject = CyaSSL_X509_NAME_oneline(
            CyaSSL_X509_get_subject_name((CYASSL_X509*)x509), 0, 0);
    
    retString = (*jenv)->NewStringUTF(jenv, subject);
    XFREE(subject, 0, DYNAMIC_TYPE_OPENSSL);

    return retString;
}

JNIEXPORT jstring JNICALL Java_com_wolfssl_WolfSSLSession_getPeerX509AltName
  (JNIEnv* jenv, jobject jcl, jlong ssl, jlong x509)
{
    char* altname;
    jstring retString;

    altname = CyaSSL_X509_get_next_altname((CYASSL_X509*)x509);

    retString = (*jenv)->NewStringUTF(jenv, altname);
    return retString;
}

JNIEXPORT jstring JNICALL Java_com_wolfssl_WolfSSLSession_getVersion
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    return (*jenv)->NewStringUTF(jenv, CyaSSL_get_version((CYASSL*)ssl));
}

JNIEXPORT jlong JNICALL Java_com_wolfssl_WolfSSLSession_getCurrentCipher
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    return (jlong) CyaSSL_get_current_cipher((CYASSL*)ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_checkDomainName
  (JNIEnv* jenv, jobject jcl, jlong ssl, jstring dn)
{
    int ret;
    const char* dname;

    if(!dn)
        return SSL_FAILURE;

    dname = (*jenv)->GetStringUTFChars(jenv, dn, 0);

    ret = CyaSSL_check_domain_name((CYASSL*)ssl, dname);

    (*jenv)->ReleaseStringUTFChars(jenv, dn, dname);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_setTmpDH
  (JNIEnv* jenv, jobject jcl, jlong ssl, jbyteArray p, jint pSz, jbyteArray g,
   jint gSz)
{
    unsigned char pBuf[pSz];
    unsigned char gBuf[gSz];

    if (!jenv || !ssl || !p || !g) {
        return BAD_FUNC_ARG;
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

    return CyaSSL_SetTmpDH((CYASSL*)ssl, pBuf, pSz, gBuf, gSz);

}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_setTmpDHFile
  (JNIEnv* jenv, jobject jcl, jlong ssl, jstring file, jint format)
{
    int ret;
    const char* fname;

    if (!file)
        return SSL_BAD_FILE;

    fname = (*jenv)->GetStringUTFChars(jenv, file, 0);

    ret = CyaSSL_SetTmpDH_file((CYASSL*)ssl, fname, format);

    (*jenv)->ReleaseStringUTFChars(jenv, file, fname);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_useCertificateBuffer
  (JNIEnv* jenv, jobject jcl, jlong ssl, jbyteArray in, jlong sz, jint format)
{
    unsigned char buff[sz];

    if (!jenv || !ssl || !in)
        return BAD_FUNC_ARG;

    (*jenv)->GetByteArrayRegion(jenv, in, 0, sz, (jbyte*)buff);
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return SSL_FAILURE;
    }

    return CyaSSL_use_certificate_buffer((CYASSL*)ssl, buff, sz, format);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_usePrivateKeyBuffer
  (JNIEnv* jenv, jobject jcl, jlong ssl, jbyteArray in, jlong sz, jint format)
{
    unsigned char buff[sz];

    if (!jenv || !ssl || !in)
        return BAD_FUNC_ARG;

    (*jenv)->GetByteArrayRegion(jenv, in, 0, sz, (jbyte*)buff);
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return SSL_FAILURE;
    }

    return CyaSSL_use_PrivateKey_buffer((CYASSL*)ssl, buff, sz, format);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_useCertificateChainBuffer
  (JNIEnv* jenv, jobject jcl, jlong ssl, jbyteArray in, jlong sz)
{
    unsigned char buff[sz];

    if (!jenv || !ssl || !in)
        return BAD_FUNC_ARG;

    (*jenv)->GetByteArrayRegion(jenv, in, 0, sz, (jbyte*)buff);
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return SSL_FAILURE;
    }

    return CyaSSL_use_certificate_chain_buffer((CYASSL*)ssl, buff, sz);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_setGroupMessages
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    return CyaSSL_set_group_messages((CYASSL*)ssl);
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setIOReadCtx
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    jclass         sslClass;
    jclass         excClass;

    int*           invalid;
    void*          ioReadCtx;
    internCtx*   myCtx;
    
    /* find exception class in case we need it */
    excClass = (*jenv)->FindClass(jenv, "java/lang/Exception");

    /* get WolfSSLSession class from object ref */
    sslClass = (*jenv)->GetObjectClass(jenv, jcl);
    if (!sslClass) {
        (*jenv)->ThrowNew(jenv, excClass,
                "Can't get WolfSSLSession object class");
        return;
    }

    /* free existing memory if it already exists, before we malloc again */
    ioReadCtx = (internCtx*) CyaSSL_GetIOReadCtx((CYASSL*)ssl);

    /* note: if CTX has not been set up yet, CyaSSL defaults to -1 */
    invalid = (int*)ioReadCtx;
    if ((*invalid != -1) && (ioReadCtx != NULL)) {
        myCtx = (internCtx*)ioReadCtx;
        if (myCtx->active == 1) {
            (*jenv)->DeleteGlobalRef(jenv, myCtx->obj);
            free(myCtx);
        }
    }

    /* allocate memory for internal JNI object reference */
    myCtx = malloc(sizeof(internCtx));
    if (!myCtx) {
        (*jenv)->ThrowNew(jenv, excClass,
                "Unable to allocate memory for I/O context\n");
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

    CyaSSL_SetIOReadCtx((CYASSL*) ssl, myCtx);
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setIOWriteCtx
  (JNIEnv* jenv, jobject jcl, jlong ssl, jobject ioctx) 
{
    jclass         sslClass;
    jclass         excClass;
    
    int*           invalid;
    void*          ioWriteCtx;
    internCtx*   myCtx;
    
    /* find exception class in case we need it */
    excClass = (*jenv)->FindClass(jenv, "java/lang/Exception");

    /* get WolfSSLSession class from object ref */
    sslClass = (*jenv)->GetObjectClass(jenv, jcl);
    if (!sslClass) {
        (*jenv)->ThrowNew(jenv, excClass,
                "Can't get WolfSSLSession object class");
        return;
    }

    /* free existing memory if it already exists, before we malloc again */
    ioWriteCtx = (internCtx*) CyaSSL_GetIOWriteCtx((CYASSL*)ssl);

    /* note: if CTX has not been set up yet, CyaSSL defaults to -1 */
    invalid = (int*)ioWriteCtx;
    if ((*invalid != -1) && (ioWriteCtx != NULL)) {
        myCtx = (internCtx*)ioWriteCtx;
        if (myCtx->active == 1) {
            (*jenv)->DeleteGlobalRef(jenv, myCtx->obj);
            free(myCtx);
        }
    }

    /* allocate memory for internal JNI object reference */
    myCtx = malloc(sizeof(internCtx));
    if (!myCtx) {
        (*jenv)->ThrowNew(jenv, excClass,
                "Unable to allocate memory for I/O context\n");
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

    CyaSSL_SetIOWriteCtx((CYASSL*) ssl, myCtx);
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setGenCookieCtx
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    jclass         sslClass;
    jclass         excClass;
    
    int*           invalid;
    void*          genCookieCtx;
    internCtx*   myCtx;
   
    /* find exception class in case we need it */
    excClass = (*jenv)->FindClass(jenv, "java/lang/Exception");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
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
    genCookieCtx = (internCtx*) CyaSSL_GetCookieCtx((CYASSL*)ssl);

    /* note: if CTX has not been set up yet, CyaSSL defaults to -1 */
    invalid = (int*)genCookieCtx;
    if ((genCookieCtx != NULL) && (*invalid != -1)) {
        myCtx = (internCtx*)genCookieCtx;
        if (myCtx->active == 1) {
            (*jenv)->DeleteGlobalRef(jenv, myCtx->obj);
            free(myCtx);
        }
    }

    /* allocate memory for internal JNI object reference */
    myCtx = malloc(sizeof(internCtx));
    if (!myCtx) {
        (*jenv)->ThrowNew(jenv, excClass,
                "Unable to allocate memory for gen cookie context\n");
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

    CyaSSL_SetCookieCtx((CYASSL*) ssl, myCtx);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_enableCRL
  (JNIEnv* jenv, jobject jcl, jlong ssl, jint options)
{
    if (!jenv || !ssl)
        return BAD_FUNC_ARG;

    return CyaSSL_EnableCRL((CYASSL*)ssl, options);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_disableCRL
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    if (!jenv || !ssl)
        return BAD_FUNC_ARG;

    return CyaSSL_DisableCRL((CYASSL*)ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_loadCRL
  (JNIEnv* jenv, jobject jcl, jlong ssl, jstring path, jint type, jint monitor)
{
    int ret;
    const char* crlPath;

    if (!jenv || !ssl || !path)
        return BAD_FUNC_ARG;

    crlPath = (*jenv)->GetStringUTFChars(jenv, path, 0);

    ret = CyaSSL_LoadCRL((CYASSL*)ssl, crlPath, type, monitor);

    (*jenv)->ReleaseStringUTFChars(jenv, path, crlPath);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_setCRLCb
  (JNIEnv* jenv, jobject jcl, jlong ssl, jobject cb)
{
    int    ret = 0;
    jclass excClass;

    if (!jenv || !ssl || !cb) {
        return BAD_FUNC_ARG;
    }
    
    /* find exception class in case we need it */
    excClass = (*jenv)->FindClass(jenv, "java/lang/Exception");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return SSL_FAILURE;
    }
        
    /* store Java CRL callback Interface object */
    g_crlCbIfaceObj = (*jenv)->NewGlobalRef(jenv, cb);
    if (!g_crlCbIfaceObj) {
        (*jenv)->ThrowNew(jenv, excClass,
               "Error storing global missingCRLCallback interface");
    }

    ret = CyaSSL_SetCRL_Cb((CYASSL*)ssl, NativeMissingCRLCallback);

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
    excClass = (*jenv)->FindClass(jenv, "java/lang/Exception");
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
    CYASSL_CIPHER* cipher;

    cipher = CyaSSL_get_current_cipher((CYASSL*)ssl);

    if (cipher != NULL) {
        cipherName = CyaSSL_CIPHER_get_name(cipher);
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
    const unsigned char* secret;
    
    /* find exception class */
    jclass excClass = (*jenv)->FindClass(jenv, "java/lang/Exception");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return NULL;
    }

    secret = CyaSSL_GetMacSecret((CYASSL*)ssl, (int)verify);
    
    if (secret != NULL) {
        
        /* get mac size */
        macLength = CyaSSL_GetHmacSize((CYASSL*)ssl);

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
    const unsigned char* key;
    
    /* find exception class */
    jclass excClass = (*jenv)->FindClass(jenv, "java/lang/Exception");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return NULL;
    }

    key = CyaSSL_GetClientWriteKey((CYASSL*)ssl);

    if (key != NULL) {

        /* get key size */
        keyLength = CyaSSL_GetKeySize((CYASSL*)ssl);

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
    
    /* find exception class */
    jclass excClass = (*jenv)->FindClass(jenv, "java/lang/Exception");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return NULL;
    }

    iv = CyaSSL_GetClientWriteIV((CYASSL*)ssl);

    if (iv != NULL) {

        /* get iv size, is block size for what CyaSSL supports */
        ivLength = CyaSSL_GetCipherBlockSize((CYASSL*)ssl);

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
    
    /* find exception class */
    jclass excClass = (*jenv)->FindClass(jenv, "java/lang/Exception");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return NULL;
    }

    key = CyaSSL_GetServerWriteKey((CYASSL*)ssl);

    if (key != NULL) {

        /* get key size */
        keyLength = CyaSSL_GetKeySize((CYASSL*)ssl);

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
    
    /* find exception class */
    jclass excClass = (*jenv)->FindClass(jenv, "java/lang/Exception");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return NULL;
    }

    iv = CyaSSL_GetServerWriteIV((CYASSL*)ssl);

    if (iv != NULL) {

        /* get iv size, is block size for what CyaSSL supports */
        ivLength = CyaSSL_GetCipherBlockSize((CYASSL*)ssl);

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
    return CyaSSL_GetKeySize((CYASSL*)ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_getSide
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    return CyaSSL_GetSide((CYASSL*)ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_isTLSv1_11
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    return CyaSSL_IsTLSv1_1((CYASSL*)ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_getBulkCipher
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    return CyaSSL_GetBulkCipher((CYASSL*)ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_getCipherBlockSize
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    return CyaSSL_GetCipherBlockSize((CYASSL*)ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_getAeadMacSize
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    return CyaSSL_GetAeadMacSize((CYASSL*)ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_getHmacSize
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    return CyaSSL_GetHmacSize((CYASSL*)ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_getHmacType
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    return CyaSSL_GetHmacType((CYASSL*)ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_getCipherType
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    return CyaSSL_GetCipherType((CYASSL*)ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_setTlsHmacInner
  (JNIEnv* jenv, jobject jcl, jlong ssl, jbyteArray inner, jlong sz,
   jint content, jint verify)
{
    int ret = 0;
    unsigned char hmacInner[CYASSL_TLS_HMAC_INNER_SZ];

    if (inner == NULL) {
        return BAD_FUNC_ARG;
    }

    /* find exception class */
    jclass excClass = (*jenv)->FindClass(jenv, "java/lang/Exception");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return -1;
    }

    ret = CyaSSL_SetTlsHmacInner((CYASSL*)ssl, hmacInner, sz, content, verify);

    /* copy hmacInner back into inner jbyteArray */
    (*jenv)->SetByteArrayRegion(jenv, inner, 0, CYASSL_TLS_HMAC_INNER_SZ,
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

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setMacEncryptCtx
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    jclass         sslClass;
    jclass         excClass;

    void*          macEncryptCtx;
    internCtx*     myCtx;
    
    /* find exception class in case we need it */
    excClass = (*jenv)->FindClass(jenv, "java/lang/Exception");

    /* get WolfSSLSession class from object ref */
    sslClass = (*jenv)->GetObjectClass(jenv, jcl);
    if (!sslClass) {
        (*jenv)->ThrowNew(jenv, excClass,
                "Can't get WolfSSLSession object class");
        return;
    }

    /* free existing memory if it already exists, before we malloc again */
    macEncryptCtx = (internCtx*) CyaSSL_GetMacEncryptCtx((CYASSL*)ssl);

    /* note: if CTX has not been set up yet, CyaSSL defaults to NULL */
    if (macEncryptCtx != NULL) {
        myCtx = (internCtx*)macEncryptCtx;
        if (myCtx->active == 1) {
            (*jenv)->DeleteGlobalRef(jenv, myCtx->obj);
            free(myCtx);
        }
    }

    /* allocate memory for internal JNI object reference */
    myCtx = malloc(sizeof(internCtx));
    if (!myCtx) {
        (*jenv)->ThrowNew(jenv, excClass,
                "Unable to allocate memory for MAC encrypt context\n");
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

    CyaSSL_SetMacEncryptCtx((CYASSL*) ssl, myCtx);
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setDecryptVerifyCtx
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    jclass         sslClass;
    jclass         excClass;

    void*          decryptVerifyCtx;
    internCtx*     myCtx;
    
    /* find exception class in case we need it */
    excClass = (*jenv)->FindClass(jenv, "java/lang/Exception");

    /* get WolfSSLSession class from object ref */
    sslClass = (*jenv)->GetObjectClass(jenv, jcl);
    if (!sslClass) {
        (*jenv)->ThrowNew(jenv, excClass,
                "Can't get WolfSSLSession object class");
        return;
    }

    /* free existing memory if it already exists, before we malloc again */
    decryptVerifyCtx = (internCtx*) CyaSSL_GetDecryptVerifyCtx((CYASSL*)ssl);

    /* note: if CTX has not been set up yet, CyaSSL defaults to NULL */
    if (decryptVerifyCtx != NULL) {
        myCtx = (internCtx*)decryptVerifyCtx;
        if (myCtx->active == 1) {
            (*jenv)->DeleteGlobalRef(jenv, myCtx->obj);
            free(myCtx);
        }
    }

    /* allocate memory for internal JNI object reference */
    myCtx = malloc(sizeof(internCtx));
    if (!myCtx) {
        (*jenv)->ThrowNew(jenv, excClass,
                "Unable to allocate memory for decrypt verify context\n");
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

    CyaSSL_SetDecryptVerifyCtx((CYASSL*) ssl, myCtx);
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setEccSignCtx
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    jclass         sslClass;
    jclass         excClass;

    void*          eccSignCtx;
    internCtx*     myCtx;
    
    /* find exception class in case we need it */
    excClass = (*jenv)->FindClass(jenv, "java/lang/Exception");

    /* get WolfSSLSession class from object ref */
    sslClass = (*jenv)->GetObjectClass(jenv, jcl);
    if (!sslClass) {
        (*jenv)->ThrowNew(jenv, excClass,
                "Can't get WolfSSLSession object class");
        return;
    }

    /* free existing memory if it already exists, before we malloc again */
    eccSignCtx = (internCtx*) CyaSSL_GetEccSignCtx((CYASSL*)ssl);

    /* note: if CTX has not been set up yet, CyaSSL defaults to NULL */
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

    CyaSSL_SetEccSignCtx((CYASSL*) ssl, myCtx);
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setEccVerifyCtx
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    jclass         sslClass;
    jclass         excClass;

    void*          eccVerifyCtx;
    internCtx*     myCtx;
    
    /* find exception class in case we need it */
    excClass = (*jenv)->FindClass(jenv, "java/lang/Exception");

    /* get WolfSSLSession class from object ref */
    sslClass = (*jenv)->GetObjectClass(jenv, jcl);
    if (!sslClass) {
        (*jenv)->ThrowNew(jenv, excClass,
                "Can't get WolfSSLSession object class");
        return;
    }

    /* free existing memory if it already exists, before we malloc again */
    eccVerifyCtx = (internCtx*) CyaSSL_GetEccVerifyCtx((CYASSL*)ssl);

    /* note: if CTX has not been set up yet, CyaSSL defaults to NULL */
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

    CyaSSL_SetEccVerifyCtx((CYASSL*) ssl, myCtx);
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setRsaSignCtx
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    jclass         sslClass;
    jclass         excClass;

    void*          rsaSignCtx;
    internCtx*     myCtx;
    
    /* find exception class in case we need it */
    excClass = (*jenv)->FindClass(jenv, "java/lang/Exception");

    /* get WolfSSLSession class from object ref */
    sslClass = (*jenv)->GetObjectClass(jenv, jcl);
    if (!sslClass) {
        (*jenv)->ThrowNew(jenv, excClass,
                "Can't get WolfSSLSession object class");
        return;
    }

    /* free existing memory if it already exists, before we malloc again */
    rsaSignCtx = (internCtx*) CyaSSL_GetRsaSignCtx((CYASSL*)ssl);

    /* note: if CTX has not been set up yet, CyaSSL defaults to NULL */
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

    CyaSSL_SetRsaSignCtx((CYASSL*) ssl, myCtx);
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setRsaVerifyCtx
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    jclass         sslClass;
    jclass         excClass;

    void*          rsaVerifyCtx;
    internCtx*     myCtx;
    
    /* find exception class in case we need it */
    excClass = (*jenv)->FindClass(jenv, "java/lang/Exception");

    /* get WolfSSLSession class from object ref */
    sslClass = (*jenv)->GetObjectClass(jenv, jcl);
    if (!sslClass) {
        (*jenv)->ThrowNew(jenv, excClass,
                "Can't get WolfSSLSession object class");
        return;
    }

    /* free existing memory if it already exists, before we malloc again */
    rsaVerifyCtx = (internCtx*) CyaSSL_GetRsaVerifyCtx((CYASSL*)ssl);

    /* note: if CTX has not been set up yet, CyaSSL defaults to NULL */
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

    CyaSSL_SetRsaVerifyCtx((CYASSL*) ssl, myCtx);
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setRsaEncCtx
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    jclass         sslClass;
    jclass         excClass;

    void*          rsaEncCtx;
    internCtx*     myCtx;
    
    /* find exception class in case we need it */
    excClass = (*jenv)->FindClass(jenv, "java/lang/Exception");

    /* get WolfSSLSession class from object ref */
    sslClass = (*jenv)->GetObjectClass(jenv, jcl);
    if (!sslClass) {
        (*jenv)->ThrowNew(jenv, excClass,
                "Can't get WolfSSLSession object class");
        return;
    }

    /* free existing memory if it already exists, before we malloc again */
    rsaEncCtx = (internCtx*) CyaSSL_GetRsaEncCtx((CYASSL*)ssl);

    /* note: if CTX has not been set up yet, CyaSSL defaults to NULL */
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

    CyaSSL_SetRsaEncCtx((CYASSL*) ssl, myCtx);
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setRsaDecCtx
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    jclass         sslClass;
    jclass         excClass;

    void*          rsaDecCtx;
    internCtx*     myCtx;
    
    /* find exception class in case we need it */
    excClass = (*jenv)->FindClass(jenv, "java/lang/Exception");

    /* get WolfSSLSession class from object ref */
    sslClass = (*jenv)->GetObjectClass(jenv, jcl);
    if (!sslClass) {
        (*jenv)->ThrowNew(jenv, excClass,
                "Can't get WolfSSLSession object class");
        return;
    }

    /* free existing memory if it already exists, before we malloc again */
    rsaDecCtx = (internCtx*) CyaSSL_GetRsaDecCtx((CYASSL*)ssl);

    /* note: if CTX has not been set up yet, CyaSSL defaults to NULL */
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

    CyaSSL_SetRsaDecCtx((CYASSL*) ssl, myCtx);
}

