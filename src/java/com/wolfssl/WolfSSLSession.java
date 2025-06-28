/* WolfSSLSession.java
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

package com.wolfssl;

import java.util.Arrays;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.DatagramSocket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.lang.StringBuilder;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.security.Security;

/**
 * Wraps a native WolfSSL session object and contains methods directly related
 * to the SSL/TLS session.
 *
 * @author  wolfSSL
 */
public class WolfSSLSession {

    /* Internal pointer to native WOLFSSL object. Access to this pointer
     * should be protected in this class with synchronization on the
     * this.sslLock lock. */
    private long sslPtr;

    private Object ioReadCtx;
    private Object ioWriteCtx;
    private Object genCookieCtx;
    private Object macEncryptCtx;
    private Object decryptVerifyCtx;
    private Object verifyDecryptCtx;
    private Object eccSignCtx;
    private Object eccVerifyCtx;
    private Object eccSharedSecretCtx;
    private Object rsaSignCtx;
    private Object rsaVerifyCtx;
    private Object rsaEncCtx;
    private Object rsaDecCtx;
    private Object alpnSelectArg;
    private Object tls13SecretCtx;
    private Object sessionTicketCtx;

    /* reference to the associated WolfSSLContext */
    private WolfSSLContext ctx = null;

    /* user-registered PSK callbacks, also at WolfSSLContext level */
    private WolfSSLPskClientCallback internPskClientCb = null;
    private WolfSSLPskServerCallback internPskServerCb = null;

    /* User-registerd I/O callbacks:
     *
     * These are called by internal WolfSSLSession I/O callback. This is done
     * in order to pass references to WolfSSLSession object. There are two sets
     * of I/O callbacks here, one set that will use byte[] and one that will
     * use ByteBuffer. Only one send and one recv callback can be set at a time
     * between the two. Native JNI code will give preference to using the
     * ByteBuffer variants for performance if set, since this will avoid an
     * extra native allocation (NewByteArray()). The ByteBuffer variant will
     * wrap the pre-allocated wolfSSL array in a Java direct ByteBuffer
     * to pass back up to Java. */
    private WolfSSLIORecvCallback internRecvSSLCb_array;
    private WolfSSLIOSendCallback internSendSSLCb_array;
    private WolfSSLByteBufferIORecvCallback internRecvSSLCb_BB;
    private WolfSSLByteBufferIOSendCallback internSendSSLCb_BB;

    /* user-registered ALPN select callback, called by internal WolfSSLSession
     * ALPN select callback */
    private WolfSSLALPNSelectCallback internAlpnSelectCb;

    /* user-registered TLS 1.3 secret callback, called by internal
     * WolfSSLSession TLS 1.3 secret callback */
    private WolfSSLTls13SecretCallback internTls13SecretCb;

    /* user-registered session ticket callback, called by internal
     * WolfSSLSession session ticket callback */
    private WolfSSLSessionTicketCallback internSessionTicketCb;

    /* have session tickets been enabled for this session? Default to false. */
    private boolean sessionTicketsEnabled = false;

    /* is this context active, or has it been freed? */
    private boolean active = false;

    /* lock around active state */
    private final Object stateLock = new Object();

    /* lock around native WOLFSSL pointer use */
    private final Object sslLock = new Object();

    /* Is static direct ByteBuffer pool enabled for read/write() calls */
    private boolean byteBufferPoolEnabled = true;

    /* Maximum direct ByteBuffer pool size */
    private static int MAX_POOL_SIZE = 16;

    /* Size of each direct ByteBuffer in the pool. This is set to 17KB, which
     * is slightly larger than the maximum SSL record size (16KB). This
     * allows for some overhead (SSL record header, etc) */
    private static int BUFFER_SIZE = 17 * 1024;

    /* Thread-local direct ByteBuffer pool for optimized JNI direct memory
     * access. Passing byte[] and offset down to JNI, on some systems this
     * will cause unaligned memory access, with pointer addition
     * (buffer + offset). Unaligned memory access can be considerably slower
     * (ex: Aarch64). To avoid this, we use a thread-local pool of ByteBuffers
     * here so native JNI does not do unaligned memory access and to eliminate
     * cross-thread contention. */
    private static final ThreadLocal<ConcurrentLinkedQueue<ByteBuffer>> directBufferPool =
        ThreadLocal.withInitial(() -> new ConcurrentLinkedQueue<>());

    /**
     * Check if static direct ByteBuffer pool has been disabled for
     * use in read/write() methods.
     *
     * The pool is enabled by default, unless explicitly disabled by setting
     * the "wolfssl.readWriteByteBufferPool.disabled" property to "true".
     *
     * @return true if disabled, otherwise false
     */
    private boolean readWritePoolDisabled() {

        String disabled =
            Security.getProperty("wolfssl.readWriteByteBufferPool.disabled");

        if (disabled == null || disabled.isEmpty()) {
            return false;
        }

        if (disabled.equalsIgnoreCase("true")) {
            return true;
        }

        return false;
    }

    /**
     * Check if the maximum size of the static per-thread direct
     * ByteBuffer pool has been adjusted by setting of the
     * "wolfssl.readWriteByteBufferPool.size" Security property.
     *
     * @return the size set, or the current default
     * (MAX_POOL_SIZE) if not.
     */
    private int readWritePoolGetMaxSizeFromProperty() {

        int maxSize = MAX_POOL_SIZE;

        String sizeProp =
            Security.getProperty("wolfssl.readWriteByteBufferPool.size");

        if (sizeProp == null || sizeProp.isEmpty()) {
            return maxSize;
        }

        try {
            int size = Integer.parseInt(sizeProp);
            if (size > 0) {
                maxSize = size;
            }
        } catch (NumberFormatException e) {
            WolfSSLDebug.log(getClass(),
                WolfSSLDebug.Component.JNI, WolfSSLDebug.ERROR, 0,
                () -> "Invalid value for " +
                "wolfssl.readWriteByteBufferPool.size: " + sizeProp);
        }

        return maxSize;
    }

    /**
     * Check if the size of the ByteBuffers in the static per-thread
     * pool has been adjusted by setting of the
     * "wolfssl.readWriteByteBufferPool.bufferSize" Security property.
     *
     * @return the size set, or the current default (BUFFER_SIZE) if not.
     */
    private int readWritePoolGetBufferSizeFromProperty() {

        int bufferSize = BUFFER_SIZE;

        String sizeProp =
            Security.getProperty("wolfssl.readWriteByteBufferPool.bufferSize");

        if (sizeProp == null || sizeProp.isEmpty()) {
            return bufferSize;
        }

        try {
            int size = Integer.parseInt(sizeProp);
            if (size > 0) {
                bufferSize = size;
            }
        } catch (NumberFormatException e) {
            WolfSSLDebug.log(getClass(),
                WolfSSLDebug.Component.JNI, WolfSSLDebug.ERROR, 0,
                () -> "Invalid value for " +
                "wolfssl.readWriteByteBufferPool.bufferSize: " + sizeProp);
        }

        return bufferSize;
    }

    /**
     * Read current values of relevant Security properties and set
     * internal behavior.
     */
    private void detectSecurityPropertySettings() {

        /* Re-use sslLock for synchronization here */
        synchronized (sslLock) {
            /* Check if static direct ByteBuffer pool has been disabled
             * with the "wolfssl.readWriteByteBufferPool.disabled"
             * Security property. */
            if (readWritePoolDisabled()) {
                this.byteBufferPoolEnabled = false;
            }

            /* Check if the maximum size of the static per-thread direct
             * ByteBuffer pool has been adjusted by setting of the
             * "wolfssl.readWriteByteBufferPool.size" Security property. */
            WolfSSLSession.MAX_POOL_SIZE =
                readWritePoolGetMaxSizeFromProperty();

            /* Check if the size of the ByteBuffers in the static per-thread
             * pool has been adjusted by setting of the
             * "wolfssl.readWriteByteBufferPool.bufferSize" Security property. */
            WolfSSLSession.BUFFER_SIZE =
                readWritePoolGetBufferSizeFromProperty();
        }
    }

    /**
     * Get a DirectByteBuffer from the thread-local pool or allocate a new one
     * if the pool is empty.
     *
     * @return a direct ByteBuffer ready to use
     */
    private static synchronized ByteBuffer acquireDirectBuffer() {
        ConcurrentLinkedQueue<ByteBuffer> threadPool = directBufferPool.get();
        ByteBuffer buffer = threadPool.poll();
        if (buffer == null) {
            WolfSSLDebug.log(WolfSSLSession.class, WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, 0,
                () -> "Thread-local DirectByteBuffer pool empty, " +
                "allocating new buffer");
            buffer = ByteBuffer.allocateDirect(BUFFER_SIZE);
        } else {
            WolfSSLDebug.log(WolfSSLSession.class, WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, 0,
                () -> "Reusing DirectByteBuffer from thread-local pool, " +
                "pool size: " + threadPool.size());
            buffer.clear();
        }
        return buffer;
    }

    /**
     * Return a DirectByteBuffer to the thread-local pool for reuse.
     *
     * If the pool is full, the ByteBuffer will be garbage collected.
     *
     * @param buffer the buffer to return to the pool
     */
    private static synchronized void releaseDirectBuffer(ByteBuffer buffer) {

        if (buffer != null && buffer.isDirect()) {

            buffer.clear();
            ConcurrentLinkedQueue<ByteBuffer> threadPool =
                directBufferPool.get();

            if (threadPool.size() < MAX_POOL_SIZE) {
                WolfSSLDebug.log(WolfSSLSession.class,
                    WolfSSLDebug.Component.JNI, WolfSSLDebug.INFO, 0,
                    () -> "Returning DirectByteBuffer to thread-local pool, " +
                    "pool size: " + threadPool.size());
                threadPool.offer(buffer);
            }
        }
    }

    /* SNI requested by this WolfSSLSession if client side and useSNI()
     * was called successfully. */
    private byte[] clientSNIRequested = null;

    /**
     * Creates a new SSL/TLS session.
     *
     * Native session created also creates JNI SSLAppData for usage
     * internal to wolfSSL JNI. This constructor creates a default
     * pipe() to use for interrupting threads waiting in select()/poll()
     * when close() is called. To skip creation of this pipe() use
     * the WolfSSLSession(WolfSSLContext ctx, boolean setupIOPipe)
     * constructor with 'setupIOPipe' set to false.
     *
     * @param  ctx   WolfSSLContext object used to create SSL session.
     *
     * @throws com.wolfssl.WolfSSLException if session object creation
     *                                      failed.
     */
    public WolfSSLSession(WolfSSLContext ctx) throws WolfSSLException {

        sslPtr = newSSL(ctx.getContextPtr(), true);
        if (sslPtr == 0) {
            throw new WolfSSLException("Failed to create SSL Object");
        }

        WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
            WolfSSLDebug.INFO, sslPtr,
            () -> "creating new WolfSSLSession (with I/O pipe)");

        detectSecurityPropertySettings();

        synchronized (stateLock) {
            this.active = true;
        }

        /* save context reference for I/O callbacks from JNI */
        this.ctx = ctx;
    }

    /**
     * Creates a new SSL/TLS session.
     *
     * Native session created also creates JNI SSLAppData for usage
     * internal to wolfSSL JNI. A pipe() can be created internally to wolfSSL
     * JNI to use for interrupting threads waiting in select()/poll()
     * when close() is called. To skip creation of this pipe(), set
     * 'setupIOPipe' to false.
     *
     * It is generally recommended to have wolfSSL JNI create the native
     * pipe(), unless you will be operating over non-Socket I/O. For example,
     * when this WolfSSLSession is being created from the JSSE level
     * SSLEngine class.
     *
     * @param ctx         WolfSSLContext object used to create SSL session.
     * @param setupIOPipe true to create internal IO pipe(), otherwise
     *        false
     *
     * @throws com.wolfssl.WolfSSLException if session object creation
     *                                      failed.
     */
    public WolfSSLSession(WolfSSLContext ctx, boolean setupIOPipe)
        throws WolfSSLException {

        sslPtr = newSSL(ctx.getContextPtr(), false);
        if (sslPtr == 0) {
            throw new WolfSSLException("Failed to create SSL Object");
        }

        if (setupIOPipe) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, sslPtr,
                () -> "creating new WolfSSLSession (with I/O pipe)");
        } else {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, sslPtr,
                () -> "creating new WolfSSLSession (without I/O pipe)");
        }

        detectSecurityPropertySettings();

        synchronized (stateLock) {
            this.active = true;
        }

        /* save context reference for I/O callbacks from JNI */
        this.ctx = ctx;
    }

    /* ------------------- private/protected methods -------------------- */

    /* used from JNI code */
    synchronized WolfSSLContext getAssociatedContextPtr() {
        return ctx;
    }

    synchronized Object getGenCookieCtx() {
        return this.genCookieCtx;
    }

    synchronized Object getMacEncryptCtx() {
        return this.macEncryptCtx;
    }

    synchronized Object getDecryptVerifyCtx() {
        return this.decryptVerifyCtx;
    }

    synchronized Object getVerifyDecryptCtx() {
        return this.verifyDecryptCtx;
    }

    synchronized Object getEccSignCtx() {
        return this.eccSignCtx;
    }

    synchronized Object getEccVerifyCtx() {
        return this.eccVerifyCtx;
    }

    synchronized Object getEccSharedSecretCtx() {
        return this.eccSharedSecretCtx;
    }

    synchronized Object getRsaSignCtx() {
        return this.rsaSignCtx;
    }

    synchronized Object getRsaVerifyCtx() {
        return this.rsaVerifyCtx;
    }

    synchronized Object getRsaEncCtx() {
        return this.rsaEncCtx;
    }

    synchronized Object getRsaDecCtx() {
        return this.rsaDecCtx;
    }

    /* Methods to detect which I/O callback variants have been set */
    private boolean isArrayIOSendCallbackSet() {
        return (internSendSSLCb_array != null);
    }

    private boolean isByteBufferIOSendCallbackSet() {
        return (internSendSSLCb_BB != null);
    }

    private boolean isArrayIORecvCallbackSet() {
        return (internRecvSSLCb_array != null);
    }

    private boolean isByteBufferIORecvCallbackSet() {
        return (internRecvSSLCb_BB != null);
    }

    /* These callbacks will be registered with native wolfSSL library */

    /**
     * Internal wolfSSL I/O receive callback, using byte array.
     */
    private int internalIOSSLRecvCallback(WolfSSLSession ssl,
        byte[] buf, int sz)
    {
        /* call user-registered recv method */
        return internRecvSSLCb_array.receiveCallback(ssl, buf, sz,
            ssl.getIOReadCtx());
    }

    /**
     * Internal wolfSSL I/O receive callback, using ByteBuffer.
     */
    private int internalIOSSLRecvCallback(WolfSSLSession ssl,
            ByteBuffer buf, int sz)
    {
        /* call user-registered recv method */
        return internRecvSSLCb_BB.receiveCallback(ssl, buf, sz,
            ssl.getIOReadCtx());
    }

    /**
     * Internal wolfSSL I/O send callback, using byte array.
     */
    private int internalIOSSLSendCallback(WolfSSLSession ssl,
        byte[] buf, int sz)
    {
        /* call user-registered recv method */
        return internSendSSLCb_array.sendCallback(ssl, buf, sz,
            ssl.getIOWriteCtx());
    }

    /**
     * Internal wolfSSL I/O send callback, using ByteBuffer.
     */
    private int internalIOSSLSendCallback(WolfSSLSession ssl,
            ByteBuffer buf, int sz)
    {
        /* call user-registered recv method */
        return internSendSSLCb_BB.sendCallback(ssl, buf, sz,
            ssl.getIOWriteCtx());
    }

    private long internalPskClientCallback(WolfSSLSession ssl, String hint,
            StringBuffer identity, long idMaxLen, byte[] key,
            long keyMaxLen)
    {
        /* call user-registered PSK client callback method */
        return internPskClientCb.pskClientCallback(ssl, hint, identity,
            idMaxLen, key, keyMaxLen);
    }

    private long internalPskServerCallback(WolfSSLSession ssl,
            String identity, byte[] key, long keyMaxLen)
    {
        /* call user-registered PSK server callback method */
        return internPskServerCb.pskServerCallback(ssl, identity,
            key, keyMaxLen);
    }

    private int internalAlpnSelectCallback(WolfSSLSession ssl, String[] out,
        String[] in)
    {
        /* call user-registered ALPN select callback */
        return internAlpnSelectCb.alpnSelectCallback(ssl, out, in,
            this.alpnSelectArg);
    }

    private int internalTls13SecretCallback(WolfSSLSession ssl, int id,
        byte[] secret)
    {
        /* call user-registered TLS 1.3 secret callback */
        return internTls13SecretCb.tls13SecretCallback(ssl, id, secret,
            this.tls13SecretCtx);
    }

    private int internalSessionTicketCallback(WolfSSLSession ssl, byte[] ticket)
    {
        /* call user-registered session ticket callback */
        return internSessionTicketCb.sessionTicketCallback(ssl, ticket,
            this.sessionTicketCtx);
    }

    /**
     * Verifies that the current WolfSSLSession object is active.
     *
     * @throws IllegalStateException if object has been freed
     */
    private synchronized void confirmObjectIsActive()
        throws IllegalStateException {

        synchronized (stateLock) {
            if (this.active == false) {
                throw new IllegalStateException(
                    "WolfSSLSession object has been freed");
            }
        }
    }

    /* ------------------ native method declarations -------------------- */

    private native long newSSL(long ctx, boolean withIOPipe);
    private native int setFd(long ssl, Socket sd, int type);
    private native int setFd(long ssl, DatagramSocket sd, int type);
    private native int useCertificateFile(long ssl, String file, int format);
    private native int usePrivateKeyFile(long ssl, String file, int format);
    private native int useCertificateChainFile(long ssl, String file);
    private native void setUsingNonblock(long ssl, int nonblock);
    private native int getUsingNonblock(long ssl);
    private native int getFd(long ssl);
    private native int connect(long ssl, int timeout);
    private native int write(long ssl, byte[] data, int offset, int length,
        int timeout);
    private native int write(long ssl, ByteBuffer data, final int position,
        final int limit, boolean hasArray, int sz, int timeout)
        throws WolfSSLException;
    private native int read(long ssl, byte[] data, int offset, int sz,
        int timeout);
    private native int read(long ssl, ByteBuffer data, final int position,
        final int limit, boolean hasArray, int sz, int timeout)
        throws WolfSSLException;
    private native int pending(long ssl);
    private native int accept(long ssl, int timeout);
    private native void freeSSL(long ssl);
    private native int shutdownSSL(long ssl, int timeout);
    private native int getError(long ssl, int ret);
    private native int setSession(long ssl, long session);
    private native long getSession(long ssl);
    private native long get1Session(long ssl);
    private static native int wolfsslSessionIsSetup(long ssl);
    private static native int wolfsslSessionIsResumable(long ssl);
    private static native long wolfsslSessionDup(long session);
    private static native String wolfsslSessionCipherGetName(long ssl);
    private static native void freeNativeSession(long session);
    private native byte[] getSessionID(long session);
    private native int setServerID(long ssl, byte[] id, int len, int newSess);
    private native int setTimeout(long ssl, long t);
    private native long getTimeout(long ssl);
    private native int setSessTimeout(long session, long t);
    private native long getSessTimeout(long session);
    private native int setCipherList(long ssl, String list);
    private native int dtlsGetCurrentTimeout(long ssl);
    private native int dtlsGotTimeout(long ssl);
    private native int dtlsRetransmit(long ssl);
    private native int dtls(long ssl);
    private native int dtlsSetPeer(long ssl, InetSocketAddress peer);
    private native int sendHrrCookie(long ssl, byte[] secret);
    private native long getDtlsMacDropCount(long ssl);
    private native long getDtlsReplayDropCount(long ssl);
    private native InetSocketAddress dtlsGetPeer(long ssl);
    private native int sessionReused(long ssl);
    private native int getPeerCertificateCount(long ssl);
    private native long getPeerCertificate(long ssl, int index);
    private native String getPeerX509Issuer(long ssl, long x509);
    private native String getPeerX509Subject(long ssl, long x509);
    private native String getPeerX509AltName(long ssl, long x509);
    private native String getVersion(long ssl);
    private native long getCurrentCipher(long ssl);
    private native int checkDomainName(long ssl, String dn);
    private native int setTmpDH(long ssl, byte[] p, int pSz, byte[] g, int gSz);
    private native int setTmpDHFile(long ssl, String fname, int format);
    private native int useCertificateBuffer(long ssl, byte[] in, long sz,
            int format);
    private native int usePrivateKeyBuffer(long ssl, byte[] in, long sz,
            int format);
    private native int useCertificateChainBuffer(long ssl, byte[] in,
            long sz);
    private native int useCertificateChainBufferFormat(
            long ssl, byte[] in, long sz, int format);
    private native int setGroupMessages(long ssl);
    private native int enableCRL(long ssl, int options);
    private native int disableCRL(long ssl);
    private native int loadCRL(long ssl, String path, int type, int monitor);
    private native int setCRLCb(long ssl, WolfSSLMissingCRLCallback cb);
    private native String cipherGetName(long ssl);
    private native byte[] getMacSecret(long ssl, int verify);
    private native byte[] getClientWriteKey(long ssl);
    private native byte[] getClientWriteIV(long ssl);
    private native byte[] getServerWriteKey(long ssl);
    private native byte[] getServerWriteIV(long ssl);
    private native int getKeySize(long ssl);
    private native int getSide(long ssl);
    private native int isTLSv1_1(long ssl);
    private native int getBulkCipher(long ssl);
    private native int getCipherBlockSize(long ssl);
    private native int getAeadMacSize(long ssl);
    private native int getHmacSize(long ssl);
    private native int getHmacType(long ssl);
    private native int getCipherType(long ssl);
    private native int setTlsHmacInner(long ssl, byte[] inner, long sz,
            int content, int verify);
    private native void setEccSignCtx(long ssl);
    private native void setEccVerifyCtx(long ssl);
    private native void setEccSharedSecretCtx(long ssl);
    private native void setRsaSignCtx(long ssl);
    private native void setRsaVerifyCtx(long ssl);
    private native void setRsaEncCtx(long ssl);
    private native void setRsaDecCtx(long ssl);
    private native void setPskClientCb(long ctx);
    private native void setPskServerCb(long ctx);
    private native String getPskIdentityHint(long ssl);
    private native String getPskIdentity(long ssl);
    private native int usePskIdentityHint(long ssl, String hint);
    private native boolean handshakeDone(long ssl);
    private native void setConnectState(long ssl);
    private native void setAcceptState(long ssl);
    private native void setVerify(long ssl, int mode, WolfSSLVerifyCallback vc);
    private native long setOptions(long ssl, long op);
    private native long getOptions(long ssl);
    private native int getShutdown(long ssl);
    private native void setSSLIORecv(long ssl);
    private native void setSSLIOSend(long ssl);
    private native int useSNI(long ssl, byte type, byte[] data);
    private native byte[] getSNIRequest(long ssl, byte type);
    private native int useSessionTicket(long ssl);
    private native int gotCloseNotify(long ssl);
    private native int sslSetAlpnProtos(long ssl, byte[] alpnProtos);
    private native byte[] sslGet0AlpnSelected(long ssl);
    private native int useALPN(long ssl, String protocols, int options);
    private native int setALPNSelectCb(long ssl);
    private native int setTls13SecretCb(long ssl);
    private native int setSessionTicketCb(long ssl);
    private native void keepArrays(long ssl);
    private native byte[] getClientRandom(long ssl);
    private native int useSecureRenegotiation(long ssl);
    private native int rehandshake(long ssl);
    private native int set1SigAlgsList(long ssl, String list);
    private native int useSupportedCurve(long ssl, int name);
    private native int disableExtendedMasterSecret(long ssl);
    private native int hasTicket(long session);
    private native int interruptBlockedIO(long ssl);
    private native int getThreadsBlockedInPoll(long ssl);
    private native int setMTU(long ssl, int mtu);
    private native String stateStringLong(long ssl);
    private native int getMaxOutputSize(long ssl);

    /* ------------------- session-specific methods --------------------- */

    /**
     * Loads a certificate file into the SSL session object.
     * This file is provided by the <b>file</b> parameter. The <b>format</b>
     * paramenter specifies the format type of the file - either
     * <b>SSL_FILETYPE_ASN1</b> or <b>SSL_FILETYPE_PEM</b>. Please see the
     * wolfSSL examples for proper usage.
     *
     * @param file      a file containing the certificate to be loaded into
     *                  the wolfSSL SSL session object.
     * @param format    format of the certificates pointed to by <code>file
     *                  </code>. Possible options are <b>SSL_FILETYPE_ASN1</b>,
     *                  for DER-encoded certificates, or <b>SSL_FILETYPE_PEM
     *                  </b> for PEM-encoded certificates.
     * @return          <code>SSL_SUCCESS</code> upon success,
     *                  <code>SSL_BAD_FILE</code> upon bad input file,
     *                  otherwise <code>SSL_FAILURE</code>. Possible failure
     *                  causes may be that the file is in the wrong format, the
     *                  format argument was given incorrectly, the file
     *                  doesn't exist, can't be read, or is corrupted,
     *                  an out of memory condition occurs, or the Base16
     *                  decoding fails on the file.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @see    WolfSSLContext#useCertificateFile(String, int)
     */
    public int useCertificateFile(String file, int format)
        throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered useCertificateFile(" + file + ", " +
                format + ")");

            return useCertificateFile(this.sslPtr, file, format);
        }
    }

    /**
     * Loads a private key file into the SSL session object.
     * This file is provided by the <b>file</b> parameter. The <b>format</b>
     * paramenter specifies the format type of the file - either
     * <b>SSL_FILETYPE_ASN1</b> or <b>SSL_FILETYPE_PEM</b>. Please see the
     * wolfSSL examples for proper usage.
     *
     * @param file      a file containing the private key to be loaded into
     *                  the wolfSSL SSL session.
     * @param format    format of the private key pointed to by <code>file
     *                  </code>. Possible options are <b>SSL_FILETYPE_ASN1</b>,
     *                  for a DER-encoded key, or <b>SSL_FILETYPE_PEM
     *                  </b> for a PEM-encoded key.
     * @return          <code>SSL_SUCCESS</code> upon success,
     *                  <code>SSL_BAD_FILE</code> upon bad input file, otherwise
     *                  <code>SSL_FAILURE</code>. Possible failure causes
     *                  may be that the file is in the wrong format, the
     *                  format argument was given incorrectly, the file
     *                  doesn't exist, can't be read, or is corrupted,
     *                  an out of memory condition occurs, the Base16
     *                  decoding fails on the file, or the key file is
     *                  encrypted but no password is provided.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @see    WolfSSLContext#usePrivateKeyFile(String, int)
     */
    public int usePrivateKeyFile(String file, int format)
        throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered usePrivateKeyFile(" + file + ", " +
                format + ")");

            return usePrivateKeyFile(this.sslPtr, file, format);
        }
    }

    /**
     * Loads a chain of certificates into the SSL session object.
     * The file containing the certificate chain is provided by the <b>file</b>
     * parameter and must contain PEM-formatted certificates. This function
     * will process up to <code>MAX_CHAIN_DEPTH</code> (default = 9, defined
     * in internal.h) certificates, plus the subject cert.
     *
     * @param file  path to the file containing the chain of certificates
     *              to be loaded into the wolfSSL SSL session. Certificates
     *              must be in PEM format.
     * @return      <code>SSL_SUCCESS</code> on success,
     *              <code>SSL_BAD_FILE</code> upon bad input file, otherwise
     *              <code>SSL_FAILURE</code>. If the function call fails,
     *              possible causes might include: the file is in the wrong
     *              format, the file doesn't exist, can't be read, or is
     *              corrupted, or an out of memory condition occurs.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @see    WolfSSLContext#useCertificateFile(String, int)
     * @see    #useCertificateFile(String, int)
     */
    public int useCertificateChainFile(String file)
        throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered useCertificateChainFile(" + file + ")");

            return useCertificateChainFile(this.sslPtr, file);
        }
    }


    /**
     * Assigns a Socket file descriptor as the input/output facility for the
     * SSL connection.
     *
     * @param sd Socket to be used as input/output facility.
     * @return   <code>SSL_SUCCESS</code> on success, otherwise
     *           <code>SSL_FAILURE</code>.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @see    #getFd()
     */
    public int setFd(Socket sd) throws IllegalStateException {

        int ret;

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered setFd(" + sd + ")");

            ret = setFd(this.sslPtr, sd, 1);

            if (ret == WolfSSL.SSL_SUCCESS) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                    WolfSSLDebug.INFO, this.sslPtr,
                    () -> "native fd set to: " + getFd(this.sslPtr));
            }

            return ret;
        }
    }

    /**
     * Assigns a DatagramSocket file descriptor as the input/output facility
     * for the SSL connection.
     * This can be used when using DatagramSocket objects with DTLS.
     *
     * @param sd Socket to be used as input/output facility.
     * @return   <code>SSL_SUCCESS</code> on success, otherwise
     *           <code>SSL_FAILURE</code>.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @see    #getFd()
     */
    public int setFd(DatagramSocket sd) throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered setFd(" + sd + ")");

            return setFd(this.sslPtr, sd, 2);
        }
    }

    /**
     * Informs wolfSSL session that the underlying I/O is non-blocking.
     * After an application creates a SSL session (native WOLFSSL object),
     * if it will be used with a non-blocking socket, this method should
     * be called. This lets the SSL session know that receiving EWOULDBLOCK
     * means that the recvfrom call would block rather than that it timed out.
     *
     * @param nonblock  value used to set non-blocking flag on the SSL
     *                  session. Use <b>1</b> to specify non-blocking,
     *                  otherwise <b>0</b>.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    #getUsingNonblock()
     * @see    #dtlsGotTimeout()
     * @see    #dtlsGetCurrentTimeout()
     */
    public void setUsingNonblock(int nonblock)
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered setUsingNonblock(" + nonblock + ")");

            setUsingNonblock(this.sslPtr, nonblock);
        }
    }

    /**
     * Allows the application to determine if wolfSSL is using non-blocking
     * I/O.
     * After an application created an SSL session object, if it will be used
     * with a non-blocking socket, call <code>setUsingNonblock()</code> on it.
     * This lets the SSL session object know that receiving EWOULDBLOCK means
     * that the recvfrom call would block rather than that it timed out.
     *
     * @return <b>1</b> if the underlying I/O is non-blocking, otherwise
     *         <b>0</b> if blocking.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    #setUsingNonblock(int)
     * @see    #setSession(long)
     */
    public int getUsingNonblock()
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered getUsingNonblock()");

            return getUsingNonblock(this.sslPtr);
        }
    }

    /**
     * Returns the file descriptor used as the input/output facility for the
     * SSL connection.
     * Typically this will be a socket file descriptor.
     *
     * @return SSL session file descriptor
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    #setFd(Socket)
     */
    public int getFd()
        throws IllegalStateException, WolfSSLJNIException {

        final int fd;

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr, () -> "entered getFd()");

            fd = getFd(this.sslPtr);

            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr, () -> "returning fd: " + fd);
        }

        return fd;
    }

    /**
     * Helper method to throw appropriate exception based on native
     * result of poll()/select() from API that does I/O.
     */
    private static void throwExceptionFromIOReturnValue(
        int ret, String nativeFunc)
        throws SocketTimeoutException, SocketException {

        if (ret == WolfSSL.WOLFJNI_IO_EVENT_TIMEOUT) {
            throw new SocketTimeoutException(
                "Native socket timed out during " + nativeFunc);
        }
        else if (ret == WolfSSL.WOLFJNI_IO_EVENT_FD_CLOSED) {
            throw new SocketException("Socket fd closed during poll(), " +
                "errno = " + WolfSSL.getErrno());
        }
        else if (ret == WolfSSL.WOLFJNI_IO_EVENT_ERROR) {
            throw new SocketException("Socket fd poll() exceptional error, " +
                "errno = " + WolfSSL.getErrno());
        }
        else if (ret == WolfSSL.WOLFJNI_IO_EVENT_POLLHUP) {
            throw new SocketException("Socket disconnected during poll(), " +
                "errno = " + WolfSSL.getErrno());
        }
        else if (ret == WolfSSL.WOLFJNI_IO_EVENT_FAIL) {
            throw new SocketException("Socket select/poll() failed, " +
                "errno = " + WolfSSL.getErrno());
        }
    }

    /**
     * Initializes an SSL/TLS handshake with a server.
     * This function is called on the client side. When called, the underlying
     * communication channel should already be set up.
     * <p>
     * <code>connect()</code> works with both blocking and non-blocking I/O.
     * When the underlying I/O is non-blocking, <code>connect()</code> will
     * return when the underlying I/O could not satisfy the needs of
     * <code>connect()</code> to continue the handshake. In this case, a call
     * to <code>getError</code> will yield either <b>SSL_ERROR_WANT_READ</b> or
     * <b>SSL_ERROR_WANT_WRITE</b>. The calling process must then repeat the
     * call to <code>connect()</code> when the underlying I/O is ready and
     * wolfSSL will pick up where it left off.
     * </p><p>
     * If the underlying I/O is blocking, <code>connect()</code> will only
     * return once the handshake has been finished or an error occurred.
     * </p><p>
     * wolfSSL takes a different approach to certificate verification than
     * OpenSSL does. The default policy for clients is to verify the server,
     * meaning that if the application doesn't load CA certificates to verify
     * the server, it will get a connect error, "unable to verify" (-155). If
     * the application wants to mimic OpenSSL behavior of having
     * <code>connect()</code> succeed even if verifying the server fails (and
     * reducing security), the application can do this by calling:
     * </p><p>
     * <code>WolfSSLContext#setVerify(ctx, SSL_VERIFY_NONE, 0);</code>
     * </p><p>
     * before calling <code>newSSL()</code>, though it's not recommended.
     * </p>
     *
     * @return <code>SSL_SUCCESS</code> if successful, otherwise
     *         <code>SSL_FAILURE</code> if an error occurred. To get
     *         a more detailed error code, call <code>getError()</code>.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws SocketTimeoutException if underlying socket timed out
     * @throws SocketException Native socket select() or poll() failed
     */
    public int connect()
        throws IllegalStateException, SocketTimeoutException, SocketException {

        return connect(0);
    }

    /**
     * Initializes an SSL/TLS handshake with a server, using socket timeout
     * value in milliseconds.
     * This function is called on the client side. When called, the underlying
     * communication channel should already be set up.
     * <p>
     * <code>connect()</code> works with both blocking and non-blocking I/O.
     * When the underlying I/O is non-blocking, <code>connect()</code> will
     * return when the underlying I/O could not satisfy the needs of
     * <code>connect()</code> to continue the handshake. In this case, a call
     * to <code>getError</code> will yield either <b>SSL_ERROR_WANT_READ</b> or
     * <b>SSL_ERROR_WANT_WRITE</b>. The calling process must then repeat the
     * call to <code>connect()</code> when the underlying I/O is ready and
     * wolfSSL will pick up where it left off.
     * <p>
     * If the underlying I/O is blocking, <code>connect()</code> will only
     * return once the handshake has been finished or an error occurred.
     * <p>
     * wolfSSL takes a different approach to certificate verification than
     * OpenSSL does. The default policy for clients is to verify the server,
     * meaning that if the application doesn't load CA certificates to verify
     * the server, it will get a connect error, "unable to verify" (-155). If
     * the application wants to mimic OpenSSL behavior of having
     * <code>connect()</code> succeed even if verifying the server fails (and
     * reducing security), the application can do this by calling:
     * <p>
     * <code>WolfSSLContext#setVerify(ctx, SSL_VERIFY_NONE, 0);</code>
     * <p>
     * before calling <code>newSSL()</code>, though it's not recommended.
     *
     * @param timeout read timeout, milliseconds. Specify 0 to use infinite
     *                timeout
     *
     * @return <code>SSL_SUCCESS</code> if successful, otherwise
     *         <code>SSL_FAILURE</code> if an error occurred. To get
     *         a more detailed error code, call <code>getError()</code>.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws SocketTimeoutException if socket timeout occurs
     * @throws SocketException Native socket select() or poll() failed
     */
    public int connect(int timeout)
        throws IllegalStateException, SocketTimeoutException, SocketException {

        final int ret;

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered connect(timeout: " + timeout +")");

            ret = connect(this.sslPtr, timeout);

            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "connect() ret: " + ret + ", err: " + getError(ret));
        }

        throwExceptionFromIOReturnValue(ret, "wolfSSL_connect()");

        return ret;
    }

    /**
     * Write bytes from a byte array to the SSL connection.
     * If necessary, <code>write()</code> will negotiate an SSL/TLS session
     * if the handshake has not already been performed yet by <code>connect
     * </code> or <code>accept</code>.
     * <p>
     * <code>write()</code> works with both blocking and non-blocking I/O.
     * When the underlying I/O is non-blocking, <code>write()</code> will
     * return when the underlying I/O could not satisfy the needs of <code>
     * write()</code> to continue. In this case, a call to <code>getError
     * </code> will yield either <b>SSL_ERROR_WANT_READ</b> or
     * <b>SSL_ERROR_WANT_WRITE</b>. The calling process must then repeat the
     * call to <code>write()</code> when the underlying I/O is ready.
     * <p>
     * If the underlying I/O is blocking, <code>write()</code> will only
     * return once the buffer <b>data</b> of size <b>length</b> has been
     * completely written or an error occurred.
     *
     * @param data   data buffer which will be sent to peer
     * @param length size, in bytes, of data to send to the peer
     * @return       the number of bytes written upon success. <code>0
     *               </code>or a negative value will be returned upon failure.
     *               <code>SSL_FAILURE</code>return upon failure when either
     *               an error occurred or, when using non-blocking sockets,
     *               the <b>SSL_ERROR_WANT_READ</b> or
     *               <b>SSL_ERROR_WANT_WRITE</b> error was received and the
     *               application needs to call <code>write()</code> again.
     *               <code>BAD_FUNC_ARC</code> when bad arguments are used.
     *               Use <code>getError</code> to get a specific error code.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws SocketTimeoutException if socket timeout occurs
     * @throws SocketException Native socket select() or poll() failed
     */
    public int write(byte[] data, int length)
        throws IllegalStateException, SocketTimeoutException, SocketException {

        return write(data, 0, length, 0);
    }

    /**
     * Write bytes from a byte array to the SSL connection, using socket
     * timeout value in milliseconds.
     * If necessary, <code>write()</code> will negotiate an SSL/TLS session
     * if the handshake has not already been performed yet by <code>connect
     * </code> or <code>accept</code>.
     * <p>
     * <code>write()</code> works with both blocking and non-blocking I/O.
     * When the underlying I/O is non-blocking, <code>write()</code> will
     * return when the underlying I/O could not satisfy the needs of <code>
     * write()</code> to continue. In this case, a call to <code>getError
     * </code> will yield either <b>SSL_ERROR_WANT_READ</b> or
     * <b>SSL_ERROR_WANT_WRITE</b>. The calling process must then repeat the
     * call to <code>write()</code> when the underlying I/O is ready.
     * <p>
     * If the underlying I/O is blocking, <code>write()</code> will only
     * return once the buffer <b>data</b> of size <b>length</b> has been
     * completely written or an error occurred.
     *
     * @param data   data buffer which will be sent to peer
     * @param length size, in bytes, of data to send to the peer
     * @param timeout read timeout, milliseconds.
     * @return       the number of bytes written upon success. <code>0
     *               </code>will be returned upon failure. <code>
     *               SSL_FATAL_ERROR</code>upon failure when either an
     *               error occurred or, when using non-blocking sockets,
     *               the <b>SSL_ERROR_WANT_READ</b> or
     *               <b>SSL_ERROR_WANT_WRITE</b> error was received and the
     *               application needs to call <code>write()</code> again.
     *               <code>BAD_FUNC_ARC</code> when bad arguments are used.
     *               Use <code>getError</code> to get a specific error code.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws SocketTimeoutException if socket timeout occurs
     * @throws SocketException Native socket select/poll() failed
     */
    public int write(byte[] data, int length, int timeout)
        throws IllegalStateException, SocketTimeoutException, SocketException {

        return write(data, 0, length, timeout);
    }

    /**
     * Write bytes from a byte array to the SSL connection, using socket
     * timeout value in milliseconds.
     * If necessary, <code>write()</code> will negotiate an SSL/TLS session
     * if the handshake has not already been performed yet by <code>connect
     * </code> or <code>accept</code>.
     * <p>
     * <code>write()</code> works with both blocking and non-blocking I/O.
     * When the underlying I/O is non-blocking, <code>write()</code> will
     * return when the underlying I/O could not satisfy the needs of <code>
     * write()</code> to continue. In this case, a call to <code>getError
     * </code> will yield either <b>SSL_ERROR_WANT_READ</b> or
     * <b>SSL_ERROR_WANT_WRITE</b>. The calling process must then repeat the
     * call to <code>write()</code> when the underlying I/O is ready.
     * <p>
     * If the underlying I/O is blocking, <code>write()</code> will only
     * return once the buffer <b>data</b> of size <b>length</b> has been
     * completely written or an error occurred.
     *
     * @param data   data buffer which will be sent to peer
     * @param offset offset into data buffer to start writing from
     * @param length size, in bytes, of data to send to the peer
     * @param timeout read timeout, milliseconds.
     * @return       the number of bytes written upon success. <code>0
     *               </code>will be returned upon failure. <code>
     *               SSL_FATAL_ERROR</code>upon failure when either an
     *               error occurred or, when using non-blocking sockets,
     *               the <b>SSL_ERROR_WANT_READ</b> or
     *               <b>SSL_ERROR_WANT_WRITE</b> error was received and the
     *               application needs to call <code>write()</code> again.
     *               <code>BAD_FUNC_ARC</code> when bad arguments are used.
     *               Use <code>getError</code> to get a specific error code.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws SocketTimeoutException if socket timeout occurs
     * @throws SocketException Native socket select/poll() failed
     */
    public int write(byte[] data, int offset, int length, int timeout)
        throws IllegalStateException, SocketTimeoutException, SocketException {

        int ret = 0;
        int err = 0;
        int totalWritten = 0;
        int remaining = length;
        long localPtr;
        ByteBuffer directBuffer = null;

        confirmObjectIsActive();

        /* Fix for Infer scan, since not synchronizing on sslLock for
         * access to this.sslPtr, see note below */
        synchronized (sslLock) {
            localPtr = this.sslPtr;
        }

        WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
            WolfSSLDebug.INFO, localPtr,
            () -> "entered write(offset: " + offset + ", length: " +
            length + ", timeout: " + timeout + ")");

        /* Use a direct ByteBuffer from the pool to avoid unaligned
         * memory access. Otherwise our native JNI code may need to do
         * "buffer + offset" and end up with unaligned memory which
         * can be slow on some targets (ex: ARM/Aarch64) */
        try {
            if (!this.byteBufferPoolEnabled) {
                /* Throw exception so we fall back to using byte[] in the
                 * catch block below */
                throw new Exception("ByteBuffer pool not enabled");
            }

            /* Get a buffer from the pool */
            directBuffer = acquireDirectBuffer();

            WolfSSLDebug.log(getClass(),
                WolfSSLDebug.Component.JNI, WolfSSLDebug.INFO, localPtr,
                () -> "write() using thread-local ByteBuffer pool: pool size: " +
                directBufferPool.get().size());

            /* Write in chunks until all data is written or an error occurs.
             * The DirectByteBuffer size might be smaller than the data length,
             * so we need to loop to handle all the data */
            while (remaining > 0) {
                /* Calculate size for current chunk */
                int writeSize = Math.min(remaining, directBuffer.capacity());

                /* Copy data from user array to direct buffer */
                directBuffer.clear();
                directBuffer.put(data, offset + totalWritten, writeSize);
                directBuffer.flip();

                /* Call native write with DirectByteBuffer */
                ret = write(localPtr, directBuffer, directBuffer.position(),
                    directBuffer.limit(), false, writeSize, timeout);

                if (ret <= 0) {
                    /* Error occurred, break out of loop */
                    err = getError(ret);
                    break;
                }

                /* Update tracking variables */
                totalWritten += ret;
                remaining -= ret;
            }

        } catch (Exception e) {

            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.ERROR, localPtr,
                () -> "write() falling back to use byte[]");

            /* Fall back to original implementation on exception (write not
             * done yet at this point in JNI call above) */
            totalWritten = write(localPtr, data, offset, length, timeout);

        } finally {
            /* Return buffer to pool */
            if (directBuffer != null) {
                releaseDirectBuffer(directBuffer);
            }
        }

        /* Return total bytes written, or last error code */
        final int finalRet = (totalWritten > 0) ? totalWritten : ret;
        final int finalErr = err;
        final int finalTotal = totalWritten;

        WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
            WolfSSLDebug.INFO, localPtr,
            () -> "write() ret: " + finalRet + ", err: " + finalErr +
                  ", totalWritten: " + finalTotal);

        throwExceptionFromIOReturnValue(finalRet, "wolfSSL_write()");

        return finalRet;
    }

    /**
     * Reads bytes from the SSL session and returns the read bytes as a byte
     * array.
     * The bytes read are removed from the internal receive buffer.
     * <p>
     * If necessary, <code>read()</code> will negotiate an SSL/TLS session
     * if the handshake has not already been performed yet by <code>connect()
     * </code> or <code>accept()</code>.
     * <p>
     * The SSL/TLS protocol uses SSL records which have a maximum size of
     * 16kB. As such, wolfSSL needs to read an entire SSL record internally
     * before it is able to process and decrypt the record. Because of this,
     * a call to <code>read()</code> will only be able to return the
     * maximum buffer size which has been decrypted at the time of calling.
     * There may be additional not-yet-decrypted data waiting in the internal
     * wolfSSL receive buffer which will be retrieved and decrypted with the
     * next call to <code>read()</code>.
     *
     * @param data  buffer where the data read from the SSL connection
     *              will be placed.
     * @param sz    number of bytes to read into <b><code>data</code></b>
     * @return      the number of bytes read upon success. <code>SSL_FAILURE
     *              </code> will be returned upon failure which may be caused
     *              by either a clean (close notify alert) shutdown or just
     *              that the peer closed the connection. <code>
     *              SSL_FATAL_ERROR</code> upon failure when either an error
     *              occurred or, when using non-blocking sockets, the
     *              <b>SSL_ERROR_WANT_READ</b> or <b>SSL_ERROR_WANT_WRITE</b>
     *              error was received and the application needs to call
     *              <code>read()</code> again. Use <code>getError</code> to
     *              get a specific error code.
     *              <code>BAD_FUNC_ARC</code> when bad arguments are used.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws SocketTimeoutException if socket timeout occurs, should not
     *         occur since infinite timeout is used for this call.
     * @throws SocketException Native socket select/poll() failed
     */
    public int read(byte[] data, int sz)
        throws IllegalStateException, SocketTimeoutException, SocketException {

        return read(data, 0, sz, 0);
    }

    /**
     * Reads bytes from the SSL session and returns the read bytes as a byte
     * array, using socket timeout value in milliseconds.
     * The bytes read are removed from the internal receive buffer.
     * <p>
     * If necessary, <code>read()</code> will negotiate an SSL/TLS session
     * if the handshake has not already been performed yet by <code>connect()
     * </code> or <code>accept()</code>.
     * <p>
     * The SSL/TLS protocol uses SSL records which have a maximum size of
     * 16kB. As such, wolfSSL needs to read an entire SSL record internally
     * before it is able to process and decrypt the record. Because of this,
     * a call to <code>read()</code> will only be able to return the
     * maximum buffer size which has been decrypted at the time of calling.
     * There may be additional not-yet-decrypted data waiting in the internal
     * wolfSSL receive buffer which will be retrieved and decrypted with the
     * next call to <code>read()</code>.
     *
     * @param data  buffer where the data read from the SSL connection
     *              will be placed.
     * @param sz    number of bytes to read into <b><code>data</code></b>
     * @param timeout read timeout, milliseconds.
     * @return      the number of bytes read upon success. <code>SSL_FAILURE
     *              </code> will be returned upon failure which may be caused
     *              by either a clean (close notify alert) shutdown or just
     *              that the peer closed the connection. <code>
     *              SSL_FATAL_ERROR</code> upon failure when either an error
     *              occurred or, when using non-blocking sockets, the
     *              <b>SSL_ERROR_WANT_READ</b> or <b>SSL_ERROR_WANT_WRITE</b>
     *              error was received and the application needs to call
     *              <code>read()</code> again. Use <code>getError</code> to
     *              get a specific error code.
     *              <code>BAD_FUNC_ARC</code> when bad arguments are used.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws SocketTimeoutException if socket timeout occurs
     * @throws SocketException Native socket select/poll() failed
     */
    public int read(byte[] data, int sz, int timeout)
        throws IllegalStateException, SocketTimeoutException, SocketException {

        return read(data, 0, sz, timeout);
    }

    /**
     * Reads bytes from the SSL session and returns the read bytes as a byte
     * array, using socket timeout value in milliseconds.
     * The bytes read are removed from the internal receive buffer.
     * <p>
     * If necessary, <code>read()</code> will negotiate an SSL/TLS session
     * if the handshake has not already been performed yet by <code>connect()
     * </code> or <code>accept()</code>.
     * <p>
     * The SSL/TLS protocol uses SSL records which have a maximum size of
     * 16kB. As such, wolfSSL needs to read an entire SSL record internally
     * before it is able to process and decrypt the record. Because of this,
     * a call to <code>read()</code> will only be able to return the
     * maximum buffer size which has been decrypted at the time of calling.
     * There may be additional not-yet-decrypted data waiting in the internal
     * wolfSSL receive buffer which will be retrieved and decrypted with the
     * next call to <code>read()</code>.
     *
     * @param data  buffer where the data read from the SSL connection
     *              will be placed.
     * @param offset offset into data buffer for data to be placed.
     * @param sz    number of bytes to read into <b><code>data</code></b>
     * @param timeout read timeout, milliseconds.
     * @return      the number of bytes read upon success. <code>SSL_FAILURE
     *              </code> will be returned upon failure which may be caused
     *              by either a clean (close notify alert) shutdown or just
     *              that the peer closed the connection. <code>
     *              SSL_FATAL_ERROR</code> upon failure when either an error
     *              occurred or, when using non-blocking sockets, the
     *              <b>SSL_ERROR_WANT_READ</b> or <b>SSL_ERROR_WANT_WRITE</b>
     *              error was received and the application needs to call
     *              <code>read()</code> again. Use <code>getError</code> to
     *              get a specific error code.
     *              <code>BAD_FUNC_ARC</code> when bad arguments are used.
     * @throws IllegalStateException WolfSSLSession has been freed
     * @throws SocketTimeoutException if socket timeout occurs
     * @throws SocketException Native socket select/poll() failed
     */
    public int read(byte[] data, int offset, int sz, int timeout)
        throws IllegalStateException, SocketTimeoutException, SocketException {

        int ret;
        int err;
        int readSz = sz;
        final int readOff = offset;
        final int tmpReadSz = sz;
        final int readTimeout = timeout;
        long localPtr;
        ByteBuffer directBuffer = null;

        confirmObjectIsActive();

        /* Fix for Infer scan, since not synchronizing on sslLock for
         * access to this.sslPtr, see note below */
        synchronized (sslLock) {
            localPtr = this.sslPtr;
        }

        WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
            WolfSSLDebug.INFO, localPtr,
            () -> "entered read(offset: " + readOff + ", sz: " + tmpReadSz +
            ", timeout: " + readTimeout + ")");

        /* Use a DirectByteBuffer from the pool to avoid unaligned
         * memory access. Otherwise our native JNI code may need to
         * do "buffer + offset" and end up with unaligned memory which
         * can be slow on some targets (ex: ARM/Aarch64) */
        try {
            if (!this.byteBufferPoolEnabled) {
                /* Throw exception so we fall back to using byte[] in the
                 * catch block below */
                throw new Exception("ByteBuffer pool not enabled");
            }

            /* Get a buffer from the pool */
            directBuffer = acquireDirectBuffer();

            WolfSSLDebug.log(getClass(),
                WolfSSLDebug.Component.JNI, WolfSSLDebug.INFO, localPtr,
                () -> "read() using thread-local ByteBuffer pool: pool size: " +
                directBufferPool.get().size());

            /* Only read up to the size of the buffer or readSz,
             * whichever is smaller. */
            readSz = Math.min(readSz, directBuffer.capacity());

            /* Use direct buffer for JNI call */
            directBuffer.limit(readSz);

            /* Call native read with DirectByteBuffer */
            ret = read(localPtr, directBuffer, 0, readSz, false,
                readSz, readTimeout);

            if (ret > 0) {
                /* Copy data from direct buffer to user array */
                directBuffer.flip();
                directBuffer.get(data, offset, ret);
            }

            err = getError(ret);

        } catch (Exception e) {

            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, localPtr,
                () -> "read() falling back to use byte[]");

            /* Fall back to original implementation on errors */
            ret = read(localPtr, data, readOff, readSz, readTimeout);
            err = getError(ret);

        } finally {

            /* Return buffer to pool */
            if (directBuffer != null) {
                releaseDirectBuffer(directBuffer);
            }
        }

        final int finalRet = ret;
        final int finalErr = err;
        WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
            WolfSSLDebug.INFO, localPtr,
            () -> "read() ret: " + finalRet + ", err: " + finalErr);

        throwExceptionFromIOReturnValue(ret, "wolfSSL_read()");

        return ret;
    }

    /**
     * Reads bytes from the SSL session and returns the read bytes into
     * the provided ByteBuffer, using socket timeout value in milliseconds.
     *
     * The bytes read are removed from the internal receive buffer.
     * <p>
     * If necessary, <code>read()</code> will negotiate an SSL/TLS session
     * if the handshake has not already been performed yet by <code>connect()
     * </code> or <code>accept()</code>.
     * <p>
     * The SSL/TLS protocol uses SSL records which have a maximum size of
     * 16kB. As such, wolfSSL needs to read an entire SSL record internally
     * before it is able to process and decrypt the record. Because of this,
     * a call to <code>read()</code> will only be able to return the
     * maximum buffer size which has been decrypted at the time of calling.
     * There may be additional not-yet-decrypted data waiting in the internal
     * wolfSSL receive buffer which will be retrieved and decrypted with the
     * next call to <code>read()</code>.
     *
     * @param data  ByteBuffer where the data read from the SSL connection
     *              will be placed. position() will be updated after this
     *              method writes data to the ByteBuffer.
     * @param sz    number of bytes to read into <b><code>data</code></b>,
     *              may be adjusted to the maximum space in data if that is
     *              smaller than this size.
     * @param timeout read timeout, milliseconds.
     * @return      the number of bytes read upon success. <code>SSL_FAILURE
     *              </code> will be returned upon failure which may be caused
     *              by either a clean (close notify alert) shutdown or just
     *              that the peer closed the connection. <code>
     *              SSL_FATAL_ERROR</code> upon failure when either an error
     *              occurred or, when using non-blocking sockets, the
     *              <b>SSL_ERROR_WANT_READ</b> or <b>SSL_ERROR_WANT_WRITE</b>
     *              error was received and the application needs to call
     *              <code>read()</code> again. Use <code>getError</code> to
     *              get a specific error code.
     *              <code>BAD_FUNC_ARC</code> when bad arguments are used.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws SocketTimeoutException if socket timeout occurs
     * @throws SocketException Native socket select/poll() failed
     */
    public int read(ByteBuffer data, int sz, int timeout)
        throws IllegalStateException, SocketTimeoutException, SocketException {

        final int ret;
        final int err;
        final int readSz = sz;
        final int readTimeout = timeout;
        final int bbPosition;
        final int bbLimit;
        boolean hasArray;
        long localPtr;

        confirmObjectIsActive();

        /* Fix for Infer scan, since not synchronizing on sslLock for
         * access to this.sslPtr, see note below */
        synchronized (sslLock) {
            localPtr = this.sslPtr;
        }

        WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
            WolfSSLDebug.INFO, localPtr,
            () -> "entered read(ByteBuffer, sz: " + readSz +
            ", timeout: " + readTimeout + ")");

        /* not synchronizing on sslLock here since JNI read() locks
         * session mutex around native wolfSSL_read() call. If sslLock
         * is locked here, since we call select() inside native JNI we
         * could timeout waiting for corresponding write() operation to
         * occur if needed */
        try {
            bbPosition = data.position();
            bbLimit = data.limit();
            hasArray = data.hasArray();

            ret = read(localPtr, data, bbPosition, bbLimit, hasArray,
                readSz, readTimeout);
            err = getError(ret);
        } catch (WolfSSLException e) {
            /* JNI code may throw WolfSSLException on JNI specific errors */
            throw new SocketException(e.getMessage());
        }

        WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
            WolfSSLDebug.INFO, localPtr,
            () -> "read() ret: " + ret + ", err: " + err);

        throwExceptionFromIOReturnValue(ret, "wolfSSL_read()");

        return ret;
    }

    /**
     * Return number of bytes available on the internal output buffer that
     * have already been decrypted and available immediately via a call to
     * read().
     *
     * @return number of bytes available on success, WolfSSL.SSL_FAILURE
     *         on error.
     *
     * @throws IllegalStateException WolfSSLSession has been freed
     */
    public int pending() throws IllegalStateException {

        int ret = 0;

        confirmObjectIsActive();

        synchronized (sslLock) {
            ret = pending(this.sslPtr);
        }

        return ret;
    }

    /**
     * Waits for an SSL client to initiate the SSL/TLS handshake.
     * This method is called on the server side. When it is called, the
     * underlying communication channel has already been set up.
     * <p>
     * <code>accept()</code> works with both blocking and non-blocking I/O.
     * When the underlying I/O is non-blocking, <code>accept()</code> will
     * return when the underlying I/O could not satisfy the needs of
     * <code>accept()</code> to continue the handshake. In this case, a call to
     * <code>getError()</code> will yield either <b>SSL_ERROR_WANT_READ</b> or
     * <b>SSL_ERROR_WANT_WRITE</b>. The calling process must then repeat the
     * call to <code>accept()</code> when data is available to be read and
     * wolfSSL will pick up where it left off. When using a non-blocking
     * socket, nothing needs to be done, but <code>select()</code> can be used
     * to check for the required condition.
     * <p>
     * If the underlying I/O is blocking, <code>accept()</code> will only
     * return once the handshake has been finished or an error occurred.
     *
     * @return <code>SSL_SUCCESS</code> on success. <code>SSL_FATAL_ERROR
     *         </code> if an error occurred. To get a more detailed
     *         error code, call <code>getError()</code>.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws SocketTimeoutException if underlying socket timed out
     * @throws SocketException Native socket select/accept() failed
     * @see    #getError(int)
     * @see    #connect()
     */
    public int accept()
        throws IllegalStateException, SocketTimeoutException, SocketException {

        return accept(0);
    }

    /**
     * Waits for an SSL client to initiate the SSL/TLS handshake, using socket
     * timeout value in milliseconds.
     * This method is called on the server side. When it is called, the
     * underlying communication channel has already been set up.
     * <p>
     * <code>accept()</code> works with both blocking and non-blocking I/O.
     * When the underlying I/O is non-blocking, <code>accept()</code> will
     * return when the underlying I/O could not satisfy the needs of
     * <code>accept()</code> to continue the handshake. In this case, a call to
     * <code>getError()</code> will yield either <b>SSL_ERROR_WANT_READ</b> or
     * <b>SSL_ERROR_WANT_WRITE</b>. The calling process must then repeat the
     * call to <code>accept()</code> when data is available to be read and
     * wolfSSL will pick up where it left off. When using a non-blocking
     * socket, nothing needs to be done, but <code>select()</code> can be used
     * to check for the required condition.
     * <p>
     * If the underlying I/O is blocking, <code>accept()</code> will only
     * return once the handshake has been finished or an error occurred.
     *
     * @param timeout read timeout, milliseconds.
     *
     * @return <code>SSL_SUCCESS</code> on success. <code>SSL_FATAL_ERROR
     *         </code> if an error occurred. To get a more detailed
     *         error code, call <code>getError()</code>.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws SocketTimeoutException if underlying socket timed out
     * @throws SocketException Native socket select() failed
     * @see    #getError(int)
     * @see    #connect()
     */
    public int accept(int timeout)
        throws IllegalStateException, SocketTimeoutException, SocketException {

        int ret;

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered accept(timeout: " + timeout + ")");

            ret = accept(this.sslPtr, timeout);

            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "accept() ret: " + ret + ", err: " + getError(ret));
        }

        throwExceptionFromIOReturnValue(ret, "wolfSSL_accept()");

        return ret;
    }

    /**
     * Frees an allocated SSL session.
     *
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    WolfSSLContext#newContext(long)
     * @see    WolfSSLContext#free()
     */
    public void freeSSL()
        throws IllegalStateException, WolfSSLJNIException {

        synchronized (sslLock) {
            synchronized (stateLock) {
                if (this.active == false) {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                        WolfSSLDebug.INFO,
                        () -> "entered freeSSL(), already freed");
                    /* already freed, just return */
                    return;
                }

                WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                    WolfSSLDebug.INFO, this.sslPtr,
                    () -> "entered freeSSL()");

                /* free native resources */
                freeSSL(this.sslPtr);

                /* free Java resources */
                this.active = false;
                this.sslPtr = 0;
                this.clientSNIRequested = null;
                this.ctx = null;
            }
        }
    }

    /**
     * Shuts down the active SSL/TLS connection using the SSL session.
     * This function will try to send a "close notify" alert to the peer,
     * with read timeout disabled (set to infinite).
     * <p>
     * The calling application can choose to wait for the peer to send its
     * "close notify" alert in response or just go ahead and shut down the
     * underlying connection after directly calling <code>shutdownSSL</code>
     * (to save resources). Either option is allowed by the TLS specification.
     * If the underlying connection will be used again in the future, the
     * complete two-directional shutdown procedure must be performed to keep
     * synchronization intact between the peers.
     * <p>
     * <code>shutdownSSL()</code> works with both blocking and non-blocking
     * I/O. When the underlying I/O is non-blocking, <code>shutdownSSL()
     * </code> will return an error if the underlying I/O could not satisfy the
     * needs of <code>shutdownSSL()</code> to continue. In this case, a call
     * to <code>getError()</code> will yield either <b>SSL_ERROR_WANT_READ</b>
     * or <b>SSL_ERROR_WANT_WRITE</b>. The calling process must then repeat
     * the call to <code>shutdownSSL()</code> when the underlying I/O is ready.
     *
     * @return <code>SSL_SUCCESS</code> on success,
     *         <code>SSL_FATAL_ERROR</code> upon failure. Call <code>
     *         getError()</code> for a more specific error code.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws SocketTimeoutException if socket timeout occurs, should not
     *         since infinite timeout is used for this call.
     * @throws SocketException Native socket select/poll() failed
     * @see    #shutdownSSL(int)
     * @see    #freeSSL(long)
     * @see    WolfSSLContext#free()
     */
    public int shutdownSSL()
        throws IllegalStateException, SocketTimeoutException, SocketException {

        return shutdownSSL(0);
    }

    /**
     * Shuts down the active SSL/TLS connection using the SSL session
     * and provided read timeout value in milliseconds.
     * This function will try to send a "close notify" alert to the peer.
     * <p>
     * The calling application can choose to wait for the peer to send its
     * "close notify" alert in response or just go ahead and shut down the
     * underlying connection after directly calling <code>shutdownSSL</code>
     * (to save resources). Either option is allowed by the TLS specification.
     * If the underlying connection will be used again in the future, the
     * complete two-directional shutdown procedure must be performed to keep
     * synchronization intact between the peers.
     * <p>
     * <code>shutdownSSL()</code> works with both blocking and non-blocking
     * I/O. When the underlying I/O is non-blocking, <code>shutdownSSL()
     * </code> will return an error if the underlying I/O could not satisfy the
     * needs of <code>shutdownSSL()</code> to continue. In this case, a call
     * to <code>getError()</code> will yield either <b>SSL_ERROR_WANT_READ</b>
     * or <b>SSL_ERROR_WANT_WRITE</b>. The calling process must then repeat
     * the call to <code>shutdownSSL()</code> when the underlying I/O is ready.
     *
     * @param timeout read timeout, milliseconds.
     *
     * @return <code>SSL_SUCCESS</code> on success,
     *         <code>SSL_FATAL_ERROR</code> upon failure. Call <code>
     *         getError()</code> for a more specific error code.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws SocketTimeoutException if socket timeout occurs.
     * @throws SocketException Native socket select/poll() failed
     * @see    #freeSSL(long)
     * @see    WolfSSLContext#free()
     */
    public int shutdownSSL(int timeout)
        throws IllegalStateException, SocketTimeoutException, SocketException {

        int ret;

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered shutdownSSL(timeout: " + timeout + ")");

            ret = shutdownSSL(this.sslPtr, timeout);

            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "shutdownSSL() ret: " + ret + ", err: " + getError(ret));
        }

        throwExceptionFromIOReturnValue(ret, "wolfSSL_shutdown()");

        return ret;
    }

    /**
     * Returns a unique error code describing why the previous API function
     * call resulted in an error return code.
     * The return value of the previous function is passed to <code>getError()
     * </code>through <code>ret</code>.
     * <p>
     * After <code>getError()</code> is called and returns the unique error
     * code, <code>getErrorString()</code> may be called to get a human-
     * readable error string.
     *
     * @param ret  return value of the previous function which resulted
     *             in an error return code.
     * @return     the unique error code describing why the previous API
     *             function failed. SSL_ERROR_NONE will be returned if
     *             <code>ret</code> is less than 0.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @see    WolfSSL#getErrorString(long)
     */
    public int getError(int ret) throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            return getError(this.sslPtr, ret);
        }
    }

    /**
     * Sets the session (native WOLFSSL_SESSION) to be used with this object
     * for session resumption.
     *
     * The native WOLFSSL_SESSION pointed to contains all the necessary
     * information required to perform a session resumption and reestablishment
     * of the connection without a new handshake.
     * <p>
     * To do session resumption, before calling <code>shutdownSSL()</code>
     * with your WolfSSLSession object, save the internal session state by
     * calling <code>getSession()</code>, which returns a pointer to the
     * native WOLFSSL_SESSION session structure. Later, when the application
     * is ready to resume a session, it should create a new WolfSSLSession
     * object and assign the previously-saved session pointer by passing it
     * to the <code>setSession(long session)</code> method. This should be
     * done before the handshake is started for the second/resumed time. After
     * calling <code>setSession(long session)</code>, the application may call
     * <code>connect()</code> and wolfSSL will try to resume the session. If
     * the session cannot be resumed, a new fresh handshake will be
     * established.
     *
     * @param session  pointer to the native WOLFSSL_SESSION structure used
     *                 to set the session for the SSL session object.
     * @return         <code>SSL_SUCCESS</code> upon successfully setting
     *                 the session. <code>SSL_FAILURE</code> will be
     *                 returned on failure. This could be caused by the
     *                 session cache being disabled, or if the session has
     *                 timed out.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @see    #getSession()
     */
    public int setSession(long session) throws IllegalStateException {

        int ret;

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered setSession(ptr: " + session + ")");

            if ((session != 0) && (wolfsslSessionIsSetup(session) == 1)) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                    WolfSSLDebug.INFO, this.sslPtr,
                    () -> "session pointer (" + session + ") is setup");
            }
            else {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                    WolfSSLDebug.INFO, this.sslPtr,
                    () -> "session pointer is null or not set up");
            }

            ret = setSession(this.sslPtr, session);

            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "setSession(session: " + session + ") ret: " +
                ret + ", err: " + getError(ret));

            return ret;
        }
    }

    /**
     * Returns a pointer to the current session (native WOLFSSL_SESSION)
     * associated with this object, or null if not available.
     *
     * The native WOLFSSL_SESSION pointed to contains all the necessary
     * information required to perform a session resumption and reestablishment
     * of the connection without a new handshake.
     * <p>
     * To do session resumption, before calling <code>shutdownSSL()</code>
     * with your WolfSSLSession object, save the internal session state by
     * calling <code>getSession()</code>, which returns a pointer to the
     * native WOLFSSL_SESSION session structure. Later, when the application
     * is ready to resume a session, it should create a new WolfSSLSession
     * object and assign the previously-saved session pointer by passing it
     * to the <code>setSession(long session)</code> method. This should be
     * done before the handshake is started for the second/resumed time. After
     * calling <code>setSession(long session)</code>, the application may call
     * <code>connect()</code> and wolfSSL will try to resume the session. If
     * the session cannot be resumed, a new fresh handshake will be
     * established.
     * <p>
     * <b>IMPORTANT:</b>
     * <p>
     * The pointer (WOLFSSL_SESSION) returned by this method needs to be freed
     * when the application is finished with it by calling
     * <code>freeSession(long session)</code>. This will release the underlying
     * native memory associated with this WOLFSSL_SESSION. Failing to free
     * the session will result in a memory leak.
     *
     * @throws IllegalStateException this WolfSSLSession has been freed
     * @return      a pointer to the current SSL session object on success.
     *              <code>null</code> if <b>ssl</b> is <code>null</code>,
     *              the SSL session cache is disabled, wolfSSL doesn't have
     *              the session ID available, or mutex functions fail.
     * @see         #setSession(long)
     */
    public long getSession() throws IllegalStateException {

        final long sessPtr;

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr, () -> "entered getSession()");

            /* Calling get1Session() here as an indication that the native
             * JNI level should always return a session pointer that needs
             * to be freed by the application. This behavior can change in
             * native wolfSSL depending on build options
             * (ex: NO_SESSION_CACHE_REF), so JNI layer here will make that
             * behavior consistent to the JNI/JSSE callers. */
            sessPtr = get1Session(this.sslPtr);

            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "get1Session(), ret ptr: " + sessPtr);

            if ((sessPtr != 0) && (wolfsslSessionIsSetup(sessPtr) == 1)) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                    WolfSSLDebug.INFO, this.sslPtr,
                    () -> "session pointer (" + sessPtr + ") is setup");
            }
            else {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                    WolfSSLDebug.INFO, this.sslPtr,
                    () -> "session pointer is null or not set up");
            }

            return sessPtr;
        }
    }

    /**
     * Check if native WOLFSSL_SESSION has been set up or not.
     *
     * This method is static and does not check active state since this
     * takes a native pointer and has no interaction with the rest of this
     * object.
     *
     * @param session pointer to native WOLFSSL_SESSION structure. May be
     *        obtained from getSession().
     *
     * @return 1 if session has been set up, otherwise 0 if not set up. May
     *         return WolfSSL.NOT_COMPILED_IN if native wolfSSL does not have
     *         wolfSSL_SessionIsSetup() compiled in. This API was added
     *         after the wolfSSL 5.7.0 release.
     */
    public static int sessionIsSetup(long session) {

        int ret;

        WolfSSLDebug.log(WolfSSLSession.class, WolfSSLDebug.Component.JNI,
            WolfSSLDebug.INFO, () -> "entered sessionIsSetup(" + session + ")");

        if (session == 0) {
            WolfSSLDebug.log(WolfSSLSession.class, WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO,
                () -> "sessionIsSetup(), ptr null, returning 0");
            return 0;
        }

        ret = wolfsslSessionIsSetup(session);

        WolfSSLDebug.log(WolfSSLSession.class, WolfSSLDebug.Component.JNI,
            WolfSSLDebug.INFO,
            () -> "sessionIsSetup(" + session + ") ret: " + ret);

        return ret;
    }

    /**
     * Check if native WOLFSSL_SESSION is resumable, calling native
     * wolfSSL_SESSION_is_resumable().
     *
     * This method is static and does not check active state since this
     * takes a native pointer and has no interaction with the rest of this
     * object.
     *
     * @param session pointer to native WOLFSSL_SESSION structure. May be
     *        obtained from getSession().
     *
     * @return 1 if session is resumable, otherwise 0. Returns
     * WolfSSL.NOT_COMPILED_IN if native wolfSSL does not have
     * wolfSSL_SESSION_is_resumable() compiled in.
     */
    public static int sessionIsResumable(long session) {

        int ret;

        WolfSSLDebug.log(WolfSSLSession.class, WolfSSLDebug.Component.JNI,
            WolfSSLDebug.INFO, () -> "entered sessionIsResumable()");

        if (session == 0) {
            return 0;
        }

        ret = wolfsslSessionIsResumable(session);

        WolfSSLDebug.log(WolfSSLSession.class, WolfSSLDebug.Component.JNI,
            WolfSSLDebug.INFO, () -> "session resumable: " + ret);

        return ret;
    }

    /**
     * Deep copy the contents of the WOLFSSL_SESSION, calling native
     * wolfSSL_SESSION_dup().
     *
     * This session will create a new WOLFSSL_SESSION and deep copy it
     * from the WOLFSSL_SESSION pointer provided. Note that if a non-zero
     * value is returned the application is responsible for freeing this
     * WOLFSSL_SESSION memory when finished by calling freeSession().
     *
     * @param session pointer to native WOLFSSL_SESSION structure. May have
     *        been obtained from getSession().
     *
     * @return long representing a native pointer to a new WOLFSSL_SESSION
     *         structure, or zero on error (equivalent to a NULL pointer).
     */
    public static long duplicateSession(long session) {

        final long sessPtr;

        WolfSSLDebug.log(WolfSSLSession.class, WolfSSLDebug.Component.JNI,
            WolfSSLDebug.INFO,
            () -> "entered duplicateSession(ptr: " + session + ")");

        if (session == 0) {
            WolfSSLDebug.log(WolfSSLSession.class, WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO,
                () -> "session pointer is null, not duplicating");
            return 0;
        }

        if (wolfsslSessionIsSetup(session) == 1) {
            WolfSSLDebug.log(WolfSSLSession.class, WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO,
                () -> "session ptr prior to dup (" + session + ") is setup");
        }
        else {
            WolfSSLDebug.log(WolfSSLSession.class, WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO,
                () -> "session ptr prior to dup is NOT set up");
        }

        sessPtr = wolfsslSessionDup(session);

        WolfSSLDebug.log(WolfSSLSession.class, WolfSSLDebug.Component.JNI,
            WolfSSLDebug.INFO, () -> "duplicated session ptr: " + sessPtr);

        if ((sessPtr != 0) && (wolfsslSessionIsSetup(sessPtr) == 1)) {
            WolfSSLDebug.log(WolfSSLSession.class, WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO,
                () -> "session pointer after dup (" + sessPtr + ") is setup");
        }
        else {
            WolfSSLDebug.log(WolfSSLSession.class, WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO,
                () -> "session pointer after dup is NOT set up");
        }

        return sessPtr;
    }

    /**
     * Get cipher suite name from WOLFSSL_SESSION, calling native
     * wolfSSL_SESSION_CIPHER_get_name().
     *
     * This method is static and does not check active state since this
     * takes a native pointer and has no interaction with the rest of this
     * object.
     *
     * @param session pointer to native WOLFSSL_SESSION structure. May have
     *        been obtained from getSession().
     * @return String representation of the cipher suite used in native
     *         WOLFSSL_SESSION structure, or NULL if not able to find the
     *         session.
     */
    public static String sessionGetCipherName(long session) {

        WolfSSLDebug.log(WolfSSLSession.class, WolfSSLDebug.Component.JNI,
            WolfSSLDebug.INFO,
            () -> "entered sessionGetCipherName(ptr: " + session + ")");

        if (session == 0) {
            return null;
        }

        return wolfsslSessionCipherGetName(session);
    }

    /**
     * Free the native WOLFSSL_SESSION structure pointed to be session.
     *
     * @param session native WOLFSSL_SESSION pointer to free
     */
    public static synchronized void freeSession(long session) {
        /* No need to call confirmObjectIsActive() because the
         * WOLFSSL_SESSION pointer being passed in here is not associated
         * with this WOLFSSL object or WolfSSLSession. */

        WolfSSLDebug.log(WolfSSLSession.class, WolfSSLDebug.Component.JNI,
            WolfSSLDebug.INFO,
            () -> "entered freeSession(ptr: " + session + ")");

        if (session != 0) {
            freeNativeSession(session);
        }

        WolfSSLDebug.log(WolfSSLSession.class, WolfSSLDebug.Component.JNI,
            WolfSSLDebug.INFO, () -> "session freed (ptr: " + session + ")");

    }

    /**
     * Returns the session ID.
     *
     * @throws IllegalStateException WolfSSLContext has been freed
     * @return      the session ID, or a empty array if unable to get valid
     *              session ID
     * @see         #setSession(long)
     */
    public byte[] getSessionID() throws IllegalStateException {

        byte[] sessId = null;

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr, () -> "entered getSessionID()");

            long sess = getSession(this.sslPtr);
            if (sess != 0) {
                /* returns new byte[] independent of sess ptr */
                 sessId = getSessionID(sess);
            } else {
                sessId = new byte[0];
            }

            WolfSSLDebug.logHex(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr, () -> "session ID", sessId,
                sessId.length);

            return sessId;
        }
    }

    /**
     * Check if there is a session ticket associated with this
     * WolfSSLSession (WOLFSSL_SESSION).
     *
     * @return true if internal session has session ticket, otherwise false
     * @throws IllegalStateException WolfSSLContext has been freed
     */
    public boolean hasSessionTicket() throws IllegalStateException {

        final boolean hasTicket;

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered hasSessionTicket()");

            long sess = getSession(this.sslPtr);
            if ((sess != 0) && (hasTicket(sess) == WolfSSL.SSL_SUCCESS)) {
                hasTicket = true;
            } else {
                hasTicket = false;
            }

            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "session has ticket: " + hasTicket);

            return hasTicket;
        }
    }

    /**
     * Gets the cache size is set at compile time.
     * This function returns the current cache size which has been set at compile
     * time.
     *
     * @return size of compile time cache.
     * @throws IllegalStateException WolfSSLSession has been freed
     */
    public long getCacheSize() throws IllegalStateException {

        long ret;

        confirmObjectIsActive();

        WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
            WolfSSLDebug.INFO, () -> "entered getCacheSize()");

        ret = this.getAssociatedContextPtr().getCacheSize();

        WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
            WolfSSLDebug.INFO, () -> "cache size: " + ret);

        return ret;
    }

    /**
     * Associate client session with serverID, find existing or store
     * for saving. If newSess flag is on, don't reuse existing session.
     *
     * @param id server ID to associate client session with
     * @param newSess if 1, don't reuse existing session, otherwise 0
     *
     * @return WolfSSL.SSL_SUCCESS on success, WolfSSL.SSL_FAILURE on
     *         error. Or WolfSSL.NOT_COMPILED_IN if native API is not
     *         compiled into library.
     * @throws IllegalStateException WolfSSLSession has been freed
     */
    public int setServerID(byte[] id, int newSess)
        throws IllegalStateException {

        int ret;

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered setServerID(byte[], newSess: " + newSess + ")");

            ret = setServerID(this.sslPtr, id, id.length, newSess);

            if (ret == WolfSSL.SSL_SUCCESS) {
                if (id != null) {
                    WolfSSLDebug.logHex(getClass(), WolfSSLDebug.Component.JNI,
                        WolfSSLDebug.INFO, this.sslPtr,
                        () -> "set server ID", id, id.length);
                }
                else {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                        WolfSSLDebug.INFO, this.sslPtr,
                        () -> "server ID byte[] null, not set");
                }
            }
            else {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                    WolfSSLDebug.INFO, this.sslPtr,
                    () -> "failed to set server ID, ret: " + ret);
            }

            return ret;
        }
    }

    /**
     * Sets the timeout in seconds in the given WOLFSSL_SESSION.
     *
     * @param t time in seconds to set
     * @throws IllegalStateException WolfSSLSession has been freed
     * @return WolfSSL.SSL_SUCCESS on success, WolfSSL.JNI_SESSION_UNAVAILABLE
     *         if underlying session is unavailable, or negative values
     *         on failure.
     * @see         #setSession(long)
     * @see         #getSession(long)
     */
    public int setSessTimeout(long t) throws IllegalStateException {

        final int ret;
        long session;

        confirmObjectIsActive();

        WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
            WolfSSLDebug.INFO,
            () -> "entered setSessTimeout(timeout (sec): " + t + ")");

        session = this.getSession();
        if (session == 0) {
            /* session may be null if session cache disabled, wolfSSL
             * doesn't have session ID available, mutex function fails, etc */
            ret = WolfSSL.JNI_SESSION_UNAVAILABLE;
        } else {
            ret = setSessTimeout(session, t);
        }

        WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
            WolfSSLDebug.INFO, () -> "set session timeout, ret: " + ret);

        return ret;
    }

    /**
     * Gets the timeout in seconds in the given WOLFSSL_SESSION.
     *
     * @throws IllegalStateException WolfSSLSession has been freed
     * @return current timeout in seconds
     * @see         #setSession(long)
     * @see         #getSession(long)
     */
    public long getSessTimeout() throws IllegalStateException {

        long ret;

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered getSessTimeout()");

            ret = getSessTimeout(this.getSession(this.sslPtr));

            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "session timeout (sec): " + ret);

            return ret;
        }
    }

    /**
     * Sets the timeout in seconds in the given SSL object.
     *
     * @param t time in seconds to set
     * @throws IllegalStateException WolfSSLSession has been freed
     * @return WOLFSSL_SUCCESS on success, negative values on failure.
     * @see         #setSession(long)
     * @see         #getSession(long)
     */
    public int setTimeout(long t) throws IllegalStateException {

        int ret;

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered setTimeout(timeout: " + t + ")");

            ret = setTimeout(this.sslPtr, t);

            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "set timeout, ret: " + ret);

            return ret;
        }
    }

    /**
     * Gets the timeout in seconds in the given SSL object.
     *
     * @throws IllegalStateException WolfSSLContext has been freed
     * @return current timeout in seconds
     * @see         #setSession(long)
     * @see         #getSession(long)
     */
    public long getTimeout() throws IllegalStateException {

        long ret;

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr, () -> "entered getTimeout()");

            ret = getTimeout(this.sslPtr);

            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr, () -> "timeout: " + ret);

            return ret;
        }
    }

    /**
     * Sets the cipher suite list for a given SSL session.
     * The ciphers in the list should be sorted in order of preference from
     * highest to lowest. Each call to <code>setCipherList()</code> resets
     * the cipher suite list for the specific SSL session to the provided list
     * each time time the method is called.
     * <p>
     * The cipher suite list, <b>list</b>, is a null-terminated text String,
     * and colon-delimited list. For example, one possible list may be:
     * <p>
     * <code>"DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:AES256-SHA256"</code>
     * <p>
     * Valid cipher values are the full name values from the cipher_names[]
     * array in the native wolfSSL src/internal.c:
     *
     * @param list  null-terminated text string and colon-delimited list
     *              of cipher suites to use with the specified SSL
     *              session.
     * @return      <code>SSL_SUCCESS</code> upon success. <code>
     *              SSL_FAILURE</code> upon failure.
     * @throws IllegalStateException WolfSSLSession has been freed
     * @see    WolfSSLContext#setCipherList(String)
     */
    public int setCipherList(String list) throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered setCipherList(" + list + ")");

            return setCipherList(this.sslPtr, list);
        }
    }

    /**
     * Sets the supported signature algorithms for the given SSL session.
     * By default, without calling this method, native wolfSSL will add the
     * signature-hash algorithms automatically to the ClientHello message
     * based on which algorithms and modes are compiled into the native library.
     *
     * Calling this function will override the defualt list with the specified
     * list.
     *
     * The signature algorithm list, <b>list</b>, is a null-terminated text
     * String, and colon delimited list. Each list item is a combination of
     * public key algorithm and MAC algorithm, concatenated with a plus
     * sign (+).
     *
     * Possible public key algorithms include the following, but are dependent
     * on which algorithms are compiled into the native library:
     *
     *    "RSA"     - available if NO_RSA is not defined
     *    "RSA-PSS" - available if !NO_RSA and WC_RSA_PSS
     *    "PSS"     - available if !NO_RSA and WC_RSA_PSS
     *    "ECDSA"   - available if HAVE_ECC
     *    "ED25519" - available if HAVE_ED25519
     *    "ED448"   - available if HAVE_ED448
     *    "DSA"     - available if !NO_DSA
     *
     * Possible MAC/hash algorithms include the following, but are also
     * dependent on which algorithms are compiled into the native library:
     *
     *    "SHA1"    - available if !NO_SHA and (!NO_OLD_TLS or WOLFSSL_ALLOW_TLS_SHA1)
     *    "SHA224"  - available if WOLFSSL_SHA224
     *    "SHA256"  - available if WOLFSSL_SHA256
     *    "SHA384"  - available if WOLFSSL_SHA384
     *    "SHA512"  - available if WOLFSSL_SHA512
     *
     * When put together as list items these would look similar to:
     *
     *    "RSA+SHA256:ECDSA+SHA256"
     *
     * @param list  null-terminated text string and colon-delimited list
     *              of signature algorithms to use with the specified SSL
     *              session.
     * @return      <code>SSL_SUCCESS</code> upon success. <code>
     *              SSL_FAILURE</code> upon failure.
     * @throws IllegalStateException WolfSSLSession has been freed
     */
    public int setSignatureAlgorithms(String list)
        throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered setSignatureAlgorithms(" + list + ")");

            return set1SigAlgsList(this.sslPtr, list);
        }
    }

    /**
     * Sets the TLS Supported Curves to be used in the ClientHello
     * extension if enabled in native wolfSSL.
     *
     * @param curveNames String array of ECC curve names to set into the
     *        Supported Curve extension. String values should match names from
     *        the following list:
     *            "sect163k1", "sect163r1", "sect163r2", "sect193r1",
     *            "sect193r2", "sect233k1", "sect233r1", "sect239k1",
     *            "sect283k1", "sect283r1", "sect409k1", "sect409r1",
     *            "sect571k1", "sect571r1", "secp160k1", "secp160r1",
     *            "secp160r2", "secp192k1", "secp192r1", "secp224k1",
     *            "secp224r1", "secp256k1", "secp256r1", "secp384r1",
     *            "secp521r1", "brainpoolP256r1", "brainpoolP384r1",
     *            "brainpoolP512r1", "x25519", "x448", "sm2P256v1",
     *            "ffdhe2048", "ffdhe3072", "ffdhe4096", "ffdhe6144",
     *            "ffdhe8192"
     *
     * @return <code>WolfSSL.SSL_SUCCESS</code> on success, otherwise
     *         negative on error.
     * @throws IllegalStateException WolfSSLSession has been freed
     */
    public int useSupportedCurves(String[] curveNames)
        throws IllegalStateException  {

        int ret = 0;
        int curveEnum = 0;

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered useSupportedCurves(" +
                Arrays.asList(curveNames) + ")");
        }

        for (String curve : curveNames) {
            curveEnum = WolfSSL.getNamedGroupFromString(curve);
            synchronized (sslLock) {
                ret = useSupportedCurve(this.sslPtr, curveEnum);
            }
        }

        return ret;
    }

    /**
     * Disable TLS Extended Master Secret usage.
     *
     * @return <code>WolfSSL.SSL_SUCCESS</code> on success, otherwise
     *         negative on error.
     * @throws IllegalStateException WolfSSLSession has been freed
     */
    public int disableExtendedMasterSecret()
        throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            return disableExtendedMasterSecret(this.sslPtr);
        }
    }

    /* ---------------- Nonblocking DTLS helper functions  -------------- */

    /**
     * Returns the current timeout value in seconds for the SSL session.
     * When using non-blocking sockets, something in the user code needs
     * to decide when to check for available recv data and how long it has
     * been waiting. The value returned by this method indicates how long the
     * application should wait.
     *
     * @return the current DTLS timeout value in seconds,
     *         <code>NOT_COMPILED_IN</code> if wolfSSL was not built
     *         with DTLS support.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    #dtls()
     * @see    #dtlsGetPeer()
     * @see    #dtlsGotTimeout()
     * @see    #dtlsSetPeer(InetSocketAddress)
     */
    public int dtlsGetCurrentTimeout()
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered dtlsGetCurrentTimeout()");

            return dtlsGetCurrentTimeout(this.sslPtr);
        }
    }

    /**
     * Performs the actions needed to retry the last retransmit, including
     * adjusting the timeout value.
     * When using non-blocking sockets with DTLS, this method should be
     * called on the SSL session when the controlling code thinks the
     * transmission has timed out.
     *
     * @return <code>SSL_SUCCESS</code> upon success. <code>
     *         SSL_FATAL_ERROR</code> if there have been too many
     *         retransmissions/timeouts without getting a response from
     *         the peer. <code>NOT_COMPILED_IN</code> if wolfSSL was
     *         not compiled with DTLS support.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @see    #dtlsGetCurrentTimeout()
     * @see    #dtlsGetPeer()
     * @see    #dtlsSetPeer(InetSocketAddress)
     * @see    #dtls()
     */
    public int dtlsGotTimeout() throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered dtlsGotTimeout()");

            return dtlsGotTimeout(this.sslPtr);
        }
    }

    /**
     * When using non-blocking sockets with DTLS, this function retransmits
     * the last handshake flight ignoring the expected timeout value and
     * retransmit count.
     *
     * It is useful for applications that are using DTLS and need to manage
     * even the timeout and retry count.
     *
     * @return <code>SSL_SUCCESS</code> upon success. <code>
     *         SSL_FATAL_ERROR</code> if there have been too many
     *         retransmissions/timeouts without getting a response from
     *         the peer. <code>NOT_COMPILED_IN</code> if wolfSSL was
     *         not compiled with DTLS support.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @see    #dtlsGetCurrentTimeout()
     * @see    #dtlsGetPeer()
     * @see    #dtlsSetPeer(InetSocketAddress)
     * @see    #dtlsGotTimeout()
     * @see    #dtls()
     */
    public int dtlsRetransmit() throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            return dtlsRetransmit(this.sslPtr);
        }
    }

    /**
     * Used to determine if the SSL session has been configured to use DTLS.
     *
     * @return <code>1</code> if the SSL has been configured to use DTLS,
     *         otherwise, <code>0</code>.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @see    #dtlsGetCurrentTimeout()
     * @see    #dtlsGetPeer()
     * @see    #dtlsGotTimeout()
     * @see    #dtlsSetPeer(InetSocketAddress)
     */
    public int dtls() throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr, () -> "entered dtls()");

            return dtls(this.sslPtr);
        }
    }

    /**
     * Sets the DTLS peer.
     *
     * @param peer  DTLS peer's InetSocketAddress
     * @return      <code>SSL_SUCCESS</code> upon success, <code>
     *              SSL_FAILURE</code> upon failure, <code>
     *              SSL_NOT_IMPLEMENTED</code> if wolfSSL was not compiled
     *              with DTLS support.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @see    #dtlsGetCurrentTimeout()
     * @see    #dtlsGetPeer()
     * @see    #dtlsGotTimeout()
     * @see    #dtls()
     */
    public int dtlsSetPeer(InetSocketAddress peer)
        throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered dtlsSetPeer(" + peer + ")");

            return dtlsSetPeer(this.sslPtr, peer);
        }
    }

    /**
     * Send a cookie with the HelloRetryRequest to avoid storing state.
     *
     * @param secret Secret to use when generating integrity check for cookie.
     * A value of null indicates to generate a new random secret.
     *
     * @return <code>WolfSSL.SSL_SUCCESS</code> on success,
     *         <code>WolfSSL.BAD_FUNC_ARG</code> when not using (D)TLS 1.3,
     *         <code>WolfSSL.SIDE_ERROR</code> when called on a client.
     *
     * @throws IllegalStateException WolfSSLContext has been freed
     */
    public int sendHrrCookie(byte[] secret)
        throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            return sendHrrCookie(this.sslPtr, secret);
        }
    }

    /**
     * Get the number of DTLS packets that have been dropped due
     * to verify MAC decrypt errors.
     *
     * Native wolfSSL must be compiled with WOLFSSL_DTLS_DROP_STATS
     * defined for this functionality to be available, otherwise this
     * method will return 0.
     *
     * @return number of dropped packets
     *
     * @throws IllegalStateException WolfSSLSession has been freed
     */
    public long getDtlsMacDropCount() throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            return getDtlsMacDropCount(this.sslPtr);
        }
    }

    /**
     * Get the number of DTLS packets that have been dropped due to
     * receiving a replayed / duplicated packet.
     *
     * Native wolfSSL must be compiled with WOLFSSL_DTLS_DROP_STATS
     * defined for this functionality to be available, otherwise this
     * method will return 0.
     *
     * @return number of dropped packets
     *
     * @throws IllegalStateException WolfSSLSession has been freed
     */
    public long getDtlsReplayDropCount() throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            return getDtlsReplayDropCount(this.sslPtr);
        }
    }

    /**
     * Gets the InetSocketAddress of the DTLS peer.
     *
     * @return      DTLS peer's InetSocketAddress upon success, <code>
     *              null</code> upon failure.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @see    #dtlsGetCurrentTimeout()
     * @see    #dtlsGotTimeout()
     * @see    #dtlsSetPeer(InetSocketAddress)
     * @see    #dtls()
     */
    public InetSocketAddress dtlsGetPeer() throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr, () -> "entered dtlsGetPeer()");

            return dtlsGetPeer(this.sslPtr);
        }
    }

    /**
     * Set the DTLS MTU to use.
     *
     * Native wolfSSL must be compiled with "--enable-dtls-mtu" in addition
     * to "--enable-dtls".
     *
     * @param mtu DTLS MTU value, must be lower than MAX_RECORD_SIZE (16k)
     *
     * @return <code>SSL_SUCCESS</code> on success,
     *         <code>SSL_FAILURE</code> on error, or
     *         <code>NOT_COMPILED_IN</code> if native support has not
     *         been compiled into native wolfSSL.
     *
     * @throws IllegalStateException WolfSSLContext has been freed
     */
    public int dtlsSetMTU(int mtu) throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            return setMTU(this.sslPtr, mtu);
        }
    }

    /**
     * Return the current handshake state of the native WOLFSSL object as
     * a String.
     *
     * @return String representing current state of handshake or empty
     *         String if not able to retrieve one.
     *
     * @throws IllegalStateException WolfSSLContext has been freed
     */
    public String getStateStringLong() throws IllegalStateException {

        String state = null;

        confirmObjectIsActive();

        synchronized (sslLock) {
            state = stateStringLong(this.sslPtr);
            if (state == null) {
                /* Return empty string instead of null, may prevent some
                 * NullPoinerExceptions from callers */
                state = "";
            }
        }

        return state;
    }

    /**
     * Return max record layer size plaintext input size
     *
     * @return max record layer size plaintext input size in bytes, or
     *         negative value on error.
     *
     * @throws IllegalStateException WolfSSLContext has been freed
     */
    public int getMaxOutputSize() throws IllegalStateException {

        int ret;

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered getOutputSize()");

            ret = getMaxOutputSize(this.sslPtr);

            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "max output size: " + ret);
        }

        return ret;
    }

    /**
     * Determine if a reused session was negotiated during the SSL
     * handshake.
     * If session resumption is being used, and the client has proposed to
     * reuse a given session, this method will notify the application if the
     * requested session has been negotiated after the handshake has completed.
     *
     * @return <b>1</b> if the session was reused, <b>0</b> if a new
     *         session needed to be negotiated.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    #setSession(long)
     * @see    #getSession()
     */
    public int sessionReused()
        throws IllegalStateException, WolfSSLJNIException {

        int ret;

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered sessionReused()");

            ret = sessionReused(this.sslPtr);

            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr, () -> "session reused: " + ret);
        }

        return ret;
    }

    /**
     * Returns the number of certificates in the peer's certificate chain.
     *
     * @return number of certificates in the peer's certificate chain.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    WolfSSLSession#getPeerCertificate(int)
     */
    public int getPeerCertificateCount()
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr, "entered getPeerCertificateCount()");

            return getPeerCertificateCount(this.sslPtr);
        }
    }

    /**
     * Gets the native (long) WOLFSSL_X509 pointer to the peer's certificate.
     * This can be used to retrieve further information about the peer's
     * certificate (issuer, subject, alt name, etc.)
     *
     * wolfSSL versions 5.3.0 or later return a newly-allocated
     * WOLFSSL_X509 structure poiner from the native
     * wolfSSL_get_peer_certificate() API called by this wrapper. If using
     * wolfSSL greater than or equal to 5.3.0, the pointer (long) returned
     * from this method must be freed by the caller. Versions of wolfSSL
     * less than 5.3.0 should not free the pointer returned since it points
     * to internal memory that is freed by native wolfSSL.
     *
     * Pointer should be freed by calling:
     *     WolfSSLCertificate.freeX509(long x509);
     *
     * @param index index of the certificate in the peer's certificate chain
     * @return (long) WOLFSSL_X509 pointer to the peer's certificate.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    WolfSSLSession#getPeerX509Issuer(long)
     * @see    WolfSSLSession#getPeerX509Subject(long)
     * @see    WolfSSLSession#getVersion()
     * @see    WolfSSLSession#getCurrentCipher()
     */
    public long getPeerCertificate(int index)
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered getPeerCertificate()");

            return getPeerCertificate(this.sslPtr, index);
        }
    }

    /**
     * Gets the peer X509 certificate's issuer information.
     *
     * @param x509  pointer (long) to native WOLFSSL_X509 structure, obtained
     *              from getPeerCertificate().
     * @return      String representation of the peer's issuer information
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    WolfSSLSession#getPeerCertificate()
     * @see    WolfSSLSession#getPeerX509Subject(long)
     * @see    WolfSSLSession#getVersion()
     * @see    WolfSSLSession#getCurrentCipher()
     */
    public String getPeerX509Issuer(long x509)
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered getPeerX509Issuer()");

            return getPeerX509Issuer(this.sslPtr, x509);
        }
    }

    /**
     * Gets the peer X509 certificate's subject information.
     *
     * @param x509  pointer (long) to native WOLFSSL_X509 structure, obtained
     *              from getPeerCertificate().
     * @return      String representation of the peer's subject information
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    WolfSSLSession#getPeerCertificate()
     * @see    WolfSSLSession#getPeerX509Issuer(long)
     * @see    WolfSSLSession#getVersion()
     * @see    WolfSSLSession#getCurrentCipher()
     */
    public String getPeerX509Subject(long x509)
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered getPeerX509Subject()");

            return getPeerX509Subject(this.sslPtr, x509);
        }
    }

    /**
     * Gets the peer X509 certificate's altname information.
     * This method may be repeatedly called to get the next altname, if any,
     * from the peer cert. If no more altnames are available, <b>null</b>
     * will be returned.
     *
     * @param x509  pointer (long) to native WOLFSSL_X509 structure, obtained
     *              from getPeerCertificate().
     * @return      String representation of the peer's subject information
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    WolfSSLSession#getPeerCertificate()
     * @see    WolfSSLSession#getPeerX509Issuer(long)
     * @see    WolfSSLSession#getPeerX509Subject(long)
     * @see    WolfSSLSession#getVersion()
     * @see    WolfSSLSession#getCurrentCipher()
     */
    public String getPeerX509AltName(long x509)
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered getPeerX509AltName()");

            return getPeerX509AltName(this.sslPtr, x509);
        }
    }

    /**
     * Returns the SSL/TLS version being used with this session object in
     * String format.
     * Examples include "SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2", "DTLS",
     * "DTLS 1.2", and "DTLS 1.3.
     *
     * @return      SSL/TLS protocol version being used in String format,
     *              or "unknown".
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     */
    public String getVersion()
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr, () -> "entered getVersion()");

            return getVersion(this.sslPtr);
        }
    }

    /**
     * Returns a pointer to the native WOLFSSL_CIPHER object being used
     * in with the SSL session.
     * This pointer can be used with the <code>getCipherName()</code> function
     * to get the name of the current cipher suite being used.
     *
     * @return      pointer (long) to the native WOLFSSL_CIPHER object
     *              currently used with the SSL session.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    WolfSSLSession#cipherGetName()
     */
    public long getCurrentCipher()
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered getCurrentCipher()");

            return getCurrentCipher(this.sslPtr);
        }
    }

    /**
     * Adds a domain check to the list of checks performed during the peer
     * verification.
     * wolfSSL by default check the peer certificate for a valid date range
     * and a verified signature. Calling this function before <code>connect()
     * </code> or <code>accept()</code> will add a domain name check to the
     * list of checks to perform.
     *
     * @param dn    domain name to check against the peer certificate
     *              when received.
     * @return      <code>SSL_SUCCESS</code> on success, <code>SSL_FAILURE
     *              </code> if a memory error was encountered.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     */
    public int checkDomainName(String dn)
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered checkDomainName(" + dn + ")");

            return checkDomainName(this.sslPtr, dn);
        }
    }

    /**
     * Sets up the group parameters to be used if the server negotiates
     * a cipher suite that uses DHE.
     *
     * @param p     Diffie-Hellman prime number parameter
     * @param pSz   size of <code>p</code>
     * @param g     Diffie-Hellman "generator" parameter
     * @param gSz   size of <code>g</code>
     * @return      <code>SSL_SUCCESS</code> on success. <code>MEMORY_E
     *              </code> if a memory error was encountered. <code>
     *              SIDE_ERROR</code> if this function is called on an
     *              SSL client instead of an SSL server.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    #accept()
     */
    public int setTmpDH(byte[] p, int pSz, byte[] g, int gSz)
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered setTmpDH(pSz: " + pSz + ", gSz: " + gSz + ")");

            return setTmpDH(this.sslPtr, p, pSz, g, gSz);
        }
    }

    /**
     * Sets up the group parameters from the specified file to be used if the
     * server negotiates a cipher suite that uses DHE.
     *
     * @param fname     path to Diffie-Hellman parameter file
     * @param format    format of DH parameter file, either
     *                  <code>SSL_FILETYPE_ASN1</code> or <code>
     *                  SSL_FILETYPE_PEM</code>.
     * @return          <code>SSL_SUCCESS</code> on success. <code>MEMORY_E
     *                  </code> if a memory error was encountered. <code>
     *                  SIDE_ERROR</code> if this function is called on an
     *                  SSL client instead of an SSL server, <code>
     *                  SSL_BAD_FILETYPE</code> if the specified format is
     *                  incorrect, <code>SSL_BAD_FILE</code> if there is a
     *                  problem with the input file.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    #setTmpDH(byte[], int, byte[], int)
     */
    public int setTmpDHFile(String fname, int format)
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered getTmpDHFile(" + fname + ", format:" +
                format + ")");

            return setTmpDHFile(this.sslPtr, fname, format);
        }
    }

    /**
     * Loads a certificate buffer into the SSL object.
     * This method behaves like the non-buffered version, only differing
     * in its ability to be called with a buffer as input instead of a file.
     *
     * @param in        input buffer containing the certificate to load
     * @param sz        size of the input buffer, <b>in</b>
     * @param format    format of the certificate buffer being loaded - either
     *                  <b>SSL_FILETYPE_PEM</b> or <b>SSL_FILETYPE_ASN1</b>
     * @return          <b><code>SSL_SUCCESS</code></b> upon success,
     *                  <b><code>SSL_BAD_FILETYPE</code></b> if the file is
     *                  in the wrong format, <b><code>SSL_BAD_FILE</code></b>
     *                  if the file doesn't exist, can't be read, or is
     *                  corrupted. <b><code>MEMORY_E</code></b> if an out of
     *                  memory condition occurs, <b><code>ASN_INPUT_E</code></b>
     *                  if Base16 decoding fails on the file, and <b><code>
     *                  BAD_FUNC_ARG</code></b> if invalid input parameters
     *                  are given.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    WolfSSLContext#loadVerifyBuffer(byte[], long, int)
     * @see    WolfSSLContext#useCertificateBuffer(byte[], long, int)
     * @see    WolfSSLContext#usePrivateKeyBuffer(byte[], long, int)
     * @see    WolfSSLContext#useCertificateChainBuffer(byte[], long)
     * @see    #usePrivateKeyBuffer(byte[], long, int)
     * @see    #useCertificateChainBuffer(byte[], long)
     */
    public int useCertificateBuffer(byte[] in, long sz, int format)
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered useCertificateBuffer(sz: " + sz + ", format: " +
                format + ")");

            return useCertificateBuffer(this.sslPtr, in, sz, format);
        }
    }

    /**
     * Loads a private key buffer into the SSL object.
     * This method behaves like the non-buffered version, only differing
     * in its ability to be called with a buffer as input rather than a file.
     *
     * @param in        the input buffer containing the private key to be
     *                  loaded
     * @param sz        the size of the input buffer, <b>in</b>
     * @param format    format of the certificate buffer being loaded - either
     *                  <b>SSL_FILETYPE_PEM</b> or <b>SSL_FILETYPE_ASN1</b>
     * @return          <b><code>SSL_SUCCESS</code></b> upon success,
     *                  <b><code>SSL_BAD_FILETYPE</code></b> if the file is
     *                  in the wrong format, <b><code>SSL_BAD_FILE</code></b>
     *                  if the file doesn't exist, can't be read, or is
     *                  corrupted. <b><code>MEMORY_E</code></b> if an out of
     *                  memory condition occurs, <b><code>ASN_INPUT_E</code></b>
     *                  if Base16 decoding fails on the file,
     *                  <b><code>NO_PASSWORD</code></b> if the key file is
     *                  encrypted but no password is provided, and <b><code>
     *                  BAD_FUNC_ARG</code></b> if invalid input parameters
     *                  are given.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    WolfSSLContext#loadVerifyBuffer(byte[], long, int)
     * @see    WolfSSLContext#useCertificateBuffer(byte[], long, int)
     * @see    WolfSSLContext#usePrivateKeyBuffer(byte[], long, int)
     * @see    WolfSSLContext#useCertificateChainBuffer(byte[], long)
     * @see    #useCertificateBuffer(byte[], long, int)
     * @see    #useCertificateChainBuffer(byte[], long)
     */
    public int usePrivateKeyBuffer(byte[] in, long sz, int format)
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered usePrivateKeyBuffer(sz: " + sz + ", format: " +
                format + ")");

            return usePrivateKeyBuffer(this.sslPtr, in, sz, format);
        }
    }

    /**
     * Loads a certificate chain buffer into the SSL object.
     * This method behaves like the non-buffered version, only differing
     * in its ability to be called with a buffer as input instead of a file.
     * The buffer must be in PEM format and start with the subject's
     * certificate, ending with the root certificate.
     *
     * @param in        the input buffer containing the PEM-formatted
     *                  certificate chain to be loaded.
     * @param sz        the size of the input buffer, <b>in</b>
     * @return          <b><code>SSL_SUCCESS</code></b> upon success,
     *                  <b><code>SSL_BAD_FILETYPE</code></b> if the file is
     *                  in the wrong format, <b><code>SSL_BAD_FILE</code></b>
     *                  if the file doesn't exist, can't be read, or is
     *                  corrupted. <b><code>MEMORY_E</code></b> if an out of
     *                  memory condition occurs, <b><code>ASN_INPUT_E</code></b>
     *                  if Base16 decoding fails on the file,
     *                  <b><code>BUFFER_E</code></b> if a chain buffer is
     *                  bigger than the receiving buffer, and <b><code>
     *                  BAD_FUNC_ARG</code></b> if invalid input parameters
     *                  are given.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    WolfSSLContext#loadVerifyBuffer(byte[], long, int)
     * @see    WolfSSLContext#useCertificateBuffer(byte[], long, int)
     * @see    WolfSSLContext#usePrivateKeyBuffer(byte[], long, int)
     * @see    WolfSSLContext#useCertificateChainBuffer(byte[], long)
     * @see    #useCertificateBuffer(byte[], long, int)
     * @see    #usePrivateKeyBuffer(byte[], long, int)
     */
    public int useCertificateChainBuffer(byte[] in, long sz)
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered useCertificateChainBuffer(sz: " + sz + ")");

            return useCertificateChainBuffer(this.sslPtr, in, sz);
        }
    }

    /**
     * Loads a certificate chain buffer into the SSL object in specific format.
     * This method behaves like the non-buffered version, only differing
     * in its ability to be called with a buffer as input instead of a file.
     * This function is similar to useCertificateChainBuffer(), but allows
     * the input format to be specified. The format must be either DER or PEM,
     * and start with the subject's certificate, ending with the root
     * certificate.
     *
     * @param in        the input buffer containing the PEM or DER formatted
     *                  certificate chain to be loaded.
     * @param sz        the size of the input buffer, <b>in</b>
     * @param format    format of the certificate buffer being loaded - either
     *                  <b>SSL_FILETYPE_PEM</b> or <b>SSL_FILETYPE_ASN1</b>
     * @return          <b><code>SSL_SUCCESS</code></b> upon success,
     *                  <b><code>SSL_FAILURE</code></b> upon general failure,
     *                  <b><code>SSL_BAD_FILETYPE</code></b> if the file is
     *                  in the wrong format, <b><code>SSL_BAD_FILE</code></b>
     *                  if the file doesn't exist, can't be read, or is
     *                  corrupted. <b><code>MEMORY_E</code></b> if an out of
     *                  memory condition occurs, <b><code>ASN_INPUT_E</code></b>
     *                  if Base16 decoding fails on the file,
     *                  <b><code>BUFFER_E</code></b> if a chain buffer is
     *                  bigger than the receiving buffer, and <b><code>
     *                  BAD_FUNC_ARG</code></b> if invalid input arguments
     *                  are provided.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    #useCertificateBuffer(byte[], long, int)
     * @see    #usePrivateKeyBuffer(byte[], long, int)
     * @see    WolfSSLSession#useCertificateBuffer(byte[], long, int)
     * @see    WolfSSLSession#usePrivateKeyBuffer(byte[], long, int)
     * @see    WolfSSLSession#useCertificateChainBuffer(byte[], long)
     */
    public int useCertificateChainBufferFormat(byte[] in, long sz, int format)
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered useCertificateChainBufferFormat(sz: " + sz +
                ", format: " + format + ")");

            return useCertificateChainBufferFormat(this.sslPtr, in, sz, format);
        }
    }


    /**
     * Turns on grouping of the handshake messages where possible using the
     * SSL session.
     *
     * @return      <code>SSL_SUCCESS</code> upon success. <code>
     *              BAD_FUNC_ARG</code> if the input session is null.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    WolfSSLContext#setGroupMessages()
     */
    public int setGroupMessages()
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered setGroupMessages()");

            return setGroupMessages(this.sslPtr);
        }
    }

    /**
     * Registers a context for the SSL session's receive callback method.
     * By default, wolfSSL sets the file descriptor passed to setFd() as
     * the context when wolfSSL is using the system's TCP library. If you've
     * registered your own receive callback you may want to set a specific
     * context for the session.
     * <p>
     * For example, if you're using memory buffers, the context may be a
     * pointer to an object describing where and how to access the memory
     * buffers.
     *
     * @param ctx   context object to be registered with the SSL session's
     *              receive callback method.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    #setIOWriteCtx(Object)
     * @see    WolfSSLContext#setIORecv(WolfSSLIORecvCallback)
     * @see    WolfSSLContext#setIOSend(WolfSSLIOSendCallback)
     */
    public void setIOReadCtx(Object ctx)
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr, () -> "entered setIOReadCtx()");

            ioReadCtx = ctx;
        }
    }

    /**
     * Return the SSL session's receive callback context, if set.
     *
     * @return Object that was set with setIOReadCtx().
     * @throws IllegalStateException WolfSSLContext has been freed
     */
    public Object getIOReadCtx()
        throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            return this.ioReadCtx;
        }
    }

    /**
     * Registers a context for the SSL session's send callback method.
     * By default, wolfSSL sets the file descriptor passed to setFd() as
     * the context when wolfSSL is using the system's TCP library. If
     * you've registered your own send callback, you may want to set a
     * specific context for the session.
     * <p>
     * For example, if you're using memory buffers the context may be a
     * pointer to an object describing where and how to access the memory
     * buffers.
     *
     * @param ctx   context object to be registered with the SSL session's
     *              send callback method.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    #setIOReadCtx(Object)
     * @see    WolfSSLContext#setIOSend(WolfSSLIOSendCallback)
     * @see    WolfSSLContext#setIORecv(WolfSSLIORecvCallback)
     */
    public void setIOWriteCtx(Object ctx)
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered setIOWriteCtx()");

            ioWriteCtx = ctx;
        }
    }

    /**
     * Return the SSL session's write callback context, if set.
     *
     * @return Object that was set with setIOWriteCtx().
     * @throws IllegalStateException WolfSSLContext has been freed
     */
    public Object getIOWriteCtx()
        throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            return this.ioWriteCtx;
        }
    }

    /**
     * Registers a context for the SSL session's DTLS cookie generation
     * callback method.
     * By default, wolfSSL sets the file descriptor passed to setFd() as
     * the context when wolfSSL is using the system's TCP library. If
     * the application has registered its own DTLS gen cookie callback, it may
     * need to set a specific context for the cookie generation method.
     *
     * @param ctx   context object to be registered with the SSL session's
     *              cookie generation method.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    WolfSSLContext#setGenCookie(WolfSSLGenCookieCallback)
     */
    public void setGenCookieCtx(Object ctx)
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered setGenCookieCtx()");

            genCookieCtx = ctx;
        }
    }

    /**
     * Turns on Certificate Revocation List (CRL) checking when
     * verifying certificates.
     * By default, CRL checking is off. <b>options</b> include
     * WOLFSSL_CRL_CHECKALL which performs CRL checking on each certificate
     * in the chain versus the leaf certificate only (which is default).
     *
     * @param options   options to use when enabling CRL
     * @return          <code>SSL_SUCCESS</code> upon success. <code>
     *                  NOT_COMPILED_IN</code> if wolfSSL was not compiled
     *                  with CRL enabled. <code>MEMORY_E</code> if an out
     *                  of memory condition occurs. <code>BAD_FUNC_ARG</code>
     *                  if a pointer is not provided, and <code>
     *                  SSL_FAILURE</code> if the CRL context cannot be
     *                  initialized properly.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    #disableCRL()
     * @see    #loadCRL(String, int, int)
     * @see    #setCRLCb(WolfSSLMissingCRLCallback)
     * @see    WolfSSLContext#enableCRL(int)
     * @see    WolfSSLContext#disableCRL()
     * @see    WolfSSLContext#setCRLCb(WolfSSLMissingCRLCallback)
     */
    public int enableCRL(int options)
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered enableCRL(" + options + ")");

            return enableCRL(this.sslPtr, options);
        }
    }

    /**
     * Turns off Certificate Revocation List (CRL) checking.
     * By default, CRL checking is off. This function can be used to
     * temporarily or permanently disable CRL checking for a given SSL
     * session object that previously had CRL checking enabled.
     *
     * @return      <code>SSL_SUCCESS</code> on success, <code>
     *              BAD_FUNC_ARG</code> if pointer is not provided.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    #enableCRL(int)
     * @see    #loadCRL(String, int, int)
     * @see    #setCRLCb(WolfSSLMissingCRLCallback)
     * @see    WolfSSLContext#enableCRL(int)
     * @see    WolfSSLContext#disableCRL()
     * @see    WolfSSLContext#setCRLCb(WolfSSLMissingCRLCallback)
     */
    public int disableCRL()
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

       synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr, () -> "entered disableCRL()");

             return disableCRL(this.sslPtr);
        }
    }

    /**
     * Loads CRL files into wolfSSL from the specified path.
     * This method loads a list of CRL files into wolfSSL. The files can be
     * in either PEM or DER format, as specified by the <b>type</b>
     * parameter.
     *
     * @param path      path to directory containing CRL files
     * @param type      type of files in <b>path</b>, either <code>
     *                  SSL_FILETYPE_PEM</code> or <code>SSL_FILETYPE_ASN1
     *                  </code>.
     * @param monitor   OR'd list of flags to indicate if wolfSSL should
     *                  monitor the provided CRL directory for changes.
     *                  Flag values include <code>WOLFSSL_CRL_MONITOR</code>
     *                  to indicate that the directory should be monitored
     *                  and <code>WOLFSSL_CRL_START_MON</code> to start the
     *                  monitor.
     * @return          <b><code>SSL_SUCCESS</code></b> upon success<br>
     *                  <b><code>SSL_FATAL_ERROR</code></b> if enabling the
     *                  internal CertManager fails<br>
     *                  <b><code>BAD_FUNC_ARG</code></b> if the SSL pointer
     *                  is null<br>
     *                  <b><code>BAD_PATH_ERROR</code></b> if there is an
     *                  error opening the provided directory<br>
     *                  <b><code>MEMORY_E</code></b> if a memory error
     *                  occurred<br>
     *                  <b><code>MONITOR_RUNNING_E</code></b> if the CRL
     *                  monitor is already running<br>
     *                  <b><code>THREAD_CREATE_E</code></b> if there was an
     *                  error when creating the CRL monitoring thread.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    #enableCRL(int)
     * @see    #disableCRL()
     * @see    #setCRLCb(WolfSSLMissingCRLCallback)
     * @see    WolfSSLContext#enableCRL(int)
     * @see    WolfSSLContext#disableCRL()
     * @see    WolfSSLContext#setCRLCb(WolfSSLMissingCRLCallback)
     */
    public int loadCRL(String path, int type, int monitor)
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered loadCRL(" + path + ", type: " + type +
                ", monitor: " + monitor + ")");

            return loadCRL(this.sslPtr, path, type, monitor);
        }
    }

    /**
     * Registers CRL callback to be called when CRL lookup fails.
     *
     * @param cb callback to be registered with SSL session, called
     *           when CRL lookup fails.
     * @return   <b><code>SSL_SUCCESS</code></b> upon success,
     *           <b><code>BAD_FUNC_ARG</code></b> if SSL pointer is null.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    #enableCRL(int)
     * @see    #disableCRL()
     * @see    #loadCRL(String, int, int)
     * @see    WolfSSLContext#enableCRL(int)
     * @see    WolfSSLContext#disableCRL()
     * @see    WolfSSLContext#setCRLCb(WolfSSLMissingCRLCallback)
     */
    public int setCRLCb(WolfSSLMissingCRLCallback cb)
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered setCRLCb(" + cb + ")");

            return setCRLCb(this.sslPtr, cb);
        }
    }

    /**
     * Returns the cipher suite name associated with the WolfSSL session
     * in String format.
     *
     * @return String representation of the cipher suite associated
     *         with the corresponding WolfSSL session.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    WolfSSLSession#getCurrentCipher()
     */
    public String cipherGetName()
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered cipherGetName()");

            return cipherGetName(this.sslPtr);
        }
    }

    /**
     * Allows retrieval of the Hmac/Mac secret from the handshake process.
     * The <b>verify</b> parameter specifies whether this is for verification
     * of a peer message.
     *
     * @param verify  specifies whether this if for verification of a peer
     *                message.
     * @return        a valid secret upon success, or <b>null</b> for an
     *                error state. The size of the secret can be obtained
     *                from getHmacSize().
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    #getHmacSize()
     */
    public byte[] getMacSecret(int verify)
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered getMacSecret()");

            return getMacSecret(this.sslPtr, verify);
        }
    }

    /**
     * Allows retrieval of the client write key from the handshake process.
     *
     * @return  a valid key buffer upon success, or <b>null</b> for an error
     *          state. The size of the key can be obtained from getKeySize().
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    #getKeySize()
     * @see    #getClientWriteIV()
     */
    public byte[] getClientWriteKey()
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered getClientWriteKey()");

            return getClientWriteKey(this.sslPtr);
        }
    }

    /**
     * Allows retrieval of the client write IV (initialization vector) from
     * the handshake process.
     *
     * @return  a valid IV buffer upon success, or <b>null</b> for an error
     *          state. The size of the IV can be obtained from
     *          getCipherBlockSize().
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    #getCipherBlockSize()
     * @see    #getClientWriteKey()
     */
    public byte[] getClientWriteIV()
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered getClientWriteIV()");

            return getClientWriteIV(this.sslPtr);
        }
    }

    /**
     * Allows retrieval of the server write key from the handshake process.
     *
     * @return  a valid key buffer upon success, or <b>null</b> for an error
     *          state. The size of the key can be obtained from getKeySize().
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    #getKeySize()
     * @see    #getServerWriteIV()
     */
    public byte[] getServerWriteKey()
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered getServerWriteKey()");

            return getServerWriteKey(this.sslPtr);
        }
    }

    /**
     * Allows retrieval of the server write IV (initialization vector) from
     * the handshake process.
     *
     * @return  a valid IV buffer upon success, or <b>null</b> for an error
     *          state. The size of the IV can be obtained from
     *          getCipherBlockSize().
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    #getCipherBlockSize()
     * @see    #getServerWriteKey()
     */
    public byte[] getServerWriteIV()
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered getServerWriteIV()");

            return getServerWriteIV(this.sslPtr);
        }
    }

    /**
     * Allows retrieval of the key size from the handshake process.
     *
     * @return  the key size in bytes upon success.
     *          <b><code>BAD_FUNC_ARG</code></b> for an error state.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @see    #getClientWriteKey()
     * @see    #getServerWriteKey()
     */
    public int getKeySize() throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered getKeySize()");

            return getKeySize(this.sslPtr);
        }
    }

    /**
     * Allows retrieval of the side of this wolfSSL connection.
     *
     * @return  <b><code>WOLFSSL_SERVER_END</code></b> or
     *          <b><code>WOLFSSL_CLIENT_END</code></b> depending on the side
     *          of the wolfSSL session object.
     *          <b><code>BAD_FUNC_ARG</code></b> for an error state.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @see    #getClientWriteKey()
     * @see    #getServerWriteKey()
     */
    public int getSide() throws IllegalStateException {

        int ret;

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr, () -> "entered getSide()");

            ret = getSide(this.sslPtr);

            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr, () -> "side: " + ret);
        }

        return ret;
    }

    /**
     * Allows callers to determine if the negotiated protocol version is at
     * least TLS version 1.1 or greater.
     *
     * @return  <b><code>1</code></b> for true, <b><code>0</code></b> for
     *          false.
     *          <b><code>BAD_FUNC_ARG</code></b> for an error state.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @see    #getSide()
     */
    public int isTLSv1_1() throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr, () -> "entered isTLSv1_1()");

            return isTLSv1_1(this.sslPtr);
        }
    }

    /**
     * Allows caller to determine the negotiated bulk cipher algorithm from
     * the handshake.
     *
     * @return  If successful, the call will return one of the following:<br>
     *          WolfSSL.wolfssl_cipher_null<br>
     *          WolfSSL.wolfssl_des<br>
     *          WolfSSL.wolfssl_triple_des<br>
     *          WolfSSL.wolfssl_aes<br>
     *          WolfSSL.wolfssl_aes_gcm<br>
     *          WolfSSL.wolfssl_aes_ccm<br>
     *          WolfSSL.wolfssl_camellia<br>
     *          <b><code>BAD_FUNC_ARG</code></b> for an error state.<br>
     * @throws IllegalStateException WolfSSLContext has been freed
     * @see    #getCipherBlockSize()
     * @see    #getKeySize()
     */
    public int getBulkCipher() throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered getBulkCipher()");

            return getBulkCipher(this.sslPtr);
        }
    }

    /**
     * Allows callers to determine the negotiated cipher block size from the
     * handshake.
     *
     * @return  the size in bytes of the cipher block size upon success,
     *          <b><code>BAD_FUNC_ARG</code></b> for an error state.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @see    #getBulkCipher()
     * @see    #getKeySize()
     */
    public int getCipherBlockSize() throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered getCipherBlockSize()");

            return getCipherBlockSize(this.sslPtr);
        }
    }

    /**
     * Allows caller to determine the negotiated aead mac size from the
     * handshake.
     * For cipher type <b>WOLFSSL_AEAD_TYPE</b>.
     *
     * @return  the size in bytes of the aead mac size upon success,
     *          <b><code>BAD_FUNC_ARG</code></b> for an error state.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @see    #getBulkCipher()
     * @see    #getKeySize()
     */
    public int getAeadMacSize() throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered getAeadMacSize()");

            return getAeadMacSize(this.sslPtr);
        }
    }

    /**
     * Allows the caller to determine the negotiated (h)mac size from the
     * handshake.
     * For cipher types except <b>WOLFSSL_AEAD_TYPE</b>.
     *
     * @return  the size in bytes of the (h)mac size upon success,
     *          <b><code>BAD_FUNC_ARG</code></b> for an error state.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @see    #getBulkCipher()
     * @see    #getHmacType()
     */
    public int getHmacSize() throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered getHmacSize()");

            return getHmacSize(this.sslPtr);
        }
    }

    /**
     * Allows caller to determine the negotiated (h)mac type from the
     * handshake.
     * For cipher types except <b>WOLFSSL_AEAD_TYPE</b>.
     *
     * @return  If successful, the call will return one of the following:<p>
     *          WolfSSL.MD5<br>
     *          WolfSSL.SHA<br>
     *          WolfSSL.SHA256<br>
     *          WolfSSL.SHA394<br><br>
     *          <b><code>BAD_FUNC_ARG</code></b> or
     *          <b><code>SSL_FATAL_ERROR</code></b> will be returned for an
     *          error state.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @see    #getBulkCipher()
     * @see    #getHmacSize()
     *
     */
    public int getHmacType() throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr, () -> "entered getHmacType()");

            return getHmacType(this.sslPtr);
        }
    }

    /**
     * Allows caller to determine the negotiated cipher type from the
     * handshake.
     *
     * @return  If successful, the call will return one of the following:<p>
     *          WolfSSL.WOLFSSL_BLOCK_TYPE<br>
     *          WolfSSL.WOLFSSL_STREAM_TYPE<br>
     *          WolfSSL.WOLFSSL_AEAD_TYPE<br><br>
     *          <b><code>BAD_FUNC_ARG</code></b> will be returned for an
     *          error state.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @see    #getBulkCipher()
     * @see    #getHmacType()
     */
    public int getCipherType() throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered getCipherType()");

            return getCipherType(this.sslPtr);
        }
    }

    /**
     * Allows caller to set the Hmac Inner vector for message sending/receiving.
     * The result is written to <b>inner</b> which should be at least
     * getHmacSize() bytes. The size of the message is specified by <b>sz</b>,
     * <b>content</b> is the type of message, and <b>verify</b> specifies
     * whether this is a verification of a peer message. Valid for cipher
     * types excluding <b>WOLFSSL_AEAD_TYPE</b>.
     *
     * @param   inner    inner HMAC vector to set
     * @param   sz       size of the message, in bytes
     * @param   content  type of the message
     * @param   verify   specifies if this is a verification of a peer message.
     *
     * @return  <b><code>1</code></b> upon success,
     *          <b><code>BAD_FUNC_ARG</code></b> for an error state.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @see    #getBulkCipher()
     * @see    #getHmacType()
     */
    public int setTlsHmacInner(byte[] inner, long sz, int content,
            int verify) throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered setTlsHmacInner(sz: " + sz + ", content: " +
                content + ", verify: " + verify + ")");

            return setTlsHmacInner(this.sslPtr, inner, sz, content, verify);
        }
    }

    /**
     * Allows caller to set the Atomic Record Processing Mac/Encrypt
     * Callback Context.
     *
     * @param ctx   context object to be registered with the SSL session's
     *              MAC/Encrypt method.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    WolfSSLContext#setMacEncryptCb(WolfSSLMacEncryptCallback)
     */
    public void setMacEncryptCtx(Object ctx)
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered setMacEncryptCtx(" + ctx + ")");

            macEncryptCtx = ctx;
        }
    }

    /**
     * Allows caller to set the Atomic User Record Processing Decrypt/Verify
     * Callback Context.
     *
     * @param ctx   context object to be registered with the SSL session's
     *              decrypt/verify method.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    WolfSSLContext#setDecryptVerifyCb(WolfSSLDecryptVerifyCallback)
     */
    public void setDecryptVerifyCtx(Object ctx)
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered setDecryptVerifyCtx(" + ctx + ")");

            decryptVerifyCtx = ctx;
        }
    }

    /**
     * Allows caller to set the Atomic User Record Processing Verify/Decrypt
     * Callback Context.
     *
     * @param ctx   context object to be registered with the SSL session's
     *              verify/decrypt method.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    WolfSSLContext#setVerifyDecryptCb(WolfSSLVerifyDecryptCallback)
     */
    public void setVerifyDecryptCtx(Object ctx)
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered setVerifyDecryptCtx(" + ctx + ")");

            verifyDecryptCtx = ctx;
        }
    }

    /**
     * Allows caller to set the Public Key ECC Signing Callback Context.
     *
     * @param ctx   context object to be registered with the SSL session's
     *              ECC signing method.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    WolfSSLContext#setEccSignCb(WolfSSLEccSignCallback)
     */
    public void setEccSignCtx(Object ctx)
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered setEccSignCtx(" + ctx + ")");

            eccSignCtx = ctx;
            setEccSignCtx(this.sslPtr);
        }
    }

    /**
     * Allows caller to set the Public Key ECC Verification Callback Context.
     *
     * @param ctx   context object to be registered with the SSL session's
     *              ECC verification method.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    WolfSSLContext#setEccVerifyCb(WolfSSLEccVerifyCallback)
     */
    public void setEccVerifyCtx(Object ctx)
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered setEccVerifyCtx(" + ctx + ")");

            eccVerifyCtx = ctx;
            setEccVerifyCtx(this.sslPtr);
        }
    }

    /**
     * Allows caller to set the Public Key ECC Shared Secret Callback Context.
     *
     * @param ctx   context object to be registered with the SSL session's
     *              ECC shared secret method.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    WolfSSLContext#setEccSignCb(WolfSSLEccSignCallback)
     * @see    WolfSSLContext#setEccVerifyCb(WolfSSLEccVerifyCallback)
     */
    public void setEccSharedSecretCtx(Object ctx)
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered setEccSharedSecretCtx(" + ctx + ")");

            eccSharedSecretCtx = ctx;
            setEccSharedSecretCtx(this.sslPtr);
        }
    }

    /**
     * Allows caller to set the Public Key RSA Signing Callback Context.
     *
     * @param ctx   context object to be registered with the SSL session's
     *              RSA signing method.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    WolfSSLContext#setRsaSignCb(WolfSSLRsaSignCallback)
     */
    public void setRsaSignCtx(Object ctx)
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered setRsaSignCtx(" + ctx + ")");

            rsaSignCtx = ctx;
            setRsaSignCtx(this.sslPtr);
        }
    }

    /**
     * Allows caller to set the Public Key RSA Verification Callback
     * Context.
     *
     * @param ctx   context object to be registered with the SSL session's
     *              RSA verification method.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    WolfSSLContext#setRsaVerifyCb(WolfSSLRsaVerifyCallback)
     */
    public void setRsaVerifyCtx(Object ctx)
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered setRsaVerifyCtx(" + ctx + ")");

            rsaVerifyCtx = ctx;
            setRsaVerifyCtx(this.sslPtr);
        }
    }

    /**
     * Allows caller to set the Public Key RSA Public Encrypt Callback
     * Context.
     *
     * @param ctx   context object to be registered with the SSL session's
     *              RSA public encrypt method.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    WolfSSLContext#setRsaEncCb(WolfSSLRsaEncCallback)
     */
    public void setRsaEncCtx(Object ctx)
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered setRsaEncCtx(" + ctx + ")");

            rsaEncCtx = ctx;
            setRsaEncCtx(this.sslPtr);
        }
    }

    /**
     * Allows caller to set the Public Key RSA Private Decrypt Callback
     * Context.
     *
     * @param ctx   context object to be registered with the SSL session's
     *              RSA private decrypt method.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    WolfSSLContext#setRsaDecCb(WolfSSLRsaDecCallback)
     */
    public void setRsaDecCtx(Object ctx)
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered setRsaDecCtx(" + ctx + ")");

            rsaDecCtx = ctx;
            setRsaDecCtx(this.sslPtr);
        }
    }

    /**
     * Allows caller to set the PSK client callback at the WolfSSLSession level.
     * This provides a method for the user to set the identity, hint, and key
     * the WolfSSLSession level. The PSK client callback can also be set at the
     * WolfSSLContext level, allowing the user to set it once for all
     * SSL/TLS sessions that are created from the WolfSSLContext.
     * The callback should return the length of the key in octets or
     * 0 for error. The <b>ssl</b> parameter is available for the user's
     * convenience. <b>hint</b> is the client PSK hint. <b>identity</b>
     * is the client identity, with a maximum size in characters of
     * <b>idMaxLen</b>. <b>key</b> is the client key, with a maximum size
     * in bytes of <b>keyMaxLen</b>. An example callback can be found
     * in examples/MyPskClientCallback.java.
     *
     * If the user sets the PSK client callback at both WolfSSLSession and
     * WolfSSLContext levels, the context-level one will be used.
     *
     * @param callback object to be registered as the PSK client callback
     *                 for the WolfSSLSession. The signature of this object
     *                 and corresponding method must match that as shown in
     *                 WolfSSLPskClientCallback.java, inside
     *                 pskClientCallback().
     * @throws IllegalStateException WolfSSLSession has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    WolfSSLContext#setPskClientCb(WolfSSLPskClientCallback)
     * @see    WolfSSLContext#setPskServerCb(WolfSSLPskServerCallback)
     * @see    WolfSSLContext#usePskIdentityHint(String)
     * @see    WolfSSLSession#setPskServerCb(WolfSSLPskServerCallback)
     * @see    WolfSSLSession#getPskIdentity()
     * @see    WolfSSLSession#getPskIdentityHint()
     */
    public void setPskClientCb(WolfSSLPskClientCallback callback)
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered setPskClientCb(" + callback + ")");

            /* set PSK client callback */
            internPskClientCb = callback;

            /* register internal callback with native library */
            setPskClientCb(this.sslPtr);
        }
    }

    /**
     * Allows caller to set the PSK server identity and key at the
     * WolfSSLSession level.
     * The PSK server callback can also be set at the WolfSSLContext level,
     * allowing the user to set it once for all SSL/TLS sessions that are
     * created from the WolfSSLContext.
     * The callback should return the length of the key in octets or
     * 0 for error. The <b>ssl</b> parameter is available for the user's
     * convenience. <b>identity</b> is the client identity,
     * <b>key</b> is the server key, with a maximum size
     * in bytes of <b>keyMaxLen</b>. An example callback can be found
     * in examples/MyPskServerCallback.java.
     *
     * @param callback object to be registered as the PSK server callback
     *                 for the WolfSSLSession. The signature of this object
     *                 and corresponding method must match that as shown in
     *                 WolfSSLPskServerCallback.java, inside
     *                 pskServerCallback().
     * @throws IllegalStateException WolfSSLSession has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    WolfSSLContext#setPskClientCb(WolfSSLPskClientCallback)
     * @see    WolfSSLContext#setPskServerCb(WolfSSLPskServerCallback)
     * @see    WolfSSLContext#usePskIdentityHint(String)
     * @see    WolfSSLSession#setPskClientCb(WolfSSLPskClientCallback)
     * @see    WolfSSLSession#getPskIdentity()
     * @see    WolfSSLSession#getPskIdentityHint()
     */
    public void setPskServerCb(WolfSSLPskServerCallback callback)
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered setPskServerCb(" + callback + ")");

            /* set PSK server callback */
            internPskServerCb = callback;

            /* register internal callback with native library */
            setPskServerCb(this.sslPtr);
        }
    }

    /**
     * Returns the PSK identity hint.
     *
     * @throws IllegalStateException WolfSSLContext has been freed
     * @return PSK identity hint String
     * @see    WolfSSLContext#setPskClientCb(WolfSSLPskClientCallback)
     * @see    WolfSSLContext#setPskServerCb(WolfSSLPskServerCallback)
     * @see    WolfSSLContext#usePskIdentityHint(String)
     * @see    WolfSSLSession#setPskClientCb(WolfSSLPskClientCallback)
     * @see    WolfSSLSession#setPskServerCb(WolfSSLPskServerCallback)
     * @see    WolfSSLSession#getPskIdentity()
     * @see    WolfSSLSession#usePskIdentityHint(String)
     */
    public String getPskIdentityHint() throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered getPskIdentityHint()");

            return getPskIdentityHint(this.sslPtr);
        }
    }

    /**
     * Returns the PSK identity.
     *
     * @throws IllegalStateException WolfSSLContext has been freed
     * @return PSK identity hint String
     * @see    WolfSSLContext#setPskClientCb(WolfSSLPskClientCallback)
     * @see    WolfSSLContext#setPskServerCb(WolfSSLPskServerCallback)
     * @see    WolfSSLContext#usePskIdentityHint(String)
     * @see    WolfSSLSession#setPskClientCb(WolfSSLPskClientCallback)
     * @see    WolfSSLSession#setPskServerCb(WolfSSLPskServerCallback)
     * @see    WolfSSLSession#getPskIdentityHint()
     * @see    WolfSSLSession#usePskIdentityHint(String)
     */
    public String getPskIdentity() {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered getPskIdentity()");

            return getPskIdentity(this.sslPtr);
        }
    }

    /**
     * Sets the identity hint for this session.
     *
     * @param  hint  identity hint to be used for session.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @return <code>SSL_SUCCESS</code> upon success,
     *         <code>SSL_FAILURE</code> upon error.
     * @see    WolfSSLContext#setPskClientCb(WolfSSLPskClientCallback)
     * @see    WolfSSLContext#setPskServerCb(WolfSSLPskServerCallback)
     * @see    WolfSSLContext#usePskIdentityHint(String)
     * @see    WolfSSLSession#setPskClientCb(WolfSSLPskClientCallback)
     * @see    WolfSSLSession#setPskServerCb(WolfSSLPskServerCallback)
     * @see    WolfSSLSession#getPskIdentityHint()
     * @see    WolfSSLSession#getPskIdentity()
     */
    public int usePskIdentityHint(String hint) {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered usePskIdentityHint(" + hint + ")");

            return usePskIdentityHint(this.sslPtr, hint);
        }
    }

    /**
     * Used to determine if the handshake has been completed.
     *
     * @throws IllegalStateException WolfSSLContext has been freed
     * @return true if the handshake is completed -- false if not.
     */
    public boolean handshakeDone() {

        final boolean done;

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered handshakeDone()");

            done = handshakeDone(this.sslPtr);

            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "handshake done: " + done);
        }

        return done;
    }

    /**
     * Sets the WOLFSSL to be a client
     *
     * @throws IllegalStateException WolfSSLContext has been freed
     */
    public void setConnectState() {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered setConnectState()");

            setConnectState(this.sslPtr);
        }
    }

    /**
     * Sets the WOLFSSL to be a server
     *
     * @throws IllegalStateException WolfSSLContext has been freed\
     */
    public void setAcceptState() {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered setAcceptState()");

            setAcceptState(this.sslPtr);
        }
    }

    /**
     * Sets the verification method for remote peers and also allows a
     * verify callback to be registered with the SSL session.
     * If no verify callback is desired, null can be used for <code>
     * callback</code>.
     * <p>
     * The verification <b>mode</b> of peer certificates is a logically
     * OR'd list of flags. The possible flag values include:
     * <p>
     * <code>SSL_VERIFY_NONE</code><br>
     * <b>Client mode:</b> the client will not verify the certificate
     * received from teh server and the handshake will continue as normal.<br>
     * <b>Server mode:</b> the server will not send a certificate request to
     * the client. As such, client verification will not be enabled.
     * <p>
     * <code>SSL_VERIFY_PEER</code><br>
     * <b>Client mode:</b> the client will verify the certificate received
     * from the server during the handshake. This is turned on by default in
     * wolfSSL, therefore, using this option has no effect.<br>
     * <b>Server mode:</b> the server will send a certificate request to the
     * client and verify the client certificate received.
     * <p>
     * <code>SSL_VERIFY_FAIL_IF_NO_PEER_CERT</code><br>
     * <b>Client mode:</b> no effect when used on the client side.<br>
     * <b>Server mode:</b> the verification will fail on the server side if
     * the client fails to send a certificate when requested to do so (when
     * using SSL_VERIFY_PEER on the SSL server).
     *
     * @param mode      verification type
     * @param callback  custom verification callback to register with the SSL
     *                  session. If no callback is desired, <code>null</code>
     *                  may be used.
     * @throws IllegalStateException WolfSSLContext has been freed
     */
    public void setVerify(int mode, WolfSSLVerifyCallback callback)
        throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered setVerify(mode: " + mode + ", callback: " +
                callback + ")");

            setVerify(this.sslPtr, mode, callback);
        }
    }

    /**
     * Sets the options to use for the WOLFSSL structure.
     * Example options are WolfSSL.SSL_OP_NO_SSLv3
     *
     *
     * @param op      bit mask of options to set
     * @return returns the revised options bit mask on success
     * @throws IllegalStateException WolfSSLContext has been freed
     */
    public long setOptions(long op)
            throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered setOptions(" + op + ")");

            return setOptions(this.sslPtr, op);
        }
    }


    /**
     * Gets the options to use for the WOLFSSL structure.
     * Example options are WolfSSL.SSL_OP_NO_SSLv3
     *
     *
     * @return returns the revised options bit mask on success
     * @throws IllegalStateException WolfSSLContext has been freed
     */
    public long getOptions()
            throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered getOptions()");

            return getOptions(this.sslPtr);
        }
    }

    /**
     * Returns true if the last alert received by this session was a
     * close_notify alert from the peer.
     *
     * @return true if close_notify has been received, otherwise false
     */
    public boolean gotCloseNotify() {

        final boolean gotNotify;

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered gotCloseNotify()");

            int ret = gotCloseNotify(this.sslPtr);
            if (ret == 1) {
                gotNotify = true;
            } else {
                gotNotify = false;
            }

            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "got close notify: " + gotNotify);

            return gotNotify;
        }
    }

    /**
     * Registers a receive callback for wolfSSL to get input data.
     *
     * This receive callback uses WolfSSLIORecvCallback which uses
     * byte arrays (byte[]). To use direct ByteBuffers, and avoid an extra
     * JNI array allocaiton, use
     * setIORecvByteBuffer(WolfSSLByteBufferIORecvCallback).
     *
     * By default, wolfSSL uses EmbedReceive() in src/io.c as the callback
     * which uses the system TCP recv() function. The user can register a
     * method here to get receive TLS-encoded data from memory, some other
     * network module, or anywhere else. Please see the EmbedReceive() function
     * in src/io.c as a guide for how the function should work and for error
     * codes.
     * <p>
     * In particular, <b>IO_ERR_WANT_READ</b> should be returned for
     * non-blocking receive when no data is ready.
     *
     * @param callback  method to be registered as the receive callback for
     *                  the wolfSSL context. The signature of this function
     *                  must follow that as shown in
     *                  WolfSSLIORecvCallback#receiveCallback(WolfSSLSession,
     *                  byte[], int, long).
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    #setIOSend(WolfSSLIOSendCallback)
     */
    public void setIORecv(WolfSSLIORecvCallback callback)
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered setIORecv(" + callback + ") - byte array");

            /* Only allow one recv callback registered at a time, if ByteBuffer
             * version has been set, set to null before setting byte variant. */
            if (internRecvSSLCb_BB != null) {
                internRecvSSLCb_BB = null;
            }

            /* set user I/O recv */
            internRecvSSLCb_array = callback;

            if (callback != null) {
                /* register internal callback with native library */
                setSSLIORecv(this.sslPtr);
            }
        }
    }

    /**
     * Registers a receive callback for wolfSSL to get input data.
     *
     * This receive callback uses WolfSSLByteBufferIORecvCallback which uses
     * a direct ByteBuffer. To use a byte array instead use
     * setIORecv(WolfSSLIORecvCallback), but this will incur one additional
     * native JNI array allocation.
     *
     * By default, wolfSSL uses EmbedReceive() in src/io.c as the callback
     * which uses the system TCP recv() function. The user can register a
     * method here to get receive TLS-encoded data from memory, some other
     * network module, or anywhere else. Please see the EmbedReceive() function
     * in src/io.c as a guide for how the function should work and for error
     * codes.
     * <p>
     * In particular, <b>IO_ERR_WANT_READ</b> should be returned for
     * non-blocking receive when no data is ready.
     *
     * @param callback  method to be registered as the receive callback for
     *                  the wolfSSL context. The signature of this function
     *                  must follow that as shown in
     *                  WolfSSLByteBufferIORecvCallback#receiveCallback(
     *                  WolfSSLSession, ByteBuffer, int, long).
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    #setIOSend(WolfSSLIOSendCallback)
     */
    public void setIORecvByteBuffer(WolfSSLByteBufferIORecvCallback callback)
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered setIORecv(" + callback + ") - ByteBuffer");

            /* Only allow one recv callback registered at a time, if array
             * version has been set, set to null before setting ByteBuffer. */
            if (internRecvSSLCb_array != null) {
                internRecvSSLCb_array = null;
            }

            /* set user I/O recv */
            internRecvSSLCb_BB = callback;

            if (callback != null) {
                /* Register internal callback with native library, registers
                 * JNI NativeSSLIORecvCb() with native wolfSSL.
                 * NativeSSLIORecvCb() will then call back into
                 * internRecvSSLCb_array/BB(). */
                setSSLIORecv(this.sslPtr);
            }
        }
    }

    /**
     * Registers a send callback for wolfSSL to write TLS encoded output data.
     *
     * This send callback uses WolfSSLIOSendCallback which uses byte arrays
     * (byte[]). To use direct ByteBuffers, and avoid an extra JNI array
     * allocation, use setIOSendByteBuffer(WolfSSLByteBufferIOSendCallback).
     *
     * By default, wolfSSL uses EmbedSend() in src/io.c as the callback,
     * which uses the system TCP send() function. The user can register
     * a method here to send TLS-encoded output data to memory, some other
     * network module, or to anywhere else. Please see the EmbedSend() function
     * in src/io.c as a guide for how the function should work and for error
     * codes.
     * <p>
     * In particular, <b>IO_ERR_WANT_WRITE</b> should be returned for
     * non-blocking send when the action cannot be taken yet.
     *
     * @param callback  method to be registered as the send callback for
     *                  the wolfSSL context. The signature of this function
     *                  must follow that as shown in
     *                  WolfSSLIOSendCallback#sendCallback(WolfSSLSession,
     *                  byte[], int, Object).
     * @throws IllegalStateException WolfSSLSession has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    #setIORecv(WolfSSLIORecvCallback)
     */
    public void setIOSend(WolfSSLIOSendCallback callback)
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered setIOSend(" + callback + ") - byte array");

            /* Only allow one send callback registered at a time, if ByteBuffer
             * version has been set, set to null before setting byte variant. */
            if (internSendSSLCb_BB != null) {
                internSendSSLCb_BB = null;
            }

            /* set user I/O send */
            internSendSSLCb_array = callback;

            if (callback != null) {
                /* Register internal callback with native library, registers
                 * JNI NativeSSLIOSendCb() with native wolfSSL.
                 * NativeSSLIOSendCb() will then call back into
                 * internSendSSLCb_array/BB(). */
                setSSLIOSend(this.sslPtr);
            }
        }
    }

    /**
     * Registers a send callback for wolfSSL to write TLS encoded output data.
     *
     * This send callback uses WolfSSLByteBufferIOSendCallback which uses a
     * ByteBuffer. To use a byte array instead, use
     * setIOSend(WolfSSLIOSendCallback), but this will incur one
     * additional native JNI array allocation.
     *
     * By default, wolfSSL uses EmbedSend() in src/io.c as the callback,
     * which uses the system TCP send() function. The user can register
     * a method here to send TLS-encoded output data to memory, some other
     * network module, or to anywhere else. Please see the EmbedSend() function
     * in src/io.c as a guide for how the function should work and for error
     * codes.
     * <p>
     * In particular, <b>IO_ERR_WANT_WRITE</b> should be returned for
     * non-blocking send when the action cannot be taken yet.
     *
     * @param callback  method to be registered as the send callback for
     *                  the wolfSSL context. The signature of this function
     *                  must follow that as shown in
     *                  WolfSSLByteBufferIOSendCallback#sendCallback(
     *                  WolfSSLSession, ByteBuffer, int, Object).
     * @throws IllegalStateException WolfSSLSession has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    #setIORecv(WolfSSLIORecvCallback)
     */
    public void setIOSendByteBuffer(WolfSSLByteBufferIOSendCallback callback)
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered setIOSend(" + callback + ") - ByteBuffer");

            /* Only allow one recv callback registered at a time, if array
             * version has been set, set to null before setting ByteBuffer. */
            if (internSendSSLCb_array != null) {
                internSendSSLCb_array = null;
            }

            /* set user I/O send */
            internSendSSLCb_BB = callback;

            if (callback != null) {
                /* Register internal callback with native library, registers
                 * JNI NativeSSLIOSendCb() with native wolfSSL.
                 * NativeSSLIOSendCb() will then call back into
                 * internSendSSLCb_array/BB(). */
                setSSLIOSend(this.sslPtr);
            }
        }
    }

    /**
     * Interrupt native I/O operations blocked inside select()/poll().
     *
     * This is used by wolfJSSE when SSLSocket.close() is called, to wake up
     * threads that are blocked in select()/poll().
     *
     * @return WolfSSL.SSL_SUCCESS on success, negative on error.
     *
     * @throws IllegalStateException WolfSSLSession has been freed
     */
    public synchronized int interruptBlockedIO()
        throws IllegalStateException {

        confirmObjectIsActive();

        /* Not synchronizing on sslLock, since we want to interrupt threads
         * blocked on I/O operations, which will already hold sslLock */

        WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
            WolfSSLDebug.INFO, this.sslPtr,
            () -> "entered interruptBlockedIO()");

        return interruptBlockedIO(this.sslPtr);
    }

    /**
     * Get count of threads currently blocked in select() or poll()
     * at the native JNI level.
     *
     * @return count of threads waiting in select() or poll()
     *
     * @throws IllegalStateException WolfSSLSession has been freed
     */
    public synchronized int getThreadsBlockedInPoll()
        throws IllegalStateException {

        confirmObjectIsActive();

        WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
            WolfSSLDebug.INFO, this.sslPtr,
            () -> "entered getThreadsBlockedInPoll()");

        return getThreadsBlockedInPoll(this.sslPtr);
    }

    /**
     * Use SNI name with this session.
     *
     * @param type SNI type. Currently supported type is
     *        WolfSSL.WOLFSSL_SNI_HOST_NAME.
     * @param data encoded data for SNI extension value
     *
     * @return WolfSSL.SSL_SUCCESS on success, negative on error
     *
     * @throws IllegalStateException if called when WolfSSLSession is not
     *         active
     */
    public int useSNI(byte type, byte[] data)
        throws IllegalStateException {

        int ret;

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered useSNI(type: " + type + ")");

            ret = useSNI(this.sslPtr, type, data);

            if (ret == WolfSSL.SSL_SUCCESS) {
                /* Save SNI requested by client for use later if needed */
                this.clientSNIRequested = Arrays.copyOf(data, data.length);
            }
        }

        return ret;
    }

    /**
     * Return copy of SNI name that this client set/requested. Used at JSSE
     * level by Endpoint Identification hostname matching on client-side.
     *
     * @return client-requested SNI name as byte array, or null if not set
     * @throws IllegalStateException if called when WolfSSLSession is not
     *         active
     */
    public byte[] getClientSNIRequest()
        throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered getClientSNIRequest()");

            if (this.clientSNIRequested == null) {
                return null;
            }

            return Arrays.copyOf(this.clientSNIRequested,
                this.clientSNIRequested.length);
        }
    }

    /**
     * Get SNI request used for this session object as bytes.
     *
     * @param type SNI type. Currently supported type is
     *             WolfSSL.WOLFSSL_SNI_HOST_NAME.
     * @return SNI name requested in this session as a byte array, or
     *         null if not available.
     * @throws IllegalStateException if called when WolfSSLSession is not
     *         active
     */
    public byte[] getSNIRequestBytes(byte type) throws IllegalStateException {

        byte[] reqBytes = null;

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered getSNIRequest(type: " + type + ")");

            /* Returns a byte array representing SNI host name */
            reqBytes = getSNIRequest(this.sslPtr, type);
        }

        if (reqBytes != null) {
            return reqBytes;
        }

        return null;
    }

    /**
     * Get SNI request used for this session object as String.
     *
     * @param type SNI type. Currently supported type is
     *             WolfSSL.WOLFSSL_SNI_HOST_NAME.
     * @return String representing SNI name requested in this session, or
     *         null if not available.
     * @throws IllegalStateException if called when WolfSSLSession is not
     *         active
     */
    public String getSNIRequest(byte type) throws IllegalStateException {
        byte[] request;

        confirmObjectIsActive();
        request = getSNIRequestBytes(type);
        if (request != null){
            return new String(request, StandardCharsets.UTF_8);
        }

        return null;
    }

    /**
     * Enable session tickets for this session.
     *
     * @return WolfSSL.SSL_SUCCESS on success, otherwise negative.
     * @throws IllegalStateException WolfSSLSession has been freed
     */
    public int useSessionTicket()
        throws IllegalStateException {

        int ret;

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered useSessionTicket()");

            ret = useSessionTicket(this.sslPtr);

            if (ret == WolfSSL.SSL_SUCCESS) {
                this.sessionTicketsEnabled = true;
            }

            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "enabled session tickets for session, ret: " + ret);
        }

        return ret;
    }

    /**
     * Determine if session tickets have been enabled for this session.
     * Session tickets can be enabled for this session by calling
     * WolfSSLSession.useSessionTicket().
     *
     * @return true if enabled, otherwise false.
     * @throws IllegalStateException WolfSSLSession has been freed
     */
    public synchronized boolean sessionTicketsEnabled()
        throws IllegalStateException {

        confirmObjectIsActive();

        WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
            WolfSSLDebug.INFO, this.sslPtr,
            () -> "entered sessionTicketsEnabled(): " +
            this.sessionTicketsEnabled);

        return this.sessionTicketsEnabled;
    }

    /**
     * Set ALPN extension protocol for this session from encoded byte array.
     * Calls SSL_set_alpn_protos() at native level. Format starts with
     * length, where length does not include length byte itself. Example format:
     *
     * byte[] p = "http/1.1".getBytes();
     *
     * Unless this input format is explicitly needed, useALPN(String[], int)
     * will likely be easier to use.
     *
     * @param alpnProtos ALPN protocols, encoded as byte array vector
     * @return WolfSSL.SSL_SUCCESS on success, otherwise negative on error.
     */
    public int useALPN(byte[] alpnProtos) throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered useALPN(byte[])");

            return sslSetAlpnProtos(this.sslPtr, alpnProtos);
        }
    }

    /**
     * Set ALPN extension protocol for this session from String array.
     * Calls native wolfSSL_useALPN(), where protocols should be a String
     * array of ALPN protocols. At the native JNI level, this is converted to
     * a comma-delimited list of prototocls and passed to native wolfSSL.
     *
     * This method is similar to useALPN(byte[]), but accepts a String array
     * and calls a different native wolfSSL API for ALPN use.
     *
     * @param protocols Array of ALPN protocol Strings
     * @param options Options to control behavior of ALPN failure mode.
     *                Possible options include:
     *                    WolfSSL.WOLFSSL_ALPN_CONTINUE_ON_MISMATCH
     *                    WolfSSL.WOLFSSL_ALPN_FAILED_ON_MISMATCH
     * @return WolfSSL.SSL_SUCCESS on success, otherwise negative on error.
     *
     */
    public int useALPN(String[] protocols, int options) {

        /* all protocols, comma delimited */
        StringBuilder allProtocols = new StringBuilder();

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered useALPN(String[], int)");
        }

        if (protocols == null) {
            return WolfSSL.BAD_FUNC_ARG;
        }

        for (int i = 0; i < protocols.length; i++) {
            if (i != 0) {
                allProtocols.append(",");
            }
            allProtocols.append(protocols[i]);
        }

        synchronized (sslLock) {
            return useALPN(this.sslPtr, allProtocols.toString(), options);
        }
    }

    /**
     * Get the ALPN protocol selected by the client/server for this session.
     *
     * @return byte array representation of selected protocol.
     * @throws IllegalStateException WolfSSLSession has been freed
     */
    public byte[] getAlpnSelected() throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered getAlpnSelected()");

            return sslGet0AlpnSelected(this.sslPtr);
        }
    }

    /**
     * Get the ALPN protocol selected by the client/server for this session.
     *
     * Same behavior as getAlpnSelected(), but returns a String instead of a
     * byte array.
     *
     * @return String of the selected ALPN protocol
     * @throws IllegalStateException WolfSSLSession has been freed
     */
    public String getAlpnSelectedString() throws IllegalStateException {

        byte[] alpnSelectedBytes = null;

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered getAlpnSelectedString()");
        }

        alpnSelectedBytes = getAlpnSelected();

        if (alpnSelectedBytes != null) {
            return new String(alpnSelectedBytes, StandardCharsets.UTF_8);
        } else {
            return null;
        }
    }

    /**
     * Registers ALPN select callback.
     *
     * This callback is called by native wolfSSL during the handshake
     * on the server side after receiving the ALPN protocols by the client
     * in the ClientHello message.
     *
     * @param cb callback to be registered with SSL session
     * @param arg Object that will be passed back to user inside callback
     *
     * @return    <code>SSL_SUCCESS</code> upon success. <code>
     *            NOT_COMPILED_IN</code> if wolfSSL was not compiled with
     *            ALPN support, and other negative value representing other
     *            error scenarios.
     *
     * @throws IllegalStateException WolfSSLSession has been freed
     * @throws WolfSSLJNIException Internal JNI error
     */
    public int setAlpnSelectCb(WolfSSLALPNSelectCallback cb, Object arg)
        throws IllegalStateException, WolfSSLJNIException {

        int ret = 0;

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered setAlpnSelectCb(" + cb + ", Object: " +
                arg + ")");

            ret = setALPNSelectCb(this.sslPtr);
            if (ret == WolfSSL.SSL_SUCCESS) {
                /* set ALPN select callback */
                internAlpnSelectCb = cb;

                /* set ALPN select arg Object, returned to user in callback */
                this.alpnSelectArg = arg;
            }
        }

        return ret;
    }

    /**
     * Register TLS 1.3 secret callback.
     *
     * The callback registered by this method is called by native wolfSSL
     * during TLS 1.3 connection to retrieve the secrets used in those
     * connections. These can be printed to a log file for consumption by
     * Wireshark.
     *
     * @param cb callback to be registered with this SSL session
     * @param ctx Object that will be passed back to user inside callback
     *
     * @return <code>SSL_SUCCESS</code> on success. <code>
     *         NOT_COMPILED_IN</code> if wolfSSL was not compiled with
     *         TLS 1.3 and HAVE_SECERT_CALLBACK defined, and other
     *         negative value on error.
     *
     * @throws IllegalStateException WolfSSLSession has been freed
     * @throws WolfSSLJNIException Internal JNI error
     */
    public int setTls13SecretCb(WolfSSLTls13SecretCallback cb, Object ctx)
        throws IllegalStateException, WolfSSLJNIException {

        int ret = 0;

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered setTls13SecretCb(" + cb + ", ctx: " + ctx + ")");

            ret = setTls13SecretCb(this.sslPtr);
            if (ret == WolfSSL.SSL_SUCCESS) {
                /* Set TLS 1.3 secret callback */
                internTls13SecretCb = cb;

                /* Set TLS 1.3 secret ctx Object, returned to user in cb */
                this.tls13SecretCtx = ctx;
            }
        }

        return ret;
    }

    /**
     * Register session ticket callback.
     *
     * The callback registered by this method is called by native wolfSSL
     * when a session ticket is received from the peer.
     *
     * @param cb callback to be registered with this SSL session
     * @param ctx Object that will be passed back to user inside callback
     *
     * @return <code>SSL_SUCCESS</code> on success. <code>
     *        NOT_COMPILED_IN</code> if wolfSSL was not compiled with
     *        session ticket support, and other negative value on error.
     *
     * @throws IllegalStateException WolfSSLSession has been freed
     * @throws WolfSSLJNIException Internal JNI error
     */
    public int setSessionTicketCb(WolfSSLSessionTicketCallback cb, Object ctx)
        throws IllegalStateException, WolfSSLJNIException {

        int ret = 0;

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered setSessionTicketCb(" + cb + ", ctx: " +
                ctx + ")");

            ret = setSessionTicketCb(this.sslPtr);
            if (ret == WolfSSL.SSL_SUCCESS) {
                /* Set session ticket callback */
                internSessionTicketCb = cb;

                /* Set session ticket ctx Object, returned to user in cb */
                this.sessionTicketCtx = ctx;
            }
        }

        return ret;
    }

    /**
     * Do not free temporary arrays at end of handshake.
     *
     * This needs to be called if using the TLS 1.3 secret callback, and
     * should be called after the WolfSSLSession object has been created.
     *
     * @throws IllegalStateException WolfSSLSession has been freed
     * @throws WolfSSLJNIException Internal JNI error
     */
    public void keepArrays()
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered keepArrays()");

            keepArrays(this.sslPtr);
        }
    }

    /**
     * Get the client random value used in this SSL/TLS session.
     *
     * @return client random byte array on success, or null if not available
     *
     * @throws IllegalStateException WolfSSLSession has been freed
     * @throws WolfSSLJNIException Internal JNI error
     */
    public byte[] getClientRandom()
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered getClientRandom()");

            return getClientRandom(this.sslPtr);
        }
    }

    /**
     * Enable use of secure renegotiation on this session. Calling this
     * API does not initiate secure renegotiation, but enables it. If enabled,
     * and peer requests secure renegotiation, this session will renegotiate.
     *
     * @return <code>WolfSSL.SSL_SUCCESS</code> on success, otherwise negative.
     *         Will return <code>WolfSSL.NOT_COMPILED_IN</code> if native
     *         wolfSSL has not been compiled with
     *         <code>HAVE_SECURE_RENEGOTIATION</code>.
     * @throws IllegalStateException WolfSSLSession has been freed
     */
    public int useSecureRenegotiation() throws IllegalStateException {

        confirmObjectIsActive();

       synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered useSecureRenegotiation()");

             return useSecureRenegotiation(this.sslPtr);
        }
    }

    /**
     * Enable use of secure renegotiation on this session. Calling this
     * API does not initiate secure renegotiation, but enables it. If enabled,
     * and peer requests secure renegotiation, this session will renegotiate.
     *
     * @return WolfSSL.SSL_SUCCESS on success, otherwise negative. Will
     *         return WolfSSL.NOT_COMPILED_IN if native wolfSSL has not been
     *         compiled with HAVE_SECURE_RENEGOTIATION.
     * @throws IllegalStateException WolfSSLSession has been freed
     */
    /**
     * Initiates a secure renegotiation attempt with the peer.
     * For this function to attempt a secure renegotiation,
     * <code>useSecureRenegotiation()</code> must be called prior to calling
     * this method. When called, the underlying communication channel should
     * also already be set up.
     * <p>
     * <code>rehandshake()</code> works with both blocking and non-blocking I/O.
     * When the underlying I/O is non-blocking, <code>rehandshake()</code> will
     * return when the underlying I/O could not satisfy the needs of
     * <code>rehandshake()</code> to continue the handshake. In this case, a
     * call to <code>getError</code> will yield either
     * <b>SSL_ERROR_WANT_READ</b> or <b>SSL_ERROR_WANT_WRITE</b>. The calling
     * process must then repeat the call to <code>rehandshake()</code> when the
     * underlying I/O is ready and wolfSSL will pick up where it left off.
     * <p>
     * If the underlying I/O is blocking, <code>rehandshake()</code> will only
     * return once the handshake has been finished or an error occurred.
     * </p>
     *
     * @return <code>SSL_SUCCESS</code> if successful, otherwise
     *         <code>SSL_FATAL_ERROR</code> if an error occurred. To get
     *         a more detailed error code, call <code>getError()</code>.
     *         <code>WolfSSL.NOT_COMPILED_IN</code> will be returned if
     *         native wolfSSL has not been compiled with
     *         <code>HAVE_SECURE_RENEGOTIATION</code>.
     *         <code>WolfSSL.SECURE_RENEGOTIATION_E</code> will be returned
     *         if secure renegotiation has not been enabled for this session,
     *         or a secure renegotiation error has occurred.
     * @throws IllegalStateException WolfSSLContext has been freed
     */
    public int rehandshake() throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered rehandshake()");

            return rehandshake(this.sslPtr);
        }
    }

    /**
     * Getter function to tell if shutdown has been sent or received
     * @return WolfSSL.SSL_SENT_SHUTDOWN or WolfSSL.SSL_RECEIVED_SHUTDOWN
     */
    public int getShutdown() throws IllegalStateException {

        int ret;

        confirmObjectIsActive();

        synchronized (sslLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "entered getShutdown()");

            ret = getShutdown(this.sslPtr);

            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.sslPtr,
                () -> "getShutdown(), ret: " + ret);
        }

        return ret;
    }

    @SuppressWarnings("deprecation")
    @Override
    protected void finalize() throws Throwable
    {
        /* free resources, freeSSL() checks and sets state */
        this.freeSSL();
        super.finalize();
    }

} /* end WolfSSLSession */

