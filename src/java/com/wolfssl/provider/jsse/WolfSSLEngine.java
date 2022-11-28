/* WolfSSLEngine.java
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

package com.wolfssl.provider.jsse;

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLException;
import com.wolfssl.WolfSSLIORecvCallback;
import com.wolfssl.WolfSSLIOSendCallback;
import com.wolfssl.WolfSSLJNIException;
import com.wolfssl.WolfSSLSession;
import java.nio.ByteBuffer;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLEngineResult.Status;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLParameters;
import java.net.SocketTimeoutException;

/**
 * wolfSSL implementation of SSLEngine.
 *
 * There is more verbose debugging available for this class apart
 * from the normal 'wolfjsse.debug' logging. To enable more verbose
 * logging use both the following system properties:
 *
 * System.setProperty("wolfjsse.debug", "true");
 * System.setProperty("wolfsslengine.debug", "true");
 *
 * This will add extra debug logs around wrap() and unwrap() calls, as well
 * as printing out the data sent/received in the I/O callbacks.
 *
 * @author wolfSSL
 */
public class WolfSSLEngine extends SSLEngine {

    private WolfSSLEngineHelper EngineHelper;
    private WolfSSLSession ssl;
    private com.wolfssl.WolfSSLContext ctx;
    private WolfSSLAuthStore authStore;
    private WolfSSLParameters params;
    private byte[] toSend; /* encrypted packet to send */
    private byte[] toRead; /* encrypted packet coming in */
    private int toReadSz = 0;
    private HandshakeStatus hs = SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;

    /* Does TLS handshake need initialization */
    private boolean needInit = true;

    private boolean inBoundOpen = true;
    private boolean outBoundOpen = true;

    /* closed completely (post shutdown or before handshake) */
    private boolean closed = true;

    /* handshake completed */
    private boolean handshakeFinished = false;

    /* closeNotify status when shutting down */
    private boolean closeNotifySent = false;
    private boolean closeNotifyReceived = false;

    /* client/server mode has been set */
    private boolean clientModeSet = false;

    private SendCB sendCb = null;
    private RecvCB recvCb = null;

    /* Locks for synchronization */
    private static final Object ioLock = new Object();

    /** Turn on extra/verbose SSLEngine debug logging */
    public boolean extraDebugEnabled = false;

    /**
     * Turns on additional debugging based on system properties set.
     */
    private void enableExtraDebug() {
        /* turn on verbose extra debugging if 'wolfsslengine.debug'
         * system property is set */
        String engineDebug  = System.getProperty("wolfsslengine.debug");
        if ((engineDebug != null) && (engineDebug.equalsIgnoreCase("true"))) {
            this.extraDebugEnabled = true;
        }
    }

    /**
     *  Create a new engine with no hints for session reuse
     *
     * @param ctx JNI level WolfSSLContext
     * @param auth WolfSSLAuthStore to use
     * @param params connection parameters to be used
     * @throws WolfSSLException if there is an issue creating the engine
     */
    protected WolfSSLEngine(com.wolfssl.WolfSSLContext ctx,
            WolfSSLAuthStore auth, WolfSSLParameters params)
            throws WolfSSLException {
        super();
        this.ctx = ctx;
        this.authStore = auth;
        this.params = params.copy();
        try {
            initSSL();
        } catch (WolfSSLJNIException ex) {
            Logger.getLogger(WolfSSLEngine.class.getName()).log(Level.SEVERE,
                             null, ex);
            throw new WolfSSLException("Error with init");
        }
        EngineHelper = new WolfSSLEngineHelper(this.ssl, this.authStore,
                this.params);
    }

    /**
     *  Create a new engine with hints for session reuse
     *
     * @param ctx JNI level WolfSSLContext
     * @param auth WolfSSLAuthStore to use
     * @param params connection parameters to be used
     * @param host to connect to
     * @param port to connect to
     * @throws WolfSSLException if there is an issue creating the engine
     */
    protected WolfSSLEngine(com.wolfssl.WolfSSLContext ctx,
            WolfSSLAuthStore auth, WolfSSLParameters params, String host,
            int port) throws WolfSSLException {
        super();
        this.ctx = ctx;
        this.authStore = auth;
        this.params = params.copy();
        try {
            initSSL();
        } catch (WolfSSLJNIException ex) {
            Logger.getLogger(WolfSSLEngine.class.getName()).log(Level.SEVERE,
                             null, ex);
            throw new WolfSSLException("Error with init");
        }
        EngineHelper = new WolfSSLEngineHelper(this.ssl, this.authStore,
                this.params, port, host);
    }

    /* use singleton pattern on callbacks */
    private void setCallbacks() throws WolfSSLJNIException {
        if (sendCb == null) {
            sendCb = new SendCB();
        }
        if (recvCb == null) {
            recvCb = new RecvCB();
        }
        ssl.setIORecv(recvCb);
        ssl.setIOSend(sendCb);
    }

    private void initSSL() throws WolfSSLException, WolfSSLJNIException {
        if (sendCb == null) {
            sendCb = new SendCB();
        }
        if (recvCb == null) {
            recvCb = new RecvCB();
        }

        ssl = new WolfSSLSession(ctx);
        if (ssl == null) {
            throw new WolfSSLException("Issue creating WOLFSSL structure");
        }
        setCallbacks();
        ssl.setIOReadCtx(this);
        ssl.setIOWriteCtx(this);

        enableExtraDebug();
    }

    /**
     * Copy buffered data to be sent into provided output ByteBuffer.
     *
     * Data sent will be minimum of either buffered data size or
     * destination buffer remaining space.
     *
     * Returns size of data copied.
     */
    private int CopyOutPacket(ByteBuffer out, Status status) {
        int sendSz = 0;

        if (this.toSend != null) {
            sendSz = Math.min(this.toSend.length, out.remaining());
            out.put(this.toSend, 0, sendSz);

            if (sendSz != this.toSend.length) {
                /* resize and adjust remaining toSend data */
                byte[] tmp = new byte[this.toSend.length - sendSz];
                System.arraycopy(this.toSend, sendSz, tmp, 0,
                                 this.toSend.length - sendSz);
                this.toSend = tmp;
            }
            else {
                this.toSend = null;
            }
        }
        return sendSz;
    }

    /**
     * Helper function, updates internal close_notify alert status
     * and inBound/outBoundOpen.
     */
    private synchronized void UpdateCloseNotifyStatus() {
        int ret;

        synchronized (ioLock) {
            ret = ssl.getShutdown();
        }
        if (ret == (WolfSSL.SSL_RECEIVED_SHUTDOWN |
                    WolfSSL.SSL_SENT_SHUTDOWN)) {
            this.closeNotifySent = true;
            this.closeNotifyReceived = true;
            this.inBoundOpen = false;
            this.outBoundOpen = false;
            closed = true;
        } else if (ret == WolfSSL.SSL_RECEIVED_SHUTDOWN) {
            this.closeNotifyReceived = true;
            this.inBoundOpen = false;
        } else if (ret == WolfSSL.SSL_SENT_SHUTDOWN) {
            this.closeNotifySent = true;
            this.outBoundOpen = false;
        }
    }

    /**
     * Handles logic during shutdown
     */
    private synchronized int ClosingConnection() {
        int ret;

        if (this.getUseClientMode() == true) {
            EngineHelper.saveSession();
        }

        /* get current close_notify state */
        UpdateCloseNotifyStatus();
        if (this.closeNotifySent == true &&
            this.closeNotifyReceived == true) {
            return WolfSSL.SSL_SUCCESS;
        }

        /* send/recv close_notify as needed */
        synchronized (ioLock) {
            ret = ssl.shutdownSSL();
        }
        UpdateCloseNotifyStatus();

        return ret;
    }

    /**
     * Starts or continues SSL/TLS handshake.
     * Returns WolfSSL.SSL_SUCCESS or WolfSSL.SSL_FAILURE
     */
    private synchronized int DoHandshake() throws SSLException {
        int ret = WolfSSL.SSL_SUCCESS;

        try {
            if (this.getUseClientMode() == true) {
                synchronized (ioLock) {
                    ret = this.ssl.connect();
                }
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "ssl.connect() ret:err = " + ret + " : " +
                    ssl.getError(ret));
            }
            else {
                synchronized (ioLock) {
                    ret = this.ssl.accept();
                }
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "ssl.accept() ret:err = " + ret + " : " +
                    ssl.getError(ret));
            }
        } catch (SocketTimeoutException e) {
            throw new SSLException(e);
        }

        return ret;
    }

    /**
     * Write application data using ssl.write().
     *
     * Only sends up to maximum app data chunk size
     * (SSLSession.getApplicationBufferSize()).
     *
     * Return bytes sent on success, negative on error */
    private synchronized int SendAppData(ByteBuffer[] in, int ofst, int len,
            ByteBuffer out) throws SSLException {

        int i = 0;
        int ret = 0;
        int totalIn = 0;
        int sendSz = 0;
        int inputLeft = 0;
        int inLimit = 0;
        ByteBuffer dataBuf;
        byte[] dataArr;
        int pos[] = new int[len];   /* in[] positions */
        int limit[] = new int[len]; /* in[] limits */

        /* get total input data size, store input array positions */
        for (i = ofst; i < ofst + len; i++) {
            totalIn += in[i].remaining();
            pos[i] = in[i].position();
            limit[i] = in[i].limit();
        }

        /* only send up to maximum app data size chunk */
        sendSz = Math.min(totalIn,
                          EngineHelper.getSession().getApplicationBufferSize());
        dataBuf = ByteBuffer.allocate(sendSz);

        /* gather byte array of sendSz bytes from input buffers */
        inputLeft = sendSz;
        for (i = ofst; i < ofst + len; i++) {
            int bufChunk = Math.min(in[i].remaining(), inputLeft);

            in[i].limit(in[i].position() + bufChunk);       /* set limit */
            dataBuf.put(in[i]);                             /* get data */
            inputLeft -= bufChunk;
            in[i].limit(limit[i]);                          /* reset limit */

            if (inputLeft == 0) {
                break; /* reached data size needed, stop reading */
            }
        }

        dataArr = new byte[sendSz];
        dataBuf.rewind();
        dataBuf.get(dataArr);

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                         "calling ssl.write() with size: " + sendSz);

        synchronized (ioLock) {
            ret = this.ssl.write(dataArr, sendSz);
        }
        if (ret <= 0) {
            /* error, reset in[] positions for next call */
            for (i = ofst; i < ofst + len; i++) {
                in[i].position(pos[i]);
            }
        }

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                         "ssl.write() returning: " + ret);

        return ret;
    }

    @Override
    public synchronized SSLEngineResult wrap(ByteBuffer in, ByteBuffer out)
            throws SSLException {
        return wrap(new ByteBuffer[] { in }, 0, 1, out);
    }


    @Override
    public synchronized SSLEngineResult wrap(ByteBuffer[] in, int ofst, int len,
            ByteBuffer out) throws SSLException {
        int ret = 0, i;
        int produced = 0;
        int consumed = 0;

        /* Set initial status for SSLEngineResult return */
        Status status = SSLEngineResult.Status.OK;

        if (in == null || ofst + len > in.length || out == null) {
            throw new SSLException("SSLEngine.wrap() bad arguments");
        }

        if (this.clientModeSet == false) {
            throw new IllegalStateException(
                    "setUseClientMode() has not been called on this SSLEngine");
        }

        if (extraDebugEnabled == true) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "==== [ entering wrap() ] ===================================");
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "setUseClientMode: " + EngineHelper.getUseClientMode());
            for (i = 0; i < len; i++) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "ByteBuffer in["+i+"].remaining(): " + in[i].remaining());
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "ByteBuffer in["+i+"].position(): " + in[i].position());
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "ByteBuffer in["+i+"].limit(): " + in[i].position());
            }
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "ofst: " + ofst + ", len: " + len);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "out.remaining(): " + out.remaining());
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "out.position(): " + out.position());
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "out.limit(): " + out.limit());
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "toReadSz: " + this.toReadSz);
            if (this.toSend != null) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "toSend.length: " + this.toSend.length);
            } else {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "toSend.length: 0");
            }
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "closeNotifySent: " + this.closeNotifySent);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "closeNotifyReceived: " + this.closeNotifyReceived);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "inBoundOpen: " + this.outBoundOpen);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "outBoundOpen: " + this.outBoundOpen);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "status: " + status);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "handshakeStatus: " + hs);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "handshakeFinished: " + this.handshakeFinished);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "===========================================================");
        }

        if (needInit) {
            EngineHelper.initHandshake();
            needInit = false;
            closed = false; /* opened a connection */
        }

        /* Force out buffer to be large enough to hold max packet size */
        if (out.remaining() < EngineHelper.getSession().getPacketBufferSize()) {
            return new SSLEngineResult(Status.BUFFER_OVERFLOW, hs, 0, 0);
        }

        /* Copy buffered data to be sent into output buffer */
        produced = CopyOutPacket(out, status);

        /* check if closing down connection */
        if (produced >= 0 && !outBoundOpen) {
            status = SSLEngineResult.Status.CLOSED;
            ClosingConnection();
            produced += CopyOutPacket(out, status);
        }
        else if (produced == 0) {
            /* continue handshake or application data */
            if (this.handshakeFinished == false) {
                ret = DoHandshake();
            }
            else {
                ret = SendAppData(in, ofst, len, out);
                if (ret > 0) {
                    consumed += ret;
                }
            }

            /* copy any produced data into output buffer */
            produced += CopyOutPacket(out, status);
        }

        SetHandshakeStatus(ret);

        if (extraDebugEnabled == true) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "==== [ exiting wrap() ] ===================================");
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "setUseClientMode: " + EngineHelper.getUseClientMode());
            for (i = 0; i < len; i++) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "ByteBuffer in["+i+"].remaining(): " + in[i].remaining());
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "ByteBuffer in["+i+"].position(): " + in[i].position());
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "ByteBuffer in["+i+"].limit(): " + in[i].position());
            }
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "ofst: " + ofst + ", len: " + len);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "out.remaining(): " + out.remaining());
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "out.position(): " + out.position());
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "out.limit(): " + out.limit());
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "toReadSz: " + this.toReadSz);
            if (this.toSend != null) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "toSend.length: " + this.toSend.length);
            } else {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "toSend.length: 0");
            }
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "closeNotifySent: " + this.closeNotifySent);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "closeNotifyReceived: " + this.closeNotifyReceived);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "handshakeFinished: " + this.handshakeFinished);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "inBoundOpen: " + this.outBoundOpen);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "outBoundOpen: " + this.outBoundOpen);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "handshakeStatus: " + hs);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "status: " + status);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "consumed: " + consumed);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "produced: " + produced);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "===========================================================");
        }

        return new SSLEngineResult(status, hs, consumed, produced);
    }

    /**
     * Return total remaining space in array of ByteBuffers.
     *
     * @param out array of ByteBuffers to be polled for available space
     * @param ofst offset into out array to begin
     * @param length length of ByteBuffer array
     *
     * @return number of available/remaining bytes in array of ByteBuffers
     * @throws IllegalArgumentException if readonly buffer found
     */
    private static synchronized int getTotalOutputSize(ByteBuffer[] out,
                                          int ofst, int length) {
        int i = 0;
        int maxOutSz = 0;

        for (i = 0; i < length; i++) {
            if (out[i + ofst] == null || out[i + ofst].isReadOnly()) {
                throw new IllegalArgumentException(
                    "null or readonly out buffer found");
            }
            maxOutSz += out[i + ofst].remaining();
        }

        return maxOutSz;
    }

    /**
     * Receive application data using ssl.read() from in buffer, placing
     * processed/decrypted data into out[].
     *
     * @param in input data encrypted/encapsulated in SSL/TLS records
     * @param out output ByteBuffer arrays, to hold processed/decoded plaintext
     * @param ofst offset into out[] array to begin writing data
     * @param length length of out[] array
     *
     * @return number of plaintext bytes received, or negative on error.
     */
    private synchronized int RecvAppData(ByteBuffer in, ByteBuffer[] out,
            int ofst, int length) throws SSLException {

        int i, sz, bufSpace;
        int totalRead = 0;
        int maxOutSz = 0;
        int ret = 0;
        int idx = 0; /* index into out[] array */
        byte[] tmp;

        /* pre-calculate max output size */
        maxOutSz = getTotalOutputSize(out, ofst, length);

        /* read all data we have cached, if it fits in output buffers */
        while ((this.toReadSz > 0) && (totalRead < maxOutSz)) {

            tmp = new byte[maxOutSz - totalRead];

            synchronized (ioLock) {
                ret = this.ssl.read(tmp, (maxOutSz - totalRead));
            }
            if (ret <= 0) {
                int err = ssl.getError(ret);

                switch (err) {
                    case WolfSSL.SSL_ERROR_WANT_READ:
                    case WolfSSL.SSL_ERROR_WANT_WRITE:
                        break;
                    case WolfSSL.SSL_ERROR_ZERO_RETURN:
                        /* check if is shutdown message */
                        synchronized (ioLock) {
                            if (ssl.getShutdown() ==
                                    WolfSSL.SSL_RECEIVED_SHUTDOWN) {
                                ret = ClosingConnection();
                                if (ret > 0) {
                                    /* Returns number of bytes read, 0, or err */
                                    ret = 0;
                                }
                                return ret;
                            }
                        }
                        break;
                    default:
                        throw new SSLException("wolfSSL_read() error: " +
                                ret + " , err = " + err);
                }
            }
            else {
                /* write processed data into output buffers */
                for (i = 0; i < ret;) {
                    if (idx + ofst >= length) {
                        /* no more output buffers left */
                        break;
                    }

                    bufSpace = out[idx + ofst].remaining();
                    if (bufSpace == 0) {
                        /* no more space in current out buffer, advance */
                        idx++;
                        continue;
                    }

                    sz = (bufSpace >= (ret - i)) ? (ret - i) : bufSpace;
                    out[idx + ofst].put(tmp, i, sz);
                    i += sz;
                    totalRead += sz;

                    if ((ret - i) > 0) {
                        idx++; /* go to next output buffer */
                    }
                }
            }
        }

        return totalRead;
    }

    @Override
    public synchronized SSLEngineResult unwrap(ByteBuffer in, ByteBuffer out)
            throws SSLException {
        return unwrap(in, new ByteBuffer[] { out }, 0, 1);
    }

    @Override
    public synchronized SSLEngineResult unwrap(ByteBuffer in, ByteBuffer[] out,
            int ofst, int length) throws SSLException {
        int i, ret = 0, sz = 0, idx = 0, pos;
        int consumed = 0;
        int produced = 0;
        byte[] tmp;

        /* Set initial status for SSLEngineResult return */
        Status status = SSLEngineResult.Status.OK;

        if (in == null || out == null || ofst + length > out.length) {
            throw new IllegalArgumentException(
                "SSLEngine.unwrap() bad arguments");
        }

        if (this.clientModeSet == false) {
            throw new IllegalStateException(
                    "setUseClientMode() has not been called on this SSLEngine");
        }

        if (extraDebugEnabled == true) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "==== [ entering unwrap() ] =================================");
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "setUseClientMode: " + EngineHelper.getUseClientMode());
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "in.remaining(): " + in.remaining());
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "in.position(): " + in.position());
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "in.limit(): " + in.position());
            for (i = 0; i < length; i++) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "out["+i+"].remaining(): " + out[i].remaining());
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "out["+i+"].position(): " + out[i].position());
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "out["+i+"].limit(): " + out[i].limit());
            }
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "ofst: " + ofst + ", length: " + length);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "toReadSz: " + this.toReadSz);
            if (this.toSend != null) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "toSend.length: " + this.toSend.length);
            } else {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "toSend.length: 0");
            }
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "closeNotifySent: " + this.closeNotifySent);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "closeNotifyReceived: " + this.closeNotifyReceived);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "inBoundOpen: " + this.outBoundOpen);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "outBoundOpen: " + this.outBoundOpen);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "handshakeFinished: " + this.handshakeFinished);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "handshakeStatus: " + hs);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "status: " + status);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "===========================================================");
        }

        if (needInit) {
            EngineHelper.initHandshake();
            needInit = false;
            closed = false;
        }

        sz = in.remaining();
        pos = in.position();
        if (sz > 0) {
            /* add new encrypted input to read buffer for wolfSSL calls */
            tmp = new byte[sz];
            in.get(tmp);
            addToRead(tmp);
            consumed += sz;
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "added " + sz + " bytes to internal read buffer");
        }

        if (outBoundOpen == false) {
            if (ClosingConnection() == WolfSSL.SSL_SUCCESS) {
                status = SSLEngineResult.Status.CLOSED;
            }
        }
        else {
            if (this.handshakeFinished == false) {

                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "starting or continuing handshake");
                ret = DoHandshake();
            }
            else {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "receiving application data");
                ret = RecvAppData(in, out, ofst, length);
                if (ret > 0) {
                    produced += ret;

                    if (this.toReadSz > 0 &&
                        getTotalOutputSize(out, ofst, length) == 0) {
                        /* We have more data buffered to read, but no more
                         * output space left in ByteBuffer[], ask for more */
                        status = SSLEngineResult.Status.BUFFER_OVERFLOW;
                    }
                }
            }

            if (outBoundOpen == false) {
                status = SSLEngineResult.Status.CLOSED;
            }

            int err = ssl.getError(ret);
            if (ret < 0 &&
                (err != WolfSSL.SSL_ERROR_WANT_READ) &&
                (err != WolfSSL.SSL_ERROR_WANT_WRITE)) {
                throw new SSLException(
                    "wolfSSL error, ret:err = " + ret + " : " + err);
            }

            if (ret < 0 && err == WolfSSL.SSL_ERROR_WANT_READ &&
                this.toReadSz == 0 && (this.toSend == null ||
                (this.toSend != null && this.toSend.length == 0))) {
                /* Need more data */
                status = SSLEngineResult.Status.BUFFER_UNDERFLOW;
            }
        }

        SetHandshakeStatus(ret);

        if (extraDebugEnabled == true) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "==== [ exiting unwrap() ] ==================================");
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "setUseClientMode: " + EngineHelper.getUseClientMode());
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "in.remaining(): " + in.remaining());
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "in.position(): " + in.position());
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "in.limit(): " + in.position());
            for (i = 0; i < length; i++) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "out["+i+"].remaining(): " + out[i].remaining());
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "out["+i+"].position(): " + out[i].position());
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "out["+i+"].limit(): " + out[i].limit());
            }
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "ofst: " + ofst + ", length: " + length);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "toReadSz: " + this.toReadSz);
            if (this.toSend != null) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "toSend.length: " + this.toSend.length);
            } else {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "toSend.length: 0");
            }
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "handshakeFinished: " + this.handshakeFinished);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "closeNotifySent: " + this.closeNotifySent);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "closeNotifyReceived: " + this.closeNotifyReceived);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "inBoundOpen: " + this.outBoundOpen);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "outBoundOpen: " + this.outBoundOpen);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "handshakeStatus: " + hs);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "status: " + status);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "consumed: " + consumed);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "produced: " + produced);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "===========================================================");
        }

        return new SSLEngineResult(status, hs, consumed, produced);
    }

    /**
     * Sets handshake status after I/O operation of unwrap(), helper function.
     */
    private synchronized void SetHandshakeStatus(int ret) {

        int err = ssl.getError(ret);

        if (this.handshakeFinished == true) {
            /* close_notify sent by wolfSSL but not across transport yet */
            if (this.closeNotifySent == true &&
                this.toSend != null && this.toSend.length > 0) {
                hs = SSLEngineResult.HandshakeStatus.NEED_WRAP;
            }
            /* close_notify received, need to send one back */
            else if (this.closeNotifyReceived == true &&
                     this.closeNotifySent == false) {
                hs = SSLEngineResult.HandshakeStatus.NEED_WRAP;
            }
            /* close_notify sent, need to read peer's */
            else if (this.closeNotifySent == true &&
                     this.closeNotifyReceived == false) {
                hs = SSLEngineResult.HandshakeStatus.NEED_UNWRAP;
            }
            else {
                hs = SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;
            }
        }
        else {
            synchronized (ioLock) {
                if (ssl.handshakeDone() && this.toSend == null) {
                    this.handshakeFinished = true;
                    hs = SSLEngineResult.HandshakeStatus.FINISHED;

                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        "SSL/TLS handshake finished");
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        "SSL/TLS protocol: " +
                        EngineHelper.getSession().getProtocol());
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        "SSL/TLS cipher suite: " +
                        EngineHelper.getSession().getCipherSuite());
                }
                /* give priority of WRAP/UNWRAP to state of our internal
                 * I/O data buffers first, then wolfSSL err status */
                else if (this.toSend != null && this.toSend.length > 0) {
                    hs = SSLEngineResult.HandshakeStatus.NEED_WRAP;
                }
                else if (this.toReadSz > 0) {
                    hs = SSLEngineResult.HandshakeStatus.NEED_UNWRAP;
                }
                else if (err == WolfSSL.SSL_ERROR_WANT_READ) {
                    hs = SSLEngineResult.HandshakeStatus.NEED_UNWRAP;
                }
                else if (err == WolfSSL.SSL_ERROR_WANT_WRITE) {
                    hs = SSLEngineResult.HandshakeStatus.NEED_WRAP;
                }
                else {
                    hs = SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;
                }
            }
        }

        return;
    }

    @Override
    public Runnable getDelegatedTask() {
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getDelegatedTask()");
        /* no tasks left to run */
        return null;
    }

    @Override
    public synchronized void closeInbound() throws SSLException {
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered closeInbound");

        if (!inBoundOpen)
            return;

        if (inBoundOpen && !closed) {
            /* this checks that peer sent back shutdown message */
            throw new SSLException("Closing in bound before shutdown is done");
        }
        else
        {
            inBoundOpen = false;
        }
    }

    @Override
    public synchronized boolean isInboundDone() {
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered isInboundDone()");
        return !inBoundOpen;
    }

    @Override
    public synchronized void closeOutbound() {
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered closeOutbound, outBoundOpen = false");
        outBoundOpen = false;
    }

    @Override
    public synchronized boolean isOutboundDone() {
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered isOutboundDone()");
        return !outBoundOpen;
    }

    @Override
    public String[] getSupportedCipherSuites() {
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getSupportedCipherSuites()");
        return EngineHelper.getAllCiphers();
    }

    @Override
    public String[] getEnabledCipherSuites() {
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getEnabledCipherSuites()");
        return EngineHelper.getCiphers();
    }

    @Override
    public void setEnabledCipherSuites(String[] suites) {
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered setEnabledCipherSuites()");
        EngineHelper.setCiphers(suites);
    }

    @Override
    public String[] getSupportedProtocols() {
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getSupportedProtocols()");
        return EngineHelper.getAllProtocols();
    }

    @Override
    public String[] getEnabledProtocols() {
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getEnabledProtocols()");
        return EngineHelper.getProtocols();
    }

    @Override
    public synchronized void setEnabledProtocols(String[] protocols) {
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered setEnabledProtocols()");
        EngineHelper.setProtocols(protocols);
    }

    @Override
    public synchronized SSLSession getSession() {
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getSession()");
        return EngineHelper.getSession();
    }

    public synchronized SSLSession getHandshakeSession() {
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getHandshakeSession()");
        return EngineHelper.getSession();
    }

    @Override
    public synchronized void beginHandshake() throws SSLException {
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered beginHandshake()");

        if (needInit == true) {
            /* will throw SSLHandshakeException if session creation is
               not allowed */
            EngineHelper.initHandshake();
            needInit = false;
        }

        try {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "calling EngineHelper.doHandshake()");
            int ret = EngineHelper.doHandshake(1, 0);
            SetHandshakeStatus(ret);

        } catch (SocketTimeoutException e) {
            e.printStackTrace();
            throw new SSLException(e);
        }
    }

    @Override
    public synchronized SSLEngineResult.HandshakeStatus getHandshakeStatus() {
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getHandshakeStatus(): " + hs);
        return hs;
    }

    @Override
    public synchronized void setUseClientMode(boolean mode) {
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered setUseClientMode()");
        EngineHelper.setUseClientMode(mode);
        this.clientModeSet = true;
    }

    @Override
    public boolean getUseClientMode() {
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getUseClientMode()");
        return EngineHelper.getUseClientMode();
    }

    @Override
    public synchronized void setNeedClientAuth(boolean need) {
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered setNeedClientAuth()");
        EngineHelper.setNeedClientAuth(need);
    }

    @Override
    public boolean getNeedClientAuth() {
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getNeedClientAuth()");
        return EngineHelper.getNeedClientAuth();
    }

    @Override
    public synchronized void setWantClientAuth(boolean want) {
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered setWantClientAuth()");
        EngineHelper.setWantClientAuth(want);
    }

    @Override
    public boolean getWantClientAuth() {
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getWantClientAuth()");
        return EngineHelper.getWantClientAuth();
    }

    @Override
    public synchronized void setEnableSessionCreation(boolean flag) {
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered setEnableSessionCreation()");
        EngineHelper.setEnableSessionCreation(flag);
    }

    @Override
    public boolean getEnableSessionCreation() {
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getEnableSessionCreation()");
        return EngineHelper.getEnableSessionCreation();
    }

    public synchronized String getApplicationProtocol() {
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getApplicationProtocol()");
        return EngineHelper.getAlpnSelectedProtocolString();
    }

    /**
     * Set the SSLParameters for this SSLSocket.
     *
     * @param params SSLParameters to set for this SSLSocket object
     */
    public synchronized void setSSLParameters(SSLParameters params) {
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered setSSLParameters()");
        if (params != null) {
            WolfSSLParametersHelper.importParams(params, this.params);
        }
    }

    /**
     * Copies buffer to end of to send queue. Encrypted packet is ready to be
     * sent out.
     *
     * @param in byte array with encrypted data to be sent
     * @param sz size of data in input array to be sent
     *
     * @return number of bytes placed into send queue
     */
    protected synchronized int setOut(byte[] in, int sz) {
        int totalSz = sz, idx = 0;
        byte[] tmp;

        if (this.toSend != null) {
            totalSz += this.toSend.length;
        }
        tmp = new byte[totalSz];
        if (this.toSend != null) {
            System.arraycopy(this.toSend, 0, tmp, idx, this.toSend.length);
            idx += this.toSend.length;
        }
        System.arraycopy(in, 0, tmp, idx, in.length);
        this.toSend = tmp;

        if (extraDebugEnabled == true) {
            printHex(in, sz, "CB Write");
        }

        return sz;
    }


    /**
     * Reads from buffer toRead
     *
     * @param toRead byte array to read data from
     * @param sz size of toRead array, bytes
     *
     * @return number of bytes read into toRead array or negative
     *         value on error
     */
    protected synchronized int setIn(byte[] toRead, int sz) {
        int max = (sz < toReadSz)? sz : toReadSz;

        if (this.toRead == null || this.toReadSz == 0) {
            /* nothing to be read */
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "No buffer to read returning want read");
            return WolfSSL.WOLFSSL_CBIO_ERR_WANT_READ;
        }
        System.arraycopy(this.toRead, 0, toRead, 0, max);

        if (max < this.toReadSz) {
            int left = this.toReadSz - max;
            System.arraycopy(this.toRead, max, this.toRead, 0, left);
            this.toReadSz = left;
        }
        else {
            /* read all from buffer */
            this.toRead = null;
            this.toReadSz = 0;
        }

        if (extraDebugEnabled == true) {
            printHex(toRead, max, "CB Read");
        }

        return max;
    }

    /* adds buffer to the internal buffer to be unwrapped */
    private synchronized void addToRead(byte[] in) {
        byte[] combined;

        combined = new byte[in.length + toReadSz];
        if (toRead != null && toReadSz > 0) {
            System.arraycopy(toRead, 0, combined, 0, toReadSz);
        }
        System.arraycopy(in, 0, combined, toReadSz, in.length);
        toRead = combined;
        toReadSz += in.length;
    }

    /**
     * Helper function, print byte[] as hex to stdout
     *
     * @param in input array to be printed as hex
     * @param sz number of bytes to print from input array
     * @param label label String to previx output with
     */
    protected void printHex(byte[] in, int sz, String label) {
        int i = 0, j = 0;

        System.out.print(label + " [" + sz + "]: ");
        for (i = 0; i < sz; i++) {
            if ((i % 8) == 0) {
                System.out.printf("\n%06X", j * 8);
                j++;
            }
            System.out.printf(" %02X ", in[i]);
        }
        System.out.println("");
    }

    /**
     * Removes the last 'sz' bytes from the internal read buffer.
     * Used to back out application data not yet ready for processing.
     */
    private synchronized void removeFromRead(int sz) {
        byte[] reduced;

        if (sz > toReadSz || toRead == null || sz == 0) {
            return;
        }

        reduced = new byte[toReadSz - sz];
        System.arraycopy(toRead, 0, reduced, 0, toReadSz - sz);
        toRead = reduced;
        toReadSz = toReadSz - sz;

        return;
    }

    private class SendCB implements WolfSSLIOSendCallback {

        protected SendCB() {

        }

        public int sendCallback(WolfSSLSession ssl, byte[] toSend, int sz,
                                Object engine) {
            return ((WolfSSLEngine)engine).setOut(toSend, sz);
        }

    }

    private class RecvCB implements WolfSSLIORecvCallback {

        protected RecvCB() {

        }

        public int receiveCallback(WolfSSLSession ssl, byte[] out, int sz,
                                   Object engine) {
            return ((WolfSSLEngine)engine).setIn(out, sz);
        }

    }
}
