/* WolfSSLEngine.java
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
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;

/**
 * wolfSSL implementation of SSLEngine
 *
 * @author wolfSSL
 */
public class WolfSSLEngine extends SSLEngine {

    private WolfSSLEngineHelper EngineHelper;
    private WolfSSLSession ssl;
    private com.wolfssl.WolfSSLContext ctx;
    private WolfSSLAuthStore authStore;
    private SSLParameters params;
    private byte[] toSend; /* encrypted packet to send */
    private byte[] toRead; /* encrypted packet coming in */
    private int toReadSz = 0;
    private HandshakeStatus hs = SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;
    private boolean needInit = true;

    private boolean inBoundOpen = true;
    private boolean outBoundOpen = true;

    /* closed completely (post shutdown or before handshake) */
    private boolean closed = true;

    static private SendCB sendCb = null;
    static private RecvCB recvCb = null;

    /**
     *  Create a new engine with no hints for session reuse
     *
     * @param ctx JNI level WolfSSLContext
     * @param auth WolfSSLAuthStore to use
     * @param params connection parameters to be used
     * @throws WolfSSLException if there is an issue creating the engine
     */
    protected WolfSSLEngine(com.wolfssl.WolfSSLContext ctx,
            WolfSSLAuthStore auth, SSLParameters params)
            throws WolfSSLException {
        super();
        this.ctx = ctx;
        this.authStore = auth;
        this.params = WolfSSLEngineHelper.decoupleParams(params);
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
            WolfSSLAuthStore auth, SSLParameters params, String host,
            int port) throws WolfSSLException {
        super();
        this.ctx = ctx;
        this.authStore = auth;
        this.params = WolfSSLEngineHelper.decoupleParams(params);
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
    }

    /**
     * returns 0 if no data was waiting and size of copied on success
     * negative values are returned in error cases
     */
    private int CopyOutPacket(ByteBuffer out, Status status) {
        int max = 0;

        if (this.toSend != null) {
            max = out.remaining();

            if (this.toSend.length > max) {
                /* output not large enough to read packet */
                status = Status.BUFFER_OVERFLOW;
                return -1;
            }
            else {
                /* read all from toSend */
                out.put(this.toSend);
                max = this.toSend.length;
                this.toSend = null;
            }
        }
        return max;
    }

    /**
     * Handles logic during shutdown
     */
    private int ClosingConnection() {
        int ret;

        if (this.getUseClientMode() == true) {
            EngineHelper.saveSession();
        }

        ret = ssl.shutdownSSL();
        if (ret == WolfSSL.SSL_SUCCESS) {
            /* if shutdown is successfull then is closed */
            closed = true;
            hs = SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;
        }
        else if (ret == WolfSSL.SSL_SHUTDOWN_NOT_DONE) {
            hs = SSLEngineResult.HandshakeStatus.NEED_UNWRAP;
        }
        else {
            int err = ssl.getError(ret);
             switch (err) {
                case WolfSSL.SSL_ERROR_WANT_READ:
                    hs = SSLEngineResult.HandshakeStatus.NEED_UNWRAP;
                    break;
                case WolfSSL.SSL_ERROR_WANT_WRITE:
                    hs = SSLEngineResult.HandshakeStatus.NEED_WRAP;
                    break;
                default:
             }
        }
        return ret;
    }

    @Override
    public SSLEngineResult wrap(ByteBuffer in, ByteBuffer out)
            throws SSLException {
        return wrap(new ByteBuffer[] { in }, 0, 1, out);
    }


    @Override
    public synchronized SSLEngineResult wrap(ByteBuffer[] in, int ofst, int len,
            ByteBuffer out) throws SSLException {
        int i, max = 0, ret = 0, idx = 0, pro = 0;
        ByteBuffer tmp;
        byte[] msg;
        int pos[] = new int[len];

        if (needInit) {
            EngineHelper.initHandshake();
            needInit = false;
            closed = false; /* opened a connection */
        }

        /* for sslengineresults return */
        Status status = SSLEngineResult.Status.OK;
        if (ofst + len > in.length || out == null) {
            throw new SSLException("bad arguments");
        }

        /* check if left over data to be wrapped
         * (pro can be negative on error) */
        pro = CopyOutPacket(out, status);

        /* check if closing down connection */
        if (pro >=0 && !outBoundOpen) {
            status = SSLEngineResult.Status.CLOSED;
            ClosingConnection();
            pro += CopyOutPacket(out, status);
        }
        else if (pro == 0) {
                /* get buffer size */
                for (i = ofst; i < ofst + len; i++) {
                    max += in[i].remaining();
                }
                tmp = ByteBuffer.allocate(max);

                for (i = ofst; i < len; i++) {
                    pos[idx++] = in[i].position();
                    tmp.put(in[i]);
                }

                msg = new byte[max];
                tmp.rewind();
                tmp.get(msg);
                ret = this.ssl.write(msg, max);
                if (ret <= 0) {
                    int err = ssl.getError(ret);

                    switch (err) {
                        case WolfSSL.SSL_ERROR_WANT_READ:
                            hs = SSLEngineResult.HandshakeStatus.NEED_UNWRAP;
                            break;
                        case WolfSSL.SSL_ERROR_WANT_WRITE:
                            hs = SSLEngineResult.HandshakeStatus.NEED_WRAP;
                            break;
                        default:
                            throw new SSLException("wolfSSL error case " + ret);
                    }
                }

                /* if the handshake is not done then reset input
                 * buffer postions */
                if (!ssl.handshakeDone()) {
                    idx = 0;
                    for (i = ofst; i < ofst + len; i++) {
                        in[i].position(pos[idx++]);
                    }
                }
                else {
                    hs = SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;
                }

                pro = CopyOutPacket(out, status);
        }

        /* consumed no bytes */
        if (ret < 0) {
            ret = 0;
        }
        return new SSLEngineResult(status, hs, ret, pro);
    }

    @Override
    public SSLEngineResult unwrap(ByteBuffer in, ByteBuffer out)
            throws SSLException {
        return unwrap(in, new ByteBuffer[] { out }, 0, 1);
    }

    @Override
    public synchronized SSLEngineResult unwrap(ByteBuffer in, ByteBuffer[] out,
            int ofst, int length) throws SSLException {
        int i, ret = 0, sz = 0, idx = 0, max = 0, pos, cns = 0, pro = 0;
        byte[] tmp;
        Status status;

        if (needInit) {
            EngineHelper.initHandshake();
            needInit = false;
            closed = false;
        }

        /* for sslengineresults return */
        status = SSLEngineResult.Status.OK;

        if (in == null || out == null || ofst + length > out.length) {
            throw new IllegalArgumentException();
        }

        for (i = 0; i < length; i++) {
            if (out[i + ofst] == null || out[i + ofst].isReadOnly()) {
                throw new IllegalArgumentException(
                        "null or readonly out buffer found");
            }
            max += out[i + ofst].remaining();
        }

        sz = cns = in.remaining();
        pos = in.position();
        if (sz > 0) {
            /* add new encrypted input to the read buffer for
             * wolfSSL_read call */
            tmp = new byte[sz];
            in.get(tmp);
            addToRead(tmp);
        }

        tmp = new byte[max];
        if (!outBoundOpen) {
            if (ClosingConnection() == WolfSSL.SSL_SUCCESS) {
                status = SSLEngineResult.Status.CLOSED;
            }
        }
        else {
            ret = this.ssl.read(tmp, max);
            if (ret <= 0) {
                int err = ssl.getError(ret);

                switch (err) {
                    case WolfSSL.SSL_ERROR_WANT_READ:
                        if (cns > 0) {
                            hs = SSLEngineResult.HandshakeStatus.NEED_WRAP;
                        }
                        break;
                    case WolfSSL.SSL_ERROR_WANT_WRITE:
                        break;

                    case WolfSSL.SSL_ERROR_ZERO_RETURN:
                        /* check if is shutdown message */
                        if (ssl.getShutdown() == WolfSSL.SSL_RECEIVED_SHUTDOWN) {
                            this.outBoundOpen = false;
                            ClosingConnection();
                            status = SSLEngineResult.Status.CLOSED;
                            if (toSend != null && toSend.length > 0) {
                                hs = SSLEngineResult.HandshakeStatus.NEED_WRAP;
                            }
                        }
                        break;

                    default:
                        throw new SSLException("wolfSSL error case " + err);
                }
            }
        }

        for (i = 0; i < ret;) {
            if (idx >= length) { /* no more output buffers left */
                break;
            }
            sz = out[idx + ofst].remaining();
            sz = (sz > ret)? ret : sz;
            out[idx + ofst].put(tmp, i, sz);
            i   += sz;
            pro += sz;
            idx++;
        }

        if (ssl.handshakeDone()) {
            hs = SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;
        }
        return new SSLEngineResult(status, hs, cns, pro);
    }

    @Override
    public Runnable getDelegatedTask() {

        /* no tasks left to run */
        return null;
    }

    @Override
    public void closeInbound() throws SSLException {
        if (!inBoundOpen)
            return;

        if (inBoundOpen && !closed) {
            /* this checks that peer sent back shutdown message */
            throw new SSLException("Closing in bound before shutdonw is done");
        }
        else
        {
            inBoundOpen = false;
        }
    }

    @Override
    public boolean isInboundDone() {
        return !inBoundOpen;
    }

    @Override
    public void closeOutbound() {
        outBoundOpen = false;
    }

    @Override
    public boolean isOutboundDone() {
        return !outBoundOpen;
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return EngineHelper.getAllCiphers();
    }

    @Override
    public String[] getEnabledCipherSuites() {
        return EngineHelper.getCiphers();
    }

    @Override
    public void setEnabledCipherSuites(String[] suites) {
        EngineHelper.setCiphers(suites);
    }

    @Override
    public String[] getSupportedProtocols() {
        return EngineHelper.getAllProtocols();
    }

    @Override
    public String[] getEnabledProtocols() {
        return EngineHelper.getProtocols();
    }

    @Override
    public void setEnabledProtocols(String[] protocols) {
        EngineHelper.setProtocols(protocols);
    }

    @Override
    public SSLSession getSession() {
        return EngineHelper.getSession();
    }

    @Override
    public void beginHandshake() throws SSLException {
        EngineHelper.initHandshake();
        EngineHelper.doHandshake();
    }

    @Override
    public SSLEngineResult.HandshakeStatus getHandshakeStatus() {
        return hs;
    }

    @Override
    public void setUseClientMode(boolean mode) {
        EngineHelper.setUseClientMode(mode);
    }

    @Override
    public boolean getUseClientMode() {
        return EngineHelper.getUseClientMode();
    }

    @Override
    public void setNeedClientAuth(boolean need) {
        EngineHelper.setNeedClientAuth(need);
    }

    @Override
    public boolean getNeedClientAuth() {
        return EngineHelper.getNeedClientAuth();
    }

    @Override
    public void setWantClientAuth(boolean want) {
        EngineHelper.setWantClientAuth(want);
    }

    @Override
    public boolean getWantClientAuth() {
        return EngineHelper.getWantClientAuth();
    }

    @Override
    public void setEnableSessionCreation(boolean flag) {
        EngineHelper.setEnableSessionCreation(flag);
    }

    @Override
    public boolean getEnableSessionCreation() {
        return EngineHelper.getEnableSessionCreation();
    }

    /* encrypted packet ready to be sent out. Copies buffer to end of to send
     * queue */
    protected int setOut(byte[] in, int sz) {
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
        return sz;
    }


    /* reads from buffer toRead */
    protected int setIn(byte[] toRead, int sz) {
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

        if (WolfSSLDebug.DEBUG) {
            System.out.println("CB Read ["+max+"] :");
            for (int i = 0; i < max; i++) {
                System.out.printf("%02X", toRead[i]);
            }
            System.out.println("");
        }

        return max;
    }

    /* adds buffer to the internal buffer to be unwrapped */
    private void addToRead(byte[] in) {
        byte[] combined;

        combined = new byte[in.length + toReadSz];
        if (toRead != null && toReadSz > 0) {
            System.arraycopy(toRead, 0, combined, 0, toReadSz);
        }
        System.arraycopy(in, 0, combined, toReadSz, in.length);
        toRead = combined;
        toReadSz += in.length;
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
