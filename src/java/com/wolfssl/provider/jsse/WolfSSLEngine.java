/* WolfSSLEngine.java
 *
 * Copyright (C) 2006-2018 wolfSSL Inc.
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
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLEngineResult.Status;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import java.util.logging.Level;
import java.util.logging.Logger;

public class WolfSSLEngine extends SSLEngine {

    private String host = null;
    private int port = 0;
    private WolfSSLEngineHelper EngineHelper;
    private WolfSSLSession ssl;
    private com.wolfssl.WolfSSLContext ctx;
    private WolfSSLAuthStore authStore;
    private SSLParameters params;
    private byte[] toSend; /* encrypted packet to send */
    private byte[] toRead; /* encrypted packet comming in */
    private int toReadSz = 0;
    private HandshakeStatus hs = SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;
    private boolean waiting = false;

    static private SendCB sendCb = null;
    static private RecvCB recvCb = null;
    
    /* has no hints for session reuse */
    protected WolfSSLEngine(com.wolfssl.WolfSSLContext ctx, WolfSSLAuthStore auth,
            SSLParameters params)
            throws WolfSSLException {
        super();
        this.ctx = ctx;
        this.authStore = auth;
        this.params = WolfSSLEngineHelper.decoupleParams(params);
        try {
            initSSL();
        } catch (WolfSSLJNIException ex) {
            Logger.getLogger(WolfSSLEngine.class.getName()).log(Level.SEVERE, null, ex);
            throw new WolfSSLException("Error with init");
        }
        EngineHelper = new WolfSSLEngineHelper(this.ssl, this.authStore,
                this.params);
    }
    
    /* host and port values for possible session reuse */
    protected WolfSSLEngine(com.wolfssl.WolfSSLContext ctx, WolfSSLAuthStore auth,
            SSLParameters params, String host, int port) throws WolfSSLException {
        super();
        this.ctx = ctx;
        this.authStore = auth;
        this.params = WolfSSLEngineHelper.decoupleParams(params);
        this.host = host;
        this.port = port;
        try {
            initSSL();
        } catch (WolfSSLJNIException ex) {
            Logger.getLogger(WolfSSLEngine.class.getName()).log(Level.SEVERE, null, ex);
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
        //System.out.println("setting io callbacks for SSL Engine");
        ssl.setIORecv(recvCb);
        //System.out.println("set recv callback");
        ssl.setIOSend(sendCb);
        //System.out.println("set send callback");
    }
    
    private void initSSL() throws WolfSSLException, WolfSSLJNIException {
        /* @TODO for testing still cettins ctx cbio */
        if (sendCb == null) {
            sendCb = new SendCB();
        }
        if (recvCb == null) {
            recvCb = new RecvCB();
        }
//        ctx.setIORecv(recvCb);
//        ctx.setIOSend(sendCb);
        
        ssl = new WolfSSLSession(ctx);
        if (ssl == null) {
            throw new WolfSSLException("Issue creating WOLFSSL structure");
        }
        setCallbacks();
        ssl.setIOReadCtx(this);
        ssl.setIOWriteCtx(this);
    }

    @Override
    public SSLEngineResult wrap(ByteBuffer in, ByteBuffer out)
            throws SSLException {
        return wrap(new ByteBuffer[] { in }, 0, 1, out);
    }
    
    
    @Override
    public SSLEngineResult wrap(ByteBuffer[] in, int ofst, int len,
            ByteBuffer out) throws SSLException {
        int i, max = 0, ret, idx = 0, pro = 0;
        ByteBuffer tmp;
        byte[] msg;
        int pos[] = new int[len];
        
        /* for sslengineresults return */
        Status status = SSLEngineResult.Status.OK;
        if (ofst + len > in.length || out == null) {
            throw new SSLException("bad arguments");
        }
        
        /* get buffer size */
        for (i = ofst; i < ofst + len; i++) {
            max += in[i].remaining();
        }
        //System.out.println("buffer max = " + max);
        tmp = ByteBuffer.allocate(max);

        for (i = ofst; i < len; i++) {
            pos[idx++] = in[i].position();
            tmp.put(in[i]);
        }
        //System.out.println("getting byte version of input");
        msg = new byte[max];
        tmp.rewind();
        tmp.get(msg);
        //System.out.println("calling wolfssl write");
        ret = this.ssl.write(msg, max);
        if (ret <= 0) {
            //@TODO handle error
            int err = ssl.getError(ret);
            //System.out.println("need to handle error case err = " + err);
            
            switch (err) {
                case WolfSSL.SSL_ERROR_WANT_READ:
                    hs = SSLEngineResult.HandshakeStatus.NEED_UNWRAP;
                    waiting = true;
                    break;
                case WolfSSL.SSL_ERROR_WANT_WRITE:
                    hs = SSLEngineResult.HandshakeStatus.NEED_WRAP;
                    waiting = false;
                    break;
                default:
                    throw new SSLException("wolfSSL error case " + ret);
            }
        }
        
        /* if the handshake is not done then reset input buffer postions */
        if (!ssl.handshakeDone()) {
            idx = 0;
            //System.out.println("trying to reset positions");
            for (i = ofst; i < ofst + len; i++) {
                in[i].position(pos[idx++]);
            }
        }

        if (this.toSend != null) {
            //System.out.println("returning packet of size %d\n" + this.toSend.length);
            max = out.remaining();
            if (this.toSend.length > max) {
                /* partial read from toSend */
                int nSz = this.toSend.length - max;
                System.arraycopy(this.toSend, 0, msg, 0, max);
                out.put(msg);
                pro = max;
                System.arraycopy(this.toSend, max, this.toSend, 0, nSz);
                this.toSend = Arrays.copyOf(this.toSend, nSz);
            }
            else {
                /* read all from toSend */
                out.put(this.toSend);
                pro = this.toSend.length;
                this.toSend = null;
            }
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
    public SSLEngineResult unwrap(ByteBuffer in, ByteBuffer[] out, int ofst,
            int length) throws SSLException {
        int i, ret, sz, idx = 0, max = 0, pos, cns = 0;
        byte[] tmp;
        
        /* for sslengineresults return */
        Status status = SSLEngineResult.Status.OK;
        
        if (in == null || out == null || ofst + length > out.length) {
            throw new IllegalArgumentException();
        }
        
        for (i = 0; i < length; i++) {
            if (out[i + ofst] == null || out[i + ofst].isReadOnly()) {
                throw new IllegalArgumentException("null or readonly out buffer found");
            }
            max += out[i + ofst].remaining();
        }
        
        sz = cns = in.remaining();
        pos = in.position();
        if (sz > 0) {
            /* add new encrypted input to the read buffer for wolfSSL_read call */
            tmp = new byte[sz];
            in.get(tmp);
            addToRead(tmp);
        }
        
        tmp = new byte[max];
        //System.out.println("calling ssl read");
        ret = this.ssl.read(tmp, max);
        if (ret <= 0) {
            int err = ssl.getError(ret);
// 
//            if (ssl.handshakeDone()) {
//                in.position(pos); /* no data was consumed from buffer */
//                cns = 0;
//                System.out.println("reset positiong to " + pos + "remaning now is " + in.remaining());
//            }
            
            switch (err) {
                case WolfSSL.SSL_ERROR_WANT_READ:
                    break;
                case WolfSSL.SSL_ERROR_WANT_WRITE:
                    break;
             
                default:
                    throw new SSLException("wolfSSL error case " + ret);
            }
        }
        
        if (waiting && this.toReadSz > 0) {
            hs = SSLEngineResult.HandshakeStatus.NEED_UNWRAP;  
        }
        else {
            hs = SSLEngineResult.HandshakeStatus.NEED_WRAP; 
        }

        for (i = 0; i < ret;) {
            if (idx >= length) { /* no more output buffers left */
                break;
            }
            sz = out[idx + ofst].remaining();
            sz = (sz > ret)? ret : sz;
            out[idx + ofst].put(tmp, i, sz);
            i += sz;
            idx++;
        }
        
        return new SSLEngineResult(status, hs, cns, i);
    }

    @Override
    public Runnable getDelegatedTask() {
        
        /* no tasks left to run */
        return null;
    }

    @Override
    public void closeInbound() throws SSLException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public boolean isInboundDone() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public void closeOutbound() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public boolean isOutboundDone() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
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
        if (ssl.handshakeDone()) {
            return SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;
        }
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
        
        //System.out.println("setout callback, adding " + sz + " bytes to toSend");
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
        //System.out.println("Added " + sz + " bytes toSend length now " + this.toSend.length);
        return sz;
    }
    
    
    /* reads from buffer toRead */
    protected int setIn(byte[] toRead, int sz) {
        int max = (sz < toReadSz)? sz : toReadSz;
        
        //System.out.println("setin callback");
        if (this.toRead == null || this.toReadSz == 0) {
            /* nothing to be read */
            //System.out.println("No buffer to read returning want read");
            return WolfSSL.WOLFSSL_CBIO_ERR_WANT_READ;
        }
        System.arraycopy(this.toRead, 0, toRead, 0, max);

        if (max < this.toReadSz) {
            int left = this.toReadSz - max;
            System.arraycopy(this.toRead, max, this.toRead, 0, left);
            this.toReadSz = left;
            //System.out.println("reading " + max + " from toRead : " + left + " bytes left");
        }
        else {
            /* read all from buffer */
            //System.out.println("read all " + max + " bytes from toRead ");
            this.toRead = null;
            this.toReadSz = 0;
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
    
    private void log(String msg) {
        WolfSSLDebug.print("[WolfSSLSocket] " + msg);
    }
 
    private class SendCB implements WolfSSLIOSendCallback {

        protected SendCB() {
            
        }
        
        public int sendCallback(WolfSSLSession ssl, byte[] toSend, int sz, Object engine) {
            return ((WolfSSLEngine)engine).setOut(toSend, sz);
        }
        
    }
    
    private class RecvCB implements WolfSSLIORecvCallback {

        protected RecvCB() {
            
        }
        
        public int receiveCallback(WolfSSLSession ssl, byte[] out, int sz, Object engine) {
            return ((WolfSSLEngine)engine).setIn(out, sz);
        }
        
    }
}
