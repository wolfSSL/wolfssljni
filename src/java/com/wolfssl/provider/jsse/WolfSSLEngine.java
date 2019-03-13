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

import com.wolfssl.WolfSSLException;
import com.wolfssl.WolfSSLIORecvCallback;
import com.wolfssl.WolfSSLIOSendCallback;
import com.wolfssl.WolfSSLJNIException;
import com.wolfssl.WolfSSLSession;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;

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
    
    private int READ_SIZE = 2048; /* how much to read at once */

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
        ctx.setIORecv(recvCb);
        ctx.setIOSend(sendCb);
    }
    
    private void initSSL() throws WolfSSLException, WolfSSLJNIException {
        setCallbacks();
        ssl = new WolfSSLSession(ctx);
        if (ssl == null) {
            throw new WolfSSLException("Issue creating WOLFSSL structure");
        }
        ssl.setIOReadCtx(ctx);
    }
        
    @Override
    public SSLEngineResult wrap(ByteBuffer[] in, int ofst, int len,
            ByteBuffer out) throws SSLException {
        int i, max = 0, ret;
        ByteBuffer tmp;
        byte[] msg;
        
        if (ofst < len || len > (in.length - ofst) || out == null) {
            throw new SSLException("bad arguments");
        }
        
        /* get buffer size */
        for (i = ofst; i < len; i++) {
            max += in[i].remaining();
        }
        tmp = ByteBuffer.allocate(max);

        for (i = ofst; i < len; i++) {
            tmp.put(in[i]);
        }
        msg = new byte[max];
        tmp.get(msg);
        ret = this.ssl.write(msg, max);
        if (ret <= 0) {
            //@TODO handle error
            System.out.println("need to handle error case");
            return null;
        }
        out.put(this.toSend);
 
        return new SSLEngineResult(SSLEngineResult.Status.OK,
                SSLEngineResult.HandshakeStatus.FINISHED, ret, this.toSend.length);
    }

    @Override
    public SSLEngineResult unwrap(ByteBuffer in, ByteBuffer[] out, int ofst,
            int length) throws SSLException {
        int i, ret, sz, idx = 0, max = 0;
        byte[] tmp;
        
        if (in == null || out == null || ofst + length > out.length) {
            throw new IllegalArgumentException();
        }
        
        for (i = 0; i < length; i++) {
            if (out[i + ofst] == null || out[i + ofst].isReadOnly()) {
                throw new IllegalArgumentException("null or readonly out buffer found");
            }
            max += out[i + ofst].remaining();
        }
        
        sz = in.remaining();
        if (sz > 0) {
            /* add new encrypted input to the read buffer for wolfSSL_read call */
            tmp = new byte[sz];
            in.get(tmp);
            addToRead(tmp);
        }
        
        tmp = new byte[max];
        ret = this.ssl.read(tmp, max);
        if (ret <= 0) {
            //@TODO handle error
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
        
        return new SSLEngineResult(SSLEngineResult.Status.OK,
                SSLEngineResult.HandshakeStatus.FINISHED, ret, this.toSend.length);
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
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
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
    protected int setOut(byte[] toSend, int sz) {
        int totalSz, idx = 0;
        byte[] tmp;
        
        totalSz = toSend.length;
        if (this.toSend != null) {
            totalSz += this.toSend.length;
        }
        tmp = new byte[totalSz];
        if (this.toSend != null) {
            System.arraycopy(this.toSend, 0, tmp, idx, this.toSend.length);
            idx += this.toSend.length;
        }
        System.arraycopy(toSend, 0, tmp, idx, toSend.length);
        return toSend.length;
    }
    
    
    /* reads from buffer toRead */
    protected int setIn(byte[] toRead, int sz) {
        int max = (sz < toReadSz)? sz : toReadSz;
        System.arraycopy(this.toRead, 0, toRead, 0, max);
        
        /* readjust plain text buffer after reading from it */
        if (max < this.toReadSz) {
            int left = this.toReadSz - max;
            System.arraycopy(this.toRead, max, this.toRead, max, left);
            this.toReadSz = left;
        }
        else {
            /* read all from buffer */
            this.toRead = null;
            this.toReadSz = 0;
        }
        return max;
    }
    
    /* adds buffer to the internal buffer to be unwrapped */
    private void addToRead(byte[] in) {
        byte[] combined;
        
        combined = new byte[in.length + toReadSz];
        System.arraycopy(toRead, 0, combined, 0, toReadSz);
        System.arraycopy(in, 0, combined, toReadSz, in.length);
        toRead = combined;
        toReadSz += in.length;
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
