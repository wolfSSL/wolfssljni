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
import com.wolfssl.WolfSSLSession;
import java.io.IOException;
import java.nio.ByteBuffer;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;

public class WolfSSLEngine extends SSLEngine {

    private String host = null;
    private int port = 0;
    private WolfSSLEngineHelper EngineHelper;
    private WolfSSLSession ssl;
    private com.wolfssl.WolfSSLContext ctx;
    private WolfSSLAuthStore params;

    public WolfSSLEngine() throws WolfSSLException {
        throw new WolfSSLException("bad constructor");
    }
    
    public WolfSSLEngine(String host, int port) throws WolfSSLException {
        throw new WolfSSLException("bad constructor");
    }
        
    public WolfSSLEngine(com.wolfssl.WolfSSLContext ctx,
            WolfSSLAuthStore params) throws WolfSSLException {
        super();
        this.ctx = ctx;
        this.params = params;
        initSSL();
        EngineHelper = new WolfSSLEngineHelper(this.ctx, this.ssl, this.params);
    }

    private void initSSL() throws WolfSSLException {
        ssl = new WolfSSLSession(ctx);
        // @TODO set io callbacks
    }
        
    @Override
    public SSLEngineResult wrap(ByteBuffer[] arg0, int arg1, int arg2, ByteBuffer arg3) throws SSLException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public SSLEngineResult unwrap(ByteBuffer arg0, ByteBuffer[] arg1, int arg2, int arg3) throws SSLException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public Runnable getDelegatedTask() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
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
    
}
