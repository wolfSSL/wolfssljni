/* WolfSSLEngineHelper.java
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
import com.wolfssl.WolfSSLSession;
import java.io.IOException;

/**
 * This is a helper function to account for similar methods between SSLSocket
 * and SSLEngine.
 * 
 * This class wraps a new WOLFSSL object that is created. All methods are
 * protected or private because this class should only be used internally.
 * 
 * @author wolfSSL
 */
public class WolfSSLEngineHelper {
    private final WolfSSLSession ssl;
    private final com.wolfssl.WolfSSLContext ctx;
    private WolfSSLImplementSSLSession session = null;
    private final WolfSSLParameters params;
    
    /* enabled cipher suites / protocols , all if null */
    private String[] cipherSuites = null;
    private String[] protocols = null;
    
    private boolean clientMode;
    private boolean clientAuth = false;
    private boolean clientWantAuth = false;
    private boolean sessionCreation;
    
    protected WolfSSLEngineHelper(com.wolfssl.WolfSSLContext ctx,
            WolfSSLSession ssl, WolfSSLParameters params) {
        this.ctx = ctx;
        this.ssl = ssl;
        this.params = params;
        this.session = new WolfSSLImplementSSLSession(ssl, params);
    }
    
    protected WolfSSLEngineHelper(com.wolfssl.WolfSSLContext ctx,
            WolfSSLSession ssl, WolfSSLParameters params, int port, String host) {
        this.ctx = ctx;
        this.ssl = ssl;
        this.params = params;
        this.session = new WolfSSLImplementSSLSession(ssl, port, host, params);
    }
    
    protected WolfSSLSession getWolfSSLSession() {
        return ssl;
    }

    protected WolfSSLImplementSSLSession getSession() {
        return session;
    }
    
    /* gets all supported cipher suites */
    protected String[] getAllCiphers() {
        return WolfSSL.getCiphers();
    }
    
    /* gets all enabled cipher suites */
    protected String[] getCiphers() {
        if (this.cipherSuites == null) {
            return getAllCiphers();
        }
        return this.cipherSuites;
    }
    
    protected void setCiphers(String[] suites) throws IllegalArgumentException {
        try {
            String list;
            StringBuilder sb = new StringBuilder();

            for (String s : suites) {
                sb.append(s);
                sb.append(":");
            }

            /* remove last : */
            sb.deleteCharAt(sb.length());
            list = sb.toString();

            ssl.setCipherList(list);

        } catch (IllegalStateException e) {
            throw new IllegalArgumentException(e);
        }
        this.cipherSuites = suites;
    }
    
    protected void setProtocols(String[] p) {
        //SSL_set_options i.e. SSL_OP_NO_TLSv1_3
        this.protocols = p;
    }
    
    /* gets enabled protocols */
    protected String[] getProtocols() {
        if (this.protocols == null) {
            return getAllProtocols();
        }
        return this.protocols;
    }
    
    /* gets all supported protocols */
    protected String[] getAllProtocols() {
        return null;
    }
    
    
    protected void setUseClientMode(boolean mode) {
        this.clientMode = mode;
        //if true than should be a client, otherwise a server
    }
    
    protected boolean getUseClientMode() {
        return this.clientMode;
    }
    
    protected void setNeedClientAuth(boolean need) {
        this.clientAuth = need;
    }
    
    protected boolean getNeedClientAuth() {
        return this.clientAuth;
    }
    
    protected void setWantClientAuth(boolean want) {
        this.clientWantAuth = want;
    }
    
    protected boolean getWantClientAuth() {
        return this.clientWantAuth;
    }
    
    protected void setEnableSessionCreation(boolean flag) {
        this.sessionCreation = flag;
    }
    
    protected boolean getEnableSessionCreation() {
        return this.sessionCreation;
    }
    
    /* start or continue handshake, return WolfSSL.SSL_SUCCESS or
     * WolfSSL.SSL_FAILURE */
    protected int doHandshake() {
        if (this.sessionCreation == false) {
            //new handshakes can not be made in this case. Need a check though
            //to allow resumption @TODO
            return WolfSSL.SSL_FAILURE;
        }
        if (this.ssl.getSide() == WolfSSL.WOLFSSL_SERVER_END) {
            return this.ssl.accept();
        }
        else {
            return this.ssl.connect();
        }
    }
}
