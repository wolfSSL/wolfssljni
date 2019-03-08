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
import javax.net.ssl.SSLParameters;

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
    private WolfSSLImplementSSLSession session = null;
    private SSLParameters params;
    
    /* enabled cipher suites / protocols , all if null */
    private String[] cipherSuites = null;
    private String[] protocols = null;
    
    private boolean clientMode;
    private boolean clientAuth = false;
    private boolean clientWantAuth = false;
    private boolean sessionCreation;
    
    protected WolfSSLEngineHelper(WolfSSLSession ssl, WolfSSLAuthStore store,
            SSLParameters params) throws WolfSSLException {
        if (params == null || ssl == null || store == null) {
            throw new WolfSSLException("Bad argument");
        }
        
        this.ssl = ssl;
        this.params = params;
        this.session = new WolfSSLImplementSSLSession(ssl, store);
    }
    
    protected WolfSSLEngineHelper(WolfSSLSession ssl, WolfSSLAuthStore store,
            SSLParameters params, int port, String host) throws WolfSSLException {
        if (params == null || ssl == null || store == null) {
            throw new WolfSSLException("Bad argument");
        }
        
        this.ssl = ssl;
        this.params = params;
        this.session = new WolfSSLImplementSSLSession(ssl, port, host, store);
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
    
    /* gets all enabled cipher suites
     * @TODO is this supposed to return null if no ciphers was set? */
    protected String[] getCiphers() {
        String[] ret = this.params.getCipherSuites();
        if (ret == null) {
            return this.getAllCiphers();
        }
        return ret;
    }
    
    protected void setCiphers(String[] suites) throws IllegalArgumentException {
        this.params.setCipherSuites(suites);
    }
    
    protected void setProtocols(String[] p) {
        this.params.setProtocols(p);
    }
    
    /* gets enabled protocols */
    protected String[] getProtocols() {
        return this.params.getProtocols();
    }
    
    /* gets all supported protocols */
    protected String[] getAllProtocols() {
        return null; // @TODO
    }
    
    
    protected void setUseClientMode(boolean mode) {
        this.clientMode = mode;
    }
    
    protected boolean getUseClientMode() {
        return this.clientMode;
    }
    
    protected void setNeedClientAuth(boolean need) {
        this.params.setNeedClientAuth(need);
    }
    
    protected boolean getNeedClientAuth() {
        return this.params.getNeedClientAuth();
    }
    
    protected void setWantClientAuth(boolean want) {
        this.params.setWantClientAuth(want);
    }
    
    protected boolean getWantClientAuth() {
        return this.params.getWantClientAuth();
    }
    
    protected void setEnableSessionCreation(boolean flag) {
        this.sessionCreation = flag;
    }
    
    protected boolean getEnableSessionCreation() {
        return this.sessionCreation;
    }
    
    /*********** Calls to transfer over parameter to wolfSSL before connection */
    /*transfer over cipher suites right before establishing a connection */
    private void setLocalCiphers(String[] suites) throws IllegalArgumentException {
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
    
    private void setLocalProtocol(String[] p) {
     
            //SSL_set_options i.e. SSL_OP_NO_TLSv1_3   
    }
    
    private void setLocalParams() {
        this.setLocalCiphers(this.params.getCipherSuites());
        this.setLocalProtocol(this.params.getProtocols());
        
    }
    
    /* sets all parameters from SSLParameters into WOLFSSL object.
     * Should be called before doHandshake */
    protected void initHandshake() {
        this.setLocalParams();
    }
    
    /* start or continue handshake, return WolfSSL.SSL_SUCCESS or
     * WolfSSL.SSL_FAILURE */
    protected int doHandshake() {
        if (this.sessionCreation == false) {
            //new handshakes can not be made in this case.
            return WolfSSL.SSL_HANDSHAKE_FAILURE;
        }
        if (this.ssl.getSide() == WolfSSL.WOLFSSL_SERVER_END) {
            return this.ssl.accept();
        }
        else {
            return this.ssl.connect();
        }
    }
}
