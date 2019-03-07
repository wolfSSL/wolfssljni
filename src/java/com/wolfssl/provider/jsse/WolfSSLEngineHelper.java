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
        
    protected WolfSSLEngineHelper(com.wolfssl.WolfSSLContext ctx,
            WolfSSLSession ssl, WolfSSLParameters params) {
        this.ctx = ctx;
        this.ssl = ssl;
        this.params = params;
    }
    
    protected WolfSSLSession getWolfSSLSession() {
        return ssl;
    }
    
    protected WolfSSLImplementSSLSession getSession(int port, String host) {
        if (session == null) {
            session = new WolfSSLImplementSSLSession(ssl, port, host, params);
        }
        return session;
    }
    
    protected WolfSSLImplementSSLSession getSession() {
        if (session == null) {
            session = new WolfSSLImplementSSLSession(ssl, params);
        }
        return session;
    }
    
    /* gets all supported cipher suites */
    protected String[] getAllCiphers() {
        return null;
    }
    
    /* gets all enabled cipher suites */
    protected String[] getCiphers() {
        return null;
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
    }
    
    protected void setProtocols(String[] p) {
        
    }
    
    /* gets enabled protocols */
    protected String[] getProtocols() {
        return null;
    }
    
    /* gets all supported protocols */
    protected String[] getAllProtocols() {
        return null;
    }
    
    
    protected void setUseClientMode(boolean mode) {
        
    }
    
    protected boolean getUseClientMode() {
        return false;
    }
    
    protected void setNeedClientAuth(boolean need) {
        
    }
    
    protected boolean getNeedClientAuth() {
        return false;
    }
    
    protected void setWantClientAuth(boolean want) {
        
    }
    
    protected boolean getWantClientAuth() {
        return false;
    }
    
    protected void setEnableSessionCreation(boolean flag) {
        
    }
    
    protected boolean getEnableSessionCreation() {
        return false;
    }
    
    /* start or continue handshake */
    protected int doHandshaed() {
        return 0;
    }
}
