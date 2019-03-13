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
import java.util.Arrays;
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

    private boolean clientMode;
    private boolean sessionCreation = true;
    
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
            SSLParameters params, int port, String host)
            throws WolfSSLException {
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
        return WolfSSL.getProtocols();
    }

    protected void setUseClientMode(boolean mode) {
        this.clientMode = mode;
        if (this.clientMode) {
            this.ssl.setConnectState();
        }
        else {
            this.ssl.setAcceptState();
        }
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

            this.ssl.setCipherList(list);

        } catch (IllegalStateException e) {
            throw new IllegalArgumentException(e);
        }
    }
   
    /* sets the protocol to use with WOLFSSL connections */
    private void setLocalProtocol(String[] p) {
        int i;
        long mask = 0;
        boolean set[] = new boolean[5];
        Arrays.fill(set, false);
        
        if (p == null) {
            /* if null then just use wolfSSL default */
            return;
        }
        
        for (i = 0; i < p.length; i++) {
            if (p[i].equals("TLSv1.3")) {
                set[0] = true;
            }
            if (p[i].equals("TLSv1.2")) {
                set[1] = true;
            }
            if (p[i].equals("TLSv1.1")) {
                set[2] = true;
            }
            if (p[i].equals("TLSv1")) {
                set[3] = true;
            }
            if (p[i].equals("SSLv3")) {
                set[4] = true;
            }
        }
        
        if (set[0] == false) {
            mask |= WolfSSL.SSL_OP_NO_TLSv1_3;
        }
        if (set[1] == false) {
            mask |= WolfSSL.SSL_OP_NO_TLSv1_2;
        }
        if (set[2] == false) {
            mask |= WolfSSL.SSL_OP_NO_TLSv1_1;
        }
        if (set[3] == false) {
            mask |= WolfSSL.SSL_OP_NO_TLSv1;
        }
        if (set[4] == false) {
            mask |= WolfSSL.SSL_OP_NO_SSLv3;
        }
        this.ssl.setOptions(mask);
    }
    
    /* sets client auth on or off if needed / wanted */
    private void setLocalAuth() {
        int mask = WolfSSL.SSL_VERIFY_NONE;

        /* default to client side authenticating the server connecting to */
        if (this.clientMode) {
            mask = WolfSSL.SSL_VERIFY_PEER;
        }

        if (this.params.getWantClientAuth()) {
            mask |= WolfSSL.SSL_VERIFY_PEER;
        }
        if (this.params.getNeedClientAuth()) {
            mask |= (WolfSSL.SSL_VERIFY_PEER |
                    WolfSSL.SSL_VERIFY_FAIL_IF_NO_PEER_CERT);
        }
        
        this.ssl.setVerify(mask, null);
    }
    
    private void setLocalParams() {
        this.setLocalCiphers(this.params.getCipherSuites());
        this.setLocalProtocol(this.params.getProtocols());
        this.setLocalAuth();
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
            /* new handshakes can not be made in this case. */
            return WolfSSL.SSL_HANDSHAKE_FAILURE;
        }

        if (this.clientMode) {
            return this.ssl.connect();
        } else {
            return this.ssl.accept();
        }
    }
    
    
    /**
     * Creates a new SSLPArameters class with the same settings as the one passed
     * in.
     * 
     * @param in SSLParameters settings to copy
     * @return new parameters object holding same settings as "in" 
     */
    protected static SSLParameters decoupleParams(SSLParameters in) {
        SSLParameters ret = new SSLParameters();
        
        ret.setAlgorithmConstraints(in.getAlgorithmConstraints());
        ret.setApplicationProtocols(in.getApplicationProtocols());
        ret.setCipherSuites(in.getCipherSuites());
        ret.setEnableRetransmissions(in.getEnableRetransmissions());
        ret.setEndpointIdentificationAlgorithm(in.getEndpointIdentificationAlgorithm());
        ret.setMaximumPacketSize(in.getMaximumPacketSize());
        ret.setNeedClientAuth(in.getNeedClientAuth());
        ret.setProtocols(in.getProtocols());
        ret.setSNIMatchers(in.getSNIMatchers());
        ret.setServerNames(in.getServerNames());
        ret.setUseCipherSuitesOrder(in.getUseCipherSuitesOrder());
        ret.setWantClientAuth(in.getWantClientAuth());
        return ret;
    }
}
