/* WolfSSLEngineHelper.java
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
import com.wolfssl.WolfSSLVerifyCallback;
import com.wolfssl.WolfSSLException;
import com.wolfssl.WolfSSLSession;
import com.wolfssl.WolfSSLCertificate;
import com.wolfssl.WolfSSLX509StoreCtx;
import java.util.Arrays;
import java.util.List;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.X509TrustManager;
import javax.net.ssl.SSLHandshakeException;
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
    private WolfSSLImplementSSLSession session = null;
    private SSLParameters params;
    private WolfSSLDebug debug;
    private int port;
    private String host = null;
    private WolfSSLAuthStore authStore = null;
    private boolean clientMode;
    private boolean sessionCreation = true;
    private boolean modeSet = false;

    /**
     * Always creates a new session
     * @param ssl WOLFSSL session
     * @param store main auth store holding session tables and managers
     * @param params default parameters to use on connection
     * @throws WolfSSLException if an exception happens during session creation
     */
    protected WolfSSLEngineHelper(WolfSSLSession ssl, WolfSSLAuthStore store,
            SSLParameters params) throws WolfSSLException {
        if (params == null || ssl == null || store == null) {
            throw new WolfSSLException("Bad argument");
        }

        this.ssl = ssl;
        this.params = params;
        this.authStore = store;
        this.session = new WolfSSLImplementSSLSession(store);
    }

    /**
     * Allows for new session and resume session by default
     * @param ssl WOLFSSL session
     * @param store main auth store holding session tables and managers
     * @param params default parameters to use on connection
     * @param port port number as hint for resume
     * @param host host as hint for resume
     * @throws WolfSSLException if an exception happens during session resume
     */
    protected WolfSSLEngineHelper(WolfSSLSession ssl, WolfSSLAuthStore store,
            SSLParameters params, int port, String host)
            throws WolfSSLException {
        if (params == null || ssl == null || store == null) {
            throw new WolfSSLException("Bad argument");
        }

        this.ssl = ssl;
        this.params = params;
        this.port = port;
        this.host = host;
        this.authStore = store;
        this.session = new WolfSSLImplementSSLSession(store);
    }

    /* used internally by SSLSocket.connect(SocketAddress) */
    protected void setHostAndPort(String host, int port) {
        this.host = host;
        this.port = port;
    }

    protected WolfSSLSession getWolfSSLSession() {
        return ssl;
    }

    protected WolfSSLImplementSSLSession getSession() {
        return session;
    }

    /* gets all supported cipher suites */
    protected String[] getAllCiphers() {
        return WolfSSL.getCiphersIana();
    }

    /* gets all enabled cipher suites */
    protected String[] getCiphers() {
        return this.params.getCipherSuites();
    }

    protected void setCiphers(String[] suites) throws IllegalArgumentException {

        if (suites == null) {
            throw new IllegalArgumentException("input array is null");
        }

        if (suites.length == 0) {
            throw new IllegalArgumentException("input array has length zero");
        }

        /* sanitize cipher array for unsupported strings */
        List<String> supported = Arrays.asList(getAllCiphers());
        for (int i = 0; i < suites.length; i++) {
            if (!supported.contains(suites[i])) {
                throw new IllegalArgumentException("Unsupported CipherSuite: " +
                    suites[i]);
            }
        }

        this.params.setCipherSuites(suites);
    }

    protected void setProtocols(String[] p) throws IllegalArgumentException {

        if (p == null) {
            throw new IllegalArgumentException("input array is null");
        }

        if (p.length == 0) {
            throw new IllegalArgumentException("input array has length zero");
        }

        /* sanitize protocol array for unsupported strings */
        List<String> supported = Arrays.asList(getAllProtocols());
        for (int i = 0; i < p.length; i++) {
            if (!supported.contains(p[i])) {
                throw new IllegalArgumentException("Unsupported protocol: " +
                    p[i]);
            }
        }

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

    protected void setUseClientMode(boolean mode)
        throws IllegalArgumentException {

        if (ssl.handshakeDone()) {
            throw new IllegalArgumentException("setUseClientMode() not " +
                "allowed after handshake is completed");
        }

        this.clientMode = mode;
        if (this.clientMode) {
            this.ssl.setConnectState();
        }
        else {
            this.ssl.setAcceptState();
        }
        this.modeSet = true;
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

    /********** Calls to transfer over parameter to wolfSSL before connection */

    /*transfer over cipher suites right before establishing a connection */
    private void setLocalCiphers(String[] suites)
            throws IllegalArgumentException {
        try {
            String list;
            StringBuilder sb = new StringBuilder();

            if (suites == null) {
                /* use default cipher suites */
                return;
            }

            for (String s : suites) {
                sb.append(s);
                sb.append(":");
            }

            /* remove last : */
            sb.deleteCharAt(sb.length() - 1);
            list = sb.toString();
            if (this.ssl.setCipherList(list) != WolfSSL.SSL_SUCCESS) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        "error setting cipher list " + list);
            }

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

        X509TrustManager tm = authStore.getX509TrustManager();
        if (tm instanceof com.wolfssl.provider.jsse.WolfSSLTrustX509) {
            /* use internal peer verification logic */
            this.ssl.setVerify(mask, null);

        } else {
            /* not our own TrustManager, set up callback so JSSE can use
             * TrustManager.checkClientTrusted/checkServerTrusted() */
            this.ssl.setVerify(WolfSSL.SSL_VERIFY_PEER,
                               new WolfSSLInternalVerifyCb());
        }
    }

    private void setLocalParams() {
        this.setLocalCiphers(this.params.getCipherSuites());
        this.setLocalProtocol(this.params.getProtocols());
        this.setLocalAuth();
    }

    /* sets all parameters from SSLParameters into WOLFSSL object and creates
     * session.
     * Should be called before doHandshake */
    protected void initHandshake() throws SSLException {
        if (!modeSet) {
            throw new SSLException("setUseClientMode has not been called");
        }

        /* create non null session */
        this.session = this.authStore.getSession(ssl, this.port, this.host,
            this.clientMode);

        if (this.session != null && this.sessionCreation == false &&
                !this.session.fromTable) {
            /* new handshakes can not be made in this case. */
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "session creation not allowed");

            /* send CloseNotify */
            /* TODO: SunJSSE sends a Handshake Failure alert instead here */
            this.ssl.shutdownSSL();

            throw new SSLHandshakeException("Session creation not allowed");
        }

        if (this.clientMode == true && this.sessionCreation) {
            /* can only add new sessions to the resumption table if session
             * creation is allowed */
            this.authStore.addSession(this.session);
        }

        this.setLocalParams();
    }

    /* start or continue handshake, return WolfSSL.SSL_SUCCESS or
     * WolfSSL.SSL_FAILURE */
    protected int doHandshake() throws SSLException {
        if (!modeSet) {
            throw new SSLException("setUseClientMode has not been called");
        }

        if (this.sessionCreation == false && !this.session.fromTable) {
            /* new handshakes can not be made in this case. */
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "session creation not allowed");

            /* send CloseNotify */
            /* TODO: SunJSSE sends a Handshake Failure alert instead here */
            this.ssl.shutdownSSL();

            return WolfSSL.SSL_HANDSHAKE_FAILURE;
        }

        if (!this.session.isValid()) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "session is marked as invalid, try creating a new seesion");
            if (this.sessionCreation == false) {
                /* new handshakes can not be made in this case. */
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "session creation not allowed");

                return WolfSSL.SSL_HANDSHAKE_FAILURE;
            }
            this.session = this.authStore.getSession(ssl);
        }

        if (this.clientMode) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "calling native wolfSSL_connect()");
            return this.ssl.connect();

        } else {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        "calling native wolfSSL_accept()");
            return this.ssl.accept();
        }
    }


    /**
     * Saves session on connection close for resumption
     */
    protected void saveSession() {
        if (this.session.isValid()) {
            this.session.setResume();
        }
    }

    /**
     * Creates a new SSLPArameters class with the same settings as the one
     * passed in.
     *
     * @param in SSLParameters settings to copy
     * @return new parameters object holding same settings as "in"
     */
    protected static SSLParameters decoupleParams(SSLParameters in) {
        SSLParameters ret = new SSLParameters();

        ret.setCipherSuites(in.getCipherSuites());
        ret.setProtocols(in.getProtocols());

        ret.setNeedClientAuth(in.getNeedClientAuth());
        if (!ret.getNeedClientAuth()) {
            ret.setWantClientAuth(in.getWantClientAuth());
        }

        /* Supported by newer version of SSLParameters but to build with API 23
         * these are currently commented out
        ret.setAlgorithmConstraints(in.getAlgorithmConstraints());
        ret.setApplicationProtocols(in.getApplicationProtocols());
        ret.setEnableRetransmissions(in.getEnableRetransmissions());
        ret.setEndpointIdentificationAlgorithm(
            in.getEndpointIdentificationAlgorithm());
        ret.setMaximumPacketSize(in.getMaximumPacketSize());
        ret.setSNIMatchers(in.getSNIMatchers());
        ret.setServerNames(in.getServerNames());
        ret.setUseCipherSuitesOrder(in.getUseCipherSuitesOrder());
        */

        return ret;
    }

    /* Internal verify callback. This is used when a user registers a
     * TrustManager which is NOT com.wolfssl.provider.jsse.WolfSSLTrustManager
     * and is used to call TrustManager checkClientTrusted() or
     * checkServerTrusted(). If wolfJSSE TrustManager is used, native wolfSSL
     * does certificate verification internally. */
    public class WolfSSLInternalVerifyCb implements WolfSSLVerifyCallback {
        public int verifyCallback(int preverify_ok, long x509StorePtr) {

            X509TrustManager tm = authStore.getX509TrustManager();
            WolfSSLCertificate[] certs = null;
            X509Certificate[] x509certs = null;
            String authType = null;

            if (preverify_ok == 1) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        "Native wolfSSL peer verification passed");
            } else {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        "WARNING: Native wolfSSL peer verification failed!");
            }

            try {
                /* get WolfSSLCertificate[] from x509StorePtr */
                WolfSSLX509StoreCtx store =
                    new WolfSSLX509StoreCtx(x509StorePtr);
                certs = store.getCerts();

            } catch (WolfSSLException e) {
                /* failed to get certs from native, give app null array */
                certs = null;
            }

            if (certs != null && certs.length > 0) {
                try {
                    /* Convert WolfSSLCertificate[] to X509Certificate[] */
                    x509certs = new X509Certificate[certs.length];
                    for (int i = 0; i < certs.length; i++) {
                        x509certs[i] = certs[i].getX509Certificate();
                    }
                } catch (CertificateException | IOException ce) {
                    /* failed to get cert array, give app null array */
                    x509certs = null;
                }

                /* get authType, use first cert */
                String sigType = certs[0].getSignatureType();
                if (sigType.contains("RSA")) {
                    authType = "RSA";
                } else if (sigType.contains("ECDSA")) {
                    authType = "ECDSA";
                } else if (sigType.contains("DSA")) {
                    authType = "DSA";
                } else if (sigType.contains("ED25519")) {
                    authType = "ED25519";
                }
            }


            try {
                /* poll TrustManager for cert verification, should throw
                 * CertificateException if verification fails */
                if (clientMode) {
                    tm.checkServerTrusted(x509certs, authType);
                } else {
                    tm.checkClientTrusted(x509certs, authType);
                }
            } catch (Exception e) {
                /* TrustManager rejected certificate, not valid */
                return 0;
            }

            /* continue handshake, verification succeeded */
            return 1;
        }
    }
}
