/* WolfSSLEngineHelper.java
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
import com.wolfssl.WolfSSLVerifyCallback;
import com.wolfssl.WolfSSLException;
import com.wolfssl.WolfSSLSession;
import java.util.Arrays;
import java.util.List;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;
import java.net.SocketTimeoutException;
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
    private WolfSSLParameters params;
    private WolfSSLDebug debug;
    private int port;
    private String hostname = null;  /* used for session lookup and SNI */
    private WolfSSLAuthStore authStore = null;
    private boolean clientMode;
    private boolean sessionCreation = true;
    private boolean modeSet = false;

    /* Internal Java verify callback, used when user/app is not using
     * com.wolfssl.provider.jsse.WolfSSLTrustX509 and instead using their
     * own TrustManager to perform verification via checkClientTrusted()
     * and/or checkServerTrusted().
     *
     * This object is stored at the native level as a global reference
     * created in Java_com_wolfssl_WolfSSLSession_setVerify()
     * of com_wolfssl_WolfSSLSession.c and deleted in native
     * Java_com_wolfssl_WolfSSLSession_freeSSL(). Deleting the native
     * global reference allows the Java object to be garbage collected. */
    private WolfSSLInternalVerifyCb wicb = null;

    /**
     * Always creates a new session
     * @param ssl WOLFSSL session
     * @param store main auth store holding session tables and managers
     * @param params default parameters to use on connection
     * @throws WolfSSLException if an exception happens during session creation
     */
    protected WolfSSLEngineHelper(WolfSSLSession ssl, WolfSSLAuthStore store,
            WolfSSLParameters params) throws WolfSSLException {
        if (params == null || ssl == null || store == null) {
            throw new WolfSSLException("Bad argument");
        }

        this.ssl = ssl;
        this.params = params;
        this.authStore = store;
        this.session = new WolfSSLImplementSSLSession(store);

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "created new WolfSSLEngineHelper()");
    }

    /**
     * Allows for new session and resume session by default
     * @param ssl WOLFSSL session
     * @param store main auth store holding session tables and managers
     * @param params default parameters to use on connection
     * @param port port number as hint for resume
     * @param hostname hostname as hint for resume and for default SNI
     * @throws WolfSSLException if an exception happens during session resume
     */
    protected WolfSSLEngineHelper(WolfSSLSession ssl, WolfSSLAuthStore store,
            WolfSSLParameters params, int port, String hostname)
            throws WolfSSLException {
        if (params == null || ssl == null || store == null) {
            throw new WolfSSLException("Bad argument");
        }

        this.ssl = ssl;
        this.params = params;
        this.port = port;
        this.hostname = hostname;
        this.authStore = store;
        this.session = new WolfSSLImplementSSLSession(store);
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "created new WolfSSLEngineHelper(port: " + port +
            ", hostname: " + hostname + ")");
    }

    /**
     * Set hostname and port
     * Used internally by SSLSocket.connect(SocketAddress)
     *
     * @param hostname peer hostname String
     * @param port peer port number
     */
    protected void setHostAndPort(String hostname, int port) {
        this.hostname = hostname;
        this.port = port;
    }

    /**
     * Get the com.wolfssl.WolfSSLSession for this object
     *
     * @return com.wolfssl.WolfSSLSession for this object
     */
    protected WolfSSLSession getWolfSSLSession() {
        return ssl;
    }

    /**
     * Get WolfSSLImplementSession for this object
     *
     * @return WolfSSLImplementSession for this object
     */
    protected WolfSSLImplementSSLSession getSession() {
        return session;
    }

    /**
     * Get all supported cipher suites in native wolfSSL library
     *
     * @return String array of all supported cipher suites
     */
    protected String[] getAllCiphers() {
        return WolfSSL.getCiphersIana();
    }

    /**
     * Get all enabled cipher suites
     *
     * @return String array of all enabled cipher suites
     */
    protected String[] getCiphers() {
        return this.params.getCipherSuites();
    }

    /**
     * Set cipher suites enabled in WolfSSLParameters
     *
     * Sanitizes input array for invalid suites
     *
     * @param suites String array of cipher suites to be enabled
     *
     * @throws IllegalArgumentException if input array contains invalid
     *         cipher suites, input array is null, or input array has length
     *         zero
     */
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

    /**
     * Set protocols enabled in WolfSSLParameters
     *
     * Sanitizes protocol array for invalid protocols
     *
     * @param p String array of SSL/TLS protocols to be enabled
     *
     * @throws IllegalArgumentException if input array is null,
     *         has length zero, or contains invalid/unsupported protocols
     */
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

    /**
     * Get enabled SSL/TLS protocols from WolfSSLParameters
     *
     * @return String array of enabled SSL/TLS protocols
     */
    protected String[] getProtocols() {
        return this.params.getProtocols();
    }

    /**
     * Get all supported SSL/TLS protocols in native wolfSSL library
     *
     * @return String array of supported protocols
     */
    protected String[] getAllProtocols() {
        return WolfSSL.getProtocols();
    }

    /**
     * Set client mode for associated WOLFSSL session
     *
     * @param mode client mode (true/false)
     *
     * @throws IllegalArgumentException if called after SSL/TLS handshake
     *         has been completed. Only allowed before.
     */
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

    /**
     * Get clientMode for associated session
     *
     * @return boolean value of clientMode set for this session
     */
    protected boolean getUseClientMode() {
        return this.clientMode;
    }

    /**
     * Set if session needs client authentication
     *
     * @param need boolean if session needs client authentication
     */
    protected void setNeedClientAuth(boolean need) {
        this.params.setNeedClientAuth(need);
    }

    /**
     * Get value of needClientAuth for this session
     *
     * @return boolean value for needClientAuth
     */
    protected boolean getNeedClientAuth() {
        return this.params.getNeedClientAuth();
    }

    /**
     * Set value of wantClientAuth for this session
     *
     * @param want boolean value of wantClientAuth for this session
     */
    protected void setWantClientAuth(boolean want) {
        this.params.setWantClientAuth(want);
    }

    /**
     * Get value of wantClientAuth for this session
     *
     * @return boolean value for wantClientAuth
     */
    protected boolean getWantClientAuth() {
        return this.params.getWantClientAuth();
    }

    /**
     * Set ability to create sessions
     *
     * @param flag boolean to set enable session creation
     */
    protected void setEnableSessionCreation(boolean flag) {
        this.sessionCreation = flag;
    }

    /**
     * Get boolean if session creation is allowed
     *
     * @return boolean value for enableSessionCreation
     */
    protected boolean getEnableSessionCreation() {
        return this.sessionCreation;
    }

    /**
     * Enable use of session tickets
     *
     * @param flag boolean to enable/disable session tickets
     */
    protected void setUseSessionTickets(boolean flag) {
        this.params.setUseSessionTickets(flag);
    }

    /**
     * Set ALPN protocols
     *
     * @param alpnProtos encoded byte array of ALPN protocols
     */
    protected void setAlpnProtocols(byte[] alpnProtos) {
        this.params.setAlpnProtocols(alpnProtos);
    }

    /**
     * Get selected ALPN protocol
     *
     * Used by some versions of Android, non-standard ALPN API.
     *
     * @return encoded byte array for selected ALPN protocol or null if
     *         handshake has not finished
     */
    protected byte[] getAlpnSelectedProtocol() {
        if (ssl.handshakeDone()) {
            return ssl.getAlpnSelected();
        }
        return null;
    }

    /**
     * Get selected ALPN protocol string
     *
     * @return String representation of selected ALPN protocol or null
     *         if handshake has not finished
     */
    protected String getAlpnSelectedProtocolString() {
        if (ssl.handshakeDone()) {
            String proto = ssl.getAlpnSelectedString();

            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "selected ALPN protocol = " + proto);

            return proto;
        }
        return null;
    }

    /********** Calls to transfer over parameter to wolfSSL before connection */

    /*transfer over cipher suites right before establishing a connection */
    private void setLocalCiphers(String[] suites)
            throws IllegalArgumentException {
        try {
            String list;
            StringBuilder sb = new StringBuilder();

            if (suites == null || suites.length == 0) {
                /* use default cipher suites */
                return;
            }

            for (String s : suites) {
                sb.append(s);
                sb.append(":");
            }

            if (sb.length() > 0) {
                /* remove last : */
                sb.deleteCharAt(sb.length() - 1);
                list = sb.toString();
                if (this.ssl.setCipherList(list) != WolfSSL.SSL_SUCCESS) {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                            "error setting cipher list " + list);
                }
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
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "X509TrustManager is of type WolfSSLTrustX509");
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "Using native internal peer verification logic");
            this.ssl.setVerify(mask, null);

        } else {
            /* not our own TrustManager, set up callback so JSSE can use
             * TrustManager.checkClientTrusted/checkServerTrusted() */
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "X509TrustManager is not of type WolfSSLTrustX509");
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "Using checkClientTrusted/ServerTrusted() for verification");
            wicb = new WolfSSLInternalVerifyCb(authStore.getX509TrustManager(),
                                               this.clientMode);
            this.ssl.setVerify(WolfSSL.SSL_VERIFY_PEER, wicb);
        }
    }

    /* sets SNI server names, if set by application in SSLParameters */
    private void setLocalServerNames() {
        if (this.clientMode) {

            /* explicitly set if user has set through SSLParameters */
            List<WolfSSLSNIServerName> names = this.params.getServerNames();
            if (names != null && names.size() > 0) {
                /* should only be one server name */
                WolfSSLSNIServerName sni = names.get(0);
                if (sni != null) {
                    this.ssl.useSNI((byte)sni.getType(), sni.getEncoded());
                }
            } else {
                /* otherwise set based on socket hostname if
                 * 'jsee.enableSNIExtension' java property is set to true */
                String enableSNI = System.getProperty("jsse.enableSNIExtension", "true");
                if (enableSNI.equalsIgnoreCase("true")) {

                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        "jsse.enableSNIExtension property set to true, " +
                        "enabling SNI by default");

                    if (this.hostname != null) {
                        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                            "setting SNI extension with hostname: " +
                            this.hostname);
                        this.ssl.useSNI((byte)0, this.hostname.getBytes());
                    } else {
                        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                            "hostname is null, not setting SNI");
                    }
                }
            }
        }
    }

    /* Session tickets are enabled in different ways depending on the JDK
     * implementation we are running on. For Oracle/OpenJDK, the following
     * system properties enable session tickets and were added in JDK 13:
     *
     * -Djdk.tls.client.enableSessionTicketExtension=true
     * -Djdk.tls.server.enableSessionTicketExtension=true
     *
     *  wolfJSSE currently supports client-side session ticket support, but
     *  not yet enabling of server-side support.
     *
     *  On Android, some libraries/frameworks (ex: okhttp) expect to enable
     *  session tickets per SSLSocket by calling a custom SSLSocket extension
     *  method called SSLSocket.setUseSessionTickets().
     *
     *  Note that for session ticket support in wolfJSSE, underlying native
     *  wolfSSL must be compiled with session ticket support enabled. This
     *  is done via "--enable-session-ticket" or "-DHAVE_SESSION_TICKET".
     */
    private void setLocalSessionTicket() {
        if (this.clientMode) {

            boolean enableFlag = this.params.getUseSessionTickets();
            String enableProperty = System.getProperty(
                    "jdk.tls.client.enableSessionTicketExtension");

            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "SSLSocket.setUseSessionTickets() set to: " +
                String.valueOf(enableFlag));

            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "jdk.tls.client.enableSessionTicketExtension property: " +
                enableProperty);

            if ((enableFlag == true) ||
                ((enableProperty != null) &&
                 (enableProperty.equalsIgnoreCase("true")))) {

                /* enable client-side session ticket support */
                this.ssl.useSessionTicket();

                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "session tickets enabled for this session");

            } else {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "session tickets not enabled on this session");
            }
        }
    }

    /* Set the ALPN to be used for this session */
    private void setLocalAlpnProtocols() {

        /* ALPN protocol list could be stored in either of the following,
         * depending on what platform/JDK we are being used on:
         *     this.params.getAlpnProtos() or
         *     this.params.getApplicationProtocols()
         * For example, Conscrypt consumers on older Android versions with
         * JDK 7 will be in params.getAlpnProtos(). JDK versions > 8, with
         * support for params.getApplicationProtocols() will likely use that
         * instead. */

        int i;
        byte[] alpnProtos = this.params.getAlpnProtos();
        String[] applicationProtocols = this.params.getApplicationProtocols();

        if ((alpnProtos != null && alpnProtos.length > 0) &&
            (applicationProtocols != null && applicationProtocols.length > 0)) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "ALPN protocols found in both params.getAlpnProtos() and " +
                "params.getApplicationProtocols()");
        }

        /* try to set from byte[] first, then overwrite with String[] if
         * both have been set */
        if (alpnProtos != null && alpnProtos.length > 0) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "Setting ALPN protocols for WOLFSSL session from byte[" +
                alpnProtos.length + "]");
            this.ssl.useALPN(alpnProtos);
        }

        if (applicationProtocols != null && applicationProtocols.length > 0) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "Setting Application Protocols for WOLFSSL session " +
                "from String[]:");
            for (i = 0; i < applicationProtocols.length; i++) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "\t" + i + ": " + applicationProtocols[i]);
            }

            /* continue on mismatch */
            this.ssl.useALPN(applicationProtocols,
                             WolfSSL.WOLFSSL_ALPN_CONTINUE_ON_MISMATCH);
        }

        if (alpnProtos == null && applicationProtocols == null) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "No ALPN protocols set, not setting for this WOLFSSL session");
        }
    }

    private void setLocalSecureRenegotiation() {
        /* Enable secure renegotiation if native wolfSSL has been compiled
         * with HAVE_SECURE_RENEGOTIATION. Some JSSE consuming apps
         * expect that secure renegotiation will be supported. */
        int ret = this.ssl.useSecureRenegotiation();
        if (ret != WolfSSL.SSL_SUCCESS && ret != WolfSSL.NOT_COMPILED_IN) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "error enabling secure renegotiation, ret = " + ret);
        } else if (ret == 0) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "enabled secure renegotiation support for session");
        }
    }

    private void setLocalParams() {
        this.setLocalCiphers(this.params.getCipherSuites());
        this.setLocalProtocol(this.params.getProtocols());
        this.setLocalAuth();
        this.setLocalServerNames();
        this.setLocalSessionTicket();
        this.setLocalAlpnProtocols();
        this.setLocalSecureRenegotiation();
    }

    /**
     * Sets all parameters from WolfSSLParameters into native WOLFSSL object
     * and creates session.
     *
     * This should be called before doHandshake()
     *
     * @throws SSLException if setUseClientMode() has not been called
     * @throws SSLHandshakeException session creation is not allowed
     *
     */
    protected void initHandshake() throws SSLException {
        if (!modeSet) {
            throw new SSLException("setUseClientMode has not been called");
        }

        /* create non null session */
        this.session = this.authStore.getSession(ssl, this.port, this.hostname,
            this.clientMode);

        if (this.session != null && this.clientMode) {
            this.session.setSessionContext(authStore.getClientContext());
            this.session.setSide(WolfSSL.WOLFSSL_CLIENT_END);
        }
        else {
            this.session.setSessionContext(authStore.getServerContext());
            this.session.setSide(WolfSSL.WOLFSSL_SERVER_END);
        }

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

        if (this.session != null && this.sessionCreation) {
            /* can only add new sessions to the resumption table if session
             * creation is allowed */
            this.authStore.addSession(this.session);
        }

        this.setLocalParams();
    }

    /**
     * Start or continue handshake
     *
     * Callers should not loop on WANT_READ/WRITE when used with SSLEngine.
     *
     * @param isSSLEngine specifies if this is being called by an SSLEngine
     *                    or not.
     * @param timeout socket timeout (milliseconds) for connect(), or 0 for
     *                infinite/no timeout.
     *
     * @return WolfSSL.SSL_SUCCESS on success or either WolfSSL.SSL_FAILURE
     *         or WolfSSL.SSL_HANDSHAKE_FAILURE on error
     *
     * @throws SSLException if setUseClientMode() has not been called.
     * @throws SocketTimeoutException if socket timed out
     */
    protected int doHandshake(int isSSLEngine, int timeout)
        throws SSLException, SocketTimeoutException {

        int ret, err;

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

        do {
            /* call connect() or accept() to do handshake, looping on
             * WANT_READ/WANT_WRITE errors in case underlying Socket is
             * non-blocking */
            if (this.clientMode) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        "calling native wolfSSL_connect()");
                /* may throw SocketTimeoutException on socket timeout */
                ret = this.ssl.connect(timeout);

            } else {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                            "calling native wolfSSL_accept()");
                ret = this.ssl.accept();
            }
            err = ssl.getError(ret);

        } while (ret != WolfSSL.SSL_SUCCESS && isSSLEngine == 0 &&
                 (err == WolfSSL.SSL_ERROR_WANT_READ ||
                  err == WolfSSL.SSL_ERROR_WANT_WRITE));

        return ret;
    }

    /**
     * Saves session on connection close for resumption
     */
    protected void saveSession() {
        if (this.session != null && this.session.isValid()) {
            this.session.setResume();
        }
    }
}

