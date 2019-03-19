/* WolfSSLSocket.java
 *
 * Copyright (C) 2006-2019 wolfSSL Inc.
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

import java.util.Arrays;
import java.util.ArrayList;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.IOException;
import java.io.ByteArrayOutputStream;
import java.net.Socket;
import java.net.InetAddress;
import java.net.SocketAddress;
import java.net.UnknownHostException;
import java.net.InetSocketAddress;
import java.lang.StringBuilder;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSession;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.KeyManager;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.SSLHandshakeException;
import java.security.SecureRandom;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateEncodingException;

import com.wolfssl.provider.jsse.WolfSSLAuthStore.TLS_VERSION;

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLContext;
import com.wolfssl.WolfSSLSession;
import com.wolfssl.WolfSSLException;
import com.wolfssl.WolfSSLJNIException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLParameters;


public class WolfSSLSocket extends SSLSocket {

    private WolfSSLAuthStore authStore = null;

    /* WOLFSSL_CTX reference, passed down to this class */
    private WolfSSLContext ctx = null;

    /* WOLFSSL reference, created in this class */
    private WolfSSLSession ssl = null;
    
    private SSLParameters params = null;

    private WolfSSLEngineHelper EngineHelper = null;
    
    private Socket socket = null;
    private boolean autoClose;
    private InetSocketAddress address = null;

    private WolfSSLInputStream inStream;
    private WolfSSLOutputStream outStream;

    private ArrayList<HandshakeCompletedListener> hsListeners = null;
    private WolfSSLDebug debug;

    public WolfSSLSocket(WolfSSLContext context, WolfSSLAuthStore authStore,
            SSLParameters params, boolean clientMode)
        throws IOException {
        super();
        this.ctx = context;
        this.authStore = authStore;
        this.params = WolfSSLEngineHelper.decoupleParams(params);
        initSSL();
        /* don't call setFd() yet since we don't have a connected socket */
        
        try {
            /* get helper class for common methods */
            EngineHelper = new WolfSSLEngineHelper(this.ssl, this.authStore,
                this.params);
            EngineHelper.setUseClientMode(clientMode);

        } catch (WolfSSLException ex) {
            Logger.getLogger(WolfSSLSocket.class.getName()).log(Level.SEVERE,
                null, ex);
        }
    }

    public WolfSSLSocket(WolfSSLContext context, WolfSSLAuthStore authStore,
            SSLParameters params, boolean clientMode, InetAddress host,
            int port)
            throws IOException {
        super(host, port);
        this.ctx = context;
        this.authStore = authStore;
        this.params = WolfSSLEngineHelper.decoupleParams(params);
        initSSL();
        setFd();

        try {
            /* get helper class for common methods */
            EngineHelper = new WolfSSLEngineHelper(this.ssl, this.authStore,
                    this.params, port, host.getHostAddress());
            EngineHelper.setUseClientMode(clientMode);

        } catch (WolfSSLException ex) {
            Logger.getLogger(WolfSSLSocket.class.getName()).log(Level.SEVERE,
                null, ex);
        }
   }

    public WolfSSLSocket(WolfSSLContext context, WolfSSLAuthStore authStore,
            SSLParameters params, boolean clientMode, InetAddress address,
            int port, InetAddress localAddress, int localPort)
        throws IOException {
        super(address, port, localAddress, localPort);
        this.ctx = context;
        this.authStore = authStore;
        this.params = WolfSSLEngineHelper.decoupleParams(params);
        initSSL();
        setFd();

        try {
            /* get helper class for common methods */
            EngineHelper = new WolfSSLEngineHelper(this.ssl, this.authStore,
                    this.params);
            EngineHelper.setUseClientMode(clientMode);

        } catch (WolfSSLException ex) {
            Logger.getLogger(WolfSSLSocket.class.getName()).log(Level.SEVERE,
                null, ex);
        }
    } 

    public WolfSSLSocket(WolfSSLContext context, WolfSSLAuthStore authStore,
            SSLParameters params, boolean clientMode, String host, int port)
            throws IOException {
        super(host, port);
        this.ctx = context;
        this.authStore = authStore;
        this.params = WolfSSLEngineHelper.decoupleParams(params);
        initSSL();
        setFd();

        try {
            /* get helper class for common methods */
            EngineHelper = new WolfSSLEngineHelper(this.ssl, this.authStore,
                    this.params, port, host);
            EngineHelper.setUseClientMode(clientMode);

        } catch (WolfSSLException ex) {
            Logger.getLogger(WolfSSLSocket.class.getName()).log(Level.SEVERE,
                null, ex);
        }
    }

    public WolfSSLSocket(WolfSSLContext context, WolfSSLAuthStore authStore,
            SSLParameters params, boolean clientMode, String host, int port,
            InetAddress localHost, int localPort)
        throws IOException {
        super(host, port, localHost, localPort);
        this.ctx = context;
        this.authStore = authStore;
        this.params = WolfSSLEngineHelper.decoupleParams(params);
        initSSL();
        setFd();

        try {
            /* get helper class for common methods */
            EngineHelper = new WolfSSLEngineHelper(this.ssl, this.authStore,
                    this.params, port, host);
            EngineHelper.setUseClientMode(clientMode);

        } catch (WolfSSLException ex) {
            Logger.getLogger(WolfSSLSocket.class.getName()).log(Level.SEVERE,
                null, ex);
        }
    }

    public WolfSSLSocket(WolfSSLContext context, WolfSSLAuthStore authStore,
            SSLParameters params, boolean clientMode, Socket s, String host,
            int port, boolean autoClose) throws IOException {
        super();
        this.ctx = context;
        this.authStore = authStore;
        this.params = WolfSSLEngineHelper.decoupleParams(params);
        this.socket = s;
        this.autoClose = autoClose;
        this.address = new InetSocketAddress(host, port);
        initSSL();
        setFd();

        try {
            /* get helper class for common methods */
            EngineHelper = new WolfSSLEngineHelper(this.ssl, this.authStore,
                    this.params);
            EngineHelper.setUseClientMode(clientMode);

        } catch (WolfSSLException ex) {
            Logger.getLogger(WolfSSLSocket.class.getName()).log(Level.SEVERE,
                null, ex);
        }
    }

    public WolfSSLSocket(WolfSSLContext context, WolfSSLAuthStore authStore,
            SSLParameters params, boolean clientMode, Socket s,
            boolean autoClose) throws IOException {
        super();
        this.ctx = context;
        this.authStore = authStore;
        this.params = WolfSSLEngineHelper.decoupleParams(params);
        this.socket = s;
        this.autoClose = autoClose;
        initSSL();
        setFd();

        try {
            /* get helper class for common methods */
            EngineHelper = new WolfSSLEngineHelper(this.ssl, this.authStore,
                    this.params);
            EngineHelper.setUseClientMode(clientMode);

        } catch (WolfSSLException ex) {
            Logger.getLogger(WolfSSLSocket.class.getName()).log(Level.SEVERE,
                null, ex);
        }
    }

    private void initSSL() throws IOException {

        int ret;

        try {
            /* initialize WolfSSLSession object, which wraps the native
             * WOLFSSL structure. */
            ssl = new WolfSSLSession(ctx);

            if (debug.DEBUG) {
                log("created new native WOLFSSL");
            }

            /* set up I/O streams */
            this.inStream = new WolfSSLInputStream(ssl);
            this.outStream = new WolfSSLOutputStream(ssl);

            if (debug.DEBUG) {
                log("created default Input/Output streams");
            }

        } catch (WolfSSLException we) {
            throw new IOException(we);
        }
    }

    private void setFd() throws IOException {

        int ret;

        if (ssl == null) {
            throw new IllegalArgumentException("WolfSSLSession object is null");
        }

        if (this.socket == null) {
            ret = ssl.setFd(this);
            if (ret != WolfSSL.SSL_SUCCESS) {
                throw new IOException("Failed to set native Socket fd");
            }

            if (debug.DEBUG)
                log("registered SSLSocket with native wolfSSL");

        } else {
            ret = ssl.setFd(this.socket);
            if (ret != WolfSSL.SSL_SUCCESS) {
                throw new IOException("Failed to set native Socket fd");
            }

            if (debug.DEBUG)
                log("registered Socket with native wolfSSL");
        }
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
    public void setEnabledCipherSuites(String[] suites)
        throws IllegalArgumentException {
        EngineHelper.setCiphers(suites);

        if (debug.DEBUG) {
            log("enabled cipher suites set to: " + Arrays.toString(suites));
        }
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
    public void setEnabledProtocols(String[] protocols)
        throws IllegalArgumentException {
        EngineHelper.setProtocols(protocols);

        if (debug.DEBUG) {
            log("enabled protocols set to: " + Arrays.toString(protocols));
        }
    }

    @Override
    public SSLSession getSession() {
        return EngineHelper.getSession();
    }

    @Override
    public void addHandshakeCompletedListener(
        HandshakeCompletedListener listener) throws IllegalArgumentException {

        if (listener == null) {
            throw new IllegalArgumentException("HandshakeCompletedListener " +
                "is null");
        }

        if (hsListeners == null) {
            hsListeners = new ArrayList<HandshakeCompletedListener>();
        }

        hsListeners.add(listener);

        if (debug.DEBUG) {
            log("registered new HandshakeCompletedListener");
        }
    }

    @Override
    public void removeHandshakeCompletedListener(
        HandshakeCompletedListener listener) throws IllegalArgumentException {

        if (listener == null) {
            throw new IllegalArgumentException("HandshakeCompletedListener " +
                "is null");
        }

        if (hsListeners != null) {
            boolean removed = hsListeners.remove(listener);
            if (removed == false) {
                throw new IllegalArgumentException(
                    "HandshakeCompletedListener not a registered listener");
            }
        }

        if (debug.DEBUG) {
            log("removed HandshakeCompletedListener");
        }
    }

    @Override
    public void startHandshake() throws IOException {
        int ret;

        /* TODO checking return value and any additional steps */
        ret = EngineHelper.doHandshake();

        if (ret != WolfSSL.SSL_SUCCESS) {

            if (ret == WolfSSL.SSL_HANDSHAKE_FAILURE) {
                throw new SSLHandshakeException("This session is not " +
                    "allowed to create new sessions");
            }

            int err = ssl.getError(ret);
            String errStr = WolfSSL.getErrorString(err);

            throw new SSLHandshakeException(errStr + " (error code: " +
                err + ")");
        }

        /* notify handshake completed listeners */
        if (ret == WolfSSL.SSL_SUCCESS && hsListeners != null) {
            HandshakeCompletedEvent event = new HandshakeCompletedEvent(
                this, EngineHelper.getSession());

            for (int i = 0; i < hsListeners.size(); i++) {
                hsListeners.get(i).handshakeCompleted(event);
            }
        }

        if (debug.DEBUG) {
            log("completed SSL/TLS handshake, listeners notified");
        }

    }

    @Override
    public void setUseClientMode(boolean mode) throws IllegalArgumentException {
        EngineHelper.setUseClientMode(mode);

        if (debug.DEBUG) {
            log("socket client mode set to: " + mode);
        }
    }

    @Override
    public boolean getUseClientMode() {
        return EngineHelper.getUseClientMode();
    }

    @Override
    public void setNeedClientAuth(boolean need) {
        EngineHelper.setNeedClientAuth(need);

        if (debug.DEBUG) {
            log("socket needClientAuth set to: " + need);
        }
    }

    @Override
    public boolean getNeedClientAuth() {
        return EngineHelper.getNeedClientAuth();
    }

    @Override
    public void setWantClientAuth(boolean want) {
        EngineHelper.setWantClientAuth(want);

        if (debug.DEBUG) {
            log("socket wantClientAuth set to: " + want);
        }
    }

    @Override
    public boolean getWantClientAuth() {
        return EngineHelper.getWantClientAuth();
    }

    @Override
    public void setEnableSessionCreation(boolean flag) {
        EngineHelper.setEnableSessionCreation(flag);

        if (debug.DEBUG) {
            log("socket session creation set to: " + flag);
        }
    }

    @Override
    public boolean getEnableSessionCreation() {
        return EngineHelper.getEnableSessionCreation();
    }

    @Override
    public InputStream getInputStream() throws IOException {
        return inStream;
    }

    @Override
    public OutputStream getOutputStream() throws IOException {
        return outStream;
    }

    @Override
    public void close() throws IOException {
        try {
            if (ssl != null) {
                if (debug.DEBUG) {
                    log("shutting down SSL/TLS connection");
                }
                ssl.shutdownSSL();
            }
            super.close();

            if (debug.DEBUG) {
                log("socket closed");
            }

        } catch (IllegalStateException e) {
            throw new IOException(e);
        }
    }

    @Override
    public void connect(SocketAddress endpoint) throws IOException {

        if (!(endpoint instanceof InetSocketAddress)) {
            throw new IllegalArgumentException("endpoint is not of type " +
                "InetSocketAddress");
        }

        if (this.socket != null) {
            this.socket.connect(endpoint);
        } else {
            super.connect(endpoint);
        }

        this.address = (InetSocketAddress)endpoint;

        /* if user is calling after WolfSSLSession creation, register
           socket fd with native wolfSSL */
        if (ssl != null) {
            setFd();
        }
    }

    @Override
    public void connect(SocketAddress endpoint, int timeout)
        throws IOException {

        if (!(endpoint instanceof InetSocketAddress)) {
            throw new IllegalArgumentException("endpoint is not of type " +
                "InetSocketAddress");
        }

        if (this.socket != null) {
            this.socket.connect(endpoint, timeout);
        } else {
            super.connect(endpoint, timeout);
        }

        this.address = (InetSocketAddress)endpoint;

        /* if user is calling after WolfSSLSession creation, register
           socket fd with native wolfSSL */
        if (ssl != null) {
            setFd();
        }
    }

    private void log(String msg) {
        debug.print("[WolfSSLSocket] " + msg);
    }
}

