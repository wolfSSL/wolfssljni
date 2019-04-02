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
import java.io.DataInputStream;
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
import com.wolfssl.WolfSSLIORecvCallback;
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

        try {
            initSSL();
            /* don't call setFd() yet since we don't have a connected socket */

            /* get helper class for common methods */
            EngineHelper = new WolfSSLEngineHelper(this.ssl, this.authStore,
                this.params);
            EngineHelper.setUseClientMode(clientMode);

        } catch (WolfSSLException e) {
            throw new IOException(e);
        }
    }

    public WolfSSLSocket(WolfSSLContext context, WolfSSLAuthStore authStore,
        SSLParameters params, boolean clientMode, InetAddress host,
        int port) throws IOException {

        super(host, port);
        this.ctx = context;
        this.authStore = authStore;
        this.params = WolfSSLEngineHelper.decoupleParams(params);

        try {
            initSSL();
            setFd();

            /* get helper class for common methods */
            EngineHelper = new WolfSSLEngineHelper(this.ssl, this.authStore,
                    this.params, port, host.getHostAddress());
            EngineHelper.setUseClientMode(clientMode);

        } catch (WolfSSLException e) {
            throw new IOException(e);
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

        try {
            initSSL();
            setFd();

            /* get helper class for common methods */
            EngineHelper = new WolfSSLEngineHelper(this.ssl, this.authStore,
                    this.params, port, address.getHostAddress());
            EngineHelper.setUseClientMode(clientMode);

        } catch (WolfSSLException e) {
            throw new IOException(e);
        }
    } 

    public WolfSSLSocket(WolfSSLContext context, WolfSSLAuthStore authStore,
        SSLParameters params, boolean clientMode, String host, int port)
        throws IOException {

        super(host, port);
        this.ctx = context;
        this.authStore = authStore;
        this.params = WolfSSLEngineHelper.decoupleParams(params);

        try {
            initSSL();
            setFd();

            /* get helper class for common methods */
            EngineHelper = new WolfSSLEngineHelper(this.ssl, this.authStore,
                    this.params, port, host);
            EngineHelper.setUseClientMode(clientMode);

        } catch (WolfSSLException e) {
            throw new IOException(e);
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

        try {
            initSSL();
            setFd();

            /* get helper class for common methods */
            EngineHelper = new WolfSSLEngineHelper(this.ssl, this.authStore,
                    this.params, port, host);
            EngineHelper.setUseClientMode(clientMode);

        } catch (WolfSSLException e) {
            throw new IOException(e);
        }
    }

    /* creates an SSLSocket layered over an existing socket connected to the
       named host, at the given port. host/port refer to logical peer, but
       Socket could be connected to a proxy */
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

        if (s == null) {
            throw new NullPointerException("Socket is null");
        }

        /* socket should already be connected */
        if (!s.isConnected()) {
            throw new IOException("Socket is not connected");
        }

        try {
            initSSL();
            setFd();

            /* get helper class for common methods */
            EngineHelper = new WolfSSLEngineHelper(this.ssl, this.authStore,
                    this.params, port, host);
            EngineHelper.setUseClientMode(clientMode);

        } catch (WolfSSLException e) {
            throw new IOException(e);
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

        if (s == null || !s.isConnected()) {
            throw new IOException("Socket is null or not connected");
        }

        try {
            initSSL();
            setFd();

            /* get helper class for common methods */
            EngineHelper = new WolfSSLEngineHelper(this.ssl, this.authStore,
                    this.params, s.getPort(),
                    s.getInetAddress().getHostAddress());
            EngineHelper.setUseClientMode(clientMode);

        } catch (WolfSSLException e) {
            throw new IOException(e);
        }
    }

    /* only creates a server mode Socket */
    public WolfSSLSocket(WolfSSLContext context, WolfSSLAuthStore authStore,
        SSLParameters params, Socket s, InputStream consumed,
        boolean autoClose) throws IOException {

        super();
        this.ctx = context;
        this.authStore = authStore;
        this.params = WolfSSLEngineHelper.decoupleParams(params);
        this.socket = s;
        this.autoClose = autoClose;

        if (s == null ) {
            throw new NullPointerException("Socket is null");
        }

        if (!s.isConnected()) {
            throw new IOException("Socket is not connected");
        }

        try {
            initSSL();
            setFd();

            /* get helper class for common methods */
            EngineHelper = new WolfSSLEngineHelper(this.ssl, this.authStore,
                    this.params, s.getPort(),
                    s.getInetAddress().getHostAddress());
            EngineHelper.setUseClientMode(false);

            /* register custom receive callback to read consumed first */
            if (consumed != null) {
                ConsumedRecvCallback recvCb = new ConsumedRecvCallback();
                this.ssl.setIORecv(recvCb);
                ConsumedRecvCtx recvCtx = new ConsumedRecvCtx(s, consumed);
                this.ssl.setIOReadCtx(recvCtx);
            }

        } catch (WolfSSLException e) {
            throw new IOException(e);
        } catch (WolfSSLJNIException jnie) {
            throw new IOException(jnie);
        }
    }

    private void initSSL() throws WolfSSLException {

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
    }

    private void setFd() throws IllegalArgumentException, WolfSSLException {

        int ret;

        if (ssl == null) {
            throw new IllegalArgumentException("WolfSSLSession object is null");
        }

        if (this.socket == null) {
            ret = ssl.setFd(this);
            if (ret != WolfSSL.SSL_SUCCESS) {
                throw new WolfSSLException("Failed to set native Socket fd");
            }

            if (debug.DEBUG)
                log("registered SSLSocket with native wolfSSL");

        } else {
            ret = ssl.setFd(this.socket);
            if (ret != WolfSSL.SSL_SUCCESS) {
                throw new WolfSSLException("Failed to set native Socket fd");
            }

            if (debug.DEBUG)
                log("registered Socket with native wolfSSL");
        }
    }

    @Override
    public String[] getSupportedCipherSuites() {
        /* returns cipher suites supported (compiled in) from native wolfSSL */
        return EngineHelper.getAllCiphers();
    }

    @Override
    synchronized public String[] getEnabledCipherSuites() {
        /* returns cipher suites set by user, or null if none have been set */
        return EngineHelper.getCiphers();
    }

    @Override
    synchronized public void setEnabledCipherSuites(String[] suites)
        throws IllegalArgumentException {

        /* sets cipher suite(s) to be used for connection */
        EngineHelper.setCiphers(suites);

        if (debug.DEBUG) {
            log("enabled cipher suites set to: " + Arrays.toString(suites));
        }
    }

    @Override
    public String[] getSupportedProtocols() {

        /* returns all protocol version supported by native wolfSSL */
        return EngineHelper.getAllProtocols();
    }

    @Override
    synchronized public String[] getEnabledProtocols() {

        /* returns protocols versions enabled for this session */
        return EngineHelper.getProtocols();
    }

    @Override
    synchronized public void setEnabledProtocols(String[] protocols)
        throws IllegalArgumentException {

        /* sets protocol versions to be enabled for use with this session */
        EngineHelper.setProtocols(protocols);

        if (debug.DEBUG) {
            log("enabled protocols set to: " + Arrays.toString(protocols));
        }
    }

    @Override
    synchronized public SSLSession getSession() {
        return EngineHelper.getSession();
    }

    @Override
    synchronized public void addHandshakeCompletedListener(
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
    synchronized public void removeHandshakeCompletedListener(
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
    synchronized public void startHandshake() throws IOException {
        int ret;

        /* will throw SSLHandshakeException if session creation is
           not allowed */
        EngineHelper.initHandshake();

        ret = EngineHelper.doHandshake();

        if (ret != WolfSSL.SSL_SUCCESS) {

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
    synchronized public void setUseClientMode(boolean mode)
        throws IllegalArgumentException {

        EngineHelper.setUseClientMode(mode);

        if (debug.DEBUG) {
            log("socket client mode set to: " + mode);
        }
    }

    @Override
    synchronized public boolean getUseClientMode() {
        return EngineHelper.getUseClientMode();
    }

    @Override
    synchronized public void setNeedClientAuth(boolean need) {

        EngineHelper.setNeedClientAuth(need);

        if (debug.DEBUG) {
            log("socket needClientAuth set to: " + need);
        }
    }

    @Override
    synchronized public boolean getNeedClientAuth() {
        return EngineHelper.getNeedClientAuth();
    }

    @Override
    synchronized public void setWantClientAuth(boolean want) {

        EngineHelper.setWantClientAuth(want);

        if (debug.DEBUG) {
            log("socket wantClientAuth set to: " + want);
        }
    }

    @Override
    synchronized public boolean getWantClientAuth() {
        return EngineHelper.getWantClientAuth();
    }

    @Override
    synchronized public void setEnableSessionCreation(boolean flag) {

        EngineHelper.setEnableSessionCreation(flag);

        if (debug.DEBUG) {
            log("socket session creation set to: " + flag);
        }
    }

    @Override
    synchronized public boolean getEnableSessionCreation() {
        return EngineHelper.getEnableSessionCreation();
    }

    @Override
    synchronized public InputStream getInputStream() throws IOException {
        return inStream;
    }

    @Override
    synchronized public OutputStream getOutputStream() throws IOException {
        return outStream;
    }

    @Override
    synchronized public void close() throws IOException {
        try {
            if (ssl != null) {
                if (debug.DEBUG) {
                    log("shutting down SSL/TLS connection");
                }
                EngineHelper.saveSession();
                ssl.shutdownSSL();
            }

            if (this.autoClose) {
                super.close();
                if (debug.DEBUG) {
                    log("socket closed");
                }
            } else {
                if (debug.DEBUG) {
                    log("socket not closed, autoClose set to false");
                }
            }

        } catch (IllegalStateException e) {
            throw new IOException(e);
        }
    }

    @Override
    synchronized public void connect(SocketAddress endpoint)
        throws IOException {

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
        try {
            if (ssl != null) {
                setFd();
            }
        } catch (WolfSSLException e) {
            throw new IOException(e);
        }
    }

    @Override
    synchronized public void connect(SocketAddress endpoint, int timeout)
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
        try {
            if (ssl != null) {
                setFd();
            }
        } catch (WolfSSLException e) {
            throw new IOException(e);
        }
    }

    private void log(String msg) {
        debug.print("[WolfSSLSocket] " + msg);
    }

    class ConsumedRecvCtx {
        private Socket s;
        private DataInputStream consumed;

        public ConsumedRecvCtx(Socket s, InputStream in) {
            this.s = s;
            this.consumed = new DataInputStream(in);
        }

        public Socket getSocket() {
            return this.s;
        }

        public DataInputStream getSocketDataStream() throws IOException {
            return new DataInputStream(this.s.getInputStream());
        }

        public DataInputStream getConsumedDataStream() {
            return this.consumed;
        }
    }

    class ConsumedRecvCallback implements WolfSSLIORecvCallback {

        public int receiveCallback(WolfSSLSession ssl, byte[] buf,
            int sz, Object ctx) {

            int ret;

            try {
                ConsumedRecvCtx context = (ConsumedRecvCtx)ctx;
                DataInputStream current = context.getSocketDataStream();
                DataInputStream consumed = context.getConsumedDataStream();

                /* try to read from consumed stream first */
                if (consumed != null && consumed.available() > 0) {
                    ret = consumed.read(buf, 0, sz);
                    /* if we are at EOF, return 0 */
                    if (ret == -1) {
                        ret = 0;
                    }

                } else {
                    /* read directly from Socket */
                    ret = current.read(buf, 0, sz);
                    if (ret == -1) {
                        /* no data available */
                        ret = WolfSSL.WOLFSSL_CBIO_ERR_WANT_READ;
                    }
                }
            } catch (IOException e) {
                if (debug.DEBUG) {
                    log("error reading from Socket InputStream");
                }
                ret = WolfSSL.WOLFSSL_CBIO_ERR_GENERAL;
            }

            /* return size read, or error */
            return ret;
        }
    }
}

