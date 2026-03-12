/* WolfSSLSocket.java
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

package com.wolfssl.provider.jsse;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketAddress;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.function.BiFunction;
import java.util.List;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicBoolean;
import java.nio.channels.SocketChannel;
import java.security.cert.CertificateEncodingException;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLException;

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLDebug;
import com.wolfssl.WolfSSLException;
import com.wolfssl.WolfSSLIOSendCallback;
import com.wolfssl.WolfSSLIORecvCallback;
import com.wolfssl.WolfSSLALPNSelectCallback;
import com.wolfssl.WolfSSLJNIException;
import com.wolfssl.WolfSSLSession;


/**
 * wolfSSL implementation of SSLSocket
 *
 * @author wolfSSL
 */
public class WolfSSLSocket extends SSLSocket {

    private WolfSSLAuthStore authStore = null;

    /* WOLFSSL_CTX reference, passed down to this class */
    private com.wolfssl.WolfSSLContext ctx = null;

    /* WOLFSSL reference, created in this class */
    private WolfSSLSession ssl = null;
    private WolfSSLParameters params = null;
    private WolfSSLEngineHelper EngineHelper = null;

    private Socket socket = null;
    private boolean autoClose;

    private WolfSSLInputStream inStream;
    private WolfSSLOutputStream outStream;

    /* Track active I/O operations to prevent use-after-free */
    private final java.util.concurrent.atomic.AtomicInteger activeOperations =
        new java.util.concurrent.atomic.AtomicInteger(0);

    private ArrayList<HandshakeCompletedListener> hsListeners = null;

    /** TLS handshake initialization called */
    protected volatile boolean handshakeInitCalled = false;
    /** TLS handshake has been started */
    protected volatile boolean handshakeStarted = false;
    /** TLS handshake has completed */
    protected volatile boolean handshakeComplete = false;
    /** Connection to peer has closed */
    protected volatile boolean connectionClosed = false;
    /** Flag representing if I/O callbacks have been set */
    private boolean ioCallbacksSet = false;
    /** Flag representing if native fd has been set */
    private boolean fdSet = false;

    /* lock for handshakInitCalled and handshakeComplete */
    private final Object handshakeLock = new Object();

    /* protect read/write/connect/accept from multiple threads simultaneously
     * accessing WolfSSLSession object / WOLFSSL struct */
    private final Object ioLock = new Object();

    /* lock for get/set of SO timeout */
    private final Object timeoutLock = new Object();

    /* lock and status for WolfSSLSocket initialization */
    private boolean isInitialized = false;
    private final Object initLock = new Object();

    /** ALPN selector callback, if set */
    protected BiFunction<SSLSocket, List<String>, String> alpnSelector = null;

    /* true if client, otherwise false */
    private boolean isClientMode = false;

    /**
     * Create new WolfSSLSocket object
     *
     * @param context WolfSSLContext to use with this SSLSocket
     * @param authStore WolfSSLAuthStore to use with this SSLSocket
     * @param params WolfSSLParameters to use with this SSLSocket
     * @param clientMode true if this is a client socket, otherwise false
     *
     * @throws IOException if initialization fails
     */
    public WolfSSLSocket(com.wolfssl.WolfSSLContext context,
           WolfSSLAuthStore authStore, WolfSSLParameters params,
           boolean clientMode)
        throws IOException {

        super();
        this.ctx = context;
        this.authStore = authStore;
        this.params = params.copy();
        this.autoClose = true;

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "creating new WolfSSLSocket(clientMode: " +
            String.valueOf(clientMode) + ")");

        try {
            initSSL();

            EngineHelper = new WolfSSLEngineHelper(this.ssl, this.authStore,
                this.params);
            EngineHelper.setUseClientMode(clientMode);
            this.isClientMode = clientMode;

        } catch (WolfSSLException e) {
            throw new IOException(e);
        }
    }

    /**
     * Create new WolfSSLSocket object
     *
     * @param context WolfSSLContext to use with this SSLSocket
     * @param authStore WolfSSLAuthStore to use with this SSLSocket
     * @param params WolfSSLParameters to use with this SSLSocket
     * @param clientMode true if this is a client socket, otherwise false
     * @param host InetAddress of peer hostname
     * @param port port of peer
     *
     * @throws IOException if initialization fails
     */
    public WolfSSLSocket(com.wolfssl.WolfSSLContext context,
            WolfSSLAuthStore authStore, WolfSSLParameters params,
            boolean clientMode, InetAddress host, int port)
            throws IOException {

        super(host, port);
        this.ctx = context;
        this.authStore = authStore;
        this.params = params.copy();
        this.autoClose = true;

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "creating new WolfSSLSocket(clientMode: " +
            String.valueOf(clientMode) + ", InetAddress, port: " +
            port + ")");

        try {
            initSSL();

            EngineHelper = new WolfSSLEngineHelper(this.ssl, this.authStore,
                this.params, port, host);
            EngineHelper.setUseClientMode(clientMode);
            this.isClientMode = clientMode;

        } catch (WolfSSLException e) {
            throw new IOException(e);
        }
   }

    /**
     * Create new WolfSSLSocket object
     *
     * @param context WolfSSLContext to use with this SSLSocket
     * @param authStore WolfSSLAuthStore to use with this SSLSocket
     * @param params WolfSSLParameters to use with this SSLSocket
     * @param clientMode true if this is a client socket, otherwise false
     * @param address InetAddress of peer hostname
     * @param port port of peer
     * @param localAddress local InetAddress to use for SSLSocket
     * @param localPort local port to use for SSLSocket
     *
     * @throws IOException if initialization fails
     */
    public WolfSSLSocket(com.wolfssl.WolfSSLContext context,
            WolfSSLAuthStore authStore, WolfSSLParameters params,
            boolean clientMode, InetAddress address, int port,
            InetAddress localAddress, int localPort)
            throws IOException {

        super(address, port, localAddress, localPort);
        this.ctx = context;
        this.authStore = authStore;
        this.params = params.copy();
        this.autoClose = true;

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "creating new WolfSSLSocket(clientMode: " +
            String.valueOf(clientMode) + ", InetAddress, port: " +
            port + ", InetAddress, localPort: " + localPort + ")");

        try {
            initSSL();

            EngineHelper = new WolfSSLEngineHelper(this.ssl, this.authStore,
                this.params, port, address);
            EngineHelper.setUseClientMode(clientMode);
            this.isClientMode = clientMode;

        } catch (WolfSSLException e) {
            throw new IOException(e);
        }
    }

    /**
     * Create new WolfSSLSocket object
     *
     * @param context WolfSSLContext to use with this SSLSocket
     * @param authStore WolfSSLAuthStore to use with this SSLSocket
     * @param params WolfSSLParameters to use with this SSLSocket
     * @param clientMode true if this is a client socket, otherwise false
     * @param host String of peer hostname
     * @param port port of peer
     *
     * @throws IOException if initialization fails
     */
    public WolfSSLSocket(com.wolfssl.WolfSSLContext context,
            WolfSSLAuthStore authStore, WolfSSLParameters params,
            boolean clientMode, String host, int port)
            throws IOException {

        super(host, port);
        this.ctx = context;
        this.authStore = authStore;
        this.params = params.copy();
        this.autoClose = true;

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "creating new WolfSSLSocket(clientMode: " +
            String.valueOf(clientMode) + ", host: " + host + ", port: " +
            port + ")");

        try {
            initSSL();

            EngineHelper = new WolfSSLEngineHelper(this.ssl, this.authStore,
                this.params, port, host);
            EngineHelper.setUseClientMode(clientMode);
            this.isClientMode = clientMode;

        } catch (WolfSSLException e) {
            throw new IOException(e);
        }
    }

    /**
     * Create new WolfSSLSocket object
     *
     * @param context WolfSSLContext to use with this SSLSocket
     * @param authStore WolfSSLAuthStore to use with this SSLSocket
     * @param params WolfSSLParameters to use with this SSLSocket
     * @param clientMode true if this is a client socket, otherwise false
     * @param host InetAddress of peer hostname
     * @param port port of peer
     * @param localHost local InetAddress to use for SSLSocket
     * @param localPort local port to use for SSLSocket
     *
     * @throws IOException if initialization fails
     */
    public WolfSSLSocket(com.wolfssl.WolfSSLContext context,
            WolfSSLAuthStore authStore, WolfSSLParameters params,
            boolean clientMode, String host, int port, InetAddress localHost,
            int localPort)
            throws IOException {

        super(host, port, localHost, localPort);
        this.ctx = context;
        this.authStore = authStore;
        this.params = params.copy();
        this.autoClose = true;

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "creating new WolfSSLSocket(clientMode: " +
            String.valueOf(clientMode) + ", host: " + host + ", port: " +
            port + ", InetAddress, locaPort: " + localPort + ")");

        try {
            initSSL();

            EngineHelper = new WolfSSLEngineHelper(this.ssl, this.authStore,
                this.params, port, host);
            EngineHelper.setUseClientMode(clientMode);
            this.isClientMode = clientMode;

        } catch (WolfSSLException e) {
            throw new IOException(e);
        }
    }

    /**
     * Create new WolfSSLSocket object layered over an existing Socket
     * connected to the named host, at the given port.
     *
     * host/port refer to logical peer, but Socket could be connected to
     * a proxy.
     *
     * @param context WolfSSLContext to use with this SSLSocket
     * @param authStore WolfSSLAuthStore to use with this SSLSocket
     * @param params WolfSSLParameters to use with this SSLSocket
     * @param clientMode true if this is a client socket, otherwise false
     * @param s existing connected Socket
     * @param host String with peer hostname
     * @param port port of peer
     * @param autoClose automatically close wrapped Socket when finished
     *
     * @throws IOException if initialization fails
     */
    public WolfSSLSocket(com.wolfssl.WolfSSLContext context,
            WolfSSLAuthStore authStore, WolfSSLParameters params,
            boolean clientMode, Socket s, String host, int port,
            boolean autoClose) throws IOException {

        super();
        this.ctx = context;
        this.authStore = authStore;
        this.params = params.copy();
        this.socket = s;
        this.autoClose = autoClose;

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "creating new WolfSSLSocket(clientMode: " +
            String.valueOf(clientMode) + ", Socket, host: " + host +
            ", port: " + port + ", autoClose: " +
            String.valueOf(autoClose) + ")");

        if (s == null) {
            throw new NullPointerException("Socket is null");
        }

        /* socket should already be connected */
        if (!s.isConnected()) {
            throw new IOException("Socket is not connected");
        }

        try {
            initSSL();

            EngineHelper = new WolfSSLEngineHelper(this.ssl, this.authStore,
                this.params, port, host);
            EngineHelper.setUseClientMode(clientMode);
            this.isClientMode = clientMode;

        } catch (WolfSSLException e) {
            throw new IOException(e);
        }
    }

    /**
     * Create new WolfSSLSocket object layered over an existing Socket.
     *
     * @param context WolfSSLContext to use with this SSLSocket
     * @param authStore WolfSSLAuthStore to use with this SSLSocket
     * @param params WolfSSLParameters to use with this SSLSocket
     * @param clientMode true if this is a client socket, otherwise false
     * @param s existing connected Socket
     * @param autoClose automatically close wrapped Socket when finished
     *
     * @throws IOException if initialization fails
     */
    public WolfSSLSocket(com.wolfssl.WolfSSLContext context,
            WolfSSLAuthStore authStore, WolfSSLParameters params,
            boolean clientMode, Socket s, boolean autoClose)
            throws IOException {

        super();
        this.ctx = context;
        this.authStore = authStore;
        this.params = params.copy();
        this.socket = s;
        this.autoClose = autoClose;

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "creating new WolfSSLSocket(clientMode: " +
            String.valueOf(clientMode) + ", Socket, autoClose: " +
            String.valueOf(autoClose) + ")");

        if (!s.isConnected()) {
            throw new IOException("Socket is not connected");
        }

        try {
            initSSL();

            EngineHelper = new WolfSSLEngineHelper(this.ssl, this.authStore,
                this.params, s.getPort(), s.getInetAddress());
            EngineHelper.setUseClientMode(clientMode);
            this.isClientMode = clientMode;

        } catch (WolfSSLException e) {
            throw new IOException(e);
        }
    }

    /**
     * Create new WolfSSLSocket object layered over an existing Socket,
     * only a server mode Socket. Use pre-consumed InputStream data
     * if provided.
     *
     * @param context WolfSSLContext to use with this SSLSocket
     * @param authStore WolfSSLAuthStore to use with this SSLSocket
     * @param params WolfSSLParameters to use with this SSLSocket
     * @param s existing connected Socket
     * @param consumed pre-consumed Socket data to use for this SSLSocket
     * @param autoClose automatically close wrapped Socket when finished
     *
     * @throws IOException if initialization fails
     */
    public WolfSSLSocket(com.wolfssl.WolfSSLContext context,
            WolfSSLAuthStore authStore, WolfSSLParameters params, Socket s,
            InputStream consumed, boolean autoClose) throws IOException {

        super();
        this.ctx = context;
        this.authStore = authStore;
        this.params = params.copy();
        this.socket = s;
        this.autoClose = autoClose;

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "creating new WolfSSLSocket(Socket, InputStream, " +
            "autoClose: " + String.valueOf(autoClose) + ")");

        if (s == null ) {
            throw new NullPointerException("Socket is null");
        }

        if (!s.isConnected()) {
            throw new IOException("Socket is not connected");
        }

        try {
            initSSL();

            EngineHelper = new WolfSSLEngineHelper(this.ssl, this.authStore,
                this.params, s.getPort(), s.getInetAddress());
            EngineHelper.setUseClientMode(false);
            this.isClientMode = false;

            /* register custom receive callback to read consumed first */
            if (consumed != null) {
                ConsumedRecvCallback recvCb = new ConsumedRecvCallback();
                this.ssl.setIORecv(recvCb);
                ConsumedRecvCtx recvCtx = new ConsumedRecvCtx(s, consumed);
                this.ssl.setIOReadCtx(recvCtx);
                this.ioCallbacksSet = true;
            }

        } catch (WolfSSLException | WolfSSLJNIException e) {
            throw new IOException(e);
        }
    }

    /**
     * Create new internal WolfSSLSession object for use with this SSLSocket.
     *
     * @throws WolfSSLException on error creating WolfSSLSession
     */
    private void initSSL() throws WolfSSLException {

        /* Initialize WolfSSLSession object, wraps WOLFSSL structure. */
        ssl = new WolfSSLSession(ctx);
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "created new native WOLFSSL");
    }

    /**
     * Initialize this WolfSSLSocket.
     *
     * Internal method, should be called before any handshake, I/O, or
     * other operations are conducted that would rely on a set up key/cert,
     * file descriptor, or I/O callback.
     *
     * This logic is not included directly in WolfSSLSocket constructors
     * to avoid possible 'this' escape before subclass is fully initialized
     * when using 'this' from setFd().
     *
     * @throws IOException if initialization fails
     */
    private void checkAndInitSSLSocket() throws IOException {

        synchronized (initLock) {

            /* If underlying Socket connected, set fd. Check before
             * initialized flag, since we may have already initialized
             * certs/keys but not fd in previous call */
            if (!this.fdSet && isConnected()) {
                try {
                    setFd();
                } catch (WolfSSLException e) {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        () -> "Failed to set native fd, may try again later");
                }
            }

            if (isInitialized) {
                return;
            }

            try {
                /* Load private key and cert chain from WolfSSLAuthStore */
                if (EngineHelper != null) {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        () -> "loading private key and cert chain");

                    if (this.socket != null) {
                        EngineHelper.LoadKeyAndCertChain(this.socket, null);
                    } else {
                        EngineHelper.LoadKeyAndCertChain(this, null);
                    }
                } else {
                    throw new WolfSSLException(
                        "EngineHelper null, cannot load key and cert chain");
                }

                isInitialized = true;

            } catch (WolfSSLException | CertificateEncodingException |
                     IOException e) {
                throw new IOException(e);
            }
        }
    }

    /**
     * Register I/O callbacks with native wolfSSL which use
     * Input/OutputStream of the wrapped Socket object.
     *
     * Called by setFd() if ssl.setFd() fails to find or set the internal
     * SocketImpl file descriptor.
     *
     * @throws WolfSSLException if this.socket is null or setting I/O
     *                          callbacks or ctx fails
     */
    private void setIOCallbacks() throws WolfSSLException {

        if (this.socket == null) {
            throw new WolfSSLException(
                "Internal Socket is null, unable to set I/O callbacks");
        }

        if (this.ioCallbacksSet) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "wolfSSL I/O callbacks already set, skipping");
            return;
        }

        try {
            /* Register send callback and context */
            SocketSendCallback sendCb = new SocketSendCallback();
            this.ssl.setIOSend(sendCb);
            SocketSendCtx writeCtx = new SocketSendCtx(this.socket);
            this.ssl.setIOWriteCtx(writeCtx);

            /* Register recv callback and context */
            SocketRecvCallback recvCb = new SocketRecvCallback();
            this.ssl.setIORecv(recvCb);
            SocketRecvCtx readCtx = new SocketRecvCtx(this.socket);
            this.ssl.setIOReadCtx(readCtx);

        } catch (WolfSSLJNIException e) {
            throw new WolfSSLException(e);
        }
    }

    private void setFd() throws IllegalArgumentException, WolfSSLException {

        int ret;

        if (ssl == null) {
            throw new IllegalArgumentException("WolfSSLSession object is null");
        }

        /* Synchronized on ioLock to prevent read/write/connect/accept calls
         * from possibly being called before descriptor or I/O callbacks
         * have been set */
        synchronized (ioLock) {
            if (this.socket == null) {
                ret = ssl.setFd(this);
                if (ret != WolfSSL.SSL_SUCCESS) {
                    throw new WolfSSLException(
                        "Failed to set native Socket fd");
                }
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "registered SSLSocket(this) with native wolfSSL");

            } else {
                ret = ssl.setFd(this.socket);
                if (ret != WolfSSL.SSL_SUCCESS) {
                    /* Failed to find/set internal SocketImpl file descriptor.
                     * Try using I/O callbacks instead with
                     * Input/OutputStream */
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        () -> "Failed to set native SocketImpl fd, " +
                        "trying I/O callbacks");

                    setIOCallbacks();
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        () -> "registered underlying Socket with " +
                        "wolfSSL I/O callbacks");
                }
                else {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        () -> "registered Socket(this.socket) with " +
                        "native wolfSSL");
                }
            }

            /* Mark fd set */
            this.fdSet = true;
        }
    }


    /**
     * Returns unique SocketChannel object assiciated with this socket.
     */
    @Override
    public final SocketChannel getChannel() {
        if (this.socket != null) {
            return this.socket.getChannel();
        } else {
            return super.getChannel();
        }
    }

    /**
     * Get the address of the remote peer.
     */
    @Override
    public final InetAddress getInetAddress() {
        if (this.socket != null) {
            return this.socket.getInetAddress();
        } else {
            return super.getInetAddress();
        }
    }

    /**
     * Get the local address the socket is bound to.
     */
    @Override
    public final InetAddress getLocalAddress() {
        if (this.socket != null) {
            return this.socket.getLocalAddress();
        } else {
            return super.getLocalAddress();
        }
    }

    /**
     * Get remote port number used by this socket.
     */
    @Override
    public final int getPort() {
        if (this.socket != null) {
            return this.socket.getPort();
        } else {
            return super.getPort();
        }
    }

    /**
     * Get local port number used by this socket.
     */
    @Override
    public final int getLocalPort() {
        if (this.socket != null) {
            return this.socket.getLocalPort();
        } else {
            return super.getLocalPort();
        }
    }

    /**
     * Tests if SO_KEEPALIVE is enabled on this socket.
     */
    @Override
    public final boolean getKeepAlive() throws SocketException {
        if (this.socket != null) {
            return this.socket.getKeepAlive();
        } else {
            return super.getKeepAlive();
        }
    }

    /**
     * Tests if SO_REUSEADDR is enabled on this socket.
     */
    @Override
    public final boolean getReuseAddress() throws SocketException {
        if (this.socket != null) {
            return this.socket.getReuseAddress();
        } else {
            return super.getReuseAddress();
        }
    }

    /**
     * Return address of the endpoint that this socket is bound to,
     * or null if not bound yet.
     */
    @Override
    public final SocketAddress getLocalSocketAddress() {
        if (this.socket != null) {
            return this.socket.getLocalSocketAddress();
        } else {
            return super.getLocalSocketAddress();
        }
    }

    /**
     * Tests if OOBINLINE is enabled.
     */
    @Override
    public final boolean getOOBInline() throws SocketException {
        if (this.socket != null) {
            return this.socket.getOOBInline();
        } else {
            return super.getOOBInline();
        }
    }

    /**
     * Gets the value of the SO_RCVBUF option for this socket.
     */
    @Override
    public final synchronized int getReceiveBufferSize()
        throws SocketException {
        if (this.socket != null) {
            return this.socket.getReceiveBufferSize();
        } else {
            return super.getReceiveBufferSize();
        }
    }

    /**
     * Returns the address of the remote endpoint, or null if not connected.
     */
    @Override
    public final SocketAddress getRemoteSocketAddress() {
        if (this.socket != null) {
            return this.socket.getRemoteSocketAddress();
        } else {
            return super.getRemoteSocketAddress();
        }
    }

    /**
     * Gets the value of the SO_SNDBUF option for this socket.
     */
    @Override
    public final synchronized int getSendBufferSize()
        throws SocketException {
        if (this.socket != null) {
            return this.socket.getSendBufferSize();
        } else {
            return super.getSendBufferSize();
        }
    }

    /**
     * Gets the value of the SO_SNDBUF option for this socket. This setting
     * only affects socket close.
     * @return -1 if option is disabled, otherwise int value
     */
    @Override
    public final int getSoLinger() throws SocketException {
        if (this.socket != null) {
            return this.socket.getSoLinger();
        } else {
            return super.getSoLinger();
        }
    }

    /**
     * Tests if TCP_NODELAY is enabled.
     */
    @Override
    public final boolean getTcpNoDelay() throws SocketException {
        if (this.socket != null) {
            return this.socket.getTcpNoDelay();
        } else {
            return super.getTcpNoDelay();
        }
    }

    /**
     * Gets traffic class or type of service in IP header.
     */
    @Override
    public final int getTrafficClass() throws SocketException {
        if (this.socket != null) {
            return this.socket.getTrafficClass();
        } else {
            return super.getTrafficClass();
        }
    }

    /**
     * Returns the binding state for this socket.
     */
    @Override
    public final boolean isBound() {
        if (this.socket != null) {
            return this.socket.isBound();
        } else {
            return super.isBound();
        }
    }

    /**
     * Returns the closed state of the socket.
     */
    @Override
    public final boolean isClosed() {
        if (this.socket != null) {
            return this.socket.isClosed();
        } else {
            return super.isClosed();
        }
    }

    /**
     * Returns the connection state of this socket.
     */
    @Override
    public final boolean isConnected() {
        if (this.socket != null) {
            return this.socket.isConnected();
        } else {
            return super.isConnected();
        }
    }

    /**
     * Returns whether the read-half of the socket connection is closed.
     */
    @Override
    public final boolean isInputShutdown() {
        if (this.socket != null) {
            return this.socket.isInputShutdown();
        } else {
            return super.isInputShutdown();
        }
    }

    /**
     * Returns whether the write-half of the socket connection is closed.
     */
    @Override
    public final boolean isOutputShutdown() {
        if (this.socket != null) {
            return this.socket.isOutputShutdown();
        } else {
            return super.isOutputShutdown();
        }
    }

    /**
     * Send one byte of urgent data on the socket.
     * Not supported by SSLSockets at this point.
     */
    @Override
    public final void sendUrgentData(int data) throws IOException {
        throw new SocketException(
            "sendUrgentData() not supported by WolfSSLSocket");
    }

    /**
     * Enable/disable SO_KEEPALIVE.
     */
    @Override
    public final void setKeepAlive(boolean on) throws SocketException {
        if (this.socket != null) {
            this.socket.setKeepAlive(on);
        } else {
            super.setKeepAlive(on);
        }
    }

    /**
     * Enable/disable SO_KEEPALIVE.
     * Enable/disable OOBINLINE (receipt of TCP urgent data). This option
     * is disabled by default. Setting OOBInline does not have any effect
     * on WolfSSLSocket since SSLSocket does not support sending urgent data.
     */
    @Override
    public final void setOOBInline(boolean on) throws SocketException {
        throw new SocketException("setOOBInline is ineffective, as sending " +
            "urgent data is not supported with SSLSocket");
    }

    /**
     * Set performance preferences for this socket.
     */
    @Override
    public final void setPerformancePreferences(int connectionTime,
            int latency, int bandwidth) {
        if (this.socket != null) {
            this.socket.setPerformancePreferences(connectionTime,
                    latency, bandwidth);
        } else {
            super.setPerformancePreferences(connectionTime, latency,
                    bandwidth);
        }
    }

    /**
     * Sets the SO_RCVBUF option to the specified value for this Socket.
     */
    @Override
    public final synchronized void setReceiveBufferSize(int size)
        throws SocketException {
        if (this.socket != null) {
            this.socket.setReceiveBufferSize(size);
        } else {
            super.setReceiveBufferSize(size);
        }
    }

    /**
     * Enable/disable the SO_REUSEADDR socket option.
     */
    @Override
    public final void setReuseAddress(boolean on) throws SocketException {
        if (this.socket != null) {
            this.socket.setReuseAddress(on);
        } else {
            super.setReuseAddress(on);
        }
    }

    /**
     * Sets the SO_SNDBUF option to the specified value for this Socket.
     */
    @Override
    public final synchronized void setSendBufferSize(int size)
        throws SocketException {
        if (this.socket != null) {
            this.socket.setSendBufferSize(size);
        } else {
            super.setSendBufferSize(size);
        }
    }

    /**
     * Enable/disable SO_LINGER with specified linger time in seconds.
     */
    @Override
    public final void setSoLinger(boolean on, int linger)
        throws SocketException {
        if (this.socket != null) {
            this.socket.setSoLinger(on, linger);
        } else {
            super.setSoLinger(on, linger);
        }
    }

    /**
     * Enable/disable TCP_NODELAY on this Socket.
     */
    @Override
    public final void setTcpNoDelay(boolean on) throws SocketException {
        if (this.socket != null) {
            this.socket.setTcpNoDelay(on);
        } else {
            super.setTcpNoDelay(on);
        }
    }

    /**
     * Sets traffic class or type-of-service octet in the IP header for packets
     * sent from this Socket.
     */
    @Override
    public final void setTrafficClass(int tc) throws SocketException {
        if (this.socket != null) {
            this.socket.setTrafficClass(tc);
        } else {
            super.setTrafficClass(tc);
        }
    }

    /**
     * shutdownInput() not supported with SSLSocket, matches OpenJDK behavior.
     */
    @Override
    public final void shutdownInput() throws IOException {
        throw new UnsupportedOperationException(
            "shutdownInput() not supported by wolfSSLSocket");
    }

    /**
     * shutdownOutput() not supported with SSLSocket, matches OpenJDK behavior.
     */
    @Override
    public final void shutdownOutput() throws IOException {
        throw new UnsupportedOperationException(
            "shutdownOutput() not supported by wolfSSLSocket");
    }

    /**
     * Returns the supported cipher suite list for this socket, and that
     * have been compiled into native wolfSSL library.
     *
     * @return array of supported cipher suite Strings
     */
    @Override
    public synchronized String[] getSupportedCipherSuites() {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "entered getSupportedCipherSuites()");

        /* getAllCiphers() is a static method, calling directly on class */
        return WolfSSLEngineHelper.getAllCiphers();
    }

    /**
     * Returns array of enabled cipher suites for this Socket.
     * This array is pre-populated by wolfJSSE with the cipher suites
     * supported by the native wolfSSL library

     * @return array of enabled cipher suite Strings
     */
    @Override
    public synchronized String[] getEnabledCipherSuites() {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "entered getEnabledCipherSuites()");

        if (this.isClosed()) {
            return null;
        }

        return EngineHelper.getCiphers();
    }

    /**
     * Sets the cipher suites enabled for this SSLSocket.
     *
     * @param suites array of cipher suites to enable for this Socket
     *
     * @throws IllegalArgumentException when suites array contains
     *         cipher suites unsupported by native wolfSSL
     */
    @Override
    public synchronized void setEnabledCipherSuites(String[] suites)
        throws IllegalArgumentException {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "entered setEnabledCipherSuites()");

        if (this.isClosed()) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "SSLSocket closed, not setting enabled cipher suites");
            return;
        }

        /* sets cipher suite(s) to be used for connection */
        EngineHelper.setCiphers(suites);
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "enabled cipher suites set to: " + Arrays.toString(suites));
    }

    /**
     * Returns the most recent application protocol value negotiated
     * during the SSL/TLS handshake by ALPN.
     *
     * Not marked at @Override since this API was added as of
     * Java SE 8 Maintenance Release 3, and Java 7 SSLSocket will not
     * have this.
     *
     * @return String representating the application protocol negotiated
     */
    public synchronized String getApplicationProtocol() {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "entered getApplicationProtocol()");

        /* If socket has been closed, return an empty string */
        if (this.isClosed()) {
            return "";
        }

        return EngineHelper.getAlpnSelectedProtocolString();
    }

    /**
     * Returns the application protocol value negotiated on a handshake
     * currently in progress.
     *
     * After the handshake has finished, this will return null. To get the
     * ALPN protocol negotiated during the handshake, after it has completed,
     * call getApplicationProtocol().
     *
     * Not marked at @Override since this API was added as of
     * Java SE 8 Maintenance Release 3, and Java 7 SSLSocket will not
     * have this.
     *
     * @return String representating the application protocol negotiated
     */
    public synchronized String getHandshakeApplicationProtocol() {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "entered getHandshakeApplicationProtocol()");

        if (this.handshakeStarted && !this.handshakeComplete) {
            return EngineHelper.getAlpnSelectedProtocolString();
        }

        return null;
    }

    /**
     * Returns the callback that selects an application protocol during the
     * SSL/TLS handshake.
     *
     * @return the callback function, or null if no callback has been set
     */
    public synchronized BiFunction<SSLSocket,List<String>,String>
        getHandshakeApplicationProtocolSelector() {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "entered getHandshakeApplicationProtocolSelector()");

        return this.alpnSelector;
    }

    /**
     * Registers a callback function that selects an application protocol
     * value for the SSL/TLS handshake.
     *
     * Usage of this callback will override any values set by
     * SSLParameters.setApplicationProtocols().
     *
     * Callback argument descriptions:
     *
     *    SSLSocket - the current SSLSocket, allows for inspection by the
     *                callback if needed
     *    List&lt;String&gt; - List of Strings representing application protocol
     *                   names sent by the peer
     *    String - Result of the callback is an application protocol
     *             name String, or null if none of the peer's protocols
     *             are acceptable. If return value is an empty String,
     *             ALPN will not be used.
     *
     * @param selector callback used to select ALPN protocol for handshake
     */
    public synchronized void setHandshakeApplicationProtocolSelector(
        BiFunction<SSLSocket,List<String>,String> selector) {

        final int ret;

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "entered setHandshakeApplicationProtocolSelector()");

        if (selector != null) {
            ALPNSelectCallback alpnCb = new ALPNSelectCallback();

            try {
                /* Pass in SSLSocket Object for use inside callback */
                ret = this.ssl.setAlpnSelectCb(alpnCb, this);
                if (ret != WolfSSL.SSL_SUCCESS) {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        () -> "Native setAlpnSelectCb() failed, ret = " + ret +
                        ", not setting selector");
                    return;
                }

                /* called from within ALPNSelectCallback during the handshake */
                this.alpnSelector = selector;

            } catch (WolfSSLJNIException e) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "Exception while calling ssl.setAlpnSelectCb, " +
                    "not setting");
            }
        }
    }

    /**
     * Inner class that implement the ALPN select callback which is registered
     * with our com.wolfssl.WolfSSLSession when
     * setHandshakeApplicationProtocolSelector() has been called.
     */
    class ALPNSelectCallback implements WolfSSLALPNSelectCallback
    {
        public int alpnSelectCallback(WolfSSLSession ssl, String[] out,
            String[] in, Object arg) {

            SSLSocket sock = (SSLSocket)arg;
            List<String> peerProtos = new ArrayList<String>();
            final String selected;

            if (alpnSelector == null) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "alpnSelector null inside ALPNSelectCallback");
                return WolfSSL.SSL_TLSEXT_ERR_ALERT_FATAL;
            }

            if (!(arg instanceof SSLSocket)) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "alpnSelectCallback arg not type of SSLSocket");
                return WolfSSL.SSL_TLSEXT_ERR_ALERT_FATAL;
            }

            if (in.length == 0) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "peer protocol list is 0 inside alpnSelectCallback");
                return WolfSSL.SSL_TLSEXT_ERR_ALERT_FATAL;
            }

            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "ALPN protos sent by peer: " + Arrays.toString(in));

            for (String s: in) {
                peerProtos.add(s);
            }
            selected = alpnSelector.apply(sock, peerProtos);

            if (selected == null) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "ALPN protocol string is null, no peer match");
                return WolfSSL.SSL_TLSEXT_ERR_ALERT_FATAL;
            }
            else {
                if (selected.isEmpty()) {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        () -> "ALPN not being used, selected proto empty");
                    return WolfSSL.SSL_TLSEXT_ERR_NOACK;
                }

                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "ALPN protocol selected by callback: " + selected);
                out[0] = selected;
                return WolfSSL.SSL_TLSEXT_ERR_OK;

            }
        }
    }

    /**
     * Returns array of protocols supported by this SSLSocket.
     *
     * @return String array containing supported SSL/TLS protocols
     */
    @Override
    public synchronized String[] getSupportedProtocols() {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "entered getSupportedProtocols()");

        /* returns all protocol version supported by native wolfSSL.
        /* getAllProtocols() is a static method, calling directly on class */
        return WolfSSLEngineHelper.getAllProtocols();
    }

    /**
     * Returns SSL/TLS protocols enabled for this SSLSocket.
     *
     * @return String array containing enabled protocols
     */
    @Override
    public synchronized String[] getEnabledProtocols() {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "entered getEnabledProtocols()");

        if (this.isClosed()) {
            return null;
        }

        /* returns protocols versions enabled for this session */
        return EngineHelper.getProtocols();
    }

    /**
     * Sets the SSL/TLS protocols enabled on this SSLSocket.
     *
     * @param protocols String array of SSL/TLS protocols to enable
     *
     * @throws IllegalArgumentException when protocols array contains
     *         protocols unsupported by native wolfSSL
     */
    @Override
    public synchronized void setEnabledProtocols(String[] protocols)
        throws IllegalArgumentException {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "entered setEnabledProtocols()");

        if (this.isClosed()) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "SSLSocket closed, not setting enabled protocols");
            return;
        }

        /* sets protocol versions to be enabled for use with this session */
        EngineHelper.setProtocols(protocols);
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "enabled protocols set to: " + Arrays.toString(protocols));
    }

    /**
     * Set ALPN extension protocol for this session.
     * Calls native SSL_set_alpn_protos() at native level. Format starts with
     * length, where length does not include length byte itself. Example format:
     *
     * Non-standard JSSE API, needed for Android compatibility. Some frameworks
     * such as OkHttp expect this API to be here.
     *
     * byte[] p = "http/1.1".getBytes();
     *
     * @param alpnProtos ALPN protocols, encoded as byte array vector
     */
    public synchronized void setAlpnProtocols(byte[] alpnProtos) {

        /* store protocol array in WolfSSLParameters, will push to WOLFSSL
         * from EngineHelper */
        EngineHelper.setAlpnProtocols(alpnProtos);
    }

    /**
     * Return ALPN protocol established for this session.
     * Calls native SSL_get0_alpn_selected().
     *
     * Non-standard JSSE API, needed for Android compatibility. Some frameworks
     * such as OkHttp expect this API to be here.
     *
     * @return byte array representation of selected protocol, starting with
     *         length byte. Length does not include length byte itself.
     */
    public synchronized byte[] getAlpnSelectedProtocol() {
        return EngineHelper.getAlpnSelectedProtocol();
    }

    /**
     * Returns the SSLSession in use by this SSLSocket.
     *
     * @return SSLSession object, otherwise null if not handshaking or
     *         Socket has not progressed enough to create the session
     */
    @Override
    public synchronized SSLSession getSession() {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "entered getSession()");

        if (this.isClosed()) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "SSLSocket has been closed, returning invalid session");

            /* return invalid session object with cipher suite
             * "SSL_NULL_WITH_NULL_NULL" */
            return new WolfSSLImplementSSLSession(this.authStore);
        }

        try {
            /* try to do handshake if not completed yet,
             * handles synchronization */
            if (this.handshakeComplete == false) {
                this.startHandshake();
            }
        } catch (Exception e) {
            /* Log error, but continue. Session returned will be empty */
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "Handshake attempt failed in SSLSocket.getSession()");

            /* close SSLSocket */
            try {
                close();
            } catch (Exception ex) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "close attempt failed in SSLSocket.getSession(): " +
                    ex);
            }

            /* return invalid session object with cipher suite
             * "SSL_NULL_WITH_NULL_NULL" */
            return new WolfSSLImplementSSLSession(this.authStore);
        }

        return EngineHelper.getSession();
    }

    /**
     * Returns the SSLSession being constructed during the SSL/TLS handshake.
     *
     * Unlike SSLSocket.getSession(), this does not start the handshake
     * automatically if it has not been done yet.
     *
     * @return null if not handshaking yet or handshake is not far enough
     *         to have a SSLSession. Otherwise, returns the SSLSession
     *         being negotiated with peer.
     */
    @Override
    public synchronized SSLSession getHandshakeSession() {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "entered getHandshakeSession()");

        if ((this.handshakeStarted == false) || this.isClosed()) {
            return null;
        }

        return EngineHelper.getSession();
    }

    /**
     * Registers a HandshakeCompletedListener with this SSLSocket.
     *
     * The handshake completed listener will be notified when the SSL/TLS
     * handshake on this Socket has completed.
     *
     * @param listener the handshake listener to register
     *
     * @throws IllegalArgumentException when listener is null
     */
    @Override
    public synchronized void addHandshakeCompletedListener(
        HandshakeCompletedListener listener) throws IllegalArgumentException {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "entered addHandshakeCompletedListener()");

        if (listener == null) {
            throw new IllegalArgumentException(
                "HandshakeCompletedListener is null");
        }

        if (hsListeners == null) {
            hsListeners = new ArrayList<HandshakeCompletedListener>();
        }

        hsListeners.add(listener);
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "registered new HandshakeCompletedListener");
    }

    /**
     * Removes a registered HandshakeCompletedListener from this SSLSocket.
     *
     * @param listener the listener to be removed
     *
     * @throws IllegalArgumentException if listener is null, or has not
     *         been registered wit this Socket
     */
    @Override
    public synchronized void removeHandshakeCompletedListener(
        HandshakeCompletedListener listener) throws IllegalArgumentException {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "entered removeHandshakeCompletedListener()");

        if (listener == null) {
            throw new IllegalArgumentException(
                "HandshakeCompletedListener is null");
        }

        if (hsListeners != null) {
            boolean removed = hsListeners.remove(listener);
            if (removed == false) {
                throw new IllegalArgumentException(
                    "HandshakeCompletedListener not a registered listener");
            }
        }
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "removed HandshakeCompletedListener");
    }

    /**
     * Begins the SSL/TLS handshake on this SSLSocket.
     *
     * @throws IOException if a network error occurs
     */
    @Override
    public synchronized void startHandshake() throws IOException {
        int ret;
        int err = 0;
        String errStr = "";

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "entered startHandshake(), trying to get handshakeLock");

        checkAndInitSSLSocket();

        synchronized (handshakeLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "thread got handshakeLock (initHandshake)");

            if (!this.isConnected()) {
                throw new SocketException("Socket is not connected");
            }

            if (connectionClosed == true) {
                throw new SocketException("Connection already shutdown");
            }

            if (handshakeComplete == true && getSession().isValid()) {
                /* Handshake already finished:
                 *   - Return early if session still valid.
                 *   - Otherwise proceed with new handshake. */
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "handshake already finished, returning early");
                return;
            }

            if (handshakeInitCalled == false) {
                /* will throw SSLHandshakeException if session creation is
                   not allowed */
                EngineHelper.initHandshake(this);
                handshakeInitCalled = true;
            }

            /* Mark handshake as started */
            this.handshakeStarted = true;

            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "thread exiting handshakeLock (initHandshake)");
        }

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "trying to get ioLock (handshake)");

        synchronized (ioLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "thread got ioLock (handshake)");

            try {
                ret = EngineHelper.doHandshake(0, this.getSoTimeout());
                err = ssl.getError(ret);
                errStr = WolfSSL.getErrorString(err);

            /* close socket if the handshake is unsuccessful */
            } catch (SocketTimeoutException e) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "got socket timeout in doHandshake()");
                close();
                throw e;

            } catch (SSLHandshakeException e){
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "got SSLHandshakeException in doHandshake()");
                throw e;
            } catch (SSLException e) {
                final int tmpErr = err;
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "native handshake failed in doHandshake(): " +
                    "error code: " + tmpErr + ", TID " +
                    Thread.currentThread().getId() + ")");
                close();
                throw e;
            } catch (WolfSSLException e) {
                /* close socket if the handshake is unsuccessful */
                close();
                throw new SSLException("Handshake failed: " + e.getMessage(), e);
            }

            if (ret != WolfSSL.SSL_SUCCESS) {
                /* Save verify exception before close(), which nullifies
                 * EngineHelper and would lose the stored exception */
                Exception verifyEx = (EngineHelper != null) ?
                    EngineHelper.getLastVerifyException() : null;
                close();
                SSLHandshakeException hse = new SSLHandshakeException(
                    errStr + " (error code: " +
                    err + ", TID " + Thread.currentThread().getId() + ")");
                if (verifyEx != null) {
                    hse.initCause(verifyEx);
                }
                throw hse;
            }

            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "thread exiting ioLock (handshake)");
        }

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "trying to get handshakeLock (handshakeComplete)");

        synchronized (handshakeLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "thread got handshakeLock (handshakeComplete)");
            /* mark handshake completed */
            handshakeComplete = true;
        }

        /* notify handshake completed listeners */
        if (ret == WolfSSL.SSL_SUCCESS && hsListeners != null) {
            HandshakeCompletedEvent event = new HandshakeCompletedEvent(
                this, EngineHelper.getSession());

            for (int i = 0; i < hsListeners.size(); i++) {
                hsListeners.get(i).handshakeCompleted(event);
            }
        }
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "completed SSL/TLS handshake, listeners notified");

        /* print debug info about connection, if enabled */
        if (EngineHelper.getSession() != null) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "SSL/TLS protocol version: " +
                EngineHelper.getSession().getProtocol());
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "SSL/TLS cipher suite: " +
                EngineHelper.getSession().getCipherSuite());
        }
    }

    /**
     * Sets the SSLSocket to use client or server mode.
     *
     * This must be called before the handshake begins on this Socket.
     *
     * @param mode true for client mode, false for server mode
     *
     * @throws IllegalArgumentException if caller tries to set the mode
     *         after handshaking has completed
     */
    @Override
    public synchronized void setUseClientMode(boolean mode)
        throws IllegalArgumentException {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "entered setUseClientMode()");

        if (!this.isClosed()) {
            EngineHelper.setUseClientMode(mode);
        }
        this.isClientMode = mode;

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "socket client mode set to: " + mode);
    }

    /**
     * Return the client mode of this SSLSocket.
     *
     * @return true if in client mode, otherwise false for server mode
     */
    @Override
    public synchronized boolean getUseClientMode() {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "entered getUseClientMode()");

        return this.isClientMode;
    }

    /**
     * Configures the SSLSocket to require client authentication.
     *
     * Only useful in server mode. Similar to setWantClientAuth(), but
     * if a client does not provide a cert/method for the server to
     * authenticate it, the connection will fail.
     *
     * @param need true sets client auth requirement, otherwise false
     */
    @Override
    public synchronized void setNeedClientAuth(boolean need) {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "entered setNeedClientAuth(need: " + String.valueOf(need) + ")");

        if (!this.isClosed()) {
            EngineHelper.setNeedClientAuth(need);
        }
    }

    /**
     * Return if mandatory client authentication is set for this SSLSocket.
     *
     * @return true if Socket has been configured to require client auth,
     *         otherwise false
     */
    @Override
    public synchronized boolean getNeedClientAuth() {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "entered getNeedClientAuth()");

        /* When socket is closed, EngineHelper gets set to null. Since we
         * don't cache needClientAuth value, return false after closure. */
        if (this.isClosed()) {
            return false;
        }

        return EngineHelper.getNeedClientAuth();
    }

    /**
     * Configures the SSLSocket to request client authentication, but not
     * require it.
     *
     * Similar to setNeedClientAuth(), but the handshake does not abort
     * if the client does not send a certificate back.
     *
     * @param want true to enable server to request certificate from client,
     *        false if client auth should be disabled
     */
    @Override
    public synchronized void setWantClientAuth(boolean want) {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "entered setWantClientAuth(want: " + String.valueOf(want) + ")");

        if (!this.isClosed()) {
            EngineHelper.setWantClientAuth(want);
        }
    }

    /**
     * Returns true if SSLSocket will request client authentication.
     *
     * "want" client auth indicates that a server socket will request
     * that the client sends a certificate to authenticate itself, but
     * the server will not abort the handshake if the client does not
     * send it.
     *
     * @return true if Socket will request client auth, false otherwise
     */
    @Override
    public synchronized boolean getWantClientAuth() {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "entered getWantClientAuth()");

        /* When socket is closed, EngineHelper gets set to null. Since we
         * don't cache wantClientAuth value, return false after closure. */
        if (this.isClosed()) {
            return false;
        }

        return EngineHelper.getWantClientAuth();
    }

    /**
     * Enables this SSLSocket to create new sessions.
     *
     * If this is set to false, and there are not sessions to resume,
     * this Socket will not be allowed to create new sessions.
     *
     * @param flag true to allow session creation, otherwise false
     */
    @Override
    public synchronized void setEnableSessionCreation(boolean flag) {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "entered setEnableSessionCreation(flag: " +
            String.valueOf(flag) + ")");

        if (!this.isClosed()) {
            EngineHelper.setEnableSessionCreation(flag);
        }
    }

    /**
     * Returns whether this SSLSocket can create new sessions.
     *
     * @return true if this Socket can create new sessions, otherwise false
     */
    @Override
    public synchronized boolean getEnableSessionCreation() {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "entered getEnableSessionCreation()");

        if (this.isClosed()) {
            return false;
        }

        return EngineHelper.getEnableSessionCreation();
    }

    /**
     * Enables use of session tickets with this session. Disabled by default.
     *
     * @param useTickets true to enable session tickets, otherwise false
     */
    public synchronized void setUseSessionTickets(boolean useTickets) {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "entered setUseSessionTickets(flag: " +
            String.valueOf(useTickets) + ")");

        EngineHelper.setUseSessionTickets(useTickets);
    }

    /**
     * Return the InputStream associated with this SSLSocket.
     *
     * @return InputStream for this Socket
     *
     * @throws IOException if InputStream is not able to be returned
     */
    @Override
    public synchronized InputStream getInputStream() throws IOException {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "entered getInputStream()");

        checkAndInitSSLSocket();

        if (!this.isConnected()) {
            throw new SocketException("Socket is not connected");
        }

        if (this.isClosed()) {
            throw new IOException("Socket has been closed");
        }

        if (inStream == null) {
            inStream = new WolfSSLInputStream(ssl, this);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "created WolfSSLInputStream");
        }

        return inStream;
    }

    /**
     * Return the OutputStream associated with this SSLSocket.
     *
     * @return OutputStream for this Socket
     *
     * @throws IOException if OutputStream is not able to be returned
     */
    @Override
    public synchronized OutputStream getOutputStream() throws IOException {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "entered getOutputStream()");

        checkAndInitSSLSocket();

        if (!this.isConnected()) {
            throw new SocketException("Socket is not connected");
        }

        if (this.isClosed()) {
            throw new IOException("Socket has been closed");
        }

        if (outStream == null) {
            outStream = new WolfSSLOutputStream(ssl, this);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "created WolfSSLOutputStream");
        }

        return outStream;
    }

    /**
     * Set the SO_TIMEOUT with specified timeout in milliseconds.
     * Must be called prior to socket operations to have an effect.
     *
     * @param timeout Read timeout in milliseconds, or 0 for infinite
     *
     * @throws SocketException if there is an error setting the timeout value
     */
    @Override
    public void setSoTimeout(int timeout) throws SocketException {
        /* timeoutLock synchronizes get/set of timeout */
        synchronized (timeoutLock) {
            if (this.socket != null) {
                this.socket.setSoTimeout(timeout);
            } else {
                super.setSoTimeout(timeout);
            }
        }
    }

    /**
     * Get the SO_TIMEOUT value, in milliseconds.
     *
     * @return Timeout value in milliseconds, or 0 if disabled/infinite
     *
     * @throws SocketException if there is an error getting timeout value
     */
    @Override
    public int getSoTimeout() throws SocketException {
        /* timeoutLock synchronizes get/set of timeout */
        synchronized (timeoutLock) {
            if (this.socket != null) {
                return this.socket.getSoTimeout();
            } else {
                return super.getSoTimeout();
            }
        }
    }

    /**
     * Set the SSLParameters for this SSLSocket.
     *
     * @param params SSLParameters to set for this SSLSocket object
     */
    public synchronized void setSSLParameters(SSLParameters params) {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "entered setSSLParameters()");

        if (params != null) {
            WolfSSLParametersHelper.importParams(params, this.params);
        }
    }

    /**
     * Gets the SSLParameters for this SSLSocket.
     *
     * @return SSLParameters for this SSLSocket object.
     */
    @Override
    public synchronized SSLParameters getSSLParameters() {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "entered getSSLParameters()");

        return WolfSSLParametersHelper.decoupleParams(this.params);
    }

    /**
     * Has the underlying WOLFSSL / WolfSSLSession been resumed / reused.
     * This calls down to native wolfSSL_session_reused()
     *
     * NON-STANDARD API, not part of JSSE. Must cast SSLSocket back
     * to WolfSSLSocke to use.
     *
     * @return true if session has been resumed, otherwise false
     * @throws SSLException if native JNI call fails or underlying
     *         WolfSSLSession has been freed
     */
    public synchronized boolean sessionResumed() throws SSLException {
        if (this.ssl != null) {
            try {
                int resume = this.ssl.sessionReused();
                if (resume == 1) {
                    return true;
                }
            } catch (IllegalStateException | WolfSSLJNIException e) {
                throw new SSLException(e);
            }
        }

        return false;
    }

    /**
     * Helper method to track entry into an I/O operation.
     * Increments the active operation counter to prevent premature freeSSL().
     */
    private void enterIOOperation() {
        activeOperations.incrementAndGet();
    }

    /**
     * Helper method to safely exit an I/O operation.
     * Must be called for every successful enterIOOperation().
     */
    private void exitIOOperation() {
        activeOperations.decrementAndGet();
    }

    /**
     * Internal private method to check if WolfSSLInputStream
     * and WolfSSLOutputStream are closed.
     *
     * @return true if both streams are closed (or were not created/null),
     * otherwise false if they were created and are still active.
     */
    private boolean ioStreamsAreClosed() {

        if (this.inStream == null && this.outStream == null) {
            return true;
        }

        if (this.inStream != null && !this.inStream.isClosed()) {
            return false;
        }

        if (this.outStream != null && !this.outStream.isClosed()) {
            return false;
        }

        return true;
    }

    /**
     * Closes this SSLSocket.
     *
     * If this socket was created with an autoClose value set to true,
     * this will also close the underlying Socket.
     *
     * @throws IOException upon error closing the connection
     */
    @Override
    public synchronized void close() throws IOException {

        int ret;
        boolean beforeObjectInit = false;
        boolean handshakeFinished = false;

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "entered close()");

        /* Test if this is called before WolfSSLSocket object has initialized,
         * meaning this is called directly from super(). If so, we skip
         * TLS-specific shutdown since not relevant. */
        try {
            synchronized (handshakeLock) { }
        } catch (NullPointerException e) {
            beforeObjectInit = true;
        }

        try {
            if (beforeObjectInit == false) {
                /* Ensure SSL state exists before TLS-specific close path. */
                checkAndInitSSLSocket();

                /* Check if underlying Socket is still open before closing,
                 * in case application calls SSLSocket.close() multiple times */
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "trying to get handshakeLock (close)");

                synchronized (handshakeLock) {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        () -> "thread got handshakeLock (close)");

                    if (this.connectionClosed == true ||
                        (this.socket != null && this.socket.isClosed()) ||
                        (this.socket == null && super.isClosed())) {
                        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                            () -> "Socket already closed, skipping " +
                            "TLS shutdown");
                        return;
                    }

                    /* Get value of handshakeComplete while inside lock */
                    handshakeFinished = this.handshakeComplete;
                }

                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "signaling any blocked I/O threads to wake up");
                if (this.ssl != null) {
                    ssl.interruptBlockedIO();
                }

                /* Try TLS shutdown procedure, only if handshake has finished */
                if (ssl != null && handshakeFinished) {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        () -> "shutting down SSL/TLS connection");

                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        () -> "thread trying to get ioLock (shutdown)");

                    synchronized (ioLock) {
                        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                            () -> "thread got ioLock (shutdown)");

                        if ((this.getUseClientMode() == true) &&
                            (handshakeFinished == true)) {
                            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                                () -> "saving WOLFSSL_SESSION into cache");
                            if (EngineHelper != null) {
                                EngineHelper.saveSession();
                            }
                        }
                        else {
                            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                                () -> "not saving WOLFSSL_SESSION into cache, " +
                                "not client or handshake not complete");
                        }

                        try {
                            /* Use SO_LINGER value when calling
                             * shutdown here, since we are closing the
                             * socket */
                            if (this.socket != null) {
                                ret = ssl.shutdownSSL(
                                    this.socket.getSoLinger());
                            } else {
                                ret = ssl.shutdownSSL(
                                    super.getSoLinger());
                            }

                            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                                () -> "ssl.shutdownSSL() ret = " + ret);

                        } catch (SocketException | SocketTimeoutException e) {
                            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                                () -> "Exception while trying to " +
                                "ssl.shutdownSSL(), ignore to finish cleanup");
                        }

                        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                            () -> "thread trying to get handshakeLock");

                        synchronized (handshakeLock) {
                            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                                () -> "thread got handshakeLock");

                            this.connectionClosed = true;

                            /* Release native verify callback (JNI global) */
                            if (this.EngineHelper != null) {
                                this.EngineHelper.unsetVerifyCallback();
                            }

                            /* Close ConsumedRecvCtx data stream */
                            Object readCtx = this.ssl.getIOReadCtx();
                            if (readCtx != null &&
                                readCtx instanceof ConsumedRecvCtx) {
                                ConsumedRecvCtx rctx = (ConsumedRecvCtx)readCtx;
                                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                                    () -> "calling ConsumedRecvCtx." +
                                    "closeDataStreams()");
                                rctx.closeDataStreams();
                            }

                            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                                () -> "thread exiting handshakeLock " +
                                "(shutdown)");

                        } /* handshakeLock */

                        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                            () -> "thread exiting ioLock (shutdown)");

                    } /* ioLock */

                    /* Release Input/OutputStream objects. Do not close
                     * WolfSSLSocket inside stream close, since we handle that
                     * next below and do differently depending on if autoClose
                     * has been set or not. */
                    if (this.inStream != null) {
                        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                            () -> "close(), closing InputStream");
                        this.inStream.close(false);
                        this.inStream = null;
                    }
                    if (this.outStream != null) {
                        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                            () -> "close(), closing OutputStream");
                        this.outStream.close(false);
                        this.outStream = null;
                    }
                }

                /* Free this.ssl here instead of above for use cases
                 * where a SSLSocket is created then closed()'d before
                 * connected or handshake is done. freeSSL() will
                 * release interruptFds[] pipe() and free up descriptor. */
                synchronized (ioLock) {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        () -> "thread got ioLock (freeSSL)");

                    /* Connection is closed, free native WOLFSSL session
                     * to release native memory earlier than garbage
                     * collector might with finalize(), Don't free if we
                     * have threads still waiting in poll/select, if
                     * our WolfSSLInputStream or WolfSSLOutputStream are
                     * still open, or if there are active I/O operations. */
                    if (this.ssl != null) {
                        if ((this.ssl.getThreadsBlockedInPoll() == 0) &&
                            ioStreamsAreClosed() && (activeOperations.get() == 0)) {
                            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                                () -> "calling this.ssl.freeSSL()");
                            this.ssl.freeSSL();
                            this.ssl = null;
                        } else {
                            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                                () -> "deferring freeing this.ssl, threads " +
                                "blocked in poll: " +
                                this.ssl.getThreadsBlockedInPoll() +
                                ", streams not closed, or active operations: " +
                                activeOperations.get());
                        }
                    }

                    /* Reset internal WolfSSLEngineHelper to null */
                    if (this.EngineHelper != null) {
                        this.EngineHelper.clearObjectState();
                        this.EngineHelper = null;
                    }

                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        () -> "thread exiting ioLock (shutdown)");
                } /* ioLock */
            }

            if (this.autoClose) {
                if (this.socket != null) {
                    this.socket.close();
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        () -> "socket (external) closed: " + this.socket);
                } else {
                    super.close();
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        () -> "socket (super) closed: " + super.toString());
                }
            } else {
                if (this.socket != null) {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        () -> "socket (external) not closed, autoClose " +
                        "set to false");
                } else {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        () -> "socket (super) not closed, autoClose " +
                        "set to false");
                }
            }

        } catch (IllegalStateException e) {
            throw new IOException(e);
        } catch (WolfSSLJNIException jnie) {
            throw new IOException(jnie);
        }
    }

    /**
     * Bind socket to local address.
     */
    @Override
    public void bind(SocketAddress bindpoint) throws IOException {
        if (this.socket != null) {
            this.socket.bind(bindpoint);
        } else {
            super.bind(bindpoint);
        }
    }

    /**
     * Connects the underlying Socket associated with this SSLSocket.
     *
     * Also called by super.connect(SocketAddress).
     *
     * @param endpoint address of peer to connect underlying socket to
     * @param timeout timeout value to set for underlying Socket connection
     *
     * @throws IOException upon error connecting Socket
     */
    @Override
    public synchronized void connect(SocketAddress endpoint, int timeout)
        throws IOException {

        final InetSocketAddress address;

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "entered connect(SocketAddress endpoint, int timeout / " +
            timeout + " ms)");

        if (!(endpoint instanceof InetSocketAddress)) {
            throw new IllegalArgumentException(
                "endpoint is not of type InetSocketAddress");
        }

        if (this.socket != null) {
            this.socket.connect(endpoint, timeout);
        } else {
            super.connect(endpoint, timeout);
        }

        address = (InetSocketAddress)endpoint;
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "Underlying Java Socket connected to peer: " + address);

        /* register host/port for session resumption in case where
           createSocket() was called without host/port, but
           SSLSocket.connect() was explicitly called with SocketAddress */
        if (address != null && EngineHelper != null) {
            EngineHelper.setHostAndPort(
                address.getAddress().getHostAddress(),
                address.getPort());
            EngineHelper.setPeerAddress(address.getAddress());
        }

        /* if user is calling after WolfSSLSession creation, register
           socket fd with native wolfSSL */
        if (ssl != null) {
            checkAndInitSSLSocket();
        }
    }

    @SuppressWarnings("deprecation")
    @Override
    protected synchronized void finalize() throws Throwable {
        if (this.ssl != null) {
            Object readCtx = this.ssl.getIOReadCtx();
            if (readCtx != null &&
                readCtx instanceof ConsumedRecvCtx) {
                ConsumedRecvCtx rctx = (ConsumedRecvCtx)readCtx;
                rctx.closeDataStreams();
            }
            this.ssl.freeSSL();
            this.ssl = null;
            this.EngineHelper = null;
            this.params = null;
        }
        super.finalize();
    }

    /**
     * wolfSSL send callback context, used with SocketSendCallback to
     * gain access to the underlying Socket object.
     */
    class SocketSendCtx {
        private Socket sock = null;

        public SocketSendCtx(Socket s) {
            this.sock = s;
        }

        public Socket getSocket() {
            return this.sock;
        }
    }

    /**
     * wolfSSL receive callback context, used with SocketRecvCallback to
     * gain access to the underlying Socket object.
     */
    class SocketRecvCtx {
        private Socket sock = null;

        public SocketRecvCtx(Socket s) {
            this.sock = s;
        }

        public Socket getSocket() {
            return this.sock;
        }
    }

    /**
     * wolfSSL send callback used when WolfSSLSocket is created
     * based on an existing Java Socket object, where that Socket is not
     * of type java.net.Socket.
     *
     * This is needed in non java.net.Socket cases since not all those
     * subclasses contain an internal file descriptor (fd), or alternatively
     * expect the calling application to do I/O using the InputStream and
     * OutputStream of the Socket */
    class SocketSendCallback implements WolfSSLIOSendCallback {

        /**
         * I/O send callback method.
         * This method acts as the I/O send callback to be used with wolfSSL.
         *
         * @param ssl  the current SSL session object from which the callback
         *             was initiated.
         * @param buf  buffer containing data to be sent to the peer.
         * @param sz   size of data in buffer "<b>buf</b>"
         * @param ctx  I/O context to be used.
         * @return     the number of bytes sent, or an error.
         */
        public int sendCallback(WolfSSLSession ssl,
            byte[] buf, int sz, Object ctx) {

            SocketSendCtx sendCtx = (SocketSendCtx)ctx;
            Socket sock = sendCtx.getSocket();
            OutputStream outStream = null;

            if (sock == null) {
                return WolfSSL.WOLFSSL_CBIO_ERR_GENERAL;
            }

            if (!sock.isConnected() || sock.isClosed()) {
                return WolfSSL.WOLFSSL_CBIO_ERR_CONN_CLOSE;
            }

            try {
                outStream = sock.getOutputStream();
                outStream.write(buf, 0, sz);

            } catch (IOException e) {
                if (sock.isClosed()) {
                    return WolfSSL.WOLFSSL_CBIO_ERR_CONN_CLOSE;
                }
                return WolfSSL.WOLFSSL_CBIO_ERR_GENERAL;

            } catch (NullPointerException |
                     IndexOutOfBoundsException e) {
                return WolfSSL.WOLFSSL_CBIO_ERR_GENERAL;
            }

            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "sent " + sz + " bytes");
            return sz;
        }
    }

    /**
     * wolfSSL receive callback used when WolfSSLSocket is created
     * based on an existing Java Socket object, where that Socket is not
     * of type java.net.Socket.
     *
     * This is needed in non java.net.Socket cases since not all those
     * subclasses contain an internal file descriptor (fd), or alternatively
     * expect the calling application to do I/O using the InputStream and
     * OutputStream of the Socket */
    class SocketRecvCallback implements WolfSSLIORecvCallback {

        /**
         * I/O receive callback method.
         * This method acts as the I/O receive callback to be used with wolfSSL.
         *
         * @param ssl  the current SSL session object from which the callback
         *             was initiated.
         * @param buf  buffer in which the application should place data which
         *             has been received from the peer.
         * @param sz   size of buffer, <b>buf</b>
         * @param ctx  I/O context to be used.
         * @return     the number of bytes read, or an error.
         */
        public int receiveCallback(WolfSSLSession ssl,
            byte[] buf, int sz, Object ctx) {

            final int ret;
            SocketRecvCtx recvCtx = (SocketRecvCtx)ctx;
            Socket sock = recvCtx.getSocket();
            InputStream inStream = null;

            if (sock == null) {
                return WolfSSL.WOLFSSL_CBIO_ERR_GENERAL;
            }

            if (!sock.isConnected() || sock.isClosed()) {
                return WolfSSL.WOLFSSL_CBIO_ERR_CONN_CLOSE;
            }

            try {
                /* Try reading from stream, returns -1 on end of stream.
                 * Blocks until data is available, end of stream is reached,
                 * or an exception is thrown. */
                inStream = sock.getInputStream();
                ret = inStream.read(buf, 0, sz);
                if (ret == -1) {
                    return WolfSSL.WOLFSSL_CBIO_ERR_CONN_CLOSE;
                }

            } catch (IOException e) {
                if (sock.isClosed()) {
                    return WolfSSL.WOLFSSL_CBIO_ERR_CONN_CLOSE;
                }
                return WolfSSL.WOLFSSL_CBIO_ERR_GENERAL;

            } catch (NullPointerException |
                     IndexOutOfBoundsException e) {
                return WolfSSL.WOLFSSL_CBIO_ERR_GENERAL;
            }

            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "received " + ret + " bytes");
            return ret;
        }
    }

    /**
     * wolfSSL receive callback context, used with ConsumedRecvCallback to
     * gain access to underlying Socket and InputStream objects.
     */
    class ConsumedRecvCtx {
        private Socket s = null;
        private DataInputStream consumed = null;
        private DataInputStream sockStream = null;

        public ConsumedRecvCtx(Socket s, InputStream in) {
            this.s = s;
            this.consumed = new DataInputStream(in);
        }

        public synchronized DataInputStream getSocketDataStream()
            throws IOException {

            if (this.s != null) {
                if (this.sockStream == null) {
                    this.sockStream =
                        new DataInputStream(this.s.getInputStream());
                }
                return this.sockStream;
            }
            else {
                return null;
            }
        }

        public synchronized DataInputStream getConsumedDataStream() {
            return this.consumed;
        }

        public synchronized void closeDataStreams()
            throws IOException {
            if (consumed != null) {
                consumed.close();
            }
            if (sockStream != null) {
                sockStream.close();
            }
        }
    }

    /**
     * wolfSSL receive callback used when WolfSSLSocket is created based
     * on an existing Socket and existing InputStream with data to read.
     *
     * This callback will read all data from the pre-existing/populated
     * InputStream first, then start reading from the Socket proper.
     */
    class ConsumedRecvCallback implements WolfSSLIORecvCallback {

        public int receiveCallback(WolfSSLSession ssl, byte[] buf,
            int sz, Object ctx) {

            int ret = 0;

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

                } else if (current != null) {
                    /* read directly from Socket, may throw SocketException
                     * if underlying socket is non-blocking and returns
                     * WANT_READ. */
                    try {
                        ret = current.read(buf, 0, sz);
                        if (ret == -1) {
                            /* no data available, end of stream reached */
                            return 0;
                        }
                    } catch (SocketException se) {
                        return WolfSSL.WOLFSSL_CBIO_ERR_WANT_READ;
                    }
                }
            } catch (IOException e) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.ERROR,
                    () -> "error reading from Socket InputStream");
                ret = WolfSSL.WOLFSSL_CBIO_ERR_GENERAL;
            }

            /* return size read, or error */
            return ret;
        }
    }

    class WolfSSLInputStream extends InputStream {

        private WolfSSLSession ssl;
        private WolfSSLSocket  socket;
        private volatile boolean isClosed = true;

        /* Atomic boolean to indicate if this InputStream has started to
         * close. Protects against deadlock between two threads calling
         * SSLSocket.close() and InputStream.close() simulatenously. */
        private AtomicBoolean isClosing = new AtomicBoolean(false);

        public WolfSSLInputStream(WolfSSLSession ssl, WolfSSLSocket socket) {
            this.ssl = ssl;
            this.socket = socket; /* parent socket */
            this.isClosed = false;
        }

        /**
         * Non standard method to check if this InputStream has been
         * closed. This is used by WolfSSLSocket to check if the associated
         * WolfSSLInputStream has been closed before calling freeSSL()
         * internally.
         *
         * @return true if this InputStream has been closed, otherwise false
         */
        public boolean isClosed() {
            return this.isClosed;
        }

        /**
         * Close InputStream, but gives caller option to close underlying
         * Socket or not.
         *
         * @param closeSocket close underlying WolfSSLSocket if set to true,
         *        otherwise if false leave WolfSSLSocket open.
         */
        protected void close(boolean closeSocket) throws IOException {

            if (isClosing.compareAndSet(false, true)) {

                if (closeSocket) {
                    if (this.socket == null || this.isClosed) {
                        /* Reset "is closing" state to false and return */
                        isClosing.set(false);
                        return;
                    }

                    if (this.socket.isClosed()) {
                        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                            () -> "socket (input) already closed");
                    }
                    else {
                        this.socket.close();
                        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                            () -> "socket (input) closed: " + this.socket);
                    }
                }

                this.isClosed = true;

                /* Reset "is closing" state to false, now closed */
                isClosing.set(false);
            }
            else {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "InputStream already in process of being closed");
            }

            return;
        }

        /**
         * Close InputStream, also closes internal WolfSSLSocket.
         */
        public void close() throws IOException {
            close(true);
        }

        @Override
        public synchronized int read() throws IOException {

            int ret;
            byte[] data = new byte[1];

            try {
                ret = this.read(data, 0, 1);

                /* check for end of stream and other errors */
                if (ret < 0) {
                    return ret;
                }

            } catch (NullPointerException ne) {
                throw new IOException(ne);

            } catch (IndexOutOfBoundsException ioe) {
                throw new IndexOutOfBoundsException(ioe.toString());
            }

            return (data[0] & 0xFF);
        }

        public synchronized int read(byte[] b)
            throws NullPointerException, IOException {

            return this.read(b, 0, b.length);
        }

        public synchronized int read(byte[] b, int off, int len)
            throws NullPointerException, IndexOutOfBoundsException,
                   IOException {

            final int ret;

            if (b == null) {
                throw new NullPointerException("Input array is null");
            }

            /* check if socket is closing */
            if (isClosing.get()) {
                throw new SocketException(
                    "InputStream in process of being closed");
            }

            /* check if socket is closed */
            if (this.isClosed || socket == null || socket.isClosed()) {
                throw new SocketException("Socket is closed");
            }

            /* check if connection has already been closed/shutdown */
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "trying to get socket.handshakeLock (read)");

            synchronized (socket.handshakeLock) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "thread got socket.handshakeLock (read)");

                if (socket.connectionClosed == true) {
                    throw new SocketException("Connection already shutdown");
                }
            }

            /* do handshake if not completed yet, handles synchronization */
            try {
                /* do handshake if not completed yet, handles synchronization */
                if (socket.handshakeComplete == false &&
                    socket.handshakeStarted == false) {
                    socket.startHandshake();
                }
            } catch (SocketTimeoutException e) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "got socket timeout in read()");
                throw e;
            }

            if (b.length == 0 || len == 0) {
                return 0;
            }

            if (off < 0 || len < 0 || len > (b.length - off)) {
                throw new IndexOutOfBoundsException(
                    "Array index out of bounds");
            }

            /* Enter I/O operation to prevent use-after-free */
            socket.enterIOOperation();

            try {
                int err;
                int timeout = socket.getSoTimeout();

                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "ssl.read() socket timeout = " + timeout);

                ret = ssl.read(b, off, len, timeout);
                err = ssl.getError(ret);

                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "ssl.read(off: " + off + ", len: " + len +
                    ") ret = " + ret + ", err = " + err);

                /* check for end of stream */
                if ((err == WolfSSL.SSL_ERROR_ZERO_RETURN) ||
                    ((err == WolfSSL.SSL_ERROR_SOCKET_PEER_CLOSED) &&
                     (ret == 0))) {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        () -> "ssl.read() got SSL_ERROR_ZERO_RETURN, " + err +
                        ", end of stream");

                    /* End of stream */
                    return -1;
                }

                if (ret < 0) {
                    /* other errors besides end of stream or WANT_READ
                     * are treated as I/O errors and throw an exception */
                    String errStr = WolfSSL.getErrorString(err);
                    if (err == WolfSSL.SOCKET_ERROR_E) {
                        /* Socket error, indicate to caller by returning
                         * end of stream */
                        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                            () -> "Native wolfSSL_read() error: " + errStr +
                            " (error code: " + err + "ret: " + ret +
                            "), end of stream");
                        return -1;

                    } else {
                        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                            () -> "Native wolfSSL_read() error: " + errStr +
                            " (error code: " + err + ", ret: " + ret + ")");
                        throw new IOException("Native wolfSSL_read() " +
                            "error: " + errStr +
                            " (error code: " + err + ", ret: " + ret + ")");
                    }
                }

            } catch (SocketException e) {
                /* ssl.read() can throw SocketException from poll() if fd
                 * closed or peer shut down connection */
                if (e.getMessage().contains("fd closed during poll") ||
                    e.getMessage().contains("disconnected during poll")) {
                    /* end of stream */
                    return -1;
                }
                throw e;

            } catch (IllegalStateException e) {
                /* SSLSocket.close() may have already called freeSSL(),
                 * thus causing a 'WolfSSLSession object has been freed'
                 * IllegalStateException to be thrown from
                 * WolfSSLSession.read(). Return as a SocketException here. */
                throw new SocketException(e.getMessage());
            } finally {
                /* Exit I/O operation */
                socket.exitIOOperation();
            }

            /* return number of bytes read */
            return ret;
        }
    } /* end WolfSSLInputStream inner class */

    class WolfSSLOutputStream extends OutputStream {

        private WolfSSLSession ssl;
        private WolfSSLSocket  socket;
        private volatile boolean isClosed = true;

        /* Atomic boolean to indicate if this InputStream has started to
         * close. Protects against deadlock between two threads calling
         * SSLSocket.close() and InputStream.close() simulatenously. */
        private AtomicBoolean isClosing = new AtomicBoolean(false);

        public WolfSSLOutputStream(WolfSSLSession ssl, WolfSSLSocket socket) {
            this.ssl = ssl;
            this.socket = socket; /* parent socket */
            this.isClosed = false;
        }

        /**
         * Non standard method to check if this OutputStream has been
         * closed. This is used by WolfSSLSocket to check if the associated
         * WolfSSLOutputStream has been closed before calling freeSSL()
         * internally.
         *
         * @return true if this OutputStream has been closed, otherwise false
         */
        public boolean isClosed() {
            return this.isClosed;
        }

        /**
         * Close OutputStream, but gives caller option to close underlying
         * Socket or not.
         *
         * @param closeSocket close underlying WolfSSLSocket if set to true,
         *        otherwise if false leave WolfSSLSocket open.
         */
        protected void close(boolean closeSocket) throws IOException {

            if (isClosing.compareAndSet(false, true)) {

                if (closeSocket) {
                    if (this.socket == null || this.isClosed) {
                        /* Reset "is closing" state to false and return */
                        isClosing.set(false);
                        return;
                    }

                    if (this.socket.isClosed()) {
                        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                            () -> "socket (output) already closed");
                    }
                    else {
                        this.socket.close();
                        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                            () -> "socket (output) closed: " + this.socket);
                    }
                }

                this.isClosed = true;

                /* Reset "is closing" state to false, now closed */
                isClosing.set(false);
            }
            else {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "OutputStream already in process of being closed");
            }

            return;
        }

        /**
         * Close OutputStream, also closes internal WolfSSLSocket.
         */
        public void close() throws IOException {
            this.close(true);
        }

        public void write(int b) throws IOException {
            byte[] data = new byte[1];
            data[0] = (byte)(b & 0xFF);

            this.write(data, 0, 1);
        }

        public void write(byte[] b) throws IOException {
            this.write(b, 0, b.length);
        }

        public synchronized void write(byte[] b, int off, int len)
            throws IOException {

            int ret;

            if (b == null) {
                throw new NullPointerException("Input array is null");
            }

            /* check if socket is closing */
            if (isClosing.get()) {
                throw new SocketException(
                    "OutputStream in process of being closed");
            }

            /* check if socket is closed */
            if (this.isClosed || socket == null || socket.isClosed()) {
                throw new SocketException("Socket is closed");
            }

            /* check if connection has already been closed/shutdown */
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "trying to get socket.handshakeLock (write)");

            synchronized (socket.handshakeLock) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "thread got socket.handshakeLock (write)");
                if (socket.connectionClosed == true) {
                    throw new SocketException(
                        "Connection already shutdown");
                }
            }

            try {
                /* do handshake if not completed yet, handles synchronization */
                if (socket.handshakeComplete == false &&
                    socket.handshakeStarted == false) {
                    socket.startHandshake();
                }
            } catch (SocketTimeoutException e) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "got socket timeout in write()");
                throw e;
            }

            if (off < 0 || len < 0 || (off + len) > b.length) {
                throw new IndexOutOfBoundsException(
                    "Array index out of bounds");
            }

            /* Enter I/O operation to prevent use-after-free */
            socket.enterIOOperation();

            try {
                int err;
                int timeout = socket.getSoTimeout();

                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "ssl.write() socket timeout = " + timeout);

                ret = ssl.write(b, off, len, timeout);
                err = ssl.getError(ret);

                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "ssl.write(off: " + off + ", len: " + len +
                    ") returned ret = " + ret + ", err = " + err);

                /* check for end of stream */
                if (err == WolfSSL.SSL_ERROR_ZERO_RETURN) {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        () -> "ssl.write() got SSL_ERROR_ZERO_RETURN, " +
                        "end of stream");

                    /* check to see if we received a close notify alert.
                     * if so, throw SocketException since peer has closed
                     * the connection */
                    if (ssl.gotCloseNotify() == true) {
                        throw new SocketException("Peer closed connection");
                    }
                }

                if (ret < 0) {
                    /* print error description string */
                    String errStr = WolfSSL.getErrorString(err);
                    throw new IOException("Native wolfSSL_write() error: " +
                        errStr + " (ret: " + ret + ", error code: " +
                        err + ")");
                }

            } catch (IllegalStateException e) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                                 () -> "got IllegalStateException: " + e +
                                 ", throwing IOException");
                throw new IOException(e);
            } finally {
                /* Exit I/O operation */
                socket.exitIOOperation();
            }
        }
    } /* end WolfSSLOutputStream inner class */
}

