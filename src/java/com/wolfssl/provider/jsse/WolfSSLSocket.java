/* WolfSSLSocket.java
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
import java.util.Arrays;
import java.nio.channels.SocketChannel;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLParameters;

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLContext;
import com.wolfssl.WolfSSLException;
import com.wolfssl.WolfSSLIORecvCallback;
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

    private ArrayList<HandshakeCompletedListener> hsListeners = null;
    private WolfSSLDebug debug;

    /** TLS handshake initialization called */
    protected volatile boolean handshakeInitCalled = false;
    /** TLS handshake has completed */
    protected volatile boolean handshakeComplete = false;
    /** Connection to peer has closed */
    protected volatile boolean connectionClosed = false;

    /* lock for handshakInitCalled and handshakeComplete */
    final private Object handshakeLock = new Object();

    /* protect read/write/connect/accept from multiple threads simultaneously
     * entering library */
    final private Object ioLock = new Object();

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
            "creating new WolfSSLSocket(clientMode: " +
            String.valueOf(clientMode) + ")");

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
            "creating new WolfSSLSocket(clientMode: " +
            String.valueOf(clientMode) + ", InetAddress, port: " +
            port + ")");

        try {
            initSSL();
            setFd();

            /* get helper class for common methods */
            EngineHelper = new WolfSSLEngineHelper(this.ssl, this.authStore,
                    this.params, port, host.getHostName());
            EngineHelper.setUseClientMode(clientMode);

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
            "creating new WolfSSLSocket(clientMode: " +
            String.valueOf(clientMode) + ", InetAddress, port: " +
            port + ", InetAddress, localPort: " + localPort + ")");

        try {
            initSSL();
            setFd();

            /* get helper class for common methods */
            EngineHelper = new WolfSSLEngineHelper(this.ssl, this.authStore,
                    this.params, port, address.getHostName());
            EngineHelper.setUseClientMode(clientMode);

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
            "creating new WolfSSLSocket(clientMode: " +
            String.valueOf(clientMode) + ", host: " + host + ", port: " +
            port + ")");

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
            "creating new WolfSSLSocket(clientMode: " +
            String.valueOf(clientMode) + ", host: " + host + ", port: " +
            port + ", InetAddress, locaPort: " + localPort + ")");

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
            "creating new WolfSSLSocket(clientMode: " +
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
            setFd();

            /* get helper class for common methods */
            EngineHelper = new WolfSSLEngineHelper(this.ssl, this.authStore,
                    this.params, port, host);
            EngineHelper.setUseClientMode(clientMode);

        } catch (WolfSSLException e) {
            throw new IOException(e);
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
    public final int getReceiveBufferSize() throws SocketException {
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
    public final int getSendBufferSize() throws SocketException {
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
        throw new SocketException("sendUrgentData() not supported by "
                + "WolfSSLSocket");
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
    public final void setReceiveBufferSize(int size) throws SocketException {
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
    public final void setSendBufferSize(int size) throws SocketException {
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
        throw new UnsupportedOperationException("shutdownInput() not " +
                "supported by wolfSSLSocket");
    }

    /**
     * shutdownOutput() not supported with SSLSocket, matches OpenJDK behavior.
     */
    @Override
    public final void shutdownOutput() throws IOException {
        throw new UnsupportedOperationException("shutdownOutput() not " +
                "supported by wolfSSLSocket");
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
            "creating new WolfSSLSocket(clientMode: " +
            String.valueOf(clientMode) + ", Socket, autoClose: " +
            String.valueOf(autoClose) + ")");

        if (!s.isConnected()) {
            throw new IOException("Socket is not connected");
        }

        try {
            initSSL();
            setFd();

            /* get helper class for common methods */
            EngineHelper = new WolfSSLEngineHelper(this.ssl, this.authStore,
                    this.params, s.getPort(),
                    s.getInetAddress().getHostName());
            EngineHelper.setUseClientMode(clientMode);

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
            "creating new WolfSSLSocket(Socket, InputStream, autoClose: " +
            String.valueOf(autoClose) + ")");

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
                    s.getInetAddress().getHostName());
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
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "created new native WOLFSSL");
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
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "registered SSLSocket with native wolfSSL");

        } else {
            ret = ssl.setFd(this.socket);
            if (ret != WolfSSL.SSL_SUCCESS) {
                throw new WolfSSLException("Failed to set native Socket fd");
            }
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "registered Socket with native wolfSSL");
        }
    }

    /**
     * Returns the supported cipher suite list for this socket, and that
     * have been compiled into native wolfSSL library.
     *
     * @return array of supported cipher suite Strings
     */
    @Override
    public String[] getSupportedCipherSuites() {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getSupportedCipherSuites()");

        return EngineHelper.getAllCiphers();
    }

    /**
     * Returns array of enabled cipher suites for this Socket.
     * This array is pre-populated by wolfJSSE with the cipher suites
     * supported by the native wolfSSL library

     * @return array of enabled cipher suite Strings
     */
    @Override
    synchronized public String[] getEnabledCipherSuites() {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getEnabledCipherSuites()");

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
    synchronized public void setEnabledCipherSuites(String[] suites)
        throws IllegalArgumentException {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered setEnabledCipherSuites()");

        /* sets cipher suite(s) to be used for connection */
        EngineHelper.setCiphers(suites);
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "enabled cipher suites set to: " + Arrays.toString(suites));
    }

    /**
     * Returns array of protocols supported by this SSLSocket.
     *
     * @return String array containing supported SSL/TLS protocols
     */
    @Override
    public String[] getSupportedProtocols() {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getSupportedProtocols()");

        /* returns all protocol version supported by native wolfSSL */
        return EngineHelper.getAllProtocols();
    }

    /**
     * Returns SSL/TLS protocols enabled for this SSLSocket.
     *
     * @return String array containing enabled protocols
     */
    @Override
    synchronized public String[] getEnabledProtocols() {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getEnabledProtocols()");

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
    synchronized public void setEnabledProtocols(String[] protocols)
        throws IllegalArgumentException {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered setEnabledProtocols()");

        /* sets protocol versions to be enabled for use with this session */
        EngineHelper.setProtocols(protocols);
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "enabled protocols set to: " + Arrays.toString(protocols));
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
    synchronized public void setAlpnProtocols(byte[] alpnProtos) {

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
    synchronized public byte[] getAlpnSelectedProtocol() {
        return EngineHelper.getAlpnSelectedProtocol();
    }

    /**
     * Returns the SSLSession in use by this SSLSocket.
     *
     * @return SSLSession object, otherwise null if not handshaking or
     *         Socket has not progressed enough to create the session
     */
    @Override
    synchronized public SSLSession getSession() {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getSession()");

        try {
            /* try to do handshake if not completed yet, handles synchronization */
            if (this.handshakeComplete == false) {
                this.startHandshake();
            }
        } catch (Exception e) {
            /* Log error, but continue. Session returned will be empty */
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "Handshake attempt failed in SSLSocket.getSession()");
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
    synchronized public void addHandshakeCompletedListener(
        HandshakeCompletedListener listener) throws IllegalArgumentException {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered addHandshakeCompletedListener()");

        if (listener == null) {
            throw new IllegalArgumentException("HandshakeCompletedListener " +
                "is null");
        }

        if (hsListeners == null) {
            hsListeners = new ArrayList<HandshakeCompletedListener>();
        }

        hsListeners.add(listener);
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "registered new HandshakeCompletedListener");
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
    synchronized public void removeHandshakeCompletedListener(
        HandshakeCompletedListener listener) throws IllegalArgumentException {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered removeHandshakeCompletedListener()");

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
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "removed HandshakeCompletedListener");
    }

    /**
     * Begins the SSL/TLS handshake on this SSLSocket.
     *
     * @throws IOException if a network error occurs
     */
    @Override
    synchronized public void startHandshake() throws IOException {
        int ret;

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered startHandshake()");

        synchronized (handshakeLock) {
            if (handshakeComplete == true) {
                /* handshake already finished */
                return;
            }

            if (handshakeInitCalled == false) {
                /* will throw SSLHandshakeException if session creation is
                   not allowed */
                EngineHelper.initHandshake();
                handshakeInitCalled = true;
            }
        }

        synchronized (ioLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                             "thread got ioLock (handshake)");

            try {
                ret = EngineHelper.doHandshake(0, this.getSoTimeout());
            } catch (SocketTimeoutException e) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        "got socket timeout in doHandshake()");
                throw e;
            }

            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                             "thread exiting ioLock (handshake)");
        }

        if (ret != WolfSSL.SSL_SUCCESS) {
            int err = ssl.getError(ret);
            String errStr = WolfSSL.getErrorString(err);

            throw new SSLHandshakeException(errStr + " (error code: " +
                err + ")");
        }

        synchronized (handshakeLock) {
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
                "completed SSL/TLS handshake, listeners notified");

        /* print debug info about connection, if enabled */
        if (EngineHelper.getSession() != null) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "SSL/TLS protocol version: " +
                EngineHelper.getSession().getProtocol());
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "SSL/TLS cipher suite: " +
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
    synchronized public void setUseClientMode(boolean mode)
        throws IllegalArgumentException {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered setUseClientMode()");

        EngineHelper.setUseClientMode(mode);
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "socket client mode set to: " + mode);
    }

    /**
     * Return the client mode of this SSLSocket.
     *
     * @return true if in client mode, otherwise false for server mode
     */
    @Override
    synchronized public boolean getUseClientMode() {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getUseClientMode()");

        return EngineHelper.getUseClientMode();
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
    synchronized public void setNeedClientAuth(boolean need) {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered setNeedClientAuth(need: " + String.valueOf(need) + ")");

        EngineHelper.setNeedClientAuth(need);
    }

    /**
     * Return if mandatory client authentication is set for this SSLSocket.
     *
     * @return true if Socket has been configured to require client auth,
     *         otherwise false
     */
    @Override
    synchronized public boolean getNeedClientAuth() {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getNeedClientAuth()");

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
    synchronized public void setWantClientAuth(boolean want) {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered setWantClientAuth(want: " + String.valueOf(want) + ")");

        EngineHelper.setWantClientAuth(want);
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
    synchronized public boolean getWantClientAuth() {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getWantClientAuth()");

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
    synchronized public void setEnableSessionCreation(boolean flag) {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered setEnableSessionCreation(flag: " +
            String.valueOf(flag) + ")");

        EngineHelper.setEnableSessionCreation(flag);
    }

    /**
     * Returns whether this SSLSocket can create new sessions.
     *
     * @return true if this Socket can create new sessions, otherwise false
     */
    @Override
    synchronized public boolean getEnableSessionCreation() {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getEnableSessionCreation()");

        return EngineHelper.getEnableSessionCreation();
    }

    /**
     * Enables use of session tickets with this session. Disabled by default.
     *
     * @param useTickets true to enable session tickets, otherwise false
     */
    synchronized public void setUseSessionTickets(boolean useTickets) {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered setUseSessionTickets(flag: " +
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
    public InputStream getInputStream() throws IOException {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getInputStream()");

        if (inStream == null) {
            inStream = new WolfSSLInputStream(ssl, this);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "created WolfSSLInputStream");
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
    public OutputStream getOutputStream() throws IOException {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getOutputStream()");

        if (outStream == null) {
            outStream = new WolfSSLOutputStream(ssl, this);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "created WolfSSLOutputStream");
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
        if (this.socket != null) {
            this.socket.setSoTimeout(timeout);
        } else {
            super.setSoTimeout(timeout);
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
        if (this.socket != null) {
            return this.socket.getSoTimeout();
        } else {
            return super.getSoTimeout();
        }
    }

    /**
     * Set the SSLParameters for this SSLSocket.
     *
     * @param params SSLParameters to set for this SSLSocket object
     */
    synchronized public void setSSLParameters(SSLParameters params) {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered setSSLParameters()");

        if (params != null) {
            WolfSSLParametersHelper.importParams(params, this.params);
        }
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
    synchronized public void close() throws IOException {

        int ret;
        boolean beforeObjectInit = false;

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered close()");

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
                /* Check if underlying Socket is still open before closing,
                 * in case application calls SSLSocket.close() multiple times */
                synchronized (handshakeLock) {
                    if (this.connectionClosed == true ||
                        (this.socket != null && this.socket.isClosed()) ||
                        (this.socket == null && super.isClosed())) {
                        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                            "Socket already closed, skipping TLS shutdown");
                        return;
                    }
                }

                if (ssl != null) {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                            "shutting down SSL/TLS connection");

                    if (this.getUseClientMode() == true ) {
                        EngineHelper.saveSession();
                    }

                    synchronized (ioLock) {
                        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                                         "thread got ioLock (shutdown)");

                        if (this.socket != null) {
                            ret = ssl.shutdownSSL(this.socket.getSoTimeout());
                        } else {
                            ret = ssl.shutdownSSL(super.getSoTimeout());
                        }
                        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                                "ssl.shutdownSSL() ret = " + ret);

                        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                                         "thread exiting ioLock (shutdown)");
                    }

                    synchronized (handshakeLock) {
                        this.connectionClosed = true;

                        /* Connection is closed, free native WOLFSSL session
                         * to release native memory earlier than garbage
                         * collector might with finalize(). */
                        this.ssl.freeSSL();
                        this.ssl = null;
                    }
                }
            }

            if (this.autoClose) {
                if (this.socket != null) {
                    this.socket.close();
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                            "socket (external) closed: " + this.socket);
                } else {
                    super.close();
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                            "socket (super) closed: " + super.toString());
                }
            } else {
                if (this.socket != null) {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                            "socket (external) not closed, autoClose set to false");
                } else {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                            "socket (super) not closed, autoClose set to false");
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
     * @param endpoint address of peer to connect underlying Socket to
     *
     * @throws IOException upon error connecting Socket
     */
    @Override
    synchronized public void connect(SocketAddress endpoint)
        throws IOException {

        InetSocketAddress address = null;

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered connect(SocketAddress endpoint)");

        if (!(endpoint instanceof InetSocketAddress)) {
            throw new IllegalArgumentException("endpoint is not of type " +
                "InetSocketAddress");
        }

        if (this.socket != null) {
            this.socket.connect(endpoint);
        } else {
            super.connect(endpoint);
        }

        address = (InetSocketAddress)endpoint;

        /* register host/port for session resumption in case where
           createSocket() was called without host/port, but
           SSLSocket.connect() was explicitly called with SocketAddress */
        if (address != null && EngineHelper != null) {
            EngineHelper.setHostAndPort(
                address.getAddress().getHostName(),
                address.getPort());
        }

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

    /**
     * Connects the underlying Socket associated with this SSLSocket.
     *
     * @param endpoint address of peer to connect underlying socket to
     * @param timeout timeout value to set for underlying Socket connection
     *
     * @throws IOException upon error connecting Socket
     */
    @Override
    synchronized public void connect(SocketAddress endpoint, int timeout)
        throws IOException {

        InetSocketAddress address = null;

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered connect(SocketAddress endpoint, int timeout)");

        if (!(endpoint instanceof InetSocketAddress)) {
            throw new IllegalArgumentException("endpoint is not of type " +
                "InetSocketAddress");
        }

        if (this.socket != null) {
            this.socket.connect(endpoint, timeout);
        } else {
            super.connect(endpoint, timeout);
        }

        address = (InetSocketAddress)endpoint;

        /* register host/port for session resumption in case where
           createSocket() was called without host/port, but
           SSLSocket.connect() was explicitly called with SocketAddress */
        if (address != null && EngineHelper != null) {
            EngineHelper.setHostAndPort(
                address.getAddress().getHostName(),
                address.getPort());
        }

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

    @SuppressWarnings("deprecation")
    @Override
    protected void finalize() throws Throwable {
        if (this.ssl != null) {
            this.ssl.freeSSL();
            this.ssl = null;
        }
        super.finalize();
    }

    class ConsumedRecvCtx {
        private Socket s;
        private DataInputStream consumed;

        public ConsumedRecvCtx(Socket s, InputStream in) {
            this.s = s;
            this.consumed = new DataInputStream(in);
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
                        "error reading from Socket InputStream");
                ret = WolfSSL.WOLFSSL_CBIO_ERR_GENERAL;
            }

            /* return size read, or error */
            return ret;
        }
    }

    static class WolfSSLInputStream extends InputStream {

        private WolfSSLSession ssl;
        private WolfSSLSocket  socket;
        final private Object readLock = new Object();

        public WolfSSLInputStream(WolfSSLSession ssl, WolfSSLSocket socket) {
            this.ssl = ssl;
            this.socket = socket; /* parent socket */
        }

        @Override
        public int read() throws IOException {

            int ret = 0;
            byte[] data = new byte[1];

            try {
                ret = this.read(data, 0, 1);

            } catch (NullPointerException ne) {
                throw new IOException(ne);

            } catch (IndexOutOfBoundsException ioe) {
                throw new IndexOutOfBoundsException(ioe.toString());
            }

            return (data[0] & 0xFF);
        }

        public int read(byte[] b) throws NullPointerException, IOException {

            return this.read(b, 0, b.length);
        }

        public int read(byte[] b, int off, int len)
            throws NullPointerException, IndexOutOfBoundsException, IOException {

            int ret = 0;
            byte[] data = null;

            if (b == null) {
                throw new NullPointerException("Input array is null");
            }

            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                             "thread trying to get readLock");

            synchronized (readLock) {

                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                                 "thread got readLock");

                /* check if connection has already been closed/shutdown */
                synchronized (socket.handshakeLock) {
                    if (socket.connectionClosed == true) {
                        throw new SocketException("Connection already shutdown");
                    }
                }

                /* do handshake if not completed yet, handles synchronization */
                try {
                    /* do handshake if not completed yet, handles synchronization */
                    if (socket.handshakeComplete == false) {
                        socket.startHandshake();
                    }
                } catch (SocketTimeoutException e) {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                            "got socket timeout in read()");
                    throw e;
                }

                if (b.length == 0 || len == 0) {
                    return 0;
                }

                if (off < 0 || len < 0 || len > (b.length - off)) {
                    throw new IndexOutOfBoundsException("Array index out of bounds");
                }

                if (off != 0) {
                    /* create new tmp buffer to read data into */
                    data = new byte[len];
                } else {
                    data = b;
                }

                try {
                    int err;

                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        "ssl.read() socket timeout = " + socket.getSoTimeout());

                    ret = ssl.read(data, len, socket.getSoTimeout());
                    err = ssl.getError(ret);

                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        "ssl.read() ret = " + ret + ", err = " + err);

                    /* check for end of stream */
                    if ((err == WolfSSL.SSL_ERROR_ZERO_RETURN) ||
                        ((err == WolfSSL.SSL_ERROR_SOCKET_PEER_CLOSED) && (ret == 0))) {
                        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                            "ssl.read() got SSL_ERROR_ZERO_RETURN, " + err +
                            ", end of stream");

                        /* End of stream */
                        return -1;
                    }

                    if (ret < 0) {
                        /* other errors besides end of stream or WANT_READ
                         * are treated as I/O errors and throw an exception */
                        String errStr = WolfSSL.getErrorString(err);
                        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                            "Native wolfSSL_read() error: " + errStr +
                            " (error code: " + err + ")");
                        throw new IOException("Native wolfSSL_read() " +
                            "error: " + errStr +
                            " (error code: " + err + ")");
                    }

                } catch (IllegalStateException e) {
                    throw new IOException(e);
                }

                if (off != 0) {
                    /* copy data into original array at offset */
                    System.arraycopy(data, 0, b, off, ret);
                }

                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                                 "thread exiting readLock");

                /* return number of bytes read */
                return ret;
            }
        }
    } /* end WolfSSLInputStream inner class */

    static class WolfSSLOutputStream extends OutputStream {

        private WolfSSLSession ssl;
        private WolfSSLSocket  socket;
        final private Object writeLock = new Object();

        public WolfSSLOutputStream(WolfSSLSession ssl, WolfSSLSocket socket) {
            this.ssl = ssl;
            this.socket = socket; /* parent socket */
        }

        public void write(int b) throws IOException {
            byte[] data = new byte[1];
            data[0] = (byte)(b & 0xFF);

            this.write(data, 0, 1);
        }

        public void write(byte[] b) throws IOException {
            this.write(b, 0, b.length);
        }

        public void write(byte[] b, int off, int len) throws IOException {

            int ret;
            byte[] data = null;

            if (b == null) {
                throw new NullPointerException("Input array is null");
            }

            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                             "thread trying to get writeLock");

            synchronized (writeLock) {

                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                                 "thread got writeLock");

                /* check if connection has already been closed/shutdown */
                synchronized (socket.handshakeLock) {
                    if (socket.connectionClosed == true) {
                        throw new SocketException("Connection already shutdown");
                    }
                }

                try {
                    /* do handshake if not completed yet, handles synchronization */
                    if (socket.handshakeComplete == false) {
                        socket.startHandshake();
                    }
                } catch (SocketTimeoutException e) {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                            "got socket timeout in write()");
                    throw e;
                }

                if (off < 0 || len < 0 || (off + len) > b.length) {
                    throw new IndexOutOfBoundsException("Array index out of bounds");
                }

                if (off != 0) {
                    data = new byte[len];
                    System.arraycopy(b, off, data, 0, len);
                } else {
                    data = b;
                }

                try {
                    int err;

                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        "ssl.write() socket timeout = " +
                        socket.getSoTimeout());

                    ret = ssl.write(data, len, socket.getSoTimeout());
                    err = ssl.getError(ret);

                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        "ssl.write returned ret = " + ret + ", err = " + err);

                    /* check for end of stream */
                    if (err == WolfSSL.SSL_ERROR_ZERO_RETURN) {
                        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                            "ssl.write() got SSL_ERROR_ZERO_RETURN, " +
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
                        throw new IOException("Native wolfSSL_write() error: "
                                + errStr + " (error code: " + err + ")");
                    }

                } catch (IllegalStateException e) {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                                     "got IllegalStateException: " + e +
                                     ", throwing IOException");
                    throw new IOException(e);
                }

                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                                 "thread exiting writeLock");
            }
        }
    } /* end WolfSSLOutputStream inner class */

}

