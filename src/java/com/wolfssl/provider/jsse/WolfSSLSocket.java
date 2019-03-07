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

import java.util.ArrayList;
import java.io.InputStream;
import java.io.IOException;
import java.io.ByteArrayOutputStream;
import java.net.Socket;
import java.net.InetAddress;
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
import java.security.SecureRandom;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateEncodingException;

import com.wolfssl.provider.jsse.WolfSSLParameters.TLS_VERSION;

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLContext;
import com.wolfssl.WolfSSLSession;
import com.wolfssl.WolfSSLException;
import com.wolfssl.WolfSSLJNIException;


public class WolfSSLSocket extends SSLSocket {

    private WolfSSLParameters params = null;

    /* WOLFSSL_CTX reference, passed down to this class */
    private WolfSSLContext ctx = null;

    /* WOLFSSL reference, created in this class */
    private WolfSSLSession ssl = null;

    private Socket socket = null;
    private boolean autoClose;
    private InetSocketAddress address = null;

    public WolfSSLSocket(WolfSSLContext context, WolfSSLParameters parameters)
        throws IOException {
        super();
        this.ctx = context;
        this.params = parameters;
        initSSL();
    }

    public WolfSSLSocket(WolfSSLContext context, WolfSSLParameters parameters,
        InetAddress host, int port) throws IOException {
        super(host, port);
        this.ctx = context;
        this.params = parameters;
        initSSL();
    }

    public WolfSSLSocket(WolfSSLContext context, WolfSSLParameters parameters,
        InetAddress address, int port, InetAddress localAddress, int localPort)
        throws IOException {
        super(address, port, localAddress, localPort);
        this.ctx = context;
        this.params = parameters;
        initSSL();
    } 

    public WolfSSLSocket(WolfSSLContext context, WolfSSLParameters parameters,
        String host, int port) throws IOException {
        super(host, port);
        this.ctx = context;
        this.params = parameters;
        initSSL();
    }

    public WolfSSLSocket(WolfSSLContext context, WolfSSLParameters parameters,
        String host, int port, InetAddress localHost, int localPort)
        throws IOException {
        super(host, port, localHost, localPort);
        this.ctx = context;
        this.params = parameters;
        initSSL();
    }

    public WolfSSLSocket(WolfSSLContext context, WolfSSLParameters parameters,
        Socket s, String host, int port, boolean autoClose) throws IOException {
        super();
        this.ctx = context;
        this.params = parameters;
        this.socket = s;
        this.autoClose = autoClose;
        this.address = new InetSocketAddress(host, port);
        initSSL();
    }

    private void initSSL() throws IOException {

        try {
            /* initialize WolfSSLSession object, which wraps the native
             * WOLFSSL structure. */
            ssl = new WolfSSLSession(ctx);

            if (this.socket == null) {
                ssl.setFd(this);
            } else {
                ssl.setFd(this.socket);
            }

        } catch (WolfSSLException we) {
            throw new IOException(we);
        }
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return WolfSSL.getCiphers();
    }

    @Override
    public String[] getEnabledCipherSuites() {
        return getSupportedCipherSuites();
    }

    @Override
    public void setEnabledCipherSuites(String[] suites)
        throws IllegalArgumentException {

        try {
            String list = null;
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

    @Override
    public String[] getSupportedProtocols() {
        /* TODO */
        return null;
    }

    @Override
    public String[] getEnabledProtocols() {
        /* TODO */
        return null;
    }

    @Override
    public void setEnabledProtocols(String[] protocols)
        throws IllegalArgumentException {
        /* TODO */
    }

    @Override
    public SSLSession getSession() {
        /* TODO */
        return null;
    }

    @Override
    public void addHandshakeCompletedListener(
        HandshakeCompletedListener listener) throws IllegalArgumentException {
        /* TODO */
    }

    @Override
    public void removeHandshakeCompletedListener(
        HandshakeCompletedListener listener) throws IllegalArgumentException {
        /* TODO */
    }

    @Override
    public void startHandshake() throws IOException {
        /* TODO */
    }

    @Override
    public void setUseClientMode(boolean mode) throws IllegalArgumentException {
        /* TODO */
    }

    @Override
    public boolean getUseClientMode() {
        /* TODO */
        return false;
    }

    @Override
    public void setNeedClientAuth(boolean need) {
        /* TODO */
    }

    @Override
    public boolean getNeedClientAuth() {
        /* TODO */
        return false;
    }

    @Override
    public void setWantClientAuth(boolean want) {
        /* TODO */
    }

    @Override
    public boolean getWantClientAuth() {
        /* TODO */
        return false;
    }

    @Override
    public void setEnableSessionCreation(boolean flag) {
        /* TODO */
    }

    @Override
    public boolean getEnableSessionCreation() {
        /* TODO */
        return false;
    }
}

