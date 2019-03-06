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
import com.wolfssl.WolfSSLException;
import com.wolfssl.WolfSSLJNIException;


public class WolfSSLSocket extends SSLSocket {

    private WolfSSLParameters params = null;
    private WolfSSLContext ctx = null;

    public WolfSSLSocket(WolfSSLContext context, WolfSSLParameters parameters) {
        super();
        this.ctx = context;
        this.params = parameters;
    }

    public WolfSSLSocket(WolfSSLContext context, WolfSSLParameters parameters,
        InetAddress host, int port) throws IOException {
        super(host, port);
        this.ctx = context;
        this.params = parameters;
    }

    public WolfSSLSocket(WolfSSLContext context, WolfSSLParameters parameters,
        InetAddress address, int port, InetAddress localAddress, int localPort)
        throws IOException {
        super(address, port, localAddress, localPort);
        this.ctx = context;
        this.params = parameters;
    } 

    public WolfSSLSocket(WolfSSLContext context, WolfSSLParameters parameters,
        String host, int port) throws IOException {
        super(host, port);
        this.ctx = context;
        this.params = parameters;
    }

    public WolfSSLSocket(WolfSSLContext context, WolfSSLParameters parameters,
        String host, int port, InetAddress localHost, int localPort)
        throws IOException {
        super(host, port, localHost, localPort);
        this.ctx = context;
        this.params = parameters;
    }

    @Override
    public String[] getSupportedCipherSuites() {
        /* TODO */
        return null;
    }

    @Override
    public String[] getEnabledCipherSuites() {
        /* TODO */
        return null;
    }

    @Override
    public void setEnabledCipherSuites(String[] suites)
        throws IllegalArgumentException {
        /* TODO */
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

