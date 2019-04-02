/* WolfSSLSocketFactory.java
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
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.KeyManager;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.net.ssl.SSLParameters;
import java.security.SecureRandom;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateEncodingException;

import com.wolfssl.provider.jsse.WolfSSLAuthStore.TLS_VERSION;

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLContext;
import com.wolfssl.WolfSSLException;
import com.wolfssl.WolfSSLJNIException;


public class WolfSSLSocketFactory extends SSLSocketFactory {

    private WolfSSLAuthStore authStore = null;
    private WolfSSLContext ctx = null;
    private SSLParameters params;

    public WolfSSLSocketFactory(com.wolfssl.WolfSSLContext ctx,
            WolfSSLAuthStore authStore, SSLParameters params) {
        super();
        this.ctx = ctx;
        this.authStore = authStore;
        this.params = params;
    }
    
    @Override
    public String[] getDefaultCipherSuites() {
        return WolfSSL.getCiphers();
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return getDefaultCipherSuites();
    }

    @Override
    public Socket createSocket() throws IOException {
        return new WolfSSLSocket(ctx, authStore, params, true);
    }

    @Override
    public Socket createSocket(InetAddress host, int port)
        throws IOException {
        return new WolfSSLSocket(ctx, authStore, params, true, host, port);
    }

    @Override
    public Socket createSocket(InetAddress address, int port,
        InetAddress localAddress, int localPort) throws IOException {
        return new WolfSSLSocket(ctx, authStore, params,
            true, address, port, localAddress, localPort);
    }

    @Override
    public Socket createSocket(String host, int port)
        throws IOException, UnknownHostException {
        return new WolfSSLSocket(ctx, authStore, params, true, host, port);
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localHost,
        int localPort) throws IOException, UnknownHostException {
        return new WolfSSLSocket(ctx, authStore, params,
            true, host, port, localHost, localPort);
    }

    @Override
    public Socket createSocket(Socket s, String host, int port,
        boolean autoClose) throws IOException {
        return new WolfSSLSocket(ctx, authStore, params,
            true, s, host, port, autoClose);
    }

    @Override
    public Socket createSocket(Socket s, InputStream consumed,
        boolean autoClose) throws IOException {
        /* TODO */
        throw new UnsupportedOperationException("not supported by wolfJSSE");
    }
}

