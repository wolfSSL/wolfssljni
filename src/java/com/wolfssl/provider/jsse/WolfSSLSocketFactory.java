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

import java.net.InetAddress;
import java.io.InputStream;
import java.net.Socket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.KeyManager;
import javax.net.ssl.TrustManager;
import java.security.SecureRandom;

import com.wolfssl.provider.jsse.WolfSSLParameters.TLS_VERSION;

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLContext;
import com.wolfssl.WolfSSLException;

import java.io.IOException;
import java.net.UnknownHostException;

public class WolfSSLSocketFactory extends SSLSocketFactory {

    private WolfSSLParameters params = null;
    private WolfSSLContext ctx = null;

    public WolfSSLSocketFactory(WolfSSLParameters parameters)
        throws WolfSSLException {
        super();

        long method = 0;
        this.params = parameters;

        switch (params.getProtocolVersion()) {
            case TLSv1:
                method = WolfSSL.TLSv1_ClientMethod();
                break;
            case TLSv1_1:
                method = WolfSSL.TLSv1_1_ClientMethod();
                break;
            case TLSv1_2:
                method = WolfSSL.TLSv1_2_ClientMethod();
                break;
            case SSLv23:
                method = WolfSSL.SSLv23_ClientMethod();
                break;
            default:
                throw new IllegalArgumentException(
                    "Invalid SSL/TLS protocol version");
        }

        if (method == WolfSSL.NOT_COMPILED_IN) {
            throw new IllegalArgumentException("Protocol version not " +
                "compiled into native wolfSSL library");
        }
        ctx = new WolfSSLContext(method);
    }

    @Override
    public String[] getDefaultCipherSuites() {
        /* TODO */
        return null;
    }

    @Override
    public String[] getSupportedCipherSuites() {
        /* TODO */
        return null;
    }

    @Override
    public Socket createSocket() throws IOException {
        /* TODO */
        return null;
    }

    @Override
    public Socket createSocket(InetAddress host, int port)
        throws IOException {
        /* TODO */
        return null;
    }

    @Override
    public Socket createSocket(InetAddress address, int port,
        InetAddress localAddress, int localPort) throws IOException {
        /* TODO */
        return null;
    }

    @Override
    public Socket createSocket(String host, int port)
        throws IOException, UnknownHostException {
        /* TODO */
        return null;
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localHost,
        int localPort) throws IOException, UnknownHostException {
        /* TODO */
        return null;
    }

    @Override
    public Socket createSocket(Socket s, String host, int port,
        boolean autoClose) throws IOException {
        /* TODO */
        return null;
    }

    @Override
    public Socket createSocket(Socket s, InputStream consumed,
        boolean autoClose) throws IOException {
        /* TODO */
        return null;
    }
}

