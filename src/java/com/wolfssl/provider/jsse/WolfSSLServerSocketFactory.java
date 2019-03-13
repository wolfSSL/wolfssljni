/* WolfSSLServerSocketFactory.java
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

import java.io.IOException;
import java.net.InetAddress;
import javax.net.ssl.SSLServerSocketFactory;
import java.net.ServerSocket;
import javax.net.ssl.SSLParameters;

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLContext;

public class WolfSSLServerSocketFactory extends SSLServerSocketFactory {

    private WolfSSLAuthStore authStore = null;
    private WolfSSLContext ctx = null;
    private SSLParameters params;

    public WolfSSLServerSocketFactory(com.wolfssl.WolfSSLContext ctx,
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
    public ServerSocket createServerSocket() throws IOException {
        return new WolfSSLServerSocket(ctx, authStore, params);
    }

    @Override
    public ServerSocket createServerSocket(int port) throws IOException {
        return new WolfSSLServerSocket(ctx, authStore, params, port);
    }

    @Override
    public ServerSocket createServerSocket(int port, int backlog)
        throws IOException {
        return new WolfSSLServerSocket(ctx, authStore, params, port, backlog);
    }

    @Override
    public ServerSocket createServerSocket(int port, int backlog,
        InetAddress ifAddress) throws IOException {
        return new WolfSSLServerSocket(ctx, authStore, params, port,
            backlog, ifAddress);
    }
}

