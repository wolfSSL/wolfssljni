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

import java.net.InetAddress;
import java.net.ServerSocket;
import javax.net.ssl.SSLServerSocketFactory;

import java.io.IOException;

public class WolfSSLServerSocketFactory extends SSLServerSocketFactory {

    private WolfSSLAuthStore params = null;

    public WolfSSLServerSocketFactory(WolfSSLAuthStore parameters) {
        super();
        this.params = parameters;
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
    public ServerSocket createServerSocket() throws IOException {
        /* TODO */
        return null;
    }

    @Override
    public ServerSocket createServerSocket(int port) throws IOException {
        /* TODO */
        return null;
    }

    @Override
    public ServerSocket createServerSocket(int port, int backlog)
        throws IOException {
        /* TODO */
        return null;
    }

    @Override
    public ServerSocket createServerSocket(int port, int backlog,
        InetAddress ifAddress) throws IOException {
        /* TODO */
        return null;
    }
}

