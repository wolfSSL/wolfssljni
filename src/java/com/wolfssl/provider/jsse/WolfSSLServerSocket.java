/* WolfSSLServerSocket.java
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
import java.net.Socket;
import java.net.InetAddress;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLParameters;

import com.wolfssl.WolfSSLContext;

public class WolfSSLServerSocket extends SSLServerSocket {

    private WolfSSLSocket socket = null;

    public WolfSSLServerSocket(WolfSSLContext context,
            WolfSSLAuthStore authStore,
            SSLParameters params) throws IOException {

        super();
        socket = new WolfSSLSocket(context, authStore, params);
    }

    public WolfSSLServerSocket(WolfSSLContext context,
            WolfSSLAuthStore authStore, SSLParameters params, int port)
        throws IOException {

        super(port);
        socket = new WolfSSLSocket(context, authStore, params);
    }

    public WolfSSLServerSocket(WolfSSLContext context,
            WolfSSLAuthStore authStore,
            SSLParameters params, int port, int backlog)
        throws IOException {

        super(port, backlog);
        socket = new WolfSSLSocket(context, authStore, params);
    } 

    public WolfSSLServerSocket(WolfSSLContext context,
            WolfSSLAuthStore authStore,
            SSLParameters params, int port, int backlog, InetAddress address)
        throws IOException {

        super(port, backlog, address);
        socket = new WolfSSLSocket(context, authStore, params);
    }

    @Override
    public String[] getEnabledCipherSuites() {
        return socket.getEnabledCipherSuites();
    }

    @Override
    public void setEnabledCipherSuites(String[] suites)
        throws IllegalArgumentException {
        socket.setEnabledCipherSuites(suites);
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return socket.getSupportedCipherSuites();
    }

    @Override
    public String[] getSupportedProtocols() {
        return socket.getSupportedProtocols();
    }

    @Override
    public String[] getEnabledProtocols() {
        return socket.getEnabledProtocols();
    }

    @Override
    public void setEnabledProtocols(String[] protocols)
        throws IllegalArgumentException {
        socket.setEnabledProtocols(protocols);
    }

    @Override
    public void setNeedClientAuth(boolean need) {
        socket.setNeedClientAuth(need);
    }

    @Override
    public boolean getNeedClientAuth() {
        return socket.getNeedClientAuth();
    }

    @Override
    public void setWantClientAuth(boolean want) {
        socket.setWantClientAuth(want);
    }

    @Override
    public boolean getWantClientAuth() {
        return socket.getWantClientAuth();
    }

    @Override
    public void setUseClientMode(boolean mode) throws IllegalArgumentException {
        socket.setUseClientMode(mode);
    }

    @Override
    public boolean getUseClientMode() {
        return socket.getUseClientMode();
    }

    @Override
    public void setEnableSessionCreation(boolean flag) {
        socket.setEnableSessionCreation(flag);
    }

    @Override
    public boolean getEnableSessionCreation() {
        return socket.getEnableSessionCreation();
    }

    @Override
    public Socket accept() throws IOException {

        /* protected method inherited from ServerSocket, returns
           a connected (WolfSSLSocket) socket */
        implAccept(socket);

        return socket;
    }
}

