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

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLContext;

public class WolfSSLServerSocket extends SSLServerSocket {

    private WolfSSLContext context = null;
    private WolfSSLAuthStore authStore = null;
    private SSLParameters params = null;

    private boolean clientMode = false;
    private boolean enableSessionCreation = true;
    private WolfSSLSocket socket = null;

    public WolfSSLServerSocket(WolfSSLContext context,
            WolfSSLAuthStore authStore,
            SSLParameters params) throws IOException {

        super();

        /* defer creating WolfSSLSocket until accept() is called */
        this.context = context;
        this.authStore = authStore;
        this.params = params;
    }

    public WolfSSLServerSocket(WolfSSLContext context,
            WolfSSLAuthStore authStore, SSLParameters params, int port)
        throws IOException {

        super(port);

        /* defer creating WolfSSLSocket until accept() is called */
        this.context = context;
        this.authStore = authStore;
        this.params = params;
    }

    public WolfSSLServerSocket(WolfSSLContext context,
            WolfSSLAuthStore authStore,
            SSLParameters params, int port, int backlog)
        throws IOException {

        super(port, backlog);

        /* defer creating WolfSSLSocket until accept() is called */
        this.context = context;
        this.authStore = authStore;
        this.params = params;
    } 

    public WolfSSLServerSocket(WolfSSLContext context,
            WolfSSLAuthStore authStore,
            SSLParameters params, int port, int backlog, InetAddress address)
        throws IOException {

        super(port, backlog, address);

        /* defer creating WolfSSLSocket until accept() is called */
        this.context = context;
        this.authStore = authStore;
        this.params = params;
    }

    @Override
    public String[] getEnabledCipherSuites() {

        String[] suites = params.getCipherSuites();
        if (suites != null)
            return suites;

        return WolfSSL.getCiphers();
    }

    @Override
    public void setEnabledCipherSuites(String[] suites)
        throws IllegalArgumentException {

        /* set in SSLParameters, WolfSSLSocket should pull from there if set */
        params.setCipherSuites(suites);
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return getEnabledCipherSuites();
    }

    @Override
    public String[] getSupportedProtocols() {

        String[] protos = params.getProtocols();
        if (protos != null)
            return protos;

        return WolfSSL.getProtocols();
    }

    @Override
    public String[] getEnabledProtocols() {
        return getSupportedProtocols();
    }

    @Override
    public void setEnabledProtocols(String[] protocols)
        throws IllegalArgumentException {
        params.setProtocols(protocols);
    }

    @Override
    public void setNeedClientAuth(boolean need) {
        params.setNeedClientAuth(need);
    }

    @Override
    public boolean getNeedClientAuth() {
        return params.getNeedClientAuth();
    }

    @Override
    public void setWantClientAuth(boolean want) {
        params.setWantClientAuth(want);
    }

    @Override
    public boolean getWantClientAuth() {
        return params.getWantClientAuth();
    }

    @Override
    public void setUseClientMode(boolean mode) throws IllegalArgumentException {
        clientMode = mode;
    }

    @Override
    public boolean getUseClientMode() {
        return clientMode;
    }

    @Override
    public void setEnableSessionCreation(boolean flag) {
        enableSessionCreation = flag;
    }

    @Override
    public boolean getEnableSessionCreation() {
        return enableSessionCreation;
    }

    @Override
    public Socket accept() throws IOException {

        /* protected method inherited from ServerSocket, returns
           a connected socket */
        Socket sock = new Socket();
        implAccept(sock);

        /* create new WolfSSLSocket wrapping connected Socket */
        socket = new WolfSSLSocket(context, authStore, params,
            clientMode, sock, true);

        socket.setEnableSessionCreation(enableSessionCreation);

        socket.startHandshake();

        return socket;
    }
}

