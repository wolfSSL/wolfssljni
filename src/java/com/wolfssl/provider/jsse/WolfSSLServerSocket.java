/* WolfSSLServerSocket.java
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
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

import java.util.Arrays;
import java.util.List;
import java.io.IOException;
import java.net.Socket;
import java.net.InetAddress;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLParameters;

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLSession;
import com.wolfssl.WolfSSLContext;

/**
 * wolfSSL implementation of SSLServerSocket
 *
 * @author wolfSSL
 */
public class WolfSSLServerSocket extends SSLServerSocket {

    private com.wolfssl.WolfSSLContext context = null;
    private WolfSSLAuthStore authStore = null;
    private SSLParameters params = null;

    private boolean clientMode = false;
    private boolean enableSessionCreation = true;
    private WolfSSLSocket socket = null;
    private WolfSSLDebug debug;

    public WolfSSLServerSocket(com.wolfssl.WolfSSLContext context,
            WolfSSLAuthStore authStore,
            SSLParameters params) throws IOException {

        super();

        /* defer creating WolfSSLSocket until accept() is called */
        this.context = context;
        this.authStore = authStore;
        this.params = WolfSSLEngineHelper.decoupleParams(params);
    }

    public WolfSSLServerSocket(com.wolfssl.WolfSSLContext context,
            WolfSSLAuthStore authStore, SSLParameters params, int port)
        throws IOException {

        super(port);

        /* defer creating WolfSSLSocket until accept() is called */
        this.context = context;
        this.authStore = authStore;
        this.params = WolfSSLEngineHelper.decoupleParams(params);
    }

    public WolfSSLServerSocket(com.wolfssl.WolfSSLContext context,
            WolfSSLAuthStore authStore,
            SSLParameters params, int port, int backlog)
        throws IOException {

        super(port, backlog);

        /* defer creating WolfSSLSocket until accept() is called */
        this.context = context;
        this.authStore = authStore;
        this.params = WolfSSLEngineHelper.decoupleParams(params);
    }

    public WolfSSLServerSocket(com.wolfssl.WolfSSLContext context,
            WolfSSLAuthStore authStore,
            SSLParameters params, int port, int backlog, InetAddress address)
        throws IOException {

        super(port, backlog, address);

        /* defer creating WolfSSLSocket until accept() is called */
        this.context = context;
        this.authStore = authStore;
        this.params = WolfSSLEngineHelper.decoupleParams(params);
    }

    @Override
    synchronized public String[] getEnabledCipherSuites() {
        return params.getCipherSuites();
    }

    @Override
    synchronized public void setEnabledCipherSuites(String[] suites)
        throws IllegalArgumentException {

        if (suites == null) {
            throw new IllegalArgumentException("input array is null");
        }

        if (suites.length == 0) {
            throw new IllegalArgumentException("input array has length zero");
        }

        /* sanitize cipher array for unsupported strings */
        List<String> supported = Arrays.asList(WolfSSL.getCiphersIana());
        for (int i = 0; i < suites.length; i++) {
            if (!supported.contains(suites[i])) {
                throw new IllegalArgumentException("Unsupported CipherSuite: " +
                    suites[i]);
            }
        }

        /* propogated down to WolfSSLEngineHelper in WolfSSLSocket creation */
        params.setCipherSuites(suites);
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "enabled cipher suites set to: " + Arrays.toString(suites));
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return WolfSSL.getCiphersIana();
    }

    @Override
    public String[] getSupportedProtocols() {
        return params.getProtocols();
    }

    @Override
    synchronized public String[] getEnabledProtocols() {
        return params.getProtocols();
    }

    @Override
    synchronized public void setEnabledProtocols(String[] protocols)
        throws IllegalArgumentException {

        if (protocols == null) {
            throw new IllegalArgumentException("input array is null");
        }

        if (protocols.length == 0) {
            throw new IllegalArgumentException("input array has length zero");
        }

        /* sanitize protocol array for unsupported strings */
        List<String> supported;
        supported = Arrays.asList(WolfSSL.getProtocols());
                
        for (int i = 0; i < protocols.length; i++) {
            if (!supported.contains(protocols[i])) {
                throw new IllegalArgumentException("Unsupported protocol: " +
                    protocols[i]);
            }
        }

        /* propogated down to WolfSSLEngineHelper in WolfSSLSocket creation */
        params.setProtocols(protocols);
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "enabled protocols set to: " + Arrays.toString(protocols));
    }

    @Override
    synchronized public void setNeedClientAuth(boolean need) {

        /* propogated down to WolfSSLEngineHelper in WolfSSLSocket creation */
        params.setNeedClientAuth(need);
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "need client auth set to: " + need);
    }

    @Override
    synchronized public boolean getNeedClientAuth() {
        return params.getNeedClientAuth();
    }

    @Override
    synchronized public void setWantClientAuth(boolean want) {

        /* propogated down to WolfSSLEngineHelper in WolfSSLSocket creation */
        params.setWantClientAuth(want);
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "want client auth set to: " + want);
    }

    @Override
    synchronized public boolean getWantClientAuth() {
        return params.getWantClientAuth();
    }

    @Override
    synchronized public void setUseClientMode(boolean mode)
        throws IllegalArgumentException {

        clientMode = mode;
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "use client mode set to: " + mode);
    }

    @Override
    synchronized public boolean getUseClientMode() {
        return clientMode;
    }

    @Override
    synchronized public void setEnableSessionCreation(boolean flag) {

        enableSessionCreation = flag;
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "enable session creation set to: " + flag);
    }

    @Override
    synchronized public boolean getEnableSessionCreation() {
        return enableSessionCreation;
    }

    @Override
    synchronized public Socket accept() throws IOException {

        /* protected method inherited from ServerSocket, returns
           a connected socket */
        Socket sock = new Socket();
        implAccept(sock);
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "Socket connected to client: " +
                sock.getInetAddress().getHostAddress() + ", port: " +
                sock.getPort());

        /* create new WolfSSLSocket wrapping connected Socket */
        socket = new WolfSSLSocket(context, authStore, params,
            clientMode, sock, true);

        socket.setEnableSessionCreation(enableSessionCreation);

        return socket;
    }
}

