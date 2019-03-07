/* WolfSSLContext.java
 *
 * Copyright (C) 2006-2018 wolfSSL Inc.
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

import javax.net.ssl.SSLContextSpi;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.KeyManager;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.security.SecureRandom;

import com.wolfssl.provider.jsse.WolfSSLAuthStore.TLS_VERSION;

import com.wolfssl.WolfSSLException;

import java.lang.IllegalArgumentException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;

public class WolfSSLContext extends SSLContextSpi {

    private TLS_VERSION currentVersion = TLS_VERSION.SSLv23;
    private WolfSSLAuthStore params = null;
    
    private WolfSSLContext(TLS_VERSION version) {
        this.currentVersion = version;
    }

    @Override
    protected void engineInit(KeyManager[] km, TrustManager[] tm,
        SecureRandom sr) throws KeyManagementException {

        try {
            params = new WolfSSLAuthStore(km, tm, sr, currentVersion);

        } catch (IllegalArgumentException iae) {
            throw new KeyManagementException(iae);
        }
    }

    @Override
    protected SSLSocketFactory engineGetSocketFactory()
        throws IllegalStateException {

        if (params == null) {
            throw new IllegalStateException("SSLContext must be initialized " +
                "before use, please call init()");
        }

        try {
            return new WolfSSLSocketFactory(params);

        } catch (WolfSSLException we) {
            throw new IllegalStateException(we);
        }
    }

    @Override
    protected SSLServerSocketFactory engineGetServerSocketFactory() {

        if (params == null) {
            throw new IllegalStateException("SSLContext must be initialized " +
                "before use, please call init()");
        }

        return new WolfSSLServerSocketFactory(params);
    }

    @Override
    protected SSLEngine engineCreateSSLEngine() {

        if (params == null) {
            throw new IllegalStateException("SSLContext must be initialized " +
                "before use, please call init()");
        }

        try {
            return new WolfSSLEngine();
        } catch (WolfSSLException ex) {
            Logger.getLogger(WolfSSLContext.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    @Override
    protected SSLEngine engineCreateSSLEngine(String host, int port) {

        if (params == null) {
            throw new IllegalStateException("SSLContext must be initialized " +
                "before use, please call init()");
        }

        try {
            return new WolfSSLEngine(host, port);
        } catch (WolfSSLException ex) {
            Logger.getLogger(WolfSSLContext.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    @Override
    protected SSLSessionContext engineGetServerSessionContext() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    protected SSLSessionContext engineGetClientSessionContext() {
        throw new UnsupportedOperationException("Not supported yet.");
    }
    
    public static final class TLSV1_Context extends WolfSSLContext {
        public TLSV1_Context() {
            super(TLS_VERSION.TLSv1);
        }
    }
    
    public static final class TLSV11_Context extends WolfSSLContext {
        public TLSV11_Context() {
            super(TLS_VERSION.TLSv1_1);
        }
    }
    
    public static final class TLSV12_Context extends WolfSSLContext {
        public TLSV12_Context() {
            super(TLS_VERSION.TLSv1_2);
        }
    }
    
    public static final class TLSV23_Context extends WolfSSLContext {
        public TLSV23_Context() {
            super(TLS_VERSION.SSLv23);
        }
    }
}
