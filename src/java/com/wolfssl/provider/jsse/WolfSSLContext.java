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

import java.security.KeyManagementException;
import java.security.SecureRandom;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContextSpi;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

public class WolfSSLContext extends SSLContextSpi {

    enum TLS_VERSION {
        TLSv1,
        TLSv1_1,
        TLSv1_2,
        TLSv1_3,
        SSLv23
    };
    
    private TLS_VERSION currentVersion = TLS_VERSION.SSLv23;
    
    private WolfSSLContext(TLS_VERSION version) {
        this.currentVersion = version;
    }
    
    @Override
    protected void engineInit(KeyManager[] arg0, TrustManager[] arg1, SecureRandom arg2) throws KeyManagementException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    protected SSLSocketFactory engineGetSocketFactory() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    protected SSLServerSocketFactory engineGetServerSocketFactory() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    protected SSLEngine engineCreateSSLEngine() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    protected SSLEngine engineCreateSSLEngine(String arg0, int arg1) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    protected SSLSessionContext engineGetServerSessionContext() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    protected SSLSessionContext engineGetClientSessionContext() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
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