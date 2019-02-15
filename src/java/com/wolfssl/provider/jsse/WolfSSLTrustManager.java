/* WolfSSLTrustManager.java
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

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactorySpi;

public class WolfSSLTrustManager extends TrustManagerFactorySpi {

    public WolfSSLTrustManager() {}
    
    private KeyStore store;
    
    @Override
    protected void engineInit(KeyStore in) throws KeyStoreException {
       this.store = in;
    }

    @Override
    protected void engineInit(ManagerFactoryParameters arg0) throws InvalidAlgorithmParameterException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    protected TrustManager[] engineGetTrustManagers() {
        /* array of WolfSSLX509Trust objects to use */
        TrustManager[] tm = {new WolfSSLTrustX509(this.store)};
        return tm;
    }
    
}