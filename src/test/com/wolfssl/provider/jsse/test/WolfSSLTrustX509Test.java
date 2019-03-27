/* WolfSSLTrustX509Test.java
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
package com.wolfssl.provider.jsse.test;

import com.wolfssl.provider.jsse.WolfSSLProvider;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 *
 * @author wolfSSL
 */
public class WolfSSLTrustX509Test {
    private static WolfSSLTestFactory tf;
    private String allJKS;
    private String provider = null;
    
    @BeforeClass
    public static void testProviderInstallationAtRuntime()
        throws NoSuchProviderException {

        System.out.println("WolfSSLTrustX509 Class");
        
                /* install wolfJSSE provider at runtime */
        Security.addProvider(new WolfSSLProvider());

        Provider p = Security.getProvider("wolfJSSE");
        assertNotNull(p);
        
        tf = new WolfSSLTestFactory();
    }
    
    @Test
    public void testParsing()
        throws NoSuchProviderException, NoSuchAlgorithmException {
        TrustManager[] tm;
        
        System.out.print("\tTesting parsing");
        
        tm = tf.createTrustManager("SunX509", allJKS, provider);
        
        if (tm == null) {
            error("\t... failed");
            fail("failed to create trustmanager"); 
        }
    }
    
    private void pass(String msg) {
        WolfSSLTestFactory.pass(msg);
    }
    
    private void error(String msg) {
        WolfSSLTestFactory.fail(msg);
    }
}
