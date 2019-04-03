/* WolfSSLContextTest.java
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

import org.junit.Test;
import org.junit.BeforeClass;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import static org.junit.Assert.*;

import java.util.ArrayList;

import com.wolfssl.WolfSSLException;
import com.wolfssl.provider.jsse.WolfSSLContext;

import java.io.FileInputStream;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import java.security.Security;
import java.security.Provider;
import java.security.KeyStore;

import java.io.IOException;
import java.io.FileNotFoundException;
import java.security.KeyStoreException;
import java.security.KeyManagementException;
import java.security.NoSuchProviderException;
import java.security.NoSuchAlgorithmException;

import com.wolfssl.provider.jsse.WolfSSLProvider;

public class WolfSSLContextTest {

    private static WolfSSLTestFactory tf;
    public final static char[] jksPass = "wolfSSL test".toCharArray();

    private static String allProtocols[] = {
        "TLSV1",
        "TLSV1.1",
        "TLSV1.2",
        "TLS"
    };

    private static ArrayList<String> enabledProtocols =
        new ArrayList<String>();

    @BeforeClass
    public static void testProviderInstallationAtRuntime()
        throws NoSuchProviderException {

        System.out.println("WolfSSLContext Class");

        /* install wolfJSSE provider at runtime */
        Security.addProvider(new WolfSSLProvider());

        Provider p = Security.getProvider("wolfJSSE");
        assertNotNull(p);

        System.out.print("\tGetting provider name");
        if (p.getName().contains("wolfJSSE")) {
            System.out.println("\t\t... passed");
        } else {
            System.out.println("\t\t... failed");
            fail("Failed to get proper wolfJSSE provider name");
        }

        /* populate enabledProtocols */
        for (int i = 0; i < allProtocols.length; i++) {
            try {
                SSLContext ctx = SSLContext.getInstance(allProtocols[i],
                    "wolfJSSE");
                enabledProtocols.add(allProtocols[i]);

            } catch (NoSuchAlgorithmException e) {
                /* protocol not enabled */
            }
        }
        
        try {
			tf = new WolfSSLTestFactory();
		} catch (WolfSSLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }

    @Test
    public void testGetSSLContextFromProvider()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        SSLContext ctx;

        System.out.print("\tTesting protocol support");

        /* try to get all available protocols we expect to have */
        for (int i = 0; i < enabledProtocols.size(); i++) {
            ctx = SSLContext.getInstance(enabledProtocols.get(i), "wolfJSSE");
        }

        /* getting a garbage protocol should throw an exception */
        try {
            ctx = SSLContext.getInstance("NotValid", "wolfJSSE");

            System.out.println("\t... failed");
            fail("SSLContext.getInstance should throw " +
                 "NoSuchAlgorithmException when given bad protocol");

        } catch (NoSuchAlgorithmException nsae) {
            System.out.println("\t... passed");
        }
    }

    @Test
    public void testGetSocketFactory() throws NoSuchProviderException,
        NoSuchAlgorithmException, IllegalStateException,
        KeyManagementException, Exception {

        SSLContext ctx;
        KeyManagerFactory km;
        TrustManagerFactory tm;
        KeyStore pKey, cert;

        System.out.print("\tgetSocketFactory()");

        try {
            /* set up KeyStore */
            pKey = KeyStore.getInstance("JKS");
            pKey.load(new FileInputStream(tf.clientJKS), jksPass);
            cert = KeyStore.getInstance("JKS");
            cert.load(new FileInputStream(tf.clientJKS), jksPass);

            /* trust manager (certificates) */
            tm = TrustManagerFactory.getInstance("SunX509");
            tm.init(cert);

            /* load private key */
            km = KeyManagerFactory.getInstance("SunX509");
            km.init(pKey, jksPass);

        } catch (KeyStoreException kse) {
            throw new Exception(kse);
        } catch (FileNotFoundException fnfe) {
            throw new Exception(fnfe);
        } catch (IOException ioe) {
            throw new Exception(ioe);
        }

        for (int i = 0; i < enabledProtocols.size(); i++) {
            ctx = SSLContext.getInstance(enabledProtocols.get(i), "wolfJSSE");

            ctx.init(km.getKeyManagers(), tm.getTrustManagers(), null);

            SSLSocketFactory sf = ctx.getSocketFactory();

        }

        System.out.println("\t\t... passed");
    }
}

