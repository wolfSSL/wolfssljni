/* WolfSSLServerSocketTest.java
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
import java.io.FileInputStream;
import java.io.IOException;
import java.io.FileNotFoundException;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLContext;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import java.security.KeyStore;
import java.security.Security;
import java.security.Provider;
import java.security.NoSuchProviderException;
import java.security.NoSuchAlgorithmException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;

import com.wolfssl.provider.jsse.WolfSSLProvider;

public class WolfSSLServerSocketTest {

    private final static String serverJKS = "./examples/provider/server.jks";
    private final static char[] jksPass = "wolfSSL test".toCharArray();
    private final static int serverPort = 11118;

    private static String allProtocols[] = {
        "TLSV1",
        "TLSV1.1",
        "TLSV1.2",
        "TLS"
    };

    private static ArrayList<String> enabledProtocols =
        new ArrayList<String>();

    /* list of SSLServerSocketFactories for each protocol supported */
    private static ArrayList<SSLServerSocketFactory> sockFactories =
        new ArrayList<SSLServerSocketFactory>();

    @BeforeClass
    public static void testSetupSocketFactory() throws NoSuchProviderException,
        NoSuchAlgorithmException, IllegalStateException,
        KeyManagementException, Exception {

        SSLContext ctx;
        KeyManagerFactory km;
        TrustManagerFactory tm;
        KeyStore pKey, cert;

        System.out.println("WolfSSLServerSocket Class");

        /* install wolfJSSE provider at runtime */
        Security.addProvider(new WolfSSLProvider());

        Provider p = Security.getProvider("wolfJSSE");
        assertNotNull(p);

        /* populate enabledProtocols */
        for (int i = 0; i < allProtocols.length; i++) {
            try {
                ctx = SSLContext.getInstance(allProtocols[i], "wolfJSSE");
                enabledProtocols.add(allProtocols[i]);

            } catch (NoSuchAlgorithmException e) {
                /* protocol not enabled */
            }
        }

        try {
            /* set up KeyStore */
            pKey = KeyStore.getInstance("JKS");
            pKey.load(new FileInputStream(serverJKS), jksPass);
            cert = KeyStore.getInstance("JKS");
            cert.load(new FileInputStream(serverJKS), jksPass);

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

            SSLServerSocketFactory sf = ctx.getServerSocketFactory();
            sockFactories.add(sf);
        }
    }

    @Test
    public void testGetSupportedCipherSuites()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               IOException {

        System.out.print("\tgetSupportedCipherSuites()");

        for (int i = 0; i < sockFactories.size(); i++) {
            SSLServerSocketFactory sf = sockFactories.get(i);
            SSLServerSocket s = (SSLServerSocket)sf.createServerSocket(
                serverPort);
            String[] cipherSuites = s.getSupportedCipherSuites();
            s.close();

            if (cipherSuites == null) {
                System.out.println("\t... failed");
                fail("SSLServerSocket.getSupportedCipherSuites() failed");
            }
        }

        System.out.println("\t... passed");
    }

    @Test
    public void testGetEnabledCipherSuites()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               IOException {

        int port = 11118;
        System.out.print("\tgetEnabledCipherSuites()");

        for (int i = 0; i < sockFactories.size(); i++) {
            SSLServerSocketFactory sf = sockFactories.get(i);
            SSLServerSocket s = (SSLServerSocket)sf.createServerSocket(
                serverPort);
            String[] cipherSuites = s.getEnabledCipherSuites();
            s.close();

            if (cipherSuites == null) {
                System.out.println("\t... failed");
                fail("SSLServerSocket.getEnabledCipherSuites() failed");
            }
        }

        System.out.println("\t... passed");
    }
}

