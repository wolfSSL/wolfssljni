/* WolfSSLServerSocketFactoryTest.java
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

package com.wolfssl.provider.jsse.test;

import org.junit.Test;
import org.junit.BeforeClass;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import static org.junit.Assert.*;

import java.util.ArrayList;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.FileNotFoundException;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.SSLServerSocket;
import java.security.KeyStore;
import java.security.Security;
import java.security.Provider;
import java.security.NoSuchProviderException;
import java.security.NoSuchAlgorithmException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;

import com.wolfssl.WolfSSLException;
import com.wolfssl.provider.jsse.WolfSSLProvider;

public class WolfSSLServerSocketFactoryTest {

    private final static char[] jksPass = "wolfSSL test".toCharArray();
    private static WolfSSLTestFactory tf;

    private static String allProtocols[] = {
        "TLSV1",
        "TLSV1.1",
        "TLSV1.2",
        "TLS"
    };

    private static ArrayList<String> enabledProtocols =
        new ArrayList<String>();

    /* list of SSLSocketFactories for each protocol supported */
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

        System.out.println("WolfSSLServerSocketFactory Class");

        /* install wolfJSSE provider at runtime */
        Security.insertProviderAt(new WolfSSLProvider(), 1);

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
            tf = new WolfSSLTestFactory();
        } catch (WolfSSLException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        try {
            /* set up KeyStore */
                InputStream stream = new FileInputStream(tf.serverJKS);
            pKey = KeyStore.getInstance(tf.keyStoreType);
            pKey.load(stream, jksPass);
            stream.close();

            stream = new FileInputStream(tf.serverJKS);
            cert = KeyStore.getInstance(tf.keyStoreType);
            cert.load(stream, jksPass);
            stream.close();

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
    public void testGetDefaultCipherSuites()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        System.out.print("\tgetDefaultCipherSuites()");

        for (int i = 0; i < sockFactories.size(); i++) {
            SSLServerSocketFactory sf = sockFactories.get(i);
            String[] cipherSuites = sf.getDefaultCipherSuites();

            if (cipherSuites == null) {
                System.out.println("\t... failed");
                fail("SSLServerSocketFactory.getDefaultCipherSuites() failed");
            }
        }

        System.out.println("\t... passed");
    }

    @Test
    public void testGetSupportedCipherSuites()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        System.out.print("\tgetSupportedCipherSuites()");

        for (int i = 0; i < sockFactories.size(); i++) {
            SSLServerSocketFactory sf = sockFactories.get(i);
            String[] cipherSuites = sf.getSupportedCipherSuites();

            if (cipherSuites == null) {
                System.out.println("\t... failed");
                fail("SSLServerSocketFactory.getSupportedCipherSuites() " +
                     "failed");
            }
        }

        System.out.println("\t... passed");
    }

    @Test
    public void testCreateSocket()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               IOException {

        System.out.print("\tcreateSocket()");

        for (int i = 0; i < sockFactories.size(); i++) {
            String addrStr = "www.example.com";
            InetAddress addr;
            int port = 11118;
            int backlog = 0;
            SSLServerSocketFactory sf = sockFactories.get(i);
            SSLServerSocket s = null;

            try {
                addr = InetAddress.getByName("www.example.com");
            } catch (UnknownHostException e) {
                /* skip test if no Internet connection available */
                System.out.println("\t\t\t... skipped");
                return;
            }

            try {

                /* no arguments */
                s = (SSLServerSocket)sf.createServerSocket();
                if (s == null) {
                    System.out.println("\t\t\t... failed");
                    fail("SSLServerSocketFactory.createSocket() failed");
                    return;
                }
                s.close();

                /* int */
                s = (SSLServerSocket)sf.createServerSocket(port);
                if (s == null) {
                    System.out.println("\t\t\t... failed");
                    fail("SSLServerSocketFactory.createSocket(i) failed");
                    return;
                }
                s.close();

                /* int, int */
                s = (SSLServerSocket)sf.createServerSocket(port, backlog);
                if (s == null) {
                    System.out.println("\t\t\t... failed");
                    fail("SSLServerSocketFactory.createSocket(Si) failed");
                    return;
                }
                s.close();

                /* int, int, InetAddress */
                s = (SSLServerSocket)sf.createServerSocket(port, backlog, null);
                if (s == null) {
                    System.out.println("\t\t\t... failed");
                    fail("SSLServerSocketFactory.createSocket(SiI) failed");
                    return;
                }
                s.close();

            } catch (SocketException e) {
                System.out.println("\t\t\t... failed");
                throw e;
            }
        }

        System.out.println("\t\t\t... passed");
    }
}

