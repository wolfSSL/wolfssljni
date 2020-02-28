/* WolfSSLSocketFactoryTest.java
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

import com.wolfssl.provider.jsse.WolfSSLSocketFactory;

import java.io.FileInputStream;
import java.io.InputStream;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import java.net.Socket;
import java.net.InetAddress;
import java.net.SocketException;
import java.security.Security;
import java.security.Provider;
import java.security.KeyStore;

import java.io.IOException;
import java.io.FileNotFoundException;
import java.net.UnknownHostException;
import java.security.KeyStoreException;
import java.security.KeyManagementException;
import java.security.NoSuchProviderException;
import java.security.NoSuchAlgorithmException;
import java.net.UnknownHostException;

import com.wolfssl.WolfSSLException;
import com.wolfssl.provider.jsse.WolfSSLProvider;

public class WolfSSLSocketFactoryTest {

    public final static char[] jksPass = "wolfSSL test".toCharArray();
    private final static String ctxProvider = "wolfJSSE";
    private static WolfSSLTestFactory tf;

    private static String allProtocols[] = {
        "TLSv1",
        "TLSv1.1",
        "TLSv1.2",
        "TLS"
    };

    private static ArrayList<String> enabledProtocols =
        new ArrayList<String>();

    /* list of SSLSocketFactories for each protocol supported */
    private static ArrayList<SSLSocketFactory> sockFactories =
        new ArrayList<SSLSocketFactory>();

    @BeforeClass
    public static void testSetupSocketFactory() throws NoSuchProviderException,
        NoSuchAlgorithmException, IllegalStateException,
        KeyManagementException, Exception {

        SSLContext ctx;
        KeyManagerFactory km;
        TrustManagerFactory tm;
        KeyStore pKey, cert;

        System.out.println("WolfSSLSocketFactory Class");

        /* install wolfJSSE provider at runtime */
        Security.insertProviderAt(new WolfSSLProvider(), 1);

        Provider p = Security.getProvider("wolfJSSE");
        assertNotNull(p);

        try {
            tf = new WolfSSLTestFactory();
        } catch (WolfSSLException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        /* populate enabledProtocols */
        for (int i = 0; i < allProtocols.length; i++) {
            try {
                ctx = SSLContext.getInstance(allProtocols[i], ctxProvider);
                enabledProtocols.add(allProtocols[i]);

            } catch (NoSuchAlgorithmException e) {
                /* protocol not enabled */
            }
        }

        try {
            /* set up KeyStore */
                InputStream stream = new FileInputStream(tf.clientJKS);
            pKey = KeyStore.getInstance(tf.keyStoreType);
            pKey.load(stream, jksPass);
            stream.close();

            stream = new FileInputStream(tf.clientJKS);
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
            ctx = SSLContext.getInstance(enabledProtocols.get(i), ctxProvider);

            ctx.init(km.getKeyManagers(), tm.getTrustManagers(), null);

            SSLSocketFactory sf = ctx.getSocketFactory();
            sockFactories.add(sf);
        }

        /* add default SSLSocketFactory to tests */
        SSLSocketFactory sfDefault =
            new com.wolfssl.provider.jsse.WolfSSLSocketFactory();
        sockFactories.add(sfDefault);
    }

    @Test
    public void testUseDefaultSSLSocketFactory()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        System.out.print("\tgetDefault()");

        SSLSocketFactory sf =
            new com.wolfssl.provider.jsse.WolfSSLSocketFactory();

        if (sf == null) {
            System.out.println("\t\t\t... failed");
            fail("SSLSocketFactory.getDefault() failed");
        }

        System.out.println("\t\t\t... passed");
    }

    @Test
    public void testGetDefaultCipherSuites()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        System.out.print("\tgetDefaultCipherSuites()");

        for (int i = 0; i < sockFactories.size(); i++) {
            SSLSocketFactory sf = sockFactories.get(i);
            String[] cipherSuites = sf.getDefaultCipherSuites();

            if (cipherSuites == null) {
                System.out.println("\t... failed");
                fail("SSLSocketFactory.getDefaultCipherSuites() failed");
            }
        }

        System.out.println("\t... passed");
    }

    @Test
    public void testGetSupportedCipherSuites()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        System.out.print("\tgetSupportedCipherSuites()");

        for (int i = 0; i < sockFactories.size(); i++) {
            SSLSocketFactory sf = sockFactories.get(i);
            String[] cipherSuites = sf.getSupportedCipherSuites();

            if (cipherSuites == null) {
                System.out.println("\t... failed");
                fail("SSLSocketFactory.getSupportedCipherSuites() failed");
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
            int port = 443;
            SSLSocketFactory sf = sockFactories.get(i);
            SSLSocket ss = null;
            Socket s = null;
            InputStream in = null;

            try {
                addr = InetAddress.getByName("www.example.com");
            } catch (UnknownHostException e) {
                /* skip test if no Internet connection available */
                System.out.println("\t\t\t... skipped");
                return;
            }

            /* good arguments */
            try {

                /* no arguments */
                ss = (SSLSocket)sf.createSocket();
                if (ss == null) {
                    System.out.println("\t\t\t... failed");
                    fail("SSLSocketFactory.createSocket() failed");
                    return;
                }
                ss.close();

                /* InetAddress, int */
                ss = (SSLSocket)sf.createSocket(addr, port);
                if (ss == null) {
                    System.out.println("\t\t\t... failed");
                    fail("SSLSocketFactory.createSocket(Ii) failed");
                    return;
                }
                ss.close();

                /* String, int */
                ss = (SSLSocket)sf.createSocket(addrStr, port);
                if (ss == null) {
                    System.out.println("\t\t\t... failed");
                    fail("SSLSocketFactory.createSocket(Si) failed");
                    return;
                }
                ss.close();

                /* Socket, String, int, boolean */
                s = new Socket(addr, port);
                ss = (SSLSocket)sf.createSocket(s, addrStr, port, true);
                if (ss == null) {
                    System.out.println("\t\t\t... failed");
                    fail("SSLSocketFactory.createSocket(SkSib) failed");
                    return;
                }
                ss.close();
                s.close();

                /* Socket, InputStream, boolean */
                s = new Socket(addr, port);
                in = s.getInputStream();
                ss = (SSLSocket)((WolfSSLSocketFactory)sf).createSocket(s, in, true);
                if (ss == null) {
                    System.out.println("\t\t\t... failed");
                    fail("SSLSocketFactory.createSocket(SkSib) failed");
                    return;
                }
                ss.close();
                s.close();
                in.close();

                /* String, int, InetAddress, int */
                ss = (SSLSocket)sf.createSocket(addrStr, port,
                    null, 0);
                if (ss == null) {
                    System.out.println("\t\t\t... failed");
                    fail("SSLSocketFactory.createSocket(SiIi) failed");
                    return;
                }
                ss.close();

                /* InetAddress, int, InetAddress, int */
                ss = (SSLSocket)sf.createSocket(addr, port,
                    null, 0);
                if (ss == null) {
                    System.out.println("\t\t\t... failed");
                    fail("SSLSocketFactory.createSocket(IiIi) failed");
                    return;
                }
                ss.close();

            } catch (SocketException e) {
                System.out.println("\t\t\t... failed");
                throw e;
            }
            catch (Exception e) {
                System.out.println("\t\t\t... failed");
                throw e;
            }

            /* bad arguments */
            try {
                /* InetAddress, int - null host */
                ss = (SSLSocket)sf.createSocket((InetAddress)null, port);
                System.out.println("\t\t\t... failed");
                fail("createSocket() should return NullPointerException");
            } catch (NullPointerException ne) {
                /* expected */
            }
            catch (Exception e) {
                System.out.println("\t\t\t... failed");
                fail("createSocket() should return NullPointerException");
            }

            try {
                /* InetAddress, int - port out of range {0:65535} */
                ss = (SSLSocket)sf.createSocket(addr, 65536);
                System.out.println("\t\t\t... failed");
                fail("createSocket() should return IllegalArgumentException");
            } catch (IllegalArgumentException ie) {
                /* expected */
            }
            catch (Exception e) {
                System.out.println("\t\t\t... failed");
                fail("createSocket() should return IllegalArgumentException");
            }

            try {
                /* String, int - bad host */
                ss = (SSLSocket)sf.createSocket("badhost", port);
                System.out.println("\t\t\t... failed");
                fail("createSocket() should return UnknownHostException");
            } catch (UnknownHostException ne) {
                /* expected */
            }
            catch (Exception e) {
                /* could also be java.net.ConnectException from connect */
            }

            try {
                /* String, int - port out of range {0:65535} */
                ss = (SSLSocket)sf.createSocket(addrStr, 65536);
                System.out.println("\t\t\t... failed");
                fail("createSocket() should return IllegalArgumentException");
            } catch (IllegalArgumentException ie) {
                /* expected */
            }
            catch (Exception e) {
                System.out.println("\t\t\t... failed");
                fail("createSocket() should return IllegalArgumentException");
            }

            try {
                /* Socket, String, int, boolean - null Socket */
                ss = (SSLSocket)sf.createSocket((Socket)null, addrStr, port,
                    true);
                System.out.println("\t\t\t... failed");
                fail("createSocket() should return NullPointerException");
            } catch (NullPointerException ne) {
                /* expected */
            }
            catch (Exception e) {
                System.out.println("\t\t\t... failed");
                fail("createSocket() should return NullPointerException");
            }

            try {
                /* Socket, String, int, boolean - Socket not connected */
                s = new Socket();
                ss = (SSLSocket)sf.createSocket(s, addrStr, port,
                    true);
                System.out.println("\t\t\t... failed");
                fail("createSocket() should return IOException");
            } catch (IOException ne) {
                /* expected */
            }
            catch (Exception e) {
                System.out.println("\t\t\t... failed");
                fail("createSocket() should return IOException");
            }
            s.close();

            try {
                /* Socket, InputStream, boolean - null Socket */
                s = new Socket(addr, port);
                in = s.getInputStream();
                ss = (SSLSocket)((WolfSSLSocketFactory)sf).createSocket((Socket)null, in, true);
                System.out.println("\t\t\t... failed");
                fail("createSocket() should throw exception");
            } catch (NullPointerException e) {
                /* expected */
            }
            catch (Exception e) {
                System.out.println("\t\t\t... failed");
                fail("createSocket() should throw exception");
            }
            in.close();
        }

        System.out.println("\t\t\t... passed");
    }
}

