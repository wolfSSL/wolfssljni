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

package com.wolfssl.provider.jsse.test;

import com.wolfssl.provider.jsse.WolfSSLProvider;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 *
 * @author wolfSSL
 */
public class WolfSSLEngineTest {
    public final static String clientJKS = "./examples/provider/client.jks";
    public final static String serverJKS = "./examples/provider/server.jks";
    public final static char[] jksPass = "wolfSSL test".toCharArray();

    private SSLContext ctx = null;
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

        System.out.println("WolfSSLEngine Class");
    }

    private TrustManager[] createTrustManager(String type, String file) {
        TrustManagerFactory tm;
        KeyStore cert;
        
        try {
            cert = KeyStore.getInstance("JKS");
            cert.load(new FileInputStream(file), jksPass);
            tm = TrustManagerFactory.getInstance(type);
            tm.init(cert);
            return tm.getTrustManagers();
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(WolfSSLEngineTest.class.getName()).log(Level.SEVERE, null, ex);
        } catch (KeyStoreException ex) {
            Logger.getLogger(WolfSSLEngineTest.class.getName()).log(Level.SEVERE, null, ex);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(WolfSSLEngineTest.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(WolfSSLEngineTest.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateException ex) {
            Logger.getLogger(WolfSSLEngineTest.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
    
    private KeyManager[] createKeyManager(String type, String file) {
        KeyManagerFactory km;
        KeyStore pKey;
        
        try {
            /* set up KeyStore */
            pKey = KeyStore.getInstance("JKS");
            pKey.load(new FileInputStream(file), jksPass);

            /* load private key */
            km = KeyManagerFactory.getInstance(type);
            km.init(pKey, jksPass);
            return km.getKeyManagers();
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(WolfSSLEngineTest.class.getName()).log(Level.SEVERE, null, ex);
        } catch (KeyStoreException ex) {
            Logger.getLogger(WolfSSLEngineTest.class.getName()).log(Level.SEVERE, null, ex);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(WolfSSLEngineTest.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(WolfSSLEngineTest.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateException ex) {
            Logger.getLogger(WolfSSLEngineTest.class.getName()).log(Level.SEVERE, null, ex);
        } catch (UnrecoverableKeyException ex) {
            Logger.getLogger(WolfSSLEngineTest.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
    
    private void createSSLContext(String protocol) {
        SSLContext ctx;
        
        try {
                //ctx = SSLContext.getInstance(protocol, "wolfJSSE");
            this.ctx = SSLContext.getInstance(protocol);
            this.ctx.init(createKeyManager("SunX509", clientJKS),
                     createTrustManager("SunX509", clientJKS), null);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(WolfSSLEngineTest.class.getName()).log(Level.SEVERE, null, ex);
        //} catch (NoSuchProviderException ex) {
        //    Logger.getLogger(WolfSSLEngineTest.class.getName()).log(Level.SEVERE, null, ex);
        } catch (KeyManagementException ex) {
            Logger.getLogger(WolfSSLEngineTest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    private int testConnection(SSLEngine server, SSLEngine client,
            String[] cipherSuites, String[] protocols, String appData) {
        ByteBuffer serToCli = ByteBuffer.allocateDirect(server.getSession().getPacketBufferSize());
        ByteBuffer cliToSer = ByteBuffer.allocateDirect(client.getSession().getPacketBufferSize());
        ByteBuffer toSend = ByteBuffer.wrap(appData.getBytes());
        ByteBuffer serPlain = ByteBuffer.allocate(appData.length());
        ByteBuffer cliPlain = ByteBuffer.allocate(appData.length());
        boolean done = false;

        int i;

        
        server.setUseClientMode(false);
        server.setEnabledCipherSuites(cipherSuites);
        String[] p = server.getSupportedProtocols();

        server.setEnabledProtocols(protocols);
        server.setNeedClientAuth(false);
        
        client.setUseClientMode(true);
        client.setEnabledCipherSuites(cipherSuites);
        client.setEnabledProtocols(protocols);

        while (!done) {
            try {
                Runnable run;
                SSLEngineResult result;
                
                result = client.wrap(toSend, cliToSer);
//                System.out.println("[client wrap] consumed = " + result.bytesConsumed() +
//                        " produced = " + result.bytesProduced() +
//                        " status = " + result.getStatus().name());
                while ((run = client.getDelegatedTask()) != null) {
                    run.run();
                }
                
                result = server.wrap(toSend, serToCli);
//                System.out.println("[server wrap] consumed = " + result.bytesConsumed() +
//                        " produced = " + result.bytesProduced() +
//                        " status = " + result.getStatus().name());
                while ((run = server.getDelegatedTask()) != null) {
                    run.run();
                }

                cliToSer.flip();
                serToCli.flip();
                
                result = client.unwrap(serToCli, cliPlain);
//                System.out.println("[client unwrap] consumed = " + result.bytesConsumed() +
//                        " produced = " + result.bytesProduced() +
//                        " status = " + result.getStatus().name());
                while ((run = client.getDelegatedTask()) != null) {
                    run.run();
                }
                
                
                result = server.unwrap(cliToSer, serPlain);
//                System.out.println("[server unwrap] consumed = " + result.bytesConsumed() +
//                        " produced = " + result.bytesProduced() +
//                        " status = " + result.getStatus().name());
                while ((run = server.getDelegatedTask()) != null) {
                    run.run();
                }
                                
                cliToSer.compact();
                serToCli.compact();
                
            
                HandshakeStatus s = client.getHandshakeStatus();
//                System.out.println("client status = " + s.toString());
                s = server.getHandshakeStatus();
//                System.out.println("server status = " + s.toString());
                
                if (toSend.remaining() == 0) {
                    byte[] b;
                    serPlain.rewind();
                    b = new byte[serPlain.remaining()];
                    serPlain.get(b);
                    String st = new String(b, StandardCharsets.UTF_8);
                    if (!appData.equals(st)) {
                        System.out.println("unexpected application data");
                        return -1;
                    }
                    done = true;
                }

            } catch (SSLException ex) {
                Logger.getLogger(WolfSSLEngineTest.class.getName()).log(Level.SEVERE, null, ex);
                return -1;
            }            
        }
        return 0;
    }
    
    
    @Test
    public void testSSLEngine()
        throws NoSuchProviderException, NoSuchAlgorithmException {
        SSLEngine e;

        /* create new SSLEngine */
        System.out.print("\tTesting creation");

        createSSLContext("TLSv1.2");
        e = this.ctx.createSSLEngine();
        if (e == null) {
            System.out.println("\t\t... failed");
            fail("failed to create engine");   
        }
        System.out.println("\t\t... passed");
    }
    
    @Test
    public void testCipherConnection()
        throws NoSuchProviderException, NoSuchAlgorithmException {
        SSLEngine server;
        SSLEngine client;
        String    cipher = null;
        int ret, i;

        /* create new SSLEngine */
        System.out.print("\tTesting setting cipher");

        createSSLContext("TLS");
        server = this.ctx.createSSLEngine();
//        client = this.ctx.createSSLEngine("client", 80);

        /* use wolfJSSE client */
        SSLContext c = SSLContext.getInstance("TLSv1.2", "wolfJSSE");
        try {
            c.init(createKeyManager("SunX509", clientJKS),
                    createTrustManager("SunX509", clientJKS), null);
        } catch (KeyManagementException ex) {
            System.out.println("unable to init context");
            Logger.getLogger(WolfSSLEngineTest.class.getName()).log(Level.SEVERE, null, ex);
        }
        client = c.createSSLEngine("client", 80);


        String[] ciphers = server.getSupportedCipherSuites();
        for (i = 0; i < ciphers.length; i++)
            if (ciphers[i].equals("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"))
                cipher = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384";
        
        ret = testConnection(server, client, new String[] { cipher },
                new String[] { "TLSv1.2" }, "Test cipher suite");
        if (ret != 0) {
            System.out.println("\t\t... failed");
            fail("failed to create engine");   
        }
        System.out.println("\t\t... passed");
    }
}
