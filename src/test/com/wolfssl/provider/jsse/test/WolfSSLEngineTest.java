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
import java.util.Arrays;
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
    public final static String engineProvider = null;
    private static boolean extraDebug = false;

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
        try {
            if (engineProvider != null) {
                this.ctx = SSLContext.getInstance(protocol, engineProvider);
            }
            else {
                this.ctx = SSLContext.getInstance(protocol);
            }
            this.ctx.init(createKeyManager("SunX509", clientJKS),
                     createTrustManager("SunX509", clientJKS), null);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(WolfSSLEngineTest.class.getName()).log(Level.SEVERE, null, ex);
        } catch (KeyManagementException ex) {
            Logger.getLogger(WolfSSLEngineTest.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchProviderException ex) {
            System.out.println("Could not find the provider : " + engineProvider);
            Logger.getLogger(WolfSSLEngineTest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    private int CloseConnection(SSLEngine server, SSLEngine client, boolean earlyClose) throws SSLException {
        ByteBuffer serToCli = ByteBuffer.allocateDirect(server.getSession().getPacketBufferSize());
        ByteBuffer cliToSer = ByteBuffer.allocateDirect(client.getSession().getPacketBufferSize());
        ByteBuffer empty = ByteBuffer.allocate(server.getSession().getPacketBufferSize());
        SSLEngineResult result;
        HandshakeStatus s;
        boolean passed;
        Runnable run;
         
        client.closeOutbound();

        result = client.wrap(empty, cliToSer);
        if (extraDebug) {
            System.out.println("[client wrap] consumed = " + result.bytesConsumed() +
                        " produced = " + result.bytesProduced() +
                        " status = " + result.getStatus().name());
        }
        while ((run = client.getDelegatedTask()) != null) {
            run.run();
        }
        s = client.getHandshakeStatus();
        if (extraDebug) {
            System.out.println("client status = " + s.toString());
        }
        if (result.bytesProduced() <= 0 || result.bytesConsumed() != 0) {
            throw new SSLException("Client wrap consumed/produced error");   
        }
        if (!s.toString().equals("NEED_UNWRAP") ||
                !result.getStatus().name().equals("CLOSED") ) {
            throw new SSLException("Bad status");
        }
        cliToSer.flip();

        /* check that early close inbounds fail */
        if (earlyClose) {
            try {
                passed = false;
                server.closeInbound();
            }
            catch (SSLException e) {
                passed = true;
            }
            if (!passed) {
                throw new SSLException("Expected to fail on early close inbound");
            }

            try {
                passed = false;
                client.closeInbound();
            }
            catch (SSLException e) {
                passed = true;
            }
            if (!passed) {
                throw new SSLException("Expected to fail on early close inbound");
            }
            return 0;
        }
        
        result = server.unwrap(cliToSer, empty);
        if (extraDebug) {
            System.out.println("[server unwrap] consumed = " + result.bytesConsumed() +
                        " produced = " + result.bytesProduced() +
                        " status = " + result.getStatus().name());
        }
        if (result.getStatus().name().equals("CLOSED")) {
            /* odd case where server tries to send "empty" if not set close */
            server.closeOutbound();
        }
        while ((run = server.getDelegatedTask()) != null) {
            run.run();
        }
        s = server.getHandshakeStatus();
        if (result.bytesProduced() != 0 || result.bytesConsumed() <= 0) {
            throw new SSLException("Server unwrap consumed/produced error");   
        }
        if (!s.toString().equals("NEED_WRAP") ||
                !result.getStatus().name().equals("CLOSED") ) {
            throw new SSLException("Bad status");
        }
                
        result = server.wrap(empty, serToCli);
        if (extraDebug) {
            System.out.println("[server wrap] consumed = " + result.bytesConsumed() +
                        " produced = " + result.bytesProduced() +
                        " status = " + result.getStatus().name());
        }
        while ((run = server.getDelegatedTask()) != null) {
            run.run();
        }
        s = server.getHandshakeStatus();
        if (result.bytesProduced() <= 0 || result.bytesConsumed() != 0) {
            throw new SSLException("Server wrap consumed/produced error");   
        }
        if (extraDebug) {
            System.out.println("server status = " + s.toString());
        }
        if (!s.toString().equals("NOT_HANDSHAKING") ||
                !result.getStatus().name().equals("CLOSED")) {
            throw new SSLException("Bad status");
        }
                
        serToCli.flip();
        result = client.unwrap(serToCli, empty);
        if (extraDebug) {
            System.out.println("[client unwrap] consumed = " + result.bytesConsumed() +
                        " produced = " + result.bytesProduced() +
                        " status = " + result.getStatus().name());
        }
        while ((run = client.getDelegatedTask()) != null) {
            run.run();
        }
        s = client.getHandshakeStatus();
        if (result.bytesProduced() != 0 || result.bytesConsumed() <= 0) {
            throw new SSLException("Client unwrap consumed/produced error");   
        }
        if (!s.toString().equals("NOT_HANDSHAKING") ||
                !result.getStatus().name().equals("CLOSED")) {
            throw new SSLException("Bad status");
        }
        if (extraDebug) {
            System.out.println("client status = " + s.toString());
        }
        
        server.closeInbound();
        client.closeInbound();
        return 0;
    }
    
    private int testConnection(SSLEngine server, SSLEngine client,
            String[] cipherSuites, String[] protocols, String appData) {
        ByteBuffer serToCli = ByteBuffer.allocateDirect(server.getSession().getPacketBufferSize());
        ByteBuffer cliToSer = ByteBuffer.allocateDirect(client.getSession().getPacketBufferSize());
        ByteBuffer toSendCli = ByteBuffer.wrap(appData.getBytes());
        ByteBuffer toSendSer = ByteBuffer.wrap(appData.getBytes());
        ByteBuffer serPlain = ByteBuffer.allocate(server.getSession().getApplicationBufferSize());
        ByteBuffer cliPlain = ByteBuffer.allocate(client.getSession().getApplicationBufferSize());
        boolean done = false;

        server.setUseClientMode(false);
        server.setNeedClientAuth(false);
        client.setUseClientMode(true);
        
        if (cipherSuites != null) {
            server.setEnabledCipherSuites(cipherSuites);
            client.setEnabledCipherSuites(cipherSuites);
        }
        
        if (protocols != null) {
            server.setEnabledProtocols(protocols);
            client.setEnabledProtocols(protocols);
        }

        while (!done) {
            try {
                Runnable run;
                SSLEngineResult result;
                HandshakeStatus s;
                
                result = client.wrap(toSendCli, cliToSer);
                if (extraDebug) {
                    System.out.println("[client wrap] consumed = " + result.bytesConsumed() +
                        " produced = " + result.bytesProduced() +
                        " status = " + result.getStatus().name());
//                        + " sequence # = " + result.sequenceNumber());
                }
                while ((run = client.getDelegatedTask()) != null) {
                    run.run();
                }
                
                result = server.wrap(toSendSer, serToCli);
                if (extraDebug) {
                    System.out.println("[server wrap] consumed = " + result.bytesConsumed() +
                        " produced = " + result.bytesProduced() +
                        " status = " + result.getStatus().name()
                        + " sequence # = " + result.sequenceNumber());
                }
                while ((run = server.getDelegatedTask()) != null) {
                    run.run();
                }

                if (extraDebug) {
                    s = client.getHandshakeStatus();
                    System.out.println("client status = " + s.toString());
                    s = server.getHandshakeStatus();
                    System.out.println("server status = " + s.toString());
                }
                
                cliToSer.flip();
                serToCli.flip();

                if (extraDebug) {
                    if (cliToSer.remaining() > 0) {
                        System.out.println("Client -> Server");
                        while (cliToSer.remaining() > 0)
                            System.out.printf("%02X", cliToSer.get());
                        System.out.println("");
                        cliToSer.flip();
                    }

                    if (serToCli.remaining() > 0) {
                        System.out.println("Server -> Client");
                        while (serToCli.remaining() > 0)
                            System.out.printf("%02X", serToCli.get());
                        System.out.println("");
                        serToCli.flip();
                    }

                    System.out.println("cliToSer remaning = " + cliToSer.remaining());
                    System.out.println("serToCli remaning = " + serToCli.remaining());
                }
                result = client.unwrap(serToCli, cliPlain);
                if (extraDebug) {
                    System.out.println("[client unwrap] consumed = " + result.bytesConsumed() +
                        " produced = " + result.bytesProduced() +
                        " status = " + result.getStatus().name());
                }
                while ((run = client.getDelegatedTask()) != null) {
                    run.run();
                }
                
                
                result = server.unwrap(cliToSer, serPlain);
                if (extraDebug) {
                    System.out.println("[server unwrap] consumed = " + result.bytesConsumed() +
                        " produced = " + result.bytesProduced() +
                        " status = " + result.getStatus().name());
                }
                while ((run = server.getDelegatedTask()) != null) {
                    run.run();
                }
                                
                cliToSer.compact();
                serToCli.compact();
                
            
                if (extraDebug) {
                    s = client.getHandshakeStatus();
                    System.out.println("client status = " + s.toString());
                    s = server.getHandshakeStatus();
                    System.out.println("server status = " + s.toString());
                }
                
                if (toSendCli.remaining() == 0 && toSendSer.remaining() == 0) {
                    byte[] b;
                    String st;
                    
                    /* check what the client received */
                    cliPlain.rewind();
                    b = new byte[cliPlain.remaining()];
                    cliPlain.get(b);
                    st = new String(b, StandardCharsets.UTF_8).trim();
                    if (!appData.equals(st)) {
                        return -1;
                    }
                    
                    /* check what the server received */
                    serPlain.rewind();
                    b = new byte[serPlain.remaining()];
                    serPlain.get(b);
                    st = new String(b, StandardCharsets.UTF_8).trim();
                    if (!appData.equals(st)) {
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
    public void testSSLEngineSetCipher()
        throws NoSuchProviderException, NoSuchAlgorithmException {
        SSLEngine e;
        String sup[];

        System.out.print("\tTesting setting cipher");

        createSSLContext("TLSv1.2");
        e = this.ctx.createSSLEngine();
        if (e == null) {
            System.out.println("\t\t... failed");
            fail("failed to create engine");   
        }
        
        /* should be null when not set , is not null? */
//        if (e.getEnabledCipherSuites() != null) {
//            System.out.println("\t\t... failed");
//            System.out.println("not null ");
//            for (String s : e.getEnabledCipherSuites()) {
//                System.out.print("" + s);
//            }
//            System.out.println("");
//            fail("unexpected cipher list");   
//        }
        sup = e.getSupportedCipherSuites();
        e.setEnabledCipherSuites(new String[] {sup[0]});
        if (e.getEnabledCipherSuites() == null ||
                !sup[0].equals(e.getEnabledCipherSuites()[0])) {
            System.out.println("\t\t... failed");
            fail("unexpected empty cipher list");   
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
        String[] ciphers;

        /* create new SSLEngine */
        System.out.print("\tTesting cipher connection");

        createSSLContext("TLS");
        server = this.ctx.createSSLEngine();
        client = this.ctx.createSSLEngine("wolfSSL client test", 11111);

//        /* use wolfJSSE client */
//        SSLContext c = SSLContext.getInstance("TLS", "wolfJSSE");
//        try {
//            c.init(createKeyManager("SunX509", clientJKS),
//                    createTrustManager("SunX509", clientJKS), null);
//        } catch (KeyManagementException ex) {
//            Logger.getLogger(WolfSSLEngineTest.class.getName()).log(Level.SEVERE, null, ex);
//        }
//        client = c.createSSLEngine("wolfSSL client test", 11111);
//        server = c.createSSLEngine();


        ciphers = client.getSupportedCipherSuites();
        
        /* use a ECDHE-RSA suite if available */
        for (String x : ciphers) {
            if (x.contains("ECDHE_RSA")) {
                cipher = x;
                break;
            }
        }
        ret = testConnection(server, client, new String[] { cipher },
                new String[] { "TLSv1.2" }, "Test cipher suite");
        if (ret != 0) {
            System.out.println("\t... failed");
            fail("failed to create engine");   
        }
        System.out.println("\t... passed");
        
        
        
        System.out.print("\tTesting close connection");        
        try {
            /* test close connection */
            CloseConnection(server, client, false);
        } catch (SSLException ex) {
            System.out.println("\t... failed");
            fail("failed to create engine"); 
        }
        System.out.println("\t... passed");
    }
    
    @Test
    public void testReuseSession()
        throws NoSuchProviderException, NoSuchAlgorithmException {
        SSLEngine server;
        SSLEngine client;
        String    cipher = null;
        int ret, i;
        String[] ciphers;

        /* create new SSLEngine */
        System.out.print("\tTesting reuse of session");

        createSSLContext("TLS");
        server = this.ctx.createSSLEngine();
        client = this.ctx.createSSLEngine("wolfSSL client test", 11111);

        /* use wolfJSSE client */
//        SSLContext c = SSLContext.getInstance("TLSv1.2", "wolfJSSE");
//        try {
//            c.init(createKeyManager("SunX509", clientJKS),
//                    createTrustManager("SunX509", clientJKS), null);
//        } catch (KeyManagementException ex) {
//            Logger.getLogger(WolfSSLEngineTest.class.getName()).log(Level.SEVERE, null, ex);
//        }
//        client = c.createSSLEngine("wolfSSL client test", 11111);
//        server = c.createSSLEngine();

        ret = testConnection(server, client, null, null, "Test reuse");
        if (ret != 0) {
            System.out.println("\t... failed");
            fail("failed to create engine");   
        }
             
        try {
            /* test close connection */
            CloseConnection(server, client, false);
        } catch (SSLException ex) {
            System.out.println("\t... failed");
            fail("failed to create engine"); 
        }

        /* use wolfJSSE client */
//        c = SSLContext.getInstance("TLSv1.2", "wolfJSSE");
//        try {
//            c.init(createKeyManager("SunX509", clientJKS),
//                    createTrustManager("SunX509", clientJKS), null);
//        } catch (KeyManagementException ex) {
//            Logger.getLogger(WolfSSLEngineTest.class.getName()).log(Level.SEVERE, null, ex);
//        }
//        client = c.createSSLEngine("wolfSSL client test", 11111);
//        server = c.createSSLEngine();


        server = this.ctx.createSSLEngine();
        client = this.ctx.createSSLEngine("wolfSSL client test", 11111);
        client.setEnableSessionCreation(false);
        ret = testConnection(server, client, null, null, "Test reuse");
        if (ret != 0) {
            System.out.println("\t... failed");
            fail("failed to create engine");   
        }
        try {
            /* test close connection */
            CloseConnection(server, client, false);
        } catch (SSLException ex) {
            System.out.println("\t... failed");
            fail("failed to create engine"); 
        }
        System.out.println("\t... passed");
    }
    
    @Test
    public void testThreadedUse()
        throws NoSuchProviderException, NoSuchAlgorithmException {
        ServerEngine server;
        ClientEngine client;

        /* create new SSLEngine */
        System.out.print("\tTesting threaded use");

        this.ctx = null; /* create new ctx */
        createSSLContext("TLS");
        server = new ServerEngine(this);
        client = new ClientEngine(this);

        /* use wolfJSSE client */
//        SSLContext c = SSLContext.getInstance("TLSv1.2", "wolfJSSE");
//        try {
//            c.init(createKeyManager("SunX509", clientJKS),
//                    createTrustManager("SunX509", clientJKS), null);
//        } catch (KeyManagementException ex) {
//            Logger.getLogger(WolfSSLEngineTest.class.getName()).log(Level.SEVERE, null, ex);
//        }
//        client = c.createSSLEngine("wolfSSL client test", 11111);
//        server = c.createSSLEngine();

        client.setServer(server);
        server.setClient(client);
        
        server.start();
        client.start();
        
        try {
            server.join(1000);
            client.join(1000);
        } catch (InterruptedException ex) {
            System.out.println("interupt happened");
            Logger.getLogger(WolfSSLEngineTest.class.getName()).log(Level.SEVERE, null, ex);
        }

        if (!server.success || !client.success) {
            System.out.println("\t\t... failed");
            fail("failed to successfully connect");   
        }
        System.out.println("\t\t... passed");
    }
    
    /* status tests buffer overflow/underflow/closed test */
    
    
    protected class ServerEngine extends Thread
    {
        private final SSLEngine server;
        private ClientEngine client;
        private HandshakeStatus status;
        protected boolean success;
        
        public ServerEngine(WolfSSLEngineTest in) {
            server = in.ctx.createSSLEngine();
            server.setUseClientMode(false);
            server.setNeedClientAuth(false);
            status = HandshakeStatus.NOT_HANDSHAKING;
            success = false;
        }
        
        @Override
        public void run() {
            ByteBuffer out =
                    ByteBuffer.allocateDirect(server.getSession().getPacketBufferSize());;
            ByteBuffer in = ByteBuffer.wrap("Hello wolfSSL JSSE".getBytes());
            
            do {
                SSLEngineResult result;
                try {
                    Runnable run;
                    result = server.wrap(in, out);
                    while ((run = server.getDelegatedTask()) != null) {
                        run.run();
                    }
                    if (result.bytesProduced() > 0) {
                        out.flip();
                        do {
                            client.toClient(out);
                        } while (out.remaining() > 0);
                        out.compact();
                    }
                    status = result.getHandshakeStatus();
                } catch (SSLException ex) {
                    Logger.getLogger(WolfSSLEngineTest.class.getName()).log(Level.SEVERE, null, ex);
                    return;
                }
            } while (status != HandshakeStatus.NOT_HANDSHAKING);
            success = true;
           
        }
        
        
        protected void toServer(ByteBuffer in) throws SSLException {
            Runnable run;
            SSLEngineResult result;
            ByteBuffer out =
                    ByteBuffer.allocateDirect(server.getSession().getPacketBufferSize());;
            result = server.unwrap(in, out);
            while ((run = server.getDelegatedTask()) != null) {
                run.run();
            }
        }
        
        protected void setClient(ClientEngine in) {
            client = in;
        }
    }
    
    protected class ClientEngine extends Thread
    {
        private final SSLEngine client;
        private ServerEngine server;
        private HandshakeStatus status;
        protected boolean success;
        
        public ClientEngine(WolfSSLEngineTest in) {
            client = in.ctx.createSSLEngine("wolfSSL threaded client test", 11111);
            client.setUseClientMode(true);
            status = HandshakeStatus.NOT_HANDSHAKING;
            success = false;
        }
        
        @Override
        public void run() {
            ByteBuffer out =
                    ByteBuffer.allocateDirect(client.getSession().getPacketBufferSize());;
            ByteBuffer in = ByteBuffer.wrap("Hello wolfSSL JSSE".getBytes());
            
            do {
                SSLEngineResult result;
                try {
                    Runnable run;
                    result = client.wrap(in, out);
                    while ((run = client.getDelegatedTask()) != null) {
                        run.run();
                    }
                    if (result.bytesProduced() > 0) {
                        out.flip();
                        do { /* send all data */
                            server.toServer(out);
                        } while (out.remaining() > 0);
                        out.compact();
                    }
                    status = result.getHandshakeStatus();
                } catch (SSLException ex) {
                    Logger.getLogger(WolfSSLEngineTest.class.getName()).log(Level.SEVERE, null, ex);
                    return;
                }
            } while (status != HandshakeStatus.NOT_HANDSHAKING);
            success = true;
        }
        
        protected void toClient(ByteBuffer in) throws SSLException {
            Runnable run;
            SSLEngineResult result;
            ByteBuffer out = 
                    ByteBuffer.allocateDirect(client.getSession().getPacketBufferSize());
            result = client.unwrap(in, out);
            while ((run = client.getDelegatedTask()) != null) {
                run.run();
            }
        }
        
        protected void setServer(ServerEngine in) {
            server = in;
        }
    }
}
