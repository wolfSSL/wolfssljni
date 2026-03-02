/* WolfSSLTestFactory.java
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

package com.wolfssl.provider.jsse.test;

import java.util.Date;
import java.time.Instant;
import java.time.Duration;
import java.math.BigInteger;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.KeyStoreException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.Arrays;
import java.util.Enumeration;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLCertificate;
import com.wolfssl.WolfSSLX509Name;
import com.wolfssl.WolfSSLException;
import com.wolfssl.WolfSSLJNIException;

/**
 * Used to create common classes among test cases
 *
 * @author wolfSSL
 */
class WolfSSLTestFactory {

    protected String allJKS;
    protected String allMixedJKS;
    protected String clientJKS;
    protected String clientRSA1024JKS;
    protected String clientRSAJKS;
    protected String clientECCJKS;
    protected String clientRSAPSSJKS;
    protected String serverJKS;
    protected String serverRSA1024JKS;
    protected String serverRSAJKS;
    protected String serverECCJKS;
    protected String serverRSAPSSJKS;
    protected String caJKS;
    protected String caClientJKS;
    protected String caServerJKS;

    protected String googleCACert;
    protected String exampleComCert;

    protected final static String jksPassStr = "wolfSSL test";
    protected final static char[] jksPass = jksPassStr.toCharArray();
    protected String keyStoreType = "JKS";
    private boolean extraDebug = false;

    /**
     * Shared lock for synchronization around tests that modify or use the Java
     * Security property: jdk.tls.disabledAlgorithms
     */
    public static final Object jdkTlsDisabledAlgorithmsLock = new Object();

    protected WolfSSLTestFactory() throws WolfSSLException {
        /* wolfJSSE example Java KeyStore files, containing:
         * all.jks               All certs
         * all_mixed.jks         All certs, mixed order
         * client.jks            RSA 2048-bit and ECC client certs
         * client-rsa-1024.jks   RSA 1024-bit only client cert
         * client-rsa.jks        RSA 2048-bit only client cert
         * client-ecc.jks        ECC only client cert
         * client-rsapss.jks     RSA_PSS only client cert
         * server.jks            RSA 2048-bit and ECC server certs
         * server-rsa-1024.jks   RSA 1024-bit only server cert
         * server-rsa.jks        RSA 2048-bit only server cert
         * server-ecc.jks        ECC only server cert
         * server-rsapss.jks     RSA_PSS only server cert
         * cacerts.jks           All CA certs (RSA, ECC, 1024, 2048, etc)
         * ca-client.jks         CA certs used to verify client certs
         * ca-server.jks         CA certs used to verify server certs */
        allJKS           = "examples/provider/all.jks";
        allMixedJKS      = "examples/provider/all_mixed.jks";
        clientJKS        = "examples/provider/client.jks";
        clientRSA1024JKS = "examples/provider/client-rsa-1024.jks";
        clientRSAJKS     = "examples/provider/client-rsa.jks";
        clientECCJKS     = "examples/provider/client-ecc.jks";
        clientRSAPSSJKS  = "examples/provider/client-rsapss.jks";
        serverJKS        = "examples/provider/server.jks";
        serverRSA1024JKS = "examples/provider/server-rsa-1024.jks";
        serverRSAJKS     = "examples/provider/server-rsa.jks";
        serverECCJKS     = "examples/provider/server-ecc.jks";
        serverRSAPSSJKS  = "examples/provider/server-rsapss.jks";
        caJKS            = "examples/provider/cacerts.jks";
        caClientJKS      = "examples/provider/ca-client.jks";
        caServerJKS      = "examples/provider/ca-server.jks";

        /* External CA certificate files */
        googleCACert     = "examples/certs/ca-google-root.der";
        exampleComCert   = "examples/certs/example-com.der";

        /* test if running from IDE directory */
        File f = new File(serverJKS);
        if (!f.exists()) {

            /* check IDE location */
            if (isIDEFile())
                return;

            /* check Android location */
            if (isAndroidFile())
                return;

            /* no known file paths */
            System.out.println("could not find file " + f.getAbsolutePath());
            throw new WolfSSLException("Unable to find test files");
        }

    }

    private void setPaths(String in) {
        allJKS = in.concat(allJKS);
        allMixedJKS = in.concat(allMixedJKS);
        clientJKS = in.concat(clientJKS);
        clientRSA1024JKS = in.concat(clientRSA1024JKS);
        clientRSAJKS = in.concat(clientRSAJKS);
        clientECCJKS = in.concat(clientECCJKS);
        clientRSAPSSJKS = in.concat(clientRSAPSSJKS);
        serverJKS = in.concat(serverJKS);
        serverRSA1024JKS = in.concat(serverRSA1024JKS);
        serverRSAJKS = in.concat(serverRSAJKS);
        serverECCJKS = in.concat(serverECCJKS);
        serverRSAPSSJKS = in.concat(serverRSAPSSJKS);
        caJKS = in.concat(caJKS);
        caClientJKS = in.concat(caClientJKS);
        caServerJKS = in.concat(caServerJKS);

        googleCACert = in.concat(googleCACert);
        exampleComCert = in.concat(exampleComCert);
    }

    private boolean isIDEFile() {
        String esc = "../../../";
        File f;

        f = new File(esc.concat(serverJKS));
        if (f.exists()) {
            setPaths(esc);
            return true;
        }
        return false;
    }

    private boolean isAndroidFile() {
        String sdc = "/data/local/tmp/";
        File f;

        if (isAndroid()) {
            allJKS           = "examples/provider/all.bks";
            allMixedJKS      = "examples/provider/all_mixed.bks";
            clientJKS        = "examples/provider/client.bks";
            clientRSA1024JKS = "examples/provider/client-rsa-1024.bks";
            clientRSAJKS     = "examples/provider/client-rsa.bks";
            clientECCJKS     = "examples/provider/client-ecc.bks";
            clientRSAPSSJKS  = "examples/provider/client-rsapss.bks";
            serverJKS        = "examples/provider/server.bks";
            serverRSA1024JKS = "examples/provider/server-rsa-1024.bks";
            serverRSAJKS     = "examples/provider/server-rsa.bks";
            serverECCJKS     = "examples/provider/server-ecc.bks";
            serverRSAPSSJKS  = "examples/provider/server-rsapss.bks";
            caJKS            = "examples/provider/cacerts.bks";
            caClientJKS      = "examples/provider/ca-client.bks";
            caServerJKS      = "examples/provider/ca-server.bks";
            keyStoreType = "BKS";
        }

        f = new File(sdc.concat(serverJKS));
        if (f.exists()) {
            setPaths(sdc);
            return true;
        }
        return false;
    }

    /* prints in a format that can be imported into wireshark */
    protected void printHex(ByteBuffer in) {
        int i = 0, j = 0;
        while (in.remaining() > 0) {
            if ((i % 8) == 0) {
                System.out.printf("\n%06X", j * 8);
                j++;
            }
            System.out.printf(" %02X ", in.get());
            i++;
        }
        System.out.println("");
        in.flip();
    }

    private TrustManager[] internalCreateTrustManager(String type,
        KeyStore store, String file, String provider)
        throws NoSuchAlgorithmException, KeyStoreException, IOException,
               CertificateException, NoSuchProviderException {

        TrustManagerFactory tm = null;
        KeyStore cert = null;

        try {
            /* Load/get correct KeyStore */
            if ((store == null) && (file != null) && !file.isEmpty()) {
                InputStream stream = new FileInputStream(file);
                cert = KeyStore.getInstance(keyStoreType);
                cert.load(stream, jksPass);
                stream.close();
            }
            else if (store != null) {
                cert = store;
            }

            /* Initialize tm with KeyStore/certs */
            if (provider == null) {
                tm = TrustManagerFactory.getInstance(type);
            }
            else {
                tm = TrustManagerFactory.getInstance(type, provider);
            }

            tm.init(cert);
            return tm.getTrustManagers();

        } catch (NoSuchAlgorithmException | KeyStoreException |
             IOException | CertificateException | NoSuchProviderException ex) {

            ex.printStackTrace();
            throw ex;
        }
    }

    /**
     * Using default password "wolfSSL test"
     *
     * @param type of key manager i.e. "SunX509"
     * @param file file name to read from
     * @return new trustmanager [] on success and null on failure
     */
    protected TrustManager[] createTrustManager(String type, String file)
        throws NoSuchAlgorithmException, KeyStoreException, IOException,
               CertificateException, NoSuchProviderException {

        return internalCreateTrustManager(type, null, file, null);
    }

    /**
     * Create TrustManager[] using default password "wolfSSL test", from
     * provided JKS file path.
     *
     * @param type of key manager i.e. "SunX509"
     * @param file JKS file name to read from
     * @return new TrustManager[] on success and null on failure
     */
    protected TrustManager[] createTrustManager(String type, String file,
            String provider) throws NoSuchAlgorithmException, KeyStoreException,
            IOException, CertificateException, NoSuchProviderException {

        return internalCreateTrustManager(type, null, file, provider);
    }

    /**
     * Create TrustManager[] using default password "wolfSSL test", from
     * provided KeyStore object.
     *
     * @param type of key manager i.e. "SunX509"
     * @param store KeyStore object containing trusted cert(s)
     * @return new TrustManager[] on success and null on failure
     */
    protected TrustManager[] createTrustManager(String type, KeyStore store,
        String provider) throws NoSuchAlgorithmException, KeyStoreException,
        IOException, CertificateException, NoSuchProviderException {

        return internalCreateTrustManager(type, store, null, provider);
    }

    private KeyManager[] internalCreateKeyManager(String type, KeyStore store,
        String file, String provider) throws NoSuchAlgorithmException,
        KeyStoreException, IOException, CertificateException,
        NoSuchProviderException, UnrecoverableKeyException {

        KeyManagerFactory km = null;
        KeyStore pKey = null;

        try {
            /* set up KeyStore */
            if ((store == null) && (file != null) && !file.isEmpty()) {
                InputStream stream = new FileInputStream(file);
                pKey = KeyStore.getInstance(keyStoreType);
                pKey.load(stream, jksPass);
                stream.close();
            }
            else if (store != null) {
                pKey = store;
            }

            /* load private key */
            if (provider == null) {
                km = KeyManagerFactory.getInstance(type);
            }
            else {
                km = KeyManagerFactory.getInstance(type, provider);
            }

            km.init(pKey, jksPass);
            return km.getKeyManagers();

        } catch (NoSuchAlgorithmException | KeyStoreException |
             IOException | CertificateException | NoSuchProviderException |
             UnrecoverableKeyException ex) {

            ex.printStackTrace();
            throw ex;
        }
    }

    /**
     * Create KeyManager[] using default password "wolfSSL test" and provided
     * path to JKS file.
     *
     * @param type of key manager i.e. "SunX509"
     * @param file JKS file path to read from
     *
     * @return new KeyManager[] on success and null on failure
     */
    protected KeyManager[] createKeyManager(String type, String file)
        throws NoSuchAlgorithmException, KeyStoreException, IOException,
               CertificateException, NoSuchProviderException,
               UnrecoverableKeyException {

        return internalCreateKeyManager(type, null, file, null);
    }

    /**
     * Create KeyManager[] using default password "wolfSSL test" and provided
     * KeyStore object.
     *
     * @param type of key manager i.e. "SunX509"
     * @param store KeyStore object to read from
     *
     * @return new KeyManager[] on success and null on failure
     */
    protected KeyManager[] createKeyManager(String type, KeyStore store)
        throws NoSuchAlgorithmException, KeyStoreException, IOException,
               CertificateException, NoSuchProviderException,
               UnrecoverableKeyException {

        return internalCreateKeyManager(type, store, null, null);
    }

    /**
     * Create KeyManager[] using default password "wolfSSL test", provided
     * path to JKS file, and specifying a JSSE provider for KeyManagerFactory.
     *
     * @param type of key manager i.e. "SunX509"
     * @param file JKS file path to read from
     * @param provider Provider of KeyManagerFactory to use
     *
     * @return new KeyManager[] on success and null on failure
     */
    protected KeyManager[] createKeyManager(String type, String file,
        String provider) throws NoSuchAlgorithmException, KeyStoreException,
        IOException, CertificateException, NoSuchProviderException,
        UnrecoverableKeyException {

        return internalCreateKeyManager(type, null, file, provider) ;
    }

    /**
     * Create KeyManager[] using default password "wolfSSL test", provided
     * KeyStore object, and specifying a JSSE provider for KeyManagerFactory.
     *
     * @param type of key manager i.e. "SunX509"
     * @param store KeyStore object to read from
     * @param provider Provider of KeyManagerFactory to use
     *
     * @return new KeyManager[] on success and null on failure
     */
    protected KeyManager[] createKeyManager(String type, KeyStore store,
        String provider) throws NoSuchAlgorithmException, KeyStoreException,
        IOException, CertificateException, NoSuchProviderException,
        UnrecoverableKeyException {

        return internalCreateKeyManager(type, store, null, provider);
    }

    private SSLContext internalCreateSSLContext(String protocol,
        String provider, TrustManager[] tm, KeyManager[] km)
        throws NoSuchAlgorithmException, KeyManagementException,
               NoSuchProviderException, KeyStoreException, CertificateException,
               UnrecoverableKeyException, IOException {

        SSLContext ctx = null;
        TrustManager[] localTm = tm;
        KeyManager[] localKm = km;

        try {
            if (provider != null) {
                ctx = SSLContext.getInstance(protocol, provider);
                if (tm == null) {
                    localTm = createTrustManager("SunX509", clientJKS,
                        provider);
                }
                if (km == null) {
                    localKm = createKeyManager("SunX509", clientJKS, provider);
                }
            } else {
                ctx = SSLContext.getInstance(protocol);
                if (tm == null) {
                    localTm = createTrustManager("SunX509", clientJKS);
                }
                if (km == null) {
                    localKm = createKeyManager("SunX509", clientJKS);
                }
            }

            ctx.init(localKm, localTm, null);
            return ctx;

        } catch (NoSuchAlgorithmException | KeyManagementException |
                 NoSuchProviderException | KeyStoreException |
                 IOException | CertificateException |
                 UnrecoverableKeyException ex) {

            ex.printStackTrace();
            throw ex;
        }
    }

    /**
     * Creates a new context using default provider of system (usually Oracle)
     *
     * @param protocol to be used when creating context
     * @return new SSLContext on success and null on failure
     */
    protected SSLContext createSSLContext(String protocol)
        throws NoSuchAlgorithmException, KeyManagementException,
               NoSuchProviderException, KeyStoreException, CertificateException,
               UnrecoverableKeyException, IOException {

        return internalCreateSSLContext(protocol, null, null, null);
    }

    /**
     * Creates a new context using provider passed in
     *
     * @param protocol to be used when creating context
     * @param provider to be used when creating context
     * @return new SSLContext on success and null on failure
     */
    protected SSLContext createSSLContext(String protocol, String provider)
        throws NoSuchAlgorithmException, KeyManagementException,
               NoSuchProviderException, KeyStoreException, CertificateException,
               UnrecoverableKeyException, IOException {

        return internalCreateSSLContext(protocol, provider, null, null);
    }

    /**
     * Creates a new context using provider passed in and km/tm. Falls back
     * and creates default TrustManager/KeyManager if those arguments are
     * null.
     *
     * @param protocol to be used when creating context
     * @param provider to be used when creating context (can be null)
     * @param tm trust manager to use (can be null)
     * @param km key manager to use (can be null)
     * @return new SSLContext on success and null on failure
     */
    protected SSLContext createSSLContext(String protocol, String provider,
        TrustManager[] tm, KeyManager[] km) throws NoSuchAlgorithmException,
        KeyManagementException, NoSuchProviderException, KeyStoreException,
        CertificateException, UnrecoverableKeyException, IOException {

        return internalCreateSSLContext(protocol, provider, tm, km);
    }

    /**
     * Creates a new context using provider passed in and km/tm, does not
     * fallback and create default TrustManager/KeyManager if thoes arguments
     * are null.
     *
     * @param protocol to be used when creating context
     * @param provider to be used when creating context (can be null)
     * @param tm trust manager to use (can be null)
     * @param km key manager to use (can be null)
     * @return new SSLContext on success and null on failure
     */
    protected SSLContext createSSLContextNoDefaults(String protocol,
        String provider, TrustManager[] tm, KeyManager[] km) {

        SSLContext ctx = null;

        try {
            if (provider != null) {
                ctx = SSLContext.getInstance(protocol, provider);
            } else {
                ctx = SSLContext.getInstance(protocol);
            }

            ctx.init(km, tm, null);
            return ctx;

        } catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace();
        } catch (KeyManagementException ex) {
            ex.printStackTrace();
        } catch (NoSuchProviderException ex) {
            ex.printStackTrace();
        }
        return null;
    }

    /**
     * Red coloring to fail message
     * @param msg
     */
    static void fail(String msg) {
        System.out.println(msg);
        /* commented out because of portability concerns
        if (System.getProperty("os.name").contains("Windows")) {
            System.out.println(msg);
        }
        else {
            String red = "\u001B[31m";
            String reset = "\u001B[0m";
            System.out.println(red + msg + reset);
        }
        */
    }

    /**
     * Green coloring to pass message
     * @param msg
     */
    static void pass(String msg) {
        System.out.println(msg);
        /* commented out because of portability concerns
        if (System.getProperty("os.name").contains("Windows")) {
            System.out.println(msg);
        }
        else {
            String green = "\u001B[32m";
            String reset = "\u001B[0m";
            System.out.println(green + msg + reset);
        }
        */
    }

    /**
     * Run SSLEngine delegated tasks.
     *
     * wolfJSSE doesn't use delegated tasks, but we use this for
     * compatibility so tests can be switched and run against different
     * providers.
     */
    private void runDelegatedTasks(SSLEngine engine) {
        Runnable run;

        while ((run = engine.getDelegatedTask()) != null) {
            run.run();
        }
    }

    /**
     * Helper method to verify received data, called by testConnection().
     */
    private boolean verifyReceivedData(ByteBuffer buf, String expected) {
        buf.flip();
        byte[] b = new byte[buf.remaining()];
        buf.get(b);
        String received = new String(b, StandardCharsets.UTF_8).trim();
        return expected.equals(received);
    }

    /**
     * Does SSL/TLS handshake between two SSLEngine objects, then
     * sends application data from client to server and vice versa.
     * Application data received by client/server is compared to
     * original sent as a sanity check.
     *
     * @param server SSLEngine for server side of connection
     * @param client SSLEngine for client side of connection
     * @param cipherSuites cipher suites to use, can be null
     * @param protocols TLS protocols to use i.e. TLSv1.2, can be null
     * @param appData message to send after handshake, can be null to not
     *                send any data.
     *
     * @return 0 on success, -1 on error. Any exceptions thrown
     *         inside the body of this method are caught and converted into
     *         a -1 return.
     */
    protected int testConnection(SSLEngine server, SSLEngine client,
        String[] cipherSuites, String[] protocols, String appData) {

        /* Max loop protection against infinite loops */
        int loops = 0;
        int maxLoops = 50;
        boolean handshakeComplete = false;

        /* Allocate buffers large enough for protocol packets */
        ByteBuffer serToCli = ByteBuffer.allocateDirect(
            server.getSession().getPacketBufferSize());
        ByteBuffer cliToSer = ByteBuffer.allocateDirect(
            client.getSession().getPacketBufferSize());

        /* Application data buffers */
        ByteBuffer toSendCli = ByteBuffer.wrap(appData.getBytes());
        ByteBuffer toSendSer = ByteBuffer.wrap(appData.getBytes());
        ByteBuffer serPlain = ByteBuffer.allocate(
            server.getSession().getApplicationBufferSize());
        ByteBuffer cliPlain = ByteBuffer.allocate(
            client.getSession().getApplicationBufferSize());

        /* Configure protocols and cipher suites if specified */
        if (cipherSuites != null) {
            server.setEnabledCipherSuites(cipherSuites);
            client.setEnabledCipherSuites(cipherSuites);
        }
        if (protocols != null) {
            server.setEnabledProtocols(protocols);
            client.setEnabledProtocols(protocols);
        }

        while (!handshakeComplete && loops++ < maxLoops) {
            try {
                HandshakeStatus clientStatus = client.getHandshakeStatus();
                HandshakeStatus serverStatus = server.getHandshakeStatus();

                /* client wrap() */
                if (clientStatus == HandshakeStatus.NEED_WRAP ||
                    (clientStatus == HandshakeStatus.NOT_HANDSHAKING &&
                     toSendCli.hasRemaining())) {
                    SSLEngineResult result = client.wrap(toSendCli, cliToSer);
                    runDelegatedTasks(client);
                    if (result.getStatus() ==
                        SSLEngineResult.Status.BUFFER_OVERFLOW) {
                        return -1;
                    }
                    if (extraDebug) {
                        System.out.println("[client wrap] " + result);
                    }
                }

                /* server wrap() */
                if (serverStatus == HandshakeStatus.NEED_WRAP ||
                    (serverStatus == HandshakeStatus.NOT_HANDSHAKING &&
                     toSendSer.hasRemaining())) {
                    SSLEngineResult result = server.wrap(toSendSer, serToCli);
                    runDelegatedTasks(server);
                    if (result.getStatus() ==
                        SSLEngineResult.Status.BUFFER_OVERFLOW) {
                        return -1;
                    }
                    if (extraDebug) {
                        System.out.println("[server wrap] " + result);
                    }
                }

                /* flip buffers for unwrap() */
                cliToSer.flip();
                serToCli.flip();

                /* client unwrap() */
                if ((clientStatus == HandshakeStatus.NEED_UNWRAP ||
                     clientStatus == HandshakeStatus.NOT_HANDSHAKING) &&
                    serToCli.hasRemaining()) {
                    SSLEngineResult result = client.unwrap(serToCli, cliPlain);
                    runDelegatedTasks(client);
                    if (result.getStatus() ==
                        SSLEngineResult.Status.BUFFER_OVERFLOW) {
                        return -1;
                    }
                    if (extraDebug) {
                        System.out.println("[client unwrap] " + result);
                    }
                }

                /* server unwrap() */
                if ((serverStatus == HandshakeStatus.NEED_UNWRAP ||
                     serverStatus == HandshakeStatus.NOT_HANDSHAKING) &&
                    cliToSer.hasRemaining()) {
                    SSLEngineResult result = server.unwrap(cliToSer, serPlain);
                    runDelegatedTasks(server);
                    if (result.getStatus() ==
                        SSLEngineResult.Status.BUFFER_OVERFLOW) {
                        return -1;
                    }
                    if (extraDebug) {
                        System.out.println("[server unwrap] " + result);
                    }
                }

                /* compact network buffers */
                cliToSer.compact();
                serToCli.compact();

                /* Check if handshake is complete and data exchanged */
                if (!toSendCli.hasRemaining() && !toSendSer.hasRemaining() &&
                    client.getHandshakeStatus() ==
                        HandshakeStatus.NOT_HANDSHAKING &&
                    server.getHandshakeStatus() ==
                        HandshakeStatus.NOT_HANDSHAKING) {

                    /* Verify received data matches expected */
                    if (!verifyReceivedData(cliPlain, appData) ||
                        !verifyReceivedData(serPlain, appData)) {
                        return -1;
                    }
                    handshakeComplete = true;
                }

            } catch (SSLException ex) {
                return -1;
            }
        }

        return handshakeComplete ? 0 : -1;
    }

    /**
     * Close down an SSLEngine connection.
     *
     * @param server
     * @param client
     * @param earlyClose
     *
     * @return 0 on success, negative on error
     *
     * @throws SSLException
     */
    public int CloseConnection(SSLEngine server, SSLEngine client,
        boolean earlyClose) throws SSLException {

        ByteBuffer serToCli = ByteBuffer.allocateDirect(
            server.getSession().getPacketBufferSize());
        ByteBuffer cliToSer = ByteBuffer.allocateDirect(
            client.getSession().getPacketBufferSize());
        ByteBuffer empty = ByteBuffer.allocate(
            server.getSession().getPacketBufferSize());
        SSLEngineResult result;
        HandshakeStatus s;
        boolean passed;

        /* Close outBound to begin process of sending close_notify alert */
        client.closeOutbound();
        if (client.getHandshakeStatus() != HandshakeStatus.NEED_WRAP) {
            throw new SSLException("closeOutbound should result in NEED_WRAP");
        }

        /* Generate close_notify alert */
        result = client.wrap(empty, cliToSer);
        if (extraDebug) {
            System.out.println(
                "[client wrap] consumed = " + result.bytesConsumed() +
                " produced = " + result.bytesProduced() +
                " status = " + result.getStatus().name());
        }
        runDelegatedTasks(client);

        s = client.getHandshakeStatus();
        if (extraDebug) {
            System.out.println("client status = " + s.toString());
        }
        /* result.bytesProduced() should be > 0 for closeNotify produced.
         * consumed will be 0 at this point since peer closeNotify not yet
         * consumed */
        if (result.bytesProduced() <= 0) {
            throw new SSLException("Client wrap consumed/produced error");
        }
        /* HandshakeStatus should be NOT_HANDSHAKING since receipt of
         * peer close_notify is optional after client sends one */
        if (!s.toString().equals("NOT_HANDSHAKING") ||
                !result.getStatus().name().equals("CLOSED") ) {
            throw new SSLException("Status should be NOT_HANDSHAKING/CLOSED");
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
                throw new SSLException(
                    "Expected to fail on early close inbound");
            }

            try {
                passed = false;
                client.closeInbound();
            }
            catch (SSLException e) {
                passed = true;
            }
            if (!passed) {
                throw new SSLException(
                    "Expected to fail on early close inbound");
            }
            return 0;
        }

        /* server unwraps client close_notify */
        result = server.unwrap(cliToSer, empty);
        cliToSer.compact();
        if (extraDebug) {
            System.out.println(
                "[server unwrap] consumed = " + result.bytesConsumed() +
                " produced = " + result.bytesProduced() +
                " status = " + result.getStatus().name());
        }
        if (result.getStatus().name().equals("CLOSED")) {
            /* odd case where server tries to send "empty" if not set close */
            server.closeOutbound();
        }
        runDelegatedTasks(server);

        s = server.getHandshakeStatus();
        if (result.bytesProduced() != 0 || result.bytesConsumed() <= 0) {
            throw new SSLException("Server unwrap consumed/produced error");
        }
        if (!s.toString().equals("NEED_WRAP") ||
                !result.getStatus().name().equals("CLOSED") ) {
            throw new SSLException(
                "Bad status: HS=" + s +
                " status=" + result.getStatus());
        }

        /* server wraps its own close_notify */
        result = server.wrap(empty, serToCli);
        serToCli.flip();
        if (extraDebug) {
            System.out.println(
                "[server wrap] consumed = " + result.bytesConsumed() +
                " produced = " + result.bytesProduced() +
                " status = " + result.getStatus().name());
        }
        runDelegatedTasks(server);

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

        /* client unwraps server close_notify */
        result = client.unwrap(serToCli, empty);
        serToCli.compact();
        if (extraDebug) {
            System.out.println(
                "[client unwrap] consumed = " + result.bytesConsumed() +
                " produced = " + result.bytesProduced() +
                " status = " + result.getStatus().name());
        }
        runDelegatedTasks(client);

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

    /**
     * Helper function, populates test subjectName for cert generation.
     * @param commonName Common Name to add to subjectName
     * @return new WolfSSLX509Name object
     */
    private WolfSSLX509Name generateTestSubjectName(String commonName)
        throws WolfSSLException {

        WolfSSLX509Name subjectName = new WolfSSLX509Name();
        subjectName.setCountryName("US");
        subjectName.setStateOrProvinceName("Montana");
        subjectName.setStreetAddress("12345 Test Address");
        subjectName.setLocalityName("Bozeman");
        subjectName.setSurname("Test Surname");
        subjectName.setCommonName(commonName);
        subjectName.setEmailAddress("support@example.com");
        subjectName.setOrganizationName("wolfSSL Inc.");
        subjectName.setOrganizationalUnitName("Test and Development");
        subjectName.setPostalCode("59715");
        subjectName.setUserId("TestUserID");

        return subjectName;
    }

    /**
     * Generate a JKS KeyStore object which contains a self-signed certificate
     * which contains the provided Common Name and Alt Name, also will have
     * basic constraints set to CA:TRUE.
     *
     * @param commonName Common Name to generate cert with
     * @param altName Subject altName to generate cert with
     *
     * @return new KeyStore object containing newly-generated certificate
     */
    protected KeyStore generateSelfSignedCertJKS(String commonName,
        String altName, boolean addPrivateKey) throws CertificateException,
        WolfSSLException, NoSuchAlgorithmException, IOException,
        KeyStoreException, WolfSSLJNIException {

        String test_KEY_USAGE =
            "digitalSignature,keyEncipherment,dataEncipherment";
        String test_EXT_KEY_USAGE =
            "clientAuth,serverAuth";

        if (commonName == null) {
            throw new CertificateException(
                "Invalid arguments, null common name");
        }

        WolfSSLCertificate x509 = new WolfSSLCertificate();

        /* Set notBefore/notAfter validity dates */
        Instant now = Instant.now();
        final Date notBefore = Date.from(now);
        final Date notAfter = Date.from(now.plus(Duration.ofDays(365)));
        x509.setNotBefore(notBefore);
        x509.setNotAfter(notAfter);

        /* Set serial number */
        x509.setSerialNumber(BigInteger.valueOf(12345));

        /* Set Subject Name */
        WolfSSLX509Name subjectName = generateTestSubjectName(commonName);
        x509.setSubjectName(subjectName);

        /* Not setting Issuer, since generating self-signed cert */

        /* Set Public Key from generated java.security.PublicKey,
         * RSA 2048-bit for now. Add method arguments later if we need
         * to generate other alg/sizes. */
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();
        PublicKey pubKey = keyPair.getPublic();
        x509.setPublicKey(pubKey);

        /* Add Extensions */
        x509.addExtension(WolfSSL.NID_key_usage, test_KEY_USAGE, false);
        x509.addExtension(WolfSSL.NID_ext_key_usage, test_EXT_KEY_USAGE, false);
        if (altName != null) {
            x509.addExtension(WolfSSL.NID_subject_alt_name, altName, false);
        }
        x509.addExtension(WolfSSL.NID_basic_constraints, true, true);

        /* Sign certificate, self-signed with java.security.PrivateKey.
         * Sign with SHA-256 for now. Can add method argument later to set
         * hash alg if needed. */
        PrivateKey privKey = keyPair.getPrivate();
        x509.signCert(privKey, "SHA256");

        /* Convert to X509Certificate */
        X509Certificate tmpX509 = x509.getX509Certificate();

        /* Create new KeyStore, load in newly generated cert. Add PrivateKey
         * if requested. */
        KeyStore store = KeyStore.getInstance(keyStoreType);
        store.load(null, jksPass);

        if (addPrivateKey) {
            store.setKeyEntry("cert_entry", privKey, jksPass,
                new X509Certificate[] { tmpX509 });
        }
        else {
            store.setCertificateEntry("cert_entry", tmpX509);
        }

        /* Free native memory */
        subjectName.free();
        x509.free();

        return store;
    }

    /**
     * Returns the DER encoded buffer of the certificate
     * @param alias lookup alias in allJKS
     * @return the DER encoded buffer of the certificate or null on failure
     * @throws KeyStoreException error getting allJKS
     * @throws NoSuchAlgorithmException exception
     * @throws CertificateException exception getting cert DER
     * @throws IOException exception reading allJKS
     */
    protected byte[] getCert(String alias) throws KeyStoreException,
    NoSuchAlgorithmException, CertificateException, IOException {
        KeyStore ks = KeyStore.getInstance(keyStoreType);
        InputStream stream = new FileInputStream(allJKS);
        ks.load(stream, jksPass);
        stream.close();
        if (!ks.containsAlias(alias)) {
            return null;
        }
        return ks.getCertificate(alias).getEncoded();
    }

    /**
     * Gets all alias's in allJKS
     * @return list of all alias's in allJKS
     * @throws KeyStoreException get allJKS keystore exception
     * @throws IOException reading file exception
     * @throws NoSuchAlgorithmException exception
     * @throws CertificateException exception
     */
    protected String[] getAlias() throws KeyStoreException, IOException,
    NoSuchAlgorithmException, CertificateException {
        KeyStore ks = KeyStore.getInstance(keyStoreType);
        Enumeration<String> alias;
        InputStream stream = new FileInputStream(allJKS);
        String ret[];
        int idx = 0;

        ks.load(stream, jksPass);
        stream.close();
        alias = ks.aliases();
        ret = new String[ks.size()];
        while (alias.hasMoreElements()) {
            if (idx >= ret.length) {
                return null;
            }

            ret[idx] = alias.nextElement();
            idx += 1;
        }
        return ret;
    }

    /**
     * Test if the env is Android
     * @return true if is Android system
     */
    protected static boolean isAndroid() {
        if (System.getProperty("java.runtime.name").contains("Android")) {
            return true;
        }
        return false;
    }

    /**
     * Test if the env is Windows.
     * @return true if Windows, otherwise false
     */
    protected static boolean isWindows() {
        if (System.getProperty("os.name").startsWith("Windows")) {
            return true;
        }
        return false;
    }

    /**
     * Check if Security property contains a specific value.
     *
     * @param prop System Security property to check
     * @param needle String value to search for in Security property
     *
     * @return true if found, otherwise false
     */
    protected static boolean securityPropContains(String prop, String needle) {

        String secProp = null;
        List<?> propList = null;

        if (prop == null || needle == null) {
            return false;
        }

        /* make sure protocol has not been disabled at system level */
        secProp = Security.getProperty(prop);
        if (secProp == null) {
            return false;
        }
        /* Remove spaces after commas, split into List */
        secProp = secProp.replaceAll(", ",",");
        propList = Arrays.asList(secProp.split(","));

        if (propList.contains(needle)) {
            return true;
        }

        return false;
    }

    /**
     * Load and convert PEM file to X509Certificate object.
     *
     * @param pemPath Path to PEM file
     * @return X509Certificate parsed from the PEM file
     * @throws Exception on parsing error
     */
    public static X509Certificate loadX509CertificateFromPem(String pemPath)
        throws Exception {

        WolfSSLCertificate cert = null;
        X509Certificate x509 = null;

        try {
            cert = new WolfSSLCertificate(pemPath, WolfSSL.SSL_FILETYPE_PEM);
            x509 = cert.getX509Certificate();

        } finally {
            if (cert != null) {
                cert.free();
            }
        }

        return x509;
    }
}
