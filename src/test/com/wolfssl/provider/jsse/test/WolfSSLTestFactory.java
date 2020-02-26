/* WolfSSLTestFactory.java
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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.Enumeration;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;

import com.wolfssl.WolfSSLException;

/**
 * Used to create common classes among test cases
 *
 * @author wolfSSL
 */
class WolfSSLTestFactory {

    protected String clientJKS;
    protected String serverJKS;
    protected String allJKS;
    protected String mixedJKS;
    protected String caJKS;
    protected String rsaJKS;
    protected String googleCACert;
    protected String exampleComCert;
    protected final static char[] jksPass = "wolfSSL test".toCharArray();
    protected String keyStoreType = "JKS";
    private boolean extraDebug = false;

    protected WolfSSLTestFactory() throws WolfSSLException {
        serverJKS = "examples/provider/server.jks";
        clientJKS = "examples/provider/client.jks";
        allJKS = "examples/provider/all.jks";
        mixedJKS = "examples/provider/all_mixed.jks";
        caJKS = "examples/provider/cacerts.jks";
        rsaJKS = "examples/provider/rsa.jks";
        googleCACert = "examples/certs/ca-google-root.der";
        exampleComCert = "examples/certs/example-com.der";

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
        serverJKS = in.concat(serverJKS);
        clientJKS = in.concat(clientJKS);
        allJKS = in.concat(allJKS);
        mixedJKS = in.concat(mixedJKS);
        caJKS = in.concat(caJKS);
        rsaJKS = in.concat(rsaJKS);
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
        String sdc = "/sdcard/";
        File f;

        if (isAndroid()) {
            serverJKS = "examples/provider/server.bks";
            clientJKS = "examples/provider/client.bks";
            allJKS = "examples/provider/all.bks";
            mixedJKS = "examples/provider/all_mixed.bks";
            caJKS = "examples/provider/cacerts.bks";
            rsaJKS = "examples/provider/rsa.bks";
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

    private TrustManager[] internalCreateTrustManager(String type, String file,
            String provider) {
        TrustManagerFactory tm;
        KeyStore cert = null;

        try {
            if (file != null) {
                InputStream stream = new FileInputStream(file);
                cert = KeyStore.getInstance(keyStoreType);
                cert.load(stream, jksPass);
                stream.close();
            }
            if (provider == null) {
                tm = TrustManagerFactory.getInstance(type);
            }
            else {
                tm = TrustManagerFactory.getInstance(type, provider);
            }
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
        } catch (NoSuchProviderException ex) {
            Logger.getLogger(WolfSSLTestFactory.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    /**
     * Using default password "wolfSSL test"
     *
     * @param type of key manager i.e. "SunX509"
     * @param file file name to read from
     * @return new trustmanager [] on success and null on failure
     */
    protected TrustManager[] createTrustManager(String type, String file) {
        return internalCreateTrustManager(type, file, null);
    }

    /**
     * Using default password "wolfSSL test"
     *
     * @param type of key manager i.e. "SunX509"
     * @param file file name to read from
     * @return new trustmanager [] on success and null on failure
     */
    protected TrustManager[] createTrustManager(String type, String file,
            String provider) {
        return internalCreateTrustManager(type, file, provider);
    }

    private KeyManager[] internalCreateKeyManager(String type, String file,
            String provider) {
        KeyManagerFactory km;
        KeyStore pKey;

        try {
            /* set up KeyStore */
            InputStream stream = new FileInputStream(file);
            pKey = KeyStore.getInstance(keyStoreType);
            pKey.load(stream, jksPass);
            stream.close();

            /* load private key */
            if (provider == null) {
                km = KeyManagerFactory.getInstance(type);
            }
            else {
                km = KeyManagerFactory.getInstance(type, provider);
            }
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
        } catch (NoSuchProviderException ex) {
            Logger.getLogger(WolfSSLTestFactory.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    /**
     * Using default password "wolfSSL test"
     *
     * @param type of key manager i.e. "SunX509"
     * @param file file name to read from
     * @return new keymanager [] on success and null on failure
     */
    protected KeyManager[] createKeyManager(String type, String file) {
        return internalCreateKeyManager(type, file, null);
    }

    /**
     * Using default password "wolfSSL test"
     *
     * @param type of key manager i.e. "SunX509"
     * @param file file name to read from
     * @return new keymanager [] on success and null on failure
     */
    protected KeyManager[] createKeyManager(String type, String file,
            String provider) {
        return internalCreateKeyManager(type, file, provider);
    }

    private SSLContext internalCreateSSLContext(String protocol, String provider,
            TrustManager[] tm, KeyManager[] km) {
        SSLContext ctx = null;
        TrustManager[] localTm = tm;
        KeyManager[] localKm = km;

        try {
            if (provider != null) {
                ctx = SSLContext.getInstance(protocol, provider);
                if (tm == null) {
                    localTm = createTrustManager("SunX509", clientJKS, provider);
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
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(WolfSSLEngineTest.class.getName()).log(Level.SEVERE, null, ex);
        } catch (KeyManagementException ex) {
            Logger.getLogger(WolfSSLEngineTest.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchProviderException ex) {
            System.out.println("Could not find the provider : " + provider);
            Logger.getLogger(WolfSSLEngineTest.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    /**
     * Creates a new context using default provider of system (usually Oracle)
     *
     * @param protocol to be used when creating context
     * @return new SSLContext on success and null on failure
     */
    protected SSLContext createSSLContext(String protocol) {
        return internalCreateSSLContext(protocol, null, null, null);
    }

    /**
     * Creates a new context using provider passed in
     *
     * @param protocol to be used when creating context
     * @param provider to be used when creating context
     * @return new SSLContext on success and null on failure
     */
    protected SSLContext createSSLContext(String protocol, String provider) {
        return internalCreateSSLContext(protocol, provider, null, null);
    }

    /**
     * Creates a new context using provider passed in and km/tm
     *
     * @param protocol to be used when creating context
     * @param provider to be used when creating context (can be null)
     * @param tm trust manager to use (can be null)
     * @param km key manager to use (can be null)
     * @return new SSLContext on success and null on failure
     */
    protected SSLContext createSSLContext(String protocol, String provider,
            TrustManager[] tm, KeyManager[] km) {
        return internalCreateSSLContext(protocol, provider, tm, km);
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
     * Engine connection. Makes server/client handshake in memory
     * @param server SSLEngine for server side of connection
     * @param client SSLEngine for client side of connection
     * @param cipherSuites cipher suites to use can be null
     * @param protocols TLS protocols to use i.e. TLSv1.2, can be null
     * @param appData message to send after handshake, can be null
     * @return
     */
    protected int testConnection(SSLEngine server, SSLEngine client,
            String[] cipherSuites, String[] protocols, String appData) {
        ByteBuffer serToCli = ByteBuffer.allocateDirect(server.getSession().getPacketBufferSize());
        ByteBuffer cliToSer = ByteBuffer.allocateDirect(client.getSession().getPacketBufferSize());
        ByteBuffer toSendCli = ByteBuffer.wrap(appData.getBytes());
        ByteBuffer toSendSer = ByteBuffer.wrap(appData.getBytes());
        ByteBuffer serPlain = ByteBuffer.allocate(server.getSession().getApplicationBufferSize());
        ByteBuffer cliPlain = ByteBuffer.allocate(client.getSession().getApplicationBufferSize());
        boolean done = false;

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
                        " status = " + result.getStatus().name());
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
                        printHex(cliToSer);
                    }

                    if (serToCli.remaining() > 0) {
                        System.out.println("Server -> Client");
                        printHex(serToCli);
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
                return -1;
            }
        }
        return 0;
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
    protected boolean isAndroid() {
        if (System.getProperty("java.runtime.name").contains("Android")) {
            return true;
        }
        return false;
    }
}
