/* DualProviderFIPSTest.java
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

import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.Security;
import java.util.concurrent.CountDownLatch;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

import com.wolfssl.wolfcrypt.Fips;
import com.wolfssl.provider.jce.WolfCryptProvider;
import com.wolfssl.provider.jsse.WolfSSLProvider;

/**
 * Test using both WolfCryptProvider (wolfJCE) and WolfSSLProvider
 * (wolfJSSE) together with wolfCrypt FIPS / FIPS Ready.
 *
 * This test verifies that the "wolfjsse.skipFIPSCAST" Security property works
 * correctly to prevent duplicate FIPS CAST execution when both providers are
 * used together. The recommended workflow is:
 *
 *   1. Run FIPS CASTs once via wolfJCE Fips.runAllCast_fips()
 *   2. Set Security property wolfjsse.skipFIPSCAST=true via
 *      Security.setProperty() or in java.security config file
 *   3. Register both WolfCryptProvider and WolfSSLProvider
 *   4. Use both providers for crypto operations
 */
public class DualProviderFIPSTest {

    /* Keystore paths, run from wolfssljni root */
    private static final String serverKS = "./examples/provider/server.jks";
    private static final String serverTS = "./examples/provider/ca-client.jks";
    private static final String clientKS = "./examples/provider/client.jks";
    private static final String clientTS = "./examples/provider/ca-server.jks";
    private static final char[] ksPass = "wolfSSL test".toCharArray();

    private static final String testMsg =
        "Hello from wolfJSSE FIPS dual provider test";

    /* Latch so client waits until server is listening */
    private static CountDownLatch serverReady = new CountDownLatch(1);

    /* Track errors from threads */
    private static volatile String serverError = null;
    private static volatile String clientError = null;

    /**
     * Server thread: accepts one TLS connection, reads a message, echoes it
     * back, then closes.
     */
    static class ServerThread extends Thread {

        private int port;

        public ServerThread(int port) {
            this.port = port;
        }

        public void run() {
            try {
                KeyStore pKey = KeyStore.getInstance("JKS");
                try (FileInputStream pKeyStream =
                        new FileInputStream(serverKS)) {
                    pKey.load(pKeyStream, ksPass);
                }

                KeyStore cert = KeyStore.getInstance("JKS");
                try (FileInputStream certStream =
                         new FileInputStream(serverTS)) {
                    cert.load(certStream, ksPass);
                }

                TrustManagerFactory tmf =
                    TrustManagerFactory.getInstance("SunX509", "wolfJSSE");
                tmf.init(cert);

                KeyManagerFactory kmf =
                    KeyManagerFactory.getInstance("SunX509", "wolfJSSE");
                kmf.init(pKey, ksPass);

                SSLContext ctx = SSLContext.getInstance("TLSv1.2", "wolfJSSE");
                ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

                try (SSLServerSocket ss =
                    (SSLServerSocket)ctx.getServerSocketFactory()
                        .createServerSocket(port)) {

                    /* Signal client that server is ready */
                    serverReady.countDown();

                    try (SSLSocket sock = (SSLSocket)ss.accept()) {
                        sock.startHandshake();

                        /* Read message from client */
                        InputStream in = sock.getInputStream();
                        byte[] buf = new byte[256];
                        int len = in.read(buf);
                        if (len <= 0) {
                            serverError = "No data received from client";
                            return;
                        }

                        /* Echo it back */
                        OutputStream out = sock.getOutputStream();
                        out.write(buf, 0, len);
                        out.flush();
                    }
                }

            }
            catch (Exception e) {
                serverError = e.toString();
                serverReady.countDown();
            }
        }
    }

    /**
     * Client thread: connects to server, sends a message,
     * reads the echo, verifies it matches.
     */
    static class ClientThread extends Thread {

        private int port;

        public ClientThread(int port) {
            this.port = port;
        }

        public void run() {
            try {
                /* Wait for server to be listening */
                serverReady.await();
                if (serverError != null) {
                    clientError = "Server failed: " + serverError;
                    return;
                }

                KeyStore pKey = KeyStore.getInstance("JKS");
                try (FileInputStream pKeyStream =
                         new FileInputStream(clientKS)) {
                    pKey.load(pKeyStream, ksPass);
                }

                KeyStore cert = KeyStore.getInstance("JKS");
                try (FileInputStream certStream =
                         new FileInputStream(clientTS)) {
                    cert.load(certStream, ksPass);
                }

                TrustManagerFactory tmf =
                    TrustManagerFactory.getInstance("SunX509", "wolfJSSE");
                tmf.init(cert);

                KeyManagerFactory kmf =
                    KeyManagerFactory.getInstance("SunX509", "wolfJSSE");
                kmf.init(pKey, ksPass);

                SSLContext ctx = SSLContext.getInstance("TLSv1.2", "wolfJSSE");
                ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

                try (SSLSocket sock = (SSLSocket)ctx.getSocketFactory()
                        .createSocket()) {
                    sock.connect(new InetSocketAddress("localhost", port));
                    sock.startHandshake();

                    /* Send test message */
                    OutputStream out = sock.getOutputStream();
                    out.write(testMsg.getBytes(StandardCharsets.UTF_8));
                    out.flush();

                    /* Read echo */
                    InputStream in = sock.getInputStream();
                    byte[] buf = new byte[256];
                    int len = in.read(buf);
                    if (len <= 0) {
                        clientError = "No echo received from server";
                    }
                    else {
                        String echo =
                            new String(buf, 0, len, StandardCharsets.UTF_8);
                        if (!testMsg.equals(echo)) {
                            clientError = "Echo mismatch: expected '" +
                                testMsg + "' got '" + echo + "'";
                        }
                    }
                }

            }
            catch (Exception e) {
                clientError = e.toString();
            }
        }
    }

    /**
     * Run FIPS CASTs once through wolfJCE, then register both providers and
     * verify they work with a full TLS connection.
     */
    public static void main(String[] args) throws Exception {

        int ret = 0;
        int testsFailed = 0;

        System.out.println("=========================================");
        System.out.println("Dual Provider FIPS Test");
        System.out.println("=========================================");

        /* Verify FIPS is enabled in wolfJCE */
        System.out.print("Checking FIPS enabled ... ");
        if (!Fips.enabled) {
            System.out.println("SKIP: FIPS not enabled, skipping test");
            return;
        }
        System.out.println("yes (version " + Fips.fipsVersion + ")");

        /* Set Security property to skip FIPS CAST in wolfJSSE init.
         * Must be set before WolfSSLProvider is constructed. */
        Security.setProperty("wolfjsse.skipFIPSCAST", "true");
        String skipCAST = Security.getProperty("wolfjsse.skipFIPSCAST");
        System.out.println(
            "wolfjsse.skipFIPSCAST = " + skipCAST);

        /* 1. Run all FIPS CASTs once through wolfJCE */
        System.out.print("Running FIPS CASTs via wolfJCE ... ");
        ret = Fips.runAllCast_fips();
        if (ret != 0) {
            System.out.println("FAILED (ret = " + ret + ")");
            System.exit(1);
        }
        System.out.println("passed");

        /* 2. Register WolfCryptProvider (wolfJCE) */
        System.out.print("Registering WolfCryptProvider ... ");
        Security.insertProviderAt(new WolfCryptProvider(), 1);
        Provider jce = Security.getProvider("wolfJCE");
        if (jce == null) {
            System.out.println("FAILED");
            System.exit(1);
        }
        System.out.println("done (" + jce + ")");

        /* 3. Register WolfSSLProvider (wolfJSSE), CASTs should be skipped via
         * Security property */
        System.out.print("Registering WolfSSLProvider ... ");
        Security.insertProviderAt(new WolfSSLProvider(), 2);
        Provider jsse = Security.getProvider("wolfJSSE");
        if (jsse == null) {
            System.out.println("FAILED");
            System.exit(1);
        }
        System.out.println("done (" + jsse + ")");

        /* 4. Test wolfJCE: SHA-256 MessageDigest */
        System.out.print("Testing wolfJCE SHA-256 digest ... ");
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256", "wolfJCE");
            byte[] hash =
                md.digest("test data".getBytes(StandardCharsets.UTF_8));
            if (hash == null || hash.length != 32) {
                System.out.println("FAILED (bad hash)");
                testsFailed++;
            }
            else {
                System.out.println("passed");
            }
        }
        catch (Exception e) {
            System.out.println("FAILED: " + e.getMessage());
            testsFailed++;
        }

        /* 5. Test wolfJSSE: TLS loopback connection with data exchange
         * between client and server threads */
        System.out.print("Testing wolfJSSE TLS connection ... ");
        try {
            int port = 11119;

            ServerThread server = new ServerThread(port);
            ClientThread client = new ClientThread(port);

            server.start();
            client.start();

            server.join(10000);
            client.join(10000);

            if (serverError != null) {
                System.out.println("FAILED (server: " + serverError + ")");
                testsFailed++;
            }
            else if (clientError != null) {
                System.out.println("FAILED (client: " + clientError + ")");
                testsFailed++;
            }
            else if (server.isAlive() || client.isAlive()) {
                System.out.println("FAILED (threads timed out)");
                testsFailed++;
            }
            else {
                System.out.println("passed");
            }
        }
        catch (Exception e) {
            System.out.println("FAILED: " + e.getMessage());
            testsFailed++;
        }

        /* Print registered providers */
        System.out.println("\nRegistered providers:");
        Provider[] providers = Security.getProviders();
        for (Provider p : providers) {
            System.out.println("  " + p);
        }

        /* Summary */
        System.out.println();
        if (testsFailed > 0) {
            System.out.println("FAIL: " + testsFailed + " test(s) failed");
            System.exit(1);
        }
        else {
            System.out.println("All dual provider tests passed");
        }
    }
}

