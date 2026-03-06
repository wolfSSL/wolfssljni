/* PskServerEngine.java
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

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.security.Security;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLSession;

import com.wolfssl.WolfSSLSession;
import com.wolfssl.WolfSSLPskServerCallback;
import com.wolfssl.provider.jsse.WolfSSLProvider;
import com.wolfssl.provider.jsse.WolfSSLParameters;

/**
 * Simple PSK server example using SSLEngine and WolfSSLParameters.
 *
 * This example demonstrates configuring PSK through WolfSSLParameters with
 * SSLEngine.
 *
 * Usage: PskServerEngine [port]
 */
public class PskServerEngine {

    private static final int DEFAULT_PORT = 11111;

    public static void main(String[] args) throws Exception {

        int port = DEFAULT_PORT;
        if (args.length >= 1) {
            port = Integer.parseInt(args[0]);
        }

        /* Install wolfJSSE provider */
        Security.insertProviderAt(new WolfSSLProvider(), 1);

        SSLContext ctx = SSLContext.getInstance("TLSv1.2", "wolfJSSE");
        ctx.init(null, null, null);

        /* Create server socket */
        ServerSocketChannel ssc = ServerSocketChannel.open();
        ssc.socket().bind(new InetSocketAddress(port));
        System.out.println("PSK Engine Server listening on port " + port);

        /* Accept one client */
        SocketChannel sc = ssc.accept();
        System.out.println("Client connected from " +
            sc.socket().getInetAddress().getHostAddress());

        try {
            /* Create SSLEngine */
            SSLEngine engine = ctx.createSSLEngine();
            engine.setUseClientMode(false);

            /* Find a PSK cipher suite available in this build */
            String pskCipher = findPskCipher(engine.getSupportedCipherSuites());

            /* Configure PSK via WolfSSLParameters */
            WolfSSLParameters params = new WolfSSLParameters();
            params.setPskServerCb(new MyPskServerCallback());
            params.setPskIdentityHint("wolfssl psk hint");
            params.setCipherSuites(new String[]{pskCipher});
            engine.setSSLParameters(params);
            System.out.println("Using cipher: " + pskCipher);

            /* Perform handshake */
            doHandshake(engine, sc);
            System.out.println("SSL handshake complete");
            SSLSession sess = engine.getSession();
            System.out.println("  Protocol: " + sess.getProtocol());
            System.out.println("  Cipher: " + sess.getCipherSuite());

            /* Receive application data */
            ByteBuffer netIn = ByteBuffer.allocate(
                sess.getPacketBufferSize());
            ByteBuffer appIn = ByteBuffer.allocate(
                sess.getApplicationBufferSize());

            sc.read(netIn);
            netIn.flip();
            SSLEngineResult res = engine.unwrap(netIn, appIn);
            appIn.flip();
            byte[] data = new byte[appIn.remaining()];
            appIn.get(data);
            String received = new String(data);
            System.out.println("Received: " + received);

            /* Echo back */
            ByteBuffer appOut = ByteBuffer.wrap(received.getBytes());
            ByteBuffer netOut = ByteBuffer.allocate(sess.getPacketBufferSize());
            res = engine.wrap(appOut, netOut);
            netOut.flip();
            while (netOut.hasRemaining()) {
                sc.write(netOut);
            }
            System.out.println("Echoed back: " + received);

            engine.closeOutbound();

        } finally {
            sc.close();
            ssc.close();
        }

        System.out.println("Server closed");
    }

    /**
     * Perform TLS handshake using SSLEngine over SocketChannel.
     */
    private static void doHandshake(SSLEngine engine, SocketChannel sc)
        throws Exception {

        SSLSession sess = engine.getSession();
        int netSize = sess.getPacketBufferSize();
        int appSize = sess.getApplicationBufferSize();

        ByteBuffer localNet = ByteBuffer.allocate(netSize);
        ByteBuffer peerNet = ByteBuffer.allocate(netSize);
        ByteBuffer localApp = ByteBuffer.allocate(0);
        ByteBuffer peerApp = ByteBuffer.allocate(appSize);

        engine.beginHandshake();
        HandshakeStatus hs = engine.getHandshakeStatus();

        while (hs != HandshakeStatus.FINISHED &&
               hs != HandshakeStatus.NOT_HANDSHAKING) {

            SSLEngineResult res;
            switch (hs) {
                case NEED_WRAP:
                    localNet.clear();
                    res = engine.wrap(localApp, localNet);
                    hs = res.getHandshakeStatus();
                    localNet.flip();
                    while (localNet.hasRemaining()) {
                        sc.write(localNet);
                    }
                    break;

                case NEED_UNWRAP:
                    if (sc.read(peerNet) < 0) {
                        throw new IOException(
                            "Channel closed during handshake");
                    }
                    peerNet.flip();
                    res = engine.unwrap(peerNet, peerApp);
                    peerNet.compact();
                    hs = res.getHandshakeStatus();

                    if (res.getStatus() ==
                        SSLEngineResult.Status.BUFFER_UNDERFLOW) {
                        continue;
                    }
                    break;

                case NEED_TASK:
                    Runnable task;
                    while ((task = engine.getDelegatedTask()) != null) {
                        task.run();
                    }
                    hs = engine.getHandshakeStatus();
                    break;

                default:
                    break;
            }
        }
    }

    /**
     * Find first available ephemeral PSK cipher suite from supported list.
     * Prefers ECDHE over DHE, AES-GCM over others. Falls back to static PSK
     * if no ephemeral suite is available.
     */
    private static String findPskCipher(String[] suites) {

        String ecdhe = null;
        String dhe = null;
        String plain = null;

        for (String s : suites) {
            if (s.startsWith("TLS_ECDHE_PSK_WITH_")) {
                if (ecdhe == null || s.contains("GCM")) {
                    ecdhe = s;
                }
            }
            else if (s.startsWith("TLS_DHE_PSK_WITH_")) {
                if (dhe == null || s.contains("GCM")) {
                    dhe = s;
                }
            }
            else if (s.startsWith("TLS_PSK_WITH_")) {
                if (plain == null) {
                    plain = s;
                }
            }
        }

        if (ecdhe != null) { return ecdhe; }
        if (dhe != null) { return dhe; }
        if (plain != null) { return plain; }

        throw new RuntimeException(
            "No PSK cipher suites available. " +
            "No PSK cipher suites compiled into wolfSSL");
    }

    /**
     * PSK server callback implementation.
     */
    static class MyPskServerCallback implements WolfSSLPskServerCallback {

        public long pskServerCallback(WolfSSLSession ssl, String identity,
            byte[] key, long keyMaxLen) {

            System.out.println("PSK Server Callback:");
            System.out.println("  Identity: " + identity);

            if (!"Client_identity".equals(identity)) {
                System.out.println("Unknown client identity!");
                return 0;
            }

            if (keyMaxLen < 4) {
                return 0;
            }

            key[0] = 26;
            key[1] = 43;
            key[2] = 60;
            key[3] = 77;

            return 4;
        }
    }
}
