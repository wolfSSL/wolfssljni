/* PskServerSocket.java
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

import java.io.InputStream;
import java.io.OutputStream;
import java.security.Security;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

import com.wolfssl.WolfSSLSession;
import com.wolfssl.WolfSSLPskServerCallback;
import com.wolfssl.provider.jsse.WolfSSLProvider;
import com.wolfssl.provider.jsse.WolfSSLParameters;

/**
 * Simple PSK server example using SSLSocket and WolfSSLParameters.
 *
 * This example demonstrates configuring PSK through WolfSSLParameters and the
 * standard setSSLParameters() API.
 *
 * Usage: PskServerSocket [port]
 */
public class PskServerSocket {

    private static final int DEFAULT_PORT = 11111;

    public static void main(String[] args) throws Exception {

        int port = DEFAULT_PORT;
        if (args.length >= 1) {
            port = Integer.parseInt(args[0]);
        }

        /* Install wolfJSSE provider */
        Security.insertProviderAt(new WolfSSLProvider(), 1);

        /* Create SSLContext with no KeyManager/TrustManager since PSK does not
         * use certificates */
        SSLContext ctx = SSLContext.getInstance("TLSv1.2", "wolfJSSE");
        ctx.init(null, null, null);

        /* Create server socket */
        SSLServerSocket ss = (SSLServerSocket)ctx.getServerSocketFactory()
            .createServerSocket(port);

        System.out.println("PSK Server listening on port " + port);

        /* Accept one client */
        SSLSocket sock = (SSLSocket)ss.accept();
        System.out.println("Client connected from " +
            sock.getInetAddress().getHostAddress());

        /* Find a PSK cipher suite available in this build */
        String pskCipher = findPskCipher(sock.getSupportedCipherSuites());

        /* Configure PSK via WolfSSLParameters */
        WolfSSLParameters params = new WolfSSLParameters();
        params.setPskServerCb(new MyPskServerCallback());
        params.setPskIdentityHint("wolfssl psk hint");
        params.setCipherSuites(new String[]{pskCipher});
        sock.setSSLParameters(params);
        System.out.println("Using cipher: " + pskCipher);

        /* Do handshake */
        sock.startHandshake();
        System.out.println("SSL handshake complete");
        System.out.println("  Protocol: " + sock.getSession().getProtocol());
        System.out.println("  Cipher: " + sock.getSession().getCipherSuite());

        /* Read/write data */
        InputStream in = sock.getInputStream();
        OutputStream out = sock.getOutputStream();

        byte[] buf = new byte[1024];
        int n = in.read(buf);
        if (n > 0) {
            String received = new String(buf, 0, n);
            System.out.println("Received: " + received);
            out.write(received.getBytes());
            System.out.println("Echoed back: " + received);
        }

        sock.close();
        ss.close();
        System.out.println("Server closed");
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

            /* Pre-shared key: 0x1a2b3c4d */
            key[0] = 26;
            key[1] = 43;
            key[2] = 60;
            key[3] = 77;

            return 4;
        }
    }
}
