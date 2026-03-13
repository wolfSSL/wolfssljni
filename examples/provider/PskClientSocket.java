/* PskClientSocket.java
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
import javax.net.ssl.SSLSocket;

import com.wolfssl.WolfSSLSession;
import com.wolfssl.WolfSSLPskClientCallback;
import com.wolfssl.provider.jsse.WolfSSLProvider;
import com.wolfssl.provider.jsse.WolfSSLParameters;

/**
 * Simple PSK client example using SSLSocket and WolfSSLParameters.
 *
 * This example demonstrates configuring PSK through WolfSSLParameters and the
 * standard setSSLParameters() API.
 *
 * Usage: PskClientSocket [host] [port]
 */
public class PskClientSocket {

    private static final String DEFAULT_HOST = "localhost";
    private static final int DEFAULT_PORT = 11111;

    public static void main(String[] args) throws Exception {

        String host = DEFAULT_HOST;
        int port = DEFAULT_PORT;

        if (args.length >= 1) {
            host = args[0];
        }
        if (args.length >= 2) {
            port = Integer.parseInt(args[1]);
        }

        /* Install wolfJSSE provider */
        Security.insertProviderAt(new WolfSSLProvider(), 1);

        /* Create SSLContext with no KeyManager/TrustManager
         * since PSK does not use certificates */
        SSLContext ctx = SSLContext.getInstance("TLSv1.2", "wolfJSSE");
        ctx.init(null, null, null);

        /* Create socket */
        SSLSocket sock = (SSLSocket)ctx.getSocketFactory()
            .createSocket(host, port);

        /* Find a PSK cipher suite available in this build */
        String pskCipher = findPskCipher(sock.getSupportedCipherSuites());

        /* Configure PSK via WolfSSLParameters */
        WolfSSLParameters params = new WolfSSLParameters();
        params.setPskClientCb(new MyPskClientCallback());
        params.setCipherSuites(new String[]{pskCipher});
        sock.setSSLParameters(params);
        System.out.println("Using cipher: " + pskCipher);

        System.out.println("Connected to " + host + ":" + port);

        /* Do handshake */
        sock.startHandshake();
        System.out.println("SSL handshake complete");
        System.out.println("  Protocol: " + sock.getSession().getProtocol());
        System.out.println("  Cipher: " + sock.getSession().getCipherSuite());

        /* Send/receive data */
        OutputStream out = sock.getOutputStream();
        InputStream in = sock.getInputStream();

        String msg = "Hello from PSK client!";
        out.write(msg.getBytes());
        System.out.println("Sent: " + msg);

        byte[] buf = new byte[1024];
        int n = in.read(buf);
        if (n > 0) {
            System.out.println("Received: " + new String(buf, 0, n));
        }

        sock.close();
        System.out.println("Connection closed");
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
     * PSK client callback implementation.
     */
    static class MyPskClientCallback implements WolfSSLPskClientCallback {

        public long pskClientCallback(WolfSSLSession ssl, String hint,
            StringBuffer identity, long idMaxLen, byte[] key, long keyMaxLen) {

            System.out.println("PSK Client Callback:");
            System.out.println("  Hint: " + hint);

            String id = "Client_identity";
            if (id.length() > idMaxLen || keyMaxLen < 4) {
                return 0;
            }
            identity.append(id);

            /* Pre-shared key: 0x1a2b3c4d */
            key[0] = 26;
            key[1] = 43;
            key[2] = 60;
            key[3] = 77;

            return 4;
        }
    }
}
