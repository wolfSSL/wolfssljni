/* ClientSSLSocket.java
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

/**
 * Example SSL/TLS client using SSLSocket class.
 * 
 * This example is compiled when "ant" is run from the main wolfssljni
 * root directory.
 *
 * To run, usage is:
 * $ ./examples/provider/ClientSSLSocket.sh [host] [port] [keystore] \
 *    [truststore]
 *
 * Note, that this uses a wrapper script to set up the correct environment
 * variables for use with the wolfJSSE provider included in the wolfssljni
 * package.
 *
 * The wrapper script enables javax.net logging, by defining:
 * -Djavax.net.debug=all
 *
 * Example usag for connecting to the wolfSSL example server is:
 *
 * $ ./examples/provider/ClientSSLSocket.sh 127.0.0.1 11111 \
 *   ./examples/provider/client.jks ./examples/provider/cacerts.jks
 * 
 * The password for both client.jks and cacerts.jks is:
 * "wolfSSL test"
 */

import java.io.*;
import java.security.*;
import javax.net.ssl.*;

import com.wolfssl.provider.jsse.WolfSSLProvider;

public class ClientSSLSocket {

    static String host = null;
    static int port;
    static String keyStorePath = null;
    static char[] keyStorePass = null;
    static String trustStorePath = null;
    static char[] trustStorePass = null;

    public static void main(String[] args) {

        KeyStore ks = null;  /* key store with client cert and key */
        KeyStore ts = null;  /* trust store with trusted roots */

        TrustManagerFactory tmf = null;
        KeyManagerFactory kmf = null;

        System.out.println("-----------------------------------");
        System.out.println("wolfSSL JSSE Example SSL/TLS Client");
        System.out.println("-----------------------------------\n");

        /* read in args */
        if (args.length != 4) {
            showUsage();
        }

        parseArgsAndPasswords(args);

        try {

            /* load wolfJSSE as provider */
            Security.addProvider(new WolfSSLProvider());

            /* set up key and trust stores */
            ks = KeyStore.getInstance("JKS");
            ks.load(new FileInputStream(keyStorePath), keyStorePass);
            ts = KeyStore.getInstance("JKS");
            ts.load(new FileInputStream(trustStorePath), trustStorePass);

            tmf = TrustManagerFactory.getInstance("SunX509");
            tmf.init(ts);
            kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, keyStorePass);

            SSLContext ctx = SSLContext.getInstance("TLSV1.2", "wolfJSSE");
            ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

            SSLSocketFactory sf = ctx.getSocketFactory();
            SSLSocket sock = (SSLSocket)sf.createSocket(host, port);

            sock.startHandshake();

            sock.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    static void parseArgsAndPasswords(String[] args) {

        host = args[0];
        port = Integer.parseInt(args[1]);
        keyStorePath = args[2];
        trustStorePath = args[3];

        getPasswords();
    }

    static void getPasswords() {
        Console c = System.console();
        if (c == null) {
            System.out.println("ERROR: Unable to get console");
            System.exit(-1);
        }

        keyStorePass = c.readPassword("Enter keystore password: ");
        trustStorePass = c.readPassword("Enter truststore password: ");
    }

    static void showUsage() {
        System.out.println("USAGE: java ClientSSLSocket " +
            "host port keyStore trustStore");
        System.exit(-1);
    }
}

