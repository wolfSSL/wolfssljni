/* ThreadedSSLSocketClientServer.java
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
 * SSLSocket example that connects a client thread to a server thread.
 *
 * This example creates two threads, one server and one client. The examples
 * are set up to use the SSLSocket and SSLServerSocket classes. They make
 * one connection (handshake) and shut down.
 *
 * Example usage:
 *
 * $ ./examples/provider/ThreadedSSLSocketClientServer.sh
 */

import java.util.*;
import java.io.*;
import java.net.*;
import javax.net.ssl.*;
import java.security.*;
import com.wolfssl.provider.jsse.WolfSSLProvider;

public class ThreadedSSLSocketClientServer
{
    String tmfImpl = "SunX509";     /* TrustManagerFactory provider */
    String kmfImpl = "SunX509";     /* KeyManagerFactory provider */
    String ctxImpl = "wolfJSSE";    /* SSLContext provider */
    int srvPort = 11118;            /* server port */

    class ServerThread extends Thread
    {
        private String keyStorePath;
        private String trustStorePath;
        private char[] ksPass;
        private char[] tsPass;

        public ServerThread(String keyStorePath, String keyStorePass,
            String trustStorePath, String trustStorePass) {

            this.keyStorePath = keyStorePath;
            this.trustStorePath = trustStorePath;
            this.ksPass = keyStorePass.toCharArray();
            this.tsPass = trustStorePass.toCharArray();
        }

        public void run() {

            try {

                KeyStore pKey = KeyStore.getInstance("JKS");
                pKey.load(new FileInputStream(keyStorePath), ksPass);
                KeyStore cert = KeyStore.getInstance("JKS");
                cert.load(new FileInputStream(trustStorePath), tsPass);
                
                TrustManagerFactory tm = TrustManagerFactory.getInstance(tmfImpl);
                tm.init(cert);
                
                KeyManagerFactory km = KeyManagerFactory.getInstance(kmfImpl);
                km.init(pKey, ksPass);

                SSLContext ctx = SSLContext.getInstance("TLS", ctxImpl);
                ctx.init(km.getKeyManagers(), tm.getTrustManagers(), null);

                SSLServerSocket ss = (SSLServerSocket)ctx
                    .getServerSocketFactory().createServerSocket(srvPort);

                SSLSocket sock = (SSLSocket)ss.accept();
                sock.startHandshake();
                sock.close();

            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    class ClientThread extends Thread
    {
        private String keyStorePath;
        private String trustStorePath;
        private char[] ksPass;
        private char[] tsPass;

        public ClientThread(String keyStorePath, String keyStorePass,
            String trustStorePath, String trustStorePass) {

            this.keyStorePath = keyStorePath;
            this.trustStorePath = trustStorePath;
            this.ksPass = keyStorePass.toCharArray();
            this.tsPass = trustStorePass.toCharArray();
        }

        public void run() {
            try {

                KeyStore pKey = KeyStore.getInstance("JKS");
                pKey.load(new FileInputStream(keyStorePath), ksPass);
                KeyStore cert = KeyStore.getInstance("JKS");
                cert.load(new FileInputStream(trustStorePath), tsPass);
                
                TrustManagerFactory tm = TrustManagerFactory.getInstance(tmfImpl);
                tm.init(cert);
                
                KeyManagerFactory km = KeyManagerFactory.getInstance(kmfImpl);
                km.init(pKey, ksPass);

                SSLContext ctx = SSLContext.getInstance("TLS", ctxImpl);
                ctx.init(km.getKeyManagers(), tm.getTrustManagers(), null);

                SSLSocket sock = (SSLSocket)ctx.getSocketFactory()
                    .createSocket();

                sock.connect(new InetSocketAddress(srvPort));

                sock.startHandshake();

                sock.close();

            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public ThreadedSSLSocketClientServer(String[] args) {

        Security.addProvider(new WolfSSLProvider());

        String serverKS = "./examples/provider/server.jks";
        String serverTS = "./examples/provider/client.jks";
        String clientKS = "./examples/provider/client.jks";
        String clientTS = "./examples/provider/client.jks";
        String pass = "wolfSSL test";

        ServerThread server = new ServerThread(
            serverKS, pass, serverTS, pass);
        server.start();

        ClientThread client = new ClientThread(
            clientKS, pass, clientTS, pass);
        client.start();
    }


    public static void main(String[] args) {
        new ThreadedSSLSocketClientServer(args);
    }
}

