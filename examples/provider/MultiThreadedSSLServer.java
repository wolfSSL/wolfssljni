/* MultiThreadedSSLServer.java
 *
 * Copyright (C) 2006-2022 wolfSSL Inc.
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
 * SSLServerSocket example that creates a new thread per client connection.
 *
 * This server waits in an infinite loop for client connections, and when
 * connected creates a new thread for each connection. This example is compiled
 * when 'ant examples' is run in the package root.
 *
 * $ ant examples
 * $ ./examples/provider/MultiThreadedSSLServer.sh
 *
 * For multi threaded client testing, test against MultiThreadedSSLClient.sh.
 * For example, to connect 10 client threads:
 *
 * ./examples/provider/MultiThreadedSSLClient.sh -n 10
 *
 */
import java.util.*;
import java.io.*;
import java.net.*;
import javax.net.ssl.*;
import java.security.*;
import com.wolfssl.provider.jsse.WolfSSLProvider;

public class MultiThreadedSSLServer
{
    private char[] psw = "wolfSSL test".toCharArray();
    private String serverKS = "./examples/provider/server.jks";
    private String serverTS = "./examples/provider/ca-client.jks";
    private String jsseProv = "wolfJSSE";
    int serverPort = 11118;

    public MultiThreadedSSLServer() {
        try {

            Security.addProvider(new WolfSSLProvider());

            /* Set up KeyStore */
            KeyStore serverKeyStore = KeyStore.getInstance("JKS");
            serverKeyStore.load(new FileInputStream(serverKS), psw);

            KeyManagerFactory km = KeyManagerFactory
                .getInstance("SunX509", jsseProv);
            km.init(serverKeyStore, psw);

            /* Set up CA TrustManagerFactory */
            KeyStore caKeyStore = KeyStore.getInstance("JKS");
            caKeyStore.load(new FileInputStream(serverTS), psw);
            
            TrustManagerFactory tm = TrustManagerFactory
                .getInstance("SunX509", jsseProv);
            tm.init(caKeyStore);

            SSLContext ctx = SSLContext.getInstance("TLS", jsseProv);
            ctx.init(km.getKeyManagers(), tm.getTrustManagers(), null);

            SSLServerSocket ss = (SSLServerSocket)ctx
                .getServerSocketFactory().createServerSocket(serverPort);

            while (true) {
                SSLSocket sock = (SSLSocket)ss.accept();

                ClientHandler client = new ClientHandler(sock);
                client.start();
            }

        } catch(Exception e) {
            e.printStackTrace();
        }
    }

    class ClientHandler extends Thread
    {
        SSLSocket sock;

        public ClientHandler(SSLSocket s) {
            sock = s;
        }

        public void run() {

            byte[] response = new byte[80];
            String msg = "I hear you fa shizzle, from Java!";

            try {

                sock.startHandshake();

                sock.getInputStream().read(response);
                System.out.println("Client message : " + new String(response));
                sock.getOutputStream().write(msg.getBytes());

                sock.close();

            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public static void main(String[] args) {
        new MultiThreadedSSLServer();
    }
}

