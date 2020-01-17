/* MultiThreadedSSLServer.java
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
 * SSLServerSocket example that creates a new thread per client connection.
 *
 * This server waits in an infinite loop for client connections, and when
 * connected creates a new thread for each connection. This example is compiled
 * when 'ant' is run in the package root.
 *
 * $ ant
 * $ ./examples/provider/MultiThreadedSSLServer.sh
 *
 * This can be tested against the normal wolfSSL example client. But, wolfSSL
 * will need to be compiled with WOLFSSL_ALT_TEST_STRINGS defined so that
 * the client strings are null terminated.
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
    private String serverJKS = "./examples/provider/server.jks";
    int serverPort = 11118;

    public MultiThreadedSSLServer() {
        try {

            Security.addProvider(new WolfSSLProvider());

            KeyStore pKey = KeyStore.getInstance("JKS");
            pKey.load(new FileInputStream(serverJKS), psw);
            KeyStore cert = KeyStore.getInstance("JKS");
            cert.load(new FileInputStream(serverJKS), psw);
            
            TrustManagerFactory tm = TrustManagerFactory.getInstance("SunX509");
            tm.init(cert);
            
            KeyManagerFactory km = KeyManagerFactory.getInstance("SunX509");
            km.init(pKey, psw);

            SSLContext ctx = SSLContext.getInstance("TLS", "wolfJSSE");
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

            try {

                OutputStream rawOut = sock.getOutputStream();

                PrintWriter out = new PrintWriter(
                    new BufferedWriter(
                        new OutputStreamWriter(rawOut)));

                BufferedReader in = new BufferedReader(
                    new InputStreamReader(sock.getInputStream()));

                String line = in.readLine();
                System.out.println("client: " + line);

                out.print("I hear you C client!");
                out.flush();
                out.close();
                in.close();

                in.close();
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

