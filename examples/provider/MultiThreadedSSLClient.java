/* MultiThreadedSSLClient.java
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
 * Multi threaded SSLSocket example that connects a specified number of
 * client threads to a server. Intended to test multi-threading with wolfJSSE.
 *
 * This example creates a specified number of client threads to a server
 * located at 127.0.0.1:11118. This example is set up to use the SSLSocket
 * class. It makes one connection (handshake), sends/receives data, and shuts
 * down.
 *
 * A random amount of time is injected into each client thread before:
 *    1) The SSL/TLS handshake
 *    2) Doing I/O operations after the handshake
 *
 * The maximum amount of sleep time for each of those is "maxSleep", or
 * 3 seconds by default. This is intended to add some randomness into the
 * the client thread operations.
 *
 * Example usage:
 *
 * $ ant examples
 * $ ./examples/provider/MultiThreadedSSLClient.sh
 *
 * This example is designed to connect against the MultiThreadedSSLServer
 * example:
 *
 * $ ./examples/provider/MultiThreadedSSLServer.sh
 *
 * This example also prints out average SSL/TLS handshake time, which is
 * measured in milliseconds on the "startHandshake()" API call.
 */

import java.util.*;
import java.io.*;
import java.net.*;
import javax.net.ssl.*;
import java.security.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadLocalRandom;
import com.wolfssl.provider.jsse.WolfSSLProvider;

public class MultiThreadedSSLClient
{
    String tmfType = "SunX509";      /* TrustManagerFactory type */
    String tmfProv = "wolfJSSE";     /* TrustManagerFactory provider */
    String kmfType = "SunX509";      /* KeyManagerFactory type */
    String kmfProv = "wolfJSSE";     /* KeyManagerFactory provider */
    String ctxProv = "wolfJSSE";     /* SSLContext provider */

    String srvHost = "127.0.0.1";    /* server host */
    int srvPort = 11118;             /* server port */

    int numClientConnections = 10;    /* number of client connection threads */
    int startedClientConnections = 0; /* active clients connected to server */
    int successClientConnections = 0; /* successful client connections */
    int failedClientConnections = 0;  /* failed client connections */

    long totalConnectionTimeMs = 0;   /* total handshake time, across clients */
    final Object timeLock = new Object();

    class ClientThread implements Runnable
    {
        private KeyManagerFactory km = null;
        private TrustManagerFactory tm = null;
        private CountDownLatch latch;

        public ClientThread(KeyManagerFactory km, TrustManagerFactory tm,
                            CountDownLatch latch) {
            this.km = km;
            this.tm = tm;
            this.latch = latch;
        }

        public void run() {

            byte[] back = new byte[80];
            String msg = "Too legit to quit";

            /* max sleep is 3 seconds */
            int maxSleep = 3000;

            /* get random sleep value before calling connect() */
            int randConnectSleep =
                ThreadLocalRandom.current().nextInt(0, maxSleep + 1);

            /* get random sleep value before doing I/O after handshake */
            int randIOSleep =
                ThreadLocalRandom.current().nextInt(0, maxSleep +1);

            try {
                SSLContext ctx = SSLContext.getInstance("TLS", ctxProv);
                ctx.init(km.getKeyManagers(), tm.getTrustManagers(), null);

                SSLSocket sock = (SSLSocket)ctx.getSocketFactory()
                    .createSocket();

                Thread.sleep(randConnectSleep);

                sock.connect(new InetSocketAddress(srvHost, srvPort));

                final long startTime = System.currentTimeMillis();
                sock.startHandshake();
                final long endTime = System.currentTimeMillis();

                synchronized (timeLock) {
                    totalConnectionTimeMs += (endTime - startTime);
                }

                Thread.sleep(randIOSleep);

                sock.getOutputStream().write(msg.getBytes());
                sock.getInputStream().read(back);
                System.out.println("Server message : " + new String(back));

                sock.close();
                successClientConnections++;

            } catch (Exception e) {
                e.printStackTrace();
                failedClientConnections++;
            }

            this.latch.countDown();
        }
    }

    public MultiThreadedSSLClient(String[] args) {

        Security.addProvider(new WolfSSLProvider());

        String clientKS = "./examples/provider/client.jks";
        String clientTS = "./examples/provider/ca-server.jks";
        String jkspass = "wolfSSL test";
        char[] passArr = jkspass.toCharArray();

        if (args.length != 2) {
            printUsage();
        }

        /* pull in command line options from user */
        for (int i = 0; i < args.length; i++)
        {
            String arg = args[i];

            if (arg.equals("-n")) {
                if (args.length < i+2)
                    printUsage();
                numClientConnections = Integer.parseInt(args[++i]);

            } else {
                printUsage();
            }
        }

        try {
            List<ClientThread> clientList = new ArrayList<ClientThread>();
            CountDownLatch latch = new CountDownLatch(numClientConnections);

            /* set up client KeyStore */
            KeyStore clientKeyStore = KeyStore.getInstance("JKS");
            clientKeyStore.load(new FileInputStream(clientKS), passArr);

            KeyManagerFactory clientKMF =
                KeyManagerFactory.getInstance(kmfType, kmfProv);
            clientKMF.init(clientKeyStore, passArr);

            /* set up CA TrustManagerFactory */
            KeyStore caKeyStore = KeyStore.getInstance("JKS");
            caKeyStore.load(new FileInputStream(clientTS), passArr);
            
            TrustManagerFactory tm = TrustManagerFactory
                .getInstance(tmfType, tmfProv);
            tm.init(caKeyStore);

            for (int i = 0; i < numClientConnections; i++) {
                clientList.add(new ClientThread(clientKMF, tm, latch));
            }

            ExecutorService executor = Executors.newFixedThreadPool(
                                           clientList.size());

            for (final ClientThread c : clientList) {
                executor.execute(c);
            }

            latch.await();
            executor.shutdown();

        } catch (Exception e) {
            e.printStackTrace();
        }

        Security.removeProvider("wolfJSSE");

        System.out.println("================================================");
        System.out.println("All Client Connections Finished");
        System.out.println("Successful = " + successClientConnections);
        System.out.println("Failed = " + failedClientConnections);
        System.out.println("Avg handshake time = " +
                totalConnectionTimeMs / successClientConnections + " ms");
        System.out.println("================================================");
    }


    public static void main(String[] args) {
        new MultiThreadedSSLClient(args);
    }

    private void printUsage() {
        System.out.println("Java wolfJSSE example threaded client usage:");
        System.out.println("-n <num>\tNumber of client connections");
        System.exit(1);
    }
}

