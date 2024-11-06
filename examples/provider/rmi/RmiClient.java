/* RmiClient.java
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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
import java.util.Arrays;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.List;
import java.util.ArrayList;
import java.security.KeyStore;
import java.net.Socket;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLContext;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicIntegerArray;

import java.net.InetAddress;
import java.rmi.server.RMIClientSocketFactory;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.security.Security;

import com.wolfssl.WolfSSL;
import com.wolfssl.provider.jsse.WolfSSLProvider;

/**
 * Client class calling remote object interface on Server via RMI.
 *
 * This client is set up to make {N} number of connections to each
 * RMI registry port broadcast by the server. For example, if the server
 * has created 1 RMI registry entry, then this client will by default make
 * 1 connection to it. {N} is controlled by the command line argument "-n XX".
 * If started with "-n 2", this client would make 2 connections to the one
 * server registry.
 *
 * If the server has registered more than one registry entry, 2 for example,
 * then by default this client will make 2 connections (one to each port). If
 * started with "-n 2", then the client will make 4 total connections (two to
 * each of the two server RMI ports).
 */
public class RmiClient
{
    /* RMI registry port, needs to be same as RmiServer.java */
    private static final int registryStartingPort = 11115;

    /* Keystore files and passwords, holding certs/keys/CAs */
    private static String clientJKS = "../provider/client.jks";
    private static String caJKS = "../provider/ca-server.jks";
    private static String jksPass = "wolfSSL test";

    /* Keystore file format */
    private static String keystoreFormat = "JKS";

    /* TLS protocol version - "TLS" uses highest compiled in */
    private static String tlsVersion = "TLS";

    /* JSSE provider to use for this example */
    private static String jsseProvider = "wolfJSSE";

    /* Number of client connections rounds to start. One "round" consists
     * of 3 connections, one each to registryPortA/B/C. */
    int numClientConnections = 1;

    /* Do random sleep before starting client threads */
    boolean doRandomSleep = false;

    /* Create new unique SocketFactory for each client, otherwise use
     * same single SocketFactory across all */
    boolean useNewSF = false;

    /* Buffer size for test buffers sent/received */
    private static final int BUFFER_SIZE = 2048;

    /* Keep track of how many connections succeed or fail */
    final AtomicIntegerArray success = new AtomicIntegerArray(1);
    final AtomicIntegerArray failures = new AtomicIntegerArray(1);

    /* Use single SSLContext across threads */
    private static SSLContext ctx = null;
    /* Use single SocketFactory across threads if useCached true */
    private static SocketFactory sf = null;

    /**
     * Create client SocketFactory for use with RMI over TLS.
     * @return new SocketFactory object or null on error.
     */
    private static SocketFactory createClientSocketFactory(boolean useCached) {

        TrustManagerFactory tm = null;
        KeyManagerFactory km = null;
        KeyStore cert, pKey = null;

        try {
            /* Only create SSLContext once */
            if (ctx == null) {
                /* Create TrustManagerFactory with certs to verify peer */
                tm = TrustManagerFactory.getInstance("SunX509", jsseProvider);
                cert = KeyStore.getInstance(keystoreFormat);
                cert.load(new FileInputStream(caJKS), jksPass.toCharArray());
                tm.init(cert);
                System.out.println("Created client TrustManagerFactory");

                /* Create KeyManagerFactory with client cert/key */
                pKey = KeyStore.getInstance(keystoreFormat);
                pKey.load(new FileInputStream(clientJKS), jksPass.toCharArray());
                km = KeyManagerFactory.getInstance("SunX509", jsseProvider);
                km.init(pKey, jksPass.toCharArray());
                System.out.println("Created client KeyManagerFactory");

                /* Create SSLContext, doing peer auth */
                ctx = SSLContext.getInstance(tlsVersion, jsseProvider);
                ctx.init(km.getKeyManagers(), tm.getTrustManagers(), null);
                System.out.println("Created client SSLContext");
            }

            if (!useCached) {
                return ctx.getSocketFactory();
            }
            else {
                if (sf == null) {
                    /* Create SocketFactory */
                    sf = ctx.getSocketFactory();
                    System.out.println("Created client SocketFactory");
                }
            }

        } catch (Exception e) {
            System.out.println("Exception when creating client SocketFactory");
            e.printStackTrace();
            return null;
        }

        return sf;
    }

    class ClientThread implements Runnable
    {
        private String host = null;
        private int port = 0;
        private SocketFactory sf = null;
        private CountDownLatch latch = null;

        public ClientThread(String host, int port, SocketFactory sf,
            CountDownLatch latch) {

            this.host = host;
            this.port = port;
            this.sf = sf;
            this.latch = latch;
        }

        public void run() {

            try {
                /* Introduce a random sleep per thread, so all client
                 * threads are not started concurrently. Better tests
                 * session cache / resumption */
                if (doRandomSleep) {
                    Thread.sleep((long)((Math.random() * 2000) + 1000));
                }

                /* Get stub for the SSL/TLS registry on specified host */
                Registry registry = LocateRegistry.getRegistry(this.host,
                    this.port, new RmiTLSClientSocketFactory(this.sf));

                /* Invoke lookup on remote registry to get remote object stub */
                RmiRemoteInterface ri =
                    (RmiRemoteInterface)registry.lookup("RmiRemoteInterface");

                /* Send message to server, works over RMI */
                ri.sendMessage("Hello server from client");

                /* Get back server response, works over RMI */
                String serverMessage = ri.getMessage();
                System.out.println(
                    "Message from server via RMI: " + serverMessage);

                /* Send byte array, works over RMI */
                byte[] tmp = new byte[BUFFER_SIZE];
                Arrays.fill(tmp, (byte)0x06);
                ri.sendByteArray(tmp);
                System.out.println("Sent byte array: " + tmp.length + " bytes");

                /* Get byte array, works over RMI */
                byte[] recv = ri.getByteArray();
                System.out.println("Got byte array: " + recv.length + " bytes");

                success.incrementAndGet(0);

                /* Can comment out next line if testing with Java System
                 * properties like below and want to test behavior around
                 * timeouts and how that changes connection dynamics:
                 *
                 * -Dsun.rmi.transport.connectionTimeout=1000
                 * -Dsun.rmi.transport.tcp.readTimeout=1000
                 *
                 * These system properties could be set in RmiClient.sh
                 * before starting the example.
                 */
                //Thread.sleep(2000);

            } catch (Exception e) {
                failures.incrementAndGet(0);
                e.printStackTrace();
            } finally {
                this.latch.countDown();
            }

        }
    }

    public RmiClient(String[] args) {

        int[] registryPorts = null;

        /* Register wolfJSSE as top priority JSSE provider */
        Security.insertProviderAt(new WolfSSLProvider(), 1);

        /* pull in command line options from user */
        for (int i = 0; i < args.length; i++)
        {
            String arg = args[i];

            if (arg.equals("-n")) {
                if (args.length < i+2) {
                    printUsage();
                }
                numClientConnections = Integer.parseInt(args[++i]);
            }
            else if (arg.equals("-randsleep")) {
                doRandomSleep = true;
            }
            else if (arg.equals("-newSF")) {
                useNewSF = true;
            }
            else if (arg.equals("-jsseProv")) {
                if (args.length < i+2) {
                    printUsage();
                }
                jsseProvider = args[++i];

            } else {
                printUsage();
            }
        }

        try {
            /* Server hostname, null indicates localhost */
            String host = InetAddress.getLocalHost().getHostName();

            /* Make single first client connection in order to get the
             * list of registry ports that have been created. Then we can
             * go and start client threads that connect and interact with
             * each one. */
            Registry registry = LocateRegistry.getRegistry(host,
                registryStartingPort, new RmiTLSClientSocketFactory(
                    createClientSocketFactory(useNewSF)));
            RmiRemoteInterface ri =
                (RmiRemoteInterface)registry.lookup("RmiRemoteInterface");
            registryPorts = ri.getRegistryPorts();
            System.out.println("Got list of server registry ports");
            for (int i = 0; i < registryPorts.length; i++) {
                System.out.println(host + ": " + registryPorts[i]);
            }

            List<ClientThread> clientList = new ArrayList<ClientThread>();
            CountDownLatch latch = new CountDownLatch(
                numClientConnections * registryPorts.length);

            /* Reset static thread counters */
            success.set(0, 0);
            failures.set(0, 0);

            for (int i = 0; i < numClientConnections; i++) {
                for (int j = 0; j < registryPorts.length; j++) {
                    ClientThread client =
                        new ClientThread(host, registryPorts[j],
                            createClientSocketFactory(useNewSF), latch);
                    clientList.add(client);
                }
            }

            ExecutorService executor = Executors.newFixedThreadPool(
                clientList.size());

            for (final ClientThread c: clientList) {
                executor.execute(c);
            }

            latch.await();
            executor.shutdown();

        } catch (Exception e) {

            System.out.println("Client exception: " + e.toString());
            e.printStackTrace();
        }

        System.out.println("=================================================");
        System.out.println("All Client Connections Finished");
        System.out.println("Successful = " + success.get(0));
        System.out.println("Failed = " + failures.get(0));
        System.out.println("=================================================");
    }

    public static void main(String[] args) {
        new RmiClient(args);
    }

    private void printUsage() {
        System.out.println("Java RMI example threaded client usage:");
        System.out.println("-n <num>\tNumber of client connection rounds");
        System.out.println("-randsleep\tRandom sleep before starting threads");
        System.out.println("-newSF\tUse new SocketFactory for each " +
            "client connection");
        System.out.println("-jsseProv <String>\tJSSE provider to use " +
            "(ex: wolfJSSE, SunJSSE)");
        System.exit(1);
    }
}

