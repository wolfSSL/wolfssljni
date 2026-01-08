/* RmiServer.java
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

import java.util.List;
import java.util.ArrayList;
import java.util.Arrays;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.net.Socket;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;

import java.rmi.registry.Registry;
import java.rmi.registry.LocateRegistry;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.security.Security;

import com.wolfssl.WolfSSL;
import com.wolfssl.provider.jsse.WolfSSLProvider;

/**
 * Server class implementing RemoteInterface methods to operate over RMI.
 *
 * This server has been set up to register a dynamic number of services on
 * different ports. By default, only one RMI registry entry will be created
 * on the default port of "registryStartingPort". If the user starts the
 * example with "-n XX", then this server will create and register that
 * many RMI entries. Port numbers will increment from "registryStartingPort".
 * For example, starting this example with "-n 3" will create RMI registry
 * entries on ports 11115, 11116, and 11117.
 *
 * The client will create one RMI connection to the default port first, then
 * call the RMI interface getRegistryPorts() to get an array of ports that
 * this server has started. The client will then subsequently make connections
 * to each of those ports. At least one connection, or maybe more if the client
 * example was started with "-n XX" greater than 1.
 */
public class RmiServer extends UnicastRemoteObject implements RmiRemoteInterface
{
    /* RMI registry ports. We start by creating one registry, but the user
     * can tell us how many registries/ports to create using cmd line args.
     * The number of registries can be increased from 1 to simulate
     * connecting to multiple server registries from a client. */
    private static final int registryStartingPort = 11115;

    /* Number of RMI registries to create */
    private int numRegistries = 1;

    /* List holding ports of registries created. Static so one across all
     * RmiServer objects */
    private static List<Integer> registryPorts = new ArrayList<>();

    /* Keystore files and passwords, holding certs/keys/CAs */
    private static String clientJKS = "../provider/client.jks";
    private static String clientCaJKS = "../provider/ca-server.jks";
    private static String serverJKS = "../provider/server.jks";
    private static String serverCaJKS = "../provider/ca-client.jks";
    private static String jksPass = "wolfSSL test";

    /* Keystore file format */
    private static String keystoreFormat = "JKS";

    /* TLS protocol version - "TLS" uses highest compiled in */
    private static String tlsVersion = "TLS";

    /* JSSE provider to use for this example */
    private static String jsseProvider = "wolfJSSE";

    /* Buffer size for test buffers sent/received */
    private static final int BUFFER_SIZE = 2048;

    /**
     * Return message from server. Implementation of
     * RmiRemoteInterface.getMessage(), callable via RMI from client.
     */
    public String getMessage() {
        return "Hello from server";
    }

    /**
     * Send message to server. Implementation of
     * RmiRemoteInterface.sendMessage(), callable via RMI from client.
     */
    public void sendMessage(String message) {
        System.out.println("Message received: " + message);
    }

    /**
     * Get dummy byte array from server. Implementation of
     * RmiRemoteInterface.getByteArray(), callable via RMI from client.
     */
    public byte[] getByteArray() {
        byte[] arr = new byte[BUFFER_SIZE];
        Arrays.fill(arr, (byte)0x05);
        System.out.println("Sending byte array (length: " + arr.length + ")");
        return arr;
    }

    /**
     * Send dummy byte array to caller. Implementation of
     * RmiRemoteInterface.sendByteArray(), callable via RMI from client.
     */
    public void sendByteArray(byte[] arr) {
        if (arr != null) {
            System.out.println("Received byte array: size = " + arr.length);
        }
        else {
            System.out.println("ERROR: received null byte array");
        }
    }

    /**
     * Get registry ports that we have created. Implementation of
     * RmiRemoteInterface.getRegistryPorts(), callable via RMI from client.
     */
    public int[] getRegistryPorts() {
        int[] ret = new int[registryPorts.size()];
        for (int i = 0; i < registryPorts.size(); i++) {
            ret[i] = registryPorts.get(i).intValue();
        }
        return ret;
    }

    /**
     * Create client SocketFactory for use with RMI over TLS.
     * @return new SocketFactory object or null on error.
     */
    private static SocketFactory createClientSocketFactory() {

        SSLContext ctx = null;
        TrustManagerFactory tm = null;
        KeyManagerFactory km = null;
        KeyStore cert, pKey = null;
        SocketFactory sf = null;

        try {
            /* Create TrustManagerFactory with certs to verify peer */
            tm = TrustManagerFactory.getInstance("SunX509", jsseProvider);
            cert = KeyStore.getInstance(keystoreFormat);
            cert.load(new FileInputStream(clientCaJKS), jksPass.toCharArray());
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

            /* Create SocketFactory */
            sf = ctx.getSocketFactory();
            System.out.println("Created client SocketFactory");

        } catch (Exception e) {
            System.out.println("Exception when creating client SocketFactory");
            e.printStackTrace();
            return null;
        }

        return sf;
    }

    /**
     * Create server SSLServerSocketFactory for use with RMI over TLS.
     * @return new SSLServerSocketFactory object or null on error.
     */
    private static SSLServerSocketFactory createServerSocketFactory() {

        SSLContext ctx = null;
        TrustManagerFactory tm = null;
        KeyManagerFactory km = null;
        KeyStore cert, pKey = null;
        SSLServerSocketFactory sf = null;

        try {
            /* Create TrustManagerFactory with certs to verify peer */
            tm = TrustManagerFactory.getInstance("SunX509", jsseProvider);
            cert = KeyStore.getInstance(keystoreFormat);
            cert.load(new FileInputStream(serverCaJKS), jksPass.toCharArray());
            tm.init(cert);
            System.out.println("Created server TrustManagerFactory");

            /* Create KeyManagerFactory with server cert/key */
            pKey = KeyStore.getInstance(keystoreFormat);
            pKey.load(new FileInputStream(serverJKS), jksPass.toCharArray());
            km = KeyManagerFactory.getInstance("SunX509", jsseProvider);
            km.init(pKey, jksPass.toCharArray());
            System.out.println("Created server KeyManagerFactory");

            /* Create SSLContext, doing peer auth */
            ctx = SSLContext.getInstance(tlsVersion, jsseProvider);
            ctx.init(km.getKeyManagers(), tm.getTrustManagers(), null);
            System.out.println("Created server SSLContext");

            /* Create SocketFactory */
            sf = (SSLServerSocketFactory)ctx.getServerSocketFactory();
            System.out.println("Created server SSLServerSocketFactory");

        } catch (Exception e) {
            System.out.println("Exception when creating server SocketFactory");
            e.printStackTrace();
            return null;
        }

        return sf;
    }

    public RmiServer() throws RemoteException {
        /* RmiRemoteInterface default constructor throws RemoteException */
        super();
    }

    public RmiServer(String[] args) throws RemoteException {

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
                numRegistries = Integer.parseInt(args[++i]);
            }
            else if (arg.equals("-jsseProv")) {
                if (args.length < i+2) {
                    printUsage();
                }
                jsseProvider = args[++i];
            }
            else {
                printUsage();
            }
        }

        try {
            /* Create one SocketFactory for server and one for client */
            SocketFactory cliSF = createClientSocketFactory();
            SSLServerSocketFactory srvSF = createServerSocketFactory();

            /* Register object with Java RMI registry. Create new registry
             * using SSL/TLS on specified port. If bind() fails, will throw
             * a RemoteException. */
            for (int i = 0; i < numRegistries; i++) {
                int port = registryStartingPort + i;
                Registry registry = LocateRegistry.createRegistry(port,
                    new RmiTLSClientSocketFactory(cliSF),
                    new RmiTLSServerSocketFactory(srvSF));
                registry.bind("RmiRemoteInterface", new RmiServer());
                registryPorts.add(port);
            }

            System.out.println("Registries created, listening for connections");
            System.out.println("Available registries:");
            for (int i = 0; i < registryPorts.size(); i++) {
                System.out.println("port: " + registryPorts.get(i));
            }

        } catch (Exception e) {
            System.out.println("Server exception: " + e.toString());
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        try {
            new RmiServer(args);
        } catch (RemoteException e) {
            e.printStackTrace();
        }
    }

    private void printUsage() {
        System.out.println("Java RMI example server usage:");
        System.out.println("-n <num>\tNumber of server registries to create, " +
            "port numbers increment from 11115");
        System.out.println("-jsseProv <String>\tJSSE provider to use " +
            "(ex: wolfJSSE, SunJSSE)");
        System.exit(1);
    }
}

