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

import java.net.InetAddress;
import java.rmi.server.RMIClientSocketFactory;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.security.Security;

import com.wolfssl.WolfSSL;
import com.wolfssl.provider.jsse.WolfSSLProvider;

/**
 * Client class calling remote object interface on Server via RMI.
 */
public class RmiClient
{
    /* RMI registry port, needs to be same as Server.java has */
    private static final int registryPort = 11115;

    public RmiClient() {
        /* Default constructor */
    }

    public static void main(String[] args) {

        try {

            /* Register wolfJSSE as top priority JSSE provider */
            WolfSSL.loadLibrary();
            Security.insertProviderAt(new WolfSSLProvider(), 1);

            /* Server hostname, null indicates localhost */
            String host = InetAddress.getLocalHost().getHostName();

            /* Get stub for the SSL/TLS registry on specified host */
            Registry registry = LocateRegistry.getRegistry(host, registryPort,
                new RmiTLSClientSocketFactory());

            /* Invoke lookup on remote registry to get remote object stub */
            RmiRemoteInterface ri =
                (RmiRemoteInterface)registry.lookup("RmiRemoteInterface");

            /* Call remote method, get back server response */
            String serverMessage = ri.getServerMessage();
            System.out.println("Message from server via RMI: " + serverMessage);

        } catch (Exception e) {

            System.out.println("Client exception: " + e.toString());
            e.printStackTrace();
        }
    }
}

