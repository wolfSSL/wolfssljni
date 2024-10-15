/* RmiServer.java
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

import java.rmi.registry.Registry;
import java.rmi.registry.LocateRegistry;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.security.Security;

import com.wolfssl.WolfSSL;
import com.wolfssl.provider.jsse.WolfSSLProvider;

/**
 * Server class implementing RemoteInterface.getServerMessage() interface.
 */
public class RmiServer extends UnicastRemoteObject implements RmiRemoteInterface
{
    private static final int registryPort = 11115;

    public RmiServer() throws Exception {
        super(registryPort,
              new RmiTLSClientSocketFactory(),
              new RmiTLSServerSocketFactory());
    }

    /**
     * Return message from server. Implementation of
     * RmiRemoteInterface.getServerHello(), callable via RMI from client.
     */
    public String getServerMessage() {
        return "Hello from server";
    }

    public static void main(String[] args) {
        
        try {
            /* Register wolfJSSE as top priority JSSE provider */
            WolfSSL.loadLibrary();
            Security.insertProviderAt(new WolfSSLProvider(), 1);

            /* Register object with Java RMI registry. Create new registry
             * using SSL/TLS on specified port. If bind() fails, will throw
             * a RemoteException. */
            Registry registry = LocateRegistry.createRegistry(registryPort,
                new RmiTLSClientSocketFactory(), new RmiTLSServerSocketFactory());

            /* Create and export a remote object */
            RmiServer srv = new RmiServer();
            registry.bind("RmiRemoteInterface", srv);

            System.out.println("Server started, listening for connections");

        } catch (Exception e) {

            System.out.println("Server exception: " + e.toString());
            e.printStackTrace();
        }
    }
}

