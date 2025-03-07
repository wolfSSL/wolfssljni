/* SSLEngineServerDTLS13.java
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

/**
 * Example DTLS 1.3 server using SSLEngine.
 *
 * This server waits in an infinite loop for client connections, and when
 * connected creates a new thread for each connection. This example is compiled
 * when 'ant examples' is run in the package root.
 *
 * $ ant examples
 * $ ./examples/provider/SSLEngineServerDTLS13.sh
 *
 * For testing, connect with the SSLEngineClientDTLS13 example:
 *
 * $ ./examples/provider/SSLEngineClientDTLS13.sh
 *
 */
import java.util.*;
import java.io.*;
import java.net.*;
import java.nio.*;
import java.nio.channels.*;
import javax.net.ssl.*;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import java.security.*;
import com.wolfssl.provider.jsse.WolfSSLProvider;

public class SSLEngineServerDTLS13 {
    /* Keystore and connection settings */
    private char[] psw;
    private String serverKS = "./examples/provider/server.jks";
    private String serverTS = "./examples/provider/ca-client.jks";
    private String jsseProv = "wolfJSSE";
    private int serverPort = 11119;
    
    /* Initialize password from environment or system property */
    {
        String password = System.getProperty("javax.net.ssl.keyStorePassword");
        if (password == null) {
            password = System.getenv("WOLFSSL_PASSWORD");
        }
        if (password == null) {
            System.err.println("Warning: Using empty password. Set password with " +
                "javax.net.ssl.keyStorePassword property or WOLFSSL_PASSWORD env var");
            password = "";
        }
        psw = password.toCharArray();
    }

    public SSLEngineServerDTLS13() {
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

            /* Create SSLContext for DTLS 1.3 */
            SSLContext ctx = SSLContext.getInstance("DTLSv1.3", jsseProv);
            ctx.init(km.getKeyManagers(), tm.getTrustManagers(), null);

            /* Create DatagramSocket for DTLS */
            DatagramSocket serverSocket = new DatagramSocket(serverPort);
            System.out.println("DTLS 1.3 Server listening on port " + serverPort);

            while (true) {
                /* Create buffer for client's initial message */
                byte[] buffer = new byte[1024];
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                
                /* Wait for client connection */
                serverSocket.receive(packet);
                
                /* Create and start new client handler thread */
                ClientHandler client = new ClientHandler(ctx, serverSocket, packet);
                client.start();
            }

        } catch(Exception e) {
            e.printStackTrace();
        }
    }

    class ClientHandler extends Thread {
        private SSLEngine engine;
        private DatagramSocket socket;
        private DatagramPacket clientPacket;
        private InetAddress clientAddress;
        private int clientPort;

        public ClientHandler(SSLContext ctx, DatagramSocket s, 
                             DatagramPacket p) {
            socket = s;
            clientPacket = p;
            clientAddress = p.getAddress();
            clientPort = p.getPort();
            
            /* Create SSLEngine for this client */
            engine = ctx.createSSLEngine(clientAddress.getHostAddress(), 
                                         clientPort);
            engine.setUseClientMode(false);
            engine.setNeedClientAuth(true);
        }

        public void run() {
            try {
                /* Configure SSLEngine for DTLS */
                SSLSession session = engine.getSession();
                int appBufferSize = session.getApplicationBufferSize();
                int netBufferSize = session.getPacketBufferSize();
                
                /* Start handshake */
                engine.beginHandshake();
                
                /* Process handshake and data exchange */
                handleConnection();
                
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        private void handleConnection() {
            try {
                SSLSession session = engine.getSession();
                ByteBuffer appData = ByteBuffer.allocate(session.getApplicationBufferSize());
                ByteBuffer netData = ByteBuffer.allocate(session.getPacketBufferSize());
                ByteBuffer peerAppData = ByteBuffer.allocate(session.getApplicationBufferSize());
                ByteBuffer peerNetData = ByteBuffer.allocate(session.getPacketBufferSize());
                
                HandshakeStatus status = engine.getHandshakeStatus();
                boolean handshakeComplete = false;
                
                /* Handle handshake */
                while (!handshakeComplete) {
                    switch (status) {
                        case NEED_UNWRAP:
                            /* Receive data from client */
                            peerNetData.clear();
                            DatagramPacket packet = new DatagramPacket(
                                peerNetData.array(), peerNetData.capacity());
                            socket.receive(packet);
                            peerNetData.position(packet.getLength());
                            peerNetData.flip();
                            
                            /* Unwrap received data */
                            SSLEngineResult result = engine.unwrap(peerNetData, peerAppData);
                            peerNetData.compact();
                            status = result.getHandshakeStatus();
                            
                            /* Handle tasks */
                            if (status == HandshakeStatus.NEED_TASK) {
                                Runnable task;
                                while ((task = engine.getDelegatedTask()) != null) {
                                    task.run();
                                }
                                status = engine.getHandshakeStatus();
                            }
                            break;
                            
                        case NEED_WRAP:
                            /* Wrap handshake data */
                            netData.clear();
                            SSLEngineResult wrapResult = engine.wrap(appData, netData);
                            status = wrapResult.getHandshakeStatus();
                            
                            /* Send wrapped data to client */
                            netData.flip();
                            byte[] data = new byte[netData.remaining()];
                            netData.get(data);
                            DatagramPacket sendPacket = new DatagramPacket(
                                data, data.length, clientAddress, clientPort);
                            socket.send(sendPacket);
                            
                            /* Handle tasks */
                            if (status == HandshakeStatus.NEED_TASK) {
                                Runnable task;
                                while ((task = engine.getDelegatedTask()) != null) {
                                    task.run();
                                }
                                status = engine.getHandshakeStatus();
                            }
                            break;
                            
                        case FINISHED:
                            handshakeComplete = true;
                            break;
                            
                        case NOT_HANDSHAKING:
                            handshakeComplete = true;
                            break;
                            
                        default:
                            throw new IllegalStateException("Invalid handshake status: " + status);
                    }
                }
                
                /* Handshake complete, now exchange application data */
                System.out.println("Handshake completed, waiting for data from client");
                
                /* Receive data from client */
                peerNetData.clear();
                DatagramPacket dataPacket = new DatagramPacket(
                    peerNetData.array(), peerNetData.capacity());
                socket.receive(dataPacket);
                peerNetData.position(dataPacket.getLength());
                peerNetData.flip();
                
                /* Unwrap received data */
                peerAppData.clear();
                SSLEngineResult dataResult = engine.unwrap(peerNetData, peerAppData);
                peerAppData.flip();
                
                /* Read the client message */
                byte[] clientMsg = new byte[peerAppData.remaining()];
                peerAppData.get(clientMsg);
                String message = new String(clientMsg);
                System.out.println("Received from client: " + message);
                
                /* Echo the message back to client */
                appData.clear();
                appData.put(clientMsg);
                appData.flip();
                
                /* Wrap the response */
                netData.clear();
                engine.wrap(appData, netData);
                netData.flip();
                
                /* Send response to client */
                byte[] responseData = new byte[netData.remaining()];
                netData.get(responseData);
                DatagramPacket responsePacket = new DatagramPacket(
                    responseData, responseData.length, clientAddress, clientPort);
                socket.send(responsePacket);
                
                /* Close the connection */
                engine.closeOutbound();
                
                /* Send close_notify */
                netData.clear();
                SSLEngineResult closeResult = engine.wrap(appData, netData);
                netData.flip();
                byte[] closeData = new byte[netData.remaining()];
                netData.get(closeData);
                DatagramPacket closePacket = new DatagramPacket(
                    closeData, closeData.length, clientAddress, clientPort);
                socket.send(closePacket);
                
                System.out.println("Connection closed");
                
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public static void main(String[] args) {
        new SSLEngineServerDTLS13();
    }
}
