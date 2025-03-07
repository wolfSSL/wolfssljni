/* SSLEngineClientDTLS13.java
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
 * Example DTLS 1.3 client using SSLEngine.
 *
 * This client connects to a DTLS 1.3 server, sends data, receives a response,
 * and then shuts down the connection. This example is compiled when 
 * 'ant examples' is run in the package root.
 *
 * $ ant examples
 * $ ./examples/provider/SSLEngineClientDTLS13.sh
 *
 * For testing, start the SSLEngineServerDTLS13 example first:
 *
 * $ ./examples/provider/SSLEngineServerDTLS13.sh
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

public class SSLEngineClientDTLS13 {
    /* Keystore and connection settings */
    private char[] psw;
    private String clientKS = "./examples/provider/client.jks";
    private String caKS = "./examples/provider/ca-server.jks";
    private String jsseProv = "wolfJSSE";
    private String host = "localhost";
    private int port = 11119;
    
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

    public SSLEngineClientDTLS13() {
        try {
            Security.addProvider(new WolfSSLProvider());

            /* Set up KeyStore */
            KeyStore clientKeyStore = KeyStore.getInstance("JKS");
            clientKeyStore.load(new FileInputStream(clientKS), psw);

            KeyManagerFactory km = KeyManagerFactory
                .getInstance("SunX509", jsseProv);
            km.init(clientKeyStore, psw);

            /* Set up CA TrustManagerFactory */
            KeyStore caKeyStore = KeyStore.getInstance("JKS");
            caKeyStore.load(new FileInputStream(caKS), psw);
            
            TrustManagerFactory tm = TrustManagerFactory
                .getInstance("SunX509", jsseProv);
            tm.init(caKeyStore);

            /* Create SSLContext for DTLS 1.3 */
            SSLContext ctx = SSLContext.getInstance("DTLSv1.3", jsseProv);
            ctx.init(km.getKeyManagers(), tm.getTrustManagers(), null);

            /* Create DatagramSocket for DTLS */
            DatagramSocket clientSocket = new DatagramSocket();
            InetAddress serverAddress = InetAddress.getByName(host);

            /* Create SSLEngine */
            SSLEngine engine = ctx.createSSLEngine(host, port);
            engine.setUseClientMode(true);

            /* Configure SSLEngine for DTLS */
            SSLSession session = engine.getSession();
            int appBufferSize = session.getApplicationBufferSize();
            int netBufferSize = session.getPacketBufferSize();

            /* Start handshake */
            engine.beginHandshake();

            /* Connect to server, perform handshake, send/receive data */
            connectToServer(engine, clientSocket, serverAddress, port);

        } catch(Exception e) {
            e.printStackTrace();
        }
    }

    private void connectToServer(SSLEngine engine, DatagramSocket socket,
                                InetAddress serverAddress, int serverPort) {
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
                    case NEED_WRAP:
                        /* Wrap handshake data */
                        netData.clear();
                        SSLEngineResult wrapResult = engine.wrap(appData, netData);
                        status = wrapResult.getHandshakeStatus();
                        
                        /* Send wrapped data to server */
                        netData.flip();
                        byte[] data = new byte[netData.remaining()];
                        netData.get(data);
                        DatagramPacket sendPacket = new DatagramPacket(
                            data, data.length, serverAddress, serverPort);
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
                        
                    case NEED_UNWRAP:
                        /* Receive data from server */
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
            
            /* Handshake complete, now send application data */
            System.out.println("Handshake completed, sending data to server");
            
            /* Prepare message to send */
            String message = "Hello from DTLS 1.3 client!";
            appData.clear();
            appData.put(message.getBytes());
            appData.flip();
            
            /* Wrap the message */
            netData.clear();
            engine.wrap(appData, netData);
            netData.flip();
            
            /* Send message to server */
            byte[] messageData = new byte[netData.remaining()];
            netData.get(messageData);
            DatagramPacket messagePacket = new DatagramPacket(
                messageData, messageData.length, serverAddress, serverPort);
            socket.send(messagePacket);
            
            /* Receive response from server */
            peerNetData.clear();
            DatagramPacket responsePacket = new DatagramPacket(
                peerNetData.array(), peerNetData.capacity());
            socket.receive(responsePacket);
            peerNetData.position(responsePacket.getLength());
            peerNetData.flip();
            
            /* Unwrap the response */
            peerAppData.clear();
            engine.unwrap(peerNetData, peerAppData);
            peerAppData.flip();
            
            /* Read the server's response */
            byte[] serverMsg = new byte[peerAppData.remaining()];
            peerAppData.get(serverMsg);
            System.out.println("Received from server: " + new String(serverMsg));
            
            /* Close the connection */
            engine.closeOutbound();
            
            /* Send close_notify */
            netData.clear();
            SSLEngineResult closeResult = engine.wrap(appData, netData);
            netData.flip();
            byte[] closeData = new byte[netData.remaining()];
            netData.get(closeData);
            DatagramPacket closePacket = new DatagramPacket(
                closeData, closeData.length, serverAddress, serverPort);
            socket.send(closePacket);
            
            /* Wait for server's close_notify */
            peerNetData.clear();
            DatagramPacket closeResponsePacket = new DatagramPacket(
                peerNetData.array(), peerNetData.capacity());
            socket.setSoTimeout(5000); // Set timeout for close_notify
            try {
                socket.receive(closeResponsePacket);
                peerNetData.position(closeResponsePacket.getLength());
                peerNetData.flip();
                engine.unwrap(peerNetData, peerAppData);
            } catch (SocketTimeoutException e) {
                /* Timeout waiting for server close_notify, continue */
            }
            
            System.out.println("Connection closed");
            socket.close();
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        new SSLEngineClientDTLS13();
    }
}
