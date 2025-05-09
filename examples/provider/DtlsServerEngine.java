/* DtlsServerEngine.java
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

import java.io.FileInputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.security.Security;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManagerFactory;

import com.wolfssl.WolfSSL;
import com.wolfssl.provider.jsse.WolfSSLProvider;

/**
 * Simple DTLS 1.3 example server using SSLEngine.
 * This class demonstrates how to use SSLEngine with DTLS 1.3
 * to accept a connection from a client, receive data, echo it back,
 * and then close the connection.
 */
public class DtlsServerEngine {

    private static final int MAX_HANDSHAKE_LOOPS = 60;
    private static final int MAX_PACKET_SIZE = 16384;
    private static final int SOCKET_TIMEOUT = 5000; /* 5 seconds */

    private int port = 11113;

    private String serverJKS = "../../examples/provider/server.jks";
    private String serverPswd = "wolfSSL test";
    private String caJKS = "../../examples/provider/ca-client.jks";
    private String caPswd = "wolfSSL test";

    private SSLContext ctx;
    private SSLEngine engine;
    private DatagramSocket socket;
    private InetSocketAddress clientAddress;

    /* Application and network buffers for data processing */
    private ByteBuffer appOutBuffer;
    private ByteBuffer appInBuffer;
    private ByteBuffer netOutBuffer;
    private ByteBuffer netInBuffer;

    public DtlsServerEngine() {
        /* Default constructor */
    }

    public DtlsServerEngine(int port) {
        this.port = port;
    }

    /**
     * Run the DTLS server
     */
    public void run() {
        try {
            /* Register wolfJSSE as first priority provider */
            Security.insertProviderAt(new WolfSSLProvider(), 1);

            /* Create socket without timeout for initial connection */
            socket = new DatagramSocket(port);
            System.out.println("DTLS 1.3 Server listening on port " + port);

            /* Set up SSL context and engine */
            setupSSL();

            /* Initialize buffer sizes based on SSLSession */
            SSLSession session = engine.getSession();
            int appBufferSize = session.getApplicationBufferSize();
            int netBufferSize = session.getPacketBufferSize();

            appOutBuffer = ByteBuffer.allocate(appBufferSize);
            appInBuffer = ByteBuffer.allocate(appBufferSize);
            netOutBuffer = ByteBuffer.allocate(netBufferSize);
            netInBuffer = ByteBuffer.allocate(netBufferSize);

            /* Wait for client connection and perform handshake */
            waitForClientAndHandshake();

            /* Receive and process data from client */
            byte[] clientData = receiveData();
            String clientMessage = new String(clientData);
            System.out.println("Received from client: " + clientMessage);

            /* Echo data back to client */
            System.out.println("Echoing message back to client");
            sendData(clientData);

            /* Close connection */
            closeConnection();

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Set up the SSLContext and SSLEngine for DTLSv1.3
     */
    private void setupSSL() throws Exception {
        /* Server KeyStore */
        KeyStore serverKeystore = KeyStore.getInstance("JKS");
        serverKeystore.load(new FileInputStream(serverJKS),
            serverPswd.toCharArray());

        /* Server TrustStore */
        KeyStore serverTruststore = KeyStore.getInstance("JKS");
        serverTruststore.load(new FileInputStream(caJKS),
            caPswd.toCharArray());

        /* Server TrustManagerFactory, init with TrustStore */
        TrustManagerFactory serverTm = TrustManagerFactory.getInstance(
            "SunX509", "wolfJSSE");
        serverTm.init(serverTruststore);

        /* Server KeyManagerFactory, init with KeyStore */
        KeyManagerFactory serverKm = KeyManagerFactory.getInstance(
            "SunX509", "wolfJSSE");
        serverKm.init(serverKeystore, serverPswd.toCharArray());

        /* Create SSLContext configured for DTLS 1.3 */
        ctx = SSLContext.getInstance("DTLSv1.3", "wolfJSSE");
        ctx.init(serverKm.getKeyManagers(), serverTm.getTrustManagers(), null);

        /* Create server-side SSLEngine with client auth enabled */
        engine = ctx.createSSLEngine();
        engine.setUseClientMode(false);
        engine.setNeedClientAuth(true);

        /* Set SSL parameters if needed */
        try {
            SSLParameters params = engine.getSSLParameters();
            engine.setSSLParameters(params);
        } catch (Exception e) {
            System.out.println(
                "DEBUG: Exception setting SSL parameters: " + e.getMessage());
        }

        System.out.println("DTLS 1.3 Server Engine created");
    }

    /**
     * Wait for a client connection and perform the DTLS handshake
     */
    private void waitForClientAndHandshake() throws Exception {
        System.out.println("Waiting for client connection...");

        /* Wait for initial message from client */
        byte[] buffer = new byte[MAX_PACKET_SIZE];
        DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
        socket.receive(packet);

        /* Store client address for future communication */
        clientAddress = new InetSocketAddress(
            packet.getAddress(), packet.getPort());
        System.out.println("Client connected from " + clientAddress);

        /* Put received data into the network buffer */
        netInBuffer.put(packet.getData(), 0, packet.getLength());

        /* Begin handshake */
        engine.beginHandshake();
        HandshakeStatus handshakeStatus = engine.getHandshakeStatus();
        int loops = 0;

        while (handshakeStatus != HandshakeStatus.FINISHED &&
               handshakeStatus != HandshakeStatus.NOT_HANDSHAKING) {

            if (loops++ > MAX_HANDSHAKE_LOOPS) {
                throw new RuntimeException(
                    "Too many handshake loops, possible handshake failure");
            }

            switch (handshakeStatus) {
                case NEED_UNWRAP:
                    handshakeStatus = handleUnwrap();
                    break;

                case NEED_WRAP:
                    handshakeStatus = handleWrap();
                    break;

                case NEED_TASK:
                    Runnable task;
                    while ((task = engine.getDelegatedTask()) != null) {
                        task.run();
                    }
                    handshakeStatus = engine.getHandshakeStatus();
                    break;

                default:
                    throw new IllegalStateException(
                        "Invalid handshake status: " + handshakeStatus);
            }
        }

        System.out.println("DTLS handshake completed successfully");

        /* Add a small delay after handshake to ensure both sides are ready */
        System.out.println(
            "Pausing briefly before processing application data...");
        try {
            Thread.sleep(200);  /* 200ms pause */
        } catch (InterruptedException e) {
            /* Ignore interruption */
        }
    }

    /**
     * Handle wrap operations during handshake
     */
    private HandshakeStatus handleWrap() throws Exception {
        netOutBuffer.clear();
        SSLEngineResult result = engine.wrap(appOutBuffer, netOutBuffer);

        switch (result.getStatus()) {
            case OK:
                sendPacket(netOutBuffer);
                return result.getHandshakeStatus();

            case BUFFER_OVERFLOW:
                /* Increase the buffer size and try again */
                int newSize = engine.getSession().getPacketBufferSize();
                ByteBuffer newBuffer = ByteBuffer.allocate(newSize);
                netOutBuffer = newBuffer;
                return engine.getHandshakeStatus();

            default:
                throw new SSLException(
                    "Unexpected wrap result: " + result.getStatus());
        }
    }

    /**
     * Handle unwrap operations during handshake
     */
    private HandshakeStatus handleUnwrap() throws Exception {
        if (netInBuffer.position() == 0) {
            /* No data in the buffer, receive a packet */
            receivePacket(netInBuffer);
        }

        netInBuffer.flip();
        SSLEngineResult result = engine.unwrap(netInBuffer, appInBuffer);
        netInBuffer.compact();

        switch (result.getStatus()) {
            case OK:
                return result.getHandshakeStatus();

            case BUFFER_UNDERFLOW:
                /* Need more data, receive another packet */
                receivePacket(netInBuffer);
                return engine.getHandshakeStatus();

            case BUFFER_OVERFLOW:
                /* Increase the buffer size and try again */
                int newSize = engine.getSession().getApplicationBufferSize();
                ByteBuffer newBuffer = ByteBuffer.allocate(newSize);
                appInBuffer = newBuffer;
                return engine.getHandshakeStatus();

            default:
                throw new SSLException(
                    "Unexpected unwrap result: " + result.getStatus());
        }
    }

    /**
     * Send application data to the client
     */
    private void sendData(byte[] data) throws Exception {
        appOutBuffer.clear();
        appOutBuffer.put(data);
        appOutBuffer.flip();

        while (appOutBuffer.hasRemaining()) {
            netOutBuffer.clear();
            SSLEngineResult result = engine.wrap(appOutBuffer, netOutBuffer);

            switch (result.getStatus()) {
                case OK:
                    sendPacket(netOutBuffer);
                    break;

                case BUFFER_OVERFLOW:
                    /* Increase the buffer size and try again */
                    int newSize = engine.getSession().getPacketBufferSize();
                    ByteBuffer newBuffer = ByteBuffer.allocate(newSize);
                    netOutBuffer = newBuffer;
                    break;

                default:
                    throw new SSLException(
                        "Unexpected wrap result: " + result.getStatus());
            }
        }
    }

    /**
     * Receive application data from the client
     */
    private byte[] receiveData() throws Exception {
        int attempts = 0;
        while (attempts++ < 3) {  /* Try a few times to get data */
            netInBuffer.clear();
            try {
                receivePacket(netInBuffer);

                netInBuffer.flip();
                appInBuffer.clear();

                SSLEngineResult result =
                    engine.unwrap(netInBuffer, appInBuffer);

                switch (result.getStatus()) {
                    case OK:
                        appInBuffer.flip();
                        byte[] data = new byte[appInBuffer.remaining()];
                        appInBuffer.get(data);
                        return data;

                    case BUFFER_UNDERFLOW:
                        /* Need more data */
                        continue;

                    case BUFFER_OVERFLOW:
                        /* Increase the buffer size and try again */
                        int newSize =
                            engine.getSession().getApplicationBufferSize();
                        ByteBuffer newBuffer = ByteBuffer.allocate(newSize);
                        appInBuffer = newBuffer;
                        break;

                    default:
                        throw new SSLException(
                            "Unexpected unwrap result: " + result.getStatus());
                }
            } catch (SocketTimeoutException e) {
                System.out.println("Socket timeout, retrying...");
            }
        }

        throw new IOException("Failed to receive data after multiple attempts");
    }

    /**
     * Close the SSL connection properly
     */
    private void closeConnection() throws Exception {
        System.out.println("Closing connection...");

        engine.closeOutbound();

        while (!engine.isOutboundDone()) {
            /* Get the close message */
            netOutBuffer.clear();
            SSLEngineResult result = engine.wrap(appOutBuffer, netOutBuffer);

            /* Check result status */
            if (result.getStatus() != SSLEngineResult.Status.OK) {
                throw new SSLException(
                    "Error closing outbound: " + result.getStatus());
            }

            /* Send the close message to the client */
            sendPacket(netOutBuffer);
        }

        System.out.println("Connection closed");
        socket.close();
    }

    /**
     * Send a packet to the client
     */
    private void sendPacket(ByteBuffer buffer) throws IOException {
        buffer.flip();
        int len = buffer.remaining();
        byte[] data = new byte[len];
        buffer.get(data);

        DatagramPacket packet = new DatagramPacket(data, len, clientAddress);
        socket.send(packet);
        System.out.println("DEBUG: Sent packet with " + len + " bytes");
    }

    /**
     * Receive a packet from the client
     */
    private void receivePacket(ByteBuffer buffer) throws IOException {
        /* Set socket timeout for data operations after connection */
        socket.setSoTimeout(SOCKET_TIMEOUT);

        byte[] data = new byte[MAX_PACKET_SIZE];
        DatagramPacket packet = new DatagramPacket(data, data.length);
        socket.receive(packet);
        System.out.println(
            "DEBUG: Received packet with " + packet.getLength() + " bytes");

        /* Update client address in case it changed */
        clientAddress = new InetSocketAddress(
            packet.getAddress(), packet.getPort());

        buffer.put(data, 0, packet.getLength());
    }

    /**
     * Main method, parse cmd line args and run new instance of DtlsServerEngine
     */
    public static void main(String[] args) {
        int port = 11113;

        /* Parse command line arguments */
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];

            if (arg.equals("-p") && i + 1 < args.length) {
                port = Integer.parseInt(args[++i]);
            } else if (arg.equals("-?")) {
                printUsage();
                return;
            }
        }

        DtlsServerEngine server = new DtlsServerEngine(port);
        server.run();
    }

    /**
     * Print usage information
     */
    private static void printUsage() {
        System.out.println("DTLS 1.3 Server Engine Example");
        System.out.println("Usage: DtlsServerEngine [-p port]");
        System.out.println("  -p port   Port to listen on (default: 11113)");
        System.out.println("  -?        Print this help menu");
    }
}

