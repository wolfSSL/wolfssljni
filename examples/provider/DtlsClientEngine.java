/* DtlsClientEngine.java
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


import java.io.FileInputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.security.Security;
import java.util.concurrent.TimeUnit;

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
 * Simple DTLS 1.3 example client using SSLEngine.
 * This class demonstrates how to use SSLEngine with DTLS 1.3
 * to establish a secure connection to a server, send some data,
 * receive a response, and then close the connection.
 */
public class DtlsClientEngine {

    private static final int SOCKET_TIMEOUT = 10000; /* 10 seconds */
    private static final int BUFFER_SIZE = 1024;
    private static final int MAX_HANDSHAKE_LOOPS = 60;
    private static final int MAX_PACKET_SIZE = 16384;

    private String host = "localhost";
    private int port = 11113;

    private String clientJKS = "../../examples/provider/client.jks";
    private String clientPswd = "wolfSSL test";
    private String caJKS = "../../examples/provider/ca-server.jks";
    private String caPswd = "wolfSSL test";

    private SSLContext ctx;
    private SSLEngine engine;
    private DatagramSocket socket;
    private InetSocketAddress serverAddress;

    /* Application and network buffers for data processing */
    private ByteBuffer appOutBuffer;
    private ByteBuffer appInBuffer;
    private ByteBuffer netOutBuffer;
    private ByteBuffer netInBuffer;

    public DtlsClientEngine() {
        /* Default constructor */
    }

    public DtlsClientEngine(String host, int port) {
        this.host = host;
        this.port = port;
    }

    /**
     * Run the DTLS client
     */
    public void run() {
        try {
            /* Register wolfJSSE as first priority provider */
            Security.insertProviderAt(new WolfSSLProvider(), 1);

            /* Create socket and server address */
            socket = new DatagramSocket();
            socket.setSoTimeout(SOCKET_TIMEOUT);

            serverAddress = new InetSocketAddress(host, port);
            System.out.println(
                "Client socket created, connecting to " + host + ":" + port);

            /* Set up SSLContext and SSLEngine */
            setupSSL();

            /* Initialize buffer sizes based on SSLSession */
            SSLSession session = engine.getSession();
            int appBufferSize = session.getApplicationBufferSize();
            int netBufferSize = session.getPacketBufferSize();

            appOutBuffer = ByteBuffer.allocate(appBufferSize);
            appInBuffer = ByteBuffer.allocate(appBufferSize);
            netOutBuffer = ByteBuffer.allocate(netBufferSize);
            netInBuffer = ByteBuffer.allocate(netBufferSize);

            /* Perform handshake */
            doHandshake();

            /* Allow the engine state to stabilize after handshake */
            System.out.println(
                "Pausing after handshake to allow connection to stabilize...");
            try {
                Thread.sleep(1000);  /* 1 second pause */
            } catch (InterruptedException e) {
                /* Ignore interruption */
            }

            /* Send application data */
            String message = "Hello from DTLS 1.3 Client!";
            System.out.println("Sending application data: " + message);
            sendData(message.getBytes());

            /* Allow time for server to process and respond */
            System.out.println(
                "Waiting for server response (allowing time for processing)...");
            try {
                Thread.sleep(2000);  /* 2 second pause */
            } catch (InterruptedException e) {
                /* Ignore interruption */
            }

            /* Receive and process response data */
            System.out.println("Now attempting to receive server response...");
            try {
                /* Receive the application data packet directly */
                byte[] data = new byte[MAX_PACKET_SIZE];
                DatagramPacket packet = new DatagramPacket(data, data.length);

                /* Set timeout for this operation */
                socket.setSoTimeout(10000); /* 10 seconds */
                System.out.println("Waiting for application data packet from server...");
                socket.receive(packet);

                int length = packet.getLength();
                System.out.println("Received packet of " + length + " bytes");

                if (length > 0) {
                    /* Show the raw bytes for debugging */
                    System.out.print("Raw bytes: ");
                    for (int i = 0; i < Math.min(length, 20); i++) {
                        System.out.printf("%02X ", packet.getData()[i] & 0xFF);
                    }
                    System.out.println(length > 20 ? "..." : "");

                    /* Process with SSLEngine */
                    netInBuffer.clear();
                    netInBuffer.put(packet.getData(), 0, length);
                    netInBuffer.flip();

                    appInBuffer.clear();
                    SSLEngineResult result =
                        engine.unwrap(netInBuffer, appInBuffer);
                    System.out.println("Unwrap result: " + result.getStatus() +
                            ", consumed: " + result.bytesConsumed() +
                            ", produced: " + result.bytesProduced());

                    if (result.bytesProduced() > 0) {
                        /* Success! We got application data */
                        appInBuffer.flip();
                        byte[] responseData = new byte[appInBuffer.remaining()];
                        appInBuffer.get(responseData);
                        String responseText = new String(responseData);
                        System.out.println(
                            "Successfully decrypted data: " + responseText);
                    } else {
                        System.out.println(
                            "No application data produced from this packet. " +
                            "Status: " + result.getStatus());

                        /* Try again in case we need another packet */
                        System.out.println(
                            "Attempting to receive another packet...");
                        try {
                            byte[] secondData = new byte[MAX_PACKET_SIZE];
                            DatagramPacket secondPacket =
                                new DatagramPacket(secondData,
                                    secondData.length);
                            socket.setSoTimeout(5000); /* 5 seconds */
                            socket.receive(secondPacket);

                            netInBuffer.clear();
                            netInBuffer.put(secondPacket.getData(), 0,
                                secondPacket.getLength());
                            netInBuffer.flip();

                            appInBuffer.clear();
                            SSLEngineResult secondResult =
                                engine.unwrap(netInBuffer, appInBuffer);
                            System.out.println(
                                "Second unwrap result: " +
                                    secondResult.getStatus() +
                                ", consumed: " + secondResult.bytesConsumed() +
                                ", produced: " + secondResult.bytesProduced());

                            if (secondResult.bytesProduced() > 0) {
                                appInBuffer.flip();
                                byte[] secondResponseData =
                                    new byte[appInBuffer.remaining()];
                                appInBuffer.get(secondResponseData);
                                String secondResponseText =
                                    new String(secondResponseData);
                                System.out.println(
                                    "Successfully decrypted data: " +
                                        secondResponseText);
                            }
                        } catch (SocketTimeoutException e) {
                            System.out.println(
                                "No additional packets received (timeout)");
                        }
                    }
                } else {
                    System.out.println("Empty packet received");
                }

            } catch (Exception e) {
                System.err.println("Error receiving server response: " +
                    e.getMessage());
                e.printStackTrace();
            }

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
        /* Trust manager (certificates) */
        KeyStore cert = KeyStore.getInstance("JKS");
        cert.load(new FileInputStream(caJKS), caPswd.toCharArray());
        TrustManagerFactory tm = TrustManagerFactory.getInstance(
            "SunX509", "wolfJSSE");
        tm.init(cert);

        /* Load private key */
        KeyStore pKey = KeyStore.getInstance("JKS");
        pKey.load(new FileInputStream(clientJKS), clientPswd.toCharArray());
        KeyManagerFactory km = KeyManagerFactory.getInstance(
            "SunX509", "wolfJSSE");
        km.init(pKey, clientPswd.toCharArray());

        /* Create SSLContext configured for DTLS 1.3 */
        ctx = SSLContext.getInstance("DTLSv1.3", "wolfJSSE");
        ctx.init(km.getKeyManagers(), tm.getTrustManagers(), null);

        /* Create SSLEngine */
        engine = ctx.createSSLEngine(host, port);
        engine.setUseClientMode(true);

        /* Enable endpoint identification if available */
        try {
            SSLParameters params = engine.getSSLParameters();
            engine.setSSLParameters(params);
        } catch (Exception e) {
            System.out.println(
                "DEBUG: Exception setting SSL parameters: " + e.getMessage());
        }

        System.out.println("DTLS 1.3 Client Engine created");
    }

    /**
     * Perform the DTLS handshake
     */
    private void doHandshake() throws Exception {
        System.out.println("Starting DTLS handshake...");

        /* Set appropriate timeout for handshake */
        socket.setSoTimeout(SOCKET_TIMEOUT);

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
                case NEED_WRAP:
                    handshakeStatus = handleWrap();
                    break;

                case NEED_UNWRAP:
                    handshakeStatus = handleUnwrap();
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

        /* Process session ticket */
        System.out.println("Processing post-handshake session tickets...");
        try {
            /* Set a timeout for receiving the session ticket */
            socket.setSoTimeout(5000);

            /* Receive the ticket */
            byte[] data = new byte[MAX_PACKET_SIZE];
            DatagramPacket packet = new DatagramPacket(data, data.length);
            socket.receive(packet);

            /* Process the packet - the session ticket */
            if (packet.getLength() > 0) {
                System.out.println("Received post-handshake packet of " +
                                 packet.getLength() + " bytes, processing...");

                /* Process with SSLEngine */
                netInBuffer.clear();
                netInBuffer.put(packet.getData(), 0, packet.getLength());
                netInBuffer.flip();

                appInBuffer.clear();
                SSLEngineResult result = engine.unwrap(netInBuffer, appInBuffer);
                System.out.println("Processed post-handshake packet: " +
                                 result.getStatus() + ", consumed: " +
                                 result.bytesConsumed() + ", produced: " +
                                 result.bytesProduced());
            }
        } catch (SocketTimeoutException e) {
            System.out.println(
                "No post-handshake messages received (timeout)");
        } catch (Exception e) {
            System.out.println(
                "Error processing post-handshake messages: " + e.getMessage());
        }

        /* Add a small delay after handshake to ensure both sides are ready */
        System.out.println("Pausing briefly before sending data...");
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
     * Send application data to the server
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
     * Receive application data from the server
     */
    private byte[] receiveData() throws Exception {
        int attempts = 0;
        int maxAttempts = 10; /* Increase max attempts */
        while (attempts++ < maxAttempts) {  /* Try more times to get data */
            netInBuffer.clear();
            try {
                /* Temporarily increase socket timeout for expected
                 * application data */
                int originalTimeout = socket.getSoTimeout();
                /* Longer timeout for app data - 20 seconds */
                socket.setSoTimeout(20000);

                receivePacket(netInBuffer);

                /* Restore original timeout */
                socket.setSoTimeout(originalTimeout);

                netInBuffer.flip();
                appInBuffer.clear();

                System.out.println("DEBUG: Before unwrap - netInBuffer " +
                    "position: " + netInBuffer.position() + ", limit: " +
                    netInBuffer.limit());

                /* Try again if we have data but unwrap consumes nothing */
                SSLEngineResult result = null;
                try {
                    result = engine.unwrap(netInBuffer, appInBuffer);
                    System.out.println(
                        "DEBUG: Unwrap result: " + result.getStatus() +
                        ", bytesConsumed: " + result.bytesConsumed() +
                        ", bytesProduced: " + result.bytesProduced());

                    /* If nothing was consumed but we have data,
                     * try a different approach */
                    if (result.bytesConsumed() == 0 && netInBuffer.hasRemaining()) {
                        System.out.println("DEBUG: Unwrap consumed 0 bytes, " +
                            "trying a second unwrap operation");

                        /* Try a second unwrap with the same data */
                        try {
                            appInBuffer.clear();
                            SSLEngineResult result2 = engine.unwrap(netInBuffer, appInBuffer);
                            System.out.println(
                                "DEBUG: Second unwrap result: " +
                                    result2.getStatus() +
                                ", bytesConsumed: " + result2.bytesConsumed() +
                                ", bytesProduced: " + result2.bytesProduced());

                            /* If second attempt produced data,
                             * use this result */
                            if (result2.bytesProduced() > 0) {
                                result = result2;
                            } else {
                                /* Otherwise try from scratch with new packet */
                                netInBuffer.clear();
                                continue;
                            }
                        } catch (Exception e) {
                            System.out.println("DEBUG: Exception during " +
                                "second unwrap: " + e.getMessage());
                            /* Continue with a new packet */
                            netInBuffer.clear();
                            continue;
                        }
                    }
                } catch (Exception e) {
                    System.out.println("DEBUG: Exception during unwrap: " +
                        e.getMessage());
                    /* Continue to try again */
                    continue;
                }

                switch (result.getStatus()) {
                    case OK:
                        appInBuffer.flip();
                        int remaining = appInBuffer.remaining();
                        System.out.println("DEBUG: Received " + remaining +
                            " bytes of application data");

                        /* If we got application data, return it */
                        if (remaining > 0) {
                            byte[] data = new byte[remaining];
                            appInBuffer.get(data);
                            return data;
                        } else {
                            /* Otherwise, keep trying to get more packets */
                            System.out.println("DEBUG: Received 0 " +
                                "application bytes, trying again...");
                            continue;
                        }

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
                System.out.println("Socket timeout, retrying... (attempt " +
                    attempts + " of " + maxAttempts + ")");
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

            /* Send the close message to the server */
            sendPacket(netOutBuffer);
        }

        System.out.println("Connection closed");
        socket.close();
    }

    /**
     * Send a packet to the server
     */
    private void sendPacket(ByteBuffer buffer) throws IOException {
        buffer.flip();
        int len = buffer.remaining();
        byte[] data = new byte[len];
        buffer.get(data);

        DatagramPacket packet = new DatagramPacket(data, len, serverAddress);
        socket.send(packet);
        System.out.println("DEBUG: Sent packet with " + len + " bytes to " +
            serverAddress.getAddress() + ":" + serverAddress.getPort());
    }

    /**
     * Receive a packet from the server
     */
    private void receivePacket(ByteBuffer buffer) throws IOException {
        byte[] data = new byte[MAX_PACKET_SIZE];
        DatagramPacket packet = new DatagramPacket(data, data.length);

        try {
            socket.receive(packet);

            int packetLength = packet.getLength();
            System.out.println("DEBUG: Received packet with " + packetLength +
                " bytes from " + packet.getAddress() + ":" + packet.getPort());

            if (packetLength > 0) {
                /* Ensure the packet is from our server */
                if (packet.getAddress().equals(serverAddress.getAddress()) &&
                    packet.getPort() == serverAddress.getPort()) {
                    buffer.put(data, 0, packetLength);
                } else {
                    System.out.println("WARNING: Received packet from " +
                        "unexpected source: " + packet.getAddress() + ":" +
                        packet.getPort() + " (expected: " +
                        serverAddress.getAddress() + ":" +
                        serverAddress.getPort() + ")");
                }
            } else {
                System.out.println("WARNING: Received empty packet!");
            }
        } catch (SocketTimeoutException e) {
            System.out.println("DEBUG: Socket timeout in receivePacket()");
            throw e;  /* Rethrow for proper handling */
        }
    }

    /**
     * Main method, parse cmd line args and run new instance of DtlsClientEngine
     */
    public static void main(String[] args) {
        String host = "localhost";
        int port = 11113;

        /* Parse command line arguments */
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];

            if (arg.equals("-h") && i + 1 < args.length) {
                host = args[++i];
            } else if (arg.equals("-p") && i + 1 < args.length) {
                port = Integer.parseInt(args[++i]);
            } else if (arg.equals("-?")) {
                printUsage();
                return;
            }
        }

        DtlsClientEngine client = new DtlsClientEngine(host, port);
        client.run();
    }

    /**
     * Print usage information
     */
    private static void printUsage() {
        System.out.println("DTLS 1.3 Client Engine Example");
        System.out.println("  -h host   Host to connect to");
        System.out.println("             (default: localhost)");
        System.out.println("  -p port   Port to connect to (default: 11113)");
        System.out.println("  -?        Print this help menu");
    }
}

