/* SimpleThreadedServer.java
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

import java.io.*;
import java.net.*;
import java.nio.*;
import java.util.*;

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLSession;
import com.wolfssl.WolfSSLContext;
import com.wolfssl.WolfSSLCertificate;
import com.wolfssl.WolfSSLException;
import com.wolfssl.WolfSSLJNIException;

/**
 * Simple SSL/TLS server that uses wolfSSL JNI (not JSSE).
 * The server listens for client connections at localhost:11111 and
 * handles each client in a separate thread as they come in.
 *
 * This is meant to be a very simple example and does not currently offer
 * much customization. It uses the hard-coded certs and keys found below,
 * and creates the WolfSSLContext using SSLv23_ServerMethod().
 */
public class SimpleThreadedServer {

    public static void main(String[] args) {
        new SimpleThreadedServer().run(args);
    }

    public void run(String[] args) {

        int ret = 0;
        int serverPort = 11111;
        Socket clientSocket = null;
        ServerSocket serverSocket = null;

        /* Cert and Key info */
        String serverCert = "../certs/server-cert.pem";
        String serverKey  = "../certs/server-key.pem";
        String caCert     = "../certs/client-cert.pem";
        String crlPemDir  = "../certs/crl";
        String dhParam    = "../certs/dh2048.pem";

        try {
            /* Load JNI library */
            WolfSSL.loadLibrary();

            /* Init library */
            WolfSSL sslLib = new WolfSSL();

            /* Create context */
            WolfSSLContext sslCtx = new WolfSSLContext(
                WolfSSL.SSLv23_ServerMethod());

            /* Load certificate/key files */
            ret = sslCtx.useCertificateChainFile(serverCert);
            if (ret != WolfSSL.SSL_SUCCESS) {
                System.out.println("failed to load server certificate!");
                System.exit(1);
            }

            ret = sslCtx.usePrivateKeyFile(serverKey,
                    WolfSSL.SSL_FILETYPE_PEM);
            if (ret != WolfSSL.SSL_SUCCESS) {
                System.out.println("failed to load server private key!");
                System.exit(1);
            }

            /* Set verify callback */
            ret = sslCtx.loadVerifyLocations(caCert, null);
            if (ret != WolfSSL.SSL_SUCCESS) {
                System.out.println("failed to load CA certificates!");
                System.exit(1);
            }

            /* Create server socket */
            serverSocket = new ServerSocket(serverPort);

            System.out.println("Started server at " +
                InetAddress.getLocalHost() + ", port " + serverPort);

            /* Wait for new client connections, process each in new thread */
            while (true) {

                clientSocket = serverSocket.accept();
                System.out.println("client connection received from " +
                        clientSocket.getInetAddress().getHostAddress() +
                        " at port " + clientSocket.getLocalPort() + "\n");

                ClientHandler client = new ClientHandler(clientSocket, sslCtx);
                client.start();
            }

        } catch (UnsatisfiedLinkError | WolfSSLException | IOException e) {
            e.printStackTrace();

        } finally {
            try {
                if (serverSocket != null) {
                    serverSocket.close();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

    } /* end run() */

    class ClientHandler extends Thread
    {
        int ret = 0;
        int insz = 0;
        int err = 0;
        Socket clientSocket;
        WolfSSLContext sslCtx;
        String msg  = "I hear you fa shizzle, from Java!";
        byte[] input = new byte[80];

        public ClientHandler(Socket s, WolfSSLContext ctx) {
            clientSocket = s;
            sslCtx = ctx;
        }

        public void run() {

            WolfSSLSession ssl = null;
            DataOutputStream outstream = null;
            DataInputStream  instream  = null;

            try {
                /* Get input and output streams */
                outstream = new DataOutputStream(
                    clientSocket.getOutputStream());
                instream = new DataInputStream(
                    clientSocket.getInputStream());

                /* Create SSL object */
                ssl = new WolfSSLSession(sslCtx);

                /* Pass socket fd to wolfSSL */
                ret = ssl.setFd(clientSocket);
                if (ret != WolfSSL.SSL_SUCCESS) {
                    throw new RuntimeException("Failed to set file descriptor");
                }

                do {
                    ret = ssl.accept();
                    err = ssl.getError(ret);

                } while (ret != WolfSSL.SSL_SUCCESS &&
                         (err == WolfSSL.SSL_ERROR_WANT_READ ||
                          err == WolfSSL.SSL_ERROR_WANT_WRITE));

                if (ret != WolfSSL.SSL_SUCCESS) {
                    err = ssl.getError(ret);
                    String errString = WolfSSL.getErrorString(err);
                    throw new RuntimeException(
                        "wolfSSL_accept failed. err = " + err +
                        ", " + errString);
                }

                /* Show peer info */
                showPeer(ssl);

                /* Read client response, and echo */
                do {
                    insz = ssl.read(input, input.length);
                    err = ssl.getError(0);
                } while (insz < 0 &&
                         (err == WolfSSL.SSL_ERROR_WANT_READ ||
                          err == WolfSSL.SSL_ERROR_WANT_WRITE));

                if (input.length > 0) {
                    String cliMsg = new String(input, 0, insz);
                    System.out.println("client says: " + cliMsg);
                } else {
                    throw new RuntimeException("read failed");
                }

                do {
                    ret = ssl.write(msg.getBytes(), msg.length());
                    err = ssl.getError(0);
                } while (ret < 0 &&
                         (err == WolfSSL.SSL_ERROR_WANT_READ ||
                          err == WolfSSL.SSL_ERROR_WANT_WRITE));

                if (ret != msg.length()) {
                    throw new RuntimeException("ssl.write() failed");
                }

                ssl.shutdownSSL();

            } catch (WolfSSLException | IOException e) {
                e.printStackTrace();

            } finally {
                if (ssl != null) {
                    try {
                        ssl.freeSSL();
                    } catch (WolfSSLJNIException e) {
                        e.printStackTrace();
                    }
                }
            }
        }
    }

    void showPeer(WolfSSLSession ssl) {

        String altname;
        long peerCrtPtr = 0;

        try {

            System.out.println("TLS version is " + ssl.getVersion());
            System.out.println("TLS cipher suite is " + ssl.cipherGetName());

            peerCrtPtr = ssl.getPeerCertificate();
            if (peerCrtPtr != 0) {
                System.out.println(
                    "issuer : " + ssl.getPeerX509Issuer(peerCrtPtr));
                System.out.println(
                    "subject : " + ssl.getPeerX509Subject(peerCrtPtr));

                while((altname = ssl.getPeerX509AltName(peerCrtPtr)) != null) {
                    System.out.println("altname = " + altname);
                }
            }

        } catch (WolfSSLJNIException e) {
            e.printStackTrace();

        } finally {
            if (WolfSSL.getLibVersionHex() >= 0x05003000) {
                if (peerCrtPtr != 0) {
                    WolfSSLCertificate.freeX509(peerCrtPtr);
                }
            }
        }
    }

} /* end Server */

