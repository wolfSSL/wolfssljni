/* ClientJSSE.java
 *
 * Copyright (C) 2006-2019 wolfSSL Inc.
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

import static org.junit.Assert.assertEquals;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

import java.security.Provider;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;

import com.wolfssl.provider.jsse.WolfSSLDebug;
import com.wolfssl.provider.jsse.WolfSSLProvider;
import com.wolfssl.WolfSSL;
import java.security.PrivateKey;
import java.security.Security;
import javax.net.ssl.KeyManager;
import javax.net.ssl.X509KeyManager;
import java.security.cert.X509Certificate;
import java.security.cert.Certificate;

public class ClientJSSE {
    public ClientJSSE() {
    }

    public void run(String[] args) throws Exception {
        int ret = 0, input;
        byte[] back = new byte[80];
        String msg  = "Too legit to quit";
        String provider = "wolfJSSE";

        KeyStore pKey, cert;
        TrustManagerFactory tm = null;
        KeyManagerFactory km = null;
        ServerSocketFactory srv;
        ServerSocket tls;
        SSLContext ctx;

        /* config info */
        String cipherList = null;             /* default ciphersuite list */
        int sslVersion = 3;                   /* default to TLS 1.2 */
        boolean verifyPeer = true;            /* verify peer by default */
        boolean useEnvVar  = false;           /* load cert/key from enviornment variable */
        boolean listSuites = false;           /* list all supported cipher suites */

        /* cert info */
        String clientJKS  = "../provider/rsa.jks";
        String caJKS      = "../provider/cacerts.jks";
        String clientPswd = "wolfSSL test";
        String caPswd = "wolfSSL test";

        /* server (peer) info */
        String host = "localhost";
        int port    =  11111;

        /* pull in command line options from user */
        for (int i = 0; i < args.length; i++)
        {
            String arg = args[i];

            if (arg.equals("-?")) {
                printUsage();

            } else if (arg.equals("-h")) {
                if (args.length < i+2)
                    printUsage();
                host = args[++i];

            } else if (arg.equals("-p")) {
                if (args.length < i+2)
                    printUsage();
                port = Integer.parseInt(args[++i]);

            } else if (arg.equals("-v")) {
                if (args.length < i+2)
                    printUsage();
                if (args[i+1].equals("d")) {
                    i++;
                    sslVersion = -1;
                }
                else {
                    sslVersion = Integer.parseInt(args[++i]);
                    if (sslVersion < 0 || sslVersion > 4) {
                        printUsage();
                    }
                }

            } else if (arg.equals("-l")) {
                if (args.length < i+2)
                    printUsage();
                cipherList = args[++i];

            } else if (arg.equals("-c")) {
                if (args.length < i+2) {
                    printUsage();
                }
                String[] tmp = args[++i].split(":");
                if (tmp.length != 2) {
                    printUsage();
                }
                clientJKS = tmp[0];
                clientPswd = tmp[1];

            } else if (arg.equals("-A")) {
                if (args.length < i+2)
                    printUsage();
                String[] tmp = args[++i].split(":");
                if (tmp.length != 2) {
                    printUsage();
                }
                caJKS = tmp[0];
                caPswd = tmp[1];

            } else if (arg.equals("-d")) {
                verifyPeer = false;

            } else if (arg.equals("-e")) {
                listSuites = true;

            } else if (arg.equals("-env")) {
                useEnvVar = true;

            } else {
                printUsage();
            }
        }

        switch (sslVersion) {
            case -1: ctx = SSLContext.getInstance("TLS", provider); break;
            case 0: ctx = SSLContext.getInstance("SSLv3", provider); break;
            case 1: ctx = SSLContext.getInstance("TLSv1", provider); break;
            case 2: ctx = SSLContext.getInstance("TLSv1.1", provider); break;
            case 3: ctx = SSLContext.getInstance("TLSv1.2", provider); break;
            case 4: ctx = SSLContext.getInstance("TLSv1.3", provider); break;
            default:
                printUsage();
                return;
        }

        /* trust manager (certificates) */
        cert = KeyStore.getInstance("JKS");
        cert.load(new FileInputStream(caJKS), caPswd.toCharArray());
        tm = TrustManagerFactory.getInstance("SunX509", provider);
        tm.init(cert);

        /* load private key */
        pKey = KeyStore.getInstance("JKS");
        pKey.load(new FileInputStream(clientJKS), clientPswd.toCharArray());
        km = KeyManagerFactory.getInstance("SunX509", provider);
        km.init(pKey, clientPswd.toCharArray());

        /* setup context with certificate and private key */
        ctx.init(km.getKeyManagers(), tm.getTrustManagers(), null);

        if (listSuites) {
            String[] suites = ctx.getDefaultSSLParameters().getCipherSuites();
            for (String x : suites) {
                System.out.println("\t" + x);
            }
            return;
        }

        System.out.printf("Using SSLContext provider %s\n", ctx.getProvider().
                getName());
        SocketFactory sf = ctx.getSocketFactory();
        SSLSocket sock = (SSLSocket)sf.createSocket(host, port);

        if (!verifyPeer) {
            sock.setNeedClientAuth(false);
        }

        if (cipherList != null) {
            sock.setEnabledCipherSuites(cipherList.split(":"));
        }

        sock.startHandshake();
        showPeer(sock);
        sock.getOutputStream().write(msg.getBytes());
        sock.getInputStream().read(back);
        System.out.println("Server message : " + new String(back));
        sock.close();
    }

    private void showPeer(SSLSocket sock) {
        SSLSession session = sock.getSession();
        System.out.println("SSL version is " + session.getProtocol());
        System.out.println("SSL cipher suite is " + session.getCipherSuite());
        if (WolfSSLDebug.DEBUG) {
            try {
                Certificate[] certs = session.getPeerCertificates();
                if (certs.length > 0) {
                    System.out.println(((X509Certificate)certs[0]).toString());
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public static void main(String[] args) {
        WolfSSL.loadLibrary();
        Security.addProvider(new WolfSSLProvider());

        ClientJSSE client = new ClientJSSE();
        try {
            client.run(args);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    private void printUsage() {
        System.out.println("Java wolfJSSE example client usage:");
        System.out.println("-?\t\tHelp, print this usage");
        System.out.println("-h <host>\tHost to connect to, default 127.0.0.1");
        System.out.println("-p <num>\tPort to connect to, default 11111");
        System.out.println("-v <num>\tSSL version [0-4], SSLv3(0) - " +
                           "TLS1.3(4)), default 3 : use 'd' for downgrade");
        System.out.println("-l <str>\tCipher list");
        System.out.println("-d\t\tDisable peer checks");
        System.out.println("-e\t\tGet all supported cipher suites");
        System.out.println("-c <file>:<password>\tCertificate/key JKS,\t\tdefault " +
                "../provider/rsa.jks:wolfSSL test");
        System.out.println("-A <file>:<password>\tCertificate/key CA JKS file,\tdefault " +
                "../provider/cacerts.jks:wolfSSL test");
        System.exit(1);
    }
}
