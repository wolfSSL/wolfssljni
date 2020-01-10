/* ServerJSSE.java
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
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

import java.io.IOException;
import java.io.FileInputStream;
import java.net.InetAddress;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLContext;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;

import com.wolfssl.WolfSSLException;
import com.wolfssl.provider.jsse.WolfSSLDebug;
import com.wolfssl.provider.jsse.WolfSSLProvider;

public class ServerJSSE {

    public static void main(String[] args) {
        new ServerJSSE().run(args);
    }

    public void run(String[] args) {

        int ret = 0, insz;
        String msg  = "I hear you fa shizzle, from Java!";
        byte[] response = new byte[80];

        /* config info */
        String cipherList = null;             /* default ciphersuite list */
        int sslVersion = 3;                   /* default to TLS 1.2 */
        String version = null;
        boolean verifyPeer = true;            /* verify peer by default */
        boolean useEnvVar  = false;           /* load cert/key from enviornment variable */
        boolean listSuites = false;           /* list all supported cipher suites */
        boolean listEnabledProtocols = false;  /* show enabled protocols */
        boolean putEnabledProtocols  = false;  /* set enabled protocols */

        /* cert info */
        String serverJKS  = "../provider/rsa.jks";
        String caJKS      = "../provider/client.jks";
        String serverPswd = "wolfSSL test";
        String caPswd     = "wolfSSL test";

        /* server (peer) info */
        String host = "localhost";
        int port    =  11111;

        String keyStorePath = null;
        String trustStorePath = null;
        String method = null;

        /* provider for SSLContext, TrustManagerFactory, KeyManagerFactory */
        String ctxProvider = "wolfJSSE";
        String tmfProvider = "wolfJSSE";
        String kmfProvider = "wolfJSSE";

        /* set/get enabled protocols */
        String[] protocols = null;

        try {

            /* load WolfSSLprovider */
            Security.addProvider(new WolfSSLProvider());

            /* pull in command line options from user */
            for (int i = 0; i < args.length; i++)
            {
                String arg = args[i];

                if (arg.equals("-?")) {
                    printUsage();

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
                    } else {
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
                    serverJKS = tmp[0];
                    serverPswd = tmp[1];

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

                } else if (arg.equals("-getp")) {
                    listEnabledProtocols = true;

                } else if (arg.equals("-setp")) {
                    putEnabledProtocols = true;
                    protocols = args[++i].split(" ");
                    sslVersion = -1;

                } else {
                    printUsage();
                }
            }

            /* set SSL version method */
            switch (sslVersion) {
                case -1:
                    version = "TLS";
                    break;
                case 0:
                    version = "SSLv3";
                    break;
                case 1:
                    version = "TLSv1.0";
                    break;
                case 2:
                    version = "TLSv1.1";
                    break;
                case 3:
                    version = "TLSv1.2";
                    break;
                case 4:
                    version = "TLSv1.3";
                    break;
                default:
                    System.err.println("Unsupported SSL version");
                    System.exit(1);
            }

            /* set up keystore and truststore */
            KeyStore keystore = KeyStore.getInstance("JKS");
            keystore.load(new FileInputStream(serverJKS),
                serverPswd.toCharArray());
            KeyStore truststore = KeyStore.getInstance("JKS");
            truststore.load(new FileInputStream(caJKS), caPswd.toCharArray());
            TrustManagerFactory tm =
                TrustManagerFactory.getInstance("SunX509", tmfProvider);
            tm.init(truststore);
            KeyManagerFactory km =
                KeyManagerFactory.getInstance("SunX509", kmfProvider);
            km.init(keystore, serverPswd.toCharArray());

            /* create context */
            SSLContext ctx = SSLContext.getInstance(version, ctxProvider);
            ctx.init(km.getKeyManagers(), tm.getTrustManagers(), null);

            /* print suites if requested */
            if (listSuites) {
                String[] suites = ctx.getDefaultSSLParameters().
                    getCipherSuites();
                for (String x : suites) {
                    System.out.println("\t" + x);
                }
                return;
            }

            SSLServerSocket ss = (SSLServerSocket)ctx.
                getServerSocketFactory().createServerSocket(port);

            /* print enabled protocols if requested */
            if (listEnabledProtocols) {
                String[] prtolists = ss.getEnabledProtocols();
                for (String str : prtolists) {
                    System.out.println("\t" + str);
                }
                return;
            }

            /* put enabled protocols if requested */
            if (putEnabledProtocols) {
                if (protocols != null)
                    ss.setEnabledProtocols(protocols);
            }

            System.out.printf("Using SSLContext provider %s\n",
                ctx.getProvider().getName());

            if (verifyPeer == false) {
                ss.setNeedClientAuth(false);
                ss.setWantClientAuth(false);
            } else {
                ss.setNeedClientAuth(true);
            }

            if (cipherList != null) {
                String[] suites = cipherList.split(":");
                ss.setEnabledCipherSuites(suites);
            }

            InetAddress hostAddress = InetAddress.getLocalHost();
            System.out.println("Started server at " + hostAddress +
                    ", port " + port);

            /* wait for new client connections, then process */
            while (true) {

                System.out.println("\nwaiting for client connection...");
                SSLSocket sock = (SSLSocket)ss.accept();
                sock.startHandshake();
                showPeer(sock);

                sock.getInputStream().read(response);
                System.out.println("Client message : " + new String(response));
                sock.getOutputStream().write(msg.getBytes());

                sock.close();
            }

        } catch (Exception e) {
            e.printStackTrace();
        }

    } /* end run() */

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

    private void printUsage() {
        System.out.println("Java wolfJSSE example server usage:");
        System.out.println("-?\t\tHelp, print this usage");
        System.out.println("-p <num>\tPort to accept on, default 11111");
        System.out.println("-v <num>\tSSL version [0-4], SSLv3(0) - " +
                           "TLS1.3(4)), default 3 : use 'd' for downgrade");
        System.out.println("-l <str>\tCipher list");
        System.out.println("-d\t\tDisable peer checks");
        System.out.println("-e\t\tGet all supported cipher suites");
        System.out.println("-getp\t\tGet enabled protocols");
        System.out.println("-setp <protocols> \tSet enabled protocols " +
                           "e.g \"TLSv1.1 TLSv1.2\"");
        System.out.println("-c <file>:<password>\tCertificate/key JKS,\t\tdefault " +
                "../provider/rsa.jks:wolfSSL test");
        System.out.println("-A <file>:<password>\tCertificate/key CA JKS file,\tdefault " +
                "../provider/cacerts.jks:wolfSSL test");
        System.exit(1);
    }

} /* end Server */

