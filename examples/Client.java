/* Client.java
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

import java.io.*;
import java.net.*;
import java.nio.*;
import java.nio.charset.Charset;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.CharacterCodingException;

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLSession;
import com.wolfssl.WolfSSLContext;
import com.wolfssl.WolfSSLException;
import com.wolfssl.WolfSSLJNIException;
import com.wolfssl.WolfSSLIOSendCallback;
import com.wolfssl.WolfSSLIORecvCallback;

/* suppress SSLv3 deprecation warnings, meant for end user not examples */
@SuppressWarnings("deprecation")
public class Client {

    public static Charset charset = Charset.forName("UTF-8");
    public static CharsetEncoder encoder = charset.newEncoder();

    public static void main(String[] args) {
        new Client().run(args);
    }

    public void run(String[] args) {

        int ret = 0, input;
        byte[] back = new byte[80];
        String msg  = "hello from jni";
        WolfSSLSession ssl;
        long method = 0;
        Socket sock = null;
        DataOutputStream outstream = null;
        DataInputStream  instream  = null;
        DatagramSocket dsock = null;          /* used with DTLS, if needed */
        InetAddress hostAddr = null;          /* used with DTLS, if needed */

        /* config info */
        boolean useIOCallbacks = false;       /* test I/O callbacks */
        String cipherList = null;             /* default ciphersuite list */
        int sslVersion = 3;                   /* default to TLS 1.2 */
        int verifyPeer = 1;                   /* verify peer by default */
        int benchmark = 0;
        int doDTLS = 0;                       /* don't use DTLS by default */
        int useOcsp = 0;                      /* don't use OCSP by default */
        String ocspUrl = null;                /* OCSP override URL */
        int useAtomic = 0;                    /* atomic record lyr processing */
        int pkCallbacks = 0;                  /* public key callbacks */
        int logCallback = 0;                  /* use test logging callback */
        int usePsk = 0;                       /* use pre shared keys */

        /* cert info */
        String clientCert = "../certs/client-cert.pem";
        String clientKey  = "../certs/client-key.pem";
        String caCert     = "../certs/ca-cert.pem";
        String crlPemDir  = "../certs/crl";

        /* server (peer) info */
        String host = "localhost";
        int port    =  11111;

        try {

            /* load JNI library */
            WolfSSL.loadLibrary();

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
                    sslVersion = Integer.parseInt(args[++i]);
                    if (sslVersion < 0 || sslVersion > 3) {
                        printUsage();
                    }

                } else if (arg.equals("-l")) {
                    if (args.length < i+2)
                        printUsage();
                    cipherList = args[++i];

                } else if (arg.equals("-c")) {
                    if (args.length < i+2)
                        printUsage();
                    clientCert = args[++i];

                } else if (arg.equals("-k")) {
                    if (args.length < i+2)
                        printUsage();
                    clientKey = args[++i];

                } else if (arg.equals("-b")) {
                    if (args.length < i+2)
                      printUsage();
                    benchmark = Integer.parseInt(args[++i]);
                    if (benchmark < 0 || benchmark > 1000000)
                        printUsage();

                } else if (arg.equals("-A")) {
                    if (args.length < i+2)
                        printUsage();
                    caCert = args[++i];

                } else if (arg.equals("-d")) {
                    verifyPeer = 0;

                } else if (arg.equals("-u")) {
                    doDTLS = 1;

                } else if (arg.equals("-s")) {
                    if (WolfSSL.isEnabledPSK() == 0) {
                        System.out.println("PSK support not enabled in " +
                                           "wolfSSL");
                        System.exit(1);
                    }
                    usePsk = 1;

                } else if (arg.equals("-iocb")) {
                    useIOCallbacks = true;

                } else if (arg.equals("-logtest")) {
                    logCallback = 1;

                } else if (arg.equals("-o")) {
                    if (WolfSSL.isEnabledOCSP() == 0) {
                        System.out.println("OCSP support not enabled in " +
                                           "wolfSSL");
                        System.exit(1);
                    }
                    useOcsp = 1;

                } else if (arg.equals("-O")) {
                    if (WolfSSL.isEnabledOCSP() == 0) {
                        System.out.println("OCSP support not enabled in " +
                                           "wolfSSL");
                        System.exit(1);
                    }
                    if (args.length < i+2)
                        printUsage();
                    useOcsp = 1;
                    ocspUrl = args[++i];

                } else if (arg.equals("-U")) {
                    if (WolfSSL.isEnabledAtomicUser() == 0) {
                        System.out.println("Atomic User support not enabled " +
                                           "in wolfSSL");
                        System.exit(1);
                    }
                    useAtomic = 1;

                } else if (arg.equals("-P")) {
                    if (WolfSSL.isEnabledPKCallbacks() == 0) {
                        System.out.println("Public Key callback support not " +
                                           "enabled in wolfSSL");
                        System.exit(1);
                    }
                    pkCallbacks = 1;

                } else {
                    printUsage();
                }
            }

            /* sort out DTLS versus TLS versions */
            if (doDTLS == 1) {
                if (sslVersion == 3)
                    sslVersion = -2;
                else
                    sslVersion = -1;
            }

            /* init library */
            WolfSSL sslLib = new WolfSSL();
            sslLib.debuggingON();

            /* set logging callback */
            if (logCallback == 1) {
                MyLoggingCallback lc = new MyLoggingCallback();
                sslLib.setLoggingCb(lc);
            }

            /* set SSL version method */
            switch (sslVersion) {
                case 0:
                    method = WolfSSL.SSLv3_ClientMethod();
                    break;
                case 1:
                    method = WolfSSL.TLSv1_ClientMethod();
                    break;
                case 2:
                    method = WolfSSL.TLSv1_1_ClientMethod();
                    break;
                case 3:
                    method = WolfSSL.TLSv1_2_ClientMethod();
                    break;
                case -1:
                    method = WolfSSL.DTLSv1_ClientMethod();
                    break;
                case -2:
                    method = WolfSSL.DTLSv1_2_ClientMethod();
                    break;
                default:
                    System.err.println("Bad SSL version");
                    System.exit(1);
            }

            /* create context */
            WolfSSLContext sslCtx = new WolfSSLContext(method);

            /* set up PSK, if being used */
            if (usePsk == 1) {

                MyPskClientCallback pskClientCb = new MyPskClientCallback();
                sslCtx.setPskClientCb(pskClientCb);

            } else {

                /* load certificate files */
                ret = sslCtx.useCertificateFile(clientCert,
                        WolfSSL.SSL_FILETYPE_PEM);
                if (ret != WolfSSL.SSL_SUCCESS) {
                    System.out.println("failed to load client certificate!");
                    System.exit(1);
                }

                ret = sslCtx.usePrivateKeyFile(clientKey,
                        WolfSSL.SSL_FILETYPE_PEM);
                if (ret != WolfSSL.SSL_SUCCESS) {
                    System.out.println("failed to load client private key!");
                    System.exit(1);
                }

                /* set verify callback */
                if (verifyPeer == 0) {
                    sslCtx.setVerify(WolfSSL.SSL_VERIFY_NONE, null);
                } else {
                    ret = sslCtx.loadVerifyLocations(caCert, null);
                    if (ret != WolfSSL.SSL_SUCCESS) {
                        System.out.println("failed to load CA certificates!");
                        System.exit(1);
                    }

                    VerifyCallback vc = new VerifyCallback();
                    sslCtx.setVerify(WolfSSL.SSL_VERIFY_PEER, vc);
                }
            }

            /* set cipher list */
            if (cipherList == null) {
                if (usePsk == 1) {
                    ret = sslCtx.setCipherList("DHE-PSK-AES128-GCM-SHA256");
                }
            } else {
                ret = sslCtx.setCipherList(cipherList);
            }

            if (ret != WolfSSL.SSL_SUCCESS) {
                System.out.println("failed to set cipher list, ret = " + ret);
                System.exit(1);
            }

            /* set OCSP options, override URL */
            if (useOcsp == 1) {

                long ocspOptions = WolfSSL.WOLFSSL_OCSP_NO_NONCE;

                if (ocspUrl != null) {
                    ocspOptions = ocspOptions |
                                  WolfSSL.WOLFSSL_OCSP_URL_OVERRIDE;
                }

                if (ocspUrl != null) {
                    ret = sslCtx.setOCSPOverrideUrl(ocspUrl);

                    if (ret != WolfSSL.SSL_SUCCESS) {
                        System.out.println("failed to set OCSP overrideUrl");
                        System.exit(1);
                    }
                }

                ret = sslCtx.enableOCSP(ocspOptions);
                if (ret != WolfSSL.SSL_SUCCESS) {
                    System.out.println("failed to enable OCSP, ret = "
                            + ret);
                    System.exit(1);
                }
            }

            /* register I/O callbacks, I/O ctx setup is later */
            if (useIOCallbacks || (doDTLS == 1)) {
                MyRecvCallback rcb = new MyRecvCallback();
                MySendCallback scb = new MySendCallback();
                sslCtx.setIORecv(rcb);
                sslCtx.setIOSend(scb);
                System.out.println("Registered I/O callbacks");
            }

            /* register atomic record layer callbacks, ctx setup later */
            if (useAtomic == 1) {
                MyMacEncryptCallback mecb = new MyMacEncryptCallback();
                MyDecryptVerifyCallback dvcb = new MyDecryptVerifyCallback();
                sslCtx.setMacEncryptCb(mecb);
                sslCtx.setDecryptVerifyCb(dvcb);
            }

            /* register public key callbacks, ctx setup is later */
            if (pkCallbacks == 1) {

                /* ECC */
                MyEccSignCallback eccSign = new MyEccSignCallback();
                MyEccVerifyCallback eccVerify = new MyEccVerifyCallback();
                MyEccSharedSecretCallback eccSharedSecret =
                    new MyEccSharedSecretCallback();
                sslCtx.setEccSignCb(eccSign);
                sslCtx.setEccVerifyCb(eccVerify);
                sslCtx.setEccSharedSecretCb(eccSharedSecret);

                /* RSA */
                MyRsaSignCallback rsaSign = new MyRsaSignCallback();
                MyRsaVerifyCallback rsaVerify = new MyRsaVerifyCallback();
                MyRsaEncCallback rsaEnc = new MyRsaEncCallback();
                MyRsaDecCallback rsaDec = new MyRsaDecCallback();
                sslCtx.setRsaSignCb(rsaSign);
                sslCtx.setRsaVerifyCb(rsaVerify);
                sslCtx.setRsaEncCb(rsaEnc);
                sslCtx.setRsaDecCb(rsaDec);
            }

            if (benchmark != 0) {
                int times = benchmark;
                int i = 0;

                long start = System.nanoTime();
                long avg;


                for (i = 0; i < times; i++) {
                    sock = new Socket(host, port);
                   /* System.out.println("Connected to " +
                            sock.getInetAddress().getHostAddress() +
                            " on port " +
                            sock.getPort() + "\n"); */

                    outstream = new DataOutputStream(sock.getOutputStream());
                    instream = new DataInputStream(sock.getInputStream());
                    ssl = new WolfSSLSession(sslCtx);
                    ssl.setFd(sock);
                    ret = ssl.connect();
                    if (ret != WolfSSL.SSL_SUCCESS)
                        System.out.println("ssl.connect failed");

                    ssl.shutdownSSL();
                    ssl.freeSSL();
                    sock.close();
                }
                avg = System.nanoTime() - start;
                avg /= times;
                avg /= 1000000; /*milliseconds*/
                System.out.println("wolfSSL_connect avg took: " + avg +
                        " milliseconds");

                sslCtx.free();
                System.exit(1);
            }
            /* create SSL object */
            ssl = new WolfSSLSession(sslCtx);

            /* enable/load CRL functionality */
            if (WolfSSL.isEnabledCRL() == 1) {
                ret = ssl.enableCRL(WolfSSL.WOLFSSL_CRL_CHECKALL);
                if (ret != WolfSSL.SSL_SUCCESS) {
                    System.out.println("failed to enable CRL check");
                    System.exit(1);
                }
                ret = ssl.loadCRL(crlPemDir, WolfSSL.SSL_FILETYPE_PEM, 0);
                if (ret != WolfSSL.SSL_SUCCESS) {
                    System.out.println("can't load CRL, check CRL file and " +
                            "date validity");
                    System.exit(1);
                }
                MyMissingCRLCallback crlCb = new MyMissingCRLCallback();
                ret = ssl.setCRLCb(crlCb);
                if (ret != WolfSSL.SSL_SUCCESS) {
                    System.out.println("can't set CRL callback");
                    System.exit(1);
                }
            }

            /* open Socket */
            if (doDTLS == 1) {
                dsock = new DatagramSocket();
                hostAddr = InetAddress.getByName(host);
                InetSocketAddress addr = new InetSocketAddress(hostAddr, port);
                ret = ssl.dtlsSetPeer(addr);
                if (ret != WolfSSL.SSL_SUCCESS) {
                    System.out.println("failed to set DTLS peer");
                    System.exit(1);
                }
            } else {
                sock = new Socket(host, port);
                System.out.println("Connected to " +
                        sock.getInetAddress().getHostAddress() +
                        " on port " +
                        sock.getPort() + "\n");

                outstream = new DataOutputStream(sock.getOutputStream());
                instream = new DataInputStream(sock.getInputStream());
            }

            if (useIOCallbacks || (doDTLS == 1)) {
                /* register I/O callback user context */
                MyIOCtx ioctx = new MyIOCtx(outstream, instream, dsock,
                        hostAddr, port);
                ssl.setIOReadCtx(ioctx);
                ssl.setIOWriteCtx(ioctx);
                System.out.println("Registered I/O callback user contexts");

            } else {

                /* if not using DTLS or I/O callbacks, pass Socket
                 * fd to wolfSSL */
                ret = ssl.setFd(sock);

                if (ret != WolfSSL.SSL_SUCCESS) {
                    System.out.println("Failed to set file descriptor");
                    return;
                }
            }

            if (useAtomic == 1) {
                /* register atomic record layer callback user contexts */
                MyAtomicEncCtx encCtx = new MyAtomicEncCtx();
                MyAtomicDecCtx decCtx = new MyAtomicDecCtx();
                ssl.setMacEncryptCtx(encCtx);
                ssl.setDecryptVerifyCtx(decCtx);
            }

            if (pkCallbacks == 1) {
                /* register public key callback user contexts */

                /* ECC */
                MyEccSignCtx eccSignCtx = new MyEccSignCtx();
                MyEccVerifyCtx eccVerifyCtx = new MyEccVerifyCtx();
                MyEccSharedSecretCtx eccSharedSecretCtx =
                    new MyEccSharedSecretCtx();
                ssl.setEccSignCtx(eccSignCtx);
                ssl.setEccVerifyCtx(eccVerifyCtx);
                ssl.setEccSharedSecretCtx(eccSharedSecretCtx);

                /* RSA */
                MyRsaSignCtx rsaSignCtx = new MyRsaSignCtx();
                MyRsaVerifyCtx rsaVerifyCtx = new MyRsaVerifyCtx();
                MyRsaEncCtx rsaEncCtx = new MyRsaEncCtx();
                MyRsaDecCtx rsaDecCtx = new MyRsaDecCtx();
                ssl.setRsaSignCtx(rsaSignCtx);
                ssl.setRsaVerifyCtx(rsaVerifyCtx);
                ssl.setRsaEncCtx(rsaEncCtx);
                ssl.setRsaDecCtx(rsaDecCtx);
            }

            /* call wolfSSL_connect */
            ret = ssl.connect();
            if (ret != WolfSSL.SSL_SUCCESS) {
                int err = ssl.getError(ret);
                String errString = sslLib.getErrorString(err);
                System.out.println("wolfSSL_connect failed. err = " + err +
                        ", " + errString);
                System.exit(1);
            }

            /* show peer info */
            showPeer(ssl);

            /* test write(long, byte[], int) */
            ret = ssl.write(msg.getBytes(), msg.length());

            input = ssl.read(back, back.length);
            if (input > 0) {
                System.out.println("got back: " + new String(back));
            } else {
                System.out.println("read failed");
            }

            /* free resources */
            sslCtx.free();

        } catch (UnsatisfiedLinkError ule) {
            ule.printStackTrace();
        } catch (WolfSSLException wex) {
            wex.printStackTrace();
        } catch (WolfSSLJNIException jex) {
           jex.printStackTrace();
        } catch (CharacterCodingException cce) {
            cce.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

    } /* end run() */

    void showPeer(WolfSSLSession ssl) {

        String altname;

        try {

            long peerCrtPtr = ssl.getPeerCertificate();

            if (peerCrtPtr != 0) {
                System.out.println("issuer : " +
                        ssl.getPeerX509Issuer(peerCrtPtr));
                System.out.println("subject : " +
                        ssl.getPeerX509Subject(peerCrtPtr));

                while( (altname = ssl.getPeerX509AltName(peerCrtPtr)) != null)
                    System.out.println("altname = " + altname);
            }

            System.out.println("SSL version is " + ssl.getVersion());
            System.out.println("SSL cipher suite is " + ssl.cipherGetName());

        } catch (WolfSSLJNIException e) {
            e.printStackTrace();
        }
    }

    void printUsage() {
        System.out.println("Java example client usage:");
        System.out.println("-?\t\tHelp, print this usage");
        System.out.println("-h <host>\tHost to connect to, default 127.0.0.1");
        System.out.println("-p <num>\tPort to connect to, default 11111");
        System.out.println("-v <num>\tSSL version [0-3], SSLv3(0) - " +
                "TLS1.2(3)), default 3");
        System.out.println("-l <str>\tCipher list");
        System.out.println("-c <file>\tCertificate file,\t\tdefault " +
                "../certs/client-cert.pem");
        System.out.println("-k <file>\tKey file,\t\t\tdefault " +
                "../certs/client-key.pem");
        System.out.println("-A <file>\tCertificate Authority file,\tdefault " +
                "../certs/ca-cert.pem");
        System.out.println("-b <num>\tBenchmark <num> connections and print" +
                " stats");
        if (WolfSSL.isEnabledPSK() == 1)
            System.out.println("-s\t\tUse pre shared keys");
        System.out.println("-d\t\tDisable peer checks");
        if (WolfSSL.isEnabledDTLS() == 1)
            System.out.println("-u\t\tUse UDP DTLS, add -v 2 for DTLSv1 " +
                    "(default), -v 3 for DTLSv1.2");
        System.out.println("-iocb\t\tEnable test I/O callbacks");
        System.out.println("-logtest\tEnable test logging callback");
        if (WolfSSL.isEnabledOCSP() == 1) {
            System.out.println("-o\t\tPerform OCSP lookup on peer certificate");
            System.out.println("-O <url>\tPerform OCSP lookup using <url> " +
                    "as responder");
        }
        if (WolfSSL.isEnabledAtomicUser() == 1)
            System.out.println("-U\t\tEnable Atomic User Record Layer Callbacks");
        if (WolfSSL.isEnabledPKCallbacks() == 1)
            System.out.println("-P\t\tPublic Key Callbacks");
        System.exit(1);
    }

} /* end Client */

