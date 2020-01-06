/* Server.java
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
public class Server {

    public static Charset charset = Charset.forName("UTF-8");
    public static CharsetEncoder encoder = charset.newEncoder();

    public static void main(String[] args) {
        new Server().run(args);
    }

    public void run(String[] args) {

        Socket clientSocket           = null;
        ServerSocket serverSocket     = null;
        DatagramSocket d_serverSocket = null;
        DataOutputStream outstream    = null;
        DataInputStream  instream     = null;

        int ret = 0, insz;
        String msg  = "I hear you fa shizzle, from Java!";
        byte[] input = new byte[80];
        long method = 0;

        /* config info */
        boolean useIOCallbacks = false;      /* test I/O callbacks */
        String cipherList = null;            /* default cipher suite list */
        int sslVersion = 3;                  /* default to TLS 1.2 */
        int verifyPeer = 1;                  /* verify peer by default */
        int doDTLS = 0;                      /* don't use DTLS by default */
        int useOcsp = 0;                     /* don't use OCSP by default */
        String ocspUrl = null;               /* OCSP override URL */
        int useAtomic = 0;                   /* atomic record lyr processing */
        int pkCallbacks = 0;                 /* public key callbacks */
        int logCallback = 0;                 /* test logging callback */
        int crlDirMonitor = 0;               /* enable CRL monitor */
        int usePsk = 0;                      /* use pre shared keys */
        int needDH = 0;                      /* toggle for loading DH params */
        int sendPskIdentityHint = 1;         /* toggle sending PSK ident hint */

        /* cert info */
        String serverCert = "../certs/server-cert.pem";
        String serverKey  = "../certs/server-key.pem";
        String caCert     = "../certs/client-cert.pem";
        String crlPemDir  = "../certs/crl";
        String dhParam    = "../certs/dh2048.pem";

        /* server info */
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
                    serverCert = args[++i];

                } else if (arg.equals("-k")) {
                    if (args.length < i+2)
                        printUsage();
                    serverKey = args[++i];

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
                    ocspUrl = args[i++];

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

                } else if (arg.equals("-m")) {
                    if (WolfSSL.isEnabledCRLMonitor() == 0) {
                        System.out.println("CRL monitor support not enabled " +
                                           "in wolfSSL");
                        System.exit(1);
                    }
                    crlDirMonitor = 1;

                } else if (arg.equals("-I")) {
                    if (WolfSSL.isEnabledPSK() == 0) {
                        System.out.println("PSK support not enabled in " +
                                           "wolfSSL");
                        System.exit(1);
                    }
                    sendPskIdentityHint = 0;

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
                    method = WolfSSL.SSLv3_ServerMethod();
                    break;
                case 1:
                    method = WolfSSL.TLSv1_ServerMethod();
                    break;
                case 2:
                    method = WolfSSL.TLSv1_1_ServerMethod();
                    break;
                case 3:
                    method = WolfSSL.TLSv1_2_ServerMethod();
                    break;
                case -1:
                    method = WolfSSL.DTLSv1_ServerMethod();
                    break;
                case -2:
                    method = WolfSSL.DTLSv1_2_ServerMethod();
                    break;
                default:
                    System.err.println("Bad SSL version");
                    System.exit(1);
            }

            /* create context */
            WolfSSLContext sslCtx = new WolfSSLContext(method);

            if (usePsk == 1) {

                MyPskServerCallback pskServerCb = new MyPskServerCallback();
                sslCtx.setPskServerCb(pskServerCb);
                if (sendPskIdentityHint == 1) {
                    ret = sslCtx.usePskIdentityHint("cyassl server");
                    if (ret != WolfSSL.SSL_SUCCESS) {
                        System.out.println("Error setting PSK Identity Hint");
                        System.exit(1);
                    }
                }

            } else {

                /* load certificate/key files */
                ret = sslCtx.useCertificateFile(serverCert,
                        WolfSSL.SSL_FILETYPE_PEM);
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
                if (usePsk == 1)
                    ret = sslCtx.setCipherList("DHE-PSK-AES128-GCM-SHA256");
                    needDH = 1;
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

                /* register DTLS cookie generation callback */
                if (doDTLS == 1) {
                    MyGenCookieCallback gccb = new MyGenCookieCallback();
                    sslCtx.setGenCookie(gccb);
                    System.out.println("Registered DTLS cookie callback");
                }
            }

            /* register atomic record layer callbacks, ctx setup later */
            if (useAtomic == 1) {
                MyMacEncryptCallback mecb = new MyMacEncryptCallback();
                MyDecryptVerifyCallback dvcb =
                    new MyDecryptVerifyCallback();
                sslCtx.setMacEncryptCb(mecb);
                sslCtx.setDecryptVerifyCb(dvcb);
            }

            /* register public key callbacks, ctx setup later */
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

            /* create server socket, later if DTLS */
            if (doDTLS == 0) {
                serverSocket = new ServerSocket(port);
            }

            InetAddress hostAddress = InetAddress.getLocalHost();
            System.out.println("Started server at " + hostAddress +
                    ", port " + port);

            /* wait for new client connections, then process */
            while (true) {

                System.out.println("\nwaiting for client connection...");
                if (doDTLS == 1) {
                    byte[] buf = new byte[1500];
                    d_serverSocket = new DatagramSocket(port);
                    DatagramPacket dp = new DatagramPacket(buf, buf.length);
                    d_serverSocket.setSoTimeout(0);
                    d_serverSocket.receive(dp);
                    d_serverSocket.connect(dp.getAddress(), dp.getPort());
                    System.out.println("client connection received from " +
                            dp.getAddress() + " at port " + dp.getPort() +
                            "\n");
                } else {
                    clientSocket = serverSocket.accept();

                    /* get input and output streams */
                    outstream =
                        new DataOutputStream(clientSocket.getOutputStream());
                    instream =
                        new DataInputStream(clientSocket.getInputStream());
                    System.out.println("client connection received from " +
                            clientSocket.getInetAddress().getHostAddress() +
                            " at port " + clientSocket.getLocalPort() + "\n");
                }

                /* create SSL object */
                WolfSSLSession ssl = new WolfSSLSession(sslCtx);

                if (usePsk == 0 || cipherList != null || needDH == 1) {
                    ret = ssl.setTmpDHFile(dhParam, WolfSSL.SSL_FILETYPE_PEM);
                    if (ret != WolfSSL.SSL_SUCCESS) {
                        System.out.println("failed to set DH file, ret = " +
                                ret);
                        System.exit(1);
                    }
                }

                /* enable/load CRL functionality */
                if (WolfSSL.isEnabledCRL() == 1) {
                    ret = ssl.enableCRL(0);
                    if (ret != WolfSSL.SSL_SUCCESS) {
                        System.out.println("failed to enable CRL, ret = "
                                + ret);
                        System.exit(1);
                    }
                    if (crlDirMonitor == 1) {
                        ret = ssl.loadCRL(crlPemDir, WolfSSL.SSL_FILETYPE_PEM,
                                (WolfSSL.WOLFSSL_CRL_MONITOR |
                                WolfSSL.WOLFSSL_CRL_START_MON));
                        if (ret == WolfSSL.MONITOR_RUNNING_E) {
                            System.out.println("CRL monitor already running, " +
                                    "continuing");
                        } else if (ret != WolfSSL.SSL_SUCCESS) {
                            System.out.println("failed to start CRL monitor, ret = "
                                    + ret);
                            System.exit(1);
                        }
                    } else {
                        ret = ssl.loadCRL(crlPemDir, WolfSSL.SSL_FILETYPE_PEM, 0);
                        if (ret != WolfSSL.SSL_SUCCESS) {
                            System.out.println("failed to load CRL, ret = " + ret);
                            System.exit(1);
                        }
                    }

                    MyMissingCRLCallback crlCb = new MyMissingCRLCallback();
                    ret = ssl.setCRLCb(crlCb);
                    if (ret != WolfSSL.SSL_SUCCESS) {
                        System.out.println("failed to set CRL callback, ret = "
                                + ret);
                        System.exit(1);
                    }
                }

                if (useIOCallbacks || (doDTLS == 1)) {
                    /* register I/O callback user context */
                    MyIOCtx ioctx = new MyIOCtx(outstream, instream,
                            d_serverSocket, hostAddress, port);
                    ssl.setIOReadCtx(ioctx);
                    ssl.setIOWriteCtx(ioctx);
                    System.out.println("Registered I/O callback user ctx");

                    /* register DTLS cookie generation callback */
                    if (doDTLS == 1) {
                        MyGenCookieCtx gctx = new MyGenCookieCtx(
                                hostAddress, port);
                        ssl.setGenCookieCtx(gctx);
                        System.out.println("Registered DTLS cookie " +
                                           "callback ctx");
                    }

                } else {
                    /* if not using DTLS or I/O callbacks, pass Socket
                     * fd to wolfSSL */
                     ret = ssl.setFd(clientSocket);

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

                ret = ssl.accept();
                if (ret != WolfSSL.SSL_SUCCESS) {
                    int err = ssl.getError(ret);
                    String errString = sslLib.getErrorString(err);
                    System.out.println("wolfSSL_accept failed. err = " + err +
                            ", " + errString);
                    System.exit(1);
                }

                /* show peer info */
                showPeer(ssl);

                /* read client response, and echo */
                insz = ssl.read(input, input.length);
                if (input.length > 0) {
                    String cliMsg = new String(input, 0, insz);
                    System.out.println("client says: " + cliMsg);
                } else {
                    System.out.println("read failed");
                }

                ret = ssl.write(msg.getBytes(), msg.length());
                if (ret != msg.length()) {
                    System.out.println("ssl.write() failed");
                    System.exit(1);
                }

                ssl.shutdownSSL();
                ssl.freeSSL();

                if (doDTLS == 1) {
                    d_serverSocket.disconnect();
                    d_serverSocket.close();
                }
            }
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
        long peerCrtPtr;

        try {

            peerCrtPtr = ssl.getPeerCertificate();

            if (peerCrtPtr != 0) {

                System.out.println("issuer : " +
                        ssl.getPeerX509Issuer(peerCrtPtr));
                System.out.println("subject : " +
                        ssl.getPeerX509Subject(peerCrtPtr));

                while( (altname = ssl.getPeerX509AltName(peerCrtPtr)) != null)
                    System.out.println("altname = " + altname);

            } else {
                System.out.println("peer has no cert!\n");
            }

            System.out.println("SSL version is " + ssl.getVersion());
            System.out.println("SSL cipher suite is " + ssl.cipherGetName());

        } catch (WolfSSLJNIException e) {
            e.printStackTrace();
        }
    }

    void printUsage() {

        System.out.println("Java example server usage:");
        System.out.println("-?\t\tHelp, print this usage");
        System.out.println("-p <num>\tPort to connect to, default 11111");
        System.out.println("-v <num>\tSSL version [0-3], SSLv3(0) - " +
                "TLS1.2(3)), default 3");
        System.out.println("-l <str>\tCipher list");
        System.out.println("-c <file>\tCertificate file,\t\tdefault " +
                "../certs/client-cert.pem");
        System.out.println("-k <file>\tKey file,\t\t\tdefault " +
                "../certs/client-key.pem");
        System.out.println("-A <file>\tCertificate Authority file,\tdefault " +
                "../certs/client-cert.pem");
        System.out.println("-d\t\tDisable peer checks");
        if (WolfSSL.isEnabledPSK() == 1)
            System.out.println("-s\t\tUse pre shared keys");
        if (WolfSSL.isEnabledDTLS() == 1)
            System.out.println("-u\t\tUse UDP DTLS, add -v 2 for DTLSv1 (default)" +
                ", -v 3 for DTLSv1.2");
        System.out.println("-iocb\t\tEnable test I/O callbacks");
        System.out.println("-logtest\tEnable test logging callback");
        if (WolfSSL.isEnabledOCSP() == 1) {
            System.out.println("-o\t\tPerform OCSP lookup on peer certificate");
            System.out.println("-O <url>\tPerform OCSP lookup using <url> " +
                    "as responder");
        }
        if (WolfSSL.isEnabledAtomicUser() == 1)
            System.out.println("-U\t\tAtomic User Record Layer Callbacks");
        if (WolfSSL.isEnabledPKCallbacks() == 1)
            System.out.println("-P\t\tPublic Key Callbacks");
        if (WolfSSL.isEnabledCRLMonitor() == 1)
            System.out.println("-m\t\tEnable CRL directory monitor");
        System.exit(1);
    }

} /* end Server */

