/* SimpleThreadedServer.java
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

import java.io.IOException;
import java.net.Socket;
import java.net.ServerSocket;
import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.LinkedHashMap;
import java.util.Iterator;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicIntegerArray;

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLContext;
import com.wolfssl.WolfSSLSession;
import com.wolfssl.WolfSSLJNIException;

/**
 * This is a simple example of a launching multiple client threads
 * connecting to the same server, while attemping to do session resumption
 * where possible. Client threads are started and sleep a random
 * value between 0 and 1 second so they are not all running at exactly the same
 * time. This behavior more closely mimics real world application use.
 *
 * A application-wide static client session cache is implemented here as
 * a LinkedHashMap. This is used to store WOLFSSL_SESSION pointer (long)
 * values obtained from getSession(), and used again with setSession().
 *
 * This is meant to be a simple usage example, so there is not much
 * customization currently from the command line. Certs and keys are hard
 * coded to the values in class variables below. 
 *
 * Client threads make SSL/TLS connections to localhost:11111, using the
 * SSLv23_ClientMethod() during creation of the WolfSSLContext.
 *
 * This example has been designed to connect against the SimpleThreadedServer
 * example in the same directory:
 *
 *     cd wolfssljni
 *     ./examples/SimpleThreadedServer.sh
 *
 *     ./examples/SimpleThreadedClient -n 10
 *
 */
public class SimpleThreadedClient {

    /* Cert and key info */
    private String clientCert = "../certs/client-cert.pem";
    private String clientKey  = "../certs/client-key.pem";
    private String caCert     = "../certs/ca-cert.pem";
    private String crlPemDir  = "../certs/crl";

    /* Server info */
    int serverPort = 11111;

    /* Number of client threads to start connecting to server,
     * can be changed using the -n command line argument. */
    int numConnections = 5;

    /* Keep track of connection count that is resumed vs full */
    final AtomicIntegerArray connectionsResumed = new AtomicIntegerArray(1);
    final AtomicIntegerArray connectionsFull = new AtomicIntegerArray(1);

    /* Client session store:
     *     Key: hash of host:port
     *     Value: pointer (long) to WOLFSSL_SESSION
     *     Default size: 33 sessions (defaultCacheSize)
     *
     * This is a Java session store to store WOLFSSL_SESSION pointers
     * to be used with setSession(). Pointers will have been obtained
     * with a call to getSession().
     *
     * Since the TLS 1.3 binder changes on each session connection, each entry
     * should only be re-used by one thread/connection resumption at a time.
     * We remove the session from the cache, try to resume it, and after
     * a new successful connection put it back in the cache. This does mean
     * that parallel concurrent client connections to the same host may not
     * have all connections resume. Only the first thread to grab the session
     * from the cache will potentially do a resumed session. Others will fall
     * back to a new full handshake.
     *
     * Access to the session store should be synchronized on storeLock.
     */
    private int defaultCacheSize = 33;
    protected SessionStore<Integer, Long> store =
        new SessionStore<>(defaultCacheSize);
    private static final Object storeLock = new Object();

    /**
     * Inner SessionStore class, used for client session store.
     */
    private class SessionStore<K, V> extends LinkedHashMap<K, V> {
        /* User defined ID */
        private static final long serialVersionUID = 1L;

        /* Max LinkedHashMap size, before purging entries */
        private final int maxSz;

        /**
         * Create new SessionStore.
         * @param size max size of LinkedHashMap before oldest entry is
         *        overwritten
         */
        protected SessionStore(int size) {
            this.maxSz = size;
        }

        protected boolean removeEldestEntry(Map.Entry<K, V> oldest) {
            return size() > maxSz;
        }
    }

    /**
     * Try to get a saved session (WOLFSSL_SESSION) from the client
     * session cache. Sessions are keyed off the hash code of
     * host+port. In production applications consder also keying off
     * cipher suite and protocol version.
     *
     * @param port port number of peer being connected to
     * @param host host of the peer being connected to
     * @return an existing pointer (long) to a WOLFSSL_SESSION structure,
     *         removing it from the client cache so other threads do not try
     *         to resume it at the same time. Or, 0 if no session is found in
     *         cache.
     */
    private synchronized long getSession(String host, int port) {

        long sesPtr = 0;
        String toHash = null;

        if (host == null || host.isEmpty()) {
            return 0;
        }

        synchronized (storeLock) {
            toHash = host.concat(Integer.toString(port));

            System.out.println("Entered getSession()\n" + 
                "|   host = " + host + ", port = " + port + "\n" +
                "|   toHash = " + toHash + ", hashCode = " +
                    toHash.hashCode() + "\n" +
                "|   store = " + store);

            if (toHash != null && store != null) {
                Integer storeKey = new Integer(toHash.hashCode());
                Long storeVal = this.store.get(storeKey);
                if (storeVal != null) {
                    sesPtr = storeVal.longValue();
                }

                /* Delete entry from cache */
                this.store.remove(storeKey);
            }

            if (sesPtr == 0) {
                System.out.println("|-- SESSION NOT FOUND IN CACHE: 0");
            } else {
                System.out.println("|-- FOUND SESSION IN CACHE: " + sesPtr);
            }

            return sesPtr;
        }
    }

    /**
     * Store WOLFSSL_SESSION pointer (long) into client session cache, keying
     * off hash code of host:port.
     *
     * Keep in mind that the WOLFSSL_SESSION pointer will need to be freed
     * at some point with freeSession().
     *
     * @param port port number of peer connected to for this session
     * @param host hots of peer connected to
     */
    private synchronized void storeSession(String host, int port, long sesPtr) {

        int hashCode = 0;
        String toHash = null;

        if (host == null || host.isEmpty() || sesPtr == 0) {
            /* Invalid args, don't store */
            return;
        }

        synchronized (storeLock) {
            toHash = host.concat(Integer.toString(port));
            hashCode = toHash.hashCode();
            if (hashCode != 0) {
                store.put(hashCode, sesPtr);
                System.out.println("Entered storeSession()\n" +
                    "|   stored session: " + sesPtr);
            }
        }
    }

    class ClientThread implements Runnable
    {
        private WolfSSLContext sslCtx = null;
        private CountDownLatch closedLatch = null;

        public ClientThread(WolfSSLContext sslCtx, CountDownLatch latch) {
            this.sslCtx = sslCtx;
            this.closedLatch = latch;
        }

        public void run() {

            int ret = 0;
            int err = 0;
            int input = 0;
            String host = "localhost";
            WolfSSLSession ssl = null;
            Socket sock = null;
            byte[] back = new byte[80];
            String msg  = "hello from jni";

            /* Pointer to native WOLFSSL_SESSION */
            long session = 0;

            try {

                /* Introduce a random sleep per thread, so all client
                 * threads are started concurrently. Otherwise, one will get
                 * the cache entry and all others will not resume. Adding
                 * a random sleep makes this more realistic to what a real
                 * application would be encountering with staggered sessions
                 * across threads.
                 *
                 * Sleep here is random between zero and 1 second.
                 */
                Thread.sleep((long)(Math.random() * 1000));

                /* Create new WolfSSLSession */
                ssl = new WolfSSLSession(sslCtx);

                /* Connect TCP Socket */
                sock = new Socket(host, serverPort);
                System.out.println("Connected to " +
                        sock.getInetAddress().getHostAddress() +
                        " on port " + sock.getPort() + "\n");

                /* Pass Socket descriptor to wolfSSL */
                ret = ssl.setFd(sock);
                if (ret != WolfSSL.SSL_SUCCESS) {
                    throw new RuntimeException("Failed to set file descriptor");
                }

                /* Try to get session from session cache. We may not have a
                 * session in the cache yet if no connection has been made to
                 * this server, or another connection/thread already
                 * grabbed the client out of the cache. We need to remove the
                 * client session from the cache each time since the TLS 1.3
                 * binder changes between resumptions. */
                session = getSession(host, serverPort);
                if (session != 0) {
                    /* Restore saved WOLFSSL_SESSION, clear pointer after use */
                    ssl.setSession(session);

                    /* Free native WOLFSSL_SESSION memory */
                    ssl.freeSession(session);
                    session = 0;
                }

                do {
                    ret = ssl.connect();
                    err = ssl.getError(ret);
                } while (ret != WolfSSL.SSL_SUCCESS &&
                       (err == WolfSSL.SSL_ERROR_WANT_READ ||
                        err == WolfSSL.SSL_ERROR_WANT_WRITE));

                if (ret != WolfSSL.SSL_SUCCESS) {
                    err = ssl.getError(ret);
                    String errString = WolfSSL.getErrorString(err);
                    throw new RuntimeException(
                        "wolfSSL_connect failed. err = " + err +
                        ", " + errString);
                }

                do {
                    ret = ssl.write(msg.getBytes(), msg.length());
                    err = ssl.getError(0);
                } while (ret < 0 &&
                         (err == WolfSSL.SSL_ERROR_WANT_READ ||
                          err == WolfSSL.SSL_ERROR_WANT_WRITE));

                /* Read response */
                do {
                    input = ssl.read(back, back.length);
                    err = ssl.getError(0);
                } while (input < 0 &&
                         (err == WolfSSL.SSL_ERROR_WANT_READ ||
                          err == WolfSSL.SSL_ERROR_WANT_WRITE));

                if (input > 0) {
                    System.out.println("got back: " + new String(back));
                } else {
                    throw new RuntimeException("read failed");
                }

                /* Did we resume a connection from the cache? */
                if (ssl.sessionReused() == 1) {
                    System.out.println("Session resumed");
                    connectionsResumed.incrementAndGet(0);
                } else {
                    System.out.println("New session was made, not resumed");
                    connectionsFull.incrementAndGet(0);
                }

                /* Get native WOLFSSL_SESSION and store into our local
                 * client cache for resumption attempts later */
                session = ssl.getSession();
                if (session == 0) {
                    System.out.println("Failed to get native WOLFSSL_SESSION");
                } else {
                    storeSession(host, serverPort, session);
                    session = 0;
                    System.out.println("Saved native WOLFSSL_SESSION");
                }

                ssl.shutdownSSL();
                ssl.freeSSL();
                ssl = null;
                sock.close();
                sock = null;

                closedLatch.countDown();

            } catch (Exception e) {
                e.printStackTrace();

            } finally {
                if (sock != null) {
                    try {
                        sock.close();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                    sock = null;
                }
            }
        }
    }

    private void LaunchClientThreads()
        throws Exception {

        int ret = 0;
        WolfSSLContext sslCtx = null;
        CountDownLatch closedLatch = null;
        List<ClientThread> clientList = null;
        ExecutorService executor = null;

        closedLatch = new CountDownLatch(numConnections);
        clientList = new ArrayList<ClientThread>();

        /* Create one WolfSSLContext to share accross all client threads */ 
        sslCtx = new WolfSSLContext(WolfSSL.SSLv23_ClientMethod());

        /* Load client certificate */
        ret = sslCtx.useCertificateFile(clientCert,
            WolfSSL.SSL_FILETYPE_PEM);
        if (ret != WolfSSL.SSL_SUCCESS) {
            throw new RuntimeException(
                "failed to load client certificate!");
        }

        /* Load client private key */
        ret = sslCtx.usePrivateKeyFile(clientKey,
                WolfSSL.SSL_FILETYPE_PEM);
        if (ret != WolfSSL.SSL_SUCCESS) {
            throw new RuntimeException(
                "failed to load client private key!");
        }

        /* Load CA certificate to verify server */
        ret = sslCtx.loadVerifyLocations(caCert, null);
        if (ret != WolfSSL.SSL_SUCCESS) {
            throw new RuntimeException("failed to load CA certificates!");
        }

        /* Start client threads */
        for (int i = 0; i < numConnections; i++) {
            clientList.add(new ClientThread(sslCtx, closedLatch));
        }

        executor = Executors.newFixedThreadPool(clientList.size());
        for (final ClientThread c : clientList) {
            executor.execute(c);
        }

        /* Wait for client connections to finish */
        closedLatch.await();
        executor.shutdown();

        /* Go through Java client session cache and free memory for
         * native WOLFSSL_SESSION pointers */
        synchronized (storeLock) {
            Iterator<Integer> iterator = store.keySet().iterator();
            while (iterator.hasNext()) {
                Integer key = iterator.next();
                Long ptr = store.get(key);

                if (ptr != 0) {
                    WolfSSLSession.freeSession(ptr);
                }
                iterator.remove();
            }
        }

        System.out.println("\nCompleted " + numConnections +
            " client connections\n");
        System.out.println("\tconnections resumed: " +
            connectionsResumed.get(0));
        System.out.println("\tconnections full handshake: " +
            connectionsFull.get(0));
    }

    public void run(String[] args) throws Exception {

        /* Read and process command line options from user */
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];

            if (arg.equals("-help")) {
                printUsage();
                return;
            }
            else if (arg.equals("-n")) {
                if (args.length < i+2) {
                    printUsage();
                    return;
                }
                numConnections = Integer.parseInt(args[++i]);
            }
        }

        connectionsResumed.set(0, 0);
        connectionsFull.set(0, 0);

        /* Setup and start client threads */
        LaunchClientThreads();
    }

    private void printUsage() {
        System.out.println("Threaded Client Example:");
        System.out.println("-help\t\tHelp, print this usage");
        System.out.println("-n <num>\tNumber of threads/connections");
    }

    public static void main(String[] args) {

        try {
            /* Load library */
            WolfSSL.loadLibrary();

            SimpleThreadedClient test = new SimpleThreadedClient();
            test.run(args);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}


