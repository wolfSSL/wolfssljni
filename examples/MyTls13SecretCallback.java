/* MyTls13SecretCallback.java
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

import java.io.FileWriter;
import java.io.PrintWriter;
import java.io.IOException;

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLSession;
import com.wolfssl.WolfSSLTls13SecretCallback;
import com.wolfssl.WolfSSLJNIException;

/**
 * Example TLS 1.3 secret callback implementation.
 *
 * This is provided as an example only, and used with the example JNI
 * applications provided in this package. Users in production environments
 * should write their own implementation to conform to desired goals.
 */
class MyTls13SecretCallback implements WolfSSLTls13SecretCallback
{
    /* SSL keylog file to output secrets to */
    private String sslKeyLogFile = "sslkeylog.log";

    /**
     * Create new MyTls13SecretCallback using default "sslkeylog.log" file
     * path.
     */
    public MyTls13SecretCallback() {
    }

    /**
     * Create new MyTls13SecretCallback object specifying SSL keylog file
     * path.
     *
     * @param keyLogFile path to output file (ex: sslkeylog.log) to use
     *        for writing TLS 1.3 secrets into.
     */
    public MyTls13SecretCallback(String keyLogFile) {
        this.sslKeyLogFile = keyLogFile;
    }

    /**
     * Callback method for printing/saving TLS 1.3 secrets, for use
     * with Wireshark. Called by native wolfSSL when each secret is available.
     *
     * @param ssl       the current SSL session object from which the
     *                  callback was initiated.
     * @param id        Identifier specifying what type of secret this callback
     *                  is being called with, one of the following:
     *                      WolfSSL.CLIENT_EARLY_TRAFFIC_SECRET
     *                      WolfSSL.EARLY_EXPORTER_SECRET
     *                      WolfSSL.CLIENT_HANDSHAKE_TRAFFIC_SECRET
     *                      WolfSSL.SERVER_HANDSHAKE_TRAFFIC_SECRET
     *                      WolfSSL.CLIENT_TRAFFIC_SECRET
     *                      WolfSSL.SERVER_TRAFFIC_SECRET
     *                      WolfSSL.EXPORTER_SECRET
     * @param secret    Current secret as byte array
     * @param ctx       Optional user context if set
     *
     * @return 0 on success, otherwise negative if callback encounters
     *         an error.
     */
    public int tls13SecretCallback(WolfSSLSession ssl, int id, byte[] secret,
        Object ctx) {

        int i;
        String str = null;
        FileWriter fw = null;
        PrintWriter pw = null;
        byte[] clientRandom = null;
       
        try { 
            /* Open FileWriter in append mode */
            fw = new FileWriter(sslKeyLogFile, true);
            pw = new PrintWriter(fw);

            clientRandom = ssl.getClientRandom();
            if (clientRandom == null || clientRandom.length == 0) {
                System.out.println("Error getting client random");
            }

            /* Set secret label based on ID */
            if (id == WolfSSL.CLIENT_EARLY_TRAFFIC_SECRET) {
                str = "CLIENT_EARLY_TRAFFIC_SECRET";
            } else if (id == WolfSSL.EARLY_EXPORTER_SECRET) {
                str = "EARLY_EXPORTER_SECRET";
            } else if (id == WolfSSL.CLIENT_HANDSHAKE_TRAFFIC_SECRET) {
                str = "CLIENT_HANDSHAKE_TRAFFIC_SECRET";
            } else if (id == WolfSSL.SERVER_HANDSHAKE_TRAFFIC_SECRET) {
                str = "SERVER_HANDSHAKE_TRAFFIC_SECRET";
            } else if (id == WolfSSL.CLIENT_TRAFFIC_SECRET) {
                str = "CLIENT_TRAFFIC_SECRET";
            } else if (id == WolfSSL.SERVER_TRAFFIC_SECRET) {
                str = "SERVER_TRAFFIC_SECRET";
            } else if (id == WolfSSL.EXPORTER_SECRET) {
                str = "EXPORTER_SECRET";
            } else {
                pw.close();
                return WolfSSL.TLS13_SECRET_CB_E;
            }

            pw.printf("%s ", str);
            for (i = 0; i < clientRandom.length; i++) {
                pw.printf("%02x", clientRandom[i]);
            }
            pw.printf(" ");
            for (i = 0; i < clientRandom.length; i++) {
                pw.printf("%02x", secret[i]);
            }
            pw.printf("\n");

            pw.close();

            return 0;

        } catch (IOException | WolfSSLJNIException e) {
            e.printStackTrace();
            return WolfSSL.TLS13_SECRET_CB_E;
        }
    }
}

