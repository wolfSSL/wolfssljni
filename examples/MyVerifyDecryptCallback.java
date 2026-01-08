/* MyVerifyDecryptCallback.java
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

import java.io.*;
import java.net.*;
import java.nio.*;
import java.util.*;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.Cipher;
import java.nio.ByteBuffer;
import com.wolfssl.*;

/*
 * Example Verify/Decrypt callback implementation. For use when
 * HAVE_ENCRYPT_THEN_MAC is defined, which can be tested from Java using
 * WolfSSL.encryptThenMacEnabled().
 *
 * This example callback has been modeled directly after the native wolfSSL
 * example callback (myVerifyDecryptCb()) in wolfssl/test.h.
 *
 * NOTE: if native HAVE_ENCRYPT_THEN_MAC is not defined, the DecryptVerify
 * callback needs to be set and used.
 */
class MyVerifyDecryptCallback implements WolfSSLVerifyDecryptCallback
{
    public int verifyDecryptCallback(WolfSSLSession ssl, ByteBuffer decOut,
            byte[] decIn, long decSz, int macContent, int macVerify,
            long[] padSz, Object ctx) {

        int hmacType = ssl.getHmacType();
        int digestSz = ssl.getHmacSize();
        byte[] myInner = new byte[WolfSSL.WOLFSSL_TLS_HMAC_INNER_SZ];
        byte[] verify = null;
        byte[] keyBytes = null;
        byte[] ivBytes  = null;
        String hmacString;
        String tlsStr   = "TLS";

        Cipher cipher = null;
        MyAtomicDecCtx decCtx = (MyAtomicDecCtx) ctx;

        /* example supports (d)tls AES */
        if (ssl.getBulkCipher() != WolfSSL.wolfssl_aes) {
            System.out.println("MyVerifyDecryptCallback not using AES");
            return -1;
        }

        try {
            if (!ssl.getVersion().contains(tlsStr)) {
                System.out.println("MyVerifyDecryptCallback not using (D)TLS");
                return -1;
            }

            ssl.setTlsHmacInner(myInner, decSz, macContent, macVerify);

            if (hmacType == WolfSSL.SHA) {
                hmacString = "HmacSHA1";
            } else if (hmacType == WolfSSL.SHA256) {
                hmacString = "HmacSHA256";
            } else if (hmacType == WolfSSL.SHA384) {
                hmacString = "HmacSHA384";
            } else if (hmacType == WolfSSL.SHA512) {
                hmacString = "HmacSHA512";
            } else {
                System.out.println("Unsupported HMAC hash type in " +
                        "MyVerifyDecryptCallback: " + hmacType);
                return -1;
            }

            /* construct HMAC key */
            SecretKeySpec hmacKey = new SecretKeySpec(
                ssl.getMacSecret(macVerify), hmacString);

            /* get Mac instance, initialize with key, compute */
            Mac mac = Mac.getInstance(hmacString);
            mac.init(hmacKey);
            mac.update(myInner, 0, myInner.length);
            mac.update(decIn, 0, (int)decSz);
            verify = mac.doFinal();

            /* Get MAC (digestSz bytes) off end of decOut for comparison */
            byte[] verifyMac = new byte[digestSz];
            int tmpPos = decOut.position();
            decOut.position(decOut.limit() - digestSz);
            decOut.get(verifyMac);
            decOut.position(tmpPos);

            if (verifyMac.length != verify.length) {
                System.out.println("MyVerifyDecryptCallback verifyMac length " +
                        "different than calculated MAC length");
                return -1;
            }

            if (!Arrays.equals(verify, verifyMac)) {
                System.out.println("MyVerifyDecryptCallback MAC " +
                    "comparison failed");
                return -1;
            }

            /* Setup AES for decrypt */
            if(!decCtx.isCipherSetup()) {
                int keyLen = ssl.getKeySize();
                SecretKeySpec key = null;
                cipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");

                /* Decrypt is from other side (peer) */
                if (ssl.getSide() == WolfSSL.WOLFSSL_SERVER_END) {
                    keyBytes = ssl.getClientWriteKey();
                    ivBytes  = ssl.getClientWriteIV();
                } else {
                    keyBytes = ssl.getServerWriteKey();
                    ivBytes  = ssl.getServerWriteIV();
                }

                key = new SecretKeySpec(keyBytes, "AES");
                cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ivBytes));
                decCtx.setCipher(cipher);
                decCtx.isCipherSetup(true);
            } else {
                cipher = decCtx.getCipher();

                if (cipher == null) {
                    System.out.println("Cipher was not previously set up");
                    return -1;
                }
            }

            /* Decrypt */
            decOut.position(0);
            decOut.put(cipher.doFinal(decIn, 0, (int)decSz));
            decOut.flip();

            byte padVal = decOut.get((int)decSz - 1);
            padSz[0] = (long)padVal + 1;

        } catch (Exception e) {
            e.printStackTrace();
        }

        return 0;
    }
}

