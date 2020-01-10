/* MyMacEncryptCallback.java
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
import com.wolfssl.*;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.Cipher;

class MyMacEncryptCallback implements WolfSSLMacEncryptCallback
{
    public int macEncryptCallback(WolfSSLSession ssl, ByteBuffer macOut,
            byte[] macIn, long macInSz, int macContent, int macVerify,
            ByteBuffer encOut, ByteBuffer encIn, long encSz, Object ctx) {

        String hmacString;
        String tlsStr   = "TLS";
        byte[] keyBytes  = null;
        byte[] ivBytes   = null;
        byte[] myInner = new byte[WolfSSL.WOLFSSL_TLS_HMAC_INNER_SZ];

        MyAtomicEncCtx encCtx = (MyAtomicEncCtx) ctx;
        Cipher cipher = null;

        try {
            /* example supports (d)tls AES */
            System.out.println("ssl.getBulkCipher() = " + ssl.getBulkCipher());
            if (ssl.getBulkCipher() != WolfSSL.wolfssl_aes) {
                System.out.println("MyMacEncryptCallback not using AES");
                return -1;
            }

            if (!ssl.getVersion().contains(tlsStr)) {
                System.out.println("MyMacEncryptCallback not using (D)TLS");
                return -1;
            }

            int hmacType = ssl.getHmacType();
            switch (hmacType) {
                case WolfSSL.SHA:
                    hmacString = "HmacSHA1";
                    break;
                case WolfSSL.SHA256:
                    hmacString = "HmacSHA256";
                    break;
                case WolfSSL.SHA384:
                    hmacString = "HmacSHA384";
                    break;
                case WolfSSL.SHA512:
                    hmacString = "HmacSHA512";
                    break;
                default:
                    System.out.println("Unsupported HMAC hash type in " +
                            "MyMacEncryptCallback");
                    return -1;
            }

            /* hmac, not needed if aead mode */
            ssl.setTlsHmacInner(myInner, macInSz, macContent, macVerify);

            /* get Hmac key */
            byte[] macSecret = ssl.getMacSecret(macVerify);
            SecretKeySpec signingKey = new SecretKeySpec(
                    macSecret, hmacString);

            /* get Hmac instance and initialize with signing key */
            Mac mac = Mac.getInstance(hmacString);
            mac.init(signingKey);

            /* compute Hmac on signing data */
            mac.update(myInner, 0, myInner.length);
            mac.update(macIn, 0, (int)macInSz);
            macOut.put(mac.doFinal());
            macOut.flip();

            /* encrypt setup on first time */
            if (!encCtx.isCipherSetup()) {
                int keyLen = ssl.getKeySize();
                cipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
                SecretKeySpec key = null;

                if (ssl.getSide() == WolfSSL.WOLFSSL_CLIENT_END) {
                    keyBytes = ssl.getClientWriteKey();
                    ivBytes  = ssl.getClientWriteIV();
                }
                else {
                    keyBytes = ssl.getServerWriteKey();
                    ivBytes  = ssl.getServerWriteIV();
                }
                key = new SecretKeySpec(keyBytes, "AES");
                cipher.init(Cipher.ENCRYPT_MODE, key,
                        new IvParameterSpec(ivBytes));
                encCtx.setCipher(cipher);
                encCtx.isCipherSetup(true);

            } else {
                cipher = encCtx.getCipher();

                if (cipher == null) {
                    System.out.println("Cipher was not previously set up");
                    return -1;
                }
            }

            /* convert encIn ByteBuffer to byte[] */
            byte[] encInArr = new byte[(int)encSz];
            encIn.duplicate().get(encInArr);
            encOut.put(cipher.doFinal(encInArr, 0, (int)encSz));
            encOut.flip();

        } catch (Exception e) {
            e.printStackTrace();
            return -1;
        }

        return 0;
    }
}

