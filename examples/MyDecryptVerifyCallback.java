/* MyDecryptVerifyCallback.java
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
import java.util.*;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.Cipher;
import java.nio.ByteBuffer;
import com.wolfssl.*;

class MyDecryptVerifyCallback implements WolfSSLDecryptVerifyCallback
{
    public int decryptVerifyCallback(WolfSSLSession ssl, ByteBuffer decOut,
            byte[] decIn, long decSz, int macContent, int macVerify,
            long[] padSz, Object ctx) {

        int ret      = 0;
        int macInSz  = 0;
        int ivExtra  = 0;
        long pad     = 0;
        long padByte = 0;
        String hmacString;
        String tlsStr   = "TLS";
        byte[] keyBytes = null;
        byte[] ivBytes  = null;
        int digestSz    = ssl.getHmacSize();
        byte[] myInner = new byte[WolfSSL.WOLFSSL_TLS_HMAC_INNER_SZ];
        byte[] verify  = new byte[WolfSSL.getHmacMaxSize()];

        MyAtomicDecCtx decCtx = (MyAtomicDecCtx) ctx;
        Cipher cipher = null;

        /* example supports (d)tls AES */
        if (ssl.getBulkCipher() != WolfSSL.wolfssl_aes) {
            System.out.println("MyDecryptVerifyCallback not using AES");
            return -1;
        }

        try {

            if (!ssl.getVersion().contains(tlsStr)) {
                System.out.println("MyDecryptVerifyCallback not using (D)TLS");
                return -1;
            }

            /* setup AES */
            if(!decCtx.isCipherSetup()) {
                int keyLen = ssl.getKeySize();
                SecretKeySpec key = null;
                cipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");

                /* decrypt is from other side (peer) */
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

            /* decrypt */
            decOut.put(cipher.doFinal(decIn, 0, (int)decSz));
            decOut.flip();

            if (ssl.getCipherType() == WolfSSL.WOLFSSL_AEAD_TYPE) {
                padSz[0] = ssl.getAeadMacSize();
                return 0;
            }

            if (ssl.getCipherType() == WolfSSL.WOLFSSL_BLOCK_TYPE) {
                pad = decOut.get((int)decSz - 1);
                padByte = 1;
                if (ssl.isTLSv1_1() == 1)
                    ivExtra = ssl.getCipherBlockSize();
            }

            padSz[0] = ssl.getHmacSize() + pad + padByte;
            macInSz = (int) (decSz - ivExtra - digestSz - pad - padByte);

            ssl.setTlsHmacInner(myInner, macInSz, macContent, macVerify);
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
                            "MyDecryptVerifyCallback");
                    return -1;
            }

            /* get Hmac SHA-1 key */
            SecretKeySpec signingKey = new SecretKeySpec(
                    ssl.getMacSecret(macVerify), hmacString);

            /* get Hmac SHA-1 instance and initialize with signing key */
            Mac mac = Mac.getInstance(hmacString);
            mac.init(signingKey);

            /* get tmp array for encrypted MAC */
            byte[] tmpMac = new byte[(int)macInSz];
            ByteBuffer tmpBuf = decOut.duplicate();
            tmpBuf.position(ivExtra);
            tmpBuf.limit(ivExtra + tmpMac.length + 1);
            tmpBuf.slice().get(tmpMac, 0, tmpMac.length);

            /* compute Hmac on signing data */
            mac.update(myInner, 0, myInner.length);
            mac.update(tmpMac, 0, (int)macInSz);
            verify = mac.doFinal();

            /* do comparison */
            int begin = (int) (decSz - digestSz - pad - padByte);
            byte[] subArray = new byte[digestSz];
            ByteBuffer tmpDigest = decOut.duplicate();
            tmpDigest.position(begin);
            tmpDigest.limit(begin + digestSz + 1);
            tmpDigest.slice().get(subArray);
            if (!Arrays.equals(verify, subArray)) {
                System.out.println("MyDecryptVerifyCallback verify failed");
                return -1;
            }

        } catch (Exception e) {
            e.printStackTrace();
        }

        return ret;
    }
}

