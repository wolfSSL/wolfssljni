/* MyEccSharedSecretCallback.java
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
import java.nio.ByteBuffer;
import com.wolfssl.*;
import com.wolfssl.wolfcrypt.*;

import java.security.KeyFactory;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import javax.crypto.KeyAgreement;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.util.Arrays;

/*
 * Example ECC shared secret callback implementation
 * This example uses the Java JCE KeyAgreement and ECC key classes
 * to generate a shared secret.
 */
class MyEccSharedSecretCallback implements WolfSSLEccSharedSecretCallback
{
    public int eccSharedSecretCallback(WolfSSLSession ssl, EccKey otherKey,
            ByteBuffer pubKeyDer, long[] pubKeyDerSz, ByteBuffer out,
            long[] outSz, int side, Object ctx) {

        int ret = -1;
        ECPublicKey ecPubKey = null;
        ECPrivateKey ecPrivKey = null;
        byte[] secret = null;

        System.out.println("------- Entered MyEccSharedSecretCallback -------");

        if (ssl == null || otherKey == null) {
            System.out.println("Bad arguments, ssl or otherKey object is null");
            return -1;
        }

        MyEccSharedSecretCtx eccSharedSecretCtx = (MyEccSharedSecretCtx)ctx;

        try {

            KeyFactory kf = KeyFactory.getInstance("EC");

            if (side == WolfSSL.WOLFSSL_CLIENT_END) {

                /* otherKey holds server's public key */
                System.out.println("side = WOLFSSL_CLIENT_END");

                KeySpec pubSpec =
                    new X509EncodedKeySpec(otherKey.getPublicKeyDer());
                ecPubKey = (ECPublicKey)kf.generatePublic(pubSpec);
                System.out.println("EC params: " + ecPubKey.getParams());

                /* Create key pair, export public part to pubKeyDer */
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
                kpg.initialize(ecPubKey.getParams());

                KeyPair kp = kpg.generateKeyPair();

                ecPrivKey = (ECPrivateKey)kp.getPrivate();
                ECPublicKey ecPubKeyOut = (ECPublicKey)kp.getPublic();

                /* strip off header, wolfSSL needs raw ECC public key */
                byte[] ecPubKeyEncoded = ecPubKeyOut.getEncoded();
                ecPubKeyEncoded = Arrays.copyOfRange(ecPubKeyEncoded, 26,
                                                     ecPubKeyEncoded.length);

                if (ecPubKeyEncoded.length > pubKeyDer.capacity()) {
                    System.out.println("ERROR: ECC public key is too long " +
                                       "for DER buffer");
                    return -1;
                }

                pubKeyDer.clear();
                pubKeyDer.put(ecPubKeyEncoded);
                pubKeyDerSz[0] = ecPubKeyEncoded.length;

            } else {

                System.out.println("... side = WOLFSSL_SERVER_END");

                /* otherKey holds server private key */
                KeySpec privSpec =
                    new PKCS8EncodedKeySpec(otherKey.getPrivateKeyPKCS8());
                ecPrivKey = (ECPrivateKey)kf.generatePrivate(privSpec);

                /* Import public key from pubKeyDer */
                byte[] pubKeyTmp = new byte[pubKeyDer.capacity()];
                pubKeyDer.get(pubKeyTmp);

                X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(pubKeyTmp);
                ecPubKey = (ECPublicKey)kf.generatePublic(pubSpec);
            }

            /* generate shared secret */
            KeyAgreement keyAgree = KeyAgreement.getInstance("ECDH");
            keyAgree.init(ecPrivKey);
            keyAgree.doPhase(ecPubKey, true);

            secret = keyAgree.generateSecret();

            if (secret.length > out.capacity()) {
                System.out.println("ERROR: ECC shared secret length too long " +
                                   "for output buffer");
                return -1;
            }

            out.clear();
            out.put(secret);
            outSz[0] = secret.length;

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e2) {
            e2.printStackTrace();
        } catch (InvalidAlgorithmParameterException e3) {
            e3.printStackTrace();
        } catch (InvalidKeyException e4) {
            e4.printStackTrace();
        }

        System.out.println("------- Leaving MyEccSharedSecretCallback -------");

        return 0;
    }
}

