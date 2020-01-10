/* MyRsaDecCallback.java
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
import com.wolfssl.wolfcrypt.*;

class MyRsaDecCallback implements WolfSSLRsaDecCallback
{
    public int rsaDecCallback(WolfSSLSession ssl, ByteBuffer in, long inSz,
            ByteBuffer out, long outSz, ByteBuffer keyDer, long keySz,
            Object ctx) {

        System.out.println("---------- Entering MyRsaDecCallback ----------");
        int ret = -1;

        RSA rsa = new RSA();
        MyRsaDecCtx rsaDecCtx = (MyRsaDecCtx)ctx;

        ret = rsa.doDec(in, inSz, out, outSz, keyDer, keySz);
        if (ret < 0) {
            System.out.println("RSA decrypt failed in " +
                    "MyRsaDecCallback");
        }

        System.out.println("---------- Leaving MyRsaDecCallback ----------");
        return ret;
    }
}

