/* MyEccVerifyCallback.java
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

class MyEccVerifyCallback implements WolfSSLEccVerifyCallback
{
    public int eccVerifyCallback(WolfSSLSession ssl, ByteBuffer sig,
            long sigSz, ByteBuffer hash, long hashSz, ByteBuffer keyDer,
            long keySz, int[] result, Object ctx) {

        System.out.println("---------- Entered MyEccVerifyCallback ----------");

        int ret = -1;
        ECC ecc = new ECC();
        MyEccVerifyCtx eccVerifyCtx = (MyEccVerifyCtx)ctx;

        ret = ecc.doVerify(sig, sigSz, hash, hashSz, keyDer, keySz, result);
        if (ret != 0) {
            System.out.println("ECC verification failed in " +
                    "MyEccVerifyCallback");
        }

        System.out.println("---------- Leaving MyEccVerifyCallback ----------");
        return ret;
    }
}

