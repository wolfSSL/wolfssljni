/* RSA.java
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

package com.wolfssl.wolfcrypt;

import java.nio.ByteBuffer;

/**
 * Wrapper for the native WolfCrypt RSA implementation, used for examples.
 * This class contains a subset of the WolfCrypt RSA implementation and was
 * written to be used with this package's example RSA public key callbacks.
 * Usage can be found in examples/Client.java and examples/Server.java.
 *
 * @author  wolfSSL
 * @version 1.0, August 2013
 */
public class RSA {

    public native int doSign(ByteBuffer in, long inSz, ByteBuffer out,
            int[] outSz, ByteBuffer key, long keySz);

    public native int doVerify(ByteBuffer sig, long sigSz, ByteBuffer out,
           long outSz, ByteBuffer keyDer, long keySz);

    public native int doEnc(ByteBuffer in, long inSz, ByteBuffer out,
            int[] outSz, ByteBuffer keyDer, long keySz);

    public native int doDec(ByteBuffer in, long inSz, ByteBuffer out,
            long outSz, ByteBuffer keyDer, long keySz);

}

