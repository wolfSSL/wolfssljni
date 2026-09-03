/* WolfCryptECCTest.java
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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

package com.wolfssl.test;

import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertEquals;

import java.nio.ByteBuffer;

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLException;
import com.wolfssl.WolfCryptECC;

public class WolfCryptECCTest {

    @Rule
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void beforeClass() throws WolfSSLException {
        System.out.println("WolfCryptECC Class");
        WolfSSL.loadLibrary();
    }

    @Test
    public void testECCNew() throws WolfSSLException {
        assertNotNull(new WolfCryptECC());
    }

    /* doVerify must reject a size larger than its backing direct buffer */
    @Test
    public void testDoVerifyRejectsOversizedSz() {
        Assume.assumeTrue(WolfSSL.EccEnabled());
        WolfCryptECC ecc = new WolfCryptECC();
        ByteBuffer sig  = ByteBuffer.allocateDirect(64);
        ByteBuffer hash = ByteBuffer.allocateDirect(32);
        ByteBuffer key  = ByteBuffer.allocateDirect(32);
        int[] result = new int[1];

        /* sigSz / hashSz over their buffers (import fails before use) */
        assertEquals(-1, ecc.doVerify(sig, 65, hash, 32, key, 32, result));
        assertEquals(-1, ecc.doVerify(sig, 64, hash, 33, key, 32, result));

        /* keySz above the key buffer and above UINT_MAX */
        assertEquals(-1,
            ecc.doVerify(sig, 64, hash, 32, key, 0x100000000L + 16, result));
    }

    /* doSign must reject a size larger than its backing direct buffer */
    @Test
    public void testDoSignRejectsOversizedSz() {
        Assume.assumeTrue(WolfSSL.EccEnabled());
        WolfCryptECC ecc = new WolfCryptECC();
        ByteBuffer in  = ByteBuffer.allocateDirect(32);
        ByteBuffer out = ByteBuffer.allocateDirect(128);
        ByteBuffer key = ByteBuffer.allocateDirect(64);

        /* inSz / outSz over their buffers (key decode fails before use) */
        assertEquals(-1, ecc.doSign(in, 33, out, new long[]{128}, key, 64));
        assertEquals(-1, ecc.doSign(in, 32, out, new long[]{129}, key, 64));

        /* negative outSz[0] must be rejected, not reinterpreted as huge */
        assertEquals(-1, ecc.doSign(in, 32, out, new long[]{-1}, key, 64));

        /* keySz above the key buffer */
        assertEquals(-1, ecc.doSign(in, 32, out, new long[]{128}, key, 65));
    }
}
