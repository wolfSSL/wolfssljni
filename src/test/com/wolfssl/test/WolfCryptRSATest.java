/* WolfCryptRSATest.java
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
import com.wolfssl.WolfCryptRSA;

public class WolfCryptRSATest {

    @Rule
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void beforeClass() throws WolfSSLException {
        System.out.println("WolfCryptRSA Class");
        WolfSSL.loadLibrary();
    }

    @Test
    public void testRSANew() throws WolfSSLException {
        assertNotNull(new WolfCryptRSA());
    }

    /* A size larger than its backing direct buffer must be rejected */
    @Test
    public void testDoSignRejectsOversizedSz() {
        Assume.assumeTrue(WolfSSL.RsaEnabled());
        WolfCryptRSA rsa = new WolfCryptRSA();
        ByteBuffer in  = ByteBuffer.allocateDirect(64);
        ByteBuffer out = ByteBuffer.allocateDirect(256);
        ByteBuffer key = ByteBuffer.allocateDirect(128);

        assertEquals(-1, rsa.doSign(in, 65, out, new int[]{256}, key, 128));
        assertEquals(-1, rsa.doSign(in, 64, out, new int[]{257}, key, 128));
        assertEquals(-1,
            rsa.doSign(in, 64, out, new int[]{256}, key, 0x100000000L + 16));
    }

    @Test
    public void testDoEncRejectsOversizedSz() {
        Assume.assumeTrue(WolfSSL.RsaEnabled());
        WolfCryptRSA rsa = new WolfCryptRSA();
        ByteBuffer in  = ByteBuffer.allocateDirect(64);
        ByteBuffer out = ByteBuffer.allocateDirect(256);
        ByteBuffer key = ByteBuffer.allocateDirect(128);

        assertEquals(-1, rsa.doEnc(in, 65, out, new int[]{256}, key, 128));
        assertEquals(-1, rsa.doEnc(in, 64, out, new int[]{257}, key, 128));
        assertEquals(-1,
            rsa.doEnc(in, 64, out, new int[]{256}, key, 0x100000000L + 16));
    }

    @Test
    public void testDoVerifyRejectsOversizedSz() {
        Assume.assumeTrue(WolfSSL.RsaEnabled());
        WolfCryptRSA rsa = new WolfCryptRSA();
        ByteBuffer sig = ByteBuffer.allocateDirect(64);
        ByteBuffer out = ByteBuffer.allocateDirect(256);
        ByteBuffer key = ByteBuffer.allocateDirect(128);

        assertEquals(-1, rsa.doVerify(sig, 65, out, 256, key, 128));
        assertEquals(-1, rsa.doVerify(sig, 64, out, 257, key, 128));
        assertEquals(-1,
            rsa.doVerify(sig, 64, out, 256, key, 0x100000000L + 16));
    }

    @Test
    public void testDoDecRejectsOversizedSz() {
        Assume.assumeTrue(WolfSSL.RsaEnabled());
        WolfCryptRSA rsa = new WolfCryptRSA();
        ByteBuffer in  = ByteBuffer.allocateDirect(64);
        ByteBuffer out = ByteBuffer.allocateDirect(256);
        ByteBuffer key = ByteBuffer.allocateDirect(128);

        assertEquals(-1, rsa.doDec(in, 65, out, 256, key, 128));
        assertEquals(-1, rsa.doDec(in, 64, out, 257, key, 128));
        assertEquals(-1,
            rsa.doDec(in, 64, out, 256, key, 0x100000000L + 16));
    }

    /* SHA-256 hash OID sum, which wolfSSL encodes two ways depending on the
     * build: current default, or the legacy WOLFSSL_OLD_OID_SUM value
     * (see wolfSSL oid_sum.h). */
    private static final int SHA256_OID     = 0x7cb37afb;
    private static final int SHA256_OID_OLD = 414;

    /* Return a SHA-256 hash OID wc_OidGetHash accepts, or -1 if none
     * (PSS not compiled, or an OID-sum scheme we do not know). */
    private static int findPssHashOid(WolfCryptRSA rsa) {
        ByteBuffer b = ByteBuffer.allocateDirect(64);
        int[] candidates = { SHA256_OID, SHA256_OID_OLD };
        for (int oid : candidates) {
            int ret = rsa.doPssVerify(b, 64, b, 64, oid, 0, b, 64);
            if (ret != -1 && ret != WolfSSL.NOT_COMPILED_IN) {
                return oid;
            }
        }
        return -1;
    }

    @Test
    public void testDoPssSignRejectsOversizedSz() {
        Assume.assumeTrue(WolfSSL.RsaEnabled());
        WolfCryptRSA rsa = new WolfCryptRSA();
        int oid = findPssHashOid(rsa);
        Assume.assumeTrue("PSS unavailable or unknown hash OID scheme",
            oid != -1);

        ByteBuffer in  = ByteBuffer.allocateDirect(64);
        ByteBuffer out = ByteBuffer.allocateDirect(256);
        ByteBuffer key = ByteBuffer.allocateDirect(128);

        assertEquals(-1,
            rsa.doPssSign(in, 65, out, new int[]{256}, oid, 0, key, 128));
        assertEquals(-1,
            rsa.doPssSign(in, 64, out, new int[]{257}, oid, 0, key, 128));
        assertEquals(-1,
            rsa.doPssSign(in, 64, out, new int[]{256}, oid, 0, key,
                0x100000000L + 16));
    }

    @Test
    public void testDoPssVerifyRejectsOversizedSz() {
        Assume.assumeTrue(WolfSSL.RsaEnabled());
        WolfCryptRSA rsa = new WolfCryptRSA();
        int oid = findPssHashOid(rsa);
        Assume.assumeTrue("PSS unavailable or unknown hash OID scheme",
            oid != -1);

        ByteBuffer sig = ByteBuffer.allocateDirect(64);
        ByteBuffer out = ByteBuffer.allocateDirect(256);
        ByteBuffer key = ByteBuffer.allocateDirect(128);

        assertEquals(-1, rsa.doPssVerify(sig, 65, out, 256, oid, 0, key, 128));
        assertEquals(-1, rsa.doPssVerify(sig, 64, out, 257, oid, 0, key, 128));
        assertEquals(-1,
            rsa.doPssVerify(sig, 64, out, 256, oid, 0, key, 0x100000000L + 16));
    }
}
