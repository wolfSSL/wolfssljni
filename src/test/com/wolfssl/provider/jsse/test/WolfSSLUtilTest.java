/* WolfSSLUtilTest.java
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

package com.wolfssl.provider.jsse.test;

import org.junit.Test;
import org.junit.Rule;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.rules.TestRule;
import static org.junit.Assert.assertEquals;

import java.lang.reflect.Method;
import java.math.BigInteger;
import java.util.Date;
import java.time.Instant;
import java.time.Duration;

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLCertificate;
import com.wolfssl.WolfSSLX509Name;
import com.wolfssl.provider.jsse.WolfSSLProvider;
import com.wolfssl.test.TimedTestWatcher;
import com.wolfssl.test.WolfSSLTestCommon;

/**
 * Tests for com.wolfssl.provider.jsse.WolfSSLUtil helper methods.
 */
public class WolfSSLUtilTest {

    private static String cliKeyPubDer = "examples/certs/client-keyPub.der";
    private static String cliKeyDer = "examples/certs/client-key.der";

    @Rule
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void setup() throws Exception {
        System.out.println("WolfSSLUtil Class");
        /* Instantiate wolfJSSE, loads native wolfSSL library */
        new WolfSSLProvider();

        cliKeyPubDer = WolfSSLTestCommon.getPath(cliKeyPubDer);
        cliKeyDer = WolfSSLTestCommon.getPath(cliKeyDer);
    }

    /* Invoke the package-private static WolfSSLUtil.isIpAddress() via
     * reflection, since this test lives in a different package. */
    private static boolean isIpAddress(String host) throws Exception {

        Method m = com.wolfssl.provider.jsse.WolfSSLUtil.class
            .getDeclaredMethod("isIpAddress", String.class);
        m.setAccessible(true);

        return (Boolean) m.invoke(null, host);
    }

    private static void check(String host, boolean expected) throws Exception {
        assertEquals("isIpAddress(\"" + host + "\")", expected,
            isIpAddress(host));
    }

    /* isIpAddress() decides whether a reference identity is matched against
     * iPAddress SANs (IP literal) or dNSName SANs and the CN (host name). */
    @Test
    public void test_isIpAddress() throws Exception {

        /* IPv4 literals */
        check("192.0.2.1", true);
        check("127.0.0.1", true);
        check("255.255.255.255", true);
        check("0.0.0.0", true);

        /* IPv6 literals, plain and bracketed */
        check("::1", true);
        check("2001:db8::1", true);
        check("[::1]", true);
        check("fe80::1", true);

        /* Host names, must not be treated as IP literals */
        check("example.com", false);
        check("wolfssl.com", false);
        check("localhost", false);
        check("host-1.example.org", false);

        /* Not valid IPv4 dotted-quads, treated as host names */
        check("192.0.2", false);
        check("192.0.2.1.5", false);
        check("256.0.0.1", false);
        check("192.0.2.x", false);
        check("192.0.2.", false);

        /* null and empty */
        check(null, false);
        check("", false);
    }

    /* Invoke the package-private static WolfSSLUtil.verifyHostnameOrIp() via
     * reflection. */
    private static int verifyHostnameOrIp(WolfSSLCertificate cert, String name,
        long flags) throws Exception {

        Method m = com.wolfssl.provider.jsse.WolfSSLUtil.class
            .getDeclaredMethod("verifyHostnameOrIp",
                WolfSSLCertificate.class, String.class, long.class);
        m.setAccessible(true);

        return (Integer) m.invoke(null, cert, name, flags);
    }

    /* Generate a certificate with a single IPv6 iPAddress SAN. */
    private static byte[] genIpv6SanCert(String sanIp) throws Exception {

        WolfSSLCertificate x509 = new WolfSSLCertificate();
        WolfSSLX509Name name = new WolfSSLX509Name();

        Instant now = Instant.now();
        x509.setNotBefore(Date.from(now));
        x509.setNotAfter(Date.from(now.plus(Duration.ofDays(365))));
        x509.setSerialNumber(BigInteger.valueOf(4321));

        name.setCountryName("US");
        name.setOrganizationName("wolfSSL Inc.");
        name.setCommonName("wolfssl.com");
        x509.setSubjectName(name);

        x509.setPublicKey(cliKeyPubDer, WolfSSL.RSAk,
            WolfSSL.SSL_FILETYPE_ASN1);
        x509.addAltName(sanIp, WolfSSL.ASN_IP_TYPE);
        x509.signCert(cliKeyDer, WolfSSL.RSAk,
            WolfSSL.SSL_FILETYPE_ASN1, "SHA256");

        byte[] der = x509.getDer();
        name.free();
        x509.free();

        return der;
    }

    /* verifyHostnameOrIp() must strip surrounding IPv6 brackets before
     * matching, so a bracketed literal like "[::1]" still matches a cert whose
     * iPAddress SAN stores the address without brackets. Native wolfSSL
     * normalizes IPv6 text forms internally, so only the brackets need
     * removing at the Java layer. */
    @Test
    public void test_verifyHostnameOrIp_ipv6Brackets() throws Exception {

        Assume.assumeTrue(WolfSSL.FileSystemEnabled());

        /* Generating an IPv6 iPAddress SAN via wolfSSL_X509_add_altname()
         * requires wolfSSL 5.9.2 or later. The bracket-stripping fix itself is
         * version independent, but this test's cert generation is not. */
        Assume.assumeTrue(WolfSSL.getLibVersionHex() >= 0x05009002L);

        byte[] der = genIpv6SanCert("::1");
        WolfSSLCertificate cert = new WolfSSLCertificate(der);
        try {
            assertEquals("bracketed IPv6 must match iPAddress SAN",
                WolfSSL.SSL_SUCCESS, verifyHostnameOrIp(cert, "[::1]", 0));
            assertEquals("bare IPv6 must match iPAddress SAN",
                WolfSSL.SSL_SUCCESS, verifyHostnameOrIp(cert, "::1", 0));
            assertEquals("non-matching IPv6 must be rejected",
                WolfSSL.SSL_FAILURE,
                verifyHostnameOrIp(cert, "[2001:db8::1]", 0));
        } finally {
            cert.free();
        }
    }
}
