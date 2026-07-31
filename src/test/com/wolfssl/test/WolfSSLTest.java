/* WolfSSLTest.java
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
import static org.junit.Assert.*;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLException;
import com.wolfssl.WolfSSLLoggingCallback;
import com.wolfssl.WolfSSLFIPSErrorCallback;

/* suppress SSLv3 deprecation warnings, meant for end user not tests */
@SuppressWarnings("deprecation")
public class WolfSSLTest {

    @Rule
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void loadLibrary() {
        System.out.println("WolfSSL Class");
        try {
            WolfSSL.loadLibrary();
        } catch (UnsatisfiedLinkError ule) {
            fail("failed to load native JNI library");
        }
    }

    @Test
    public void test_WolfSSL_new() {
        try {
            new WolfSSL();
        } catch (UnsatisfiedLinkError ule) {
            fail("failed to load native JNI library");
        } catch (WolfSSLException we) {
            fail("failed to create WolfSSL object");
        }
    }

    @Test
    public void test_WolfSSL_protocol() {
        String[] p = WolfSSL.getProtocols();
        if (p == null) {
            fail("failed to get protocols");
        }
    }

    @Test
    public void test_WolfSSL_getProtocolsMask() {
        /* Get all protocols (no mask) */
        String[] allProtocols = WolfSSL.getProtocolsMask(0);
        if (allProtocols == null) {
            fail("getProtocolsMask(0) returned null");
        }

        /* Test with TLSv1.3 masked off, verify TLSv1.3 not in result */
        String[] noTls13 = WolfSSL.getProtocolsMask(WolfSSL.SSL_OP_NO_TLSv1_3);
        if (noTls13 == null) {
            fail("getProtocolsMask(SSL_OP_NO_TLSv1_3) returned null");
        }
        List<String> noTls13List = Arrays.asList(noTls13);
        if (noTls13List.contains("TLSv1.3")) {
            fail("TLSv1.3 should not be in result when masked");
        }

        /* Test with TLSv1.2 masked off, verify TLSv1.2 not in result */
        String[] noTls12 = WolfSSL.getProtocolsMask(WolfSSL.SSL_OP_NO_TLSv1_2);
        if (noTls12 == null) {
            fail("getProtocolsMask(SSL_OP_NO_TLSv1_2) returned null");
        }
        List<String> noTls12List = Arrays.asList(noTls12);
        if (noTls12List.contains("TLSv1.2")) {
            fail("TLSv1.2 should not be in result when masked");
        }

        /* Test with multiple versions masked off */
        long multiMask = WolfSSL.SSL_OP_NO_TLSv1_2 | WolfSSL.SSL_OP_NO_TLSv1_3;
        String[] noTls12And13 = WolfSSL.getProtocolsMask(multiMask);
        if (noTls12And13 == null) {
            fail("getProtocolsMask with multiple masks returned null");
        }
        List<String> noTls12And13List = Arrays.asList(noTls12And13);
        if (noTls12And13List.contains("TLSv1.2") ||
            noTls12And13List.contains("TLSv1.3")) {
            fail("TLSv1.2 and TLSv1.3 should not be in result when masked");
        }
    }

    @Test
    public void test_WolfSSL_Method_Allocators() {
        /* Get protocols compiled into native wolfSSL */
        List<String> enabledProtocols = Arrays.asList(WolfSSL.getProtocols());

        if (enabledProtocols.contains("SSLv3")) {
            tstMethod(WolfSSL.SSLv3_ServerMethod(), "SSLv3_ServerMethod()");
            tstMethod(WolfSSL.SSLv3_ClientMethod(), "SSLv3_ClientMethod()");
        }
        if (enabledProtocols.contains("TLSv1")) {
            tstMethod(WolfSSL.TLSv1_ServerMethod(), "TLSv1_ServerMethod()");
            tstMethod(WolfSSL.TLSv1_ClientMethod(), "TLSv1_ClientMethod()");
        }
        if (enabledProtocols.contains("TLSv1.1")) {
            tstMethod(WolfSSL.TLSv1_1_ServerMethod(), "TLSv1_1_ServerMethod()");
            tstMethod(WolfSSL.TLSv1_1_ClientMethod(), "TLSv1_1_ClientMethod()");
        }
        if (enabledProtocols.contains("TLSv1.2")) {
            tstMethod(WolfSSL.TLSv1_2_ServerMethod(), "TLSv1_2_ServerMethod()");
            tstMethod(WolfSSL.TLSv1_2_ClientMethod(), "TLSv1_2_ClientMethod()");
        }
        if (enabledProtocols.contains("TLSv1.3")) {
            tstMethod(WolfSSL.TLSv1_3_ServerMethod(), "TLSv1_3_ServerMethod()");
            tstMethod(WolfSSL.TLSv1_3_ClientMethod(), "TLSv1_3_ClientMethod()");
        }
        if (enabledProtocols.contains("DTLSv1")) {
            tstMethod(WolfSSL.DTLSv1_ServerMethod(), "DTLSv1_ServerMethod()");
            tstMethod(WolfSSL.DTLSv1_ClientMethod(), "DTLSv1_ClientMethod()");
        }
        if (enabledProtocols.contains("DTLSv1.2")) {
            tstMethod(WolfSSL.DTLSv1_2_ServerMethod(),
                "DTLSv1_2_ServerMethod()");
            tstMethod(WolfSSL.DTLSv1_2_ClientMethod(),
                "DTLSv1_2_ClientMethod()");
        }
        if (enabledProtocols.contains("DTLSv1.3")) {
            tstMethod(WolfSSL.DTLSv1_3_ServerMethod(),
                "DTLSv1_3_ServerMethod()");
            tstMethod(WolfSSL.DTLSv1_3_ClientMethod(),
                "DTLSv1_3_ClientMethod()");
        }
        tstMethod(WolfSSL.SSLv23_ServerMethod(), "SSLv23_ServerMethod()");
        tstMethod(WolfSSL.SSLv23_ClientMethod(), "SSLv23_ClientMethod()");
    }

    private void tstMethod(long method, String name) {
        if (method == 0) {
            fail(name + " method test failed, method was null");
        } else if (method != WolfSSL.NOT_COMPILED_IN) {
            WolfSSL.nativeFree(method);
        }
    }

    @Test
    public void testGetCiphersAvailableIana() {
        String[] ciphers = WolfSSL.getCiphersAvailableIana(
                WolfSSL.TLS_VERSION.SSLv23);
        if (ciphers == null) {
            fail("available ciphers array was null");
        }
        if (ciphers.length == 0) {
            fail("available ciphers array length was zero");
        }

        /* Test all protocol versions. For each, if a non-null list is returned
         * it must not be empty and must not contain empty strings. A null
         * return is acceptable for protocol versions not compiled into native
         * wolfSSL. */
        for (WolfSSL.TLS_VERSION ver : WolfSSL.TLS_VERSION.values()) {
            if (ver == WolfSSL.TLS_VERSION.INVALID) {
                continue;
            }
            String[] verCiphers = WolfSSL.getCiphersAvailableIana(ver);
            if (verCiphers != null) {
                if (verCiphers.length == 0) {
                    fail("getCiphersAvailableIana(" + ver +
                        ") returned empty array");
                }
                for (int i = 0; i < verCiphers.length; i++) {
                    if (verCiphers[i] == null ||
                        verCiphers[i].isEmpty()) {
                        fail("getCiphersAvailableIana(" + ver +
                            ") contains null/empty cipher at index " + i);
                    }
                }
            }
        }
    }

    @Test
    public void test_WolfSSL_getLibVersionHex() {
        long verHex = WolfSSL.getLibVersionHex();
        if (verHex == 0 || verHex < 0) {
            fail("getting library version hex failed");
        }
    }

    @Test
    public void test_WolfSSL_getErrno() {
        /* Just make sure we don't seg fault or crash here */
        WolfSSL.getErrno();
    }

    @Test
    public void test_WolfSSL_getSNIFromBuffer() throws WolfSSLException {
        /* Minimal TLS 1.2 ClientHello with SNI extension for "www.example.com".
         * This is a hand crafted minimal valid ClientHello message. */
        String hostname = "www.example.com";
        byte[] hostBytes = hostname.getBytes(StandardCharsets.UTF_8);
        int hostLen = hostBytes.length;

        /* SNI extension: type(2) + len(2) + sni_list_len(2) + sni_type(1) +
         * sni_len(2) + sni_data */
        int sniExtLen = 2 + 2 + 2 + 1 + 2 + hostLen;
        /* Extensions block: ext_len(2) + sni_ext */
        int extBlockLen = 2 + sniExtLen;

        /* ClientHello body:
         *   version(2) + random(32) + sessId_len(1) + cipher_suites_len(2) +
         *   one_suite(2) + comp_len(1) + comp_null(1) + extensions */
        int chBodyLen = 2 + 32 + 1 + 2 + 2 + 1 + 1 + extBlockLen;

        /* Handshake header: type(1) + length(3) */
        int hsLen = 1 + 3 + chBodyLen;

        /* TLS record: type(1) + version(2) + length(2) */
        int totalLen = 1 + 2 + 2 + hsLen;

        byte[] clientHello = new byte[totalLen];
        int offset = 0;

        /* TLS record header */
        clientHello[offset++] = 0x16; /* handshake */
        clientHello[offset++] = 0x03; /* TLS 1.0 */
        clientHello[offset++] = 0x01;
        clientHello[offset++] = (byte)((hsLen >> 8) & 0xFF);
        clientHello[offset++] = (byte)(hsLen & 0xFF);

        /* Handshake header */
        clientHello[offset++] = 0x01; /* client_hello */
        clientHello[offset++] = 0x00; /* length (3B) */
        clientHello[offset++] = (byte)((chBodyLen >> 8) & 0xFF);
        clientHello[offset++] = (byte)(chBodyLen & 0xFF);

        /* ClientHello body */
        clientHello[offset++] = 0x03; /* TLS 1.2 */
        clientHello[offset++] = 0x03;

        /* 32 bytes random (zeros for test) */
        offset += 32;

        /* Session ID length = 0 */
        clientHello[offset++] = 0x00;

        /* Cipher suites: length=2, one suite */
        clientHello[offset++] = 0x00;
        clientHello[offset++] = 0x02;
        clientHello[offset++] = (byte)0xC0;
        clientHello[offset++] = 0x2F;

        /* Compression: length=1, null */
        clientHello[offset++] = 0x01;
        clientHello[offset++] = 0x00;

        /* Extensions length */
        int extTotalLen = sniExtLen;
        clientHello[offset++] = (byte)((extTotalLen >> 8) & 0xFF);
        clientHello[offset++] = (byte)(extTotalLen & 0xFF);

        /* SNI extension type = 0x0000 */
        clientHello[offset++] = 0x00;
        clientHello[offset++] = 0x00;

        /* SNI extension data length */
        int sniDataLen = 2 + 1 + 2 + hostLen;
        clientHello[offset++] = (byte)((sniDataLen >> 8) & 0xFF);
        clientHello[offset++] = (byte)(sniDataLen & 0xFF);

        /* SNI list length */
        int sniListLen = 1 + 2 + hostLen;
        clientHello[offset++] = (byte)((sniListLen >> 8) & 0xFF);
        clientHello[offset++] = (byte)(sniListLen & 0xFF);

        /* SNI type: host_name = 0 */
        clientHello[offset++] = 0x00;

        /* SNI host name length */
        clientHello[offset++] = (byte)((hostLen >> 8) & 0xFF);
        clientHello[offset++] = (byte)(hostLen & 0xFF);

        /* SNI host name data */
        System.arraycopy(hostBytes, 0, clientHello, offset, hostLen);
        offset += hostLen;

        byte[] sniOut = new byte[256];

        int ret = WolfSSL.getSNIFromBuffer(clientHello,
            (byte)WolfSSL.WOLFSSL_SNI_HOST_NAME, sniOut);

        Assume.assumeTrue(ret != WolfSSL.NOT_COMPILED_IN);

        if (ret <= 0) {
            fail("getSNIFromBuffer() returned: " + ret);
        }

        String extracted = new String(sniOut, 0, ret, StandardCharsets.UTF_8);
        if (!hostname.equals(extracted)) {
            fail("getSNIFromBuffer() expected [" + hostname + "] got [" +
                extracted + "]");
        }

        /* Test null clientHello throws exception */
        try {
            WolfSSL.getSNIFromBuffer(null, (byte)WolfSSL.WOLFSSL_SNI_HOST_NAME,
                sniOut);
            fail("Expected IllegalArgumentException for null clientHello");
        } catch (IllegalArgumentException e) {
            /* expected */
        }

        /* Test null sni output buffer throws exception */
        try {
            WolfSSL.getSNIFromBuffer(clientHello,
                (byte)WolfSSL.WOLFSSL_SNI_HOST_NAME, null);
            fail("Expected IllegalArgumentException for null sni");
        } catch (IllegalArgumentException e) {
            /* expected */
        }
    }

    @Test
    public void test_isLibraryLoadSkippedReturnsFalseByDefault() {
        /* Library was loaded normally in @BeforeClass, so
         * isLibraryLoadSkipped() should return false */
        assertFalse("isLibraryLoadSkipped() should be false when " +
            "library was loaded normally", WolfSSL.isLibraryLoadSkipped());
    }

    @Test
    public void test_SystemPropertyNotSetByDefault() {
        /* Verify property is not set by default in test env */
        String val = System.getProperty("wolfssl.skipLibraryLoad");
        assertNull("wolfssl.skipLibraryLoad should not be set by default", val);
    }

    @Test
    public void test_SettingPropertyAfterLoadHasNoEffect() {
        /* Setting the property after library has already been
         * loaded should not change isLibraryLoadSkipped() */
        try {
            System.setProperty("wolfssl.skipLibraryLoad", "true");

            assertFalse("isLibraryLoadSkipped() should still be " +
                "false after setting property post-load",
                WolfSSL.isLibraryLoadSkipped());

        } finally {
            System.clearProperty("wolfssl.skipLibraryLoad");
        }
    }

    @Test
    public void test_PQC_NamedGroup_Constants() {

        /* Values must match wolfssl/ssl.h enum exactly. Drift here would
         * cause silent codepoint mismatch. */
        assertEquals(512,   WolfSSL.WOLFSSL_ML_KEM_512);
        assertEquals(513,   WolfSSL.WOLFSSL_ML_KEM_768);
        assertEquals(514,   WolfSSL.WOLFSSL_ML_KEM_1024);

        assertEquals(4587,  WolfSSL.WOLFSSL_SECP256R1MLKEM768);
        assertEquals(4588,  WolfSSL.WOLFSSL_X25519MLKEM768);
        assertEquals(4589,  WolfSSL.WOLFSSL_SECP384R1MLKEM1024);

        assertEquals(12107, WolfSSL.WOLFSSL_SECP256R1MLKEM512);
        assertEquals(12108, WolfSSL.WOLFSSL_SECP384R1MLKEM768);
        assertEquals(12109, WolfSSL.WOLFSSL_SECP521R1MLKEM1024);
        assertEquals(12214, WolfSSL.WOLFSSL_X25519MLKEM512);
        assertEquals(12215, WolfSSL.WOLFSSL_X448MLKEM768);
    }

    @Test
    public void test_getNamedGroupFromString_PQC() {

        /* ML-KEM standalone: both compact ("MLKEMN") and FIPS 203 standard
         * name ("ML-KEM-N") spellings */
        assertEquals(WolfSSL.WOLFSSL_ML_KEM_512,
            WolfSSL.getNamedGroupFromString("MLKEM512"));
        assertEquals(WolfSSL.WOLFSSL_ML_KEM_512,
            WolfSSL.getNamedGroupFromString("ML-KEM-512"));
        assertEquals(WolfSSL.WOLFSSL_ML_KEM_768,
            WolfSSL.getNamedGroupFromString("MLKEM768"));
        assertEquals(WolfSSL.WOLFSSL_ML_KEM_768,
            WolfSSL.getNamedGroupFromString("ML-KEM-768"));
        assertEquals(WolfSSL.WOLFSSL_ML_KEM_1024,
            WolfSSL.getNamedGroupFromString("MLKEM1024"));
        assertEquals(WolfSSL.WOLFSSL_ML_KEM_1024,
            WolfSSL.getNamedGroupFromString("ML-KEM-1024"));

        /* IETF hybrids: IANA mixed-case ("SecP256r1MLKEM768") and the all caps
         * variants we accept */
        assertEquals(WolfSSL.WOLFSSL_X25519MLKEM768,
            WolfSSL.getNamedGroupFromString("X25519MLKEM768"));
        assertEquals(WolfSSL.WOLFSSL_SECP256R1MLKEM768,
            WolfSSL.getNamedGroupFromString("SecP256r1MLKEM768"));
        assertEquals(WolfSSL.WOLFSSL_SECP256R1MLKEM768,
            WolfSSL.getNamedGroupFromString("SECP256R1MLKEM768"));
        assertEquals(WolfSSL.WOLFSSL_SECP384R1MLKEM1024,
            WolfSSL.getNamedGroupFromString("SecP384r1MLKEM1024"));
        assertEquals(WolfSSL.WOLFSSL_SECP384R1MLKEM1024,
            WolfSSL.getNamedGroupFromString("SECP384R1MLKEM1024"));

        /* OQS hybrids */
        assertEquals(WolfSSL.WOLFSSL_SECP256R1MLKEM512,
            WolfSSL.getNamedGroupFromString("SECP256R1MLKEM512"));
        assertEquals(WolfSSL.WOLFSSL_SECP384R1MLKEM768,
            WolfSSL.getNamedGroupFromString("SECP384R1MLKEM768"));
        assertEquals(WolfSSL.WOLFSSL_SECP521R1MLKEM1024,
            WolfSSL.getNamedGroupFromString("SECP521R1MLKEM1024"));
        assertEquals(WolfSSL.WOLFSSL_X25519MLKEM512,
            WolfSSL.getNamedGroupFromString("X25519MLKEM512"));
        assertEquals(WolfSSL.WOLFSSL_X448MLKEM768,
            WolfSSL.getNamedGroupFromString("X448MLKEM768"));

        /* Matching is case insensitive: lowercase, uppercase, and mixed
         * case spellings of the same token all resolve to the same
         * constant. */
        assertEquals(WolfSSL.WOLFSSL_X25519MLKEM768,
            WolfSSL.getNamedGroupFromString("x25519mlkem768"));
        assertEquals(WolfSSL.WOLFSSL_SECP256R1MLKEM768,
            WolfSSL.getNamedGroupFromString("secp256r1mlkem768"));
        assertEquals(
            WolfSSL.getNamedGroupFromString("SECP256R1MLKEM768"),
            WolfSSL.getNamedGroupFromString("secp256r1mlkem768"));
        assertEquals(WolfSSL.WOLFSSL_SECP384R1MLKEM1024,
            WolfSSL.getNamedGroupFromString("secp384r1mlkem1024"));
        assertEquals(WolfSSL.WOLFSSL_ML_KEM_768,
            WolfSSL.getNamedGroupFromString("ml-kem-768"));
        assertEquals(
            WolfSSL.getNamedGroupFromString("ML-KEM-768"),
            WolfSSL.getNamedGroupFromString("ml-kem-768"));
        assertEquals(WolfSSL.WOLFSSL_ML_KEM_768,
            WolfSSL.getNamedGroupFromString("mlkem768"));
        assertEquals(WolfSSL.WOLFSSL_ML_KEM_768,
            WolfSSL.getNamedGroupFromString("Ml-Kem-768"));

        /* Unknown / typo / empty / null fall through to INVALID */
        assertEquals(WolfSSL.WOLFSSL_NAMED_GROUP_INVALID,
            WolfSSL.getNamedGroupFromString("X25519MLKEM"));
        assertEquals(WolfSSL.WOLFSSL_NAMED_GROUP_INVALID,
            WolfSSL.getNamedGroupFromString("nonsense"));
        assertEquals(WolfSSL.WOLFSSL_NAMED_GROUP_INVALID,
            WolfSSL.getNamedGroupFromString(""));
        assertEquals(WolfSSL.WOLFSSL_NAMED_GROUP_INVALID,
            WolfSSL.getNamedGroupFromString(null));

        /* Existing classical curves still resolve correctly, also case
         * insensitively. */
        assertEquals(WolfSSL.WOLFSSL_ECC_X25519,
            WolfSSL.getNamedGroupFromString("X25519"));
        assertEquals(WolfSSL.WOLFSSL_ECC_X25519,
            WolfSSL.getNamedGroupFromString("x25519"));
        assertEquals(WolfSSL.WOLFSSL_ECC_SECP256R1,
            WolfSSL.getNamedGroupFromString("secp256r1"));
        assertEquals(WolfSSL.WOLFSSL_ECC_SECP256R1,
            WolfSSL.getNamedGroupFromString("SECP256R1"));
    }

    @Test
    public void test_isPQCNamedGroup() {

        /* All PQC standalone + hybrids return true. */
        assertTrue(WolfSSL.isPQCNamedGroup(WolfSSL.WOLFSSL_ML_KEM_512));
        assertTrue(WolfSSL.isPQCNamedGroup(WolfSSL.WOLFSSL_ML_KEM_768));
        assertTrue(WolfSSL.isPQCNamedGroup(WolfSSL.WOLFSSL_ML_KEM_1024));
        assertTrue(WolfSSL.isPQCNamedGroup(
            WolfSSL.WOLFSSL_X25519MLKEM768));
        assertTrue(WolfSSL.isPQCNamedGroup(
            WolfSSL.WOLFSSL_SECP256R1MLKEM768));
        assertTrue(WolfSSL.isPQCNamedGroup(
            WolfSSL.WOLFSSL_SECP384R1MLKEM1024));
        assertTrue(WolfSSL.isPQCNamedGroup(
            WolfSSL.WOLFSSL_SECP256R1MLKEM512));
        assertTrue(WolfSSL.isPQCNamedGroup(
            WolfSSL.WOLFSSL_SECP384R1MLKEM768));
        assertTrue(WolfSSL.isPQCNamedGroup(
            WolfSSL.WOLFSSL_SECP521R1MLKEM1024));
        assertTrue(WolfSSL.isPQCNamedGroup(
            WolfSSL.WOLFSSL_X25519MLKEM512));
        assertTrue(WolfSSL.isPQCNamedGroup(WolfSSL.WOLFSSL_X448MLKEM768));

        /* Classical curves and FFDHE return false. */
        assertFalse(WolfSSL.isPQCNamedGroup(WolfSSL.WOLFSSL_ECC_X25519));
        assertFalse(WolfSSL.isPQCNamedGroup(WolfSSL.WOLFSSL_ECC_SECP256R1));
        assertFalse(WolfSSL.isPQCNamedGroup(WolfSSL.WOLFSSL_ECC_SECP384R1));
        assertFalse(WolfSSL.isPQCNamedGroup(WolfSSL.WOLFSSL_FFDHE_2048));

        /* Sentinel and out-of-range integers return false. */
        assertFalse(WolfSSL.isPQCNamedGroup(
            WolfSSL.WOLFSSL_NAMED_GROUP_INVALID));
        assertFalse(WolfSSL.isPQCNamedGroup(0));
        assertFalse(WolfSSL.isPQCNamedGroup(99999));
        assertFalse(WolfSSL.isPQCNamedGroup(-1));
    }

    @Test
    public void test_isECCNamedGroup() {

        /* Classic ECC curves return true, spanning the low and high ends
         * of the curve ID range (SECT, SECP, Brainpool, X25519/X448, SM2). */
        assertTrue(WolfSSL.isECCNamedGroup(WolfSSL.WOLFSSL_ECC_SECT163K1));
        assertTrue(WolfSSL.isECCNamedGroup(WolfSSL.WOLFSSL_ECC_SECP256R1));
        assertTrue(WolfSSL.isECCNamedGroup(WolfSSL.WOLFSSL_ECC_SECP384R1));
        assertTrue(WolfSSL.isECCNamedGroup(WolfSSL.WOLFSSL_ECC_SECP521R1));
        assertTrue(WolfSSL.isECCNamedGroup(
            WolfSSL.WOLFSSL_ECC_BRAINPOOLP512R1));
        assertTrue(WolfSSL.isECCNamedGroup(WolfSSL.WOLFSSL_ECC_X25519));
        assertTrue(WolfSSL.isECCNamedGroup(WolfSSL.WOLFSSL_ECC_X448));
        assertTrue(WolfSSL.isECCNamedGroup(WolfSSL.WOLFSSL_ECC_SM2P256V1));

        /* The whole registry range below the FFDHE block classifies as
         * ECC (RFC 7919 partition), including IANA-assigned curve IDs
         * without WOLFSSL_ECC_* constants yet: 31 is
         * brainpoolP256r1tls13 (RFC 8734), 34 is GC256A (RFC 9189), and
         * 255 is the top of the elliptic curve range. */
        assertTrue(WolfSSL.isECCNamedGroup(31));
        assertTrue(WolfSSL.isECCNamedGroup(34));
        assertTrue(WolfSSL.isECCNamedGroup(255));

        /* FFDHE groups and the reserved FFDHE block (256-511) return
         * false. */
        assertFalse(WolfSSL.isECCNamedGroup(WolfSSL.WOLFSSL_FFDHE_2048));
        assertFalse(WolfSSL.isECCNamedGroup(WolfSSL.WOLFSSL_FFDHE_8192));
        assertFalse(WolfSSL.isECCNamedGroup(511));

        /* PQC standalone and hybrid groups return false, including
         * hybrids with an ECDHE component. */
        assertFalse(WolfSSL.isECCNamedGroup(WolfSSL.WOLFSSL_ML_KEM_768));
        assertFalse(WolfSSL.isECCNamedGroup(
            WolfSSL.WOLFSSL_X25519MLKEM768));
        assertFalse(WolfSSL.isECCNamedGroup(
            WolfSSL.WOLFSSL_SECP256R1MLKEM768));

        /* Sentinel and out-of-range integers return false. */
        assertFalse(WolfSSL.isECCNamedGroup(
            WolfSSL.WOLFSSL_NAMED_GROUP_INVALID));
        assertFalse(WolfSSL.isECCNamedGroup(0));
        assertFalse(WolfSSL.isECCNamedGroup(-1));
    }

    @Test
    public void test_PQC_FeatureDetect_NativeReturns() {

        /* Each native call should be reachable and return a boolean
         * consistent with the build. The only invariant we can assert is
         * that native calls returned without crashing. Reference variables
         * to silence "unused" warnings on older toolchains. */
        boolean mlkem  = WolfSSL.MLKEMEnabled();
        boolean mldsa  = WolfSSL.MLDSAEnabled();
        boolean oldIds = WolfSSL.MLKEMOldIdsEnabled();

        if (mlkem || mldsa || oldIds) {
            /* nothing */
        }
    }

    @Test
    public void test_SessionCerts_FeatureDetect_NativeReturns() {

        /* Native call should be reachable, a broken JNI binding shows up
         * as UnsatisfiedLinkError. */
        boolean sessionCerts = WolfSSL.sessionCertsEnabled();

        if (sessionCerts) {
            /* N/A, keep to prevent unused var warning */
        }
    }

    /* Logging callback used by the setLoggingCb test. Uses a shared static
     * counter so invocations across swapped instances accumulate. */
    static class TestLoggingCallback implements WolfSSLLoggingCallback {
        static final AtomicLong count = new AtomicLong(0);
        public void loggingCallback(int logLevel, String logMessage) {
            count.incrementAndGet();
        }
    }

    @Test
    public void test_WolfSSL_setLoggingCb() throws InterruptedException {

        int ret;

        /* Return is SSL_ERROR_NONE on a debug build, else NOT_COMPILED_IN. */
        ret = WolfSSL.setLoggingCb(new TestLoggingCallback());
        if (ret != WolfSSL.SSL_ERROR_NONE && ret != WolfSSL.NOT_COMPILED_IN) {
            fail("WolfSSL.setLoggingCb() returned unexpected value: " + ret);
        }

        /* Re-register a different callback, releases the prior ref. */
        ret = WolfSSL.setLoggingCb(new TestLoggingCallback());
        if (ret != WolfSSL.SSL_ERROR_NONE && ret != WolfSSL.NOT_COMPILED_IN) {
            fail("WolfSSL.setLoggingCb() re-register returned: " + ret);
        }

        ret = WolfSSL.setLoggingCb(null);
        if (ret != WolfSSL.SSL_ERROR_NONE && ret != WolfSSL.NOT_COMPILED_IN) {
            fail("WolfSSL.setLoggingCb(null) returned unexpected value: " +
                ret);
        }

        WolfSSL.debuggingON();

        /* Concurrency stress: writers swap and clear the callback while drivers
         * make native calls that log, firing NativeLoggingCallback during the
         * swap/free. Exercises both the g_loggingCbIfaceObj mutex (no jobject
         * UAF) and one-time native registration (setLoggingCb(null) never nulls
         * native LogFunction). Passing with no JVM abort is the assertion. */
        final int numThreads = 8;
        final int iterations = 500;
        final AtomicReference<Throwable> firstError =
            new AtomicReference<Throwable>();
        Thread[] threads = new Thread[numThreads];

        for (int i = 0; i < numThreads; i++) {
            final int id = i;
            threads[i] = new Thread(new Runnable() {
                public void run() {
                    String role = ((id % 2) == 0) ? "writer" : "driver";
                    try {
                        for (int j = 0; j < iterations; j++) {
                            if ((id % 2) == 0) {
                                /* writer: swap in a callback, then clear it */
                                WolfSSL.setLoggingCb(new TestLoggingCallback());
                                WolfSSL.setLoggingCb(null);
                            }
                            else {
                                /* driver: native call that logs on debug */
                                long m = WolfSSL.SSLv23_ClientMethod();
                                if (m != 0 && m != WolfSSL.NOT_COMPILED_IN) {
                                    WolfSSL.nativeFree(m);
                                }
                            }
                        }
                    } catch (Throwable t) {
                        firstError.compareAndSet(null,
                            new Exception("in " + role + " thread", t));
                    }
                }
            });
        }

        for (int i = 0; i < numThreads; i++) {
            threads[i].start();
        }
        for (int i = 0; i < numThreads; i++) {
            threads[i].join();
        }

        WolfSSL.debuggingOFF();

        /* leave unregistered for other tests */
        WolfSSL.setLoggingCb(null);

        Throwable err = firstError.get();
        if (err != null) {
            AssertionError ae = new AssertionError(
                "concurrent setLoggingCb() threw " + err.getMessage());
            ae.initCause(err);
            throw ae;
        }
    }

    /* Test that NativeLoggingCallback dispatches to Java. Skips on builds
     * without debug logging, or where WOLFSSL_ENTER trace messages are
     * compiled out (ex: WOLFSSL_DEBUG_ERRORS_ONLY), rather than failing. */
    @Test
    public void test_WolfSSL_setLoggingCbDispatch() {

        int ret = WolfSSL.setLoggingCb(new TestLoggingCallback());
        Assume.assumeTrue("debug logging not compiled in",
            ret == WolfSSL.SSL_ERROR_NONE);

        WolfSSL.debuggingON();
        TestLoggingCallback.count.set(0);
        long m = WolfSSL.SSLv23_ClientMethod();
        if (m != 0 && m != WolfSSL.NOT_COMPILED_IN) {
            WolfSSL.nativeFree(m);
        }
        WolfSSL.debuggingOFF();
        WolfSSL.setLoggingCb(null);

        /* No message means this build compiled out trace logging, skip. */
        Assume.assumeTrue("no trace messages emitted by this build",
            TestLoggingCallback.count.get() > 0);
    }

    /* FIPS error callback used by the setFIPSCb test. */
    static class TestFIPSErrorCallback implements WolfSSLFIPSErrorCallback {
        public void errorCallback(int ok, int err, String hash) {
        }
    }

    /* setFIPSCb() must register, re-register (freeing prior global ref under
     * the FIPS callback mutex), and deregister without error. */
    @Test
    public void test_WolfSSL_setFIPSCb() {

        int ret = WolfSSL.setFIPSCb(new TestFIPSErrorCallback());
        if (ret != WolfSSL.SSL_SUCCESS && ret != WolfSSL.NOT_COMPILED_IN) {
            fail("WolfSSL.setFIPSCb() returned unexpected value: " + ret);
        }

        /* re-register a different callback, releases the prior ref */
        ret = WolfSSL.setFIPSCb(new TestFIPSErrorCallback());
        if (ret != WolfSSL.SSL_SUCCESS && ret != WolfSSL.NOT_COMPILED_IN) {
            fail("WolfSSL.setFIPSCb() re-register returned: " + ret);
        }

        /* deregister for other tests */
        ret = WolfSSL.setFIPSCb(null);
        if (ret != WolfSSL.SSL_SUCCESS && ret != WolfSSL.NOT_COMPILED_IN) {
            fail("WolfSSL.setFIPSCb(null) returned: " + ret);
        }
    }
}
