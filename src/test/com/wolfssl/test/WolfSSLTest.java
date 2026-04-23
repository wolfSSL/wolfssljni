/* WolfSSLTest.java
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLException;

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
}
