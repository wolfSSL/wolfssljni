/* WolfSSLNameConstraintsTest.java
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

import java.util.List;

import org.junit.Test;
import org.junit.BeforeClass;
import static org.junit.Assert.*;

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLCertificate;
import com.wolfssl.WolfSSLException;
import com.wolfssl.WolfSSLNameConstraints;
import com.wolfssl.WolfSSLGeneralName;

/**
 * JUnit tests for WolfSSLNameConstraints and WolfSSLGeneralName classes.
 *
 * Tests the X.509 Name Constraints extension (OID 2.5.29.30) support.
 *
 * @author wolfSSL
 */
public class WolfSSLNameConstraintsTest {

    /* Test certificate with email name constraint (.wolfssl.com) */
    public static String certWithNC = "examples/certs/test/cert-ext-nc.pem";

    /* Test certificate with IP address name constraint (192.168.1.0/24) */
    public static String certWithNCIP = "examples/certs/test/cert-ext-ncip.pem";

    /* Test certificate with DNS name constraint (wolfssl.com, example.com) */
    public static String certWithNCDNS =
        "examples/certs/test/cert-ext-ncdns.pem";

    /* Test certificate with combined DNS and URI constraints (.wolfssl.com) */
    public static String certWithNCCombined =
        "examples/certs/test/cert-ext-nc-combined.pem";

    /* Test certificate with mixed permitted/excluded constraints */
    public static String certWithNCMulti =
        "examples/certs/test/cert-ext-ncmulti.pem";

    /* Test certificate without name constraints */
    public static String certWithoutNC = "examples/certs/ca-cert.pem";

    @BeforeClass
    public static void setUp() throws WolfSSLException {

        System.out.println("WolfSSLNameConstraints Class");

        try {
            WolfSSL.loadLibrary();
        } catch (UnsatisfiedLinkError ule) {
            fail("Failed to load native JNI library");
        }

        certWithNC = WolfSSLTestCommon.getPath(certWithNC);
        certWithNCIP = WolfSSLTestCommon.getPath(certWithNCIP);
        certWithNCDNS = WolfSSLTestCommon.getPath(certWithNCDNS);
        certWithNCCombined = WolfSSLTestCommon.getPath(certWithNCCombined);
        certWithNCMulti = WolfSSLTestCommon.getPath(certWithNCMulti);
        certWithoutNC = WolfSSLTestCommon.getPath(certWithoutNC);
    }

    @Test
    public void testGetNameConstraintsWithNC() throws WolfSSLException {

        System.out.print("\tgetNameConstraints() with ext");

        if (!WolfSSL.NameConstraintsEnabled()) {
            System.out.println("\t... skipped (not compiled in)");
            return;
        }

        WolfSSLCertificate cert = null;
        WolfSSLNameConstraints nc = null;
        try {
            cert = new WolfSSLCertificate(certWithNC,
                WolfSSL.SSL_FILETYPE_PEM);
            assertNotNull("Certificate should not be null", cert);

            nc = cert.getNameConstraints();
            assertNotNull("Name constraints should not be null", nc);

            /* Should have permitted subtrees */
            List<WolfSSLGeneralName> permitted = nc.getPermittedSubtrees();
            assertNotNull("Permitted subtrees should not be null", permitted);
            assertTrue("Should have at least one permitted subtree",
                permitted.size() > 0);

            /* Check the first permitted entry */
            WolfSSLGeneralName gn = permitted.get(0);
            assertNotNull("GeneralName should not be null", gn);

            /* cert-ext-nc.pem has EMAIL constraint */
            assertEquals("Expected EMAIL type",
                WolfSSLGeneralName.GEN_EMAIL, gn.getType());
            assertNotNull("Value should not be null", gn.getValue());
            assertTrue("Value should contain wolfssl.com",
                gn.getValue().contains("wolfssl.com"));

            System.out.println("\t... passed");
        } finally {
            if (nc != null) {
                nc.free();
            }
            if (cert != null) {
                cert.free();
            }
        }
    }

    @Test
    public void testGetNameConstraintsWithoutNC() throws WolfSSLException {

        System.out.print("\tgetNameConstraints() no ext");

        if (!WolfSSL.NameConstraintsEnabled()) {
            System.out.println("\t... skipped (not compiled in)");
            return;
        }

        WolfSSLCertificate cert = null;
        try {
            cert = new WolfSSLCertificate(certWithoutNC,
                WolfSSL.SSL_FILETYPE_PEM);
            assertNotNull("Certificate should not be null", cert);

            WolfSSLNameConstraints nc = cert.getNameConstraints();

            /* Should be null for cert without name constraints extension */
            assertNull("Name constraints should be null for cert without NC",
                nc);

            System.out.println("\t... passed");
        } finally {
            if (cert != null) {
                cert.free();
            }
        }
    }

    @Test
    public void testGetNameConstraintsIPAddress() throws WolfSSLException {

        System.out.print("\tgetNameConstraints() IP address");

        if (!WolfSSL.NameConstraintsEnabled()) {
            System.out.println("\t... skipped (not compiled in)");
            return;
        }

        WolfSSLCertificate cert = null;
        WolfSSLNameConstraints nc = null;
        try {
            cert = new WolfSSLCertificate(certWithNCIP,
                WolfSSL.SSL_FILETYPE_PEM);
            assertNotNull("Certificate should not be null", cert);

            nc = cert.getNameConstraints();
            assertNotNull("Name constraints should not be null", nc);

            List<WolfSSLGeneralName> permitted = nc.getPermittedSubtrees();
            assertNotNull("Permitted subtrees should not be null", permitted);
            assertTrue("Should have at least one permitted subtree",
                permitted.size() > 0);

            WolfSSLGeneralName gn = permitted.get(0);

            assertEquals("Expected IP address type",
                WolfSSLGeneralName.GEN_IPADD, gn.getType());
            assertNotNull("IP value should not be null", gn.getValue());

            /* IP constraint should be formatted as IP/mask */
            String value = gn.getValue();
            assertTrue("IP constraint should contain network address",
                value.contains("192.168.1.0") || value.contains(":"));

            System.out.println("\t... passed");
        } finally {
            if (nc != null) {
                nc.free();
            }
            if (cert != null) {
                cert.free();
            }
        }
    }

    @Test
    public void testGeneralNameTypes() throws WolfSSLException {

        System.out.print("\tGeneralName type constants");

        /* Verify type constants match RFC 5280 */
        assertEquals("GEN_OTHERNAME", 0, WolfSSLGeneralName.GEN_OTHERNAME);
        assertEquals("GEN_EMAIL", 1, WolfSSLGeneralName.GEN_EMAIL);
        assertEquals("GEN_DNS", 2, WolfSSLGeneralName.GEN_DNS);
        assertEquals("GEN_X400", 3, WolfSSLGeneralName.GEN_X400);
        assertEquals("GEN_DIRNAME", 4, WolfSSLGeneralName.GEN_DIRNAME);
        assertEquals("GEN_EDIPARTY", 5, WolfSSLGeneralName.GEN_EDIPARTY);
        assertEquals("GEN_URI", 6, WolfSSLGeneralName.GEN_URI);
        assertEquals("GEN_IPADD", 7, WolfSSLGeneralName.GEN_IPADD);
        assertEquals("GEN_RID", 8, WolfSSLGeneralName.GEN_RID);

        System.out.println("\t... passed");
    }

    @Test
    public void testGeneralNameTypeName() {

        System.out.print("\tGeneralName.getTypeName()");

        WolfSSLGeneralName gn = new WolfSSLGeneralName(
            WolfSSLGeneralName.GEN_DNS, "example.com");

        assertEquals("DNS", gn.getTypeName());
        assertEquals(WolfSSLGeneralName.GEN_DNS, gn.getType());
        assertEquals("example.com", gn.getValue());
        assertEquals("DNS:example.com", gn.toString());

        System.out.println("\t... passed");
    }

    @Test
    public void testCheckDnsNamePermitted() throws WolfSSLException {

        System.out.print("\tcheckDnsName() permitted");

        if (!WolfSSL.NameConstraintsEnabled()) {
            System.out.println("\t... skipped (not compiled in)");
            return;
        }

        WolfSSLCertificate cert = null;
        WolfSSLNameConstraints nc = null;
        try {
            cert = new WolfSSLCertificate(certWithNC,
                WolfSSL.SSL_FILETYPE_PEM);
            nc = cert.getNameConstraints();
            assertNotNull("Name constraints should not be null", nc);

            /* cert-ext-nc.pem has EMAIL constraint for wolfssl.com,
             * but no DNS constraints, so all DNS names should pass */
            assertTrue("DNS name should be permitted when no DNS constraint",
                nc.checkDnsName("www.example.com"));

            System.out.println("\t... passed");
        } finally {
            if (nc != null) {
                nc.free();
            }
            if (cert != null) {
                cert.free();
            }
        }
    }

    @Test
    public void testCheckEmailPermitted() throws WolfSSLException {

        System.out.print("\tcheckEmail() permitted");

        if (!WolfSSL.NameConstraintsEnabled()) {
            System.out.println("\t\t... skipped (not compiled in)");
            return;
        }

        WolfSSLCertificate cert = null;
        WolfSSLNameConstraints nc = null;
        try {
            cert = new WolfSSLCertificate(certWithNC,
                WolfSSL.SSL_FILETYPE_PEM);
            nc = cert.getNameConstraints();
            assertNotNull("Name constraints should not be null", nc);

            /* cert-ext-nc.pem has permitted EMAIL constraint ".wolfssl.com"
             * (with leading dot). Per RFC 5280, a leading dot constraint
             * only matches subdomains, NOT the exact domain. */
            assertFalse("Email @wolfssl.com should NOT match .wolfssl.com",
                nc.checkEmail("user@wolfssl.com"));
            assertTrue("Email @sub.wolfssl.com should be permitted",
                nc.checkEmail("user@sub.wolfssl.com"));
            assertTrue("Deeper subdomain should also be permitted",
                nc.checkEmail("user@a.b.wolfssl.com"));

            System.out.println("\t\t... passed");
        } finally {
            if (nc != null) {
                nc.free();
            }
            if (cert != null) {
                cert.free();
            }
        }
    }

    @Test
    public void testCheckEmailNotPermitted() throws WolfSSLException {

        System.out.print("\tcheckEmail() not permitted");

        if (!WolfSSL.NameConstraintsEnabled()) {
            System.out.println("\t... skipped (not compiled in)");
            return;
        }

        WolfSSLCertificate cert = null;
        WolfSSLNameConstraints nc = null;
        try {
            cert = new WolfSSLCertificate(certWithNC,
                WolfSSL.SSL_FILETYPE_PEM);
            nc = cert.getNameConstraints();
            assertNotNull("Name constraints should not be null", nc);

            /* Email outside wolfssl.com domain should not be permitted */
            assertFalse("Email @other.com should not be permitted",
                nc.checkEmail("user@other.com"));
            assertFalse("Email @notwolfssl.com should not be permitted",
                nc.checkEmail("user@notwolfssl.com"));

            System.out.println("\t... passed");
        } finally {
            if (nc != null) {
                nc.free();
            }
            if (cert != null) {
                cert.free();
            }
        }
    }

    @Test
    public void testCheckNameWithNullArgument() throws WolfSSLException {

        System.out.print("\tcheckName() null argument");

        if (!WolfSSL.NameConstraintsEnabled()) {
            System.out.println("\t... skipped (not compiled in)");
            return;
        }

        WolfSSLCertificate cert = null;
        WolfSSLNameConstraints nc = null;
        try {
            cert = new WolfSSLCertificate(certWithNC,
                WolfSSL.SSL_FILETYPE_PEM);
            nc = cert.getNameConstraints();
            assertNotNull("Name constraints should not be null", nc);

            try {
                nc.checkName(WolfSSLGeneralName.GEN_DNS, null);
                fail("Should throw IllegalArgumentException for null name");
            } catch (IllegalArgumentException e) {
                /* Expected */
            }

            System.out.println("\t... passed");
        } finally {
            if (nc != null) {
                nc.free();
            }
            if (cert != null) {
                cert.free();
            }
        }
    }

    @Test
    public void testNameConstraintsFree() throws WolfSSLException {

        System.out.print("\tNameConstraints.free()");

        if (!WolfSSL.NameConstraintsEnabled()) {
            System.out.println("\t\t... skipped (not compiled in)");
            return;
        }

        WolfSSLCertificate cert = null;
        WolfSSLNameConstraints nc = null;
        try {
            cert = new WolfSSLCertificate(certWithNC,
                WolfSSL.SSL_FILETYPE_PEM);
            nc = cert.getNameConstraints();
            assertNotNull("Name constraints should not be null", nc);

            /* Free should not throw */
            nc.free();

            /* Double free should not throw */
            nc.free();

            /* Access after free should throw IllegalStateException */
            try {
                nc.getPermittedSubtrees();
                fail("Should throw IllegalStateException after free");
            } catch (IllegalStateException e) {
                /* Expected */
            }

            System.out.println("\t\t... passed");
        } finally {
            /* nc already freed in test, but safe due to double-free handling */
            if (cert != null) {
                cert.free();
            }
        }
    }

    @Test
    public void testExcludedSubtrees() throws WolfSSLException {

        System.out.print("\tgetExcludedSubtrees()");

        if (!WolfSSL.NameConstraintsEnabled()) {
            System.out.println("\t\t... skipped (not compiled in)");
            return;
        }

        WolfSSLCertificate cert = null;
        WolfSSLNameConstraints nc = null;
        try {
            cert = new WolfSSLCertificate(certWithNC,
                WolfSSL.SSL_FILETYPE_PEM);
            nc = cert.getNameConstraints();
            assertNotNull("Name constraints should not be null", nc);

            /* Get excluded subtrees, may be empty but should not be null */
            List<WolfSSLGeneralName> excluded = nc.getExcludedSubtrees();
            assertNotNull("Excluded subtrees list should not be null",
                excluded);

            /* List should be unmodifiable */
            try {
                excluded.add(null);
                fail("List should be unmodifiable");
            } catch (UnsupportedOperationException e) {
                /* Expected */
            }

            System.out.println("\t\t... passed");
        } finally {
            if (nc != null) {
                nc.free();
            }
            if (cert != null) {
                cert.free();
            }
        }
    }

    @Test
    public void testPermittedSubtreesUnmodifiable() throws WolfSSLException {

        System.out.print("\tSubtrees unmodifiable");

        if (!WolfSSL.NameConstraintsEnabled()) {
            System.out.println("\t\t... skipped (not compiled in)");
            return;
        }

        WolfSSLCertificate cert = null;
        WolfSSLNameConstraints nc = null;
        try {
            cert = new WolfSSLCertificate(certWithNC,
                WolfSSL.SSL_FILETYPE_PEM);
            nc = cert.getNameConstraints();
            assertNotNull("Name constraints should not be null", nc);

            List<WolfSSLGeneralName> permitted = nc.getPermittedSubtrees();
            assertNotNull(permitted);

            /* List should be unmodifiable */
            try {
                permitted.clear();
                fail("List should be unmodifiable");
            } catch (UnsupportedOperationException e) {
                /* Expected */
            }

            System.out.println("\t\t... passed");
        } finally {
            if (nc != null) {
                nc.free();
            }
            if (cert != null) {
                cert.free();
            }
        }
    }

    @Test
    public void testCheckIpAddressPermitted() throws WolfSSLException {
        System.out.print("\tcheckIpAddress() permitted");

        if (!WolfSSL.NameConstraintsEnabled()) {
            System.out.println("\t... skipped (not compiled in)");
            return;
        }

        WolfSSLCertificate cert = null;
        WolfSSLNameConstraints nc = null;
        try {
            cert = new WolfSSLCertificate(certWithNCIP,
                WolfSSL.SSL_FILETYPE_PEM);
            nc = cert.getNameConstraints();
            assertNotNull("Name constraints should not be null", nc);

            /* cert-ext-ncip.pem has permitted IP 192.168.1.0/255.255.255.0 */
            assertTrue("IP 192.168.1.50 should be permitted",
                nc.checkIpAddress("192.168.1.50"));
            assertTrue("IP 192.168.1.1 should be permitted",
                nc.checkIpAddress("192.168.1.1"));
            assertTrue("IP 192.168.1.254 should be permitted",
                nc.checkIpAddress("192.168.1.254"));

            System.out.println("\t... passed");
        } finally {
            if (nc != null) {
                nc.free();
            }
            if (cert != null) {
                cert.free();
            }
        }
    }

    @Test
    public void testCheckIpAddressNotPermitted() throws WolfSSLException {
        System.out.print("\tcheckIpAddress() not permitted");

        if (!WolfSSL.NameConstraintsEnabled()) {
            System.out.println("\t... skipped (not compiled in)");
            return;
        }

        WolfSSLCertificate cert = null;
        WolfSSLNameConstraints nc = null;
        try {
            cert = new WolfSSLCertificate(certWithNCIP,
                WolfSSL.SSL_FILETYPE_PEM);
            nc = cert.getNameConstraints();
            assertNotNull("Name constraints should not be null", nc);

            /* IP outside 192.168.1.0/24 should not be permitted */
            assertFalse("IP 192.168.2.1 should not be permitted",
                nc.checkIpAddress("192.168.2.1"));
            assertFalse("IP 10.0.0.1 should not be permitted",
                nc.checkIpAddress("10.0.0.1"));
            assertFalse("IP 8.8.8.8 should not be permitted",
                nc.checkIpAddress("8.8.8.8"));

            System.out.println("\t... passed");
        } finally {
            if (nc != null) {
                nc.free();
            }
            if (cert != null) {
                cert.free();
            }
        }
    }

    @Test
    public void testIpConstraintValueFormat() throws WolfSSLException {
        System.out.print("\tIP constraint value format");

        if (!WolfSSL.NameConstraintsEnabled()) {
            System.out.println("\t... skipped (not compiled in)");
            return;
        }

        WolfSSLCertificate cert = null;
        WolfSSLNameConstraints nc = null;
        try {
            cert = new WolfSSLCertificate(certWithNCIP,
                WolfSSL.SSL_FILETYPE_PEM);
            nc = cert.getNameConstraints();
            assertNotNull("Name constraints should not be null", nc);

            List<WolfSSLGeneralName> permitted = nc.getPermittedSubtrees();
            assertNotNull(permitted);
            assertTrue("Should have IP constraint", permitted.size() > 0);

            WolfSSLGeneralName gn = permitted.get(0);

            assertEquals("Should be IP type",
                WolfSSLGeneralName.GEN_IPADD, gn.getType());

            /* Verify IP/mask format for IPv4 */
            String value = gn.getValue();
            assertNotNull("IP value should not be null", value);
            assertTrue("IPv4 should have IP/mask format with slash",
                value.contains("/"));
            assertEquals("Should be 192.168.1.0/255.255.255.0",
                "192.168.1.0/255.255.255.0", value);

            System.out.println("\t... passed");
        } finally {
            if (nc != null) {
                nc.free();
            }
            if (cert != null) {
                cert.free();
            }
        }
    }

    @Test
    public void testCheckUriNoConstraint() throws WolfSSLException {
        System.out.print("\tcheckUri() no constraint");

        if (!WolfSSL.NameConstraintsEnabled()) {
            System.out.println("\t... skipped (not compiled in)");
            return;
        }

        WolfSSLCertificate cert = null;
        WolfSSLNameConstraints nc = null;
        try {
            /* Test with cert that has no URI constraint, should allow all */
            cert = new WolfSSLCertificate(certWithNC,
                WolfSSL.SSL_FILETYPE_PEM);
            nc = cert.getNameConstraints();
            assertNotNull("Name constraints should not be null", nc);

            /* No URI constraint means all URIs should be permitted */
            assertTrue("URI should be permitted when no URI constraint",
                nc.checkUri("https://example.com/path"));
            assertTrue("Any URI should be permitted",
                nc.checkUri("http://wolfssl.com/test"));

            System.out.println("\t... passed");
        } finally {
            if (nc != null) {
                nc.free();
            }
            if (cert != null) {
                cert.free();
            }
        }
    }

    @Test
    public void testCheckNameGeneric() throws WolfSSLException {
        System.out.print("\tcheckName() generic type");

        if (!WolfSSL.NameConstraintsEnabled()) {
            System.out.println("\t... skipped (not compiled in)");
            return;
        }

        WolfSSLCertificate cert = null;
        WolfSSLNameConstraints nc = null;
        try {
            cert = new WolfSSLCertificate(certWithNCIP,
                WolfSSL.SSL_FILETYPE_PEM);
            nc = cert.getNameConstraints();
            assertNotNull("Name constraints should not be null", nc);

            /* Test checkName with explicit type parameter */
            assertTrue("checkName with GEN_IPADD should work",
                nc.checkName(WolfSSLGeneralName.GEN_IPADD, "192.168.1.100"));
            assertFalse("checkName with GEN_IPADD outside range",
                nc.checkName(WolfSSLGeneralName.GEN_IPADD, "10.0.0.1"));

            /* DNS should be permitted since no DNS constraint exists */
            assertTrue("checkName with GEN_DNS should be permitted",
                nc.checkName(WolfSSLGeneralName.GEN_DNS, "www.example.com"));

            System.out.println("\t... passed");
        } finally {
            if (nc != null) {
                nc.free();
            }
            if (cert != null) {
                cert.free();
            }
        }
    }

    @Test
    public void testIpSubnetBoundaries() throws WolfSSLException {
        System.out.print("\tIP subnet boundary cases");

        if (!WolfSSL.NameConstraintsEnabled()) {
            System.out.println("\t... skipped (not compiled in)");
            return;
        }

        WolfSSLCertificate cert = null;
        WolfSSLNameConstraints nc = null;
        try {
            cert = new WolfSSLCertificate(certWithNCIP,
                WolfSSL.SSL_FILETYPE_PEM);
            nc = cert.getNameConstraints();
            assertNotNull("Name constraints should not be null", nc);

            /* Test subnet boundaries for 192.168.1.0/24 */

            /* Network address, typically not a valid host but in range */
            assertTrue("Network address 192.168.1.0 should be in range",
                nc.checkIpAddress("192.168.1.0"));

            /* Broadcast address, in range */
            assertTrue("Broadcast 192.168.1.255 should be in range",
                nc.checkIpAddress("192.168.1.255"));

            /* Just outside the range */
            assertFalse("192.168.0.255 should be outside range",
                nc.checkIpAddress("192.168.0.255"));
            assertFalse("192.168.2.0 should be outside range",
                nc.checkIpAddress("192.168.2.0"));

            System.out.println("\t... passed");
        } finally {
            if (nc != null) {
                nc.free();
            }
            if (cert != null) {
                cert.free();
            }
        }
    }

    @Test
    public void testIterateAllSubtrees() throws WolfSSLException {
        System.out.print("\tIterate all subtrees");

        if (!WolfSSL.NameConstraintsEnabled()) {
            System.out.println("\t\t... skipped (not compiled in)");
            return;
        }

        WolfSSLCertificate cert = null;
        WolfSSLNameConstraints nc = null;
        try {
            cert = new WolfSSLCertificate(certWithNC,
                WolfSSL.SSL_FILETYPE_PEM);
            nc = cert.getNameConstraints();
            assertNotNull("Name constraints should not be null", nc);

            /* Iterate permitted subtrees */
            List<WolfSSLGeneralName> permitted = nc.getPermittedSubtrees();
            for (WolfSSLGeneralName gn : permitted) {
                assertNotNull("GeneralName should not be null", gn);

                int type = gn.getType();
                String value = gn.getValue();
                String typeName = gn.getTypeName();

                assertTrue("Type should be valid", type >= 0 && type <= 8);
                assertNotNull("Value should not be null", value);
                assertNotNull("Type name should not be null", typeName);

                /* Verify toString works */
                String str = gn.toString();
                assertTrue("toString should contain type and value",
                    str.contains(typeName) && str.contains(value));
            }

            /* Iterate excluded subtrees */
            List<WolfSSLGeneralName> excluded = nc.getExcludedSubtrees();
            for (WolfSSLGeneralName gn : excluded) {
                assertNotNull("Excluded GeneralName should not be null", gn);
            }

            System.out.println("\t\t... passed");
        } finally {
            if (nc != null) {
                nc.free();
            }
            if (cert != null) {
                cert.free();
            }
        }
    }

    @Test
    public void testDnsConstraintEnforcement() throws WolfSSLException {
        System.out.print("\tDNS constraint enforcement");

        if (!WolfSSL.NameConstraintsEnabled()) {
            System.out.println("\t... skipped (not compiled in)");
            return;
        }

        WolfSSLCertificate cert = null;
        WolfSSLNameConstraints nc = null;
        try {
            /* Use dotted DNS cert (.wolfssl.com) which matches subdomains */
            cert = new WolfSSLCertificate(certWithNCCombined,
                WolfSSL.SSL_FILETYPE_PEM);
            nc = cert.getNameConstraints();
            assertNotNull("Name constraints should not be null", nc);

            /* Cert has permitted DNS:.wolfssl.com (with leading dot)
             * Per RFC 5280, leading dot matches subdomains only */

            /* Subdomains should be permitted */
            assertTrue("www.wolfssl.com should be permitted",
                nc.checkDnsName("www.wolfssl.com"));
            assertTrue("mail.wolfssl.com should be permitted",
                nc.checkDnsName("mail.wolfssl.com"));
            assertTrue("deep.sub.wolfssl.com should be permitted",
                nc.checkDnsName("deep.sub.wolfssl.com"));

            /* Exact domain should not match .wolfssl.com per RFC 5280 */
            assertFalse("wolfssl.com should NOT match .wolfssl.com",
                nc.checkDnsName("wolfssl.com"));

            /* Other domains should not be permitted */
            assertFalse("example.com should not be permitted",
                nc.checkDnsName("example.com"));
            assertFalse("notwolfssl.com should not be permitted",
                nc.checkDnsName("notwolfssl.com"));

            System.out.println("\t... passed");
        } finally {
            if (nc != null) {
                nc.free();
            }
            if (cert != null) {
                cert.free();
            }
        }
    }

    @Test
    public void testUriConstraintEnforcement() throws WolfSSLException {
        System.out.print("\tURI constraint enforcement");

        if (!WolfSSL.NameConstraintsEnabled()) {
            System.out.println("\t... skipped (not compiled in)");
            return;
        }

        WolfSSLCertificate cert = null;
        WolfSSLNameConstraints nc = null;
        try {
            cert = new WolfSSLCertificate(certWithNCCombined,
                WolfSSL.SSL_FILETYPE_PEM);
            nc = cert.getNameConstraints();
            assertNotNull("Name constraints should not be null", nc);

            /* Cert has permitted URI:.wolfssl.com */

            /* URIs with wolfssl.com subdomain host should be permitted */
            assertTrue("https://www.wolfssl.com should be permitted",
                nc.checkUri("https://www.wolfssl.com/path"));
            assertTrue("http://sub.wolfssl.com should be permitted",
                nc.checkUri("http://sub.wolfssl.com"));

            /* URIs with other hosts should not be permitted */
            assertFalse("https://example.com should not be permitted",
                nc.checkUri("https://example.com/path"));

            System.out.println("\t... passed");
        } finally {
            if (nc != null) {
                nc.free();
            }
            if (cert != null) {
                cert.free();
            }
        }
    }

    @Test
    public void testExcludedConstraintEnforcement() throws WolfSSLException {
        System.out.print("\tExcluded constraint enforcement");

        if (!WolfSSL.NameConstraintsEnabled()) {
            System.out.println("\t... skipped (not compiled in)");
            return;
        }

        WolfSSLCertificate cert = null;
        WolfSSLNameConstraints nc = null;
        try {
            /* Use ncmulti cert which has:
             * permitted: .example.com (DNS/email)
             * excluded: .blocked.example.com (DNS/email) */
            cert = new WolfSSLCertificate(certWithNCMulti,
                WolfSSL.SSL_FILETYPE_PEM);
            nc = cert.getNameConstraints();
            assertNotNull("Name constraints should not be null", nc);

            /* Verify excluded subtrees were parsed */
            List<WolfSSLGeneralName> excluded = nc.getExcludedSubtrees();
            assertNotNull("Excluded list should not be null", excluded);
            assertTrue("Should have excluded subtrees", excluded.size() > 0);

            /* Excluded .blocked.example.com subdomains should be blocked */
            assertFalse("www.blocked.example.com DNS should be excluded",
                nc.checkDnsName("www.blocked.example.com"));
            assertFalse("sub.blocked.example.com DNS should be excluded",
                nc.checkDnsName("sub.blocked.example.com"));
            assertFalse("user@www.blocked.example.com email should be excluded",
                nc.checkEmail("user@www.blocked.example.com"));

            /* Permitted .example.com subdomains should be allowed */
            assertTrue("www.example.com DNS should be permitted",
                nc.checkDnsName("www.example.com"));
            assertTrue("user@www.example.com email should be permitted",
                nc.checkEmail("user@www.example.com"));

            /* Domains outside permitted .example.com should not be allowed */
            assertFalse("www.wolfssl.com DNS should not be permitted",
                nc.checkDnsName("www.wolfssl.com"));

            System.out.println("\t... passed");
        } finally {
            if (nc != null) {
                nc.free();
            }
            if (cert != null) {
                cert.free();
            }
        }
    }

    @Test
    public void testMixedPermittedExcludedConstraints()
        throws WolfSSLException {

        System.out.print("\tMixed permitted/excluded");

        if (!WolfSSL.NameConstraintsEnabled()) {
            System.out.println("\t... skipped (not compiled in)");
            return;
        }

        WolfSSLCertificate cert = null;
        WolfSSLNameConstraints nc = null;
        try {
            cert = new WolfSSLCertificate(certWithNCMulti,
                WolfSSL.SSL_FILETYPE_PEM);
            nc = cert.getNameConstraints();
            assertNotNull("Name constraints should not be null", nc);

            /* Cert has:
             * Permitted: DNS:.example.com, email:.example.com
             * Excluded: DNS:.blocked.example.com, email:.blocked.example.com
             */

            /* Verify both permitted and excluded subtrees exist */
            List<WolfSSLGeneralName> permitted = nc.getPermittedSubtrees();
            List<WolfSSLGeneralName> excluded = nc.getExcludedSubtrees();
            assertTrue("Should have permitted subtrees", permitted.size() > 0);
            assertTrue("Should have excluded subtrees", excluded.size() > 0);

            /* Subdomains of example.com should be permitted */
            assertTrue("www.example.com should be permitted",
                nc.checkDnsName("www.example.com"));
            assertTrue("mail.example.com should be permitted",
                nc.checkDnsName("mail.example.com"));
            assertTrue("user@sub.example.com should be permitted",
                nc.checkEmail("user@sub.example.com"));

            /* Subdomains of blocked.example.com should be excluded
             * even though they match the permitted .example.com */
            assertFalse("www.blocked.example.com should be excluded",
                nc.checkDnsName("www.blocked.example.com"));
            assertFalse("user@sub.blocked.example.com should be excluded",
                nc.checkEmail("user@sub.blocked.example.com"));

            /* Domains outside example.com should not be permitted */
            assertFalse("other.com should not be permitted",
                nc.checkDnsName("other.com"));
            assertFalse("user@other.com should not be permitted",
                nc.checkEmail("user@other.com"));

            System.out.println("\t... passed");
        } finally {
            if (nc != null) {
                nc.free();
            }
            if (cert != null) {
                cert.free();
            }
        }
    }

    @Test
    public void testDnsConstraintValueFormat() throws WolfSSLException {
        System.out.print("\tDNS constraint value format");

        if (!WolfSSL.NameConstraintsEnabled()) {
            System.out.println("\t... skipped (not compiled in)");
            return;
        }

        WolfSSLCertificate cert = null;
        WolfSSLNameConstraints nc = null;
        try {
            /* Use dotted DNS cert to verify leading dot format */
            cert = new WolfSSLCertificate(certWithNCCombined,
                WolfSSL.SSL_FILETYPE_PEM);
            nc = cert.getNameConstraints();
            assertNotNull("Name constraints should not be null", nc);

            List<WolfSSLGeneralName> permitted = nc.getPermittedSubtrees();
            assertNotNull(permitted);
            assertTrue("Should have constraints", permitted.size() > 0);

            /* Find the DNS constraint (cert has both DNS and URI) */
            WolfSSLGeneralName dnsGn = null;
            for (WolfSSLGeneralName gn : permitted) {
                if (gn != null &&
                    gn.getType() == WolfSSLGeneralName.GEN_DNS) {
                    dnsGn = gn;
                    break;
                }
            }
            assertNotNull("No DNS constraint found in permitted subtrees",
                dnsGn);

            assertEquals("Should be DNS type",
                WolfSSLGeneralName.GEN_DNS, dnsGn.getType());
            assertEquals("Type name should be DNS", "DNS", dnsGn.getTypeName());

            String value = dnsGn.getValue();
            assertNotNull("DNS value should not be null", value);
            assertEquals("Should be .wolfssl.com", ".wolfssl.com", value);

            System.out.println("\t... passed");
        } finally {
            if (nc != null) {
                nc.free();
            }
            if (cert != null) {
                cert.free();
            }
        }
    }
}

