/* WolfSSLX509NameTest.java
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
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

import javax.security.auth.x500.X500Principal;

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLException;
import com.wolfssl.WolfSSLX509Name;

public class WolfSSLX509NameTest {

    /* True if native wolfSSL recognizes the "title" attribute (added in
     * v5.8.2). When false, tests that exercise title / domainComponent /
     * serialNumber are skipped via Assume. */
    private static boolean extendedAttrsSupported = false;

    @Rule
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void loadLibrary() {

        System.out.println("WolfSSLX509Name Class");

        try {
            WolfSSL.loadLibrary();
        } catch (UnsatisfiedLinkError ule) {
            fail("failed to load native JNI library");
        }

        /* Check if wolfSSL knows the extended attributes added in v5.8.2
         * (title, domainComponent, serialNumber). The check uses setTitle
         * since title was the first added in that set. */
        try {
            WolfSSLX509Name probe = new WolfSSLX509Name();
            try {
                probe.setTitle("probe");
                extendedAttrsSupported = true;
            } finally {
                probe.free();
            }
        } catch (Exception e) {
            extendedAttrsSupported = false;
        }
    }

    @Test
    public void test_String_RFC2253_AllKnownAttributes()
        throws WolfSSLException {

        /* Exercises every cached mirror field that wolfSSL has
         * supported since before v5.8.2. The extended attributes (title,
         * domainComponent, serialNumber) are covered separately by
         * test_String_RFC2253_ExtendedAttributes since they require
         * wolfSSL >= 5.8.2. */
        String dn = "UID=tester,CN=wolfssl.com," +
            "EMAILADDRESS=support@wolfssl.com,SN=Smith," +
            "OU=Engineering,O=wolfSSL Inc.,POSTALCODE=59715," +
            "STREET=12345 Test St,L=Bozeman,ST=Montana,C=US";

        WolfSSLX509Name name = new WolfSSLX509Name(dn);
        try {
            assertEquals("US", name.getCountryName());
            assertEquals("Montana", name.getStateOrProvinceName());
            assertEquals("Bozeman", name.getLocalityName());
            assertEquals("12345 Test St", name.getStreetAddress());
            assertEquals("59715", name.getPostalCode());
            assertEquals("wolfSSL Inc.", name.getOrganizationName());
            assertEquals("Engineering", name.getOrganizationalUnitName());
            assertEquals("Smith", name.getSurname());
            assertEquals("support@wolfssl.com", name.getEmailAddress());
            assertEquals("wolfssl.com", name.getCommonName());
            assertEquals("tester", name.getUserId());
        } finally {
            name.free();
        }
    }

    @Test
    public void test_toString_ReturnsPopulatedName()
        throws WolfSSLException {

        WolfSSLX509Name name =
            new WolfSSLX509Name("CN=wolfssl.com,O=wolfSSL Inc.,C=US");

        try {
            String str = name.toString();
            assertNotNull(str);
            assertTrue("toString() returned empty for a populated name",
                !str.isEmpty());
            assertTrue("toString() missing commonName: " + str,
                str.contains("wolfssl.com"));
            assertTrue("toString() missing organizationName: " + str,
                str.contains("wolfSSL Inc."));
            assertTrue("toString() missing countryName: " + str,
                str.contains("US"));

        } finally {
            name.free();
        }
    }

    @Test
    public void test_String_RFC2253_ExtendedAttributes()
        throws WolfSSLException {

        /* title, domainComponent, and serialNumber were added to wolfSSL
         * OBJ table in v5.8.2. Skip on older builds. The input also tests
         * case-sensitive aliases that wolfSSL natively doesn't recognize
         * without canonical mapping (lowercase "dc", short forms "T" /
         * "SERIALNUMBER". */
        Assume.assumeTrue(
            "wolfSSL does not recognize 'title' (require >= 5.8.2)",
            extendedAttrsSupported);

        WolfSSLX509Name name = new WolfSSLX509Name(
            "T=CTO,dc=example,SERIALNUMBER=42,CN=foo");
        try {
            assertEquals("CTO", name.getTitle());
            assertEquals("example", name.getDomainComponent());
            assertEquals("42", name.getSerialNumber());
            assertEquals("foo", name.getCommonName());
        } finally {
            name.free();
        }
    }

    @Test
    public void test_String_RFC2253_SerialNumberOid()
        throws WolfSSLException {

        /* 2.5.4.5 is the standard X.500 OID for serialNumber. The
         * canonicalAttributeName() OID switch must map it to "serialNumber"
         * so the mirror populates the same as if the user had passed
         * "SERIALNUMBER=foo". Gated like the other extended-attribute tests
         * since wolfSSL added serialNumber to its OBJ table in v5.8.2. */
        Assume.assumeTrue(
            "wolfSSL does not recognize 'serialNumber' (require >= 5.8.2)",
            extendedAttrsSupported);

        WolfSSLX509Name name =
            new WolfSSLX509Name("2.5.4.5=ABC123,CN=foo");
        try {
            assertEquals("ABC123", name.getSerialNumber());
            assertEquals("foo", name.getCommonName());
        } finally {
            name.free();
        }
    }

    @Test
    public void test_String_RFC2253_LongAttributeNames()
        throws WolfSSLException {

        String dn = "commonName=wolfssl.com," +
            "organizationName=wolfSSL,countryName=US";

        WolfSSLX509Name name = new WolfSSLX509Name(dn);
        try {
            assertEquals("US", name.getCountryName());
            assertEquals("wolfSSL", name.getOrganizationName());
            assertEquals("wolfssl.com", name.getCommonName());
        } finally {
            name.free();
        }
    }

    @Test
    public void test_String_RFC2253_SemicolonSeparator()
        throws WolfSSLException {

        /* RFC 2253 also accepts ';' as an RDN separator. */
        String dn = "CN=wolfssl.com;O=wolfSSL Inc.;C=US";

        WolfSSLX509Name name = new WolfSSLX509Name(dn);
        try {
            assertEquals("US", name.getCountryName());
            assertEquals("wolfSSL Inc.", name.getOrganizationName());
            assertEquals("wolfssl.com", name.getCommonName());
        } finally {
            name.free();
        }
    }

    @Test
    public void test_String_RFC2253_OidAttributeTypes()
        throws WolfSSLException {

        /* 2.5.4.3  = commonName,
         * 2.5.4.10 = organizationName,
         * 2.5.4.6  = countryName. */
        String dn = "2.5.4.3=wolfssl.com,2.5.4.10=wolfSSL,2.5.4.6=US";

        WolfSSLX509Name name = new WolfSSLX509Name(dn);
        try {
            /* Well known X.500 OIDs are translated to their canonical
             * keyword, so mirror fields populate the same as if the user
             * had passed "CN=...,O=...,C=...". */
            assertEquals("US", name.getCountryName());
            assertEquals("wolfSSL", name.getOrganizationName());
            assertEquals("wolfssl.com", name.getCommonName());
        } finally {
            name.free();
        }
    }

    @Test
    public void test_String_RFC2253_UnknownOidPassesThrough() {

        /* An OID not in our well known table. wolfSSL doesn't recognize
         * "1.2.3.4.5.6.7" so the native call rejects it. This documents
         * that unknown OIDs reach native and aren't silently swallowed. */
        try {
            new WolfSSLX509Name("1.2.3.4.5.6.7=foo,CN=bar");
            fail("expected WolfSSLException for unknown OID");
        } catch (WolfSSLException e) {
            /* expected */
        }
    }

    @Test
    public void test_String_RFC2253_QuotedValueWithComma()
        throws WolfSSLException {

        /* RFC 2253 allows quoting a value that contains a comma. */
        String dn = "CN=\"Foo, Inc.\",O=Bar,C=US";

        WolfSSLX509Name name = new WolfSSLX509Name(dn);
        try {
            assertEquals("Foo, Inc.", name.getCommonName());
            assertEquals("Bar", name.getOrganizationName());
            assertEquals("US", name.getCountryName());
        } finally {
            name.free();
        }
    }

    @Test
    public void test_String_RFC2253_EscapedComma()
        throws WolfSSLException {

        /* Backslash-escaped comma in value. */
        String dn = "CN=Foo\\, Inc.,O=Bar,C=US";

        WolfSSLX509Name name = new WolfSSLX509Name(dn);
        try {
            assertEquals("Foo, Inc.", name.getCommonName());
        } finally {
            name.free();
        }
    }

    @Test
    public void test_String_RFC2253_LeadingTrailingWhitespace()
        throws WolfSSLException {

        WolfSSLX509Name name = new WolfSSLX509Name("   CN=wolfssl.com,C=US   ");
        try {
            assertEquals("US", name.getCountryName());
            assertEquals("wolfssl.com", name.getCommonName());
        } finally {
            name.free();
        }
    }

    @Test
    public void test_String_RFC2253_SingleComponent()
        throws WolfSSLException {

        WolfSSLX509Name name = new WolfSSLX509Name("CN=foo");
        try {
            assertEquals("foo", name.getCommonName());
            assertNull(name.getCountryName());
        } finally {
            name.free();
        }
    }

    @Test
    public void test_String_Oneline_Basic() throws WolfSSLException {

        WolfSSLX509Name name = new WolfSSLX509Name(
            "/C=US/ST=Montana/L=Bozeman/O=wolfSSL Inc." +
            "/OU=Engineering/CN=wolfssl.com");
        try {
            assertEquals("US", name.getCountryName());
            assertEquals("Montana", name.getStateOrProvinceName());
            assertEquals("Bozeman", name.getLocalityName());
            assertEquals("wolfSSL Inc.", name.getOrganizationName());
            assertEquals("Engineering", name.getOrganizationalUnitName());
            assertEquals("wolfssl.com", name.getCommonName());
        } finally {
            name.free();
        }
    }

    @Test
    public void test_String_Oneline_SingleComponent()
        throws WolfSSLException {

        WolfSSLX509Name name = new WolfSSLX509Name("/CN=foo");
        try {
            assertEquals("foo", name.getCommonName());
        } finally {
            name.free();
        }
    }

    @Test
    public void test_String_Oneline_LongAttributeNames()
        throws WolfSSLException {

        WolfSSLX509Name name =
            new WolfSSLX509Name("/countryName=US/commonName=foo");
        try {
            assertEquals("US", name.getCountryName());
            assertEquals("foo", name.getCommonName());
        } finally {
            name.free();
        }
    }

    @Test
    public void test_String_Oneline_LeadingTrailingWhitespace()
        throws WolfSSLException {

        WolfSSLX509Name name = new WolfSSLX509Name("  /C=US/CN=foo  ");
        try {
            assertEquals("US", name.getCountryName());
            assertEquals("foo", name.getCommonName());
        } finally {
            name.free();
        }
    }

    @Test
    public void test_String_Oneline_BareSlashThrows() {

        try {
            new WolfSSLX509Name("/");
            fail("expected WolfSSLException for bare '/'");
        } catch (WolfSSLException e) {
            /* expected */
        }
    }

    @Test
    public void test_String_Oneline_MissingEqualsThrows() {

        try {
            new WolfSSLX509Name("/CN=foo/bar/O=baz");
            fail("expected WolfSSLException for RDN missing '='");
        } catch (WolfSSLException e) {
            /* expected */
        }
    }

    @Test
    public void test_String_Oneline_EmptyTypeThrows() {

        try {
            new WolfSSLX509Name("/=foo/CN=bar");
            fail("expected WolfSSLException for empty attribute type");
        } catch (WolfSSLException e) {
            /* expected */
        }
    }

    @Test
    public void test_String_Oneline_DoubleSlashThrows() {

        /* "//CN=foo" (empty first RDN) */
        try {
            new WolfSSLX509Name("//CN=foo");
            fail("expected WolfSSLException for empty RDN");
        } catch (WolfSSLException e) {
            /* expected */
        }
    }

    @Test
    public void test_String_Oneline_TrailingSlashThrows() {

        /* split with limit -1 keeps trailing empty (empty RDN) */
        try {
            new WolfSSLX509Name("/CN=foo/");
            fail("expected WolfSSLException for trailing '/'");
        } catch (WolfSSLException e) {
            /* expected */
        }
    }

    @Test
    public void test_String_Oneline_BackslashEscapeThrows() {

        /* OpenSSL's oneline can emit "\/" for slashes in values. We
         * reject rather than mis-parse, and the message points users
         * to RFC 2253 / X500Principal alternatives. */
        try {
            new WolfSSLX509Name("/O=ACME\\/West/CN=foo");
            fail("expected WolfSSLException for backslash escape");
        } catch (WolfSSLException e) {
            /* expected */
        }
    }

    @Test
    public void test_String_Oneline_UnknownAttributeThrows() {

        try {
            new WolfSSLX509Name("/FOO=bar/CN=baz");
            fail("expected WolfSSLException for unknown attribute");
        } catch (WolfSSLException e) {
            /* expected */
        }
    }

    @Test
    public void test_String_NullThrows() {

        try {
            new WolfSSLX509Name((String) null);
            fail("expected WolfSSLException for null String DN");
        } catch (WolfSSLException e) {
            /* expected */
        }
    }

    @Test
    public void test_String_EmptyThrows() {

        try {
            new WolfSSLX509Name("");
            fail("expected WolfSSLException for empty String DN");
        } catch (WolfSSLException e) {
            /* expected */
        }
    }

    @Test
    public void test_String_WhitespaceOnlyThrows() {

        try {
            new WolfSSLX509Name("    ");
            fail("expected WolfSSLException for whitespace-only DN");
        } catch (WolfSSLException e) {
            /* expected */
        }
    }

    @Test
    public void test_String_InvalidSyntaxThrows() {

        try {
            new WolfSSLX509Name("not a valid dn");
            fail("expected WolfSSLException for invalid DN syntax");
        } catch (WolfSSLException e) {
            /* expected */
        }
    }

    @Test
    public void test_String_MultiValuedRdnThrows() {

        try {
            new WolfSSLX509Name("CN=foo+OU=bar,O=baz,C=US");
            fail("expected WolfSSLException for multi-valued RDN");
        } catch (WolfSSLException e) {
            /* expected */
        }
    }

    @Test
    public void test_String_UnknownAttributeThrows() {

        /* "FOO" is not a recognized short/long name and is not a dotted
         * OID, so wolfSSL_OBJ_txt2nid() returns WC_NID_undef and the native
         * add_entry_by_txt() call fails. */
        try {
            new WolfSSLX509Name("FOO=bar,CN=baz");
            fail("expected WolfSSLException for unknown attribute");
        } catch (WolfSSLException e) {
            /* expected */
        }
    }

    @Test
    public void test_String_RFC2253_HexEncodedValueThrows() {

        /* RFC 2253 #hexpairs form are rejected: bytes are BER-encoded
         * (tag + length + value), not UTF-8 text. "#1303616263" =
         * PrintableString "abc" in BER. */
        try {
            new WolfSSLX509Name("CN=#1303616263,O=foo,C=US");
            fail("expected WolfSSLException for hex-encoded BER value");
        } catch (WolfSSLException e) {
            /* expected */
        }
    }

    @Test
    public void test_String_RFC2253_HexByteEscape()
        throws WolfSSLException {

        /* "\C3\A9" = UTF-8 encoding of 'e' acute (U+00E9). The parser
         * accumulates hex-byte escapes as a byte sequence and decodes the
         * whole value as UTF-8, so multi-byte sequences round-trip.
         *
         * Use a unicode escape for the literal rather than the raw 'e'
         * acute character, so this test compiles correctly on platforms
         * where javac defaults to a non-UTF-8 source encoding (e.g. on
         * Windows where javac defaults to the platform charset). */
        WolfSSLX509Name name = new WolfSSLX509Name("CN=Caf\\C3\\A9,C=US");
        try {
            assertEquals("Caf\u00e9", name.getCommonName());
            assertEquals("US", name.getCountryName());
        } finally {
            name.free();
        }
    }

    @Test
    public void test_String_RFC2253_BackslashLiteral()
        throws WolfSSLException {

        WolfSSLX509Name name = new WolfSSLX509Name("CN=foo\\\\bar,C=US");
        try {
            assertEquals("foo\\bar", name.getCommonName());
        } finally {
            name.free();
        }
    }

    @Test
    public void test_String_RFC2253_EscapedTrailingSpacePreserved()
        throws WolfSSLException {

        /* RFC 2253 requires trailing spaces in unquoted values to be escaped
         * (single-char "\ " or hex "\20"). The parser must preserve the
         * escaped space and only trim unescaped trailing whitespace. */
        WolfSSLX509Name viaCharEscape = new WolfSSLX509Name("CN=foo\\ ,O=bar");
        try {
            assertEquals("foo ", viaCharEscape.getCommonName());
        } finally {
            viaCharEscape.free();
        }

        WolfSSLX509Name viaHexEscape = new WolfSSLX509Name("CN=foo\\20,O=bar");
        try {
            assertEquals("foo ", viaHexEscape.getCommonName());
        } finally {
            viaHexEscape.free();
        }
    }

    @Test
    public void test_String_RFC2253_MixedEscapedAndUnescapedTrailingSpace()
        throws WolfSSLException {

        /* "foo\  " = escaped space then unescaped space. The escaped space
         * is preserved, the unescaped one is trimmed. */
        WolfSSLX509Name name = new WolfSSLX509Name("CN=foo\\  ,O=bar");
        try {
            assertEquals("foo ", name.getCommonName());
        } finally {
            name.free();
        }
    }

    @Test
    public void test_String_RFC2253_UnescapedTrailingWhitespaceTrimmed()
        throws WolfSSLException {

        /* Plain trailing whitespace in an unquoted value is trimmed. */
        WolfSSLX509Name name = new WolfSSLX509Name("CN=foo   ,O=bar");
        try {
            assertEquals("foo", name.getCommonName());
            assertEquals("bar", name.getOrganizationName());
        } finally {
            name.free();
        }
    }

    @Test
    public void test_String_RFC2253_QuotedWithEmbeddedQuote()
        throws WolfSSLException {

        WolfSSLX509Name name =
            new WolfSSLX509Name("CN=\"he said \\\"hi\\\"\",C=US");
        try {
            assertEquals("he said \"hi\"", name.getCommonName());
        } finally {
            name.free();
        }
    }

    @Test
    public void test_String_RFC2253_WhitespaceAroundEquals()
        throws WolfSSLException {

        WolfSSLX509Name name = new WolfSSLX509Name("CN = foo, C = US");
        try {
            assertEquals("foo", name.getCommonName());
            assertEquals("US", name.getCountryName());
        } finally {
            name.free();
        }
    }

    @Test
    public void test_String_RFC2253_TrailingSeparatorThrows() {

        try {
            new WolfSSLX509Name("CN=foo,C=US,");
            fail("expected WolfSSLException for trailing separator");
        } catch (WolfSSLException e) {
            /* expected */
        }
    }

    @Test
    public void test_String_RFC2253_MissingEqualsThrows() {

        try {
            new WolfSSLX509Name("CN foo,C=US");
            fail("expected WolfSSLException for missing '='");
        } catch (WolfSSLException e) {
            /* expected */
        }
    }

    @Test
    public void test_String_RFC2253_UnterminatedQuoteThrows() {

        try {
            new WolfSSLX509Name("CN=\"unterminated,C=US");
            fail("expected WolfSSLException for unterminated quote");
        } catch (WolfSSLException e) {
            /* expected */
        }
    }

    @Test
    public void test_String_RFC2253_TrailingBackslashThrows() {

        /* Single '\' at end of value with nothing to escape. */
        try {
            new WolfSSLX509Name("CN=foo\\");
            fail("expected WolfSSLException for trailing backslash");
        } catch (WolfSSLException e) {
            /* expected */
        }
    }

    @Test
    public void test_String_RFC2253_IncompleteHexEscapeAtEndThrows() {

        /* "\C" at end of input: only one hex digit, no second to make a
         * complete \xx byte escape. */
        try {
            new WolfSSLX509Name("CN=foo\\C");
            fail("expected WolfSSLException for incomplete hex escape");
        } catch (WolfSSLException e) {
            /* expected */
        }
    }

    @Test
    public void test_String_RFC2253_IncompleteHexEscapeBadDigitThrows() {

        /* "\Cz": first nibble is hex, second isn't. Parser must reject
         * rather than treat as single-char escape. */
        try {
            new WolfSSLX509Name("CN=foo\\Cz");
            fail("expected WolfSSLException for non-hex second digit");
        } catch (WolfSSLException e) {
            /* expected */
        }
    }

    @Test
    public void test_String_RFC2253_UnexpectedCharAtTypeStartThrows() {

        /* '=' is not a valid first char for an attribute type. */
        try {
            new WolfSSLX509Name("=foo,CN=bar");
            fail("expected WolfSSLException for unexpected character");
        } catch (WolfSSLException e) {
            /* expected */
        }
    }

    @Test
    public void test_String_RFC2253_BadRdnSeparatorThrows() {

        /* After a quoted value the next non-whitespace char must be ','
         * or ';'. Anything else (here '|') hits the parser's separator
         * check rather than being silently absorbed into the value. */
        try {
            new WolfSSLX509Name("CN=\"foo\"|O=bar");
            fail("expected WolfSSLException for bad RDN separator");
        } catch (WolfSSLException e) {
            /* expected */
        }
    }

    @Test
    public void test_String_RFC2253_RdnInsertionOrderIsReversed()
        throws WolfSSLException {

        /* Parser walks textual L-to-R then Collections.reverse()s before
         * insertion (least-significant-first / X.509 encoding order).
         * Mirrors are "last write wins": after reversal the calls happen
         * as CN=last then CN=first, leaving "first" in the mirror. If
         * reversal weren't happening, the mirror would hold "last". */
        WolfSSLX509Name name = new WolfSSLX509Name("CN=first,CN=last");
        try {
            assertEquals("first", name.getCommonName());
        } finally {
            name.free();
        }
    }

    @Test
    public void test_String_RFC2253_EmptyValueAtEofMatchesSetX()
        throws WolfSSLException {

        /* "CN=" at end of input and "CN=,O=foo" both produce an RDN with an
         * empty value, matching the explicit setX("") path. Native may or may
         * not produce a useful cert from an empty value, but the wrapper
         * accepts it consistently across all three entry points (no-arg +
         * setX, parser at EOF, parser mid-DN). */
        WolfSSLX509Name viaSet = new WolfSSLX509Name();
        try {
            viaSet.setCommonName("");
        } catch (WolfSSLException e) {
            /* If setX("") doesn't go through cleanly, the parser path for
             * "CN=" must fail the same way. Verify and exit. */
            viaSet.free();
            try {
                new WolfSSLX509Name("CN=");
                fail("setX(\"\") threw but parser path didn't");
            } catch (WolfSSLException e2) {
                /* expected: paths conform */
            }
            return;
        }
        viaSet.free();

        /* setX("") succeeded, so the parser must too. */
        WolfSSLX509Name viaParser = new WolfSSLX509Name("CN=");
        try {
            assertEquals("", viaParser.getCommonName());
        } finally {
            viaParser.free();
        }
    }

    @Test
    public void test_String_RFC2253_SurrogatePairValue()
        throws WolfSSLException {

        /* U+1F600 (grinning face emoji) encodes as a UTF-16 surrogate
         * pair in a Java String and four UTF-8 bytes. The parser uses
         * codePointAt + charCount so the pair flows through to the byte
         * stream correctly. charAt-only logic would split or mangle it. */
        String emoji = "\uD83D\uDE00";
        WolfSSLX509Name name =
            new WolfSSLX509Name("CN=" + emoji + ",C=US");
        try {
            assertEquals(emoji, name.getCommonName());
            assertEquals("US", name.getCountryName());
        } finally {
            name.free();
        }
    }

    @Test
    public void test_X500Principal_PopulatesMirrorFields()
        throws WolfSSLException {

        X500Principal principal = new X500Principal(
            "CN=wolfssl.com,O=wolfSSL Inc.,C=US");

        WolfSSLX509Name name = new WolfSSLX509Name(principal);
        try {
            assertEquals("US", name.getCountryName());
            assertEquals("wolfSSL Inc.", name.getOrganizationName());
            assertEquals("wolfssl.com", name.getCommonName());
        } finally {
            name.free();
        }
    }

    @Test
    public void test_X500Principal_RoundTrip() throws WolfSSLException {

        /* Build a principal from RFC 2253 string, feed it to our
         * constructor, verify mirrors match. This is the canonical use case
         * for round tripping cert subjects. */
        String original = "CN=wolfssl.com,OU=Engineering," +
            "O=wolfSSL Inc.,L=Bozeman,ST=Montana,C=US";

        X500Principal principal = new X500Principal(original);
        WolfSSLX509Name name = new WolfSSLX509Name(principal);
        try {
            assertEquals("US", name.getCountryName());
            assertEquals("Montana", name.getStateOrProvinceName());
            assertEquals("Bozeman", name.getLocalityName());
            assertEquals("wolfSSL Inc.", name.getOrganizationName());
            assertEquals("Engineering", name.getOrganizationalUnitName());
            assertEquals("wolfssl.com", name.getCommonName());
        } finally {
            name.free();
        }
    }

    @Test
    public void test_X500Principal_NullThrows() {

        try {
            new WolfSSLX509Name((X500Principal) null);
            fail("expected WolfSSLException for null X500Principal");
        } catch (WolfSSLException e) {
            /* expected */
        }
    }

    @Test
    public void test_X500Principal_UnknownAttributeThrows() {

        /* X500Principal accepts any attribute as a string. Our constructor
         * should fail when wolfSSL doesn't recognize it. */
        X500Principal principal = new X500Principal("1.2.3.4.5.6.7=foo,CN=bar");
        try {
            new WolfSSLX509Name(principal);
            fail("expected WolfSSLException for unknown OID");
        } catch (WolfSSLException e) {
            /* expected */
        }
    }
}
