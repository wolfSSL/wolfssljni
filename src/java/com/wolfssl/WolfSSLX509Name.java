/* WolfSSLX509Name.java
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
package com.wolfssl;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

import javax.security.auth.x500.X500Principal;

/**
 * WolfSSLX509Name class, wraps native WOLFSSL_X509_NAME functionality.
 */
public class WolfSSLX509Name {

    private boolean active = false;
    private long x509NamePtr = 0;

    /* Lock around active state */
    private final Object stateLock = new Object();

    /* Lock around x509NamePtr pointer access */
    private final Object x509NameLock = new Object();

    /* Cache name elements in Java before pushing through JNI, for easier
     * retrieval from getXXX() methods */
    private String countryName               = null;
    private String stateOrProvinceName       = null;
    private String streetAddress             = null;
    private String localityName              = null;
    private String surname                   = null;
    private String commonName                = null;
    private String emailAddress              = null;
    private String organizationName          = null;
    private String organizationalUnitName    = null;
    private String postalCode                = null;
    private String userId                    = null;
    private String title                     = null;
    private String domainComponent           = null;
    private String serialNumber              = null;

    /* Encoding types, matched to native define values */
    private static final int MBSTRING_UTF8 = 0x100;

    /* Native JNI methods */
    static native long X509_NAME_new();
    static native void X509_NAME_free(long x509Name);
    static native int X509_NAME_add_entry_by_txt(long x509Name, String field,
        int type, byte[] entry, int len, int loc, int set);

    /**
     * Create new empty WolfSSLX509Name object.
     *
     * @throws WolfSSLException if native API call fails.
     */
    public WolfSSLX509Name() throws WolfSSLException {

        initNative();
    }

    /**
     * Create new WolfSSLX509Name populated from a distinguished name string.
     *
     * Two string formats are accepted:
     *   - RFC 2253 / RFC 4514:          "CN=foo,O=bar,C=US"
     *   - OpenSSL-style oneline:        "/C=US/O=bar/CN=foo"
     *
     * The format is auto detected. A string with first non-whitespace
     * character '/' is parsed as OpenSSL-style oneline. Everything else is
     * parsed as RFC 2253 / RFC 4514. Both ',' and ';' are accepted as RDN
     * separators in RFC 2253 input. Backslash escapes (single character or
     * two-hex-digit byte form) and double-quoted values are supported in
     * RFC 2253. Hex-encoded values ("#hexdigits") are not supported and will
     * cause this constructor to throw a WolfSSLException.
     *
     * Callers with a javax.naming.ldap.LdapName instance can pass
     * myLdapName.toString() since LdapName's string form is RFC 2253.
     * javax.naming is not available on Android, which is why this class
     * does not provide a typed LdapName constructor.
     *
     * Relative Distinguished Names (RDNs) are added in the order used to build
     * the X.509 subject, not necessarily in the textual order of the input.
     * For RFC 2253 / RFC 4514 input, RDNs are added in reverse textual order
     * (least significant first). For example "CN=foo,O=bar,C=US" is added as
     * C, O, CN. OpenSSL-style oneline input is already written in that
     * insertion order.
     *
     * Multi value RDNs (ex: "CN=a+OU=b") are not currently supported and will
     * cause this constructor to throw a WolfSSLException (not supported in
     * native wolfSSL).
     *
     * @param dn distinguished name string in RFC 2253 or OpenSSL oneline format
     *
     * @throws WolfSSLException if dn is null, empty, cannot be parsed, contains
     *         a multi value RDN, or contains an attribute type not recognized
     *         by native wolfSSL.
     */
    @SuppressWarnings("this-escape")
    public WolfSSLX509Name(String dn) throws WolfSSLException {

        String trimmed = null;

        if (dn == null) {
            throw new WolfSSLException("WolfSSLX509Name dn is null");
        }

        trimmed = dn.trim();
        if (trimmed.isEmpty()) {
            throw new WolfSSLException("WolfSSLX509Name dn is empty");
        }

        initNative();

        try {
            if (trimmed.charAt(0) == '/') {
                populateFromOneline(trimmed);
            } else {
                populateFromRfc2253(trimmed);
            }

        } catch (WolfSSLException | RuntimeException e) {
            free();
            throw e;
        }
    }

    /**
     * Create new WolfSSLX509Name populated from an X500Principal.
     *
     * Internally calls X500Principal.getName(RFC2253) and parses the string.
     * This could be used with X509Certificate.getSubjectX500Principal().
     *
     * Multi value Relative Distinguished Names (RDNs) are not currently
     * supported and will cause this constructor to throw a WolfSSLException.
     *
     * @param principal X500Principal to populate from
     *
     * @throws WolfSSLException if principal is null, contains a multi value
     *         RDN, or contains an attribute type not recognized by wolfSSL.
     */
    @SuppressWarnings("this-escape")
    public WolfSSLX509Name(X500Principal principal)
        throws WolfSSLException {

        String dn = null;

        if (principal == null) {
            throw new WolfSSLException("principal is null");
        }

        dn = principal.getName(X500Principal.RFC2253);
        initNative();

        try {
            populateFromRfc2253(dn);

        } catch (WolfSSLException | RuntimeException e) {
            free();
            throw e;
        }
    }

    /**
     * Allocate the native WOLFSSL_X509_NAME and mark this object active.
     * Shared initialization for all constructors.
     *
     * @throws WolfSSLException if native API call fails.
     */
    private void initNative() throws WolfSSLException {

        x509NamePtr = X509_NAME_new();
        if (x509NamePtr == 0) {
            throw new WolfSSLException("Failed to create WolfSSLX509Name");
        }

        WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
            WolfSSLDebug.INFO, x509NamePtr,
            () -> "creating new WolfSSLX509Name");

        synchronized (stateLock) {
            this.active = true;
        }
    }

    /**
     * Parse an OpenSSL "oneline" DN string into a list of [type, value] pairs,
     * in encoded order (country first).
     *
     * The oneline format is "/Type1=Value1/Type2=Value2/..." with no defined
     * escaping for '/' or '=' inside values. Inputs containing backslash
     * escapes are rejected. Leading and trailing whitespace around both the
     * attribute type and value is trimmed.
     *
     * @param dn oneline DN string to parse
     *
     * @throws WolfSSLException on malformed input (empty RDN, missing '=',
     *         empty attribute type, or backslash escape sequences)
     */
    private static List<String[]> parseOnelineDn(String dn)
        throws WolfSSLException {

        int eq;
        String type = null;
        String value = null;
        String[] parts = null;
        List<String[]> rdns = new ArrayList<String[]>();

        if (dn.length() < 2 || dn.charAt(0) != '/') {
            throw new WolfSSLException(
                "Oneline DN must start with '/' followed by RDNs");
        }

        if (dn.indexOf('\\') >= 0) {
            throw new WolfSSLException(
                "Backslash escapes in oneline DN are not supported, " +
                "use RFC 2253 form (e.g. \"CN=foo,O=bar\") or pass an " +
                "X500Principal instead");
        }

        parts = dn.substring(1).split("/", -1);
        int partOffset = 1;
        for (String part : parts) {
            if (part.isEmpty()) {
                throw new WolfSSLException(
                    "Invalid oneline DN: empty RDN at position " + partOffset);
            }
            eq = part.indexOf('=');
            if (eq < 0) {
                throw new WolfSSLException(
                    "Invalid oneline DN: missing '=' at position " +
                    partOffset + " (in segment \"" + part + "\")");
            }
            type = part.substring(0, eq).trim();
            value = part.substring(eq + 1).trim();
            if (type.isEmpty()) {
                throw new WolfSSLException(
                    "Invalid oneline DN: empty attribute type at " +
                    "position " + partOffset);
            }
            rdns.add(new String[] { type, value });
            partOffset += part.length() + 1;
        }

        if (rdns.isEmpty()) {
            throw new WolfSSLException("Invalid oneline DN: no RDNs found");
        }

        return rdns;
    }

    /**
     * Populate this name from a parsed oneline DN. The oneline format stores
     * RDNs in encoded order (country first), which matches our append-to-end
     * behavior in addEntryByTxt.
     *
     * @param dn oneline DN string to parse and populate from
     * @throws WolfSSLException if dn is malformed or contains an attribute
     *         type not recognized by native wolfSSL.
     */
    private void populateFromOneline(String dn)
        throws WolfSSLException {

        for (String[] tv : parseOnelineDn(dn)) {
            addAttribute(tv[0], tv[1]);
        }
    }

    /**
     * Populate this name from an RFC 2253 / RFC 4514 distinguished name
     * string. Parses the input, then iterates RDNs in reverse textual order
     * (least significant first), so "CN=foo,O=bar,C=US" is added as C, O, CN.
     *
     * @param dn RFC 2253 / RFC 4514 distinguished name string
     * @throws WolfSSLException if dn is malformed, contains a multi value RDN,
     *         contains a hex-encoded value, or contains an attribute type not
     *         recognized by native wolfSSL.
     */
    private void populateFromRfc2253(String dn) throws WolfSSLException {

        for (String[] tv : parseRfc2253Dn(dn)) {
            addAttribute(tv[0], tv[1]);
        }
    }

    /**
     * Parse an RFC 2253 / RFC 4514 distinguished name string into a list of
     * [type, value] pairs, in encoded order (least significant RDN first,
     * matching conventional X.509 subject encoding order such as C, O, OU,
     * CN).
     *
     * Supported syntax:
     *   - ',' and ';' as RDN separators
     *   - Whitespace tolerated around '=' and RDN separators
     *   - Attribute type as descr ([A-Za-z][A-Za-z0-9-]*) or numericoid
     *     ([0-9]+(\.[0-9]+)*)
     *   - Single-character escapes: \, \; \+ \" \\ \= \&lt; \&gt; \# \space
     *   - Hex-byte escapes: \xx, accumulated and decoded as UTF-8 (so \C3\A9
     *     produces 'e' acute)
     *   - Double-quoted values (defined in RFC 2253, omitted from RFC 4514
     *     but still accepted by major parsers including LdapName and
     *     X500Principal)
     *
     * Rejected (throws WolfSSLException):
     *   - '#hexpairs' values (BER-encoded form)
     *   - '+' multi-valued RDNs
     *   - Malformed input (missing '=', unterminated quote, trailing
     *     separator, etc.)
     *
     * @param dn RFC 2253 / RFC 4514 distinguished name string
     * @return list of [type, value] pairs in least-significant-first order
     * @throws WolfSSLException on malformed or unsupported input
     */
    private static List<String[]> parseRfc2253Dn(String dn)
        throws WolfSSLException {

        List<String[]> rdns = new ArrayList<String[]>();
        int len = dn.length();
        int pos = 0;

        while (true) {
            pos = skipDnWhitespace(dn, pos);
            if (pos >= len) {
                if (rdns.isEmpty()) {
                    throw new WolfSSLException(
                        "Invalid DN: no RDNs found at position " + pos);
                }
                throw new WolfSSLException(
                    "Invalid DN: trailing RDN separator at position " + pos);
            }

            /* Parse attribute type */
            int typeStart = pos;
            char c = dn.charAt(pos);
            if (c >= '0' && c <= '9') {
                while (pos < len) {
                    char dc = dn.charAt(pos);
                    if ((dc >= '0' && dc <= '9') || dc == '.') {
                        pos++;
                    } else {
                        break;
                    }
                }
            } else if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
                while (pos < len) {
                    char tc = dn.charAt(pos);
                    if ((tc >= 'A' && tc <= 'Z') || (tc >= 'a' && tc <= 'z') ||
                        (tc >= '0' && tc <= '9') || tc == '-') {
                        pos++;
                    } else {
                        break;
                    }
                }
            } else {
                throw new WolfSSLException(
                    "Invalid DN: unexpected character '" + c +
                    "' at position " + pos);
            }
            String type = dn.substring(typeStart, pos);

            /* Skip whitespace, expect '=' */
            pos = skipDnWhitespace(dn, pos);
            if (pos >= len || dn.charAt(pos) != '=') {
                throw new WolfSSLException(
                    "Invalid DN: missing '=' after type '" + type + "'");
            }
            pos++;
            pos = skipDnWhitespace(dn, pos);

            /* Parse value */
            int[] posRef = new int[] { pos };
            String value = parseRfc2253Value(dn, posRef);
            pos = posRef[0];

            rdns.add(new String[] { type, value });

            /* Separator */
            pos = skipDnWhitespace(dn, pos);
            if (pos >= len) {
                break;
            }
            char sep = dn.charAt(pos);
            if (sep == '+') {
                throw new WolfSSLException(
                    "Multi-valued RDNs are not supported");
            }
            if (sep != ',' && sep != ';') {
                throw new WolfSSLException(
                    "Invalid DN: expected ',' or ';' at position " + pos);
            }
            pos++;
        }

        if (rdns.isEmpty()) {
            throw new WolfSSLException(
                "Invalid DN: no RDNs found at position " + pos);
        }

        /* Reverse to insertion order matching the conventional X.509
         * subject encoding order (least significant first, e.g. C, O, OU,
         * CN for input "CN=foo,O=bar,OU=baz,C=US"). */
        Collections.reverse(rdns);

        return rdns;
    }

    /**
     * Parse a single RFC 2253 attribute value starting at posRef[0]. Updates
     * posRef[0] to the index after the value (before any separator).
     *
     * Handles quoted and unquoted forms, single-char and hex-byte escapes.
     * Builds the value as a byte stream so multi-byte UTF-8 escapes (e.g.
     * \C3\A9) decode correctly.
     */
    private static String parseRfc2253Value(String dn, int[] posRef)
        throws WolfSSLException {

        int pos = posRef[0];
        int len = dn.length();

        /* Empty value at end of input ("CN=") is allowed for parity with the
         * explicit setX("") path and the mid-DN empty case ("CN=,O=foo").
         * Native may or may not produce useful output for an empty value, but
         * the wrapper accepts it consistently across all entry points. */
        if (pos >= len) {
            posRef[0] = pos;
            return "";
        }

        char first = dn.charAt(pos);
        if (first == '#') {
            throw new WolfSSLException(
                "Hex-encoded RFC 2253 attribute values (#hexpairs form) " +
                "are not supported");
        }

        ByteArrayOutputStream bytes = new ByteArrayOutputStream();

        /* Number of unescaped trailing whitespace bytes (' ' or '\t')
         * appended at the current end of `bytes`. Reset to 0 by any
         * non-whitespace byte and by any escape (so escaped trailing
         * whitespace per RFC 2253, e.g. "CN=foo\ ", is preserved).
         * Used to trim only unescaped trailing whitespace at the end. */
        int trimmableTail = 0;
        boolean quoted = (first == '"');
        int quoteStart = pos;
        if (quoted) {
            pos++;
        }

        while (pos < len) {
            char ch = dn.charAt(pos);

            if (quoted) {
                if (ch == '"') {
                    pos++;
                    posRef[0] = pos;
                    return new String(bytes.toByteArray(),
                        StandardCharsets.UTF_8);
                }
            } else {
                if (ch == ',' || ch == ';' || ch == '+') {
                    break;
                }
            }

            if (ch == '\\') {
                if (pos + 1 >= len) {
                    throw new WolfSSLException(
                        "Invalid DN: trailing '\\' escape at position " + pos);
                }
                char next = dn.charAt(pos + 1);
                if (isHex(next)) {
                    if (pos + 2 >= len || !isHex(dn.charAt(pos + 2))) {
                        throw new WolfSSLException(
                            "Invalid DN: incomplete hex escape at position " +
                            pos);
                    }
                    bytes.write((hexValue(next) << 4) |
                                hexValue(dn.charAt(pos + 2)));
                    pos += 3;
                } else {
                    /* Single-character escape, encode as UTF-8 */
                    appendCodePointUtf8(bytes, next);
                    pos += 2;
                }
                /* Any escape (single-char or hex byte) is intentional content,
                 * even if the resulting byte is a whitespace one. Reset so we
                 * don't trim. */
                trimmableTail = 0;

            } else {
                /* Plain code point, encode as UTF-8. Handle surrogate pairs by
                 * reading the full code point. */
                int cp = dn.codePointAt(pos);
                appendCodePointUtf8(bytes, cp);
                pos += Character.charCount(cp);
                if (!quoted && (ch == ' ' || ch == '\t')) {
                    trimmableTail++;
                } else {
                    trimmableTail = 0;
                }
            }
        }

        if (quoted) {
            throw new WolfSSLException(
                "Invalid DN: unterminated quoted value starting at " +
                "position " + quoteStart);
        }

        posRef[0] = pos;

        /* Trim unescaped trailing whitespace. Escaped trailing whitespace
         * ("CN=foo\ " or "CN=foo\20") is preserved because trimmableTail was
         * reset to 0 at each escape. */
        byte[] all = bytes.toByteArray();
        return new String(all, 0, all.length - trimmableTail,
            StandardCharsets.UTF_8);
    }

    private static int skipDnWhitespace(String dn, int pos) {

        while (pos < dn.length() && (dn.charAt(pos) == ' ' ||
            dn.charAt(pos) == '\t')) {
            pos++;
        }
        return pos;
    }

    private static boolean isHex(char c) {

        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
            (c >= 'A' && c <= 'F');
    }

    private static int hexValue(char c) {

        if (c >= '0' && c <= '9') {
            return c - '0';
        }

        if (c >= 'a' && c <= 'f') {
            return c - 'a' + 10;
        }

        return c - 'A' + 10;
    }

    private static void appendCodePointUtf8(ByteArrayOutputStream out, int cp) {

        byte[] b = new String(Character.toChars(cp))
            .getBytes(StandardCharsets.UTF_8);

        out.write(b, 0, b.length);
    }

    /**
     * Add a single attribute to this name, normalizing the type before the
     * native call and updating the cached Java side mirror.
     *
     * Normalization is necessary because wolfSSL's OBJ_txt2nid() lookup
     * is case sensitive, while X500Principal.getName(RFC2253) commonly
     * returns uppercase forms (ex: "STREET", "EMAILADDRESS") that don't
     * match wolfSSL's canonical form.
     *
     * @param type attribute type string, for example "CN" or "commonName"
     * @param value attribute value string
     *
     * @throws WolfSSLException if native JNI error has occurred, or input
     *        attribute type is not recognized by native wolfSSL.
     */
    private void addAttribute(String type, String value)
        throws WolfSSLException {

        confirmObjectIsActive();

        String nativeType = canonicalAttributeName(type);
        addEntryByTxt(nativeType, value);
        updateMirrorField(nativeType, value);
    }

    /**
     * Map a DN attribute type to the canonical form recognized by native
     * wolfSSL_OBJ_txt2nid(). Handles the common short/long aliases case
     * insensitively. Dotted OIDs are mapped to their canonical keyword for
     * well known X.500 attributes. Unrecognized OIDs and unrecognized keyword
     * types are passed through. For pass through types the downstream native
     * call will succeed if the casing matches, or fail cleanly via
     * addEntryByTxt() if not. Null and empty inputs are returned unchanged.
     * Callers downstream reject them via addEntryByTxt().
     *
     * @param attrType attribute type string, for example "CN", "commonName",
     *        or "2.5.4.3"
     *
     * @return canonical attribute type string recognized by wolfSSL, for
     *         example "commonName" for "CN" / "commonName" / "2.5.4.3".
     *         Unrecognized inputs are passed through.
     */
    private static String canonicalAttributeName(String attrType) {

        String key = null;

        if (attrType == null || attrType.isEmpty()) {
            return attrType;
        }

        /* Dotted OIDs start with an ASCII digit. Translate well known X.500
         * attribute OIDs to their canonical keyword so equivalent DN forms
         * (ex: "CN=foo" vs "2.5.4.3=foo") produce identical state. Unknown
         * OIDs are passed through. wolfSSL_OBJ_txt2nid() handles dotted OID
         * lookup natively. */
        char first = attrType.charAt(0);
        if (first >= '0' && first <= '9') {
            switch (attrType) {
                case "2.5.4.3":  return "commonName";
                case "2.5.4.4":  return "surname";
                case "2.5.4.5":  return "serialNumber";
                case "2.5.4.6":  return "countryName";
                case "2.5.4.7":  return "localityName";
                case "2.5.4.8":  return "stateOrProvinceName";
                case "2.5.4.9":  return "streetAddress";
                case "2.5.4.10": return "organizationName";
                case "2.5.4.11": return "organizationalUnitName";
                case "2.5.4.12": return "title";
                case "2.5.4.17": return "postalCode";
                case "0.9.2342.19200300.100.1.1":  return "userId";
                case "0.9.2342.19200300.100.1.25": return "domainComponent";
                case "1.2.840.113549.1.9.1": return "emailAddress";
                default: return attrType;
            }
        }

        key = attrType.toUpperCase(Locale.ROOT);
        switch (key) {
            case "C":
            case "COUNTRYNAME":
                return "countryName";
            case "ST":
            case "STATEORPROVINCENAME":
                return "stateOrProvinceName";
            case "STREET":
            case "STREETADDRESS":
                return "streetAddress";
            case "L":
            case "LOCALITYNAME":
                return "localityName";
            case "SN":
            case "SURNAME":
                return "surname";
            case "CN":
            case "COMMONNAME":
                return "commonName";
            case "EMAILADDRESS":
                return "emailAddress";
            case "O":
            case "ORGANIZATIONNAME":
                return "organizationName";
            case "OU":
            case "ORGANIZATIONALUNITNAME":
                return "organizationalUnitName";
            case "POSTALCODE":
                return "postalCode";
            case "UID":
            case "USERID":
                return "userId";
            case "T":
            case "TITLE":
                return "title";
            case "DC":
            case "DOMAINCOMPONENT":
                return "domainComponent";
            case "SERIALNUMBER":
                return "serialNumber";
            default:
                return attrType;
        }
    }

    /**
     * Update the cached Java-side mirror field if attrType matches one of the
     * known short/long names. Unknown attribute types are silently skipped
     * since they were already pushed through the native call. Comparison is
     * case-insensitive.
     *
     * @param attrType attribute type string
     * @param value attribute value string
     */
    private void updateMirrorField(String attrType, String value) {

        String key = null;

        if (attrType == null) {
            return;
        }

        key = attrType.toUpperCase(Locale.ROOT);
        switch (key) {
            case "C":
            case "COUNTRYNAME":
                this.countryName = value;
                break;
            case "ST":
            case "STATEORPROVINCENAME":
                this.stateOrProvinceName = value;
                break;
            case "STREET":
            case "STREETADDRESS":
                this.streetAddress = value;
                break;
            case "L":
            case "LOCALITYNAME":
                this.localityName = value;
                break;
            case "SN":
            case "SURNAME":
                this.surname = value;
                break;
            case "CN":
            case "COMMONNAME":
                this.commonName = value;
                break;
            case "EMAILADDRESS":
                this.emailAddress = value;
                break;
            case "O":
            case "ORGANIZATIONNAME":
                this.organizationName = value;
                break;
            case "OU":
            case "ORGANIZATIONALUNITNAME":
                this.organizationalUnitName = value;
                break;
            case "POSTALCODE":
                this.postalCode = value;
                break;
            case "UID":
            case "USERID":
                this.userId = value;
                break;
            case "T":
            case "TITLE":
                this.title = value;
                break;
            case "DC":
            case "DOMAINCOMPONENT":
                this.domainComponent = value;
                break;
            case "SERIALNUMBER":
                this.serialNumber = value;
                break;
            default:
                break;
        }
    }

    /**
     * Verifies that the current WolfSSLX509Name object is active.
     *
     * @throws IllegalStateException if object has been freed
     */
    private void confirmObjectIsActive()
        throws IllegalStateException {

        synchronized (stateLock) {
            if (this.active == false) {
                throw new IllegalStateException(
                    "WolfSSLX509Name object has been freed");
            }
        }
    }

    /**
     * For package use only, return native WOLFSSL_X509_NAME pointer.
     *
     * The returned pointer is only valid while this object is not freed.
     * Callers must synchronize on this WolfSSLX509Name while using the
     * returned pointer so a concurrent free() cannot release it.
     *
     * @return native WOLFSSL_X509_NAME pointer value
     * @throws IllegalStateException if WolfSSLX509Name has been freed.
     */
    protected long getNativeX509NamePtr() throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (x509NameLock) {
            return this.x509NamePtr;
        }
    }

    /**
     * Private helper function to call native JNI function
     * X509_NAME_add_entry_by_txt().
     *
     * @param field String containing field name to set, for example
     *              "countryName"
     * @param entry String value to store into field
     *
     * @throws WolfSSLException if arguments are invalid or error occurs
     *         with native JNI call.
     */
    private synchronized void addEntryByTxt(String field, String entry)
        throws WolfSSLException {

        int ret = 0;
        byte[] entryBytes = null;

        if (field == null || entry == null) {
            throw new WolfSSLException(
                "field or entry is null in addEntryByTxt()");
        }
        if (field.isEmpty()) {
            throw new WolfSSLException(
                "field is empty in addEntryByTxt()");
        }

        synchronized (x509NameLock) {
            entryBytes = entry.getBytes(StandardCharsets.UTF_8);

            ret = X509_NAME_add_entry_by_txt(this.x509NamePtr, field,
                    MBSTRING_UTF8, entryBytes, entryBytes.length, -1, 0);
        }

        if (ret != WolfSSL.SSL_SUCCESS) {
            throw new WolfSSLException("Error setting " + field +
                " into WolfSSLX509Name (error: " + ret + ")");
        }
    }

    /**
     * Set country name for this name object.
     *
     * @param countryName String containing country name to be set
     *
     * @throws IllegalStateException if WolfSSLX509Name has been freed.
     * @throws WolfSSLException if native JNI error has occurred, or input
     *         argument is invalid.
     */
    public synchronized void setCountryName(String countryName)
        throws IllegalStateException, WolfSSLException {

        confirmObjectIsActive();

        WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
            WolfSSLDebug.INFO, this.x509NamePtr,
            () -> "entered setCountryName(" + countryName + ")");

        addEntryByTxt("countryName", countryName);
        this.countryName = countryName;
    }

    /**
     * Set state or province name for this name object.
     *
     * @param name String containing state or province name to be set
     *
     * @throws IllegalStateException if WolfSSLX509Name has been freed.
     * @throws WolfSSLException if native JNI error has occurred, or input
     *         argument is invalid.
     */
    public synchronized void setStateOrProvinceName(String name)
        throws IllegalStateException, WolfSSLException {

        confirmObjectIsActive();

        WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
            WolfSSLDebug.INFO, this.x509NamePtr,
            () -> "entered setStateOrProvinceName(" + name + ")");

        addEntryByTxt("stateOrProvinceName", name);
        this.stateOrProvinceName = name;
    }

    /**
     * Set street address for this name object.
     *
     * @param address String containing street address to be set
     *
     * @throws IllegalStateException if WolfSSLX509Name has been freed.
     * @throws WolfSSLException if native JNI error has occurred, or input
     *         argument is invalid.
     */
    public synchronized void setStreetAddress(String address)
        throws IllegalStateException, WolfSSLException {

        confirmObjectIsActive();

        WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
            WolfSSLDebug.INFO, this.x509NamePtr,
            () -> "entered setStreetAddress(" + address + ")");

        addEntryByTxt("streetAddress", address);
        this.streetAddress = address;
    }

    /**
     * Set locality name / city for this name object.
     *
     * @param name String containing locality name to be set
     *
     * @throws IllegalStateException if WolfSSLX509Name has been freed.
     * @throws WolfSSLException if native JNI error has occurred, or input
     *         argument is invalid.
     */
    public synchronized void setLocalityName(String name)
        throws IllegalStateException, WolfSSLException {

        confirmObjectIsActive();

        WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
            WolfSSLDebug.INFO, this.x509NamePtr,
            () -> "entered setLocalityName(" + name + ")");

        addEntryByTxt("localityName", name);
        this.localityName = name;
    }

    /**
     * Set surname for this name object.
     *
     * @param name String containing surname to be set
     *
     * @throws IllegalStateException if WolfSSLX509Name has been freed.
     * @throws WolfSSLException if native JNI error has occurred, or input
     *         argument is invalid.
     */
    public synchronized void setSurname(String name)
        throws IllegalStateException, WolfSSLException {

        confirmObjectIsActive();

        WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
            WolfSSLDebug.INFO, this.x509NamePtr,
            () -> "entered setSurname(" + name + ")");

        addEntryByTxt("surname", name);
        this.surname = name;
    }

    /**
     * Set common name for this name object.
     *
     * @param name String containing common name to be set
     *
     * @throws IllegalStateException if WolfSSLX509Name has been freed.
     * @throws WolfSSLException if native JNI error has occurred, or input
     *         argument is invalid.
     */
    public synchronized void setCommonName(String name)
        throws IllegalStateException, WolfSSLException {

        confirmObjectIsActive();

        WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
            WolfSSLDebug.INFO, this.x509NamePtr,
            () -> "entered setCommonName(" + name + ")");

        addEntryByTxt("commonName", name);
        this.commonName = name;
    }

    /**
     * Set email address for this name object.
     *
     * @param email String containing email address to be set
     *
     * @throws IllegalStateException if WolfSSLX509Name has been freed.
     * @throws WolfSSLException if native JNI error has occurred, or input
     *         argument is invalid.
     */
    public synchronized void setEmailAddress(String email)
        throws IllegalStateException, WolfSSLException {

        confirmObjectIsActive();

        WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
            WolfSSLDebug.INFO, this.x509NamePtr,
            () -> "entered setEmailAddress(" + email + ")");

        addEntryByTxt("emailAddress", email);
        this.emailAddress = email;
    }

    /**
     * Set organization name for this name object.
     *
     * @param name String containing organization name to be set
     *
     * @throws IllegalStateException if WolfSSLX509Name has been freed.
     * @throws WolfSSLException if native JNI error has occurred, or input
     *         argument is invalid.
     */
    public synchronized void setOrganizationName(String name)
        throws IllegalStateException, WolfSSLException {

        confirmObjectIsActive();

        WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
            WolfSSLDebug.INFO, this.x509NamePtr,
            () -> "entered setOrganizationName(" + name + ")");

        addEntryByTxt("organizationName", name);
        this.organizationName = name;
    }

    /**
     * Set organizational unit name for this name object.
     *
     * @param name String containing organizational unit name to be set
     *
     * @throws IllegalStateException if WolfSSLX509Name has been freed.
     * @throws WolfSSLException if native JNI error has occurred, or input
     *         argument is invalid.
     */
    public synchronized void setOrganizationalUnitName(String name)
        throws IllegalStateException, WolfSSLException {

        confirmObjectIsActive();

        WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
            WolfSSLDebug.INFO, this.x509NamePtr,
            () -> "entered setOrganizationalUnitName(" + name + ")");

        addEntryByTxt("organizationalUnitName", name);
        this.organizationalUnitName = name;
    }

    /**
     * Set postal code for this name object.
     *
     * @param code String containing postal code to be set
     *
     * @throws IllegalStateException if WolfSSLX509Name has been freed.
     * @throws WolfSSLException if native JNI error has occurred, or input
     *         argument is invalid.
     */
    public synchronized void setPostalCode(String code)
        throws IllegalStateException, WolfSSLException {

        confirmObjectIsActive();

        WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
            WolfSSLDebug.INFO, this.x509NamePtr,
            () -> "entered setPostalCode(" + code + ")");

        addEntryByTxt("postalCode", code);
        this.postalCode = code;
    }

    /**
     * Set user ID for this name object.
     *
     * @param id String containing user ID to be set
     *
     * @throws IllegalStateException if WolfSSLX509Name has been freed.
     * @throws WolfSSLException if native JNI error has occurred, or input
     *         argument is invalid.
     */
    public synchronized void setUserId(String id)
        throws IllegalStateException, WolfSSLException {

        confirmObjectIsActive();

        WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
            WolfSSLDebug.INFO, this.x509NamePtr,
            () -> "entered setUserId(" + id + ")");

        addEntryByTxt("userId", id);
        this.userId = id;
    }

    /**
     * Set title for this name object.
     *
     * @param name String containing title to be set
     *
     * @throws IllegalStateException if WolfSSLX509Name has been freed.
     * @throws WolfSSLException if native JNI error has occurred, or input
     *         argument is invalid.
     */
    public synchronized void setTitle(String name)
        throws IllegalStateException, WolfSSLException {

        confirmObjectIsActive();

        WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
            WolfSSLDebug.INFO, this.x509NamePtr,
            () -> "entered setTitle(" + name + ")");

        addEntryByTxt("title", name);
        this.title = name;
    }

    /**
     * Set domain component for this name object.
     *
     * @param dc String containing domain component to be set
     *
     * @throws IllegalStateException if WolfSSLX509Name has been freed.
     * @throws WolfSSLException if native JNI error has occurred, or input
     *         argument is invalid.
     */
    public synchronized void setDomainComponent(String dc)
        throws IllegalStateException, WolfSSLException {

        confirmObjectIsActive();

        WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
            WolfSSLDebug.INFO, this.x509NamePtr,
            () -> "entered setDomainComponent(" + dc + ")");

        addEntryByTxt("domainComponent", dc);
        this.domainComponent = dc;
    }

    /**
     * Set serial number for this name object.
     *
     * @param sn String containing serial number to be set
     *
     * @throws IllegalStateException if WolfSSLX509Name has been freed.
     * @throws WolfSSLException if native JNI error has occurred, or input
     *         argument is invalid.
     */
    public synchronized void setSerialNumber(String sn)
        throws IllegalStateException, WolfSSLException {

        confirmObjectIsActive();

        WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
            WolfSSLDebug.INFO, this.x509NamePtr,
            () -> "entered setSerialNumber(" + sn + ")");

        addEntryByTxt("serialNumber", sn);
        this.serialNumber = sn;
    }

    /**
     * Get country name set in this object.
     *
     * @return country name string, or null if not yet set
     *
     * @throws IllegalStateException if WolfSSLX509Name has been freed.
     */
    public synchronized String getCountryName() {

        confirmObjectIsActive();

        WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
            WolfSSLDebug.INFO, this.x509NamePtr,
            () -> "entered getCountryName()");

        return this.countryName;
    }

    /**
     * Get state or province name set in this object.
     *
     * @return state or province name string, or null if not yet set
     *
     * @throws IllegalStateException if WolfSSLX509Name has been freed.
     */
    public synchronized String getStateOrProvinceName() {

        confirmObjectIsActive();

        WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
            WolfSSLDebug.INFO, this.x509NamePtr,
            () -> "entered getStateOrProvinceName()");

        return this.stateOrProvinceName;
    }

    /**
     * Get street address set in this object.
     *
     * @return street address string, or null if not yet set
     *
     * @throws IllegalStateException if WolfSSLX509Name has been freed.
     */
    public synchronized String getStreetAddress() {

        confirmObjectIsActive();

        WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
            WolfSSLDebug.INFO, this.x509NamePtr,
            () -> "entered getStreetAddress()");

        return this.streetAddress;
    }

    /**
     * Get locality name set in this object.
     *
     * @return locality name string, or null if not yet set
     *
     * @throws IllegalStateException if WolfSSLX509Name has been freed.
     */
    public synchronized String getLocalityName() {

        confirmObjectIsActive();

        WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
            WolfSSLDebug.INFO, this.x509NamePtr,
            () -> "entered getLocalityName()");

        return this.localityName;
    }

    /**
     * Get surname set in this object.
     *
     * @return surname string, or null if not yet set
     *
     * @throws IllegalStateException if WolfSSLX509Name has been freed.
     */
    public synchronized String getSurname() {

        confirmObjectIsActive();

        WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
            WolfSSLDebug.INFO, this.x509NamePtr,
            () -> "entered getSurname()");

        return this.surname;
    }

    /**
     * Get common name set in this object.
     *
     * @return common name string, or null if not yet set
     *
     * @throws IllegalStateException if WolfSSLX509Name has been freed.
     */
    public synchronized String getCommonName() {

        confirmObjectIsActive();

        WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
            WolfSSLDebug.INFO, this.x509NamePtr,
            () -> "entered getCommonName()");

        return this.commonName;
    }

    /**
     * Get email address set in this object.
     *
     * @return email address string, or null if not yet set
     *
     * @throws IllegalStateException if WolfSSLX509Name has been freed.
     */
    public synchronized String getEmailAddress() {

        confirmObjectIsActive();

        WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
            WolfSSLDebug.INFO, this.x509NamePtr,
            () -> "entered getEmailAddress()");

        return this.emailAddress;
    }

    /**
     * Get organization name set in this object.
     *
     * @return organization name string, or null if not yet set
     *
     * @throws IllegalStateException if WolfSSLX509Name has been freed.
     */
    public synchronized String getOrganizationName() {

        confirmObjectIsActive();

        WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
            WolfSSLDebug.INFO, this.x509NamePtr,
            () -> "entered getOrganizationName()");

        return this.organizationName;
    }

    /**
     * Get organizational unit name set in this object.
     *
     * @return organizational unit name string, or null if not yet set
     *
     * @throws IllegalStateException if WolfSSLX509Name has been freed.
     */
    public synchronized String getOrganizationalUnitName() {

        confirmObjectIsActive();

        WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
            WolfSSLDebug.INFO, this.x509NamePtr,
            () -> "entered getOrganizationalUnitName()");

        return this.organizationalUnitName;
    }

    /**
     * Get postal code set in this object.
     *
     * @return postal code string, or null if not yet set
     *
     * @throws IllegalStateException if WolfSSLX509Name has been freed.
     */
    public synchronized String getPostalCode() {

        confirmObjectIsActive();

        WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
            WolfSSLDebug.INFO, this.x509NamePtr,
            () -> "entered getPostalCode()");

        return this.postalCode;
    }

    /**
     * Get user ID set in this object.
     *
     * @return user ID string, or null if not yet set
     *
     * @throws IllegalStateException if WolfSSLX509Name has been freed.
     */
    public synchronized String getUserId() {

        confirmObjectIsActive();

        WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
            WolfSSLDebug.INFO, this.x509NamePtr,
            () -> "entered getUserId()");

        return this.userId;
    }

    /**
     * Get title set in this object.
     *
     * @return title string, or null if not yet set
     *
     * @throws IllegalStateException if WolfSSLX509Name has been freed.
     */
    public synchronized String getTitle() {

        confirmObjectIsActive();

        WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
            WolfSSLDebug.INFO, this.x509NamePtr, () -> "entered getTitle()");

        return this.title;
    }

    /**
     * Get domain component set in this object.
     *
     * @return domain component string, or null if not yet set
     *
     * @throws IllegalStateException if WolfSSLX509Name has been freed.
     */
    public synchronized String getDomainComponent() {

        confirmObjectIsActive();

        WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
            WolfSSLDebug.INFO, this.x509NamePtr,
            () -> "entered getDomainComponent()");

        return this.domainComponent;
    }

    /**
     * Get serial number set in this object.
     *
     * @return serial number string, or null if not yet set
     *
     * @throws IllegalStateException if WolfSSLX509Name has been freed.
     */
    public synchronized String getSerialNumber() {

        confirmObjectIsActive();

        WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
            WolfSSLDebug.INFO, this.x509NamePtr,
            () -> "entered getSerialNumber()");

        return this.serialNumber;
    }

    @Override
    public String toString() {

        synchronized (stateLock) {
            if (this.active == false) {
                return "";
            }
        }

        /* TODO: wrap wolfSSL_X509_NAME_oneline() */
        return "";
    }

    /**
     * Free native resources of WolfSSLX509Name.
     */
    public synchronized void free() {

        synchronized (stateLock) {
            if (this.active == false) {
                /* already freed, just return */
                return;
            }

            synchronized (x509NameLock) {

                WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                    WolfSSLDebug.INFO, this.x509NamePtr,
                    () -> "entered free()");

                /* free native resources */
                X509_NAME_free(this.x509NamePtr);

                this.active = false;
                this.x509NamePtr = 0;
            }
        }
    }

    @SuppressWarnings({"deprecation", "removal"})
    @Override
    protected void finalize() throws Throwable
    {
        this.free();
        super.finalize();
    }
}

