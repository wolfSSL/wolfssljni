/* WolfSSLAltName.java
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

package com.wolfssl;

import java.io.Serializable;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;

/**
 * Represents a Subject Alternative Name (SAN) entry from an X.509 certificate.
 *
 * This class encapsulates the type and value of a GeneralName as defined in
 * RFC 5280. It provides access to SAN data including special handling for
 * otherName types used by Microsoft Active Directory for
 * User Principal Names (UPN).
 *
 * GeneralName types (from RFC 5280):
 * <ul>
 *   <li>0 = otherName</li>
 *   <li>1 = rfc822Name (email)</li>
 *   <li>2 = dNSName</li>
 *   <li>3 = x400Address (not supported)</li>
 *   <li>4 = directoryName</li>
 *   <li>5 = ediPartyName (not supported)</li>
 *   <li>6 = uniformResourceIdentifier (URI)</li>
 *   <li>7 = iPAddress</li>
 *   <li>8 = registeredID</li>
 * </ul>
 *
 * Example usage for parsing Microsoft AD UPN:
 * <pre>
 * WolfSSLAltName[] sans = cert.getSubjectAltNamesArray();
 * for (WolfSSLAltName san : sans) {
 *     if (san.getType() == WolfSSLAltName.TYPE_OTHER_NAME) {
 *         if (WolfSSLAltName.OID_MS_UPN.equals(san.getOtherNameOID())) {
 *             byte[] valueBytes = san.getOtherNameValue();
 *             String upn = san.getOtherNameValueAsString();
 *         }
 *     }
 * }
 * </pre>
 *
 * @author wolfSSL
 */
public final class WolfSSLAltName implements Serializable {

    private static final long serialVersionUID = 1L;

    /* GeneralName type constants (RFC 5280) */

    /** otherName [0] */
    public static final int TYPE_OTHER_NAME = 0;
    /** rfc822Name [1] - email address */
    public static final int TYPE_RFC822_NAME = 1;
    /** dNSName [2] */
    public static final int TYPE_DNS_NAME = 2;
    /** x400Address [3] - not supported */
    public static final int TYPE_X400_ADDRESS = 3;
    /** directoryName [4] */
    public static final int TYPE_DIRECTORY_NAME = 4;
    /** ediPartyName [5] - not supported */
    public static final int TYPE_EDI_PARTY_NAME = 5;
    /** uniformResourceIdentifier [6] */
    public static final int TYPE_URI = 6;
    /** iPAddress [7] */
    public static final int TYPE_IP_ADDRESS = 7;
    /** registeredID [8] */
    public static final int TYPE_REGISTERED_ID = 8;

    /* Well-known OIDs for otherName types */

    /** Microsoft UPN (User Principal Name) OID: 1.3.6.1.4.1.311.20.2.3 */
    public static final String OID_MS_UPN = "1.3.6.1.4.1.311.20.2.3";

    /** GeneralName type (0-8), see TYPE_* constants */
    private final int type;
    /** String value for string-based SAN types */
    private final String stringValue;
    /** Byte array value for iPAddress type */
    private final byte[] bytesValue;
    /** OID string for otherName type */
    private final String otherNameOID;
    /** ASN.1 DER-encoded value for otherName type */
    private final byte[] otherNameValue;

    /**
     * Creates a WolfSSLAltName for string-based types (email, DNS, URI, etc).
     *
     * @param type SAN type (1, 2, 4, 6, or 8)
     * @param value String value
     */
    WolfSSLAltName(int type, String value) {
        this.type = type;
        this.stringValue = value;
        this.bytesValue = null;
        this.otherNameOID = null;
        this.otherNameValue = null;
    }

    /**
     * Creates a WolfSSLAltName for byte-based types (iPAddress).
     *
     * @param type SAN type (7 for iPAddress)
     * @param value byte array value
     */
    WolfSSLAltName(int type, byte[] value) {
        this.type = type;
        this.stringValue = null;
        this.bytesValue = (value != null) ? value.clone() : null;
        this.otherNameOID = null;
        this.otherNameValue = null;
    }

    /**
     * Creates a WolfSSLAltName for otherName type with OID and value.
     *
     * @param oid OID string (e.g., "1.3.6.1.4.1.311.20.2.3" for MS UPN)
     * @param value ASN.1 DER-encoded value bytes
     */
    WolfSSLAltName(String oid, byte[] value) {
        this.type = TYPE_OTHER_NAME;
        this.stringValue = null;
        this.bytesValue = null;
        this.otherNameOID = oid;
        this.otherNameValue = (value != null) ? value.clone() : null;
    }

    /**
     * Returns the GeneralName type.
     *
     * @return type constant (0-8), see TYPE_* constants
     */
    public int getType() {
        return type;
    }

    /**
     * Returns a human-readable name for the type.
     *
     * @return type name string
     */
    public String getTypeName() {
        switch (type) {
            case TYPE_OTHER_NAME:
                return "otherName";
            case TYPE_RFC822_NAME:
                return "rfc822Name";
            case TYPE_DNS_NAME:
                return "dNSName";
            case TYPE_X400_ADDRESS:
                return "x400Address";
            case TYPE_DIRECTORY_NAME:
                return "directoryName";
            case TYPE_EDI_PARTY_NAME:
                return "ediPartyName";
            case TYPE_URI:
                return "uniformResourceIdentifier";
            case TYPE_IP_ADDRESS:
                return "iPAddress";
            case TYPE_REGISTERED_ID:
                return "registeredID";
            default:
                return "unknown(" + type + ")";
        }
    }

    /**
     * Returns the string value for string-based types.
     *
     * Applicable for types: rfc822Name (1), dNSName (2), directoryName (4),
     * uniformResourceIdentifier (6), registeredID (8).
     *
     * @return string value, or null if not a string-based type
     */
    public String getStringValue() {
        return stringValue;
    }

    /**
     * Returns the byte array value for iPAddress type.
     *
     * For IPv4, returns 4 bytes. For IPv6, returns 16 bytes.
     *
     * @return copy of IP address bytes, or null if not iPAddress type
     */
    public byte[] getIPAddress() {
        if (type == TYPE_IP_ADDRESS && bytesValue != null) {
            return bytesValue.clone();
        }
        return null;
    }

    /**
     * Returns the IP address as a formatted string.
     *
     * Uses java.net.InetAddress for canonical formatting, which provides
     * proper IPv6 compression (e.g., "::1" instead of "0:0:0:0:0:0:0:1").
     *
     * @return IP address string (e.g., "127.0.0.1" or "::1"), or null if
     *         not iPAddress type or invalid IP bytes
     */
    public String getIPAddressString() {
        if (type != TYPE_IP_ADDRESS || bytesValue == null) {
            return null;
        }

        /* Validate IP address byte length (4 for IPv4, 16 for IPv6) */
        if (bytesValue.length != 4 && bytesValue.length != 16) {
            return null;
        }

        try {
            return InetAddress.getByAddress(bytesValue).getHostAddress();
        }
        catch (UnknownHostException e) {
            /* Should not happen with valid 4 or 16 byte arrays */
            return null;
        }
    }

    /**
     * Returns the OID for otherName type.
     *
     * @return OID string (e.g., "1.3.6.1.4.1.311.20.2.3"), or null if not
     *         otherName type
     */
    public String getOtherNameOID() {
        return otherNameOID;
    }

    /**
     * Returns the ASN.1 DER-encoded value for otherName type.
     *
     * @return copy of value bytes, or null if not otherName type
     */
    public byte[] getOtherNameValue() {
        if (otherNameValue != null) {
            return otherNameValue.clone();
        }
        return null;
    }

    /**
     * Attempts to parse the otherName value as a UTF-8 string.
     *
     * This is useful for Microsoft UPN values which are encoded as
     * UTF8String. The method handles simple ASN.1 UTF8String (tag 0x0C)
     * encoding.
     *
     * @return decoded string value, or null if parsing fails or not
     *         otherName type
     */
    public String getOtherNameValueAsString() {
        if (type != TYPE_OTHER_NAME || otherNameValue == null ||
            otherNameValue.length < 2) {
            return null;
        }

        /* Check for UTF8String tag (0x0C) */
        if (otherNameValue[0] != 0x0C) {
            return null;
        }

        int len = otherNameValue[1] & 0xFF;
        int offset = 2;

        /* Handle long form length (support up to 4 octets for large values) */
        if ((len & 0x80) != 0) {
            int numOctets = len & 0x7F;
            if (numOctets < 1 || numOctets > 4 ||
                otherNameValue.length < 2 + numOctets) {
                return null;
            }
            long longLen = 0;
            for (int i = 0; i < numOctets; i++) {
                longLen = (longLen << 8) | (otherNameValue[offset++] & 0xFF);
            }
            if (longLen > Integer.MAX_VALUE) {
                return null;
            }
            len = (int)longLen;
        }

        if (len < 0 || len > otherNameValue.length - offset) {
            return null;
        }

        try {
            return new String(otherNameValue, offset, len, "UTF-8");
        }
        catch (Exception e) {
            return null;
        }
    }

    /**
     * Checks if this is a Microsoft UPN otherName entry.
     *
     * @return true if this is an otherName with MS UPN OID
     */
    public boolean isMicrosoftUPN() {
        return type == TYPE_OTHER_NAME && OID_MS_UPN.equals(otherNameOID);
    }

    /**
     * Returns the value in a format suitable for display or logging.
     *
     * @return formatted value string
     */
    public String getValue() {
        switch (type) {
            case TYPE_OTHER_NAME:
                String upnStr = getOtherNameValueAsString();
                if (upnStr != null) {
                    return upnStr;
                }
                return (otherNameOID != null) ? otherNameOID : "";
            case TYPE_IP_ADDRESS:
                String ipStr = getIPAddressString();
                return (ipStr != null) ? ipStr : "";
            default:
                return (stringValue != null) ? stringValue : "";
        }
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(getTypeName()).append(":");
        switch (type) {
            case TYPE_OTHER_NAME:
                sb.append("OID=").append(otherNameOID);
                String val = getOtherNameValueAsString();
                if (val != null) {
                    sb.append(",value=").append(val);
                }
                break;
            case TYPE_IP_ADDRESS:
                sb.append(getIPAddressString());
                break;
            default:
                sb.append(stringValue);
                break;
        }
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof WolfSSLAltName)) {
            return false;
        }
        WolfSSLAltName other = (WolfSSLAltName) obj;
        if (type != other.type) {
            return false;
        }
        if (stringValue != null) {
            return stringValue.equals(other.stringValue);
        }
        if (bytesValue != null) {
            return Arrays.equals(bytesValue, other.bytesValue);
        }
        if (otherNameOID != null) {
            return otherNameOID.equals(other.otherNameOID) &&
                   Arrays.equals(otherNameValue, other.otherNameValue);
        }
        return true;
    }

    @Override
    public int hashCode() {
        int result = type;
        if (stringValue != null) {
            result = 31 * result + stringValue.hashCode();
        }
        if (bytesValue != null) {
            result = 31 * result + Arrays.hashCode(bytesValue);
        }
        if (otherNameOID != null) {
            result = 31 * result + otherNameOID.hashCode();
        }
        if (otherNameValue != null) {
            result = 31 * result + Arrays.hashCode(otherNameValue);
        }
        return result;
    }
}

