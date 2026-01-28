/* WolfSSLGeneralName.java
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

/**
 * Represents an X.509 GeneralName (RFC 5280).
 * Used as the base type in name constraints.
 *
 * @author wolfSSL
 */
public class WolfSSLGeneralName {

    /** otherName */
    public static final int GEN_OTHERNAME  = 0;
    /** rfc822Name */
    public static final int GEN_EMAIL      = 1;
    /** dNSName */
    public static final int GEN_DNS        = 2;
    /** x400Address */
    public static final int GEN_X400       = 3;
    /** directoryName */
    public static final int GEN_DIRNAME    = 4;
    /** ediPartyName */
    public static final int GEN_EDIPARTY   = 5;
    /** uniformResourceIdentifier */
    public static final int GEN_URI        = 6;
    /** iPAddress */
    public static final int GEN_IPADD      = 7;
    /** registeredID */
    public static final int GEN_RID        = 8;

    private int type;
    private String value;

    /**
     * Create a new GeneralName.
     *
     * @param type GeneralName type (GEN_DNS, GEN_EMAIL, etc.)
     * @param value String representation of the name
     */
    public WolfSSLGeneralName(int type, String value) {
        this.type = type;
        this.value = value;
    }

    /**
     * Get the GeneralName type.
     *
     * @return One of the GEN_* constants
     */
    public int getType() {
        return type;
    }

    /**
     * Get the name value as a string.
     *
     * @return The name value
     */
    public String getValue() {
        return value;
    }

    /**
     * Get human-readable type name.
     *
     * @return String representation of the type
     */
    public String getTypeName() {
        switch (type) {
            case GEN_OTHERNAME: return "otherName";
            case GEN_EMAIL:     return "email";
            case GEN_DNS:       return "DNS";
            case GEN_X400:      return "x400";
            case GEN_DIRNAME:   return "dirName";
            case GEN_EDIPARTY:  return "ediParty";
            case GEN_URI:       return "URI";
            case GEN_IPADD:     return "IP";
            case GEN_RID:       return "RID";
            default:            return "unknown(" + type + ")";
        }
    }

    @Override
    public String toString() {
        return getTypeName() + ":" + value;
    }
}

