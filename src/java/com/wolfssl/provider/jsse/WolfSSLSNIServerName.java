/* WolfSSLSNIServerName.java
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */
package com.wolfssl.provider.jsse;

import java.util.Objects;
import java.util.Arrays;

/**
 * wolfJSSE implementation that replicates functionality of the Java
 * SNIServerName class. Used for internal WolfSSLParameters, unable to use
 * standard class as some Java versions less than 1.8 do not have it
 * available
 */
public abstract class WolfSSLSNIServerName
{
    private int type;
    private byte[] encoded = null;

    protected WolfSSLSNIServerName(int type, byte[] encoded) {

        if (type < 0 || type > 255) {
            throw new IllegalArgumentException(
                "type must be between 0 and 255");
        }

        if (encoded == null) {
            throw new NullPointerException(
                "encoded input array cannot be null");
        }

        this.type = type;
        this.encoded = encoded.clone();
    }

    public final int getType() {
        return this.type;
    }

    public final byte[] getEncoded() {
        if (this.encoded == null) {
            return null;
        }
        return encoded.clone();
    }

    public boolean equals(Object other) {
        if (!(other instanceof WolfSSLSNIServerName)) {
            return false;
        }
        WolfSSLSNIServerName tmp = (WolfSSLSNIServerName)other;

        if (tmp.type != this.type) {
            return false;
        }

        if (!Arrays.equals(tmp.encoded, this.encoded)) {
            return false;
        }

        return true;
    }

    public int hashCode() {
        return Objects.hash(this.type, this.encoded);
    }

    public String toString() {
        StringBuilder s = new StringBuilder();
        s.append("type=(" + this.type + "), ");

        for (byte b : this.encoded) {
            String h = Integer.toHexString((int)b & 0xff);
            s.append(h);
        }

        return s.toString();
    }
}

