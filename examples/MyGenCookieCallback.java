/* MyGenCookieCallback.java
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

import java.io.*;
import java.net.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import com.wolfssl.*;

class MyGenCookieCallback implements WolfSSLGenCookieCallback
{
    public int genCookieCallback(WolfSSLSession ssl, byte[] buf, int sz,
            Object ctx) {

        int port = 0;
        byte[] out = null;
        InetAddress hostAddr = null;
        MessageDigest digest = null;

        MyGenCookieCtx gctx = (MyGenCookieCtx) ctx;
        hostAddr = gctx.getAddress();
        port = gctx.getPort();

        if ( (hostAddr == null) || (port == 0))
            return WolfSSL.GEN_COOKIE_E;

        try {

            digest = MessageDigest.getInstance("SHA-1");
            digest.reset();
            digest.update(hostAddr.getHostAddress().getBytes());
            digest.update((byte)port);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return WolfSSL.GEN_COOKIE_E;
        }

        out = new byte[digest.getDigestLength()];

        out = digest.digest();
        if (sz > digest.getDigestLength())
            sz = digest.getDigestLength();

        System.arraycopy(out, 0, buf, 0, sz);

        return buf.length;
    }
}

