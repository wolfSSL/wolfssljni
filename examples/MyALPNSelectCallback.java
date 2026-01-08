/* MyALPNSelectCallback.java
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

import java.io.*;
import java.net.*;
import java.nio.*;
import com.wolfssl.*;

class MyALPNSelectCallback implements WolfSSLALPNSelectCallback
{
    public int alpnSelectCallback(WolfSSLSession ssl, String[] out,
        String[] in, Object arg) {

        System.out.println("Entered MyALPNSelectCallback");
        System.out.println("... out.length = " + out.length);
        if (out.length > 0) {
            System.out.println("out[0] = " + out[0]);
        }
        System.out.println("... in.length = " + in.length);
        if (in.length > 0) {
            System.out.println("in[0] = " + in[0]);
        }
        System.out.println("... arg = " + arg);

        if (in.length > 0 && in[0].equals("h2")) {
            out[0] = "h22";
            return WolfSSL.SSL_TLSEXT_ERR_OK;
        }

        return WolfSSL.SSL_TLSEXT_ERR_ALERT_FATAL;
    }
}

