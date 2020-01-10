/* MyPskServerCallback.java
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
import java.nio.*;
import com.wolfssl.*;

class MyPskServerCallback implements WolfSSLPskServerCallback
{
    public long pskServerCallback(WolfSSLSession ssl, String identity,
            byte[] key, long keyMaxLen) {

        System.out.println("PSK Server Callback:");

        /* check the client identity */
        System.out.println(" | PSK identity : " + identity);
        if (!identity.equals("Client_identity")) {
            System.out.println("Client PSK identity isn't what we expect!\n");
            return 0;
        }

        /* set the server key, max key size is key.length */
        key[0] = 26;
        key[1] = 43;
        key[2] = 60;
        key[3] = 77;

        /* return size of key */
        return 4;
    }
}

