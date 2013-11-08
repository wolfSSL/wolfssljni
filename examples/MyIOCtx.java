/* MyIOCtx.java
 *
 * Copyright (C) 2006-2013 wolfSSL Inc.
 *
 * This file is part of CyaSSL.
 *
 * CyaSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * CyaSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

import java.io.*;
import java.net.*;
import java.nio.*;
import com.wolfssl.*;

class MyIOCtx
{
    private DataOutputStream out;
    private DataInputStream in;
    private DatagramSocket dsock;
    private InetAddress hostAddress;
    private int port;

    /* if not using DTLS, sock and hostAddr may be null */
    public MyIOCtx(DataOutputStream outStr, DataInputStream inStr,
            DatagramSocket s, InetAddress hostAddr, int port) {
        this.out = outStr;
        this.in = inStr;
        this.dsock = s;
        this.hostAddress = hostAddr;
        this.port = port;
    }

    public void test() {
        if (this.out == null) {
            System.out.println("out is NULL!");
            System.exit(1);
        }
        if (this.in == null) {
            System.out.println("in is NULL!");
            System.exit(1);
        }
    }

    public DataOutputStream getOutputStream() {
        return this.out;
    }

    public DataInputStream getInputStream() {
        return this.in;
    }

    public DatagramSocket getDatagramSocket() {
        return this.dsock;
    }

    public InetAddress getHostAddress() {
        return this.hostAddress;
    }

    public void setAddress(InetAddress addr) {
        this.hostAddress = addr;
    }

    public int getPort() {
        return this.port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public int isDTLS() {
        if (dsock != null)
            return 1;
        else
            return 0;
    }
}

