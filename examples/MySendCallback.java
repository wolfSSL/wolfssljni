/* MySendCallback.java
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

class MySendCallback implements WolfSSLIOSendCallback
{
    public int sendCallback(WolfSSLSession ssl, byte[] buf, int sz,
           Object ctx) {

        MyIOCtx ioctx = (MyIOCtx) ctx;
        int doDTLS = ioctx.isDTLS();
        
        if (doDTLS == 1) {

            DatagramSocket dsock = ioctx.getDatagramSocket();
            InetAddress hostAddr = ioctx.getHostAddress();
            int port = ioctx.getPort();
            DatagramPacket dp = new DatagramPacket(buf, sz, hostAddr, port);
            
            try {
                dsock.send(dp);

            } catch (IOException ioe) {
                ioe.printStackTrace();
                return WolfSSL.CYASSL_CBIO_ERR_GENERAL; 
            } catch (Exception e) {
                e.printStackTrace();
                return WolfSSL.CYASSL_CBIO_ERR_GENERAL; 
            }

            return dp.getLength();
        } else {
            DataOutputStream os = ioctx.getOutputStream();
            if (os == null) {
                System.out.println("DataOutputStream is null in sendCallback!");
                System.exit(1);
            }

            try {
                os.write(buf, 0, sz);
            } catch (IOException e) {
                e.printStackTrace();
                return WolfSSL.CYASSL_CBIO_ERR_GENERAL; 
            }
        }

        return sz;
    }
}

