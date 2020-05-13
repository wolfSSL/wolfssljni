/* WolfSSLJDK8Helper.java
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

import java.util.List;
import java.util.ArrayList;
import java.lang.reflect.Method;
import java.security.AccessController;
import java.security.PrivilegedAction;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SNIHostName;

/**
 * This class contains functionality that was added as of JDK 1.8, and is
 * isolated in this class as to more easily avoid pre-JDK 1.8 execution from
 * loading this class. Otherwise, importing the classes that did not exist
 * on older JDKs would fail.
 *
 * Execution should be prevented from calling functions in this class on
 * JDK version less than 1.8.
 */
public class WolfSSLJDK8Helper
{
    /* Call SSLParameters.setServerNames() to set SNI server names from
     * WolfSSLParameters into SSLParameters */
    protected static void setServerNames(final SSLParameters out,
                                         final Method m, WolfSSLParameters in) {

        if (out == null || m == null || in == null) {
            throw new NullPointerException("input arguments to " +
                "WolfSSLJDK8Helper.setServerNames() cannot be null");
        }

        List<WolfSSLSNIServerName> wsni = in.getServerNames();
        if (wsni != null) {
            /* convert WolfSSLSNIServerName list to SNIServerName */
            final ArrayList<SNIServerName> sni = new ArrayList<SNIServerName>(wsni.size());
            for (WolfSSLSNIServerName name : wsni) {
                sni.add(new SNIHostName(name.getEncoded()));
            }

            /* call SSLParameters.setServerName() */
            AccessController.doPrivileged(new PrivilegedAction<Object>() {
                public Object run() {
                    try {
                        m.invoke(out, sni);
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }

                    return null;
                }
            });
        }
    }

    /* Call SSLParameters.getServerNames() to set SNI server names from
     * SSLParameters into WolfSSLParameters */
    protected static void getServerNames(final SSLParameters in,
                                         WolfSSLParameters out) {

        if (out == null || in == null) {
            throw new NullPointerException("input arguments to " +
                "WolfSSLJDK8Helper.getServerNames() cannot be null");
        }

        List<SNIServerName> sni = in.getServerNames();
        if (sni != null) {
            /* convert SNIServerName list to WolfSSLSNIServerName */
            final ArrayList<WolfSSLSNIServerName> wsni = new ArrayList<WolfSSLSNIServerName>(sni.size());
            for (SNIServerName name : sni) {
                wsni.add(new WolfSSLGenericHostName(name.getType(), name.getEncoded()));
            }

            /* call WolfSSLParameters.setServerNames() */
            out.setServerNames(wsni);
        }
    }
}

