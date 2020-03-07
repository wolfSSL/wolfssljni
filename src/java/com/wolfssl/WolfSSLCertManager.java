/* WolfSSLCertManager.java
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

package com.wolfssl;

/**
 * CertManager class which wraps the native WolfSSL embedded SSL library.
 * This class contains library init and cleanup methods, general callback
 * methods, as well as error codes and general wolfSSL codes.
 *
 * @author  wolfSSL
 * @version 1.1, February 2019
 */
public class WolfSSLCertManager {
    private boolean active = false;
    private long cmPtr;

    static native long CertManagerNew();
    static native void CertManagerFree(long cm);
    static native int CertManagerLoadCA(long cm, String f, String d);
    static native int CertManagerLoadCABuffer(long cm, byte[] in, long sz,
                                              int format);
    static native int CertManagerVerifyBuffer(long cm, byte[] in, long sz,
                                              int format);

    public WolfSSLCertManager() throws WolfSSLException {
        cmPtr = CertManagerNew();
        if (cmPtr == 0) {
            throw new WolfSSLException("Failed to create SSL Context");
        }
        this.active = true;
    }

    public int CertManagerLoadCA(String f, String d) {
        if (this.active == false)
            throw new IllegalStateException("Object has been freed");

        return CertManagerLoadCA(this.cmPtr, f, d);
    }

    public int CertManagerLoadCABuffer(byte[] in, long sz, int format) {
        if (this.active == false)
            throw new IllegalStateException("Object has been freed");

        return CertManagerLoadCABuffer(this.cmPtr, in, sz, format);
    }

    public int CertManagerVerifyBuffer(byte[] in, long sz, int format) {
        if (this.active == false)
            throw new IllegalStateException("Object has been freed");

        return CertManagerVerifyBuffer(this.cmPtr, in, sz, format);
    }

    /**
     * Frees an CertManager.
     *
     * @throws IllegalStateException WolfSSLContext has been freed
     * @see         WolfSSLSession#freeSSL()
     */
    public void free() throws IllegalStateException {

        if (this.active == false)
            throw new IllegalStateException("Object has been freed");

        /* free native resources */
        CertManagerFree(this.cmPtr);

        /* free Java resources */
        this.active = false;
    }

    @SuppressWarnings("deprecation")
    @Override
    protected void finalize() throws Throwable
    {
        if (this.active == true) {
            /* free resources, set state */
            this.free();
            this.active = false;
        }
        super.finalize();
    }
}
