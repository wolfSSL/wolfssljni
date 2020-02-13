/* WolfSSLX509StoreCtxjava
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

import com.wolfssl.WolfSSLCertificate;

public class WolfSSLX509StoreCtx {

    private boolean active = false;
    private long ctxPtr = 0;

    static native byte[][] X509_STORE_CTX_getDerCerts(long ctxPtr);

    public WolfSSLX509StoreCtx(long ctxPtr) throws WolfSSLException {
        if (ctxPtr == 0) {
            throw new WolfSSLException("Failed to create " +
                "WolfSSLX509StoreCtx, input ptr was null");
        }
        this.active = true;
        this.ctxPtr = ctxPtr;
    }

    /**
     * Get certificates in WOLFSSL_X509_STORE_CTX as an array of
     * WolfSSLCertificate objects.
     *
     * @return array of certificates
     * @throws WolfSSLException on error
     */
    public WolfSSLCertificate[] getCerts() throws WolfSSLException {

        WolfSSLCertificate[] certs = null;

        if (this.active == false)
            throw new IllegalStateException("Object is not active");

        byte[][] derCerts = X509_STORE_CTX_getDerCerts(this.ctxPtr);

        if (derCerts != null) {
            certs = new WolfSSLCertificate[derCerts.length];

            for (int i = 0; i < derCerts.length; i++) {
                byte[] derCert = derCerts[i];
                certs[i] = new WolfSSLCertificate(derCert);
            }
        }

        return certs;
    }
}

