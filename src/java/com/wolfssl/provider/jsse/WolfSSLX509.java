/* WolfSSLX509.java
 *
 * Copyright (C) 2006-2018 wolfSSL Inc.
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

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Set;

import com.wolfssl.WolfSSLCertificate;
import com.wolfssl.WolfSSLException;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.util.logging.Level;
import java.util.logging.Logger;

public class WolfSSLX509 extends X509Certificate {
    private WolfSSLCertificate cert;
    
    public WolfSSLX509(byte[] der){
        try {
            this.cert = new WolfSSLCertificate(der);
        } catch (WolfSSLException ex) {
            Logger.getLogger(WolfSSLX509.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public WolfSSLX509(String derName) {
        try {
            this.cert = new WolfSSLCertificate(derName);
        } catch (WolfSSLException ex) {
            Logger.getLogger(WolfSSLX509.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    @Override
    public void checkValidity() throws CertificateExpiredException, CertificateNotYetValidException {
        this.checkValidity(new Date());
    }

    @Override
    public void checkValidity(Date date) throws CertificateExpiredException, CertificateNotYetValidException {
        Date after = this.cert.notAfter();
        Date before = this.cert.notBefore();
        
        if (date.after(after)) {
            throw new CertificateExpiredException();
        }
        if (date.before(before)) {
            throw new CertificateNotYetValidException();
        }
    }

    @Override
    public int getVersion() {
        return this.cert.getVersion();
    }

    @Override
    public BigInteger getSerialNumber() {
        return this.cert.getSerial();
    }

    @Override
    public Principal getIssuerDN() {
        String name = this.cert.getIssuer();
        return new WolfSSLPrincipal(name);
    }

    @Override
    public Principal getSubjectDN() {
        String name = this.cert.getSubject();
        return new WolfSSLPrincipal(name);
    }

    @Override
    public Date getNotBefore() {
        return this.cert.notBefore();
    }

    @Override
    public Date getNotAfter() {
        return this.cert.notAfter();
    }

    @Override
    public byte[] getTBSCertificate() throws CertificateEncodingException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public byte[] getSignature() {
        return this.cert.getSignature();
    }

    @Override
    public String getSigAlgName() {
        return this.cert.getSignatureType();
    }

    @Override
    public String getSigAlgOID() {
        return this.cert.getSignatureOID();
    }

    @Override
    public byte[] getSigAlgParams() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public boolean[] getIssuerUniqueID() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public boolean[] getSubjectUniqueID() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public boolean[] getKeyUsage() {
        return this.cert.getKeyUsage();
    }

    @Override
    public int getBasicConstraints() {
        if (this.cert.isCA() == 1) {
            int pLen = this.cert.getPathLen();
            if (pLen == -1) { /* if not set then return max int value */
                return Integer.MAX_VALUE;
            }
            return pLen;
        }
        return -1;
    }

    @Override
    public byte[] getEncoded() throws CertificateEncodingException {
        return this.cert.getDer();
    }

    @Override
    public void verify(PublicKey key) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
        byte[] pubKey;
        boolean ret;
        
        if (key == null) {
            throw new InvalidKeyException();
        }
        pubKey = key.getEncoded();
        ret = this.cert.verify(pubKey, pubKey.length);
        if (ret != true) {
            throw new SignatureException();
        }
    }

    @Override
    public void verify(PublicKey key, String sigProvider) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
        Provider p = Security.getProvider(sigProvider);
        Signature sig;
        String sigOID;
        byte[] sigBuf;
        
        if (key == null || sigProvider == null) {
            throw new InvalidKeyException();
        }
        
        sigOID = this.getSigAlgName();
        sigBuf = this.getSignature();
        sig = Signature.getInstance(sigOID, sigProvider);
        if (sig == null || sigBuf == null) {
            throw new CertificateException();
        }
        
        sig.initVerify(key);
        if (sig.verify(sigBuf) == false) {
            throw new SignatureException();
        }
    }

    @Override
    public String toString() {
        return this.cert.toString();
    }

    @Override
    public PublicKey getPublicKey() {
        try {
            return new WolfSSLPubKey(this.getEncoded(),
                    this.cert.getPubkeyType());
        } catch (CertificateEncodingException ex) {
            Logger.getLogger(WolfSSLX509.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    public boolean hasUnsupportedCriticalExtension() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    public Set<String> getCriticalExtensionOIDs() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    public Set<String> getNonCriticalExtensionOIDs() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    
    /* slight difference in that the ASN1 syntax is not returned.
     * i.e. no OCTET STRING Id "04 16 04 14" before subject key id */
    public byte[] getExtensionValue(String oid) {
        return this.cert.getExtension(oid);
    }
    
    
    /* wolfSSL public key class */
    private class WolfSSLPubKey implements PublicKey {
        private byte[] encoding;
        private String type;
        private String format = "X.509";
        
        private WolfSSLPubKey(byte[] der, String type) {
            this.encoding = der;
            this.type = type;
        }
        
        public String getAlgorithm() {
            return this.type;
        }

        public String getFormat() {
            return this.format;
        }

        public byte[] getEncoded() {
            return this.encoding;
        }
        
    }
    
    /* wolfSSL Principal class */
    private class WolfSSLPrincipal implements Principal {
        private String name;
        
        private WolfSSLPrincipal(String in) {
            this.name = in;
        }
        
        public String getName() {
            return this.name;
        }
        
    }
}
