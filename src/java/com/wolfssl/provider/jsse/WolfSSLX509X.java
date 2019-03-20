/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.wolfssl.provider.jsse;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.Date;
import javax.security.cert.CertificateEncodingException;
import javax.security.cert.CertificateException;
import javax.security.cert.CertificateExpiredException;
import javax.security.cert.CertificateNotYetValidException;
import javax.security.cert.X509Certificate;

/**
 * javax version of certificates
 * 
 * @author wolfSSL
 */
public class WolfSSLX509X extends X509Certificate {
    WolfSSLX509 cert;
    
    public WolfSSLX509X(byte[] der){
        this.cert = new WolfSSLX509(der);
    }
    
    public WolfSSLX509X(String derName) {
        this.cert = new WolfSSLX509(derName);
    }
    
    public WolfSSLX509X(long x509) {
        this.cert = new WolfSSLX509(x509);
    }
    
    @Override
    public void checkValidity() throws CertificateExpiredException, CertificateNotYetValidException {
        try {
            this.cert.checkValidity();
        } catch (java.security.cert.CertificateExpiredException ex) {
            throw new CertificateExpiredException();
        } catch (java.security.cert.CertificateNotYetValidException ex) {
            throw new CertificateNotYetValidException();
        }
    }

    @Override
    public void checkValidity(Date date) throws CertificateExpiredException, CertificateNotYetValidException {
        try {
            this.cert.checkValidity(date);
        } catch (java.security.cert.CertificateExpiredException ex) {
            throw new CertificateExpiredException();
        } catch (java.security.cert.CertificateNotYetValidException ex) {
            throw new CertificateNotYetValidException();
        }
    }

    @Override
    public int getVersion() {
        return this.cert.getVersion();
    }

    @Override
    public BigInteger getSerialNumber() {
        return this.cert.getSerialNumber();
    }

    @Override
    public Principal getIssuerDN() {
        return this.cert.getIssuerDN();
    }

    @Override
    public Principal getSubjectDN() {
        return this.cert.getSubjectDN();
    }

    @Override
    public Date getNotBefore() {
        return this.cert.getNotBefore();
    }

    @Override
    public Date getNotAfter() {
        return this.cert.getNotAfter();
    }

    @Override
    public String getSigAlgName() {
        return this.cert.getSigAlgName();
    }

    @Override
    public String getSigAlgOID() {
        return this.cert.getSigAlgOID();
    }

    @Override
    public byte[] getSigAlgParams() {
        return this.cert.getSigAlgParams();
    }

    @Override
    public byte[] getEncoded() throws CertificateEncodingException {
        try {
            return this.cert.getEncoded();
        } catch (java.security.cert.CertificateEncodingException ex) {
            throw new CertificateEncodingException();
        }
    }

    @Override
    public void verify(PublicKey key) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
        try {
            this.cert.verify(key);
        } catch (java.security.cert.CertificateException ex) {
            throw new CertificateException();
        }
    }

    @Override
    public void verify(PublicKey key, String provider) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
        try {
            this.cert.verify(key, provider);
        } catch (java.security.cert.CertificateException ex) {
            throw new CertificateException();
        }
    }

    @Override
    public String toString() {
        return this.cert.toString();
    }

    @Override
    public PublicKey getPublicKey() {
        return this.cert.getPublicKey();
    }
    
    @Override
    public void finalize() throws Throwable {
        super.finalize();
        this.cert.free();
    }
    
}