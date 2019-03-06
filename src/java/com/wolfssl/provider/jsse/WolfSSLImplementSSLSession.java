/* WolfSSLImplementSession.java
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

import com.wolfssl.WolfSSLJNIException;
import com.wolfssl.WolfSSLSession;
import java.security.Principal;
import java.security.cert.Certificate;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionBindingEvent;
import javax.net.ssl.SSLSessionBindingListener;
import javax.net.ssl.SSLSessionContext;
import javax.security.cert.X509Certificate;

/**
 *
 * @author wolfSSL
 */
public class WolfSSLImplementSSLSession implements SSLSession {
    private WolfSSLSession ssl;
    private boolean valid;
    private HashMap<String, Object> binding;
    private int port;
    private String host;
    Date creation;
    Date accessed; /* when new connection was made using session */
    
    public WolfSSLImplementSSLSession (WolfSSLSession in, int port, String host) {
        this.ssl = in;
        this.port = port;
        this.host = host;
        this.valid = true; /* flag if joining or resuming session is allowed */
        binding = new HashMap();
        
        creation = new Date();
        accessed = new Date();
    }
    
    public byte[] getId() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    public SSLSessionContext getSessionContext() {
        return new WolfSSLSessionContext(this, this.ssl);
    }

    public long getCreationTime() {
        return creation.getTime();
    }

    public long getLastAccessedTime() {
        return accessed.getTime();
    }

    public void invalidate() {
        this.valid = false;
    }

    public boolean isValid() {
        return this.valid;
    }

    public void putValue(String name, Object obj) {
        if (name == null) {
            throw new IllegalArgumentException();
        }
        
        /* check if Object should be notified */
        if (obj instanceof SSLSessionBindingListener) {
            ((SSLSessionBindingListener) obj).valueBound(
                    new SSLSessionBindingEvent(this, name));
        }
        
        /* not checking return because overwriting previous obj is desired */
        binding.put(name, obj);
    }

    public Object getValue(String name) {
        return binding.get(name);
    }

    public void removeValue(String name) {
        Object obj;
        
        if (name == null) {
            throw new IllegalArgumentException();
        }
        
        obj = binding.get(name);
        if (obj == null) {
            /* name not found in hash map */
            throw new IllegalArgumentException();
        }
        
        /* check if Object should be notified */
        if (obj instanceof SSLSessionBindingListener) {
            ((SSLSessionBindingListener) obj).valueUnbound(
                    new SSLSessionBindingEvent(this, name));
        }
        binding.remove(name);
    }

    public String[] getValueNames() {
         return binding.keySet().toArray(new String[binding.keySet().size()]);
    }

    public Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException {
        long x509;
        WolfSSLX509 cert;
        
        try {
            x509 = this.ssl.getPeerCertificate();
        } catch (IllegalStateException ex) {
            Logger.getLogger(WolfSSLImplementSSLSession.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        } catch (WolfSSLJNIException ex) {
            Logger.getLogger(WolfSSLImplementSSLSession.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        }
        cert = new WolfSSLX509(x509);
        return new Certificate[] { cert };
    }

    public Certificate[] getLocalCertificates() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    public X509Certificate[] getPeerCertificateChain() throws SSLPeerUnverifiedException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    public Principal getLocalPrincipal() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    public String getCipherSuite() {
        try {
            return this.ssl.cipherGetName();
        } catch (IllegalStateException ex) {
            Logger.getLogger(WolfSSLImplementSSLSession.class.getName()).log(Level.SEVERE, null, ex);
        } catch (WolfSSLJNIException ex) {
            Logger.getLogger(WolfSSLImplementSSLSession.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    public String getProtocol() {
        try {
            return this.ssl.getVersion();
        } catch (IllegalStateException ex) {
            Logger.getLogger(WolfSSLImplementSSLSession.class.getName()).log(Level.SEVERE, null, ex);
        } catch (WolfSSLJNIException ex) {
            Logger.getLogger(WolfSSLImplementSSLSession.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    public String getPeerHost() {
        return this.host;
    }

    public int getPeerPort() {
        return this.port;
    }

    public int getPacketBufferSize() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    public int getApplicationBufferSize() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
    
    
    private class WolfSSLSessionContext implements SSLSessionContext {
        private WolfSSLImplementSSLSession session;
        private WolfSSLSession ssl;
        
        public WolfSSLSessionContext(WolfSSLImplementSSLSession in,
                WolfSSLSession ssl) {
            this.session = in;
            this.ssl = ssl;
        }

        public SSLSession getSession(byte[] arg0) {
            return session;
        }

        public Enumeration<byte[]> getIds() {
            throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        }

        public void setSessionTimeout(int arg0) throws IllegalArgumentException {
            throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        }

        public int getSessionTimeout() {
            throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        }

        public void setSessionCacheSize(int arg0) throws IllegalArgumentException {
            throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        }

        public int getSessionCacheSize() {
            throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        }
        
    }
}
