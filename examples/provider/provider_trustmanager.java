/* provider_server.java
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

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import com.wolfssl.provider.jsse.WolfSSLProvider;
import com.wolfssl.WolfSSL;
        
public class provider_trustmanager {
    public provider_trustmanager(){}

    public void test_trustmanager() throws NoSuchAlgorithmException, KeyManagementException,
            IOException, KeyStoreException, CertificateException,
            UnrecoverableKeyException {
        KeyStore cert;
        TrustManagerFactory tm;
        char[] psw = "wolfSSL test".toCharArray();
        InputStream in;
        X509TrustManager X509tm;
        X509Certificate serv;
        X509Certificate servEcc;
        X509Certificate CAs[];
        X509Certificate chain[];
        
 
        
        System.out.printf("Inserted wolfSSL at position %d\n",
                Security.insertProviderAt(new WolfSSLProvider(), 1));

        
        in = new FileInputStream("../certs/server-cert.pem");
        serv = (X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(in);

        in = new FileInputStream("../certs/server-ecc.pem");
        servEcc = (X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(in);

        
        cert = KeyStore.getInstance("JKS");
        cert.load(new FileInputStream("../provider/server.jks"), psw);
        
        /* trust manager (certificates) */
        tm = TrustManagerFactory.getInstance("X509");
        tm.init(cert);
        System.out.printf("Provider name = %s\n", tm.getProvider().getName());

        X509tm = (X509TrustManager)tm.getTrustManagers()[0];
        CAs = X509tm.getAcceptedIssuers();
        if (CAs.length > 0) {
            System.out.printf("Found %d CAs\n", CAs.length);
        }
        
        chain = new X509Certificate[]{serv};
        X509tm.checkServerTrusted(chain, "RSA");
        System.out.println("Verified serv ok");
        
        try {
            chain[0] = servEcc;
            X509tm.checkServerTrusted(chain, "ECC");
        }
        catch (Exception ex) {
            System.out.println("Found exception success");
        }
    }
    
    public static void main(String[] args) {
        provider_trustmanager t = new provider_trustmanager();
        try {        
            WolfSSL.loadLibrary();
            //WolfSSL ssl = new WolfSSL();
            //ssl.debuggingON();
            t.test_trustmanager();
        } catch (Exception ex) {
            Logger.getLogger(provider_trustmanager.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
