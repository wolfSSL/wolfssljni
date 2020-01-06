/* MainActivity.java
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


package com.example.wolfssl;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.widget.TextView;
import android.Manifest;
import android.content.pm.PackageManager;

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLException;
import com.wolfssl.provider.jsse.WolfSSLProvider;
import com.wolfssl.provider.jsse.WolfSSLX509;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateException;

import javax.net.ssl.SSLEngine;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        int permission;
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        TextView tv = (TextView) findViewById(R.id.sample_text);
        tv.setText("wolfSSL JNI Android Studio Example App");


        permission = checkSelfPermission(Manifest.permission.READ_EXTERNAL_STORAGE);
        if (permission != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[] {Manifest.permission.READ_EXTERNAL_STORAGE},1);
        }

        try {
            testLoadCert(tv);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void testLoadCert(TextView tv)
            throws NoSuchProviderException, NoSuchAlgorithmException, KeyStoreException, IOException, CertificateException, WolfSSLException {
        SSLEngine e;
        String file = "/sdcard/examples/provider/all.bks";
        WolfSSLX509 x509;
        KeyStore ks;


        WolfSSL.loadLibrary();

        /* create new SSLEngine */
        Security.addProvider(new WolfSSLProvider());

        Provider p = Security.getProvider("wolfJSSE");
        if (p == null) {
            System.out.println("Unable to find wolfJSSE provider");
            return;
        }

        ks = KeyStore.getInstance("BKS");
        ks.load(new FileInputStream(file), "wolfSSL test".toCharArray());

        x509 = new WolfSSLX509(ks.getCertificate("server").getEncoded());
        tv.setText("Server Certificate Found:\n" + x509.toString());
    }
}
