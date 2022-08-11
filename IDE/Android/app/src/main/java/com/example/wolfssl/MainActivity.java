/* MainActivity.java
 *
 * Copyright (C) 2006-2022 wolfSSL Inc.
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

import android.content.Intent;
import android.net.Uri;
import android.os.Environment;
import android.provider.Settings;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLException;
import com.wolfssl.provider.jsse.WolfSSLProvider;
import com.wolfssl.provider.jsse.WolfSSLX509;

import java.io.FileInputStream;
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

    private View.OnClickListener buttonListener = new View.OnClickListener() {
        @Override
        public void onClick(View v) {
            TextView tv = (TextView) findViewById(R.id.sample_text);

            try {
                testLoadCert(tv);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        int permission;
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Button button = (Button) findViewById(R.id.button);
        button.setOnClickListener(buttonListener);

        TextView tv = (TextView) findViewById(R.id.sample_text);
        tv.setText("wolfSSL JNI Android Studio Example App");


        if (Environment.isExternalStorageManager()) {
        } else {
            Intent intent = new Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION);
            Uri uri = Uri.fromParts("package", getPackageName(), null);
            intent.setData(uri);
            startActivity(intent);
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
