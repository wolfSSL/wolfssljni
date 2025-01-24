/* MainActivity.java
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */


package com.example.wolfssl;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLException;
import com.wolfssl.provider.jsse.WolfSSLProvider;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;

public class MainActivity extends AppCompatActivity {

    private View.OnClickListener buttonListener = new View.OnClickListener() {
        @Override
        public void onClick(View v) {
            TextView tv = (TextView) findViewById(R.id.sample_text);

            try {
                testFindProvider(tv);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    };

    private void setDisplayText(String s)
    {
        runOnUiThread(() -> {
            TextView tv = (TextView) findViewById(R.id.sample_text);
            tv.setText(s);
        });
    }

    private void appendDisplayText(String s)
    {
        runOnUiThread(() -> {
            TextView tv = (TextView) findViewById(R.id.sample_text);
            tv.append(s);
        });
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Button button = (Button) findViewById(R.id.button);
        button.setOnClickListener(buttonListener);

        setDisplayText("wolfSSL JNI Android Studio Example App\n");
    }

    public void testFindProvider(TextView tv)
            throws NoSuchProviderException, NoSuchAlgorithmException,
                   WolfSSLException {

        WolfSSL.loadLibrary();

        /* create new SSLEngine */
        Security.insertProviderAt(new WolfSSLProvider(), 1);

        Provider p = Security.getProvider("wolfJSSE");
        if (p == null) {
            appendDisplayText("Unable to find wolfJSSE provider\n");
        }
        else {
            appendDisplayText("Successfully found wolfJSSE provider\n");
        }

        appendDisplayText("\n");
        appendDisplayText("For more detailed example, see:\n");
        appendDisplayText("github.com/wolfssl/wolfssl-examples\n");
    }
}