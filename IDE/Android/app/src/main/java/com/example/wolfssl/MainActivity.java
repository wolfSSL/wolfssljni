/* MainActivity.java
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLFIPSErrorCallback;
import com.wolfssl.provider.jsse.WolfSSLProvider;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.security.Security;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = "wolfSSL FIPS";

    /**
     * Custom FIPS error callback that logs directly to Android logcat via
     * android.util.Log. This ensures FIPS error details and the expected
     * verifyCore hash are always visible in logcat, regardless of whether
     * wolfJSSE debug logging is enabled.
     *
     * The expected verifyCore hash can also be seen in the wolfJSSE
     * debug logs by setting the "wolfjsse.debug" system property to "true"
     * before creating the provider, ie:
     *
     * System.setProperty("wolfjsse.debug", "true");
     */
    private static class FIPSErrorCallback
        implements WolfSSLFIPSErrorCallback {

        @Override
        public void errorCallback(
            int ok, int err, String hash) {

            if (ok == 1) {
                Log.d(TAG, "FIPS callback: ok = " + ok + ", err = " + err);
                Log.d(TAG, "Expected verifyCore hash: " + hash);
            }
            else {
                Log.e(TAG, "FIPS error callback: ok = " + ok + ", err = " + err);
                Log.e(TAG, "Expected verifyCore hash: " + hash);

                if (err == -203) {
                    Log.e(TAG,
                        "FIPS in-core integrity check failed. Copy the " +
                        "above hash into WOLFCRYPT_FIPS_CORE_HASH_VALUE in " +
                        "CMakeLists.txt and rebuild.");
                }
            }
        }
    }

    private View.OnClickListener buttonListener =
        new View.OnClickListener() {
        @Override
        public void onClick(View v) {
            new Thread(new Runnable() {
                @Override
                public void run() {
                    testTLSConnection();
                }
            }).start();
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

    private void testTLSConnection()
    {
        String host = "www.wolfssl.com";
        int port = 443;
        SSLSocket sock = null;

        setDisplayText("wolfSSL JSSE TLS Connection Test\n");
        appendDisplayText("==================================\n\n");

        try {
            /* Register wolfJSSE provider if not already registered.
             * This loads native libraries, registers the default
             * FIPS callback, and calls wolfSSL_Init() internally. */
            if (Security.getProvider("wolfJSSE") == null) {
                Security.insertProviderAt(new WolfSSLProvider(), 1);

                /* Register custom FIPS error callback after creating the
                 * provider. The provider registers its own callback internally,
                 * so custom one must be set after. Only one callback can be
                 * registered at a time. */
                WolfSSL.setFIPSCb(new FIPSErrorCallback());
            }

            if (Security.getProvider("wolfJSSE") == null) {
                appendDisplayText("ERROR: wolfJSSE provider not found\n");
                return;
            }
            appendDisplayText("Registered wolfJSSE provider\n");

            /* Create SSLContext and SSLSocket */
            SSLContext ctx = SSLContext.getInstance("TLS", "wolfJSSE");
            ctx.init(null, null, null);

            SSLSocketFactory sf = ctx.getSocketFactory();

            appendDisplayText("Connecting to " + host + ":" + port + "\n");

            sock = (SSLSocket) sf.createSocket(host, port);
            sock.startHandshake();

            appendDisplayText("TLS handshake complete\n");
            appendDisplayText("Protocol: " +
                sock.getSession().getProtocol() + "\n");
            appendDisplayText("Cipher:   " +
                sock.getSession().getCipherSuite() + "\n\n");

            /* Send HTTP GET request */
            String httpGet = "GET / HTTP/1.1\r\n" +
                "Host: " + host + "\r\n" +
                "Connection: close\r\n\r\n";

            OutputStream os = sock.getOutputStream();
            os.write(httpGet.getBytes());
            os.flush();
            appendDisplayText("Sent HTTP GET request\n\n");

            /* Read response (first few lines) */
            InputStream is = sock.getInputStream();
            BufferedReader br = new BufferedReader(new InputStreamReader(is));

            String line;
            int lineCount = 0;
            int maxLines = 15;

            appendDisplayText("--- Response ---\n");
            while ((line = br.readLine()) != null && lineCount < maxLines) {
                appendDisplayText(line + "\n");
                lineCount++;
            }
            if (lineCount >= maxLines) {
                appendDisplayText("...\n");
            }
            appendDisplayText("--- End ---\n\n");

        } catch (Exception e) {
            appendDisplayText("ERROR: " + e.getMessage() + "\n");
            e.printStackTrace();

        } finally {
            if (sock != null) {
                try {
                    sock.close();
                    appendDisplayText("Socket closed successfully\n");
                } catch (Exception e) {
                    appendDisplayText("Error closing socket: " +
                        e.getMessage() + "\n");
                }
            }
        }
    }
}
