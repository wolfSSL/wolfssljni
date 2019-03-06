/* com_wolfssl_WolfSSLSessionInfo.c
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

#include <stdio.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>

#include "com_wolfssl_globals.h"
#include "com_wolfssl_WolfSSLSessionInfo.h"

JNIEXPORT jlong JNICALL Java_com_wolfssl_WolfSSLSessionInfo_SESSION_1set_1timeout
  (JNIEnv* jenv, jclass jcl, jlong ses, jlong t)
{
    return wolfSSL_SSL_SESSION_set_timeout((WOLFSSL_SESSION*)ses, t);
}

JNIEXPORT jlong JNICALL Java_com_wolfssl_WolfSSLSessionInfo_SESSION_1get_1timeout
  (JNIEnv* jenv, jclass jcl, jlong ses)
{
    return wolfSSL_SESSION_get_timeout((WOLFSSL_SESSION*)ses);
}
