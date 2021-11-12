
# wolfJSSE Provider Examples

This directory contains examples for the wolfSSL JSSE provider (wolfJSSE).

Examples should be run from the package root directory, and using the provided
wrapper scripts. The wrapper scripts set up the correct environment variables
for use with the wolfJSSE provider included in the wolfssljni package. For
example to run the example JSSE server and client, after compiling wolfSSL and
wolfssljni:

```
$ cd <wolfssljni_root>
$ ./examples/provider/ServerJSSE.sh
$ ./examples/provider/ClientJSSE.sh
```

## Notes on Debug and Logging

wolfJSSE debug logging can be enabled by using `-Dwolfjsse.debug=true` at
runtime.

wolfSSL native debug logging can be enabled by using `-Dwolfssl.debug=true` at
runtime, if native wolfSSL has been compiled with `--enable-debug`.

JDK debug logging can be enabled using the `-Djavax.net.debug=all` option.

## wolfJSSE Example Client and Server

Example client/server applications that use wolfJSSE along with the SSLSocket
API.

**ServerJSSE.java** - Example wolfJSSE server \
**ClientJSSE.java** - Example wolfJSSE client

These examples can be run with the provided bash scripts:

```
$ ./examples/provider/ServerJSSE.sh <options>
$ ./examples/provider/ClientJSSE.sh <options>
```

## ClientSSLSocket.java

Very minimal JSSE client example using SSLSocket. Does not support all the
options that ClientJSSE.java does.

Example usage is:

```
$ ./examples/provider/ClientSSLSocket.sh [host] [port] [keystore] [truststore]
```

Example usage for connecting to the wolfSSL example server is:

```
$ ./examples/provider/ClientSSLSocket.sh 127.0.0.1 11111 \
  ./examples/provider/client.jks ./examples/provider/client.jks
```

The password for client.jks is: "wolfSSL test"

## MultiThreadedSSLClient.java

Multi threaded SSLSocket example that connects a specified number of client
threads to a server. Intended to test multi-threading with wolfJSSE.

This example creates a specified number of client threads to a server located
at 127.0.0.1:11118. This example is set up to use the SSLSocket class. It makes
one connection (handshake), sends/receives data, and shuts down.

A random amount of time is injected into each client thread before:

  1) The SSL/TLS handshake
  2) Doing I/O operations after the handshake

The maximum amount of sleep time for each of those is "maxSleep", or 3 seconds
by default. This is intended to add some randomness into the the client thread
operations.

Example usage:

```
$ ant examples
$ ./examples/provider/MultiThreadedSSLClient.sh -n <num_client_threads>
```

This example is designed to connect against the MultiThreadedSSLServer example:

```
$ ./examples/provider/MultiThreadedSSLServer.sh
```

This example also prints out average SSL/TLS handshake time, which is measured
in milliseconds on the "startHandshake()" API call.

## MultiThreadedSSLServer.java

SSLServerSocket example that creates a new thread per client connection.

This server waits in an infinite loop for client connections, and when connected
creates a new thread for each connection. This example is compiled when
`ant examples` is run in the package root.

```
$ ant examples
$ ./examples/provider/MultiThreadedSSLServer.sh
```

For multi threaded client testing, test against MultiThreadedSSLClient.sh.
For example, to connect 10 client threads:

```
$ ./examples/provider/MultiThreadedSSLClient.sh -n 10
```

## ProviderTest.java

This example tests the wolfSSL provider installation.  It lists all providers
installed on the system, tries to look up the wolfSSL provider, and if
found, prints out the information about the wolfSSL provider. Finally, it tests
what provider is registered to provide TLS to Java.

This app can be useful for testing if wolfJSSE has been installed
correctly at the system level.

```
$ ./examples/provider/ProviderTest.sh
```

Note, if wolfJSSE has not been installed at the OS system level, wolfJSSE
will not show up as an installed provider when this example is run.

## ThreadedSSLSocketClientServer.java

SSLSocket example that connects a client thread to a server thread.

This example creates two threads, one server and one client. The examples
are set up to use the SSLSocket and SSLServerSocket classes. They make
one connection (handshake) and shut down.

Example usage:

```
$ ./examples/provider/ThreadedSSLSocketClientServer.sh
```

## Support

Please contact the wolfSSL support team at support@wolfssl.com with any
questions or feedback.

