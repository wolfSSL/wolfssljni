
# Java Remote Method Invocation (RMI) Example Client and Server

This is a simple example of Java Remote Method Invocation (RMI), including
the implementation of a very basic client (RmiClient.java) and server
(RmiServer.java) with associated remote object interface definition
(RmiRemoteInterface.java). These examples are set up to work over SSL/TLS.

The `RmiRemoteInterface.java` file defines an interface with one public method
named `String getServerMessage() throws RemoteException;`. This method
should be implemented to one that returns a simple string message from the
server implementation.

The `RmiServer.java` file implements a simple server, which implements the
`RemoteInterface` class and `getServerMessage()` method. The server binds
an object with the stub "RemoteInterface" to the local default registry at
localhost:1099.

The `RmiClient.java` file gets an object stub from the remote registry, and
makes the remote method invocation for `getServerMessage()`.

## Compiling Example Code

The example code is set up to compile as part of the `ant examples` target:

```
$ cd wolfssljni
$ ./java.sh
$ ant
$ ant examples
```

## Start the Server

To start the server, run the following helper script from the wolfSSL JNI/JSSE
root directory:

```
$ cd wolfssljni
$ ./examples/provider/rmi/RmiServer.sh
```

You should see the following message after the server has finished setting up
the RMI object:

```
Created server TrustManagerFactory
Created server KeyManagerFactory
Created server SSLContext
Created server SSLServerSocketFactory
Creating server Socket
Created server TrustManagerFactory
Created server KeyManagerFactory
Created server SSLContext
Created server SSLServerSocketFactory
Server started, listening for connections
```

## Connecting the Client

To start the client, run the following helper script from the wolfSSL JNI/JSSE
root directory:

```
$ cd wolfssljni
$ ./examples/provider/rmi/RmiClient.sh
```

You should see the response sent back from the server method:

```
Created client TrustManagerFactory
Created client KeyManagerFactory
Created client SSLContext
Created client SocketFactory
Creating client Socket
Created client TrustManagerFactory
Created client KeyManagerFactory
Created client SSLContext
Created client SocketFactory
Creating client Socket
Message from server via RMI: Hello from server
```

## Support

For support or questions with these examples, please email support@wolfssl.com.

