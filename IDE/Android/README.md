# Android Studio Example Project

This is an example Android Studio project file for wolfssljni / wolfJSSE. This
project should be used for reference only.

Tool and version information used when testing this project:

- Ubuntu 20.04.3 LTS
- Android Studio Arctic Fox 2020.3.1 Patch 3
- Android Gradle Plugin Version: 4.2.2
- Gradle Version: 6.9.1
- API 28: Android 9.0 (Pie)
- Emulator: Nexus 5X API 28

The following sections outline steps required to run this example on an
Android device or emulator.

## Converting JKS to BKS for Android Use

On the Android device BKS format key stores are expected. To convert the
JKS example bundles to BKS use the following commands. Note: you will need
to download a version of the bcprov JAR from the Bouncy Castle website:

```
cd examples/provider
./convert-to-bks.sh <path/to/provider>
```

For exmaple, when using bcprov-ext-jdk15on-169.jar:

```
cd examples/provider
./convert-to-bks.sh ~/Downloads/bcprov-ext-jdk15on-169.jar
```

## Push BKS to Android Device or Emulator

Push BKS bundles up to the device along with certificates. To do this start
up the emulator/device and use `adb push`. An example of this would be the
following commands from root wolfssljni directory:

```
adb shell
cd sdcard
mkdir examples
mkdir examples/provider
mkdir examples/certs
exit
adb push ./examples/provider/*.bks /sdcard/examples/provider/
adb push ./examples/certs/ /sdcard/examples/
```

## Add Native wolfSSL Library Source Code to Project

This example project is already set up to compile and build the native
wolfSSL library source files, but the wolfSSL files themselves have not been
included in this package. You must download or link an appropriate version
of wolfSSL to this project using one of the options below.

The project looks for the directory
`wolfssljni/IDE/Android/app/src/main/cpp/wolfssl` for wolfSSL source code.
This can added in multiple ways:

- OPTION A: Download the latest wolfSSL library release from www.wolfssl.com,
unzip it, rename it to `wolfssl`, and place it in the direcotry
`wolfssljni/IDE/Android/app/src/main/cpp/`.

```
$ unzip wolfssl-X.X.X.zip
$ mv wolfssl-X.X.X wolfssljni/IDE/Android/app/src/main/cpp/wolfssl
```

- OPTION B: Alternatively GitHub can be used to clone wolfSSL:

```
$ cd /IDE/Android/app/src/main/cpp/
$ git clone https://github.com/wolfssl/wolfssl
$ cp wolfssl/options.h.in wolfssl/options.h
```

- OPTION C: A symbolic link to a wolfssl directory on the system by using:

```
$ cd /IDE/Android/app/src/main/cpp/
$ ln -s /path/to/local/wolfssl ./wolfssl
```

## Importing and Building the Example Project with Android Studio

4) Open the Android Studio project by double clicking on the `Android` folder
in wolfssljni/IDE/

5) Build the project and run MainActivity from app -> java/com/example.wolfssl.
This will ask for permissions to access the certificates in the /sdcard/
directory and then print out the server certificate information on success.

6) OPTIONAL: The androidTests can be run after permissions has been given.
app->java->com.wolfssl->provider.jsse.test->WolfSSLJSSETestSuite and
app->java->com.wolfssl->test->WolfSSLTestSuite

## Support

Please contact wolfSSL support at support@wolfssl.com with any questions or
feedback.

