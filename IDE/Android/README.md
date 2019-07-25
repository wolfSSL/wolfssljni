This is an example of use with Android Studio.

An emulation of Nexus 4 API 23 (Android 6.0, API 23) was used with testing and Android Studio IDE version 3.3.2 was used.

Steps to run example:

1) On the Android device BKS format key stores are expected. To convert the JKS example bundles to BKS use the following commands:

```
cd examples/provider
./convert-to-bks.sh <path/to/provider>

exmaple:
cd examples/provider
./convert-to-bks.sh ~/Downloads/bcprov-jdk15on-161.jar
```

2) Push BKS bundles up to the device along with certificates. To do this start up the emulator/device and use "adb push". An example of this would be the following commands from root wolfssljni directory:

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

3) Add wolfssl source code for compiling. The project looks for the directory wolfssljni/IDE/Android/app/src/main/cpp/wolfssl for wolfSSL source code. This can be done multiple ways one being to download the latest release from wolfSSL's website, unzip it, rename it to wolfssl, and place it in the direcotry wolfssljni/IDE/Android/app/src/main/cpp/. Alternatively GitHub can be used with "cd /IDE/Android/app/src/main/cpp/ && git clone https://github.com/wolfssl/wolfssl". And the final method to be mentioned in this document is by creating a symbolic link to a wolfssl directory on the system by using "cd /IDE/Android/app/src/main/cpp/ && ln -s /path/to/local/wolfssl ./wolfssl".

4) Open the Android studio project by double clicking on the Android folder in wolfssljni/IDE/

5) Compile the project and run MainActivity from app -> java -> com -> example.wolfssl. This will ask for permissions to access the certificates in the /sdcard/ directory and then print out the server certificate information on success.

6) OPTIONAL : The androidTests can then be ran after permissions has been given. app->java->com.wolfssl->provider.jsse.test->WolfSSLJSSETestSuite and app->java->com.wolfssl->test->WolfSSLTestSuite