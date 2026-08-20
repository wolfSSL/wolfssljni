# Android Studio Example Project

This is an example Android Studio project file for wolfssljni / wolfJSSE. This
project should be used for reference only.

Tool and version information for this project, taken from `build.gradle`,
`app/build.gradle`, `gradle/wrapper/gradle-wrapper.properties`, and the
`.github/workflows/android_gradle.yml` CI workflow:

- Android Gradle Plugin Version: 8.3.1 (needs Android Studio Iguana
  2023.2.1 or newer)
- Gradle Version: 8.4
- JDK 17 or newer (CI uses JDK 21)
- compileSdk / targetSdk 33, minSdk 24
- CI: Ubuntu (GitHub Actions ubuntu-latest), emulator API 30 x86_64

The following sections outline steps required to run this example on an
Android device or emulator.

## 1. Add Native wolfSSL Library Source Code to Project

This example project is already set up to compile and build the native
wolfSSL library source files, but the wolfSSL files themselves have not been
included in this package. You must download or link an appropriate version
of wolfSSL to this project using one of the options below.

The project looks for the directory
`wolfssljni/IDE/Android/app/src/main/cpp/wolfssl` for wolfSSL source code.
This can added in multiple ways:

- OPTION A: Download the latest wolfSSL library release from www.wolfssl.com,
unzip it, rename it to `wolfssl`, and place it in the directory
`wolfssljni/IDE/Android/app/src/main/cpp/`.

```
$ unzip wolfssl-X.X.X.zip
$ mv wolfssl-X.X.X wolfssljni/IDE/Android/app/src/main/cpp/wolfssl
```

- OPTION B: Alternatively GitHub can be used to clone wolfSSL:

```
$ cd /IDE/Android/app/src/main/cpp/
$ git clone https://github.com/wolfssl/wolfssl
$ cd wolfssl
$ ./autogen.sh
$ cp wolfssl/options.h.in wolfssl/options.h
```

- OPTION C: A symbolic link to a wolfssl directory on the system by using:

```
$ cd /IDE/Android/app/src/main/cpp/
$ ln -s /path/to/local/wolfssl ./wolfssl
```

## 2. Update Java Symbolic Links (Only applies to Windows Users)

The following Java source directory is a Unix/Linux symlink:

```
wolfssljni/IDE/Android/app/src/main/java/com/wolfssl
```

This will not work correctly on Windows, and a new Windows symbolic link needs
to be created in this location. To do so:

1) Open Windows Command Prompt (Right click, and "Run as Administrator")
2) Navigate to `wolfssljni\IDE\Android\app\src\main\java\com`
3) Delete the existing symlink file (it shows up as a file called "wolfssl")

```
del wolfssl
```

4) Create a new relative symbolic link with `mklink`:

```
mklink /D wolfssl ..\..\..\..\..\..\..\src\java\com\wolfssl\
```

## 3. Convert Example JKS files to BKS for Android Use

On an Android device BKS format key stores are expected. To convert the
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

## 4. Push BKS files to Android Device or Emulator

Push BKS bundles up to the device along with certificates. To do this start
up the emulator/device and use `adb push`. An example of this would be the
following commands from root wolfssljni directory. This step may be done
after the starting Android Studio and compiling the project, but must be done
before running the app or test cases.

```
adb shell mkdir -p /data/local/tmp/examples/provider
adb shell mkdir -p /data/local/tmp/examples/certs/intermediate
adb push ./examples/provider/*.bks /data/local/tmp/examples/provider/
adb push ./examples/certs/ /data/local/tmp/examples/
```

## 5. Import and Build the Example Project with Android Studio

1) Open the Android Studio project by double clicking on the `Android` folder
in wolfssljni/IDE/. Or, from inside Android Studio, open the `Android` project
located in the wolfssljni/IDE directory.

2) Build the project and run MainActivity from app -> java/com/example.wolfssl.
This will print out the server certificate information on success.

3) OPTIONAL: The androidTests can be run to verify functionality.
app->java->com.wolfssl->provider.jsse.test->WolfSSLJSSETestSuite and
app->java->com.wolfssl->test->WolfSSLTestSuite.

## Gradle Dependency Verification

This project enables Gradle dependency verification. The file
`gradle/verification-metadata.xml` holds SHA-256 checksums for the Android
Gradle Plugin, every resolved dependency artifact, and their POM/module
metadata files. Gradle checks each artifact it resolves against this list and
fails the build if a checksum does not match or an artifact is not listed.
Source and Javadoc JARs downloaded by Android Studio are trusted by pattern
since they are never executed.

If you change a dependency or plugin version in `build.gradle` or
`app/build.gradle`, regenerate the file as follows.

1. Delete the whole `<components>` block from
   `gradle/verification-metadata.xml` and keep the `<configuration>` block.
   `--write-verification-metadata` only adds entries and never removes
   entries for versions that are no longer resolved, so without this step
   stale entries accumulate and the diff only ever shows additions.

2. Regenerate the checksums:

```
cd IDE/Android
./gradlew --refresh-dependencies --write-verification-metadata sha256 \
    help assembleDebug assembleDebugUnitTest assembleDebugAndroidTest \
    assembleRelease connectedDebugAndroidTest
```

   `--refresh-dependencies` is required. Without it Gradle serves POM/module
   metadata it already parsed from its cache without reading the files
   again, so their checksums are not recorded and a fresh checkout (for
   example CI) then fails verification. `connectedDebugAndroidTest` can be
   run without a device attached. It fails with "No connected devices!" but
   only after resolving the Android test platform (UTP) artifacts, so they
   are still recorded.

3. Add AAPT2 entries for the other platforms. Gradle only records artifacts
   resolved on the host that ran the command, and the AAPT2 binary
   (`com.android.tools.build:aapt2`) is OS specific. Find the AAPT2 version
   Gradle recorded for your host in `gradle/verification-metadata.xml`, set
   `V` to it, and run the snippet below. It downloads the JARs for all
   platforms and prints ready to paste `<artifact>` entries. Paste the ones
   for the platforms other than your host under the existing `aapt2`
   component. These entries carry `origin="Downloaded from ..."` instead
   of `origin="Generated by Gradle"`. Re-add them after every step 1.

```
V=8.3.1-10880808
B=https://dl.google.com/dl/android/maven2/com/android/tools/build/aapt2
for os in linux osx windows; do
    curl -sSfO $B/$V/aapt2-$V-$os.jar
    printf '         <artifact name="aapt2-%s-%s.jar">\n' $V $os
    printf '            <sha256 value="%s" origin="Downloaded from %s"/>\n' \
        $(shasum -a 256 aapt2-$V-$os.jar | cut -d ' ' -f 1) $B
    printf '         </artifact>\n'
done
```

4. Review the resulting diff and commit the updated file.

## Support

Please contact wolfSSL support at support@wolfssl.com with any questions or
feedback.

