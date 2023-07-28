# wolfSSL JNI/JSSE Windows Support

wolfSSL JNI/JSSE supports building on Windows using Visual Studio.

This README includes instructions and tips for building wolfSSL JNI/JSSE on
Windows, along with environment setup instructions. wolfSSL JNI/JSSE depends
on and links against the native wolfSSL SSL/TLS library. As such, native
wolfSSL will need to be compiled first. Further instructions are below.

## Windows Environment Setup

### JDK and `JAVA_HOME`

Make sure you have downloaded and installed a Java Developer Kit (JDK). Once
a JDK has been installed, `JAVA_HOME` needs to be configured as a Windows
environment variable.

1. Open the "Environment Variables" window. This can be found by searching for
"Environment Variables", or by opening "System Properties", clicking on the
"Advanced" tab, then "Environment Variables...".

![System Properties](./img/system_properties.png)

2. In "Environment Variables", add a new variable called `JAVA_HOME` under
"System variables". The value for this variable should point to your JDK
installation location. For example:

```
C:\Program Files\Java\jdk1.8.0_361
```

![JAVA\_HOME](./img/environment_variables.png)

### Apache Ant and `ANT_HOME`

Apache ant needs to be downloaded in order to build the Java .JAR component of
this package.

1. Download Apache Ant from the
[Apache Ant Binary Distributions](https://ant.apache.org/bindownload.cgi) page.
On the download page there should be a binary zip file. For example,
`apache-ant-1.10.13-bin.zip`. Unzip this archive to a location on your PC where
you would like to install Apache Ant.

![Apache Ant Download](./img/apache_ant_download.png)

2. After you have downloaded and installed `ant`, configure a new Windows
environment variable called `ANT_HOME`. Follow similar steps as above to open
the "Environment Variables" window. The value of this variable should be the
directory that you placed ant in. For example:

`C:\apache-ant-1.10.13`

![ANT\_HOME](./img/ant_home_environment_variable.png)

3. After `ANT_HOME` has been configured as an environment variable, the
Windows `Path` needs to be updated to contain the `ANT_HOME` location.

- Open "Environment Variables" window.
- Under "System variables", edit the "Path" variable.
- Add a new entry at the bottom of the `Path` value list for `%ANT\_HOME%\bin`.

![Windows Path](./img/environment_variables_path.png)

![ANT\_HOME on Path](./img/path_ant_home.png)

4. To test that `ant` has been correctly installed:

- Open a Command Prompt window
- Typing `ant -v` should output something similar to the following:

```
ANT_OPTS is set to  -Djava.security.manager=allow
Apache Ant(TM) version 1.10.13 compiled on January 4 2023
Trying the default build file: build.xml
BuildFile: build.xml does not exist!
Build failed
```

### Microsoft Visual Studio

These instructions have been tested with Visual Studio 2019, although other 
versions should work as well. If not installed,
[download](https://visualstudio.microsoft.com/) and install before continuing
these instructions.

# Directory Setup Structure

The Visual Studio projects included in this directory assume that the wolfSSL
JNI/JSSE and wolfSSL SSL/TLS directories are side-by-side on the file system,
and that the directories for each are simply named `wolfssl` and `wolfssljni`.
This may require renaming the wolfSSL and wolfSSL JNI/JSSE directories.

For example, your high-level directory structure should look like:

```
C:\wolfssl
C:\wolfssljni
```

# Building wolfSSL SSL/TLS Library

For instructions on building the wolfSSL SSL/TLS DLL, see wolfSSL Manual
[Chapter 2 Building on Windows](https://www.wolfssl.com/documentation/manuals/wolfssl/chapter02.html#building-on-windows),
or [Using wolfSSL with Visual Studio](https://www.wolfssl.com/docs/visual-studio/).

There are a few different Visual Studio solutions which will compile wolfSSL,
depending on what variant of wolfSSL you would like to build. Notes on each
are provided below.

## Normal wolfSSL (non-FIPS)

To build a normal, non-FIPS wolfSSL DLL, use the Visual Studio solution file
located in the root of the wolfSSL package:

```
<wolfssl>\wolfssl64.sln
```

This will contain build configurations for both 32-bit and 64-bit DLL's, with
either "DLL Debug" or "DLL Release". wolfSSL JNI/JSSE will expect to link
against a wolfSSL DLL library.

wolfSSL proper's Visual Studio projects use a custom `user_settings.h` header
file to customize preprocessor defines and configuration for the wolfSSL
library build. The `user_settings.h` header that is used for this non-FIPS build
is located at:

```
<wolfssl>\IDE\WIN\user_settings.h
```

When builidng wolfSSL for use with wolfSSL JNI/JSSE, edit this header file
before compiling the library DLL and insert the following defines above the
section titled `/* Configuration */`:

```
#define WOLFSSL_JNI
#define HAVE_EX_DATA
#define OPENSSL_ALL
#define HAVE_CRL
#define HAVE_OCSP
#define PERSIST_SESSION_CACHE
#define PERSIST_CERT_CACHE
#define HAVE_ECC
#define HAVE_DH
#define WOLFSSL_CERT_EXT
#define WOLFSSL_CERT_GEN
#define HAVE_TLS_EXTENSIONS
#define HAVE_SNI
#define HAVE_ALPN
```

After editing and saving the `user_settings.h` file, select one of the following
DLL Library configurations and build the wolfSSL library solution:

- Win32 | DLL Debug
- Win32 | DLL Release
- x64 | DLL Debug
- x64 | DLL Release

The wolfSSL library DLL will be built and placed under one of the following
directories:

- `wolfssl\DLL Debug\Win32`
- `wolfssl\DLL Debug\x64`
- `wolfssl\DLL Release\Win32`
- `wolfssl\DLL Release\x64`

When bulding wolfSSL JNI/JSSE, the Visual Studio project file for that library
will look in the above locations to link against the wolfSSL DLL matching
the same build configuration.

## wolfSSL FIPS 140-2 (Certificate #3389)

To build a wolfSSL FIPS 140-2 variant of wolfSSL for use with FIPS 140-2
certificate #3389 or later, use the Visual Studio solution file located under
the `IDE\WIN10` directory inside the wolfSSL FIPS release package:

```
<wolfssl>\IDE\WIN10\wolfssl-fips.sln
```

Follow build instructions in the FIPS User Guide PDF included with the FIPS
release package.

In summary:

1. Open the above Visual Studio solution file.
2. Select one of the following build configurations:

- x64 | DLL Debug
- x64 | DLL Release

3. Open Project properties for the `wolfssl` and `test` projects, go to
`C/C++ -> Preprocessor`, and change `HAVE_FIPS_VERSION=5` to
`HAVE_FIPS_VERSION=2`.
4. Open the `user_settings.h` file under `<wolfssl>\IDE\WIN10\user_settings.h`
and set the values for `HAVE_FIPS`, `HAVE_FIPS_VERSION`, and
`HAVE_FIPS_VERSION_MINOR` to the following:

```
#if 1
#undef HAVE_FIPS
#define HAVE_FIPS
#undef HAVE_FIPS_VERSION
#define HAVE_FIPS_VERSION 2
#undef HAVE_FIPS_VERSION_MINOR
#define HAVE_FIPS_VERSION_MINOR 0
#endif
```

5. When building for wolfSSL JNI/JSSE, add the following to the
`user_settings.h` file mentioned in the previous step:

```
#define WOLFSSL_JNI
#define HAVE_EX_DATA
#define OPENSSL_ALL
#define HAVE_CRL
#define HAVE_OCSP
#define PERSIST_SESSION_CACHE
#define PERSIST_CERT_CACHE
#define HAVE_ECC
#define HAVE_DH
#define WOLFSSL_CERT_EXT
#define WOLFSSL_CERT_GEN
#define HAVE_TLS_EXTENSIONS
#define HAVE_SNI
#define HAVE_ALPN
```

6. Build the `wolfssl-fips` project, which will create a DLL in one of the
following locations:

```
<wolfssl>\IDE\WIN10\DLL Debug\x64\wolfssl-fips.dll
<wolfssl>\IDE\WIN10\DLL Release\x64\wolfssl-fips.dll
```

7. Build the `test` project inside the wolfSSL Visual Studio solution, then
run the wolfCrypt test by right clicking on the `test` project, selecting
`Debug`, then `Run New Instance`.

If a error shows up with "In Core Integrity check FIPS error", copy the
provided hash value, open `fips_test.c`, update the `verifyCore` array with
the given hash, then re-compile the `wolfssl-fips` DLL. This is the FIPS
Power-On Integrity Check, which runs an HMAC-SHA256 over the object files
within the FIPS module boundary.

Re-compiling the `test` project and re-running the application should result
in the wolfCrypt tests successfully running.

See the FIPS User Guide for more details on the FIPS verifyCore hash, or
email support@wolfssl.com.

## wolfSSL FIPS 140-3 (Upcoming)

To build a version of wolfSSL that has been submitted for FIPS 140-3, use
the Visual Studio solution file under the `IDE\WIN10` directory inside the
wolfSSL package:

```
<wolfssl>\IDE\WIN10\wolfssl-fips.sln
```

Follow instructions in the above section for 140-2 / 3389, except use the
following values for `HAVE_FIPS`, `HAVE_FIPS_VERSION`, and
`HAVE_FIPS_VERSION_MINOR` in `user_settings.h`:

```
#if 1
#undef HAVE_FIPS
#define HAVE_FIPS
#undef HAVE_FIPS_VERSION
#define HAVE_FIPS_VERSION 5
#undef HAVE_FIPS_VERSION_MINOR
#define HAVE_FIPS_VERSION_MINOR 1
#endif
```

The following additional defines will also need to be added to
`user_settings.h` like above, for compilation and use with wolfSSL JNI/JSSE.

```
#define WOLFSSL_JNI
#define HAVE_EX_DATA
#define OPENSSL_ALL
#define HAVE_CRL
#define HAVE_OCSP
#define PERSIST_SESSION_CACHE
#define PERSIST_CERT_CACHE
#define HAVE_ECC
#define HAVE_DH
#define WOLFSSL_CERT_EXT
#define WOLFSSL_CERT_GEN
#define HAVE_TLS_EXTENSIONS
#define HAVE_SNI
#define HAVE_ALPN
```

For additional help, contact support@wolfssl.com.

# Building wolfSSL JNI/JSSE Library

After the wolfSSL SSL/TLS library DLL has been built (above), the wolfSSL
JNI/JSSE library DLL can then be built using the Visual Studio solution
located in this directory.

1. Open the Visual Studio solution `wolfssljni.sln` under this directory.

2. Select the build configuration which matches the one you built wolfSSL
proper above for. The following are the possible build configurations for
the `wolfslsjni` project:

- Win32 | DLL Debug
- Win32 | DLL Release
- x64 | DLL Debug
- x64 | DLL Release
- x64 | DLL Debug FIPS   (Requires wolfSSL FIPS 140-2/140-3 archive)
- x64 | DLL Release FIPS (Requires wolfSSL FIPS 140-2/140-3 archive)

3. Build Solution

This will first compile the `wolfssljni.dll` library and place it under one
of the following build directories, based on build configuration:

- `wolfssljni\IDE\WIN\DLL Debug\Win32`
- `wolfssljni\IDE\WIN\DLL Debug\x64`
- `wolfssljni\IDE\WIN\DLL Debug FIPS\x64`
- `wolfssljni\IDE\WIN\DLL Release\Win32`
- `wolfssljni\IDE\WIN\DLL Release\x64`
- `wolfssljni\IDE\WIN\DLL Release FIPS\x64`

It will also run a post-build action which runs `ant` from the `wolfssljni`
root directory. This compiles the Java JAR file, and places that in the
following directory. There are two JAR files built, one that contains only
the thin JNI wrapper around native wolfSSL's APIs (`wolfssl.jar`) and one that
includes both the thin JNI wrapper as well as the wolfSSL JSSE provider. For
JSSE users, the `wolfssl-jsse.jar` library should be used.

```
wolfssljni\lib\wolfssl.jar
wolfssljni\lib\wolfssl-jsse.jar
```

# Running ant Tests

wolfSSL JNI/JSSE includes ant tests that can be run from a Windows Command
Prompt or other shell that has access to the `ant` executable.

You will need to download the following JUnit JAR files in order to run the
wolfSSL JNI/JSSE tests:

[junit-4.13.2.jar](https://repo1.maven.org/maven2/junit/junit/4.13.2/junit-4.13.2.jar)
[hamcrest-all-1.3.jar](https://repo1.maven.org/maven2/org/hamcrest/hamcrest-all/1.3/hamcrest-all-1.3.jar)

Download and place these JAR files on your system, noting the location to be
used below to set the `JUNIT_HOME` environment variable.

After wolfSSL and wolfSSL JNI/JSSE have been compiled using the above steps,
the ant tests can be run with the following steps:

1. Open the Windows Command Prompt
2. Set the `JUNIT_HOME` environment variable to point to the directory which
contains the JUnit JAR files you downloaded above:

```
set JUNIT_HOME=path\to\junit\jar\directory
```

2. Navigate to the `wolfssljni` directory

```
cd path\to\wolfssljni
```

3. Run one of the following ant test targets, depending on what library build
configuration you compiled:

```
ant test-win32-debug
ant test-win32-release

ant test-win64-debug
ant test-win64-release

ant test-win32-debug-fips
ant test-win32-release-fips

ant test-win64-debug-fips
ant test-win64-release-fips
```
# Running Examples

Windows batch scripts have been included to easily run some of the provided
examples from the Windows command line.

After the above steps have been followed to compile native wolfSSL and
wolfSSL JNI/JSSE, open a Command Prompt and navigate to the wolfSSL JNI/JSSE
directory root (ie: wolfssljni).

Compile the examples:

```
ant examples
```

Edit the Windows configuration batch script to set the appropriate paths
for native wolfSSL and wolfSSL JNI DLL locations. This can change between
build types (ex: normal wolfSSL, FIPS 140-2, etc):

**Edit examples\WindowsConfig.bat**

From the root wolfssljni directory, run the desired .bat file. For example,
to run the ProviderTest:

```
examples\provider\ProviderTest.bat
```

Or to run the X509v3 certificate generation example:

```
examples\X509v3CertificateGeneration.bat
```

