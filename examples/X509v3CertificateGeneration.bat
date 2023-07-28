
cd %~dp0\build >NUL 2>NUL
SETLOCAL

:: Populate correct config for build
call ..\WindowsConfig.bat

:: Set PATH to include DLL for native wolfSSL and wolfSSL JNI (native library)
SET PATH="%WOLFSSLJNI_DLL_DIR%;%WOLFSSL_DLL_DIR%";%PATH%

java -cp ".;..\..\lib\wolfssl.jar;..\..\lib\wolfssl-jsse.jar" -Djava.library.path="%WOLFSSLJNI_DLL_DIR%;%WOLFSSL_DLL_DIR%" X509v3CertificateGeneration

ENDLOCAL
cd %~dp0\..
