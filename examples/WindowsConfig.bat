
:: -----------------------------------------------------------------------------
:: Build Configuration
:: -----------------------------------------------------------------------------

:: Set below directories containing native wolfSSL DLL and wolfSSL JNI DLL
:: Default pathing expects wolfssl and wolfssljni dirs to be side by side
:: May uncomment / comment lines below that match your build. This file is
:: included by other example .bat files.

:: wolfSSL Normal non-FIPS (DLL Debug x64)
SET WOLFSSL_DLL_DIR=..\..\..\wolfssl\IDE\WIN10\DLL Debug\x64
SET WOLFSSLJNI_DLL_DIR=..\..\IDE\WIN\DLL Debug\x64

:: wolfSSL Normal non-FIPS (DLL Release x64)
:: SET WOLFSSL_DLL_DIR=..\..\..\wolfssl\IDE\WIN10\DLL Release\x64
:: SET WOLFSSLJNI_DLL_DIR=..\..\IDE\WIN\DLL Release\x64

:: wolfSSL Normal non-FIPS (DLL Debug Win32)
:: SET WOLFSSL_DLL_DIR=..\..\..\wolfssl\IDE\WIN10\DLL Debug\Win32
:: SET WOLFSSLJNI_DLL_DIR=..\..\IDE\WIN\DLL Debug\Win32

:: wolfSSL Normal non-FIPS (DLL Release Win32)
:: SET WOLFSSL_DLL_DIR=..\..\..\wolfssl\IDE\WIN10\DLL Release\Win32
:: SET WOLFSSLJNI_DLL_DIR=..\..\IDE\WIN\DLL Release\Win32

:: wolfSSL FIPS 140-2 #3389 Build (DLL Debug x64)
:: SET WOLFSSL_DLL_DIR=..\..\..\wolfssl\IDE\WIN10\DLL Debug\x64
:: SET WOLFSSLJNI_DLL_DIR=..\..\IDE\WIN\DLL Debug FIPS\x64

:: wolfSSL FIPS 140-2 #3389 Build (DLL Release x64)
:: SET WOLFSSL_DLL_DIR=..\..\..\wolfssl\IDE\WIN10\DLL Release\x64
:: SET WOLFSSLJNI_DLL_DIR=..\..\IDE\WIN\DLL Release FIPS\x64

:: wolfSSL FIPS 140-2 #3389 Build (DLL Debug Win32)
:: SET WOLFSSL_DLL_DIR=..\..\..\wolfssl\IDE\WIN10\DLL Debug\Win32
:: SET WOLFSSLJNI_DLL_DIR=..\..\IDE\WIN\DLL Debug FIPS\Win32

:: wolfSSL FIPS 140-2 #3389 Build (DLL Release Win32)
:: SET WOLFSSL_DLL_DIR=..\..\..\wolfssl\IDE\WIN10\DLL Release\Win32
:: SET WOLFSSLJNI_DLL_DIR=..\..\IDE\WIN\DLL Release FIPS\Win32

