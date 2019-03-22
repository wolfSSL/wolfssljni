#!/bin/bash

export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:./lib/:/usr/local/lib
java -classpath ./lib/wolfssl.jar:./lib/wolfssl-jsse.jar:./examples/build -Dsun.boot.library.path=./lib/ -Dwolfjsse.debug=true ThreadedSSLSocketClientServer $@

