#!/bin/bash

cd ./examples/build
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:../../lib/:/usr/local/lib
java -classpath ../../lib/wolfssl.jar:../../lib/wolfssl-jsse.jar:./ -Dsun.boot.library.path=../../lib/ -Dwolfjsse.debug=true -Dsun.rmi.transport.connectionTimeout=1000 -Dsun.rmi.transport.tcp.readTimeout=1000 RmiClient "$@"
#java -classpath ../../lib/wolfssl.jar:../../lib/wolfssl-jsse.jar:./ -Dsun.boot.library.path=../../lib/ -Dwolfjsse.debug=true RmiClient "$@"

