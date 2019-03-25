#!/bin/bash

PROGRAMES="sm2keygen sm2enc sm2sign sm4_evp"
INC_DIR=/root/tassl-1.1.1_lib/include
LIB_DIR=/root/tassl-1.1.1_lib/lib

if [ $1"X" == "cleanX" ]; then
printf "cleaning the programe %s.....\n" $PROGRAMES
	rm -rf ${PROGRAMES} 
else
printf "compiling the programe.....\n"
gcc -ggdb3 -O0 -o sm2keygen sm2keygen.c -I${INC_DIR}  ${LIB_DIR}/libssl.a ${LIB_DIR}/libcrypto.a  -ldl -lpthread
gcc -ggdb3 -O0 -o sm2enc sm2enc.c -I${INC_DIR}  ${LIB_DIR}/libssl.a ${LIB_DIR}/libcrypto.a  -ldl -lpthread
gcc -ggdb3 -O0 -o sm2sign sm2sign.c -I${INC_DIR}  ${LIB_DIR}/libssl.a ${LIB_DIR}/libcrypto.a  -ldl -lpthread
gcc -ggdb3 -O0 -o sm4_evp sm4_evp.c -I${INC_DIR}  ${LIB_DIR}/libssl.a ${LIB_DIR}/libcrypto.a  -ldl -lpthread
fi
