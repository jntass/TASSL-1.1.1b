/* crypto/sm4/sm4test.c */
/*
 * Written by caichenghang for the TaSSL project.
 */
/* ====================================================================
 * Copyright (c) 2016 - 2018 Beijing JN TASS Technology Co.,Ltd.  All 
 * rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by Beijing JN TASS 
 *    Technology Co.,Ltd. TaSSL Project.(http://www.tass.com.cn/)"
 *
 * 4. The name "TaSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    TaSSL@tass.com.cn.
 *
 * 5. Products derived from this software may not be called "TaSSL"
 *    nor may "TaSSL" appear in their names without prior written
 *    permission of the TaSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Beijing JN TASS 
 *    Technology Co.,Ltd. TaSSL Project.(http://www.tass.com.cn/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE TASSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE TASSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes software developed by the TaSSL Project
 * for use in the OpenSSL Toolkit (http://www.openssl.org/).
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <openssl/evp.h>
#include <unistd.h>
#include <signal.h>
#include "openssl/sm4.h"

uint32_t run;

void time_out(int sig)
{
    signal(SIGALRM, time_out);
    run = 0;
}

const char *test1result = "\x68\x1E\xDF\x34\xD2\x06\x96\x5E\x86\xB3\xE9\x4F\x53\x6E\x42\x46";
const char *test2result = "\x59\x52\x98\xC7\xC6\xFD\x27\x1F\x04\x02\xF8\x04\xC3\x3D\x3F\x66";

int main(int argc, char **argv)
{
    unsigned char key[] = "0123456789";
    unsigned char iv[] = "12345678";
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char outbuf[1024] = {0};
    char *inbuf = "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
    int outlen = 0;
    int tmplen = 0;
    

    if((ctx = EVP_CIPHER_CTX_new()) == NULL){
	printf("ctx new fail!\n");
	exit(0);
    }

    EVP_CIPHER_CTX_init(ctx);
    EVP_CipherInit_ex(ctx, EVP_sm4_ecb(), NULL, key, iv, 1);

    //EVP_CIPHER_CTX_set_key_length(ctx, 10);
    //完毕參数设置。进行key和IV的设置
    //EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, do_encrypt);

    if(!EVP_CipherUpdate(ctx, outbuf, &outlen, inbuf, strlen(inbuf)))
    {
    /*出错处理 */
    return 0;
    }

    if(!EVP_EncryptFinal_ex(ctx, outbuf + outlen, &tmplen))
     {
     /* 出错处理*/
     return 0;
     }
    outlen += tmplen;


    EVP_CIPHER_CTX_cleanup(ctx);
    return 1;

}
