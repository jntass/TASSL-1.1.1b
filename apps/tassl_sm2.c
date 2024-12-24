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

#include <string.h>
#include "openssl/evp.h"
#include "openssl/sm2.h"
#include "openssl/ec.h"
#include "apps.h"

const OPTIONS tassl_sm2_options[] = {
    {NULL},
};

struct SM2_Ciphertext_st {
    BIGNUM *C1x;
    BIGNUM *C1y;
    ASN1_OCTET_STRING *C3;
    ASN1_OCTET_STRING *C2;
};

static int tassl_sm2_enc_main(int argc, char *argv[])
{
    int rv = 0;
	EC_KEY *ec_key = NULL;
    unsigned char *text = NULL;
    size_t text_len;
    unsigned char *der = NULL;
	size_t derlen;
    unsigned char *bin = NULL;
    size_t binlen;
    const unsigned char *p = NULL;
    int outlen;
    SM2_Ciphertext *sm2_ctext = NULL;
    int i, ret;
	
    SM2_Ciphertext_new();

	if (argc != 3)
	{
		goto err;
	}

    text_len = atoi(argv[2]);
    if( text_len <= 0 )
    {
        BIO_printf(bio_err, "text_len error\r\n");
        goto err;
    }
    
    ec_key = EC_KEY_new_by_curve_name(NID_sm2);
	if( NULL == ec_key )
	{
		goto err;
	}

    ret = EC_KEY_generate_key(ec_key);
    if( 1 != ret )
    {
        goto err;
    }
    
    for( i = 0; i < 2; i++ )
    {
        const EC_POINT *ec_pub = NULL;
        const BIGNUM *ec_pri = NULL;
        const EC_GROUP *ec_group = NULL;
        unsigned char pub_key_buf[65];
        unsigned char pri_key_buf[32];

        if( NULL != text )
        {
            OPENSSL_free(text);
        }
        text = OPENSSL_malloc(text_len);
        if( NULL == text )
        {
            goto err;
        }

        derlen = text_len + 64 + 32 + 256;
        if( NULL != der )
        {
            OPENSSL_free(der);
        }
        der = OPENSSL_malloc(derlen);
    	if( NULL == der )
    	{
        	goto err;
    	}
        
        binlen = text_len + 64 + 32;
        if( NULL != bin )
        {
            OPENSSL_free(bin);
        }
        bin = OPENSSL_malloc(binlen);
    	if( NULL == bin )
    	{
        	goto err;
    	}
        
        ret = RAND_bytes(text, text_len);
        if( 1 != ret )
        {
            goto err;
        }

        ret = sm2_encrypt(ec_key, EVP_sm3(), text, text_len, der, &derlen);
        if( 1 != ret )
        {
            goto err;
        }
	
    	/*OK, output cipher*/
        p = der;
        outlen = 0;

        if( NULL != sm2_ctext )
        {
            SM2_Ciphertext_free(sm2_ctext);
        }
        sm2_ctext = (SM2_Ciphertext *)d2i_SM2_Ciphertext(NULL, &p, derlen);
        if( 32 != BN_bn2binpad(sm2_ctext->C1x, bin + outlen, 32) )
        {
            goto err;
        }

        outlen += 32;
        if( 32 != BN_bn2binpad(sm2_ctext->C1y, bin + outlen, 32) )
        {
            goto err;
        }
        outlen += 32;
        
        memcpy(bin + outlen, ASN1_STRING_get0_data(sm2_ctext->C3), ASN1_STRING_length(sm2_ctext->C3));
        outlen += ASN1_STRING_length(sm2_ctext->C3);
        
        memcpy(bin + outlen, ASN1_STRING_get0_data(sm2_ctext->C2), ASN1_STRING_length(sm2_ctext->C2));
        outlen += ASN1_STRING_length(sm2_ctext->C2);

        ec_group = EC_KEY_get0_group(ec_key);
        if( !ec_group )
        {
            goto err;
        }
        
        ec_pub = EC_KEY_get0_public_key(ec_key);
        if( !ec_pub )
        {
            goto err;
        }

        ret = EC_POINT_point2oct(ec_group, ec_pub, POINT_CONVERSION_UNCOMPRESSED, pub_key_buf, sizeof(pub_key_buf), NULL);
        if( 65 != ret )
        {
            goto err;
        }
        
        ec_pri = EC_KEY_get0_private_key(ec_key);
        if( !ec_pri )
        {
            goto err;
        }
        
        if( 32 != BN_bn2binpad(ec_pri, pri_key_buf, 32) )
        {
            goto err;
        }

        BIO_printf(bio_out, "公钥= ");
        for( ret = 0; ret < 64; ret++ )
        {
            BIO_printf(bio_out, "%02X", pub_key_buf[ret+1] & 0xff);
        }
        BIO_printf(bio_out, "\n");
        
        BIO_printf(bio_out, "私钥= ");
        for( ret = 0; ret < 32; ret++ )
        {
            BIO_printf(bio_out, "%02X", pri_key_buf[ret] & 0xff);
        }
        BIO_printf(bio_out, "\n");
        
        BIO_printf(bio_out, "明文长度= ");
        BIO_printf(bio_out, "%08X\n", (unsigned int)text_len);
        
        if( 0 == i )
        {
            BIO_printf(bio_out, "明文= ");
            for( ret = 0; (size_t)ret < text_len; ret++ )
            {
                BIO_printf(bio_out, "%02X", text[ret] & 0xff);
            }
            BIO_printf(bio_out, "\n");
            
            BIO_printf(bio_out, "密文= ");
            for( ret = 0; ret < outlen; ret++ )
            {
                BIO_printf(bio_out, "%02X", bin[ret] & 0xff);
            }
            BIO_printf(bio_out, "\n");
        }
        else
        {
            BIO_printf(bio_out, "密文= ");
            for( ret = 0; ret < outlen; ret++ )
            {
                BIO_printf(bio_out, "%02X", bin[ret] & 0xff);
            }
            BIO_printf(bio_out, "\n");
            
            BIO_printf(bio_out, "明文= ");
            for( ret = 0; (size_t)ret < text_len; ret++ )
            {
                BIO_printf(bio_out, "%02X", text[ret] & 0xff);
            }
            BIO_printf(bio_out, "\n");

        }
    }
    rv = 1;

err:
    if( ec_key ) EC_KEY_free(ec_key);
	if( text ) OPENSSL_free(text);
	if( der ) OPENSSL_free(der);
    if( bin ) OPENSSL_free(bin);
	if( sm2_ctext ) SM2_Ciphertext_free(sm2_ctext);
	return rv;
}

static int tassl_sm2_sig_main(int argc, char *argv[])
{
    int rv = 0;
	EC_KEY *ec_key = NULL;
    unsigned char *text = NULL;
    size_t text_len;
    unsigned char *der = NULL;
	unsigned int derlen;
    unsigned char *bin = NULL;
    size_t binlen;
    const unsigned char *p = NULL;
    int outlen;
    ECDSA_SIG *ecdsa_sig = NULL;
    int i, ret;

	if (argc != 3)
	{
		goto err;
	}

    text_len = atoi(argv[2]);
    if( text_len <= 0 )
    {
        BIO_printf(bio_err, "text_len error\r\n");
        goto err;
    }
    
    ec_key = EC_KEY_new_by_curve_name(NID_sm2);
	if( NULL == ec_key )
	{
		goto err;
	}

    ret = EC_KEY_generate_key(ec_key);
    if( 1 != ret )
    {
        goto err;
    }
    
    for( i = 0; i < 2; i++ )
    {
        const EC_POINT *ec_pub = NULL;
        const BIGNUM *ec_pri = NULL;
        const EC_GROUP *ec_group = NULL;
        unsigned char pub_key_buf[65];
        unsigned char pri_key_buf[32];

        if( NULL != text )
        {
            OPENSSL_free(text);
        }
        text = OPENSSL_malloc(text_len);
        if( NULL == text )
        {
            goto err;
        }

        derlen = 64 + 256;
        if( NULL != der )
        {
            OPENSSL_free(der);
        }
        der = OPENSSL_malloc(derlen);
    	if( NULL == der )
    	{
        	goto err;
    	}
        
        binlen = 64;
        if( NULL != bin )
        {
            OPENSSL_free(bin);
        }
        bin = OPENSSL_malloc(binlen);
    	if( NULL == bin )
    	{
        	goto err;
    	}
        
        ret = RAND_bytes(text, text_len);
        if( 1 != ret )
        {
            goto err;
        }

        ret = sm2_sign(text, text_len, der, &derlen, ec_key);
        if( 1 != ret )
        {
            goto err;
        }
	
    	/*OK, output cipher*/
        p = der;
        outlen = 0;

        if( NULL != ecdsa_sig )
        {
            ECDSA_SIG_free(ecdsa_sig);
        }
        ecdsa_sig = (ECDSA_SIG *)d2i_ECDSA_SIG(NULL, &p, derlen);
        if( 32 != BN_bn2binpad(ECDSA_SIG_get0_r(ecdsa_sig), bin + outlen, 32) )
        {
            goto err;
        }

        outlen += 32;
        if( 32 != BN_bn2binpad(ECDSA_SIG_get0_s(ecdsa_sig), bin + outlen, 32) )
        {
            goto err;
        }
        outlen += 32;
        
        ec_group = EC_KEY_get0_group(ec_key);
        if( !ec_group )
        {
            goto err;
        }
        
        ec_pub = EC_KEY_get0_public_key(ec_key);
        if( !ec_pub )
        {
            goto err;
        }

        ret = EC_POINT_point2oct(ec_group, ec_pub, POINT_CONVERSION_UNCOMPRESSED, pub_key_buf, sizeof(pub_key_buf), NULL);
        if( 65 != ret )
        {
            goto err;
        }
        
        ec_pri = EC_KEY_get0_private_key(ec_key);
        if( !ec_pri )
        {
            goto err;
        }
        
        if( 32 != BN_bn2binpad(ec_pri, pri_key_buf, 32) )
        {
            goto err;
        }

        BIO_printf(bio_out, "公钥= ");
        for( ret = 0; ret < 64; ret++ )
        {
            BIO_printf(bio_out, "%02X", pub_key_buf[ret+1] & 0xff);
        }
        BIO_printf(bio_out, "\n");
        
        BIO_printf(bio_out, "私钥= ");
        for( ret = 0; ret < 32; ret++ )
        {
            BIO_printf(bio_out, "%02X", pri_key_buf[ret] & 0xff);
        }
        BIO_printf(bio_out, "\n");

        BIO_printf(bio_out, "签名数据e= ");
        for( ret = 0; (size_t)ret < text_len; ret++ )
        {
            BIO_printf(bio_out, "%02X", text[ret] & 0xff);
        }
        BIO_printf(bio_out, "\n");

        BIO_printf(bio_out, "签名结果= ");
        for( ret = 0; ret < outlen; ret++ )
        {
            BIO_printf(bio_out, "%02X", bin[ret] & 0xff);
        }
        BIO_printf(bio_out, "\n");
    }

    rv = 1;
err:
    if( ec_key ) EC_KEY_free(ec_key);
    if( text ) OPENSSL_free(text);
    if( der ) OPENSSL_free(der);
    if( bin ) OPENSSL_free(bin);
    if( ecdsa_sig ) ECDSA_SIG_free(ecdsa_sig);
    return rv;
}

#define USAGE    "Usage : openssl tassl_sm2 enc/sig text_len\n""example: openssl tassl_sm2 enc 32"
#define ENC_CMD  "enc"
#define SIG_CMD  "sig"

int tassl_sm2_main( int argc, char *argv[] )
{
    int rv = 0;
    if( argc >= 2 )
    {
        if( 0 == strncasecmp(ENC_CMD, argv[1], strlen(ENC_CMD)) )
        {
            rv = tassl_sm2_enc_main(argc, argv);
        }
        else if( 0 == strncasecmp(SIG_CMD, argv[1], strlen(SIG_CMD)) )
        {
            rv = tassl_sm2_sig_main(argc, argv);
        }
    }

    if( !rv )
        BIO_printf(bio_err, "%s\n", USAGE);
    return 0;
}
