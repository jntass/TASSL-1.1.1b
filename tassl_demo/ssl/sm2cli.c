#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "openssl/bio.h"
#include "openssl/err.h"
#include "openssl/rand.h"
#include "openssl/ssl.h"
#include "openssl/x509v3.h"

#define MAX_BUF_LEN 4096
#define CLIENT_S_CERT   "../cert/certs/CS.pem"
#define CLIENT_E_CERT   "../cert/certs/CE.pem"
#define CLIENT_CA_CERT  "../cert/certs/CA.pem"
#define SSL_ERROR_WANT_HSM_RESULT 10


void Init_OpenSSL()
{
    if (!SSL_library_init())
        exit(0);
    SSL_load_error_strings();
}

int seed_prng(int bytes)
{
    if (!RAND_load_file("/dev/random", bytes))
        return 0;
    return 1;
}

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	BIO *conn = NULL;
	SSL *ssl = NULL;
	SSL_CTX *ctx = NULL;
	int usecert = 1;
	int retval;
	int aio_tag = 0;
	char sendbuf[MAX_BUF_LEN];
	int i = 0;
	const SSL_METHOD      *meth;

    /*Detect arguments*/
	if (argc < 2)
	{
		printf("Usage : %s host:port [use_cert] [aio]\n", argv[0]);
		exit(0);
	}

	if (argc >= 3)
		usecert = atoi(argv[2]);
	
	if (argc >= 4)
		aio_tag = atoi(argv[3]);

	Init_OpenSSL();
	

	meth = CNTLS_client_method();
	ctx = SSL_CTX_new(meth);
	if (ctx == NULL)
	{
		printf("Error of Create SSL CTX!\n");
		goto err;
	}

	if (usecert)
	{
		if (SSL_CTX_use_certificate_file(ctx, CLIENT_S_CERT, SSL_FILETYPE_PEM) <= 0)
		{
			ERR_print_errors_fp(stderr);
			goto err;
		}

		if (SSL_CTX_use_PrivateKey_file(ctx, CLIENT_S_CERT, SSL_FILETYPE_PEM) <= 0)
		{
			ERR_print_errors_fp(stderr);
			goto err;
		}

		if (SSL_CTX_use_enc_certificate_file(ctx, CLIENT_E_CERT, SSL_FILETYPE_PEM) <= 0)
		{
			ERR_print_errors_fp(stderr);
			goto err;
		}
		if (SSL_CTX_use_enc_PrivateKey_file(ctx, CLIENT_E_CERT, SSL_FILETYPE_PEM) <= 0)
		{
			ERR_print_errors_fp(stderr);
			goto err;
		}

		if (!SSL_CTX_check_private_key(ctx))
		{
			printf("Private key does not match the certificate public key/n");
			goto err;
		}

		if (!SSL_CTX_check_enc_private_key(ctx))
		{
			printf("Private key does not match the certificate public key/n");
			goto err;
		}

                if (!SSL_CTX_load_verify_locations(ctx, CLIENT_CA_CERT, NULL))
                {
                        ERR_print_errors_fp(stderr);
                        exit(1);
                }

	} 

    /*Now Connect host:port*/
	conn = BIO_new_connect(argv[1]);
	if (!conn)
	{
		printf("Error Of Create Connection BIO\n");
		goto err;
	}

	if (BIO_do_connect(conn) <= 0)
	{
		printf("Error Of Connect to %s\n", argv[1]);
		goto err;
	}
	
	if(!SSL_CTX_set_cipher_list(ctx, "ECDHE-SM4-SM3")){
		printf("set cipher list fail!\n");
		exit(0);
	}

	ssl = SSL_new(ctx);
	if (ssl == NULL)
	{
		printf("SSL New Error\n");
		goto err;
	}

	SSL_set_bio(ssl, conn, conn);

	/*if (SSL_connect(ssl) <= 0)
	{
	    printf("Error Of SSL connect server\n");
	    goto err;
	}*/

	SSL_set_connect_state(ssl);
	//SSL_set_sm2_group_id_custom(29);
	while (1)
	{
		retval = SSL_do_handshake(ssl);
		if (retval > 0)
			break;
		else
		{
			if (SSL_get_error(ssl, retval) == SSL_ERROR_WANT_HSM_RESULT)
				continue;
			else
			{
				printf("Error Of SSL do handshake\n");
				goto err;
			}
		}
	}
	
	for(i=0; i<MAX_BUF_LEN; i++){

		sprintf(sendbuf+i, "%d", i%10);
	}

	while(1){

		if (SSL_write(ssl, "hello i am from client ", strlen("hello i am from client ")) <= 0)
		{
			printf("ssl_write fail!\n");
			break;
		}
		break;
	}
	{
		char rbuf[2048];

		memset( rbuf, 0x0, sizeof(rbuf) );
		if ( SSL_read( ssl, rbuf, 2048 ) > 0 )
			printf( "SSL recv: %s.\n", rbuf );
		else
			printf( "None recv buf.\n" );
		
		SSL_shutdown(ssl);
	}

err:
	if (ssl) SSL_free(ssl);
	if (ctx) SSL_CTX_free(ctx);

	return 0;
}


