//----------------------------------------------------------------------------
// File: ssl_server.cpp
// Description: Implementation of an SSL-secured server that performs
//              secure file transfer to a single client over a single
//              connection.
//----------------------------------------------------------------------------
#include <string>
#include <time.h>
using namespace std;

#include <openssl/ssl.h>	// Secure Socket Layer library
#include <openssl/bio.h>	// Basic Input/Output objects for SSL
#include <openssl/rsa.h>	// RSA algorithm etc
#include <openssl/pem.h>	// For reading .pem files for RSA keys
#include <openssl/err.h>
#include <iostream>
#include "utils.h"

//-----------------------------------------------------------------------------
// Function: main()
//-----------------------------------------------------------------------------
int main(int argc, char** argv)
{
    //-------------------------------------------------------------------------
    // initialize
	ERR_load_crypto_strings();
	SSL_load_error_strings();
    SSL_library_init();
    
    setbuf(stdout, NULL); // disables buffered output

	// Handle commandline arguments
	// Useage: client -server serveraddress -port portnumber filename
	if (argc < 2)
	{
		printf("Useage: server portnumber\n");
		exit(EXIT_FAILURE);
	}
	char* port = argv[1];

	printf("------------\n");
	printf("-- SERVER --\n");
	printf("------------\n");

    //-------------------------------------------------------------------------
	// 1. Allow for a client to establish an SSL connection
	printf("1. Allowing for client SSL connection...");

	// Setup DH object and generate Diffie-Helman Parameters
	DH* dh = DH_generate_parameters(128, 5, NULL, NULL);
	int dh_err;
	DH_check(dh, &dh_err);
	if (dh_err != 0)
	{
		printf("Error during Diffie-Helman parameter generation.\n");
        print_errors();
		exit(EXIT_FAILURE);
	}

	// Setup server context
	SSL_CTX* ctx = SSL_CTX_new(SSLv23_method());
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
//	SSL_CTX_set_options(ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_SINGLE_DH_USE);
	SSL_CTX_set_tmp_dh(ctx, dh);
	if (SSL_CTX_set_cipher_list(ctx, "ALL") != 1)
	{
		printf("Error setting cipher list. Sad christmas...\n");
        print_errors();
		exit(EXIT_FAILURE);
	}

	// Setup the BIO
	BIO* server = BIO_new(BIO_s_accept());
	BIO_set_accept_port(server, port);
	BIO_do_accept(server);

	// Setup the SSL
	SSL* ssl = SSL_new(ctx);
	if (!ssl)
	{
		printf("Error creating new SSL object from context.\n");
        print_errors();
		exit(EXIT_FAILURE);
	}
	SSL_set_accept_state(ssl);
	SSL_set_bio(ssl, server, server);
	if (SSL_accept(ssl) <= 0)
	{
		printf("Error doing SSL_accept(ssl).\n");
        print_errors();
		exit(EXIT_FAILURE);
	}

	printf("DONE.\n");
	printf("    (Now listening on port: %s)\n", port);

    //-------------------------------------------------------------------------
	// 2. Receive a random number (the challenge) from the client
	printf("2. Waiting for client to connect and send challenge...");
    
    //SSL_read challenge from client 
    char challenge[5];
    int lenght_cha = SSL_read(ssl, challenge , 5);cout<<lenght_cha;
	printf("DONE.\n");
	printf("    (Challenge: \"%s\")\n", challenge);

    //-------------------------------------------------------------------------
	// 3. Generate the SHA1 hash of the challenge
	printf("3. Generating SHA1 hash...");

	BIO* buff_new;
	buff_new = BIO_new(BIO_s_mem());
	BIO_write(buff_new, challenge,lenght_cha);
	BIO* hash_new;
	hash_new = BIO_new(BIO_f_md());
  	BIO_set_md(hash_new, EVP_sha1());
	buff_new = BIO_push(hash_new,buff_new);
    int mdlen=0;
	char hash_string[lenght_cha];
	mdlen = BIO_read(buff_new, hash_string, lenght_cha);
	string temp = buff2hex((const unsigned char*)(hash_string),mdlen);
	printf("SUCCESS.\n");
	printf("    (SHA1 hash: \"%s\" (%d bytes))\n",temp.c_str() , mdlen);

    //-------------------------------------------------------------------------
	// 4. Sign the key using the RSA private key specified in the
	//     file "rsaprivatekey.pem"
	printf("4. Signing the key...");
	char signature[BUFFER_SIZE];
	BIO *privatekey =BIO_new_file("rsaprivatekey.pem", "r");;
    RSA * rsa_private = PEM_read_bio_RSAPrivateKey(privatekey,NULL,NULL,NULL);
    int x =RSA_private_encrypt(EVP_MAX_MD_SIZE,(unsigned char*)hash_string,(unsigned char*)signature,rsa_private, RSA_PKCS1_PADDING);
    int siglen=x;

    printf("DONE.\n");
    printf("    (Signed key length: %d bytes)\n", siglen);
    printf("    (Signature: \"%s\" (%d bytes))\n", buff2hex((const unsigned char*)signature, siglen).c_str(), siglen);

    //-------------------------------------------------------------------------
	// 5. Send the signature to the client for authentication
	printf("5. Sending signature to client for authentication...");

	SSL_write(ssl,signature,siglen);
	BIO_flush(server);
    printf("DONE.\n");
    
    //-------------------------------------------------------------------------
	// 6. Receive a filename request from the client
	printf("6. Receiving file request from client...");
	char file[BUFFER_SIZE];
    memset(file,0,sizeof(file));
	int u = SSL_read(ssl,file,BUFFER_SIZE);
    printf("RECEIVED.\n");
    printf("    (File requested: \"%s\"\n", file);

    //-------------------------------------------------------------------------
	// 7. Send the requested file back to the client (if it exists)
	printf("7. Attempting to send requested file to client...");

	PAUSE(2);
	int bytesSent=0;
	int extra=0;
	char buffer[1024];
	BIO * reading = BIO_new_file((const char *)file,"r");
	while((extra = BIO_read(reading, buffer, sizeof(buffer)-1)) > 0)
	{	cout<<extra;
		bytesSent+=SSL_write(ssl, buffer, extra);
		memset(buffer,0,bytesSent);
	}
    
    
    printf("SENT.\n");
    printf("    (Bytes sent: %d)\n", bytesSent);

    //-------------------------------------------------------------------------
	// 8. Close the connection
	printf("8. Closing connection...");

	SSL_shutdown(ssl);
    BIO_reset(server);
    printf("DONE.\n");

    printf("\n\nALL TASKS COMPLETED SUCCESSFULLY.\n");
	
    //-------------------------------------------------------------------------
	// Freedom!
    
	BIO_free_all(server);
	return EXIT_SUCCESS;
}
