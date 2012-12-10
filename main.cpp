#include <iostream>
#include <fstream>
#include <openssl/ssl.h>
#include <openssl/bio.h>

using namespace std;

void check_cert(SSL *ssl,char *host)
{
 X509 *peer;
 char peer_CN[256];

 if(SSL_get_verify_result(ssl)!=X509_V_OK)
 berr_exit("Certificate doesn’t verify");

 /*Check the cert chain. The chain length
 is automatically checked by OpenSSL when
 we set the verify depth in the ctx */

 /*Check the common name*/
 peer=SSL_get_peer_certificate(ssl);
 X509_NAME_get_text_by_NID
 	(X509_get_subject_name(peer),
 	NID_commonName, peer_CN, 256);
 if(strcasecmp(peer_CN,host))
 err_exit
 	("Common name doesn’t match host name");
 }

SSL_CTX *initialize_ctx(char *keyfile,char *password)
{
	 SSL_METHOD *meth;
	 SSL_CTX *ctx;

	 if(!bio_err)
	{
	 /* Global system initialization*/
	 SSL_library_init();
	 SSL_load_error_strings();

	 /* An error write context */
	 bio_err=BIO_new_fp(stderr,BIO_NOCLOSE);
	 }

	 /* Set up a SIGPIPE handler */
	 signal(SIGPIPE,sigpipe_handle);

	 /* Create our context*/
	 meth=SSLv23_method();
	 ctx=SSL_CTX_new(meth);

	 /* Load our keys and certificates*/
	 if(!(SSL_CTX_use_certificate_chain_file(ctx,keyfile)))
	 	berr_exit("Can’t read certificate file");

	 pass=password;
	 SSL_CTX_set_default_passwd_cb(ctx,password_cb);
	 if(!(SSL_CTX_use_PrivateKey_file(ctx,keyfile,SSL_FILETYPE_PEM)))
	 	berr_exit("Can’t read key file");

	 /* Load the CAs we trust*/
	 if(!(SSL_CTX_load_verify_locations(ctx,CA_LIST,0)))
	 	berr_exit("Ca’t read CA list");
	 #if (OPENSSL_VERSION_NUMBER < 0x0090600fL)
	 SSL_CTX_set_verify_depth(ctx,1);
	 #endif

	 return ctx;
 }

int main()
{

	return 0;
}
