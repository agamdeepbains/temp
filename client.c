#include<stdio.h>
#include<unistd.h>
#include<sys/wait.h>
#include<string.h>
#include<fcntl.h>
#include<openssl/conf.h>
#include<openssl/evp.h>
#include<openssl/err.h>

int encrypt(unsigned char *original,int originall,unsigned char *key,unsigned char *iv,unsigned char *encoded)
{
	EVP_CIPHER_CTX *ctx=EVP_CIPHER_CTX_new();
	int len;
	EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
	EVP_EncryptUpdate(ctx,encoded,&len,original,originall);
	int encodel=len;
	EVP_EncryptFinal_ex(ctx,encoded+len,&len);
	encodel+=len;
	EVP_CIPHER_CTX_free(ctx);
	return encodel;
}

int generate(const unsigned char *encoded,size_t encodel, unsigned char **hmac, size_t *hmacl,EVP_PKEY *pkey)
{
	EVP_MD_CTX* ctx=EVP_MD_CTX_new();
	size_t req=0;
	int rc=EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey);
	rc=EVP_DigestSignUpdate(ctx,encoded,encodel);
	rc=EVP_DigestSignFinal(ctx, NULL, &req);
	*hmac=(unsigned char*)OPENSSL_malloc(req);
	*hmacl=req;
	rc=EVP_DigestSignFinal(ctx,*hmac,hmacl);
	EVP_MD_CTX_free(ctx);
	return 1;
}

int main(int argc, char **argv)
{
	int p[2], pid, nbytes;

	pipe(p);
  
	if ((pid = fork()) > 0) {
		unsigned char *key=(unsigned char *)"mynameisagamdeepbainsrnum2019009";
		unsigned char *iv=(unsigned char *)malloc(sizeof(unsigned char)*16);
		int fl=open("/dev/urandom",O_RDONLY);
		read(fl,iv,16);
		close(fl);
		unsigned char *original=(unsigned char *)malloc(sizeof(unsigned char)*1024);
		fl=open(argv[1],O_RDONLY);
		read(fl,original,1024);
		close(fl);
		unsigned char *encoded=(unsigned char*)malloc(sizeof(unsigned char)*1024);
		int encodel=encrypt(original,strlen((char*)original),key,iv,encoded+48);
		EVP_PKEY *sk=EVP_PKEY_new_mac_key(EVP_PKEY_HMAC,NULL,key,32);
		size_t hmacl=0;
		unsigned char* hmac=NULL;
		int r=generate(encoded+48,encodel,&hmac,&hmacl,sk);
		memcpy(encoded,iv,16);
		memcpy(encoded+16,hmac,32);

		int ret=write(p[1],encoded,encodel+48);
	}
	else {
		dup2(p[0],STDIN_FILENO);
		execl("/bin/nc","/bin/nc","127.0.0.1","4500",NULL);
	}
	return 0;
}