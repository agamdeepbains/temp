#include<stdio.h>
#include<unistd.h>
#include<sys/wait.h>
#include<string.h>
#include<fcntl.h>
#include<openssl/conf.h>
#include<openssl/evp.h>
#include<openssl/err.h>

int decrypt(unsigned char *encoded,int encodel,unsigned char *key,unsigned char *iv,unsigned char *original)
{
	int len;
	int originall;
	EVP_CIPHER_CTX *ctx=EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
	EVP_DecryptUpdate(ctx,original,&len,encoded,encodel);
	originall=len;
	EVP_DecryptFinal_ex(ctx,original+len, &len);
	originall+=len;
	EVP_CIPHER_CTX_free(ctx);
	return originall;
}

int verification(const unsigned char *encoded,size_t encodel,const unsigned char *hmac,size_t hmacl,EVP_PKEY *pkey)
{
	EVP_MD_CTX* ctx=EVP_MD_CTX_new();
	int rc=EVP_DigestSignInit(ctx,NULL,EVP_sha256(),NULL,pkey);
	rc=EVP_DigestSignUpdate(ctx,encoded,encodel);
	unsigned char buff[EVP_MAX_MD_SIZE];
	size_t size=sizeof(buff);
	rc=EVP_DigestSignFinal(ctx,buff,&size);
	EVP_MD_CTX_free(ctx);
	return (hmacl==size)&&(CRYPTO_memcmp(hmac,buff,size)==0);
}

int main()
{
	int p[2],pid;
	pipe(p);
	pid=fork();
	if (pid>0)
	{
		unsigned char *key=(unsigned char *)"mynameisagamdeepbainsrnum2019009";
		unsigned char *encoded=(unsigned char*)malloc(sizeof(unsigned char)*1024);
		unsigned char *decrypted=(unsigned char*)malloc(sizeof(unsigned char)*1024);
		unsigned char *iv=(unsigned char*)malloc(sizeof(unsigned char)*16);
		unsigned char *hmac=(unsigned char*)malloc(sizeof(unsigned char)*32);
		int r=read(p[0],encoded,1024);
		memcpy(iv,encoded,16);
		memcpy(hmac,encoded+16,32);
		EVP_PKEY *vk=EVP_PKEY_new_mac_key(EVP_PKEY_HMAC,NULL,key,32);
		int res=verification(encoded+48,r-48,hmac,32,vk);
		int fl=open("output.txt",O_CREAT | O_RDWR,S_IRWXU);
		if(res==1)
		{
			int decryptedl=decrypt(encoded+48, r-48,key,iv,decrypted);
			decrypted[decryptedl]='\0';
			write(fl,decrypted,decryptedl);
		}
		else
		{
			unsigned char* temp=(unsigned char *)"Incorrect\n";
			write(fl,temp,strlen(temp));
		}
		close(fl);
	}
	else
	{
		dup2(p[1],STDOUT_FILENO);
		execl("/bin/nc","/bin/nc","-l","-p","4500",NULL);
	}
	return 0;
}