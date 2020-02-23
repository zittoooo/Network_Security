#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "packet.h"
#include "codec.h"
#include "packet_controller.h"

#if defined(csecSSL)

#include <openssl/rsa.h>      
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

int SSU_SEC_SSL_server(int sd, unsigned char* msg, char* cert, char* key);
int read_msg(SSL *ssl, unsigned char **msgBuf, int *msgType);
ssize_t readn(SSL *ssl, unsigned char *buf, size_t nbytes);
ssize_t writen(SSL *ssl, unsigned char *buf, size_t nbytes);

#else
int SSU_server(int sd, unsigned char* msg);
int read_msg(int sock, unsigned char **msgBuf, int *msgType);
#endif

void error_handling(char *message);

int main(int argc, char *argv[])
{
	int serv_sock, clnt_sock;
	unsigned char *message;
	int i = 0;
	int optVal = 1;

	struct sockaddr_in serv_adr;
	struct sockaddr_in clnt_adr;
	socklen_t clnt_adr_sz;

	if(argc!=2) {
		printf("Usage : %s <port>\n", argv[0]);
		exit(1);
	}

	serv_sock=socket(PF_INET, SOCK_STREAM, 0);
	if(serv_sock==-1)
		error_handling("socket() error");

	memset(&serv_adr, 0, sizeof(serv_adr));
	serv_adr.sin_family=AF_INET;
	serv_adr.sin_addr.s_addr=htonl(INADDR_ANY);
	serv_adr.sin_port=htons(atoi(argv[1]));

	setsockopt(serv_sock, SOL_SOCKET, SO_REUSEADDR, (void *)&optVal, sizeof(int));

	if(bind(serv_sock, (struct sockaddr*)&serv_adr, sizeof(serv_adr))==-1)
		error_handling("bind() error");

	if(listen(serv_sock, 5)==-1)
		error_handling("listen() error");

	clnt_adr_sz=sizeof(clnt_adr);

	while(1)
	{
		clnt_sock=accept(serv_sock, (struct sockaddr*)&clnt_adr, &clnt_adr_sz);
		if(clnt_sock==-1)
			continue;
		else
			printf("Connected client %d \n", ++i);

		pid_t pid = fork();
		if(pid == 0)
		{
			close(serv_sock);
			#if defined(csecSSL)
			char* certfile = "cert/servercert.pem";
			char* keyfile = "cert/serverkey.pem";
			SSU_SEC_SSL_server(clnt_sock, message, certfile, keyfile);
			#else
			SSU_server(clnt_sock, message);
			#endif
			close(clnt_sock);
		}
			
		else if(pid < 0)
		{
			fprintf(stderr, "Fork() Failed\n");
			close(clnt_sock);
		}
		else
			close(clnt_sock);
		
	}

	close(serv_sock);
	return 0;
}

#if defined(csecSSL)
int SSU_SEC_SSL_server(int sd, unsigned char* msg, char* cert, char* key)
{
	int size;
	SSL_CTX *ctx;
	SSL *ssl;
	X509 *client_cert;

	int msgType;
	size_t length;
	size_t recv_len = 0;
	unsigned char *sendBuf;
   
	SSL_load_error_strings();
	SSLeay_add_ssl_algorithms();
	ctx = SSL_CTX_new(SSLv23_server_method());  

	if(SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) <= 0) {      
		return -1;
	}
	if(SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0) {
		return -1;
	}

	if(!SSL_CTX_check_private_key(ctx)) {
		return -1;
	}

	ssl = SSL_new(ctx);
	SSL_set_fd(ssl, sd);
	if(SSL_accept(ssl) == -1){
		return -1;
	}

	printf("\nSSL connection using %s\n", SSL_get_cipher(ssl));

	while(1)
	{
		recv_len = read_msg(ssl, &msg, &msgType); //데이터수신
		if(recv_len !=0){
			if(Packet_Handler(msg, &sendBuf, msgType, &length)!= -1){
				writen(ssl, sendBuf, length);  //데이터 송신
				free(sendBuf);free(msg);
				continue;
			}
 		}
		break;
	}

	free(msg);

	SSL_free(ssl);
	SSL_CTX_free(ctx);

    return(0);
}

int read_msg(SSL *ssl, unsigned char **msgBuf, int *msgType)
{
	size_t msgLength = 0;
	PACKET_HEADER *header = NULL;
	int headerLength = sizeof(PACKET_HEADER);
	unsigned char *buf = (unsigned char *)calloc(1, headerLength);

	readn(ssl, buf, headerLength);

	decode_PacketHeader(buf, &header);
	msgLength = header->length;
	*msgType = header->msgType;

	*msgBuf = (unsigned char *)calloc(1, msgLength);

	readn(ssl, *msgBuf, msgLength);

	free(buf);
	return msgLength;
}

ssize_t readn(SSL *ssl, unsigned char *buf, size_t nbytes)
{
	size_t nleft;
	ssize_t nread;
	unsigned char *ptr;
	
	ptr = buf;
	nleft = nbytes;

	while(nleft > 0){
		nread = SSL_read(ssl, ptr, nleft);
		if(nread == 0)
			break;
		ptr += nread;
		nleft -= nread;
	}
	return (nbytes - nleft);
}

ssize_t writen(SSL *ssl, unsigned char *buf, size_t nbytes)
{
	size_t nleft;
	ssize_t nwrite;
	unsigned char *ptr;
	
	ptr = buf;
	nleft = nbytes;

	while(nleft > 0){
		nwrite = SSL_write(ssl, ptr, nleft);
		if(nwrite == 0)
			break;
		ptr += nwrite;
		nleft -= nwrite;
	}
	return (nbytes - nleft);
}
#else

int SSU_server(int sock, unsigned char* msg){
	int msgType;
	size_t length;
	size_t recv_len = 0;
	unsigned char *sendBuf;
	while(1)
	{
		recv_len = read_msg(sock, &msg, &msgType);
		if(recv_len != 0){
			if(Packet_Handler(msg, &sendBuf, msgType, &length) != -1) {
				write(sock, sendBuf, length); 
				free(sendBuf); free(msg);
				continue;
			}
		}
		break;
	}
	free(msg);
	return(0);
}

int read_msg(int sock, unsigned char **msgBuf, int *msgType)
{
	size_t msgLength = 0;
	PACKET_HEADER *header = NULL;
	int headerLength = sizeof(PACKET_HEADER);
	unsigned char *buf = (unsigned char *)calloc(1, headerLength);

	read(sock, buf, headerLength);
	
	decode_PacketHeader(buf, &header);
	msgLength = header->length;
	*msgType = header->msgType;

	*msgBuf = (unsigned char *)calloc(1, msgLength);
	read(sock, *msgBuf, msgLength); 

	free(buf);
	return msgLength;
}

#endif
void error_handling(char *message)
{
	fputs(message, stderr);
	fputc('\n', stderr);
	exit(1);
}

