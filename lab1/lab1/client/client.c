#include "codec.h"
#include "packet.h"
#include "packet_controller.h"
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#if defined(csecSSL)
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

int read_msg(SSL *ssl, unsigned char **msgBuf, PACKET_HEADER **header);
ssize_t readn(SSL *ssl, unsigned char *buf, size_t nbytes);
ssize_t writen(SSL *ssl, unsigned char *buf, size_t nbytes);
#else
int read_msg(int sock, unsigned char **msgBuf, PACKET_HEADER **header);
#endif


void error_handling(char *message);

int main(int argc, char *argv[])
{
	int sock;
	struct sockaddr_in serv_adr;
	int length, recv_len = 0;
	unsigned char *message, *sendBuf = NULL;
	char * path="image.jpg";

	PACKET_HEADER *header;

	if(argc!=3) {
		printf("Usage : %s <IP> <port>\n", argv[0]);
		exit(1);
	}

	sock=socket(PF_INET, SOCK_STREAM, 0);
	if(sock==-1)
		error_handling("socket() error");

	memset(&serv_adr, 0, sizeof(serv_adr));
	serv_adr.sin_family=AF_INET;
	serv_adr.sin_addr.s_addr=inet_addr(argv[1]);
	serv_adr.sin_port=htons(atoi(argv[2]));

	if(connect(sock, (struct sockaddr*)&serv_adr, sizeof(serv_adr))==-1)
		error_handling("connect() error!");
	else
		puts("Connected...........");

	#if defined(csecSSL)
	SSL_CTX *ctx;
	SSL *ssl;
	X509 *server_cert;

	SSL_load_error_strings();
	SSLeay_add_ssl_algorithms();

	ctx = SSL_CTX_new(TLSv1_2_client_method());

	ssl = SSL_new(ctx);

	SSL_set_fd(ssl, sock);
	if(SSL_connect(ssl) == -1){
		return -1;
	}

	server_cert = SSL_get_peer_certificate(ssl);

	printf("\nServer certificate:\n");
	printf("subject: %s\n", X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0));
	printf("issuer: %s\n", X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0));

	X509_free(server_cert);
	
	#endif

	FILE * fp;
	unsigned char *imgBuf;
	IMG_SEND *imgSend;
	IMG_ACK *imgAck;
	int fileSize;
	while(1)
	{
		fileSize=0;
		fp = fopen(path, "rb");
		fseek(fp, 0, SEEK_END);
		fileSize = ftell(fp);
		fseek(fp, 0, SEEK_SET);

		imgBuf = (unsigned char *)calloc(1, fileSize+1);

		if(fread(imgBuf, 1, fileSize, fp) == -1)
		{
			fprintf(stderr, "fread error\n");
			exit(1);
		}
		fclose(fp);
		break;
	}

	imgSend= (IMG_SEND *)calloc(1,sizeof(IMG_SEND));
	imgSend->imgLength = fileSize;
	imgSend->img = (unsigned char*)calloc(1,fileSize);
	memcpy(imgSend->img, imgBuf,fileSize);
	//strcpy(imgSend->img,imgBuf); //strcpy stop 0x00 binary 0x00 exist
	
	//Encoding Packet
	length = encode_packet(MT_IMG_SEND, (void *)imgSend, &sendBuf);
	free(imgSend->img); free(imgSend); free(imgBuf);

	#if defined(csecSSL)
	//Sending image send Packet
	length = writen(ssl, sendBuf, length);
	printf("\nClient Sent %d bytes\n", length);
	free(sendBuf); sendBuf = NULL;

	#else
	//send image send packet
	
	length = write(sock, sendBuf, length);
	printf("\nClient Sent %d bytes\n", length);
	
	free(sendBuf); sendBuf = NULL;

	#endif

	do{
		//Receiving image ack packet
		#if defined(csecSSL)
		recv_len = read_msg(ssl, &message, &header);
		#else
		recv_len = read_msg(sock, &message, &header);
		#endif
	}while(!(recv_len > 0));

	if(Packet_Handler(message, header->msgType) == -1)
		error_handling("Unknown Message Type!");

	#if defined(csecSSL)
	SSL_shutdown(ssl);
	SSL_free(ssl);
	SSL_CTX_free(ctx);
	#endif

	free(header);
	free(message);
	close(sock);
	return 0;
}

#if defined(csecSSL)
int read_msg(SSL *ssl, unsigned char **msgBuf, PACKET_HEADER **header)
{
	size_t msgLength = 0;

	int headerLength = sizeof(PACKET_HEADER);
	unsigned char *buf = (unsigned char *)calloc(1, headerLength);
	
	readn(ssl, buf, headerLength);

	decode_PacketHeader(buf, header);
	msgLength = (*header)->length;

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
		nread = SSL_read(ssl,ptr,nleft);
		if(nread ==0)
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
		nwrite = SSL_write(ssl,ptr,nleft);
		if(nwrite == 0)
			break;
		ptr += nwrite;
		nleft -= nwrite;
	}
	return (nbytes - nleft);
}
#else
int read_msg(int sock, unsigned char **msgBuf, PACKET_HEADER **header)
{
	size_t msgLength = 0;

	int headerLength = sizeof(PACKET_HEADER);
	unsigned char *buf = (unsigned char *)calloc(1, headerLength);

	read(sock, buf, headerLength);

	decode_PacketHeader(buf, header);
	msgLength = (*header)->length;

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



