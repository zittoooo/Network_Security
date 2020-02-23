#include "codec.h"
#include <string.h>

int encode_PacketHeader(PACKET_HEADER *src, unsigned char **dst)
{
	unsigned char *pt;
	int msgType, length;

	*dst = (unsigned char *)calloc(1, sizeof(PACKET_HEADER));
	pt = *dst;

	msgType = htonl(src->msgType);
	memcpy(pt, &msgType, sizeof(int));
	pt += sizeof(int);

	length = htonl(src->length);
	memcpy(pt, &length, sizeof(int));

	return sizeof(PACKET_HEADER);
}

int decode_PacketHeader(unsigned char *src, PACKET_HEADER **dst)
{
	unsigned char *pt;
	int msgType, length;

	pt = src;
	*dst = (PACKET_HEADER *)calloc(1, sizeof(PACKET_HEADER));

	memcpy(&msgType, pt, sizeof(int));
	(*dst)->msgType = ntohl(msgType);
	pt += sizeof(int);

	memcpy(&length, pt, sizeof(int));
	(*dst)->length = ntohl(length);

	return sizeof(PACKET_HEADER);
}


int encode_ImgSend(IMG_SEND *src, unsigned char **dst)
{
	unsigned char *pt;
	*dst = (unsigned char *)calloc(1, sizeof(int) + src->imgLength);
	
	pt = *dst;
	int size = htonl(src->imgLength);
	memcpy(pt, &size, sizeof(int));
	pt += sizeof(int);
	memcpy(pt, src->img, src->imgLength);

	return sizeof(int) + src->imgLength;
}

int decode_ImgSend(unsigned char *src, IMG_SEND **dst)
{
	unsigned char *pt;
	*dst = (IMG_SEND *)calloc(1, sizeof(IMG_SEND));
	
	pt = src;
	memcpy(&((*dst)->imgLength), pt, sizeof(int));
	(*dst)->imgLength = ntohl((*dst)->imgLength);
	
	(*dst)->img = (unsigned char *)calloc(1, (*dst)->imgLength);
	pt += sizeof(int);
	memcpy((*dst)->img, pt, (*dst)->imgLength);
	
	return sizeof(int) + (*dst)->imgLength;

}

int encode_ImgAck(IMG_ACK *src, unsigned char **dst)
{
	unsigned char *pt;
	int imgResult;
	int answerLength;
	int tmplen=0;
	int len=0;

	len = sizeof(int) + sizeof(int) + src->answerLength;

	*dst = (unsigned char *) calloc(1,len);
	pt = *dst;
	
	imgResult = htonl(src->imgResult);
	memcpy(pt, &imgResult, sizeof(int));
	pt += sizeof(int);
	
	tmplen = src->answerLength;
	answerLength = htonl(src->answerLength);
	memcpy(pt,  &answerLength, sizeof(int));
	pt += sizeof(int);

	memcpy(pt, src->answer, tmplen);

	return len;
	
}

int decode_ImgAck(unsigned char *src, IMG_ACK **dst)
{

	unsigned char *pt;
	int imgResult;
	int answerLength;
	int len=0 , tmplen=0;

	pt = src;
	*dst = (IMG_ACK *) calloc (1,sizeof(IMG_ACK));
	
	tmplen = sizeof((*dst)->imgResult);
	
	memcpy(&imgResult, pt, tmplen);
	(*dst)->imgResult = ntohl(imgResult);
	pt += tmplen; len+=tmplen;
	
	tmplen = sizeof((*dst)->answerLength);
	memcpy(&answerLength, pt, tmplen);
	(*dst)->answerLength = ntohl(answerLength);
	pt += tmplen; len+=tmplen;

	(*dst)->answer = (char *) calloc(1, (*dst)->answerLength);
	memcpy((*dst)->answer, pt , (*dst)->answerLength);
	len += (*dst)->answerLength;

	return len;

}


int encode_packet(int msgType, void *msg, unsigned char **dst)
{
	int msgLen=0, headLen=0;
	unsigned char *headBuf, *msgBuf, *pt;
	PACKET_HEADER *header;
	
	switch(msgType){
	case MT_IMG_SEND:
		msgLen = encode_ImgSend((IMG_SEND *)msg, &msgBuf);
		header = (PACKET_HEADER *)calloc(1, sizeof(PACKET_HEADER));
		header->msgType=MT_IMG_SEND;
		header->length = msgLen;
		headLen = encode_PacketHeader(header, &headBuf);
		break;	
	case MT_IMG_ACK:
		msgLen = encode_ImgAck((IMG_ACK *)msg, &msgBuf);
		header = (PACKET_HEADER *)calloc(1, sizeof(PACKET_HEADER));
		header->msgType = MT_IMG_ACK;
		header->length = msgLen;
		headLen = encode_PacketHeader(header, &headBuf);
		break;
	}

	*dst = (unsigned char *)calloc(1, headLen + msgLen);
	pt = *dst;

	memcpy(pt, headBuf, headLen);
	pt += headLen;

	memcpy(pt, msgBuf, msgLen);

	free(headBuf);
	free(msgBuf);

	return (headLen + msgLen);
}

