#ifndef PACKET_H_
#define PACKET_H_

#define MT_IMG_SEND 0x01
#define MT_IMG_ACK 0x02

#define R_SUCCESS 0x01
#define R_FAIL 0x00

typedef struct packet_header{
	int msgType;
	int length;
} PACKET_HEADER;

typedef struct img_send{
	int imgLength;
	unsigned char *img;
} IMG_SEND;

typedef struct img_ack{
	int imgResult;
	int answerLength;
	char * answer;
} IMG_ACK;


#endif /* PACKET_H_ */

