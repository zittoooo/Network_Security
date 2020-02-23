#include "packet_controller.h"
#include "packet.h"
#include "codec.h"

int Packet_Handler(unsigned char *src, int msgType)
{
	IMG_ACK *imgAck;
	int rv;

	switch(msgType){
		case MT_IMG_ACK:
			printf("\nClient received IMG_ACK packet.\n");
			decode_ImgAck(src, &imgAck);
			printf("\nThe answer received from the server is : %s\n", imgAck->answer);
			free(imgAck->answer);
			free(imgAck);
			rv = 0;
			break;

		default:
			rv = -1;
			break;
	}
	return rv;
}

