#include "packet_controller.h"
#include "packet.h"
#include "codec.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

int Packet_Handler(unsigned char *src, unsigned char **dst, int msgType, size_t* dst_len)
{
	IMG_SEND *imgSend;
	IMG_ACK *imgAck;
	int rv;
	FILE *fp;
	char * path = "image.jpg";
	char input[512];

	switch(msgType){
		case MT_IMG_SEND:
			printf("\nImage Send received\n");
			//Decoding Message
			decode_ImgSend(src, &imgSend);
			//Generating Packet Message
			if(imgSend->img != NULL)
			{
				//save image file
	   			fp = fopen(path, "wb");
	   			if(fwrite(imgSend->img, 1,imgSend->imgLength, fp) == -1)
	   			{
	   				fprintf(stderr, "fwrite error\n");
	   				fclose(fp);
	   				return -1;
	   			}

				fclose(fp);

				//open image file
				char command[32] = {0};
				strcat(command, "xdg-open ");
				strcat(command, path);
				system(command);
				do{
					printf("\nPlease write the string you have seen on the screen here : ");
					fgets(input,512,stdin);
				}
				while(strlen(input) > 36);
				char *res_msg = "IMG SEND Success!";
				imgAck = (IMG_ACK *)calloc(1,sizeof(IMG_ACK));
				imgAck->answer= (char*)calloc(1,strlen(input));
				imgAck->answerLength=strlen(input);
				imgAck->imgResult = R_SUCCESS;
				strcpy(imgAck->answer, input);
			}

			else
			{
				printf("\nReceived Image is NULL!\n");
				char *res_msg = "IMG SEND Fail!";
				imgAck = (IMG_ACK *)calloc(1, sizeof(IMG_ACK));
				imgAck->imgResult = R_FAIL;
				strcpy(imgAck->answer, input);
			}
			//Encoding Packet
			*dst_len = encode_packet(MT_IMG_ACK, (void *)imgAck, dst);
			printf("Sending... Image Ack Message to client\n");
			free(imgSend->img); free(imgSend); free(imgAck->answer); free(imgAck);
			rv = 0;
			break;
		default:
			rv = -1;
			break;
	}

	return rv;
}


