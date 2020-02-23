CC := g++
CLFAGS :=
LDFLAGS :=

dir_common = ../common

default_flag = -lcrypto

ssl_flag = $(default_flag) -lssl -DcsecSSL

COMMON_SRC = $(dir_common)/codec.c

CLIENT_SRC = client.c packet_controller.c

.SUFFIXES: .c .o

all : client ssl_client

client : $(CLIENT_SRC) $(COMMON_SRC)
	gcc -g -o $@ $^ -I$(dir_common) $(default_flag)

ssl_client : $(CLIENT_SRC) $(COMMON_SRC)
	gcc -g -o $@ $^ -I$(dir_common) $(ssl_flag)

clean : 
	rm -f client ssl_client



