CC := g++
CLFAGS :=
LDFLAGS :=

dir_common = ../common

default_flag = -lcrypto

ssl_flag = $(default_flag) -w -lssl -DcsecSSL

COMMON_SRC = $(dir_common)/codec.c

SERVER_SRC = server.c packet_controller.c

.SUFFIXES: .c .o

all : server ssl_server

server : $(SERVER_SRC) $(COMMON_SRC)
	gcc -g -o $@ $^ -I$(dir_common) $(default_flag)

ssl_server : $(SERVER_SRC) $(COMMON_SRC)
	gcc -g -o $@ $^ -I$(dir_common) $(ssl_flag)

clean : 
	rm -f server ssl_server *.jpg


