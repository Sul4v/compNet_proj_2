CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -g
LDFLAGS =

# Binaries
CLIENT_BIN = ftp_client
SERVER_BIN = ftp_server

# Source files
CLIENT_SRC = code/client_code/ftpcli.c
SERVER_SRC = code/server_code/ftpserv.c

# Object files
CLIENT_OBJS = $(CLIENT_SRC:.c=.o)
SERVER_OBJS = $(SERVER_SRC:.c=.o)

.PHONY: all clean client server

all: client server

client: $(CLIENT_BIN)

server: $(SERVER_BIN)

$(CLIENT_BIN): $(CLIENT_OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(SERVER_BIN): $(SERVER_OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# Rule to compile .c files to .o files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(CLIENT_BIN) $(SERVER_BIN) $(CLIENT_OBJS) $(SERVER_OBJS) core.* 