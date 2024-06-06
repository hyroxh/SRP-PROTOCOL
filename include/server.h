#ifndef SERVER_H
#define SERVER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#define PORT 8080

void sending(int* client_fd, char* message);

char* reading(int* client_fd);

void connection(int* server_fd, int* new_socket, struct sockaddr_in* address);

#endif
