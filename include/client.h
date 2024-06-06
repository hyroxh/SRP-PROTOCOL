#ifndef CLIENT_H
#define CLIENT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#define PORT 8080

void sending(int* client_fd, char* message);

char* reading(int* client_fd);

int connection(int* status, int* client_fd, struct sockaddr_in* pserv_addr);


#endif
