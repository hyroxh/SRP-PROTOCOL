#include "server.h"

void sending(int* client_fd, char* message)
{
	uint32_t len = htonl(strlen(message));
	send(*client_fd, &len, sizeof(len), 0); //sending length
	send(*client_fd, message, strlen(message), 0);//sending string
}

char* reading(int* client_fd)
{
	uint32_t len;
	recv(*client_fd, &len, sizeof(len), 0);
	len = ntohl(len);
	
	char* result = (char*)calloc(len + 1, sizeof(char));
	
	recv(*client_fd, result, len, 0);
	*(result + len) = '\0';
	
	return result;
}

void connection(int* server_fd, int* new_socket, struct sockaddr_in* address)
{
	int opt = 1;
	socklen_t addrlen = sizeof(*address);
	
	if ((*server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		perror("socket_failed");
		exit(EXIT_FAILURE);
	}
	
	if(setsockopt(*server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)))
	{
		perror("setsockopt");
		exit(EXIT_FAILURE);
	}
	
	address->sin_family = AF_INET;
	address->sin_addr.s_addr = INADDR_ANY;
	address->sin_port = htons(PORT);
	
	//Forcefull attaching socket to the port 8080
	if(bind(*server_fd, (struct sockaddr*)address, sizeof(*address)) < 0)
	{
		perror("bind failed");
		exit(EXIT_FAILURE);
	}
	
	if(listen(*server_fd, 3) < 0)
	{
		perror("listen");
		exit(EXIT_FAILURE);
	}
	
	if((*new_socket = accept(*server_fd, (struct sockaddr*)address, &addrlen)) < 0)
	{
		perror("accept");
		exit(EXIT_FAILURE);
	}	
	
}
