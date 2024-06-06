#include "client.h"

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

int connection(int* status, int* client_fd, struct sockaddr_in* pserv_addr)
{
	*client_fd = socket(AF_INET, SOCK_STREAM, 0);
	if(client_fd < 0)
	{
		printf("\nSocket creation error\n");
		return -1;
	}
	
	pserv_addr->sin_family = AF_INET;
	pserv_addr->sin_port = htons(PORT);
	
	if(inet_pton(AF_INET, "127.0.0.1", &(pserv_addr->sin_addr)) <= 0)
	{
		printf("\nInvalid address / Address not supported\n");
		return -1;
	}
	
	*status = connect(*client_fd, (struct sockaddr*)pserv_addr, sizeof(*pserv_addr));
	if(*status < 0)
	{
		printf("\nConnection Failed\n");
		return -1;
	}
	
	return 1;
}

