/*

Sources:

https://datatracker.ietf.org/doc/html/draft-ietf-tls-srp-08
http://srp.stanford.edu/design.html

*/


#include "client.h"
#include "setup.h"
#include "prover.h"

const char* group_prime = "AC6BDB41 324A9A9B F166DE5E 1389582F AF72B665 1987EE07 FC319294 3DB56050 A37329CB B4A099ED 8193E075 7767A13D D52312AB 4B03310D CD7F48A9 DA04FD50 E8083969 EDB767B0 CF609517 9A163AB3 661A05FB D5FAAAE8 2918A996 2F0B93B8 55F97993 EC975EEA A80D740A DBF4FF74 7359D041 D5C33EA7 1D281E44 6B14773B CA97B43A 23FB8016 76BD207A 436C6481 F1D2B907 8717461A 5B9D32E6 88F87748 544523B5 24B0D57D 5EA77A27 75D2ECFA 032CFBDB F52FB378 61602790 04E57AE6 AF874E73 03CE5329 9CCC041C 7BC308D8 2A5698F3 A8D0C382 71AE35F8 E9DBFBB6 94B5C803 D89F7AE4 35DE236D 525F5475 9B65E372 FCD68EF2 0FA7111F 9E4AFF73";

const int group_gen = 2;

//setting const_salt
const uint8_t const_salt[SALTLEN] = {0};

//setting parameters
const uint32_t t_cost = 2;            // 2-pass computation
const uint32_t m_cost = (1<<16);      // 64 mebibytes memory usage
const uint32_t parallelism = 1;       // number of threads and lanes

int setup(int* client_fd)
{

	/*
	
	The client sends a username.
	
	If the username already appears in the database, the server will not proceed with signing up, closing the connection
	
	If the username does not appear in the database, the server will record it, along with the corresponding salt and verifier value.
	
	*/

	//entering the username
	printf("Enter your username:\n");
	char myusername[20];
	scanf("%99s", myusername);
	sending(client_fd, myusername);
	
	//response from the server
	char* response = reading(client_fd);
	if(*response == '1')
	{
		printf("This username already exists. Please log in\n");
		return 0;
	}
	
	uint8_t salt[SALTLEN];
	char* mysalt = salt_gen(salt, SALTLEN);
	
	//entering the password
	printf("Enter your password:\n");
	char mypassword[20];
	scanf("%99s", mypassword);
	
	char* myver = pwd_verifier(salt, SALTLEN, mypassword);
	
	//sending salt and v
	sending(client_fd, mysalt);
	sending(client_fd, myver);
	
	//freeing memory
	free(mysalt);
	free(myver);
	
	return 1;

}

int proof(int* client_fd)
{

	mpz_t prime;
	mpz_init(prime);
	mpz_set_str(prime, group_prime, 16);
	
	/*
	
	Round I.
	
	User -> Host: {username, A = g^a}
	Host -> User: {salt, B}
	
	*/	
	printf("Enter your username:\n");
	char myusername[20];
	scanf("%99s", myusername);
	
	mpz_t a, A;
	mpz_inits(a, A, NULL);
	char* stra = rnum_gen(a);
	char* strA = A_num(A, stra);
	
	sending(client_fd, myusername);
	sending(client_fd, strA);
	
	char* existUser = reading(client_fd);
	if(strcmp(existUser, "n") == 0)
	{
		printf("User doesn't exist!\n");
		exit(EXIT_FAILURE);
	}
	
	
	char* getsalt = reading(client_fd);
	char* strB = reading(client_fd);
	
	/*
	
	NB!!! EXIT CONDITION I. CHECK IF B == 0 mod p 
	
	*/
			
			mpz_t B;
			mpz_init(B);
			mpz_set_str(B, strB, 16);
			
			mpz_tdiv_r(B, B, prime); // B mod p
			if(mpz_cmp_ui(B, 0) == 0)
			{
				perror("Fatal Error!\n");
				exit(EXIT_FAILURE);
			}
	
	// -------------------------------------------
	
	
	/*
	
	Round II.
	
	u = H(A, B);
	
	*/
	
	mpz_t u;
	mpz_init(u);
	
	char* stru = u_num(u, strA, strB);
	
	/*
	
	NB!!! EXIT CONDITION II. CHECK IF u == 0
	
	*/
			if(mpz_cmp_ui(u, 0) == 0)
			{
				printf("Fatal Error!\n");
				exit(EXIT_FAILURE);
			}
	
	// -------------------------------------------
	
	/*
	
	Round III.
	
	x = H(salt, password);
	S = (B - kg^x) ^ (a + ux);
	K = H(S);
	
	*/
	printf("Enter your password:\n");
	char mypassword[20];
	scanf("%99s", mypassword);
	
	mpz_t x, S, K;
	mpz_inits(x, S, K, NULL);
	
	char* strx = x_num(x, getsalt, mypassword);
	char* strS = S_num(S, strB, strx, stra, stru);
	char* strK = K_num(K, strS);
	
	/*
	
	Round IV.
	
	M = H(H(N) xor H(g), H(I), s, A, B, K)
	
	R = H(A, M, K)
	
	*/
	mpz_t M;
	mpz_init(M);
	
	char* strM = M_num(M, myusername, getsalt, strA, strB, strK);
	
	sending(client_fd, strM); 
	
	char* server_decision = reading(client_fd);
	
	if(strcmp(server_decision, "n") == 0)
	{
		printf("Wrong password!\n");
		exit(EXIT_FAILURE);
	}
	
	mpz_t R;
	mpz_init(R);
	
	char* strR = R_num(R, strA, strM, strK);
	
	char* strHostR = reading(client_fd);
	
	if(strcmp(strR, strHostR) != 0)
	{
		printf("Server is invalid. Fatal Error!\n");
		exit(EXIT_FAILURE);
	}
	
	char* mess = reading(client_fd);
	printf("%s\n", mess);
	
	
	//freeing memory
	mpz_clears(prime, a, A, u, x, S, K, M, R, NULL);
	free(stra);
	free(strA);
	free(existUser);
	free(getsalt);
	free(strB);
	free(stru);
	free(strx);
	free(strS);
	free(strK);
	free(strM);
	free(server_decision);
	free(strR);
	free(strHostR);
	free(mess);
	
	return 1;
	
	
}

int main()
{
	//Establishing the connection
	int status = 0;
	ssize_t valread = 0; 
	int client_fd = 0;;
	struct sockaddr_in serv_addr;
	
	if(connection(&status, &client_fd, &serv_addr) != 1)
	{
		return 0;
	}
	
	printf("Connection Established!\n");
	printf("Greetings! Please choose an option:\n");
	printf("Press 1 to sign up\n");
	printf("Press 2 to log in\n");
	
	char option[1];
	scanf("%99s", option);
	
	sending(&client_fd, option);
	
	if(option[0] == '1')
	{
		setup(&client_fd);
	}
	else if(option[0] == '2')
	{
		proof(&client_fd);
	}
	else
	{
		printf("Input is invalid!\n");
	}
	close(client_fd);
	return 0;
		
}
