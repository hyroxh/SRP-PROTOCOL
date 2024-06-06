/*

Sources:

https://datatracker.ietf.org/doc/html/draft-ietf-tls-srp-08
http://srp.stanford.edu/design.html

*/


#include "server.h"
#include "verifier.h"

const char* group_prime = "AC6BDB41 324A9A9B F166DE5E 1389582F AF72B665 1987EE07 FC319294 3DB56050 A37329CB B4A099ED 8193E075 7767A13D D52312AB 4B03310D CD7F48A9 DA04FD50 E8083969 EDB767B0 CF609517 9A163AB3 661A05FB D5FAAAE8 2918A996 2F0B93B8 55F97993 EC975EEA A80D740A DBF4FF74 7359D041 D5C33EA7 1D281E44 6B14773B CA97B43A 23FB8016 76BD207A 436C6481 F1D2B907 8717461A 5B9D32E6 88F87748 544523B5 24B0D57D 5EA77A27 75D2ECFA 032CFBDB F52FB378 61602790 04E57AE6 AF874E73 03CE5329 9CCC041C 7BC308D8 2A5698F3 A8D0C382 71AE35F8 E9DBFBB6 94B5C803 D89F7AE4 35DE236D 525F5475 9B65E372 FCD68EF2 0FA7111F 9E4AFF73";

const int group_gen = 2;

//setting const_salt
const uint8_t const_salt[SALTLEN] = {0};

//setting parameters
const uint32_t t_cost = 2;            // 2-pass computation
const uint32_t m_cost = (1<<16);      // 64 mebibytes memory usage
const uint32_t parallelism = 1;       // number of threads and lanes

typedef struct
{
	char username[20 + 1];
	char salt[2*SALTLEN + 1];
	char verifier[1024 + 1];

} UserRecord;

int setup(int* new_socket)
{
	/*
	
	The server receives a username.
	
	If the username already appears in the database, the server will not proceed with signing up, closing the connection
	
	If the username does not appear in the database, the server will record it, along with the corresponding salt and verifier value.
	
	
	*/

	//receiving a username
	char* strUser = reading(new_socket);
	
	//open file
	FILE* f;
	
	//creating the file, if it doesn't exist
	f = fopen("userdatabase.data", "a");
	fclose(f);
	
	f = fopen("userdatabase.data", "r");
	
	if(!f)
	{
		perror("Error reading file!");
		exit(EXIT_FAILURE);
	}
	
	
	for(int i = 0; ; i++)
	{
		if(feof(f))
		{
			sending(new_socket, "0"); //no matching username found
			break;
		}
		
		//Searching for the username in the database
		UserRecord user;	
			
		size_t read_size = fread(&user, sizeof(UserRecord), 1, f);
		
		if(strncmp(user.username, strUser, 20) == 0)
		{
			sending(new_socket, "1"); //matching username found
			free(strUser);
			fclose(f);
			return 0;
		}
		
		
	}
	
	fclose(f);
	
	//Writing the tuple in the database
	f = fopen("userdatabase.data", "a");
	if(!f)
	{
		perror("Error reading file!");
		exit(EXIT_FAILURE);
	}
	
	//writing data into a struct
	UserRecord new_user;
	
	char* salt = reading(new_socket);
	char* ver = reading(new_socket);
		
	memcpy(new_user.username, strUser, strlen(strUser) + 1);
	memcpy(new_user.salt, salt, strlen(salt) + 1);
	memcpy(new_user.verifier, ver, strlen(ver) + 1);
	
	//writing into the file
	fwrite(&new_user, sizeof(UserRecord), 1, f);
	
	//closing the file
	fclose(f);
	
	//console message
	printf("%s has just signed up!\n", strUser);
	
	//freeing memory
	free(strUser);
	free(salt);
	free(ver);
	
	return 1; //successfully written
	
	
}

int verification(int* new_socket)
{

	mpz_t prime;
	mpz_init(prime);
	mpz_set_str(prime, group_prime, 16);
	
	/*
	
	Round I.
	
	User -> Host: {username, A = g^a}
	Host -> User: {salt, B}
	
	*/
	
	char* strUser = reading(new_socket);
	char* strA = reading(new_socket);
	
	/*
	
	NB!!! EXIT CONDITION I. CHECK IF A == 0 mod p
	
	*/
			mpz_t A;
			mpz_init(A);
			mpz_set_str(A, strA, 16);
			
			mpz_tdiv_r(A, A, prime); // A <- A mod p
			if(mpz_cmp_ui(A, 0) == 0)
			{
				perror("Fatal Error!\n");
				exit(EXIT_FAILURE);
			}
	// -------------------------------------------
	
	char* strSalt = (char*)calloc(2*SALTLEN + 1, sizeof(char));
	char* strVerifier = (char*)calloc(1024 + 1, sizeof(char));
	
	//searching for the corresponding username
	FILE* f;
	
	f = fopen("userdatabase.data", "r");
	
	if(!f)
	{
		perror("Error reading file!");
		exit(EXIT_FAILURE);
	}
	
	//Searching for the username in the database
	UserRecord user;
	
	for(int i = 0; ; i++)
	{
		size_t read_size = fread(&user, sizeof(UserRecord), 1, f);
		
		if(strncmp(user.username, strUser, 20) == 0)
		{
			//matching username found
			memcpy(strSalt, user.salt, strlen(user.salt) + 1);
			memcpy(strVerifier, user.verifier, strlen(user.verifier) + 1);
			sending(new_socket, "y");
			break;
		}
		
		if(feof(f))
		{
			perror("No matching usernames!");
			sending(new_socket, "n");
			exit(EXIT_FAILURE);
		}
		
	}
	
	fclose(f);
	//computing b and B
	mpz_t b, B;
	mpz_inits(b, B, NULL);
	char* strb = rnum_gen(b);
	char* strB = B_num(B, strVerifier, strb);
	
	sending(new_socket, strSalt);
	sending(new_socket, strB);
	
	// -------------------------------------------------------------------
	
	/*
	
	Round II.
	
	u = H(A, B);
	
	*/
	
	mpz_t u;
	mpz_init(u);
	
	char* stru = u_num(u, strA, strB);
	
	
	/*
	
	Round III.
	
	S = (Av^u) ^ b;
	K = H(S);
	
	*/
	
	mpz_t S, K;
	mpz_inits(S, K, NULL);
	
	char* strS = S_num(S, strA, strVerifier, stru, strb);
	
	char* strK = K_num(K, strS);
	
	/*
	
	Round IV.
	
	Computing M and comparing it to received M.
	
	Computing R = H(A, M, K) and sending it to the client;

	*/
	
	mpz_t M;
	mpz_init(M);
	
	char* strM = M_num(M, strUser, strSalt, strA, strB, strK);
	
	char* strUserM = reading(new_socket);
	
	/*
	
	EXIT CONDITION II. CHECK IF M == USER_M. EXIT IF NOT
	
	*/
			
			if(strcmp(strM, strUserM) != 0)
			{
				printf("%s has entered a wrong password\n", strUser);
				sending(new_socket, "n");
				return 0;
			}
		
	
	// -------------------------------------------
	sending(new_socket, "y");
	
	mpz_t R;
	mpz_init(R);
	
	char* strR = R_num(R, strA, strM, strK);
	
	sending(new_socket, strR);
	
	printf("%s succesfully logged in!\n", strUser);
	
	sending(new_socket, "You're logged in!");
	
	//freeing memory
	mpz_clears(prime, A, b, B, u, S, K, M, R, NULL);
	free(strUser);
	free(strA);
	free(strSalt);
	free(strVerifier);
	free(strb);
	free(strB);
	free(stru);
	free(strS);
	free(strK);
	free(strM);
	free(strUserM);
	free(strR);
	
	return 1;
	
}

int main()
{
	int server_fd;
	int new_socket;
	ssize_t valread;
	struct sockaddr_in address;
	
	connection(&server_fd, &new_socket, &address);
	
	// ---------------------------------------------------------------------
	
	char* option = reading(&new_socket);
	if(*option == '1')
	{
		setup(&new_socket);
	}
	else
	{
		verification(&new_socket);
	}
	
	close(new_socket);
	close(server_fd);
	
	free(option);
	
	return 0;
}
