#include "argon2.h"
#include "setup.h"

static void uint8_t_to_mpz_t(mpz_t rop, uint8_t* arr, int len, int radix) // len - length of arr, radix - number of digits for arr[i]
{
	int base = 1;
	
	for(int i = 1; i <= radix; i++)
	{
		base = base * 16;
	}
	
	for(int i = 0; i < len; i++)
	{
		mpz_mul_ui(rop, rop, base);
		mpz_add_ui(rop, rop, arr[i]);
	}
}

static void argon2i_to_mpz_t(mpz_t rop, char* str)
{
	uint8_t* pwd = (uint8_t*)strdup(str);
	uint32_t pwdlen = strlen((char*)pwd);
	
	uint8_t hash[HASHLEN];
	argon2i_hash_raw(t_cost, m_cost, parallelism, pwd, pwdlen, const_salt, SALTLEN, hash, HASHLEN);
	
	uint8_t_to_mpz_t(rop, hash, HASHLEN, 2);
	
	free(pwd);
}


char* username_input(int len)
{
	printf("Enter your username:\n");
	
	char* result = (char*)calloc(len+1, sizeof(char));
	fgets(result, len, stdin);
	
	return result; 
}       

char* salt_gen(uint8_t* salt, int len) //fills uint8_t array with random values (0-255) and returns the equivalent string, written in hex
{
	//filling uint8_t salt with random values (0-255)
	FILE* f;
	f = fopen("/dev/random", "r"); 
	
	for(int i = 0; i < len ; i++)
	{
		int a = 0;
		fread(&a, 1, 1, f);
		a = a%256;
		*(salt + i) = a;
	}

	fclose(f);
	
	//converting to mpz_t
	mpz_t mysalt;
	mpz_init(mysalt);
	uint8_t_to_mpz_t(mysalt, salt, len, 2);
	
	//converting to char*
	char* result = mpz_get_str(NULL, 16, mysalt);
	
	//freeing space
	mpz_clear(mysalt);
	f = NULL;
	
	return result;
	
}

char* pwd_verifier(uint8_t* salt, int len, char* password) // H(salt | password)
{
	uint8_t hash[HASHLEN];
	
	//For the purposes of SRP algorithm, salt must be appended directly to password;
	//We use const_salt = {00} for the respective position in the argon2 function 
	
	mpz_t mysalt;
	mpz_init(mysalt);
	uint8_t_to_mpz_t(mysalt, salt, len, 2);
	
	char* salt_password = mpz_get_str(NULL, 16, mysalt);
	salt_password = (char*)realloc(salt_password, strlen(salt_password) + strlen(password) + 1);
	strcat(salt_password, password);
	
	uint8_t *pwd = (uint8_t*)strdup(salt_password);
	uint32_t pwdlen = strlen((char*)pwd);
	
	mpz_clear(mysalt);
	
	argon2i_hash_raw(t_cost, m_cost, parallelism, pwd, pwdlen, const_salt, SALTLEN, hash, HASHLEN);
	
	//For the purposes of this algorithm, salt must be appended directly to password; 
	
	//initialization
	mpz_t myhash, prime, verifier;
	mpz_inits(myhash, prime, verifier, NULL);
	
	//assignment
	uint8_t_to_mpz_t(myhash, hash, HASHLEN, 2); //myhash
	mpz_set_str(prime, group_prime, 16); //prime
	mpz_set_ui(verifier, group_gen); //verifier
	
	//computing v = g^x mod p
	mpz_powm_sec(verifier, verifier, myhash, prime);
	
	//generating string
	char* result = mpz_get_str(NULL, 16, verifier);
	
	//freeing allocated space
	mpz_clears(myhash, prime, verifier, NULL);
	free(pwd);
	free(salt_password);
	
	//return
	return result;
}

