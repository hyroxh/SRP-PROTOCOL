#include "prover.h"
#include "argon2.h"

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

/*

Round I.

Generating a random number a and computing A = g^a mod p 

*/

char* rnum_gen(mpz_t rop)
{
	//Establishing a seed
	FILE* f;
	f = fopen("/dev/random", "r"); 
	
	unsigned long int seed = 0;
	fread(&seed, sizeof(unsigned long int), 1, f);

	fclose(f);
	
	f = NULL;

	//Assigning the prime
	mpz_t prime;
	mpz_init(prime);
	mpz_set_str(prime, group_prime, 16);
	
	//Setting a state
	gmp_randstate_t state;
	gmp_randinit_mt(state);
	gmp_randseed_ui(state, seed);
	
	//Getting a random number in the range 0,...,p-1
	mpz_urandomm(rop, state, prime);
	
	//Freeing memory
	mpz_clear(prime);
	gmp_randclear(state);
	
	//returning the value
	char* result = mpz_get_str(NULL, 16, rop);
	return result;
}

char* A_num(mpz_t rop, char* stra) // A = g^a mod p
{
	//Assigning the prime
	mpz_t prime;
	mpz_init(prime);
	mpz_set_str(prime, group_prime, 16);
	
	//Assigning a
	mpz_t a;
	mpz_init(a);
	mpz_set_str(a, stra, 16);
	
	//Generating A = g ^ a mod p;
	mpz_t gen;
	mpz_init_set_ui(gen, group_gen);
	mpz_powm_sec(rop, gen, a, prime);
	
	//freeing memory
	mpz_clears(prime, a, gen, NULL);
	
	//returning a corresponding string
	char* result = mpz_get_str(NULL, 16, rop);
	return result;
}

/*

Round II.

Given A and B, generate u = H(A, B);

*/

char* u_num(mpz_t rop, char* strA, char* strB)
{
	char* str = (char*)calloc(strlen(strA) + strlen(strB) + 1, sizeof(char));
	strcat(str, strA);
	strcat(str, strB);
	
	argon2i_to_mpz_t(rop, str);
	
	//freeing allocated space
	free(str);
	
	//returning string
	char* result = mpz_get_str(NULL, 16, rop);
	return result;
}

/*

Round III.

Generating x, S, K, where:
  
x = H(s, p)                 (user enters password)
S = (B - kg^x) ^ (a + ux)   (computes session key) //k = 3 or k = H(N, g)
K = H(S)

*/

char* x_num (mpz_t rop, char* salt, char* password)
{
	char* str = (char*)calloc(strlen(salt) + strlen(password) + 1, sizeof(char));
	//str = strcat(salt, password);
	strcat(str, salt);
	strcat(str, password);
	
	/*
	uint8_t *pwd = (uint8_t*)strdup(str);
	uint32_t pwdlen = strlen((char*)pwd);
	
	uint8_t hash[HASHLEN];
	argon2i_hash_raw(t_cost, m_cost, parallelism, pwd, pwdlen, const_salt, SALTLEN, hash, HASHLEN);
	
	uint8_t_to_mpz_t(rop, hash, HASHLEN, 2);
	*/
	
	argon2i_to_mpz_t(rop, str);
	
	//freeing allocated space
	free(str);
	//free(pwd);
	
	//returning string
	char* result = mpz_get_str(NULL, 16, rop);
	return result;
}

char* S_num (mpz_t rop, char* strB, char* strx, char* stra, char* stru)
{
	//initializing
	mpz_t B, x, a, u, k, left, right; //left = B - k*g^x; right = a + u*x
	mpz_inits(B, x, a, u, k, left, right, NULL);
	
	//assigning
	mpz_set_str(B, strB, 16);
	mpz_set_str(x, strx, 16);
	mpz_set_str(a, stra, 16);
	mpz_set_str(u, stru, 16);
	mpz_set_ui(k, 3);
	
	//Assigning the prime
	mpz_t prime;
	mpz_init(prime);
	mpz_set_str(prime, group_prime, 16);
	
	//Assigning the generator
	mpz_t gen;
	mpz_init_set_ui(gen, group_gen);
	
	//left = B - k*g^x;
	mpz_powm_sec(left, gen, x, prime); //g^x mod p
	mpz_mul(left, k, left); //k*g^x
	mpz_sub(left, B, left); //B - k*g^x;
	
	mpz_tdiv_r(left, left, prime); //(B-k*g^x) mod p
	
	//right = a + u*x;
	mpz_mul(right, u, x); //u*x
	mpz_add(right, a, right); //a + u*x
	
	mpz_tdiv_r(right, right, prime); //(a+u*x) mod p
	
	//S = (B-kg^x)^(a+u*x) mod p
	mpz_powm_sec(rop, left, right, prime);
	
	//freeing memory
	mpz_clears(B, x, a, u, k, left, right, prime, gen, NULL);
	
	char* result = mpz_get_str(NULL, 16, rop);
	return result;
}

char* K_num (mpz_t rop, char* strS)
{
	/*
	uint8_t *pwd = (uint8_t*)strdup(strS);
	uint32_t pwdlen = strlen((char*)pwd);
	
	uint8_t hash[HASHLEN];
	argon2i_hash_raw(t_cost, m_cost, parallelism, pwd, pwdlen, const_salt, SALTLEN, hash, HASHLEN);
	
	uint8_t_to_mpz_t(rop, hash, HASHLEN, 2);
	*/
	
	argon2i_to_mpz_t(rop, strS);
	
	//freeing allocated space
	//free(pwd);
	
	//returning string
	char* result = mpz_get_str(NULL, 16, rop);
	return result;
}

/*

Round IV.

Computing M, where

M := H(H(p) xor H(g), H(I), s, A, B, K)

R := H(A, M, K)

*/

char* M_num(mpz_t rop, char* strI, char* strs, char* strA, char* strB, char* strK)
{
	//Initialization
	mpz_t hashp, prime, hashg, gen, hashxor, hashI, s, A, B, K;
	mpz_inits(hashp, prime, hashg, gen, hashxor, hashI, s, A, B, K, NULL);
	
	//setting p and g (aka prime and gen) and obtaining corresponding strings
	mpz_set_str(prime, group_prime, 16);
	mpz_set_ui(gen, group_gen);
	char* strp = mpz_get_str(NULL, 16, prime);
	char* strg = mpz_get_str(NULL, 16, gen);
	
	//hashing functions 
	argon2i_to_mpz_t(hashp, strp);
	argon2i_to_mpz_t(hashg, strg);
	argon2i_to_mpz_t(hashI, strI);
	
	//xor
	mpz_xor(hashxor, hashp, hashg);
	
	//getting strings
	char* strhashxor = mpz_get_str(NULL, 16, hashxor);
	char* strhashI = mpz_get_str(NULL, 16, hashI);
	
	//strcat
	char* str = (char*)calloc(strlen(strhashxor) + strlen(strhashI) + strlen(strs) + strlen(strA) + strlen(strB) + strlen(strK) + 1, sizeof(char));
	strcat(str, strhashxor);
	strcat(str, strhashI);
	strcat(str, strs);
	strcat(str, strA);
	strcat(str, strB);
	strcat(str, strK);
	
	//final hashing
	argon2i_to_mpz_t(rop, str);
	
	//freeing memory
	mpz_clears(hashp, prime, hashg, gen, hashxor, hashI, s, A, B, K, NULL);
	free(strp); 
	free(strg);
	free(strhashxor); 
	free(strhashI);
	free(str);
	
	//returning string
	char* result = mpz_get_str(NULL, 16, rop);
	return result;	
}

char* R_num(mpz_t rop, char* strA, char* strM, char* strK)
{
	char* str = (char*)calloc(strlen(strA) + strlen(strM) + strlen(strK) + 1, sizeof(char));
	strcat(str, strA);
	strcat(str, strM);
	strcat(str, strK);
	
	//hash
	argon2i_to_mpz_t(rop, str);
	
	//freeing memory
	free(str);
	
	//returning string
	char* result = mpz_get_str(NULL, 16, rop);
	return result;

}







