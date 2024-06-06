#include "argon2.h"
#include "verifier.h"

void uint8_t_to_mpz_t(mpz_t rop, uint8_t* arr, int len, int radix) // len - length of arr, radix - number of digits for arr[i]
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

void argon2i_to_mpz_t(mpz_t rop, char* str)
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

Generating a random number b and computing B = kv + g^b


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

char* B_num(mpz_t rop, char* strver, char* strb) 
{
	//Initializing
	mpz_t k, v, gen, b, prime, left, right;
	mpz_inits(k, v, gen, b, prime, left, right, NULL);
	
	//Assigning
	mpz_set_ui(k, 3);
	mpz_set_str(v, strver, 16);
	mpz_set_ui(gen, group_gen);
	mpz_set_str(b, strb, 16);
	mpz_set_str(prime, group_prime, 16);
	
	//left = k*v
	mpz_mul(left, k, v);
	mpz_tdiv_r(left, left, prime); //k*v mod p
	
	//right = g^b
	mpz_powm_sec(right, gen, b, prime); //g^b mod p
	
	mpz_add(rop, left, right); //k*v + g^b
	mpz_tdiv_r(rop, rop, prime); //(k*v + g^b) mod p
	
	//freeing memory
	mpz_clears(k, v, gen, b, prime, left, right, NULL);
	
	//returning string
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
	
	//hash
	argon2i_to_mpz_t(rop, str);
	
	//freeing allocated space
	free(str);
	
	//returning string
	char* result = mpz_get_str(NULL, 16, rop);
	return result;
}

/*

Round III.

Generating S and K, where

S = (Av^u) ^ b
K = H(S) 

*/

char* S_num(mpz_t rop, char* strA, char* strver, char* stru, char* strb)
{
	//Initializing
	mpz_t A, v, u, b, prime;
	mpz_inits(A, v, u, b, prime, NULL);
	
	//Assigning
	mpz_set_str(A, strA, 16);
	mpz_set_str(v, strver, 16);
	mpz_set_str(u, stru, 16);
	mpz_set_str(b, strb, 16);
	mpz_set_str(prime, group_prime, 16);
	
	//Computing rop
	mpz_powm_sec(rop, v, u, prime); //v^u mod p
	mpz_mul(rop, A, rop); //A*v^u
	mpz_tdiv_r(rop, rop, prime); //A*v^u mod p
	mpz_powm_sec(rop, rop, b, prime); // (A*v^u)^b mod p 
	
	//freeing memory
	mpz_clears(A, v, u, b, prime, NULL);
	
	//returning result
	char* result = mpz_get_str(NULL, 16, rop);
	return result;
}

char* K_num (mpz_t rop, char* strS)
{
	//hash
	argon2i_to_mpz_t(rop, strS);
	
	//returning string
	char* result = mpz_get_str(NULL, 16, rop);
	return result;
}

/*

Round IV

Computing M, where

M := H(H(p) xor H(g), H(I), s, A, B, K)

Computing R = H(A, M, K)


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



