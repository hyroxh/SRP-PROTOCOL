#ifndef PROVER_H
#define PROVER_H

#include <gmp.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>

#define HASHLEN 32
#define SALTLEN 16

extern const char* group_prime;

extern const int group_gen;

extern const uint8_t const_salt[SALTLEN];

//setting parameters
extern const uint32_t t_cost;
extern const uint32_t m_cost;
extern const uint32_t parallelism;

static void uint8_t_to_mpz_t(mpz_t rop, uint8_t* arr, int len, int radix);
static void argon2i_to_mpz_t(mpz_t rop, char* str);

char* rnum_gen(mpz_t rop);

char* A_num(mpz_t rop, char* stra);

char* u_num(mpz_t rop, char* strA, char* strB);

char* x_num (mpz_t rop, char* salt, char* password);

char* S_num (mpz_t rop, char* strB, char* strx, char* stra, char* stru);

char* K_num (mpz_t rop, char* strS);

char* M_num(mpz_t rop, char* strI, char* strs, char* strA, char* strB, char* strK);

char* R_num(mpz_t rop, char* strA, char* strM, char* strK);


#endif
