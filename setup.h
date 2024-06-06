#ifndef SETUP_H
#define SETUP_H

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

char* username_input(int len);

char* salt_gen(uint8_t* salt, int len);

char* pwd_verifier(uint8_t* salt, int len, char* password);


#endif
