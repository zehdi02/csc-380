/* Diffie Hellman key exchange + HKDF */
#pragma once
#include <gmp.h>

/* convenience macros */
#define ISPRIME(x) mpz_probab_prime_p(x,10)
#define NEWZ(x) mpz_t x; mpz_init(x)
/* these will read/write integers from byte arrays where the
 * least significant byte is first (little endian bytewise). */
#define BYTES2Z(x,buf,len) mpz_import(x,len,-1,1,0,0,buf)
#define Z2BYTES(buf,len,x) mpz_export(buf,&len,-1,1,0,0,x)


extern mpz_t q; /** "small" prime; should be 256 bits or more */
extern mpz_t p; /** "large" prime; should be 2048 bits or more, with q|(p-1) */
extern mpz_t g; /** generator of the subgroup of order q */
extern size_t qBitlen; /** length of q in bits */
extern size_t pBitlen; /** length of p in bits */
extern size_t qLen; /** length of q in bytes */
extern size_t pLen; /** length of p in bytes */

/* NOTE: you must call init or initFromScratch before doing anything else. */
/** Try to read q,p,g from a file: */
int init(const char* fname);
/** Generate fresh Diffie Hellman parameters.  This is a somewhat
 * expensive computation, so it's best to save and reuse params.
 * Prints generated parameters to stdout. */
int initFromScratch(size_t qBitlen, size_t pBitlen);
/** set sk to a random exponent (this part is secret) and set
 * pk to g^(sk) mod p */
int dhGen(mpz_t sk, mpz_t pk);
/** given a secret (sk_mine say from dhGen above) and your friend's
 * public key (pk_yours), compute the diffie hellman value, and
 * apply a KDF to obtain buflen bytes of key, stored in keybuf */
int dhFinal(mpz_t sk_mine, mpz_t pk_mine, mpz_t pk_yours, unsigned char* keybuf, size_t buflen);
/* NOTE: pk_mine is included just to avoid recomputing it from sk_mine */
