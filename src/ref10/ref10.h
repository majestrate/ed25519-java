#ifndef REF10_H__
#define REF10_H__
#include "api.h"


#define curve25519_sign crypto_sign
#define curve25519_open crypto_sign_open
#define curve25519_pubkey crypto_sign_keypair

int crypto_sign_open(
  unsigned char *m,unsigned long long *mlen,
  const unsigned char *sm,unsigned long long smlen,
  const unsigned char *pk
);

int crypto_sign(
  unsigned char *sm,unsigned long long *smlen,
  const unsigned char *m,unsigned long long mlen,
  const unsigned char *sk
);


int crypto_sign_keypair(unsigned char *pk,unsigned char *sk);


#endif
