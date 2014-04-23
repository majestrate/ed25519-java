#define CRYPTO_BYTES 64
#define CRYPTO_STATEBYTES 64
#define CRYPTO_BLOCKBYTES 128

extern int crypto_hash(unsigned char *out,const unsigned char *in,unsigned long long inlen);
#define crypto_hash_sha512 crypto_hash
