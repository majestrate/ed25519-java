extern "C" { 
#include "ref10/ref10.h"
}

#include <array>
#include <iostream>
#include <iomanip>
#include <string.h>

#define MSGLEN 24


typedef std::array<unsigned char, 32> seed_t;
typedef std::array<unsigned char, MSGLEN> message_t;
typedef std::array<unsigned char, MSGLEN+CRYPTO_BYTES> signed_message_t;
typedef std::array<unsigned char, CRYPTO_SECRETKEYBYTES> secret_key_t;
typedef std::array<unsigned char, CRYPTO_PUBLICKEYBYTES> public_key_t;

void print_buffer(std::ostream & os, uint8_t * data, uint32_t dlen)
{
    os << std::to_string(dlen) << " bytes: ";
    // os << std::setiosflags(std::ios_base::hex |  std::ios_base::showbase);
    while ( dlen-- ) {
        os << std::hex << std::setfill('0') << std::setw(2) << (int)*data++;
    }
}

int main(int argc, char *argv[])
{
    message_t message;
    std::string msg = "This is a secret message";
    memcpy(message.data(),msg.c_str(), message.size());
    
    signed_message_t signed_message;
    signed_message.fill(0);

    secret_key_t sk;
    sk.fill(0);
    
    public_key_t pk;
    pk.fill(0);

    seed_t seed;
    seed.fill(0);

    std::cout << "seed\t= ";
    print_buffer(std::cout, seed.data(), seed.size());

    if ( ed25519_pubkey(pk.data(), sk.data(), seed.data()) ) { std::cout << "failed" << std::endl; return -1; }
    std::cout << std::endl << "pk\t= ";
    print_buffer(std::cout, pk.data(), pk.size());

    std::cout << std::endl << "sk\t= ";
    print_buffer(std::cout, sk.data(), sk.size());

    std::cout << std::endl;

    unsigned long long smsglen = 0;

    //std::cout << "signing message of length " << std::to_string(message.size()) << " ...";

    auto result = ed25519_sign(signed_message.data(), &smsglen,
                               message.data(), message.size(),
                               sk.data());

    if ( result == -1 ) { std::cout << "failed to sign" << std::endl; return -1; }
    //std::cout << "signed, signed message is " << std::to_string(smsglen) << " bytes" << std::endl;
    
    std::cout << "sig\t= ";
    print_buffer(std::cout, signed_message.data(), CRYPTO_BYTES);
   
    message_t message2;
    message2.fill(0);

    unsigned long long newmsglen = 0;

    result = ed25519_open(message2.data(),&newmsglen,
                          signed_message.data(), smsglen,
                          pk.data());
   
    if ( result == -1 ) { std::cout << std::endl << "verify failed" << std::endl; return -1; }
    
}
