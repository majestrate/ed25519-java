/*
 * JNI Wrapper for nacl ref10 implementation of curve 25519 
 *
 * I seriously hope I did this all right, probably didn't
 * there's probably a lot of holes please correct any you find
 *
 */
#include "Curve25519.h"

extern "C" {
#include "ref10/ref10.h"
}

#include <cstdint>
#include <string.h>

JNIEXPORT jint JNICALL Java_Curve25519__1sig_1length
(JNIEnv *, jclass) { return CRYPTO_BYTES; }


JNIEXPORT jint JNICALL Java_Curve25519__1pubkey_1length
(JNIEnv * env, jclass cls) { return CRYPTO_PUBLICKEYBYTES; }

JNIEXPORT jint JNICALL Java_Curve25519__1seckey_1length
(JNIEnv * env, jclass cls) { return CRYPTO_SECRETKEYBYTES; }

JNIEXPORT jbyteArray JNICALL Java_Curve25519__1crypto_1sign
(JNIEnv * env, jclass cls, jbyteArray j_msg, jbyteArray j_sk)
{
    // get parameters
    jboolean b;
    jbyte * jmsg = env->GetByteArrayElements(j_msg, &b);
    jbyte * jsk = env->GetByteArrayElements(j_sk, &b);

    jsize msglen = env->GetArrayLength(j_msg);

    // signed message + signed message length
    unsigned char sm[msglen + CRYPTO_BYTES];
    unsigned long long smlen;

    // we're going to assume the jvm doesn't give us the wrong size
    unsigned char msg[msglen];
    memcpy(msg, jmsg, msglen);

    unsigned char sk[CRYPTO_SECRETKEYBYTES];
    
    memcpy(sk, jsk, CRYPTO_SECRETKEYBYTES);


    // sign
    // this function's behavior is completely deterministic, except when it's not
    curve25519_sign(sm, &smlen,
                    msg, msglen, 
                    sk); 
    

    // allocate and copy in signature 
    jbyteArray j_sig = env->NewByteArray(CRYPTO_BYTES);
    jbyte _sig[CRYPTO_BYTES];
    memcpy(_sig, sm, CRYPTO_BYTES);

    env->SetByteArrayRegion(j_sig, 0, CRYPTO_BYTES, _sig); 

    // release parameters
    env->ReleaseByteArrayElements(j_msg, jmsg, 0);
    env->ReleaseByteArrayElements(j_sk, jsk, 0);

    return j_sig;
}

JNIEXPORT jboolean JNICALL Java_Curve25519__1crypto_1verify
(JNIEnv * env, jclass cls, jbyteArray j_sig, jbyteArray j_msg, jbyteArray j_pk)
{
    jboolean valid;
    valid = JNI_FALSE;

    jboolean b;
    jbyte * jmsg = env->GetByteArrayElements(j_msg, &b);
    jbyte * jpk = env->GetByteArrayElements(j_pk, &b);
    jbyte * jsig = env->GetByteArrayElements(j_sig, &b);

    jsize jmsglen = env->GetArrayLength(j_msg);

    unsigned long long ind;

    unsigned long long smlen = CRYPTO_BYTES + jmsglen;
    unsigned char sm[smlen];
    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    
    memcpy(pk, jpk, CRYPTO_PUBLICKEYBYTES);


    memcpy(sm, jsig, CRYPTO_BYTES);
    memcpy(sm+CRYPTO_BYTES, jmsg, jmsglen);


    unsigned char msg[jmsglen];

    unsigned long long msglen;


    // check for valid signature
    // behavior is also totally deterministic except when it's not
    if ( curve25519_open(msg, &msglen, sm, smlen, pk) == 0 ) { 
        if ( msglen == jmsglen ) {
            valid = JNI_TRUE;
            for ( ind = 0 ; ind < msglen ; ++ind ) {
                if ( msg[ind] !=  jmsg[ind]) { valid = JNI_FALSE; break; }
            }
        }
    } else {
        printf("ex");
        // TODO throw exception         
    }
    return valid;
}

JNIEXPORT jbyteArray JNICALL Java_Curve25519_publickey
(JNIEnv * env, jclass cls, jbyteArray j_sk)
{
    jboolean b;
    jbyte * jsk = env->GetByteArrayElements(j_sk, &b);
    
    jsize sksize = env->GetArrayLength(j_sk);

    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[sksize];

    memcpy(sk, jsk, sksize);
    
    curve25519_pubkey(pk, sk);
    
    env->ReleaseByteArrayElements(j_sk, jsk, 1);
    
    jbyteArray j_pk = env->NewByteArray(CRYPTO_PUBLICKEYBYTES);
    jbyte _pk[CRYPTO_PUBLICKEYBYTES];
 
    memcpy(_pk, pk, CRYPTO_PUBLICKEYBYTES);   

    env->SetByteArrayRegion(j_pk, 0, CRYPTO_PUBLICKEYBYTES, _pk);
    return j_pk;
}
