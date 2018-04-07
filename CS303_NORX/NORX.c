/******************************************************************************
*                                                                             *
* File -> NORX.c                                                              *
* Purpose -> Encrypt and Decrypt text using the NORX algorithm                *
* Author -> Joseph Kroeker                                                    *
* Version -> 1.0 03/10/2018 - Setting Up Core Permutation (3 hours)           *
*            2.0 03/11/2018 - Adding High Level Prototypes/Functions and      *
*                              calls in main functions (3 hours)               *
*                                                                             *
******************************************************************************/

//*****************************************************************************
// Flag for 32 Bit Words
//*****************************************************************************
#define WORD_32

//*****************************************************************************
// Includes
//*****************************************************************************
#include <stdbool.h>   // bool types
#include <stdint.h>    // uintXX_t types

#include "NORX.h"      // NORX defines and prototypes

//*****************************************************************************
//
// Function -> NORXEnc
// Purpose -> Run all steps needed to complete a full NORX encryption
// Inputs -> nkey_t K - Key value
//           nonce_t N - Nonce value
//           word_t A[] - Message Header
//           word_t M[] - Message Text 
//           word_t Z[] - Message Footer
//
//*****************************************************************************
void 
NORXEnc(word_t K[4], nonce_t N, word_t A[], word_t M[], word_t Z[]) {
    word_t S[16] = { 0 }    // State, 4x4 matrix of words
    word_t Sbar[16] ={ 0 }  // State bar, 4x4 matrix of words

    initialise(&K, &N, &S);
    absorb(&S, &A, 0x01);
    branch(&S, &Sbar, sizeof(M), 0x10);
    encyrpt(&Sbar, &M, , 0x02);
    merge(&Sbar, sizeof(M), 0x20);
    absorb(&S, &Z, 0x04);
    finalise(&S, &K, 0x08);
}

//*****************************************************************************
//
// Function -> NORXDec
// Purpose -> Run all steps needed to complete a full NORX decryption
// Inputs -> nkey_t K - Key value
//           nonce_t N - Nonce value
//           word_t A[] - Message Header
//           word_t C[] - Cipher text 
//           word_t Z[] - Message Footer
//           tag_t T - Hash Value from Encryption
//
//*****************************************************************************
void 
NORXDec(word_t K[4], nonce_t N, word_t A[], word_t C[], word_t Z[], tag_t T) {
    word_t S[16] = { 0 }    // State, 4x4 matrix of words
    word_t Sbar[16] ={ 0 }  // State bar, 4x4 matrix of words

    initialise(&K, &N, &S);
    absorb(&S, &A, 0x01);
    branch(&S, &Sbar, sizeof(M), 0x10);
    decrypt(&Sbar, &M, , 0x02);
    merge(&Sbar, sizeof(M), 0x20);
    absorb(&S, &Z, 0x04);
    finalise(&S, &K, 0x08);
}

//*****************************************************************************
//
// Function -> initialise
// Purpose -> 
// Inputs -> word_t* pwKIni - Key value
//           word_t* pwNIni - Nonce value
//           word_t* pwSIni[] - Pointer to State, 4x4 matrix of words
//
//*****************************************************************************
void
initialise(word_t* pwKIni[4], word_t* pwNIni[4], word_t* pwSIni[16]) {
    S = {N[0], N[1], N[2], N[3], K[0], K[1], K[2], K[3], 
    	 U8, U9, U10, U11, U12, U13, U14, U15};
    S[12] ^= WORD_LEN;
    S[13] ^= RND_NUM; 
    S[14] ^= PARALLEL;
    S[15] ^= TAG_LEN; 
    F(pwSIni)
    S[12] ^= K[0];
    S[13] ^= K[1]; 
    S[14] ^= K[2];
    S[15] ^= K[3];
}

//*****************************************************************************
//
// Function -> absorb
// Purpose ->
// Inputs -> word_t* pwSAbs[] - Pointer to State, 4x4 matrix of words
//           word_t* pwAZ[] - Pointer to Either the Header or Footer
//           uint32_t absDomain - Domain Constant for Absorb
//
//*****************************************************************************
void 
absorb(word_t* pwSAbs[16], word_t* pwAZ[], uint32_t absDomain) {

}

//*****************************************************************************
//
// Function -> branch
// Purpose ->
// Inputs -> word_t* pwSBrch[] - Pointer to State, 4x4 matrix of words
//           uint32_t msgSize - Size of Message
//           uint32_t brchDomain - Domain Constant for Branch
//
//*****************************************************************************
void 
branch(word_t* pwSBrch[16], uint32_t msgSize, uint32_t brchDomain) {

} 

//*****************************************************************************
//
// Function -> encrypt
// Purpose -> Run a given number of rounds of encryption on the given text
// Inputs -> word_t* pwSbarEnc[] - Pointer to State, 4x4 matrix of words
//           word_t pwM[] - Pointer to message
//           uint32_t encDomain - Domain Constant for Encrypt
//
//*****************************************************************************
void
encrypt(word_t* pwSbarEnc[16], word_t* pwM[], uint32_t encDomain) {

}

//*****************************************************************************
//
// Function -> decrypt
// Purpose -> Run a given number of rounds of decryption on the given text
// Inputs -> word_t* pwSbarDec[] - Pointer to State, 4x4 matrix of words
//           word_t* pwC[] - Pointer to cipher text
//           uint32_t decDomain - Domain Constant for Decrypt
//
//*****************************************************************************
void
decrypt(word_t* pwSbarDec[16], word_t* pwC[], uint32_t decDomain) {

}

//*****************************************************************************
//
// Function -> F
// Purpose -> Run F perumtation on given text
// Input -> word_t* pwS[] - Pointer to State, 4x4 matrix of words
//
//*****************************************************************************
void
F(word_t* pwS[16]) {
    diag(col(pS));
}

//*****************************************************************************
//
// Function -> diag
// Purpose -> Run G function on words diaganol from each other 
// Input -> word_t* pwS[] - Pointer to State, 4x4 matrix of words
//
//*****************************************************************************
void 
diag(word_t* pwS[16]) {
    G(pS, 0, 5, 10, 15);
    G(pS, 1, 6, 11, 12);
    G(pS, 2, 7, 8, 13);
    G(pS, 3, 4, 9, 14);	
}

//*****************************************************************************
//
// Function -> col
// Purpose -> Run G function on words in a collumn 
// Input -> word_t* pwS[] -> Pointer to State, 4x4 matrix of words
//
//*****************************************************************************
void 
col(word_t* pwS[16]) {
    G(pS, 0, 4, 8, 12);
    G(pS, 1, 5, 9, 13);
    G(pS, 2, 6, 10, 14);
    G(pS, 3, 7, 11, 15);
}

//*****************************************************************************
//
// Function -> G
// Purpose -> G function of NORX
// Input -> word_t* pwS[] - Pointer to State, 4x4 matrix of words
//          uint32_t sX - Index in state of 4 words that will be operated on
//
//*****************************************************************************
void 
G(word_t* pwS[16], uint32_t s0, uint32_t s1, uint32_t s2, uint32_t s3) {
    pS[s0] = H(pS[s0], pS[s1]);
    pS[s3] = (pS[s0] ^ pS[s3]) >> R0;
    pS[s2] = H(pS[s2], pS[s3]); 
    pS[s2] = (pS[s1] ^ pS[s2]) >> R1;
    pS[s1] = H(pS[s0], pS[s1]);
    pS[s3] = (pS[s0] ^ pS[s3]) >> R2;
    pS[s2] = H(pS[s2], pS[s3]);
    pS[s1] = (pS[s1] ^ pS[s2]) >> R3;
}

//*****************************************************************************
//
// Function -> H
// Purpose -> H function of NORX permutation
// Input -> word_t x,y - Words to be operated on
//
//*****************************************************************************
word_t
H(word_t x, word_t y) {
    return (x ^ y) ^ ((x & y) << 1);
}

//*****************************************************************************
//
// Function -> merge
// Purpose ->
//
//*****************************************************************************
void 
merge(word_t* pwSbarMrg[16], uint32_t msgSize, uint32_t mrgDomain) {

}

//*****************************************************************************
//
// Function -> finalise 
// Purpose -> 
// Inputs -> word_t* pwSfin[] - Pointer to State; 4x4 matrix of words
//           nkey_t K - Key
//           uint32_t finDomain - Domain constant for finalise 
//           word_t*  pTag[4] - Hash value of message
//
//*****************************************************************************
void
finalise(word_t* pwSFin[16], nkey_t K, word_t* pTag[4], uint32_t finDomain) {

}
