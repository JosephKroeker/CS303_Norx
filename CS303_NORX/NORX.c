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
#define WORD_32 0x1

//*****************************************************************************
// Includes
//*****************************************************************************
#include <stdbool.h>   // bool types
#include <stdint.h>    // uintXX_t types
#include <string.h>    // string functions

#include "NORX.h"      // NORX defines and prototypes

int 
main(void) {
  return 0;
}
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
NORXEnc(word_t K[], word_t N[], word_t A[], word_t M[], word_t Z[]) {
    word_t S[16] = { 0 };    // State, 4x4 matrix of words
    word_t Sbar[16] = { 0 };  // State bar, 4x4 matrix of words
    word_t outT[4] = { 0 }; // 4 word tag

    initialise(K, N, S);
    absorb(S, A, 0x01);
    branch(S, Sbar, sizeof(M) / sizeof(word_t) , 0x10);
    encrypt(Sbar, M , 0x02);
    merge(Sbar, sizeof(M)/ sizeof(word_t) , 0x20);
    absorb(S, Z, 0x04);
    finalise(S, K, 0x08, outT);
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
NORXDec(word_t K[], word_t N[], word_t A[], word_t C[], word_t Z[], word_t T[]) {
    word_t S[16] = { 0 };    // State, 4x4 matrix of words
    word_t Sbar[16] = { 0 };  // State bar, 4x4 matrix of words
    word_t outT[4] = { 0 }; // 4 word tag

    initialise(K, N, S);
    absorb(S, A, 0x01);
    branch(S, Sbar, sizeof(C) / sizeof(word_t), 0x10);
    decrypt(Sbar, C, 0x02);
    merge(Sbar, sizeof(C) / sizeof(word_t), 0x20);
    absorb(S, Z, 0x04);
    finalise(S, K, 0x08, outT);
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
initialise(word_t* pwKIni, word_t* pwNIni, word_t* pwSIni) {
    pwSIni[0] = pwNIni[0];  
    pwSIni[1] = pwNIni[1];
    pwSIni[2] = pwNIni[2];
    pwSIni[3] = pwNIni[3];
    pwSIni[4] = pwKIni[0];
    pwSIni[5] = pwKIni[1];
    pwSIni[6] = pwKIni[2];
    pwSIni[7] = pwKIni[3];
    pwSIni[8] = U8;
    pwSIni[9] = U9;
    pwSIni[10] = U10;
    pwSIni[11] = U11;
    pwSIni[12] = U12;
    pwSIni[13] = U13;
    pwSIni[14] = U14;
    pwSIni[15] = U15;

    pwSIni[12] ^= WORD_LEN;
    pwSIni[13] ^= RND_NUM; 
    pwSIni[14] ^= PARALLEL;
    pwSIni[15] ^= TAG_LEN; 
    F(pwSIni);
    pwSIni[12] ^= pwKIni[0];
    pwSIni[13] ^= pwKIni[1]; 
    pwSIni[14] ^= pwKIni[2];
    pwSIni[15] ^= pwKIni[3];
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
absorb(word_t* pwSAbs, word_t* pwAZ, uint32_t absDomain) {

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
branch(const word_t* pwSBrch, word_t* pwSBar, uint32_t msgSize, uint32_t brchDomain) {

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
encrypt(word_t* pwSbarEnc, word_t* pwM, uint32_t encDomain) {

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
decrypt(word_t* pwSbarDec, word_t* pwC, uint32_t decDomain) {

}

//*****************************************************************************
//
// Function -> F
// Purpose -> Run F perumtation on given text
// Input -> word_t* pwS[] - Pointer to State, 4x4 matrix of words
//
//*****************************************************************************
void
F(word_t* pwS) {
    col(pwS);
    diag(pwS);
}

//*****************************************************************************
//
// Function -> diag
// Purpose -> Run G function on words diaganol from each other 
// Input -> word_t* pwS[] - Pointer to State, 4x4 matrix of words
//
//*****************************************************************************
void 
diag(word_t* pwS) {
    G(pwS, 0, 5, 10, 15);
    G(pwS, 1, 6, 11, 12);
    G(pwS, 2, 7, 8, 13);
    G(pwS, 3, 4, 9, 14);	
}

//*****************************************************************************
//
// Function -> col
// Purpose -> Run G function on words in a collumn 
// Input -> word_t* pwS[] -> Pointer to State, 4x4 matrix of words
//
//*****************************************************************************
void 
col(word_t* pwS) {
    G(pwS, 0, 4, 8, 12);
    G(pwS, 1, 5, 9, 13);
    G(pwS, 2, 6, 10, 14);
    G(pwS, 3, 7, 11, 15);
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
G(word_t* pwS, uint32_t s0, uint32_t s1, uint32_t s2, uint32_t s3) {
    pwS[s0] = H(pwS[s0], pwS[s1]);
    pwS[s3] = (pwS[s0] ^ pwS[s3]) >> R0;
    pwS[s2] = H(pwS[s2], pwS[s3]); 
    pwS[s2] = (pwS[s1] ^ pwS[s2]) >> R1;
    pwS[s1] = H(pwS[s0], pwS[s1]);
    pwS[s3] = (pwS[s0] ^ pwS[s3]) >> R2;
    pwS[s2] = H(pwS[s2], pwS[s3]);
    pwS[s1] = (pwS[s1] ^ pwS[s2]) >> R3;
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
merge(word_t* pwSbarMrg, uint32_t msgSize, uint32_t mrgDomain) {

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
finalise(word_t* pwSFin, word_t* K, uint32_t finDomain, word_t outTag) {

}

