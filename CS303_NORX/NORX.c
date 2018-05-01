/******************************************************************************
*                                                                             *
* File -> NORX.c                                                              *
* Purpose -> Encrypt and Decrypt text using the NORX algorithm                *
* Author -> Joseph Kroeker                                                    *
* Version -> 1.0 03/10/2018 - Setting Up Core Permutation                     *
*            2.0 03/11/2018 - Adding High Level Prototypes/Functions and      *
*                              calls in main functions                        *
*            3.0 04/07/2018 - Compiling and correcting errors                 *
*            4.0 04/18/2018 - Fill finalise() and create right()              *
*            5.0 04/30/2018 - Review of previous functions and corrections    * 
*                             for functionality                               *
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

//***************************************************************************
//
// Function -> main
// Purpose -> test encode and decode functions
// 
//***************************************************************************
int 
main(void) {
  word_t K[0x10];
  word_t N[0x30];
  int i;
  word_t Test[0x10]; // buffer for testing the different functions 

  // Init K to 0x0, 0x1, ... 0xE, 0xF
  for (i = 0; i <= 0xF; i++) {
    K[i] = i;
  }
  // Init N to 0x0, 0x1, ... 0x2E, 0x2F 
  for (i = 0; i <= 0x2F; i++) {
    N[i] = i;
  }
  printf("Shift test\n%x\n", rightRot(1, 1));
  
  // Print test key
  printf("Key : \n");
  for (i=0; i<=0xF; i++) {
    printf("%x ", K[i]);
  } 

  // Print test Nonce
  printf("\nNonce : \n");
  for (i = 0; i<= 0x2F; i++) {
    printf("%x ", N[i]);
  } 

  // Print test init run
  // TODO fix this to display given values from NORX instructions
  // TODO test out different round amounts, indexing may be off
  initialise(K, N, Test);
  printf("\nTest Init : \n");
  for (i=0; i<=0xF; i++) {
    printf("%x ", Test[i]);
  }
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
    word_t S[16] = { 0 };     // State, 4x4 matrix of words
    word_t Sbar[16] = { 0 };  // State bar, 4x4 matrix of words
    word_t C[16] = { 0 };      // Final encrypted text
    word_t outT[TAG_LEN] = { 0 };   // 4 word tag

    uint32_t msgSize = sizeof(M) / sizeof(word_t);
    uint32_t headSize = sizeof(A) / sizeof(word_t);
    uint32_t footSize = sizeof(Z) / sizeof (word_t);

    initialise(K, N, S);
    absorb(S, A, headSize, 0x01);
    branch(S, Sbar, msgSize , 0x10);
    encrypt(Sbar, M , 0x02, C);
    merge(Sbar, S, msgSize , 0x20);
    absorb(S, Z, footSize, 0x04);
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
    word_t S[16] = { 0 };     // State, 4x4 matrix of words
    word_t Sbar[16] = { 0 };  // State bar, 4x4 matrix of words
    word_t outT[4] = { 0 };   // 4 word tag

    uint32_t encSize = sizeof(C) / sizeof(word_t);
    uint32_t headSize = sizeof(A) / sizeof(word_t);
    uint32_t footSize = sizeof(Z) / sizeof (word_t);
    
    initialise(K, N, S);
    absorb(S, A, headSize, 0x01);
    branch(S, Sbar, encSize, 0x10);
    decrypt(Sbar, C, 0x02);
    merge(Sbar, S, encSize, 0x20);
    absorb(S, Z, footSize, 0x04);
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
    int i;
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
absorb(word_t* pwSAbs, word_t* pwAZ, uint32_t AZSize, uint32_t absDomain) {
  uint32_t i;
  uint32_t j;
  uint32_t m = RATE;  // given rate value based on word size
  // TODO check functionality, notation is weird in the notes
  if (AZSize > 0) {
    for (i = 0; i <= m - 2; i++) {
      pwSAbs[15] ^= absDomain;
      F(pwSAbs);
      for (j = 0; j < AZSize; j++) {
	 pwSAbs[j] ^= pwAZ[j];
      } 
    }
    pwSAbs[15] ^= absDomain; 
    F(pwSAbs); 
    pwSAbs[j + 1] ^= pad(pwAZ[j]);
  } 

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
  if (PARALLEL == 1) {
    pwSBrch = pwSBar;
  } 
  else {
    //
    // TODO work with P != 1
    //
  } 
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
encrypt(word_t* pwSbarEnc, word_t* pwM, uint32_t encDomain, word_t* pwC) {
  uint32_t i;
  uint32_t m = RATE;  // given rate value based on word size
  uint32_t b = WIDTH;  // given block length for word size
  uint32_t j = 0;  
  if (sizeof(pwM) > 0) {
    for (i = 0; i <= m-2; i++) {
      j = i % (sizeof(pwSbarEnc) / sizeof(word_t));

    }
  }
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
  int i;
  for (i = 0; i < RND_NUM; i++) { 
    col(pwS);
    diag(pwS);
  } 
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
G(word_t* pwS, word_t s0, word_t s1, word_t s2, word_t s3) {
    pwS[s0] = H(pwS[s0], pwS[s1]);        
    pwS[s3] = rightRot((pwS[s0] ^ pwS[s3]), R0);  
    pwS[s2] = H(pwS[s2], pwS[s3]);        
    pwS[s2] = rightRot((pwS[s1] ^ pwS[s2]), R1); 
    pwS[s1] = H(pwS[s0], pwS[s1]);        
    pwS[s3] = rightRot((pwS[s0] ^ pwS[s3]), R2);
    pwS[s2] = H(pwS[s2], pwS[s3]);
    pwS[s1] = rightRot((pwS[s1] ^ pwS[s2]), R3);
}

//*****************************************************************************
//
// Function -> Rot()
// Purpose -> Rotate the given value by a set shift
// Input -> 
//
//*****************************************************************************
word_t  
rightRot(word_t value, uint32_t shift) {
  return ((value >> shift) | (value << (32 - shift)));
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
merge(word_t* pwSbarMrg, word_t* pwSMrg, uint32_t msgSize, uint32_t mrgDomain) {
  if (PARALLEL == 1) {
    pwSMrg = pwSbarMrg;
  }
  else {
  //
  // TODO Work with P != 1
  //
  }
}

//*****************************************************************************
//
// Function -> finalise()
// Purpose -> 
// Inputs -> word_t* pwSfin[] - Pointer to State; 4x4 matrix of words
//           nkey_t K - Key
//           uint32_t finDomain - Domain constant for finalise 
//           word_t*  pTag[4] - Hash value of message
//
//*****************************************************************************
void
finalise(word_t* pwSFin, word_t* K, uint32_t finDomain, word_t* outTag) {
  pwSFin[15] ^= finDomain;
  F(pwSFin);

  // (s12, s13, s14, s15) ^= k0, k1, k2, k3
  pwSFin[12] ^= K[12];
  pwSFin[13] ^= K[13];
  pwSFin[14] ^= K[14];
  pwSFin[15] ^= K[15];

  F(pwSFin);

  // (s12, s13, s14, s15) ^= k0, k1, k2, k3
  pwSFin[12] ^= K[12];
  pwSFin[13] ^= K[13];
  pwSFin[14] ^= K[14];
  pwSFin[15] ^= K[15];

  right(pwSFin, outTag, TAG_LEN);
}

//***************************************************************************
//
// Function -> pad()
// Purpose -> pad out any values that need padding
// Inputs -> 
//
//***************************************************************************
//TODO make this do something rather than just return value. Currently place holder
word_t
pad(word_t input) {
  return input;
} 

//***************************************************************************
//
// Function -> right
// Purpose -> Truncation of bitstring x to its r right-most bits.
// Inputs
// 
//***************************************************************************
void
right(word_t* pwSR, word_t* retVal, uint32_t len) {
  int i;
  retVal = 0;
  for (i = 0; i < len; i++) {
    retVal[i] = pwSR[i];
  } 
}

