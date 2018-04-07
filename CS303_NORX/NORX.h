/******************************************************************************
*                                                                             *
* File -> NORX.h                                                              *
* Purpose -> Header file to encrypt and decrypt the NORX algoritm             *
* Author -> Joseph Kroeker                                                    *
* Version -> 1.0 03/10/2018 - Setting Up Core Permutation, and Defining       *
*                             Constants (3 hours)                             *
*            2.0 03/11/2018 - Adding High Level Prototypes/Functions          * 
*                                                                             *
******************************************************************************/

//TODO check constants (I don't trust me)
//TODO Add ifdef for 32 bit words and constants for 64 bit

#include <stdint.h>

//*****************************************************************************
//
// If flag for 32 bit words is defined go through 32 bit defines
//
//*****************************************************************************
#ifdef WORD_32
  //***************************************************************************
  // Define Overall Parameters
  //***************************************************************************
  #define WORD_LEN  32              // Word size of 32 bits  
  #define RND_NUM   4               // 4 rounds to be run
  #define PARALLEL  1               // Parallelism degree of 1
  #define TAG_LEN   4 * WORD_LEN    // Tag size of 4 words

  //***************************************************************************
  // Define Shifts for G Function for 32 Bits
  //***************************************************************************
  #define R0        8   
  #define R1        11
  #define R2        16
  #define R3        31

  //***************************************************************************
  // Define Initialisation Constants for 32 Bits
  //***************************************************************************
  #define U0        0x0454edab
  #define U1        0xac6851cc
  #define U2        0xb707322f
  #define U3        0xa0c7c90d
  #define U4        0x99ab09ac
  #define U5        0xa643466d
  #define U6        0x21c22362
  #define U7        0x1230c950
  #define U8        0xa3d8d930
  #define U9        0x3fa8b72c
  #define U10       0xed84eb49
  #define U11       0xedca4787
  #define U12       0x335463eb
  #define U13       0xf994220b
  #define U14       0xbe0bf5c9
  #define U15       0xd7c49104

  //***************************************************************************
  // Define Word Type for 32 Bits
  //***************************************************************************
  typedef uint32_t word_t;     // 32 bit words 

//*****************************************************************************
//
// If flag for 32 bit words is not set then go through 64 bit set up
//
//*****************************************************************************
#else 
  //***************************************************************************
  // Define Overall Parameters
  //***************************************************************************
  #define WORD_LEN  64              // Word size of 32 bits  
  #define RND_NUM   4               // 4 rounds to be run
  #define PARALLEL  1               // Parallelism degree of 1
  #define TAG_LEN   4 * WORD_LEN    // Tag size of 4 words

  //***************************************************************************
  // Define Shifts for G Function for 64 Bits
  //***************************************************************************
  #define R0        8   
  #define R1        19
  #define R2        40
  #define R3        63

  //***************************************************************************
  // Define Initialisation Constants for 64 Bits
  //***************************************************************************
  #define U0        0xe4d324772b91df79
  #define U1        0x3aec9abaaeb02ccb
  #define U2        0x9dfba13db4289311
  #define U3        0xef9eb4bf5a97f2c8
  #define U4        0x3f466e92c1532034
  #define U5        0xe6e986626cc405c1
  #define U6        0xace40f3b549184e1
  #define U7        0xd9cfd35762614477
  #define U8        0xb15e641748de5e6b
  #define U9        0xaa95e955e10f8410
  #define U10       0x28d1034441a9dd40
  #define U11       0x7f31bbf964e93bf5
  #define U12       0xb5e9e22493dffb96
  #define U13       0xb980c852479fafbd
  #define U14       0xda24516bf55eafd4
  #define U15       0x86026ae8536f1501

  //***************************************************************************
  // Define Word Type for 64 Bits
  //***************************************************************************
  typedef uint64_t word_t;     // 64 bit words 

#endif

//*****************************************************************************
// Main Algorithm Prototypes
//*****************************************************************************
extern void NORXEnc(word_t K[4], nonce_t N, word_t A[], word_t M[], word_t Z[]);
extern void NORXDec(word_t K[4], nonce_t N, word_t A[], word_t C[], word_t Z[], tag_t T);

//***************************************************************************
// Initialisation prototypes
//***************************************************************************
extern void initialise(word_t* pwKIni[4], word_t* pwNIni[4], word_t* pwSIni[16]);

//***************************************************************************
// Absorb Prototypes
//***************************************************************************
extern void absorb(word_t* pwSAbs[16], word_t* pwAZ[], uint32_t absDomain);

//***************************************************************************
// Branch Protoypes
//***************************************************************************
extern void branch(const word_t* pwSBrch[16], word_t* pwSBar[16], 
                   uint32_t msgSize, uint32_t brchDomain);

//***************************************************************************
// Encrypt/Decrypt Prototypes
//***************************************************************************
extern void encrypt(word_t* pwSbarEnc[16], word_t* pwM[], uint32_t encDomain);
extern void decrypt(word_t* pwSbarDec[16], word_t* pwC[], uint32_t decDomain);
extern void F(word_t* pwS[16]);
extern void diag(word_t* pwS[16]);
extern void col(word_t* pwS[16]);
extern void G(word_t* pwS[16], uint32_t s0, uint32_t s1, uint32_t s2, uint32_t s3);
extern word_t H(word_t x, word_t y);

//***************************************************************************
// Merge prototypes
//***************************************************************************
extern void merge(word_t* pwSbarMrg[16], uint32_t msgSize, uint32_t mrgDomain);

//***************************************************************************
// Finalise Protypes
//***************************************************************************
extern tag_t finalise(word_t* pwSFin[16], nkey_t K, uint32_t finDomain);

