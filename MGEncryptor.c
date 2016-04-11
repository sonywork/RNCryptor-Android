#include "MGCryptor.h"
#include "MGEncryptor.h"
#include "AES/rijndael.h"
#include "HMAC/memxor.h"

//#include "debuglog.h"  //for debug purpose only


//perform the AES crypto using the CBC mode and return the lenght of data in the plainBuffer pre-allocated array
int encAES128cbc(void* pkey, void* pIV, void* pOutBuffer, void* pInBuffer, int len)
{
  unsigned long rk[RKLENGTH(KEYBITS)];
  //unsigned char key[KEYLENGTH(KEYBITS)];
  int i;
  int nrounds;
  int nblocks;
  int paddinglen;
  unsigned char plaintext[16];
  unsigned char ciphertext[16];

  //initialize the algorithm
  nrounds = rijndaelSetupEncrypt(rk, pkey, KEYBITS);

  nblocks = (len/16)+1; 		//+1 to consider the last block complete

  //PKCS#7 padding have to be added
  paddinglen = 16-(len%16);
  //if the message len is exactly a multiple of the AES block size (16 bytes), so an entire more block all to 0x10 have to be added
  memset(pInBuffer+len, paddinglen, paddinglen);

  //prepare the IV vector
  memcpy(ciphertext, pIV, sizeof(ciphertext));

  for (i=0; i<nblocks; i++)
  {
	  //prepare the plaintext array
	  memcpy(plaintext, (pInBuffer+i*16), sizeof(plaintext));

	  //xor of plaintext with the previouse output interation (or IV)
	  memxor(plaintext, ciphertext, sizeof(plaintext));

	  //do the block cipher
	  rijndaelEncrypt(rk, nrounds, plaintext, ciphertext);

	  //copy the result in the output buffer
	  memcpy((pOutBuffer+i*16), ciphertext, sizeof(ciphertext));
  }



  return (len+paddinglen);
}
