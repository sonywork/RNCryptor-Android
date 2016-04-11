

#include "MGCryptor.h"
#include "MGDecryptor.h"
#include "AES/rijndael.h"
#include "HMAC/memxor.h"

//perform the AES decyption using the CBC mode and return the lenght of data in the plainBuffer pre-allocated array
int decAES128cbc(void* pkey, void* pIV, void* pOutBuffer, void* pInBuffer, int len)
{
	unsigned long rk[RKLENGTH(KEYBITS)];

	int i;
	int nrounds;
	int nblocks;
	unsigned char *paddinglen = pOutBuffer+len-1;
	unsigned char plaintext[16];

	//initialize the algorithm
	nrounds = rijndaelSetupDecrypt(rk, pkey, KEYBITS);

	nblocks = len/16;

	for (i=0; i<nblocks; i++)
	{
		//do the block decrypt
		rijndaelDecrypt(rk, nrounds, (pInBuffer+i*16), plaintext);

		//xor of plaintext with the previouse output interation (or IV)
		if (i == 0)
		{
			memxor(plaintext, pIV, sizeof(plaintext));
		}
		else
		{
			memxor(plaintext, pInBuffer+(i-1)*16, sizeof(plaintext));
		}

		//copy the result in the output buffer
		memcpy((pOutBuffer+i*16), plaintext, sizeof(plaintext));
	}

	//PKCS#7 padding have to be removed
	return (len-*paddinglen);
}
