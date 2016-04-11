/* Encryptor/Decryptor in ANSI C
 *
 * Provides an easy-to-use, ANSI C interface to the AES functionality.
 * Simplifies correct handling of password stretching (PBKDF2), salting, and IV.
 * Also includes automatic HMAC handling to integrity-check messages.
 *
 * The idea of this code are:
 * 1) to be "dependency library free"
 * 2) easy to port in a general purpose microcontroller (32 bit preferred, but
 *    AES 128 bit work great also in a 8 bit)
 * 3) can be easily interfaced with RNCryptor library for iOS developed by Rob Napier
 *    for more information see https://github.com/rnapier/RNCryptor
 *    for documentation see: http://rnapier.github.com/RNCryptor/doc/html/Classes/RNCryptor.html
 *
 */


#include "MGCryptor.h"
#include "MGEncryptor.h"
#include "MGDecryptor.h"
#include "PBKDF2/pkcs5_pbkdf2.h"
#include "debug.h"

//first version(2),second platform(android)
static const unsigned char kRNCryptorFileVersion[SIZE_VERSION] = { 0x02, 0x02 };

//perform the encryption and return the lenght of data in the cipherBuffer pre-allocated array
int MGEncryptor(void* message, size_t messagelen, void * password, size_t passwordlen, void* pOutBuffer)
{
	int len;
	unsigned char keyword[KEYBITS/8];
	char IV[SIZE_IV];
	char salt[SIZE_SALT];
	unsigned char plainBuffer[messagelen];


	//init compose the output buffer
	memcpy((pOutBuffer+OFFSET_VERSION), kRNCryptorFileVersion, sizeof(kRNCryptorFileVersion));

	//generate the encryption key salt
	randBuffer(salt, SIZE_SALT);
	__FILE__, __LINE__, __func__;

	LOGD(__func__);

	memcpy((pOutBuffer+OFFSET_ENCSALT), salt, SIZE_SALT);

	//generate the encryption key
	if (pkcs5_pbkdf2(password, passwordlen, salt, SIZE_SALT, keyword, sizeof(keyword), 10000))
	{
		return 0;	//put zero to len output to indicate an error
	}

	//generate the IV with random generator
	randBuffer(IV, SIZE_IV);
	memcpy((pOutBuffer+OFFSET_IV), IV, SIZE_IV);
	//copy the original message into the buffer
	memcpy(plainBuffer, message, messagelen);

	//do the AES128 in CBC mode directly to the output array and return the lenght of the bytes
	len = encAES128cbc(keyword, IV, pOutBuffer+OFFSET_CIPHER, plainBuffer, messagelen);

	//calculate the lenght of complete array where do the hmac-sha1
	len = len + SIZE_VERSION+SIZE_SALT+SIZE_SALT+SIZE_IV;

	//generate the HMAC key salt
	randBuffer(salt, SIZE_SALT);
	memcpy((pOutBuffer+OFFSET_HMACSALT), salt, SIZE_SALT);

	//generate the HMAC key
	if (pkcs5_pbkdf2(password, passwordlen, salt, SIZE_SALT, keyword, sizeof(keyword), 10000))
	{
		return 0;	//put zero to len output to indicate an error
	}

	//do the HMAC-SHA1 directoy to the output array
	hmac_sha1(keyword, sizeof(keyword), pOutBuffer, len, pOutBuffer+len);

	//calculate the lenght of complete array
	len = len + SIZE_HMAC;

	return len;
}

//perform the decryption and return the lenght of data in the plainBuffer pre-allocated array
int MGDecryptor(void* pInBuffer, size_t inbufferlen, void * password, size_t passwordlen, void* pOutBuffer)
{
	int len;
	unsigned char keyword[KEYBITS/8];

	//generate the HMAC key
	if (pkcs5_pbkdf2(password, passwordlen, pInBuffer+OFFSET_HMACSALT, SIZE_SALT, keyword, sizeof(keyword), 10000))
	{
		return 0;	//put zero to len output to indicate an error
	}

	//do the HMAC-SHA1 directoy to the output array for compare
	hmac_sha1(keyword, sizeof(keyword), pInBuffer, inbufferlen-SIZE_HMAC, pOutBuffer);


  	if (memcmp(pInBuffer+inbufferlen-SIZE_HMAC, pOutBuffer, SIZE_HMAC))
  	{
  		return 0;	//HMAC-SHA1 signature not match
  	}

	//generate the encryption key
	if (pkcs5_pbkdf2(password, passwordlen, pInBuffer+OFFSET_ENCSALT, SIZE_SALT, keyword, sizeof(keyword), 10000))
	{
		return 0;	//put zero to len output to indicate an error
	}

	//do the AES128 in CBC mode directly to the output array and return the lenght of the bytes
	len = decAES128cbc(keyword, pInBuffer+OFFSET_IV, pOutBuffer, pInBuffer+OFFSET_CIPHER, inbufferlen-(SIZE_VERSION+SIZE_SALT+SIZE_SALT+SIZE_IV+SIZE_HMAC));

	return len;
}
