

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "HMAC/hmac-sha1.h"
#include "random/random.h"

/* RNCryptor setting struct (AES128)
static const RNCryptorSettings kMGCryptorAES128Settings = {
    .algorithm = kCCAlgorithmAES128,
    .blockSize = kCCBlockSizeAES128,
    .IVSize = kCCBlockSizeAES128,
    .options = kCCOptionPKCS7Padding,
    .HMACAlgorithm = kCCHmacAlgSHA1,
    .HMACLength = CC_SHA1_DIGEST_LENGTH,

    .keySettings = {
        .keySize = kCCKeySizeAES128,
        .saltSize = 8,
        .PBKDFAlgorithm = kCCPBKDF2,
        .PRF = kCCPRFHmacAlgSHA1,
        .rounds = 10000
    },

    .HMACKeySettings = {
        .keySize = kCCKeySizeAES128,
        .saltSize = 8,
        .PBKDFAlgorithm = kCCPBKDF2,
        .PRF = kCCPRFHmacAlgSHA1,
        .rounds = 10000
    }
};
*/


/* configuration of the project */
#define DEBUG_LOG		0		/* set to 1 to enable the print log, for debug purpose only */
#define BUFFER_LEN 2000		/* the malloc is not used in this project, so this is the maximum lenght in byte of the imput data array */
#define KEYBITS 		128		/* do not change this parameters, it represent the AES 128 bit standard */

/* configuration of the data structure stream */
#define SIZE_VERSION	2
#define SIZE_SALT		8
#define SIZE_IV			16
#define SIZE_HMAC		20

#define OFFSET_VERSION	0
#define OFFSET_ENCSALT	(OFFSET_VERSION+SIZE_VERSION)
#define OFFSET_HMACSALT	(OFFSET_ENCSALT+SIZE_SALT)
#define OFFSET_IV		(OFFSET_HMACSALT+SIZE_SALT)
#define OFFSET_CIPHER	(OFFSET_IV+SIZE_IV)

#define CIPHER_BUFFER_LEN (SIZE_VERSION+SIZE_SALT+SIZE_SALT+SIZE_IV+BUFFER_LEN+SIZE_HMAC)


#ifndef MGCRYPTOR_H_
#define MGCRYPTOR_H_

int MGEncryptor(void* message, size_t messagelen, void * password, size_t passwordlen, void* pOutBuffer);

int MGDecryptor(void* pInBuffer, size_t inbufferlen, void * password, size_t passwordlen, void* pOutBuffer);


#endif /* MGCRYPTOR_H_ */
