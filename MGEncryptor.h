
#ifndef MGENCRYPTOR_H_
#define MGENCRYPTOR_H_

int encAES128cbc(void* pkey, void* pIV, void* pOutBuffer, void* pInBuffer, int len);

#endif /* MGENCRYPTOR_H_ */
