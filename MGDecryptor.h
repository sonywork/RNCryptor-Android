

#ifndef MGDECRYPTOR_H_
#define MGDECRYPTOR_H_

int decAES128cbc(void* pkey, void* pIV, void* pOutBuffer, void* pInBuffer, int len);

#endif /* MGDECRYPTOR_H_ */
