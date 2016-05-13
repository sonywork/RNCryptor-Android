#include <jni.h>
#include "b64/base64.h"

#include "debug.h"
#include "MGCryptor.h"
#include "errno_t.h"


void RegisterRawAES (JNIEnv *env);
void RegisterBase64 (JNIEnv *env);


JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved)
{
	JNIEnv *env;

//	LOGPOS();

	if ((*vm)->GetEnv(vm, (void**)&env, JNI_VERSION_1_4) != JNI_OK) {
		LOGE("Get Env Failed");
		return JNI_ERR;
	}

	RegisterRawAES(env);
	RegisterBase64(env);

	return JNI_VERSION_1_4;
}
/*
 *
 */



/* =============================== RawAES ================================== */

#define PASS "yMv5zoSx4waLDj4rdfgf6LSTTGd8exS"
#define UPASS "dJsCwbEr95kubHEWnQx94UPnvTrF6sq"
#define NPASS ""



/*
 * Signature: ([B)[B
 */
static jbyteArray Encrypto(JNIEnv *env, jobject thiz, jbyteArray ba, jint tp)
{

	char * data = (*env)->GetByteArrayElements(env, ba, 0);
//	int len = (*env)->GetArrayLength(env, ba);
	int type = tp;

	char * key;
	if(tp == 1){
		key = PASS;
	}else if(tp == 2){
		key = UPASS;
	}else{
		key = NPASS;
	}

	int cipherBufferLen;

	void * cipherBuffer = malloc(CIPHER_BUFFER_LEN);
	cipherBufferLen = MGEncryptor(data, strlen(data), key, strlen(key), cipherBuffer);

	unsigned long enDataLen;
	char* enData = (char*)malloc(BUFFER_LEN);
	enDataLen = Base64encode(enData,cipherBuffer,cipherBufferLen);
	free(cipherBuffer);


	jbyteArray jarrRV =(*env)->NewByteArray(env,enDataLen);

	(*env)->SetByteArrayRegion(env,jarrRV, 0,enDataLen, enData);

	(*env)->ReleaseByteArrayElements(env,ba,data,0);
	free(enData);


	return jarrRV;
}


/*
 * Signature: ([B)[B
 */
static jbyteArray Decrypto(JNIEnv *env, jobject thiz, jbyteArray ba, jint tp)
{
//	monstartup("libjcryptoc.so");
//	LOGPOS();
	char * data = (*env)->GetByteArrayElements(env, ba, 0);
//	int len = (*env)->GetArrayLength(env, ba);

	unsigned long deDataLen;
	char* deData = (char*)malloc(CIPHER_BUFFER_LEN);
	deDataLen = Base64decode(deData,data);

	char * key;
	if(tp == 1){
		key = PASS;
	}else if(tp == 2){
		key = UPASS;
	}else{
		key = NPASS;
	}

	int plainBufferLen;
	void * plainBuffer = malloc(BUFFER_LEN);

	plainBufferLen = MGDecryptor(deData, deDataLen, key, strlen(key), plainBuffer);
	free(deData);



	jbyteArray jarrRV =(*env)->NewByteArray(env,plainBufferLen);

	(*env)->SetByteArrayRegion(env,jarrRV, 0,plainBufferLen, plainBuffer);
	free(plainBuffer);

	(*env)->ReleaseByteArrayElements(env,ba,data,0);

//	setenv("CPUPROFILE", "/sdcard/gmon.out", 1);
//	moncleanup();
	return jarrRV;
}


/* =============================== Base64 ================================== */

/*
 * Signature: ([B)[B
 */
static jbyteArray Base64Encode(JNIEnv *env, jobject thiz, jbyteArray ba)
{
	char * data = (*env)->GetByteArrayElements(env, ba, 0);
	int len = (*env)->GetArrayLength(env, ba);
	unsigned long enDataLen;
	char* enData = (char*)malloc(BUFFER_LEN);
	enDataLen = Base64encode(enData,data,len);

	jbyteArray jarrRV =(*env)->NewByteArray(env,enDataLen);

	(*env)->SetByteArrayRegion(env,jarrRV, 0,enDataLen, enData);

	(*env)->ReleaseByteArrayElements(env,ba,data,0);
	free(enData);
	return jarrRV;
}

/*
 * Signature: ([B)[B
 */
static jbyteArray Base64Decode(JNIEnv *env, jobject thiz, jbyteArray ba)
{
	char * data = (*env)->GetByteArrayElements(env, ba, 0);
//	int len = (*env)->GetArrayLength(env, ba);
	unsigned long deDataLen;
	char* deData = (char*)malloc(BUFFER_LEN);
	deDataLen = Base64decode(deData,data);

	jbyteArray jarrRV =(*env)->NewByteArray(env,deDataLen);

	(*env)->SetByteArrayRegion(env,jarrRV, 0,deDataLen, deData);

	(*env)->ReleaseByteArrayElements(env,ba,data,0);
	free(deData);
	return jarrRV;
}

/* =============================== RegisterNativeMethods ================================== */

void RegisterNativeMethods(JNIEnv *env, const char *clazz,
	const JNINativeMethod* methods, uint32_t num)
{
	errno_t err;

//	LOGPOS();

	ASSERT((*env)->FindClass(env, clazz) != NULL);

	err = (*env)->RegisterNatives(env,
		(*env)->FindClass(env, clazz),
		methods,
		num);

	if (err != JNI_OK) {
		LOGW("Error Register Methods for %s", clazz);
	}
}
void RegisterRawAES (JNIEnv *env) {
	static JNINativeMethod methods[]  = {
		{ "Encrypto",      "([BI)[B", (void*)Encrypto },
		{ "Decrypto",      "([BI)[B", (void*)Decrypto }
	};
	RegisterNativeMethods(env, "com/jia13/youyue/crypto/AES", methods,
		sizeof(methods)/sizeof(methods[0]));
}
void RegisterBase64 (JNIEnv *env) {
	static JNINativeMethod methods[]  = {
		{ "encode",      "([B)[B", (void*)Base64Encode },
		{ "decode",      "([B)[B", (void*)Base64Decode }
	};
	RegisterNativeMethods(env, "com/jia13/youyue/crypto/Base64", methods,
		sizeof(methods)/sizeof(methods[0]));
}
