#include <jni.h>
#include <memory>
#include <iostream>
#include <sstream>
extern "C" {
#include <android/log.h>
}

#include "net_sergeych_ttcrypt_RsaKey.h"
#include "net_sergeych_ttcrypt_RsaKey_Error.h"

#include "ttcrypt/rsa_key.h"
#include "ttcrypt/pollard_rho.h"
#include "ttcrypt/rijndael.h"

using namespace ttcrypt;

static jfieldID instanceId;

std::shared_ptr<char> bb1;
std::function<void(void)> *pfun1;

JNIEXPORT void JNICALL Java_net_sergeych_ttcrypt_RsaKey_staticInit
(JNIEnv *env, jclass cls) {

	instanceId = env->GetFieldID(cls, "instancePtr", "J");
}

inline rsa_key* rsa(JNIEnv* env, jobject obj) {
	return (rsa_key*) env->GetLongField(obj, instanceId);
}

JNIEXPORT void JNICALL Java_net_sergeych_ttcrypt_RsaKey_freeResources
(JNIEnv *env, jobject obj) {
	auto key = rsa(env, obj);
	if( key )
		delete key;
	env->SetLongField(obj, instanceId, 0);
}

JNIEXPORT jint JNICALL Java_net_sergeych_ttcrypt_RsaKey_bits(JNIEnv *e,
		jobject o) {
	return rsa(e, o)->size_in_bits();
}

byte_buffer array2buffer(JNIEnv *env, jbyteArray array) {
	jboolean isCopy = false;
	jsize len = env->GetArrayLength(array);
	jbyte* data = env->GetByteArrayElements(array, &isCopy);
	byte_buffer res((byte*) data, (size_t) len);
	env->ReleaseByteArrayElements(array, data, JNI_ABORT);
	return res;
}

jbyteArray buffer2array(JNIEnv *env, const byte_buffer& buffer) {
	jbyteArray res = env->NewByteArray(buffer.size());
	jbyte *data = env->GetByteArrayElements(res, NULL);
	memcpy(data, buffer.data().get(), buffer.size());
	env->ReleaseByteArrayElements(res, data, JNI_COMMIT);
	return res;
}

string java2string(JNIEnv* env, jstring jstr) {
	const char* str = env->GetStringUTFChars(jstr, 0);
	string res(str);
	env->ReleaseStringUTFChars(jstr, str);
	return res;
}

jint throwNoClassDefError(JNIEnv *env, const char *message) {
	jclass exClass;
	char *className = (char*) "java/lang/NoClassDefFoundError";

	exClass = env->FindClass(className);
	if (exClass == NULL) {
		return 0;
	}

	return env->ThrowNew(exClass, (char*) message);
}

jint throwError(JNIEnv *env, const char* className, const char *message) {
	jclass exClass;

	exClass = env->FindClass((char*) className);
	if (exClass == NULL) {
		return throwNoClassDefError(env, (char*) className);
	}

	return env->ThrowNew(exClass, (char*) message);
}

template<typename Ret, typename Block>
Ret protect(JNIEnv *env, Block block) {
	try {
		return block();
	} catch (const rsa_key::error& e) {
		throwError(env, "net/sergeych/ttcrypt/RsaKey$Error", e.what());
	} catch (const std::exception& e) {
		throwError(env, "java/lang/RuntimeException", e.what());
	} catch (...) {
		throwError(env, "java/lang/RuntimeException",
				"RSA tests failed, no reason");
	}
	return 0;
}

void protect_void(JNIEnv *env, const std::function<void()>& block) {
	protect<int>(env, [=] {
		block();
		return 0;
	});
}

JNIEXPORT jboolean JNICALL Java_net_sergeych_ttcrypt_RsaKey_selfTest(
		JNIEnv *env, jclass self) {
	return protect<jboolean>(env,
			[=] {
				ostringstream os;
				rsa_key k = rsa_key::generate(1024);
				k.use_blinding(true);
				byte_buffer m = "hello";
				bool ok = k.self_test(os);
				if( !ok ) {
					__android_log_write(ANDROID_LOG_ERROR, "TTCRYPT", "----------------------------------------------");
					os.flush();
					string debug_str = os.str();
					__android_log_write(ANDROID_LOG_ERROR, "TTCRYPT", debug_str.c_str());
					__android_log_write(ANDROID_LOG_ERROR, "TTCRYPT", "----------------------------------------------");
				}
				return ok;
			});
}

JNIEXPORT jbyteArray JNICALL Java_net_sergeych_ttcrypt_RsaKey__1sign(
		JNIEnv *env, jobject obj, jbyteArray messageArray, jint hashMethod) {
	return protect<jbyteArray>(env,
			[=] () -> jbyteArray {
				byte_buffer (*hash)(const byte_buffer&) = hashMethod == 0 ? sha1 : sha256;
				hash=sha1;
				auto k = rsa(env, obj);
				byte_buffer signature = rsa(env, obj)->sign(array2buffer(env, messageArray), hash);
				if( !k->verify(array2buffer(env, messageArray), signature, hash) ) {
					throwError(env, "java/lang/RuntimeException", "integration tests failed");
					return nullptr;
				}
				return buffer2array(env, signature);
			});
}

JNIEXPORT jboolean JNICALL Java_net_sergeych_ttcrypt_RsaKey__1verify(
		JNIEnv *env, jobject obj, jbyteArray message, jbyteArray signature,
		jint hashMethod) {
	return protect<jboolean>(env,
			[=] {
				byte_buffer (*hash)(const byte_buffer&) = hashMethod == 0 ? sha1 : sha256;
				hash = sha1;
				return rsa(env, obj)->verify(array2buffer(env, message),
						array2buffer(env, signature), hash);
			});
}

JNIEXPORT void JNICALL Java_net_sergeych_ttcrypt_RsaKey_generate
(JNIEnv *env, jobject obj, jint bit_length) {
	protect_void(env, [=] {
				rsa_key *key = new rsa_key();
				*key = rsa_key::generate(bit_length);
				env->SetLongField(obj, instanceId, (long)key);
			});
}

JNIEXPORT jbyteArray JNICALL Java_net_sergeych_ttcrypt_RsaKey_getParam(
		JNIEnv *env, jobject obj, jstring name) {
	return protect<jbyteArray>(env,
			[=] {
				auto params = rsa(env, obj)->get_params();
				return buffer2array(env, params[java2string(env, name)].to_byte_buffer());
			});
}

JNIEXPORT void JNICALL Java_net_sergeych_ttcrypt_RsaKey_setParam
(JNIEnv *env, jobject obj, jstring name, jbyteArray value) {
	protect_void(env, [=] {
				rsa_key *k = rsa(env,obj);
				if( !k ) {
					k = new rsa_key();
					env->SetLongField(obj, instanceId, (long)k);

				}
				k->set(java2string(env,name), array2buffer(env,value));
			});
}

JNIEXPORT void JNICALL Java_net_sergeych_ttcrypt_RsaKey_normalizeKey
(JNIEnv *env, jobject obj) {
	protect_void(env, [=] {
				rsa(env,obj)->normalize_key();
			});
}

JNIEXPORT jboolean JNICALL Java_net_sergeych_ttcrypt_RsaKey_hasPrivate(
		JNIEnv *env, jobject obj) {
	return protect<jboolean>(env, [=] {
		return rsa(env,obj)->is_private();
	});
}

JNIEXPORT jobjectArray JNICALL
Java_net_sergeych_ttcrypt_RsaKey_factorize(JNIEnv *env, jclass type, jbyteArray product_) {
	return protect<jobjectArray>(env,
							   [=] {
								   auto source = array2buffer(env, product_);
								   vector<ttcrypt::big_integer> factors = ttcrypt::pollard_rho::factorize(source, 25);

								   jobjectArray array = env->NewObjectArray(factors.size(), env->FindClass("[B"),
																			nullptr );
								   for(unsigned i=0; i<factors.size(); i++) {
									   jbyteArray element = buffer2array(env, factors[i].to_byte_buffer() );
									   env->SetObjectArrayElement(array, i, element);
								   }
								   return array;
							   });
}

JNIEXPORT void JNICALL
Java_net_sergeych_ttcrypt_RJ256__1cipherBlock(JNIEnv *env, jclass type, jboolean encrypt,
											  jbyteArray key_, jbyteArray block_) {
	jbyte *key = env->GetByteArrayElements(key_, NULL);
	jbyte *block = env->GetByteArrayElements(block_, NULL);

	RI ri;
	rj256_set_key( &ri, (byte *) key);
	if( encrypt )
		rj256_encrypt( &ri, (byte*) block );
	else
		rj256_decrypt( &ri, (byte*) block );

	env->ReleaseByteArrayElements(key_, key, 0);
	env->ReleaseByteArrayElements(block_, block, 0);
}