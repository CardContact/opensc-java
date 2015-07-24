/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jnix.h>
/* Header for class org_opensc_pkcs11_wrap_PKCS11Object */

#ifndef _Included_org_opensc_pkcs11_wrap_PKCS11Object
#define _Included_org_opensc_pkcs11_wrap_PKCS11Object
#ifdef __cplusplus
extern "C" {
#endif
#undef org_opensc_pkcs11_wrap_PKCS11Object_CKO_CERTIFICATE
#define org_opensc_pkcs11_wrap_PKCS11Object_CKO_CERTIFICATE 1L
#undef org_opensc_pkcs11_wrap_PKCS11Object_CKO_PUBLIC_KEY
#define org_opensc_pkcs11_wrap_PKCS11Object_CKO_PUBLIC_KEY 2L
#undef org_opensc_pkcs11_wrap_PKCS11Object_CKO_PRIVATE_KEY
#define org_opensc_pkcs11_wrap_PKCS11Object_CKO_PRIVATE_KEY 3L
#undef org_opensc_pkcs11_wrap_PKCS11Object_CKO_SECRET_KEY
#define org_opensc_pkcs11_wrap_PKCS11Object_CKO_SECRET_KEY 4L
/*
 * Class:     org_opensc_pkcs11_wrap_PKCS11Object
 * Method:    enumObjectsNative
 * Signature: (JJJ[Lorg/opensc/pkcs11/wrap/PKCS11Attribute;)[J
 */
JNIEXPORT jlongArray JNICALL JNIX_FUNC_NAME(Java_org_opensc_pkcs11_wrap_PKCS11Object_enumObjectsNative)
  (JNIEnv *, jclass, jlong, jlong, jlong, jobjectArray);

/*
 * Class:     org_opensc_pkcs11_wrap_PKCS11Object
 * Method:    getAttributeNative
 * Signature: (JJJJI)[B
 */
JNIEXPORT jbyteArray JNICALL JNIX_FUNC_NAME(Java_org_opensc_pkcs11_wrap_PKCS11Object_getAttributeNative)
  (JNIEnv *, jclass, jlong, jlong, jlong, jlong, jint);

/*
 * Class:     org_opensc_pkcs11_wrap_PKCS11Object
 * Method:    getULongAttributeNative
 * Signature: (JJJJI)I
 */
JNIEXPORT jint JNICALL JNIX_FUNC_NAME(Java_org_opensc_pkcs11_wrap_PKCS11Object_getULongAttributeNative)
  (JNIEnv *, jclass, jlong, jlong, jlong, jlong, jint);

/*
 * Class:     org_opensc_pkcs11_wrap_PKCS11Object
 * Method:    getBooleanAttributeNative
 * Signature: (JJJJI)Z
 */
JNIEXPORT jboolean JNICALL JNIX_FUNC_NAME(Java_org_opensc_pkcs11_wrap_PKCS11Object_getBooleanAttributeNative)
  (JNIEnv *, jclass, jlong, jlong, jlong, jlong, jint);

/*
 * Class:     org_opensc_pkcs11_wrap_PKCS11Object
 * Method:    getAllowedMechanismsNative
 * Signature: (JJJJ)[Lorg/opensc/pkcs11/wrap/PKCS11Mechanism;
 */
JNIEXPORT jobjectArray JNICALL JNIX_FUNC_NAME(Java_org_opensc_pkcs11_wrap_PKCS11Object_getAllowedMechanismsNative)
  (JNIEnv *, jclass, jlong, jlong, jlong, jlong);

/*
 * Class:     org_opensc_pkcs11_wrap_PKCS11Object
 * Method:    createObjectNative
 * Signature: (JJJ[Lorg/opensc/pkcs11/wrap/PKCS11Attribute;)J
 */
JNIEXPORT jlong JNICALL JNIX_FUNC_NAME(Java_org_opensc_pkcs11_wrap_PKCS11Object_createObjectNative)
  (JNIEnv *, jclass, jlong, jlong, jlong, jobjectArray);

/*
 * Class:     org_opensc_pkcs11_wrap_PKCS11Object
 * Method:    deleteObjectNative
 * Signature: (JJJJ)V
 */
JNIEXPORT void JNICALL JNIX_FUNC_NAME(Java_org_opensc_pkcs11_wrap_PKCS11Object_deleteObjectNative)
  (JNIEnv *, jclass, jlong, jlong, jlong, jlong);

#ifdef __cplusplus
}
#endif
#endif