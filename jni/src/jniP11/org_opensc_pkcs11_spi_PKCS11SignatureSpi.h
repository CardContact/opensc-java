/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jnix.h>
/* Header for class org_opensc_pkcs11_spi_PKCS11SignatureSpi */

#ifndef _Included_org_opensc_pkcs11_spi_PKCS11SignatureSpi
#define _Included_org_opensc_pkcs11_spi_PKCS11SignatureSpi
#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     org_opensc_pkcs11_spi_PKCS11SignatureSpi
 * Method:    initSignNative
 * Signature: (JJJJI)V
 */
JNIEXPORT void JNICALL JNIX_FUNC_NAME(Java_org_opensc_pkcs11_spi_PKCS11SignatureSpi_initSignNative)
  (JNIEnv *, jobject, jlong, jlong, jlong, jlong, jint);

/*
 * Class:     org_opensc_pkcs11_spi_PKCS11SignatureSpi
 * Method:    updateSignNative
 * Signature: (JJJ[BII)V
 */
JNIEXPORT void JNICALL JNIX_FUNC_NAME(Java_org_opensc_pkcs11_spi_PKCS11SignatureSpi_updateSignNative)
  (JNIEnv *, jobject, jlong, jlong, jlong, jbyteArray, jint, jint);

/*
 * Class:     org_opensc_pkcs11_spi_PKCS11SignatureSpi
 * Method:    updateSignNative1
 * Signature: (JJJB)V
 */
JNIEXPORT void JNICALL JNIX_FUNC_NAME(Java_org_opensc_pkcs11_spi_PKCS11SignatureSpi_updateSignNative1)
  (JNIEnv *, jobject, jlong, jlong, jlong, jbyte);

/*
 * Class:     org_opensc_pkcs11_spi_PKCS11SignatureSpi
 * Method:    signNative
 * Signature: (JJJ)[B
 */
JNIEXPORT jbyteArray JNICALL JNIX_FUNC_NAME(Java_org_opensc_pkcs11_spi_PKCS11SignatureSpi_signNative)
  (JNIEnv *, jobject, jlong, jlong, jlong);

/*
 * Class:     org_opensc_pkcs11_spi_PKCS11SignatureSpi
 * Method:    initVerifyNative
 * Signature: (JJJJI)V
 */
JNIEXPORT void JNICALL JNIX_FUNC_NAME(Java_org_opensc_pkcs11_spi_PKCS11SignatureSpi_initVerifyNative)
  (JNIEnv *, jobject, jlong, jlong, jlong, jlong, jint);

/*
 * Class:     org_opensc_pkcs11_spi_PKCS11SignatureSpi
 * Method:    updateVerifyNative
 * Signature: (JJJ[BII)V
 */
JNIEXPORT void JNICALL JNIX_FUNC_NAME(Java_org_opensc_pkcs11_spi_PKCS11SignatureSpi_updateVerifyNative)
  (JNIEnv *, jobject, jlong, jlong, jlong, jbyteArray, jint, jint);

/*
 * Class:     org_opensc_pkcs11_spi_PKCS11SignatureSpi
 * Method:    updateVerifyNative1
 * Signature: (JJJB)V
 */
JNIEXPORT void JNICALL JNIX_FUNC_NAME(Java_org_opensc_pkcs11_spi_PKCS11SignatureSpi_updateVerifyNative1)
  (JNIEnv *, jobject, jlong, jlong, jlong, jbyte);

/*
 * Class:     org_opensc_pkcs11_spi_PKCS11SignatureSpi
 * Method:    verifyNative
 * Signature: (JJJ[B)Z
 */
JNIEXPORT jboolean JNICALL JNIX_FUNC_NAME(Java_org_opensc_pkcs11_spi_PKCS11SignatureSpi_verifyNative)
  (JNIEnv *, jobject, jlong, jlong, jlong, jbyteArray);

#ifdef __cplusplus
}
#endif
#endif
