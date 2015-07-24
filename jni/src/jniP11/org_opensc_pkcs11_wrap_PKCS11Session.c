/* jniP11, a JCE cryptographic povider in top of PKCS#11 API
 *
 * Copyright (C) 2006 by ev-i Informationstechnologie GmbH www.ev-i.at
 *
 * Many code-snippets imported from libp11, which is
 *
 * Copyright (C) 2005 Olaf Kirch <okir@lst.de>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 */

#include <org_opensc_pkcs11_wrap_PKCS11Session.h>

#include <jniP11private.h>


/*
 * Populate mechanism structure from Java Object
 */
void mechanismFromJavaObject(JNIEnv *env, CK_MECHANISM_PTR mech, jobject jobj)
{
	jclass jbytearrayclazz;

	mech->ulParameterLen = 0;
	mech->pParameter = 0;

	if (jobj != 0) {
		jbytearrayclazz = (*env)->FindClass(env, "[B");

		if ((*env)->IsInstanceOf(env, jobj, jbytearrayclazz)) {
			allocaCArrayFromJByteArray(mech->pParameter,mech->ulParameterLen, env, jobj);
		} else {
			// Add other types
		}
	}
}


/*
 * Class:     org_opensc_pkcs11_wrap_PKCS11Session
 * Method:    openNative
 * Signature: (JJI)J
 */
JNIEXPORT jlong JNICALL JNIX_FUNC_NAME(Java_org_opensc_pkcs11_wrap_PKCS11Session_openNative)
  (JNIEnv *env, jclass jsession, jlong mh, jlong shandle, jint rw)
{
  int rv;
  CK_SESSION_HANDLE hsession;
  pkcs11_slot_t *slot;
  pkcs11_module_t *mod =  pkcs11_module_from_jhandle(env,mh);
  if (!mod) return 0;

  slot = pkcs11_slot_from_jhandle(env,shandle);
  if (!slot) return 0;


  rv = mod->method->C_OpenSession(slot->id,
                                  rw ? (CKF_SERIAL_SESSION | CKF_RW_SESSION) : (CKF_SERIAL_SESSION),
                                  NULL, NULL,
                                  &hsession);
  if (rv != CKR_OK)
    {
      jnixThrowExceptionI(env,"org/opensc/pkcs11/wrap/PKCS11Exception",rv,
                         "C_OpenSession for PKCS11 slot %d failed.",
                         (int)slot->id);
      return 0;
    }

   return hsession;
}

/*
 * Class:     org_opensc_pkcs11_wrap_PKCS11Session
 * Method:    closeNative
 * Signature: (JJJ)V
 */
JNIEXPORT void JNICALL JNIX_FUNC_NAME(Java_org_opensc_pkcs11_wrap_PKCS11Session_closeNative)
  (JNIEnv *env, jclass jsession, jlong mh, jlong shandle, jlong hsession)
{
  int rv;
  pkcs11_slot_t *slot;
  pkcs11_module_t *mod =  pkcs11_module_from_jhandle(env,mh);
  if (!mod) return;

  slot = pkcs11_slot_from_jhandle(env,shandle);
  if (!slot) return;

  rv = mod->method->C_CloseSession(hsession);
  if (rv != CKR_OK)
    {
      fprintf(stderr,"pkcs11_slot_close_session: C_CloseSession for PKCS11 slot %d(" PKCS11_MOD_NAME_FMT ") failed.",
              (int)slot->id,mod->name);
    }
}

/*
 * Class:     org_opensc_pkcs11_wrap_PKCS11Session
 * Method:    loginNative
 * Signature: (JJJI[B)V
 */
JNIEXPORT void JNICALL JNIX_FUNC_NAME(Java_org_opensc_pkcs11_wrap_PKCS11Session_loginNative)
  (JNIEnv *env, jobject jsession, jlong mh, jlong shandle, jlong hsession, jint type, jbyteArray jpin)
{
  int rv;
  CK_UTF8CHAR_PTR pin=0;
  CK_ULONG pin_len=0;
  pkcs11_slot_t *slot;
  pkcs11_module_t *mod =  pkcs11_module_from_jhandle(env,mh);
  if (!mod) return;

  slot = pkcs11_slot_from_jhandle(env,shandle);
  if (!slot) return;

  if (jpin)
    {
      allocaCArrayFromJByteArray(pin,pin_len,env,jpin);
    }

  rv = mod->method->C_Login(hsession,type,pin,pin_len);
  if (rv != CKR_OK)
    {
      jnixThrowExceptionI(env,"org/opensc/pkcs11/wrap/PKCS11Exception",rv,
                         "C_Login for PKCS11 slot %d failed.",
                         (int)slot->id);
      return;
    }
}

/*
 * Class:     org_opensc_pkcs11_wrap_PKCS11Session
 * Method:    logoutNative
 * Signature: (JJJ)V
 */
JNIEXPORT void JNICALL JNIX_FUNC_NAME(Java_org_opensc_pkcs11_wrap_PKCS11Session_logoutNative)
  (JNIEnv *env, jobject jsession, jlong mh, jlong shandle, jlong hsession)
{
  int rv;
  pkcs11_slot_t *slot;
  pkcs11_module_t *mod =  pkcs11_module_from_jhandle(env,mh);
  if (!mod) return;

  slot = pkcs11_slot_from_jhandle(env,shandle);
  if (!slot) return;

  rv = mod->method->C_Logout(hsession);
  if (rv != CKR_OK)
    {
      fprintf(stderr,"PKCS11Session.logoutNative: C_Logout for PKCS11 slot %d(" PKCS11_MOD_NAME_FMT ") failed (%s).",
              (int)slot->id,mod->name,pkcs11_strerror(rv));
    }
}

/*
 * Class:     org_opensc_pkcs11_wrap_PKCS11Session
 * Method:    initPINNative
 * Signature: (JJJ[B)V
 */
JNIEXPORT void JNICALL JNIX_FUNC_NAME(Java_org_opensc_pkcs11_wrap_PKCS11Session_initPINNative)
  (JNIEnv *env, jobject jsession, jlong mh, jlong shandle, jlong hsession, jbyteArray jpin)
{
  int rv;
  CK_UTF8CHAR_PTR pin=0;
  CK_ULONG pin_len=0;
  pkcs11_slot_t *slot;
  pkcs11_module_t *mod =  pkcs11_module_from_jhandle(env,mh);
  if (!mod) return;

  slot = pkcs11_slot_from_jhandle(env,shandle);
  if (!slot) return;

  if (jpin)
    {
      allocaCArrayFromJByteArray(pin,pin_len,env,jpin);
    }

  rv = mod->method->C_InitPIN(hsession,pin,pin_len);
  if (rv != CKR_OK)
    {
      jnixThrowExceptionI(env,"org/opensc/pkcs11/wrap/PKCS11Exception",rv,
                         "C_InitPIN for PKCS11 slot %d failed.",
                         (int)slot->id);
      return;
    }
}

/*
 * Class:     org_opensc_pkcs11_wrap_PKCS11Session
 * Method:    setPINNative
 * Signature: (JJJ[B[B)V
 */
JNIEXPORT void JNICALL JNIX_FUNC_NAME(Java_org_opensc_pkcs11_wrap_PKCS11Session_setPINNative)
  (JNIEnv *env, jobject jsession, jlong mh, jlong shandle, jlong hsession, jbyteArray joldpin, jbyteArray jnewpin)
{
  int rv;
  CK_UTF8CHAR_PTR oldpin=0;
  CK_ULONG oldpin_len=0;
  CK_UTF8CHAR_PTR newpin=0;
  CK_ULONG newpin_len=0;
  pkcs11_slot_t *slot;
  pkcs11_module_t *mod =  pkcs11_module_from_jhandle(env,mh);
  if (!mod) return;

  slot = pkcs11_slot_from_jhandle(env,shandle);
  if (!slot) return;

  if (joldpin)
    {
      allocaCArrayFromJByteArray(oldpin,oldpin_len,env,joldpin);
    }

  if (jnewpin)
    {
      allocaCArrayFromJByteArray(newpin,newpin_len,env,jnewpin);
    }

  rv = mod->method->C_SetPIN(hsession,oldpin,oldpin_len,newpin,newpin_len);
  if (rv != CKR_OK)
    {
      jnixThrowExceptionI(env,"org/opensc/pkcs11/wrap/PKCS11Exception",rv,
                         "C_SetPIN for PKCS11 slot %d failed.",
                         (int)slot->id);
      return;
    }
}



/*
 * Class:     org_opensc_pkcs11_wrap_PKCS11Session
 * Method:    signInitNative
 * Signature: (JJJJI[B)V
 */
JNIEXPORT void JNICALL JNIX_FUNC_NAME(Java_org_opensc_pkcs11_wrap_PKCS11Session_signInitNative)
  (JNIEnv *env, jclass cls, jlong mh, jlong shandle, jlong hsession, jlong hkey, jint mech, jbyteArray param)
{
  int rv;
  CK_MECHANISM mechanism;
  pkcs11_slot_t *slot;

  pkcs11_module_t *mod =  pkcs11_module_from_jhandle(env,mh);
  if (!mod) return;

  slot = pkcs11_slot_from_jhandle(env,shandle);
  if (!slot) return;

  memset(&mechanism, 0, sizeof(mechanism));
  mechanism.mechanism = mech;

  if (param) {
      mechanism.ulParameterLen = (*env)->GetArrayLength(env, param);
      mechanism.pParameter = alloca(mechanism.ulParameterLen);
      (*env)->GetByteArrayRegion(env,param,0,mechanism.ulParameterLen,(jbyte*)mechanism.pParameter);
  }

  rv = mod->method->C_SignInit(hsession,&mechanism,hkey);

  if (rv  != CKR_OK)
    {
      jnixThrowExceptionI(env,"org/opensc/pkcs11/wrap/PKCS11Exception",rv,
                          "C_SignInit failed for slot %d.",
                          (int)slot->id);
      return;
    }
}



/*
 * Class:     org_opensc_pkcs11_wrap_PKCS11Session
 * Method:    signUpdateNative
 * Signature: (JJJ[BII)V
 */
JNIEXPORT void JNICALL JNIX_FUNC_NAME(Java_org_opensc_pkcs11_wrap_PKCS11Session_signUpdateNative)
  (JNIEnv *env, jclass cls, jlong mh, jlong shandle, jlong hsession, jbyteArray ba, jint off, jint len)
{
  int rv;
  CK_BYTE_PTR pPart;
  pkcs11_slot_t *slot;
  pkcs11_module_t *mod =  pkcs11_module_from_jhandle(env,mh);

  if (!mod) return;

  slot = pkcs11_slot_from_jhandle(env,shandle);
  if (!slot) return;

  if (len < 0)
    {
      jnixThrowException(env,"org/opensc/pkcs11/wrap/PKCS11Exception",
                         "Invalid data length %d.",(int)len);
      return;
    }

  if (ba == NULL)
    {
      jnixThrowException(env,"org/opensc/pkcs11/wrap/PKCS11Exception",
                         "NULL input data.");
      return;
    }

  if (off < 0)
    {
      jnixThrowException(env,"org/opensc/pkcs11/wrap/PKCS11Exception",
                         "Invalid input offset %d.",(int)off);
      return;
    }

  allocaCArrayFromJByteArrayOffLen(pPart,env,ba,off,len);

  rv = mod->method->C_SignUpdate(hsession,pPart,len);

  if (rv  != CKR_OK)
    {
      jnixThrowExceptionI(env,"org/opensc/pkcs11/wrap/PKCS11Exception",rv,
                          "C_SignUpdate failed for slot %d.",
                          (int)slot->id);
      return;
    }
}



/*
 * Class:     org_opensc_pkcs11_wrap_PKCS11Session
 * Method:    signUpdateByteNative
 * Signature: (JJJB)V
 */
JNIEXPORT void JNICALL JNIX_FUNC_NAME(Java_org_opensc_pkcs11_wrap_PKCS11Session_signUpdateByteNative)
  (JNIEnv *env, jclass cls, jlong mh, jlong shandle, jlong hsession, jbyte b)
{
  int rv;
  CK_BYTE bb;
  pkcs11_slot_t *slot;
  pkcs11_module_t *mod =  pkcs11_module_from_jhandle(env,mh);
  if (!mod) return;

  slot = pkcs11_slot_from_jhandle(env,shandle);
  if (!slot) return;

  bb = (CK_BYTE)b;

  rv = mod->method->C_SignUpdate(hsession,&bb,1);

  if (rv  != CKR_OK)
    {
      jnixThrowExceptionI(env,"org/opensc/pkcs11/wrap/PKCS11Exception",rv,
                          "C_SignUpdate failed for slot %d.",
                          (int)slot->id);
      return;
    }
}



/*
 * Class:     org_opensc_pkcs11_wrap_PKCS11Session
 * Method:    signFinalNative
 * Signature: (JJJ)[B
 */
JNIEXPORT jbyteArray JNICALL JNIX_FUNC_NAME(Java_org_opensc_pkcs11_wrap_PKCS11Session_signFinalNative)
  (JNIEnv *env, jclass cls, jlong mh, jlong shandle, jlong hsession)
{
  int rv;
  CK_BYTE_PTR pSignature = NULL;
  CK_ULONG    ulSignatureLen = 0;
  jbyteArray ret;
  pkcs11_slot_t *slot;
  pkcs11_module_t *mod =  pkcs11_module_from_jhandle(env,mh);
  if (!mod) return 0;

  slot = pkcs11_slot_from_jhandle(env,shandle);
  if (!slot) return 0;

  rv = mod->method->C_SignFinal(hsession,pSignature,&ulSignatureLen);

  if (rv  != CKR_OK)
    {
      jnixThrowExceptionI(env,"org/opensc/pkcs11/wrap/PKCS11Exception",rv,
                          "C_SignFinal failed for slot %d.",
                          (int)slot->id);
      return 0;
    }

  pSignature = (CK_BYTE_PTR)alloca(ulSignatureLen);

  rv = mod->method->C_SignFinal(hsession,pSignature,&ulSignatureLen);

  if (rv  != CKR_OK)
    {
      jnixThrowExceptionI(env,"org/opensc/pkcs11/wrap/PKCS11Exception",rv,
                          "C_SignFinal failed for slot %d.",
                          (int)slot->id);
      return 0;
    }

  ret = (*env)->NewByteArray(env,ulSignatureLen);
  if (ret)
    (*env)->SetByteArrayRegion(env,ret,0,ulSignatureLen,(jbyte*)pSignature);

  return ret;
}



/*
 * Class:     org_opensc_pkcs11_wrap_PKCS11Session
 * Method:    signNative
 * Signature: (JJJ[BII)[B
 */
JNIEXPORT jbyteArray JNICALL JNIX_FUNC_NAME(Java_org_opensc_pkcs11_wrap_PKCS11Session_signNative)
  (JNIEnv *env, jclass cls, jlong mh, jlong shandle, jlong hsession, jbyteArray ba, jint off, jint len)
{
  int rv;
  CK_BYTE_PTR pMessage = NULL;
  CK_BYTE_PTR pSignature = NULL;
  CK_ULONG    ulSignatureLen = 0;
  jbyteArray ret;
  pkcs11_slot_t *slot;
  pkcs11_module_t *mod =  pkcs11_module_from_jhandle(env,mh);
  if (!mod) return 0;

  slot = pkcs11_slot_from_jhandle(env,shandle);
  if (!slot) return 0;

  if (len < 0)
    {
      jnixThrowException(env,"org/opensc/pkcs11/wrap/PKCS11Exception",
                         "Invalid data length %d.",(int)len);
      return NULL;
    }

  if (ba == NULL)
    {
      jnixThrowException(env,"org/opensc/pkcs11/wrap/PKCS11Exception",
                         "NULL input data.");
      return NULL;
    }

  if (off < 0)
    {
      jnixThrowException(env,"org/opensc/pkcs11/wrap/PKCS11Exception",
                         "Invalid input offset %d.",(int)off);
      return NULL;
    }

  allocaCArrayFromJByteArrayOffLen(pMessage,env,ba,off,len);

  rv = mod->method->C_Sign(hsession,pMessage,len,pSignature,&ulSignatureLen);

  if (rv  != CKR_OK)
    {
      jnixThrowExceptionI(env,"org/opensc/pkcs11/wrap/PKCS11Exception",rv,
                          "C_Sign failed for slot %d.",
                          (int)slot->id);
      return NULL;
    }

  pSignature = (CK_BYTE_PTR)alloca(ulSignatureLen);

  rv = mod->method->C_Sign(hsession,pMessage,len,pSignature,&ulSignatureLen);

  if (rv  != CKR_OK)
    {
      jnixThrowExceptionI(env,"org/opensc/pkcs11/wrap/PKCS11Exception",rv,
                          "C_SignFinal failed for slot %d.",
                          (int)slot->id);
      return NULL;
    }

  ret = (*env)->NewByteArray(env,ulSignatureLen);
  if (ret)
    (*env)->SetByteArrayRegion(env,ret,0,ulSignatureLen,(jbyte*)pSignature);

  return ret;
}



/*
 * Class:     org_opensc_pkcs11_wrap_PKCS11Session
 * Method:    verifyInitNative
 * Signature: (JJJJI[B)V
 */
JNIEXPORT void JNICALL JNIX_FUNC_NAME(Java_org_opensc_pkcs11_wrap_PKCS11Session_verifyInitNative)
  (JNIEnv *env, jclass cls, jlong mh, jlong shandle, jlong hsession, jlong hkey, jint alg, jbyteArray param)

{
  int rv;
  CK_MECHANISM mechanism;
  pkcs11_slot_t *slot;
  pkcs11_module_t *mod =  pkcs11_module_from_jhandle(env,mh);
  if (!mod) return;

  slot = pkcs11_slot_from_jhandle(env,shandle);
  if (!slot) return;

  memset(&mechanism, 0, sizeof(mechanism));
  mechanism.mechanism = alg;

  if (param) {
      mechanism.ulParameterLen = (*env)->GetArrayLength(env, param);
      mechanism.pParameter = alloca(mechanism.ulParameterLen);
      (*env)->GetByteArrayRegion(env,param,0,mechanism.ulParameterLen,(jbyte*)mechanism.pParameter);
  }

  rv = mod->method->C_VerifyInit(hsession,&mechanism,hkey);

  if (rv  != CKR_OK)
    {
      jnixThrowExceptionI(env,"org/opensc/pkcs11/wrap/PKCS11Exception",rv,
                          "C_VerifyInit failed for slot %d.",
                          (int)slot->id);
      return;
    }
}



/*
 * Class:     org_opensc_pkcs11_wrap_PKCS11Session
 * Method:    verifyUpdateNative
 * Signature: (JJJ[BII)V
 */
JNIEXPORT void JNICALL JNIX_FUNC_NAME(Java_org_opensc_pkcs11_wrap_PKCS11Session_verifyUpdateNative)
  (JNIEnv *env, jclass cls, jlong mh, jlong shandle, jlong hsession, jbyteArray data, jint off, jint len)
{
  int rv;
  CK_BYTE_PTR pPart;
  pkcs11_slot_t *slot;
  pkcs11_module_t *mod =  pkcs11_module_from_jhandle(env,mh);
  if (!mod) return;

  slot = pkcs11_slot_from_jhandle(env,shandle);
  if (!slot) return;

  if (len < 0)
    {
      jnixThrowException(env,"org/opensc/pkcs11/wrap/PKCS11Exception",
                         "Invalid data length %d.",(int)len);
      return;
    }

  if (data == NULL)
    {
      jnixThrowException(env,"org/opensc/pkcs11/wrap/PKCS11Exception",
                         "NULL input data.");
      return;
    }

  if (off < 0 || off > len)
    {
      jnixThrowException(env,"org/opensc/pkcs11/wrap/PKCS11Exception",
                         "Invalid input offset %d.",(int)off);
      return;
    }


  allocaCArrayFromJByteArrayOffLen(pPart,env,data,off,len);

  rv = mod->method->C_VerifyUpdate(hsession,pPart,len);

  if (rv  != CKR_OK)
    {
      jnixThrowExceptionI(env,"org/opensc/pkcs11/wrap/PKCS11Exception",rv,
                          "C_VerifyUpdate failed for slot %d.",
                          (int)slot->id);
      return;
    }
}




/*
 * Class:     org_opensc_pkcs11_wrap_PKCS11Session
 * Method:    verifyUpdateByteNative
 * Signature: (JJJB)V
 */
JNIEXPORT void JNICALL JNIX_FUNC_NAME(Java_org_opensc_pkcs11_wrap_PKCS11Session_verifyUpdateByteNative)
  (JNIEnv *env, jclass cls, jlong mh, jlong shandle, jlong hsession, jbyte b)
{ 
  int rv;
  CK_BYTE bb = (CK_BYTE)b;
  pkcs11_slot_t *slot;
  pkcs11_module_t *mod =  pkcs11_module_from_jhandle(env,mh);
  if (!mod) return;

  slot = pkcs11_slot_from_jhandle(env,shandle);
  if (!slot) return;

  rv = mod->method->C_VerifyUpdate(hsession,&bb,1);

  if (rv  != CKR_OK)
    {
      jnixThrowExceptionI(env,"org/opensc/pkcs11/wrap/PKCS11Exception",rv,
                          "C_VerifyUpdate failed for slot %d.",
                          (int)slot->id);
      return;
    }
}



/*
 * Class:     org_opensc_pkcs11_wrap_PKCS11Session
 * Method:    verifyFinalNative
 * Signature: (JJJ[B)Z
 */
JNIEXPORT jboolean JNICALL JNIX_FUNC_NAME(Java_org_opensc_pkcs11_wrap_PKCS11Session_verifyFinalNative)
  (JNIEnv *env, jclass cls, jlong mh, jlong shandle, jlong hsession, jbyteArray data)
{
  int rv;
  CK_BYTE_PTR pSignature;
  CK_ULONG    ulSignatureLen;
  pkcs11_slot_t *slot;
  pkcs11_module_t *mod =  pkcs11_module_from_jhandle(env,mh);
  if (!mod) return JNI_FALSE;

  slot = pkcs11_slot_from_jhandle(env,shandle);
  if (!slot) return JNI_FALSE;

  if (data == NULL)
    {
      jnixThrowException(env,"org/opensc/pkcs11/wrap/PKCS11Exception",
                         "NULL input data.");
      return JNI_FALSE;
    }

  allocaCArrayFromJByteArray(pSignature,ulSignatureLen,env,data);

  rv = mod->method->C_VerifyFinal(hsession,pSignature,ulSignatureLen);

  switch (rv)
    {
    case CKR_SIGNATURE_INVALID:
      return JNI_FALSE;

    case CKR_OK:
      return JNI_TRUE;

    default:
      jnixThrowExceptionI(env,"org/opensc/pkcs11/wrap/PKCS11Exception",rv,
                          "C_VerifyFinal failed for slot %d.",
                          (int)slot->id);
      return JNI_FALSE;
    }
}




/*
 * Class:     org_opensc_pkcs11_wrap_PKCS11Session
 * Method:    verifyNative
 * Signature: (JJJ[BII[B)Z
 */
JNIEXPORT jboolean JNICALL JNIX_FUNC_NAME(Java_org_opensc_pkcs11_wrap_PKCS11Session_verifyNative)
  (JNIEnv *env, jclass cls, jlong mh, jlong shandle, jlong hsession, jbyteArray ba, jint off, jint len, jbyteArray data)
{
  int rv;
  CK_BYTE_PTR pMessage = NULL;
  CK_BYTE_PTR pSignature;
  CK_ULONG    ulSignatureLen;
  pkcs11_slot_t *slot;
  pkcs11_module_t *mod =  pkcs11_module_from_jhandle(env,mh);
  if (!mod) return JNI_FALSE;

  slot = pkcs11_slot_from_jhandle(env,shandle);
  if (!slot) return JNI_FALSE;

  if (len < 0)
    {
      jnixThrowException(env,"org/opensc/pkcs11/wrap/PKCS11Exception",
                         "Invalid data length %d.",(int)len);
      return JNI_FALSE;
    }

  if (ba == NULL)
    {
      jnixThrowException(env,"org/opensc/pkcs11/wrap/PKCS11Exception",
                         "NULL input data.");
      return JNI_FALSE;
    }

  if (off < 0)
    {
      jnixThrowException(env,"org/opensc/pkcs11/wrap/PKCS11Exception",
                         "Invalid input offset %d.",(int)off);
      return JNI_FALSE;
    }

  allocaCArrayFromJByteArrayOffLen(pMessage,env,ba,off,len);

  if (data == NULL)
    {
      jnixThrowException(env,"org/opensc/pkcs11/wrap/PKCS11Exception",
                         "NULL input data.");
      return JNI_FALSE;
    }

  allocaCArrayFromJByteArray(pSignature,ulSignatureLen,env,data);

  rv = mod->method->C_Verify(hsession,pMessage,len,pSignature,ulSignatureLen);

  switch (rv)
    {
    case CKR_SIGNATURE_INVALID:
      return JNI_FALSE;

    case CKR_OK:
      return JNI_TRUE;

    default:
      jnixThrowExceptionI(env,"org/opensc/pkcs11/wrap/PKCS11Exception",rv,
                          "C_Verify failed for slot %d.",
                          (int)slot->id);
      return JNI_FALSE;
    }
}




/*
 * Class:     org_opensc_pkcs11_wrap_PKCS11Session
 * Method:    decryptInitNative
 * Signature: (JJJJI[B)V
 */
JNIEXPORT void JNICALL JNIX_FUNC_NAME(Java_org_opensc_pkcs11_wrap_PKCS11Session_decryptInitNative)
  (JNIEnv *env, jclass cls, jlong mh, jlong shandle, jlong hsession, jlong hkey, jint alg, jbyteArray param)
{
  int rv;
  CK_MECHANISM mechanism;
  pkcs11_slot_t *slot;

  pkcs11_module_t *mod =  pkcs11_module_from_jhandle(env,mh);
  if (!mod) return;

  slot = pkcs11_slot_from_jhandle(env,shandle);
  if (!slot) return;

  memset(&mechanism, 0, sizeof(mechanism));
  mechanism.mechanism = alg;

  if (param) {
      mechanism.ulParameterLen = (*env)->GetArrayLength(env, param);
      mechanism.pParameter = alloca(mechanism.ulParameterLen);
      (*env)->GetByteArrayRegion(env,param,0,mechanism.ulParameterLen,(jbyte*)mechanism.pParameter);
  }

  rv = mod->method->C_DecryptInit(hsession,&mechanism,hkey);

  if (rv  != CKR_OK)
    {
      jnixThrowExceptionI(env,"org/opensc/pkcs11/wrap/PKCS11Exception",rv,
                          "C_DecryptInit failed for slot %d.",
                          (int)slot->id);
      return;
    }
}




/*
 * Class:     org_opensc_pkcs11_wrap_PKCS11Session
 * Method:    encryptInitNative
 * Signature: (JJJJI[B)V
 */
JNIEXPORT void JNICALL JNIX_FUNC_NAME(Java_org_opensc_pkcs11_wrap_PKCS11Session_encryptInitNative)
  (JNIEnv *env, jclass cls, jlong mh, jlong shandle, jlong hsession, jlong hkey, jint alg, jbyteArray param)
{
  int rv;
  CK_MECHANISM mechanism;
  pkcs11_slot_t *slot;

  pkcs11_module_t *mod =  pkcs11_module_from_jhandle(env,mh);
  if (!mod) return;

  slot = pkcs11_slot_from_jhandle(env,shandle);
  if (!slot) return;

  memset(&mechanism, 0, sizeof(mechanism));
  mechanism.mechanism = alg;

  if (param) {
      mechanism.ulParameterLen = (*env)->GetArrayLength(env, param);
      mechanism.pParameter = alloca(mechanism.ulParameterLen);
      (*env)->GetByteArrayRegion(env,param,0,mechanism.ulParameterLen,(jbyte*)mechanism.pParameter);
  }

  rv = mod->method->C_EncryptInit(hsession,&mechanism,hkey);

  if (rv  != CKR_OK)
    {
      jnixThrowExceptionI(env,"org/opensc/pkcs11/wrap/PKCS11Exception",rv,
                          "C_EncryptInit failed for slot %d.",
                          (int)slot->id);
      return;
    }
}



/*
 * Class:     org_opensc_pkcs11_wrap_PKCS11Session
 * Method:    decryptUpdateNative
 * Signature: (JJJ[BII)[B
 */
JNIEXPORT jbyteArray JNICALL JNIX_FUNC_NAME(Java_org_opensc_pkcs11_wrap_PKCS11Session_decryptUpdateNative)
  (JNIEnv *env, jclass cls, jlong mh, jlong shandle, jlong hsession, jbyteArray input, jint off, jint len)
{
  int rv;
  CK_BYTE_PTR pInputPart;
  CK_BYTE_PTR pOutputPart = 0;
  CK_ULONG ulOutputLen = 0;
  jbyteArray ret;
  pkcs11_slot_t *slot;

  pkcs11_module_t *mod =  pkcs11_module_from_jhandle(env,mh);
  if (!mod) return 0;

  slot = pkcs11_slot_from_jhandle(env,shandle);
  if (!slot) return 0;

  if (len < 0)
    {
      jnixThrowException(env,"org/opensc/pkcs11/wrap/PKCS11Exception",
                         "Invalid data length %d.",(int)len);
      return 0;
    }

  if (input == NULL)
    {
      jnixThrowException(env,"org/opensc/pkcs11/wrap/PKCS11Exception",
                         "NULL input data.");
      return 0;
    }

  if (off < 0)
    {
      jnixThrowException(env,"org/opensc/pkcs11/wrap/PKCS11Exception",
                         "Invalid input offset %d.",(int)off);
      return 0;
    }

  allocaCArrayFromJByteArrayOffLen(pInputPart,env,input,off,len);

  rv = mod->method->C_DecryptUpdate(hsession,pInputPart,len,pOutputPart,&ulOutputLen);

  if (rv  != CKR_OK)
    {
      jnixThrowExceptionI(env,"org/opensc/pkcs11/wrap/PKCS11Exception",rv,
                          "C_DecryptUpdate failed for slot %d.",
                          (int)slot->id);
      return 0;
    }

  pOutputPart=alloca(ulOutputLen);

  rv = mod->method->C_DecryptUpdate(hsession,pInputPart,len,pOutputPart,&ulOutputLen);

  if (rv  != CKR_OK)
    {
      jnixThrowExceptionI(env,"org/opensc/pkcs11/wrap/PKCS11Exception",rv,
                          "C_DecryptUpdate failed for slot %d.",
                          (int)slot->id);
      return 0;
    }

  ret = (*env)->NewByteArray(env,ulOutputLen);
  if (ret)
    (*env)->SetByteArrayRegion(env,ret,0,ulOutputLen,(jbyte*)pOutputPart);
  
  return ret;
}



/*
 * Class:     org_opensc_pkcs11_wrap_PKCS11Session
 * Method:    encryptUpdateNative
 * Signature: (JJJ[BII)[B
 */
JNIEXPORT jbyteArray JNICALL JNIX_FUNC_NAME(Java_org_opensc_pkcs11_wrap_PKCS11Session_encryptUpdateNative)
  (JNIEnv *env, jclass cls, jlong mh, jlong shandle, jlong hsession, jbyteArray input, jint off, jint len)
{
  int rv;
  CK_BYTE_PTR pInputPart;
  CK_BYTE_PTR pOutputPart = 0;
  CK_ULONG ulOutputLen = 0;
  jbyteArray ret;
  pkcs11_slot_t *slot;

  pkcs11_module_t *mod =  pkcs11_module_from_jhandle(env,mh);
  if (!mod) return 0;

  slot = pkcs11_slot_from_jhandle(env,shandle);
  if (!slot) return 0;

  if (len < 0)
    {
      jnixThrowException(env,"org/opensc/pkcs11/wrap/PKCS11Exception",
                         "Invalid data length %d.",(int)len);
      return 0;
    }

  if (input == NULL)
    {
      jnixThrowException(env,"org/opensc/pkcs11/wrap/PKCS11Exception",
                         "NULL input data.");
      return 0;
    }

  if (off < 0)
    {
      jnixThrowException(env,"org/opensc/pkcs11/wrap/PKCS11Exception",
                         "Invalid input offset %d.",(int)off);
      return 0;
    }

  allocaCArrayFromJByteArrayOffLen(pInputPart,env,input,off,len);

  rv = mod->method->C_EncryptUpdate(hsession,pInputPart,len,pOutputPart,&ulOutputLen);

  if (rv  != CKR_OK)
    {
      jnixThrowExceptionI(env,"org/opensc/pkcs11/wrap/PKCS11Exception",rv,
                          "C_EncryptUpdate failed for slot %d.",
                          (int)slot->id);
      return 0;
    }

  pOutputPart=alloca(ulOutputLen);

  rv = mod->method->C_EncryptUpdate(hsession,pInputPart,len,pOutputPart,&ulOutputLen);

  if (rv  != CKR_OK)
    {
      jnixThrowExceptionI(env,"org/opensc/pkcs11/wrap/PKCS11Exception",rv,
                          "C_EncryptUpdate failed for slot %d.",
                          (int)slot->id);
      return 0;
    }

  ret = (*env)->NewByteArray(env,ulOutputLen);
  if (ret)
    (*env)->SetByteArrayRegion(env,ret,0,ulOutputLen,(jbyte*)pOutputPart);
  
  return ret;
}



/*
 * Class:     org_opensc_pkcs11_wrap_PKCS11Session
 * Method:    decryptUpdateOffNative
 * Signature: (JJJ[BII[BI)I
 */
JNIEXPORT jint JNICALL JNIX_FUNC_NAME(Java_org_opensc_pkcs11_wrap_PKCS11Session_decryptUpdateOffNative)
  (JNIEnv *env, jclass cls, jlong mh, jlong shandle, jlong hsession, jbyteArray input, jint off, jint len, jbyteArray output, jint output_off)
{
  int rv;
  CK_BYTE_PTR pOutputPart,pInputPart;
  CK_ULONG ulOutputLen;
  pkcs11_slot_t *slot;
  pkcs11_module_t *mod =  pkcs11_module_from_jhandle(env,mh);
  if (!mod) return 0;

  slot = pkcs11_slot_from_jhandle(env,shandle);
  if (!slot) return 0;

  if (len < 0)
    {
      jnixThrowException(env,"org/opensc/pkcs11/wrap/PKCS11Exception",
                         "Invalid data length %d.",(int)len);
      return 0;
    }

  if (input == NULL)
    {
      jnixThrowException(env,"org/opensc/pkcs11/wrap/PKCS11Exception",
                         "NULL input data.");
      return 0;
    }

  if (off < 0)
    {
      jnixThrowException(env,"org/opensc/pkcs11/wrap/PKCS11Exception",
                         "Invalid input offset %d.",(int)off);
      return 0;
    }

  if (output == NULL)
    {
      jnixThrowException(env,"org/opensc/pkcs11/wrap/PKCS11Exception",
                         "NULL output data.");
      return 0;
    }

  ulOutputLen = (*env)->GetArrayLength(env,output);
  
  if (output_off < 0 || output_off > ulOutputLen)
    {
      jnixThrowException(env,"org/opensc/pkcs11/wrap/PKCS11Exception",
                         "Invalid output offset %d.",(int)output_off);
      return 0;
    }
 
  ulOutputLen -= output_off;
  pOutputPart = alloca(ulOutputLen);

  allocaCArrayFromJByteArrayOffLen(pInputPart,env,input,off,len);

  rv = mod->method->C_DecryptUpdate(hsession,pInputPart,len,pOutputPart,&ulOutputLen);

  if (rv  != CKR_OK)
    {
      jnixThrowExceptionI(env,"org/opensc/pkcs11/wrap/PKCS11Exception",rv,
                         "C_DecryptUpdate failed for slot %d.",
                         (int)slot->id);
      return 0;
    }

  (*env)->SetByteArrayRegion(env,output,output_off,ulOutputLen,(jbyte*)pOutputPart);
  
  return ulOutputLen;
}



/*
 * Class:     org_opensc_pkcs11_wrap_PKCS11Session
 * Method:    encryptUpdateOffNative
 * Signature: (JJJ[BII[BI)I
 */
JNIEXPORT jint JNICALL JNIX_FUNC_NAME(Java_org_opensc_pkcs11_wrap_PKCS11Session_encryptUpdateOffNative)
  (JNIEnv *env, jclass cls, jlong mh, jlong shandle, jlong hsession, jbyteArray input, jint off, jint len, jbyteArray output, jint output_off)
{
  int rv;
  CK_ULONG ulOutputLen;
  CK_BYTE_PTR pOutputPart,pInputPart;
  pkcs11_slot_t *slot;
  pkcs11_module_t *mod =  pkcs11_module_from_jhandle(env,mh);
  if (!mod) return 0;

  slot = pkcs11_slot_from_jhandle(env,shandle);
  if (!slot) return 0;

  if (len < 0)
    {
      jnixThrowException(env,"org/opensc/pkcs11/wrap/PKCS11Exception",
                         "Invalid data length %d.",(int)len);
      return 0;
    }

  if (input == NULL)
    {
      jnixThrowException(env,"org/opensc/pkcs11/wrap/PKCS11Exception",
                         "NULL input data.");
      return 0;
    }

  if (off < 0)
    {
      jnixThrowException(env,"org/opensc/pkcs11/wrap/PKCS11Exception",
                         "Invalid input offset %d.",(int)off);
      return 0;
    }

  if (output == NULL)
    {
      jnixThrowException(env,"org/opensc/pkcs11/wrap/PKCS11Exception",
                         "NULL output data.");
      return 0;
    }

  ulOutputLen = (*env)->GetArrayLength(env,output);
  
  if (output_off < 0 || output_off > ulOutputLen)
    {
      jnixThrowException(env,"org/opensc/pkcs11/wrap/PKCS11Exception",
                         "Invalid output offset %d.",(int)output_off);
      return 0;
    }
 
  ulOutputLen -= output_off;
  pOutputPart = alloca(ulOutputLen);

  allocaCArrayFromJByteArrayOffLen(pInputPart,env,input,off,len);

  rv = mod->method->C_EncryptUpdate(hsession,pInputPart,len,pOutputPart,&ulOutputLen);

  if (rv  != CKR_OK)
    {
      jnixThrowExceptionI(env,"org/opensc/pkcs11/wrap/PKCS11Exception",rv,
                          "C_EncryptUpdate failed for slot %d.",
                          (int)slot->id);
      return 0;
    }

  (*env)->SetByteArrayRegion(env,output,output_off,ulOutputLen,(jbyte*)pOutputPart);
  
  return ulOutputLen;
}




/*
 * Class:     org_opensc_pkcs11_wrap_PKCS11Session
 * Method:    decryptFinalNative
 * Signature: (JJJ)[B
 */
JNIEXPORT jbyteArray JNICALL JNIX_FUNC_NAME(Java_org_opensc_pkcs11_wrap_PKCS11Session_decryptFinalNative)
  (JNIEnv *env, jclass cls, jlong mh, jlong shandle, jlong hsession)
{
  int rv;
  CK_BYTE_PTR pOutputPart = 0;
  CK_ULONG ulOutputLen = 0;
  jbyteArray ret;
  pkcs11_slot_t *slot;

  pkcs11_module_t *mod =  pkcs11_module_from_jhandle(env,mh);
  if (!mod) return 0;

  slot = pkcs11_slot_from_jhandle(env,shandle);
  if (!slot) return 0;

  rv = mod->method->C_DecryptFinal(hsession,pOutputPart,&ulOutputLen);

  if (rv  != CKR_OK)
    {
      jnixThrowExceptionI(env,"org/opensc/pkcs11/wrap/PKCS11Exception",rv,
                          "C_DecryptFinal failed for slot %d.",
                          (int)slot->id);
      return 0;
    }

  pOutputPart=alloca(ulOutputLen);

  rv = mod->method->C_DecryptFinal(hsession,pOutputPart,&ulOutputLen);

  if (rv  != CKR_OK)
    {
      jnixThrowExceptionI(env,"org/opensc/pkcs11/wrap/PKCS11Exception",rv,
                          "C_DecryptFinal failed for slot %d.",
                          (int)slot->id);
      return 0;
    }

  ret = 0;

  if (ulOutputLen > 0)
    { 
      ret = (*env)->NewByteArray(env,ulOutputLen);
      if (ret)
        {
          (*env)->SetByteArrayRegion(env,ret,0,ulOutputLen,(jbyte*)pOutputPart);
        }
    }
  
  return ret;
}



/*
 * Class:     org_opensc_pkcs11_wrap_PKCS11Session
 * Method:    encryptFinalNative
 * Signature: (JJJ[BII)[B
 */
JNIEXPORT jbyteArray JNICALL JNIX_FUNC_NAME(Java_org_opensc_pkcs11_wrap_PKCS11Session_encryptFinalNative)
  (JNIEnv *env, jclass cls, jlong mh, jlong shandle, jlong hsession)
{
  int rv;
  CK_BYTE_PTR pOutputPart = 0;
  CK_ULONG ulOutputLen = 0;
  jbyteArray ret;
  pkcs11_slot_t *slot;

  pkcs11_module_t *mod =  pkcs11_module_from_jhandle(env,mh);
  if (!mod) return 0;

  slot = pkcs11_slot_from_jhandle(env,shandle);
  if (!slot) return 0;

  rv = mod->method->C_EncryptFinal(hsession,pOutputPart, &ulOutputLen);

  if (rv  != CKR_OK)
    {
      jnixThrowExceptionI(env,"org/opensc/pkcs11/wrap/PKCS11Exception",rv,
                          "C_EncryptFinal failed for slot %d.",
                          (int)slot->id);
      return 0;
    }

  pOutputPart=alloca(ulOutputLen);

  rv = mod->method->C_EncryptFinal(hsession,pOutputPart,&ulOutputLen);

  if (rv  != CKR_OK)
    {
      jnixThrowExceptionI(env,"org/opensc/pkcs11/wrap/PKCS11Exception",rv,
                          "C_EncryptFinal failed for slot %d.",
                          (int)slot->id);
      return 0;
    }

  ret = 0;

  if (ulOutputLen > 0)
    { 
      ret = (*env)->NewByteArray(env,ulOutputLen);
      if (ret)
        {
          (*env)->SetByteArrayRegion(env,ret,0,ulOutputLen,(jbyte*)pOutputPart);
        }
    }

  return ret;
}



/*
 * Class:     org_opensc_pkcs11_wrap_PKCS11Session
 * Method:    decryptNative
 * Signature: (JJJ[BII)[B
 */
JNIEXPORT jbyteArray JNICALL JNIX_FUNC_NAME(Java_org_opensc_pkcs11_wrap_PKCS11Session_decryptNative)
  (JNIEnv *env, jclass cls, jlong mh, jlong shandle, jlong hsession, jbyteArray input, jint off, jint len)
{
  int rv;
  CK_BYTE_PTR pInputPart;
  CK_BYTE_PTR pOutputPart = 0;
  CK_ULONG ulOutputLen = 0;
  jbyteArray ret;
  pkcs11_slot_t *slot;

  pkcs11_module_t *mod =  pkcs11_module_from_jhandle(env,mh);
  if (!mod) return 0;

  slot = pkcs11_slot_from_jhandle(env,shandle);
  if (!slot) return 0;

  if (len < 0)
    {
      jnixThrowException(env,"org/opensc/pkcs11/wrap/PKCS11Exception",
                         "Invalid data length %d.",(int)len);
      return 0;
    }

  if (input == NULL)
    {
      jnixThrowException(env,"org/opensc/pkcs11/wrap/PKCS11Exception",
                         "NULL input data.");
      return 0;
    }

  if (off < 0)
    {
      jnixThrowException(env,"org/opensc/pkcs11/wrap/PKCS11Exception",
                         "Invalid input offset %d.",(int)off);
      return 0;
    }

  allocaCArrayFromJByteArrayOffLen(pInputPart,env,input,off,len);

  rv = mod->method->C_Decrypt(hsession,pInputPart,len,pOutputPart,&ulOutputLen);

  if (rv  != CKR_OK)
    {
      jnixThrowExceptionI(env,"org/opensc/pkcs11/wrap/PKCS11Exception",rv,
                          "C_Decrypt failed for slot %d.",
                          (int)slot->id);
      return 0;
    }

  pOutputPart=alloca(ulOutputLen);

  rv = mod->method->C_Decrypt(hsession,pInputPart,len,pOutputPart,&ulOutputLen);

  if (rv  != CKR_OK)
    {
      jnixThrowExceptionI(env,"org/opensc/pkcs11/wrap/PKCS11Exception",rv,
                          "C_Decrypt failed for slot %d.",
                          (int)slot->id);
      return 0;
    }

  ret = (*env)->NewByteArray(env,ulOutputLen);
  if (ret)
    (*env)->SetByteArrayRegion(env,ret,0,ulOutputLen,(jbyte*)pOutputPart);
  
  return ret;
}



/*
 * Class:     org_opensc_pkcs11_wrap_PKCS11Session
 * Method:    encryptNative
 * Signature: (JJJ[BII)[B
 */
JNIEXPORT jbyteArray JNICALL JNIX_FUNC_NAME(Java_org_opensc_pkcs11_wrap_PKCS11Session_encryptNative)
  (JNIEnv *env, jclass cls, jlong mh, jlong shandle, jlong hsession, jbyteArray input, jint off, jint len)
{
  int rv;
  CK_BYTE_PTR pInputPart;
  CK_BYTE_PTR pOutputPart = 0;
  CK_ULONG ulOutputLen = 0;
  jbyteArray ret;
  pkcs11_slot_t *slot;

  pkcs11_module_t *mod =  pkcs11_module_from_jhandle(env,mh);
  if (!mod) return 0;

  slot = pkcs11_slot_from_jhandle(env,shandle);
  if (!slot) return 0;

  if (len < 0)
    {
      jnixThrowException(env,"org/opensc/pkcs11/wrap/PKCS11Exception",
                         "Invalid data length %d.",(int)len);
      return 0;
    }

  if (input == NULL)
    {
      jnixThrowException(env,"org/opensc/pkcs11/wrap/PKCS11Exception",
                         "NULL input data.");
      return 0;
    }

  if (off < 0)
    {
      jnixThrowException(env,"org/opensc/pkcs11/wrap/PKCS11Exception",
                         "Invalid input offset %d.",(int)off);
      return 0;
    }

  allocaCArrayFromJByteArrayOffLen(pInputPart,env,input,off,len);

  rv = mod->method->C_Encrypt(hsession,pInputPart,len,pOutputPart,&ulOutputLen);

  if (rv  != CKR_OK)
    {
      jnixThrowExceptionI(env,"org/opensc/pkcs11/wrap/PKCS11Exception",rv,
                          "C_Encrypt failed for slot %d.",
                          (int)slot->id);
      return 0;
    }

  pOutputPart=alloca(ulOutputLen);

  rv = mod->method->C_Encrypt(hsession,pInputPart,len,pOutputPart,&ulOutputLen);

  if (rv  != CKR_OK)
    {
      jnixThrowExceptionI(env,"org/opensc/pkcs11/wrap/PKCS11Exception",rv,
                          "C_Encrypt failed for slot %d.",
                          (int)slot->id);
      return 0;
    }

  ret = (*env)->NewByteArray(env,ulOutputLen);
  if (ret)
    (*env)->SetByteArrayRegion(env,ret,0,ulOutputLen,(jbyte*)pOutputPart);
  
  return ret;
}



/*
 * Class:     org_opensc_pkcs11_wrap_PKCS11Session
 * Method:    generateKeyNative
 * Signature: (JJJI[B[Lorg/opensc/pkcs11/wrap/PKCS11Attribute;)J
 */
JNIEXPORT jlong JNICALL JNIX_FUNC_NAME(Java_org_opensc_pkcs11_wrap_PKCS11Session_generateKeyNative)
  (JNIEnv *env, jclass cls, jlong mh, jlong shandle, jlong hsession, jint algo, jobject param, jobjectArray keyAttrs)
{
	int rv;
	CK_ULONG i;
	CK_ULONG ulKeyAttributeCount;
	CK_ATTRIBUTE_PTR pKeyTemplate;
	CK_MECHANISM keyMechanism;
	CK_OBJECT_HANDLE hKey;
	jclass clazz;
	jmethodID getKindID;
	jmethodID getDataID;
	pkcs11_slot_t *slot;
	pkcs11_module_t *mod = pkcs11_module_from_jhandle(env, mh);
	if (!mod) return 0;
  
	slot = pkcs11_slot_from_jhandle(env, shandle);
	if (!slot) return 0;

	clazz = (*env)->FindClass(env,"org/opensc/pkcs11/wrap/PKCS11Attribute");

	if (!clazz) return 0;

	getKindID = (*env)->GetMethodID(env,clazz,"getKind","()I");

	if (!getKindID) return 0;

	getDataID = (*env)->GetMethodID(env,clazz,"getData","()[B");

	if (!getDataID) return 0;

	ulKeyAttributeCount = (*env)->GetArrayLength(env,keyAttrs);
	pKeyTemplate = alloca(ulKeyAttributeCount * sizeof(CK_ATTRIBUTE));

	for (i=0;i<ulKeyAttributeCount;++i) {
		jbyteArray data;
		jobject jattr = (*env)->GetObjectArrayElement(env,keyAttrs,i);
		if (!jattr) return 0;

		pKeyTemplate[i].type = (*env)->CallIntMethod(env,jattr,getKindID);

		data = (jbyteArray)(*env)->CallObjectMethod(env,jattr,getDataID);

		allocaCArrayFromJByteArray(pKeyTemplate[i].pValue,pKeyTemplate[i].ulValueLen,env,data);
	}

	keyMechanism.mechanism      = algo;
	mechanismFromJavaObject(env, &keyMechanism, param);

	rv = mod->method->C_GenerateKey(hsession, &keyMechanism,
                                      pKeyTemplate, ulKeyAttributeCount,
                                      &hKey);

	if (rv  != CKR_OK) {
		jnixThrowExceptionI(env,"org/opensc/pkcs11/wrap/PKCS11Exception",rv,
                          "C_GenerateKey failed.");
		return 0;
    }

	return hKey;
}



/*
 * Class:     org_opensc_pkcs11_wrap_PKCS11Session
 * Method:    generateKeyPairNative
 * Signature: (JJJI[B[Lorg/opensc/pkcs11/wrap/PKCS11Attribute;[Lorg/opensc/pkcs11/wrap/PKCS11Attribute;)[J
 */
JNIEXPORT jlongArray JNICALL JNIX_FUNC_NAME(Java_org_opensc_pkcs11_wrap_PKCS11Session_generateKeyPairNative)
  (JNIEnv *env, jclass cls, jlong mh, jlong shandle, jlong hsession, jint algo, jobject param, jobjectArray pubAttrs, jobjectArray privAttrs)
{
	int rv;
	CK_ULONG i;
	CK_ULONG ulPublicKeyAttributeCount;
	CK_ATTRIBUTE_PTR pPublicKeyTemplate;
	CK_ULONG ulPrivateKeyAttributeCount;
	CK_ATTRIBUTE_PTR pPrivateKeyTemplate;
	CK_MECHANISM keyPairMechanism;
	CK_OBJECT_HANDLE hPublicKey, hPrivateKey;
	jclass clazz;
	jmethodID getKindID;
	jmethodID getDataID;
	jlong buf[2];
	jlongArray ret;
	pkcs11_slot_t *slot;
	pkcs11_module_t *mod = pkcs11_module_from_jhandle(env, mh);
	if (!mod) return 0;
  
	slot = pkcs11_slot_from_jhandle(env, shandle);
	if (!slot) return 0;

	clazz = (*env)->FindClass(env,"org/opensc/pkcs11/wrap/PKCS11Attribute");

	if (!clazz) return 0;

	getKindID = (*env)->GetMethodID(env,clazz,"getKind","()I");

	if (!getKindID) return 0;

	getDataID = (*env)->GetMethodID(env,clazz,"getData","()[B");

	if (!getDataID) return 0;

	ulPublicKeyAttributeCount = (*env)->GetArrayLength(env,pubAttrs);
	pPublicKeyTemplate = alloca(ulPublicKeyAttributeCount * sizeof(CK_ATTRIBUTE));

	for (i=0;i<ulPublicKeyAttributeCount;++i) {
		jbyteArray data;
		jobject jattr = (*env)->GetObjectArrayElement(env,pubAttrs,i);
		if (!jattr) return 0;

		pPublicKeyTemplate[i].type = (*env)->CallIntMethod(env,jattr,getKindID);

		data = (jbyteArray)(*env)->CallObjectMethod(env,jattr,getDataID);

		allocaCArrayFromJByteArray(pPublicKeyTemplate[i].pValue,pPublicKeyTemplate[i].ulValueLen,env,data);
	}

	ulPrivateKeyAttributeCount = (*env)->GetArrayLength(env,privAttrs);
	pPrivateKeyTemplate = alloca(ulPrivateKeyAttributeCount * sizeof(CK_ATTRIBUTE));

	for (i=0;i<ulPrivateKeyAttributeCount;++i) {
		jbyteArray data;
		jobject jattr = (*env)->GetObjectArrayElement(env,privAttrs,i);
		if (!jattr) return 0;

		pPrivateKeyTemplate[i].type = (*env)->CallIntMethod(env,jattr,getKindID);

		data = (jbyteArray)(*env)->CallObjectMethod(env,jattr,getDataID);

		allocaCArrayFromJByteArray(pPrivateKeyTemplate[i].pValue,pPrivateKeyTemplate[i].ulValueLen,env,data);
    }

	keyPairMechanism.mechanism      = algo;
	mechanismFromJavaObject(env, &keyPairMechanism, param);

	rv = mod->method->C_GenerateKeyPair(hsession, &keyPairMechanism,
                                      pPublicKeyTemplate, ulPublicKeyAttributeCount,
                                      pPrivateKeyTemplate, ulPrivateKeyAttributeCount,
                                      &hPublicKey, &hPrivateKey);

	if (rv  != CKR_OK) {
		jnixThrowExceptionI(env,"org/opensc/pkcs11/wrap/PKCS11Exception",rv,
                          "C_GenerateKeyPair failed.");
		return 0;
    }

	ret = (*env)->NewLongArray(env,2);

	if (!ret) return 0;

	buf[0] = hPublicKey;
	buf[1] = hPrivateKey;
	(*env)->SetLongArrayRegion(env,ret,0,2,buf);

	return ret;
}



/*
 * Class:     org_opensc_pkcs11_wrap_PKCS11Session
 * Method:    wrapKeyNative
 * Signature: (JJJI[BJJ)[B
 */
JNIEXPORT jbyteArray JNICALL JNIX_FUNC_NAME(Java_org_opensc_pkcs11_wrap_PKCS11Session_wrapKeyNative)
  (JNIEnv *env, jclass cls, jlong mh, jlong shandle, jlong hsession, jint algo, jobject param, jlong wrappingKey, jlong key)
{
	int rv;
	CK_BYTE_PTR pOutputPart = 0;
	CK_ULONG ulOutputLen = 0;
	CK_MECHANISM wrapMechanism;
	jbyteArray ret;
	pkcs11_slot_t *slot;

	pkcs11_module_t *mod =  pkcs11_module_from_jhandle(env,mh);
	if (!mod) return 0;

	slot = pkcs11_slot_from_jhandle(env,shandle);
	if (!slot) return 0;

	wrapMechanism.mechanism      = algo;
	mechanismFromJavaObject(env, &wrapMechanism, param);

	rv = mod->method->C_WrapKey(hsession, &wrapMechanism, wrappingKey, key, pOutputPart, &ulOutputLen);

	if (rv  != CKR_OK)
    {
		jnixThrowExceptionI(env,"org/opensc/pkcs11/wrap/PKCS11Exception",rv,
                          "C_WrapKey failed for slot %d.",
                          (int)slot->id);
		return 0;
    }

	pOutputPart=alloca(ulOutputLen);

	rv = mod->method->C_WrapKey(hsession, &wrapMechanism, wrappingKey, key, pOutputPart, &ulOutputLen);

	if (rv  != CKR_OK)
    {
		jnixThrowExceptionI(env,"org/opensc/pkcs11/wrap/PKCS11Exception",rv,
                          "C_WrapKey failed for slot %d.",
                          (int)slot->id);
		return 0;
    }

	ret = 0;

	if (ulOutputLen > 0)
	{ 
		ret = (*env)->NewByteArray(env,ulOutputLen);
		if (ret)
		{
			(*env)->SetByteArrayRegion(env,ret,0,ulOutputLen,(jbyte*)pOutputPart);
		}
	}

	return ret;
}



/*
 * Class:     org_opensc_pkcs11_wrap_PKCS11Session
 * Method:    unwrapKeyNative
 * Signature: (JJJI[BJ[B[Lorg/opensc/pkcs11/wrap/PKCS11Attribute;)J
 */
JNIEXPORT jlong JNICALL JNIX_FUNC_NAME(Java_org_opensc_pkcs11_wrap_PKCS11Session_unwrapKeyNative)
  (JNIEnv *env, jclass cls, jlong mh, jlong shandle, jlong hsession, jint algo, jobject param, jlong unwrappingKey, jbyteArray wrappedKey, jobjectArray keyAttrs)
{
	int rv;
	CK_ULONG i;
	CK_ULONG ulKeyAttributeCount;
	CK_ATTRIBUTE_PTR pKeyTemplate;
	CK_MECHANISM unwrapMechanism;
	CK_OBJECT_HANDLE hKey;
	CK_ULONG ulWrappedKeyLength = 0;
	CK_BYTE_PTR pWrappedKey = 0;

	jclass clazz;
	jmethodID getKindID;
	jmethodID getDataID;
	pkcs11_slot_t *slot;
	pkcs11_module_t *mod = pkcs11_module_from_jhandle(env, mh);
	if (!mod) return 0;
  
	slot = pkcs11_slot_from_jhandle(env, shandle);
	if (!slot) return 0;

	clazz = (*env)->FindClass(env,"org/opensc/pkcs11/wrap/PKCS11Attribute");

	if (!clazz) return 0;

	getKindID = (*env)->GetMethodID(env,clazz,"getKind","()I");

	if (!getKindID) return 0;

	getDataID = (*env)->GetMethodID(env,clazz,"getData","()[B");

	if (!getDataID) return 0;

	ulKeyAttributeCount = (*env)->GetArrayLength(env,keyAttrs);
	pKeyTemplate = alloca(ulKeyAttributeCount * sizeof(CK_ATTRIBUTE));

	for (i=0;i<ulKeyAttributeCount;++i) {
		jbyteArray data;
		jobject jattr = (*env)->GetObjectArrayElement(env,keyAttrs,i);
		if (!jattr) return 0;

		pKeyTemplate[i].type = (*env)->CallIntMethod(env,jattr,getKindID);

		data = (jbyteArray)(*env)->CallObjectMethod(env,jattr,getDataID);

		allocaCArrayFromJByteArray(pKeyTemplate[i].pValue,pKeyTemplate[i].ulValueLen,env,data);
	}

	unwrapMechanism.mechanism      = algo;
	mechanismFromJavaObject(env, &unwrapMechanism, param);

    allocaCArrayFromJByteArray(pWrappedKey,ulWrappedKeyLength, env, wrappedKey);

	rv = mod->method->C_UnwrapKey(hsession, &unwrapMechanism, unwrappingKey, pWrappedKey, ulWrappedKeyLength,
                                      pKeyTemplate, ulKeyAttributeCount,
                                      &hKey);

	if (rv  != CKR_OK) {
		jnixThrowExceptionI(env,"org/opensc/pkcs11/wrap/PKCS11Exception",rv,
                          "C_UnwrapKey failed.");
		return 0;
    }

	return hKey;
}



/*
 * Class:     org_opensc_pkcs11_wrap_PKCS11Session
 * Method:    deriveKeyNative
 * Signature: (JJJI[BJ[Lorg/opensc/pkcs11/wrap/PKCS11Attribute;)J
 */
JNIEXPORT jlong JNICALL JNIX_FUNC_NAME(Java_org_opensc_pkcs11_wrap_PKCS11Session_deriveKeyNative)
  (JNIEnv *env, jclass cls, jlong mh, jlong shandle, jlong hsession, jint algo, jobject param, jlong baseKey, jobjectArray keyAttrs)
{
	int rv;
	CK_ULONG i;
	CK_ULONG ulKeyAttributeCount;
	CK_ATTRIBUTE_PTR pKeyTemplate;
	CK_MECHANISM deriveMechanism;
	CK_OBJECT_HANDLE hKey;

	jclass clazz;
	jmethodID getKindID;
	jmethodID getDataID;
	pkcs11_slot_t *slot;
	pkcs11_module_t *mod = pkcs11_module_from_jhandle(env, mh);
	if (!mod) return 0;
  
	slot = pkcs11_slot_from_jhandle(env, shandle);
	if (!slot) return 0;

	clazz = (*env)->FindClass(env,"org/opensc/pkcs11/wrap/PKCS11Attribute");

	if (!clazz) return 0;

	getKindID = (*env)->GetMethodID(env,clazz,"getKind","()I");

	if (!getKindID) return 0;

	getDataID = (*env)->GetMethodID(env,clazz,"getData","()[B");

	if (!getDataID) return 0;

	ulKeyAttributeCount = (*env)->GetArrayLength(env,keyAttrs);
	pKeyTemplate = alloca(ulKeyAttributeCount * sizeof(CK_ATTRIBUTE));

	for (i=0;i<ulKeyAttributeCount;++i) {
		jbyteArray data;
		jobject jattr = (*env)->GetObjectArrayElement(env,keyAttrs,i);
		if (!jattr) return 0;

		pKeyTemplate[i].type = (*env)->CallIntMethod(env,jattr,getKindID);

		data = (jbyteArray)(*env)->CallObjectMethod(env,jattr,getDataID);

		allocaCArrayFromJByteArray(pKeyTemplate[i].pValue,pKeyTemplate[i].ulValueLen,env,data);
	}

	deriveMechanism.mechanism = algo;
	mechanismFromJavaObject(env, &deriveMechanism, param);

	rv = mod->method->C_DeriveKey(hsession, &deriveMechanism, baseKey, 
                                      pKeyTemplate, ulKeyAttributeCount,
                                      &hKey);

	if (rv  != CKR_OK) {
		jnixThrowExceptionI(env,"org/opensc/pkcs11/wrap/PKCS11Exception",rv,
                          "C_DeriveKey failed.");
		return 0;
    }

	return hKey;
}



