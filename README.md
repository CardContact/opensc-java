# opensc-java
A Java PKCS#11 wrapper and JCE Provider

The code is derived from the original (OpenSC repo)[https://github.com/OpenSC/OpenSC-Java/tree/master/pkcs11], but uses
IVY and ANT rather than MAVEN.

You need a JCE Code Signer to build the module. Please create a jarsigner.cfg file one level above the project
directory which contains

	# Code signer key store, key alias and password
	jarsigner.keystore=<path to keystore>
	jarsigner.alias=<key alias>
	jarsigner.password=<keystore password>

Prebuild DLLs and shared objects are provided in jni/prebuild.

Shared objects are build on Ubuntu 12.04, DLLs are build with MSVC10.
