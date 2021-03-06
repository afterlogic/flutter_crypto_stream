//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/params/X25519PrivateKeyParameters.java
//

#include "Arrays.h"
#include "AsymmetricKeyParameter.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "Streams.h"
#include "X25519.h"
#include "X25519PrivateKeyParameters.h"
#include "X25519PublicKeyParameters.h"
#include "java/io/EOFException.h"
#include "java/io/InputStream.h"
#include "java/lang/IllegalStateException.h"
#include "java/lang/System.h"
#include "java/security/SecureRandom.h"

@interface LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters () {
 @public
  IOSByteArray *data_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters, data_, IOSByteArray *)

@implementation LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters

+ (jint)KEY_SIZE {
  return LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters_KEY_SIZE;
}

+ (jint)SECRET_SIZE {
  return LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters_SECRET_SIZE;
}

- (instancetype)initWithJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random {
  LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters_initWithJavaSecuritySecureRandom_(self, random);
  return self;
}

- (instancetype)initWithByteArray:(IOSByteArray *)buf
                          withInt:(jint)off {
  LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters_initWithByteArray_withInt_(self, buf, off);
  return self;
}

- (instancetype)initWithJavaIoInputStream:(JavaIoInputStream *)input {
  LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters_initWithJavaIoInputStream_(self, input);
  return self;
}

- (void)encodeWithByteArray:(IOSByteArray *)buf
                    withInt:(jint)off {
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(data_, 0, buf, off, LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters_KEY_SIZE);
}

- (IOSByteArray *)getEncoded {
  return LibOrgBouncycastleUtilArrays_cloneWithByteArray_(data_);
}

- (LibOrgBouncycastleCryptoParamsX25519PublicKeyParameters *)generatePublicKey {
  IOSByteArray *publicKey = [IOSByteArray newArrayWithLength:LibOrgBouncycastleMathEcRfc7748X25519_POINT_SIZE];
  LibOrgBouncycastleMathEcRfc7748X25519_generatePublicKeyWithByteArray_withInt_withByteArray_withInt_(data_, 0, publicKey, 0);
  return new_LibOrgBouncycastleCryptoParamsX25519PublicKeyParameters_initWithByteArray_withInt_(publicKey, 0);
}

- (void)generateSecretWithLibOrgBouncycastleCryptoParamsX25519PublicKeyParameters:(LibOrgBouncycastleCryptoParamsX25519PublicKeyParameters *)publicKey
                                                                    withByteArray:(IOSByteArray *)buf
                                                                          withInt:(jint)off {
  IOSByteArray *encoded = [IOSByteArray newArrayWithLength:LibOrgBouncycastleMathEcRfc7748X25519_POINT_SIZE];
  [((LibOrgBouncycastleCryptoParamsX25519PublicKeyParameters *) nil_chk(publicKey)) encodeWithByteArray:encoded withInt:0];
  if (!LibOrgBouncycastleMathEcRfc7748X25519_calculateAgreementWithByteArray_withInt_withByteArray_withInt_withByteArray_withInt_(data_, 0, encoded, 0, buf, off)) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"X25519 agreement failed");
  }
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, 3, -1, -1, -1 },
    { NULL, "V", 0x1, 4, 1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoParamsX25519PublicKeyParameters;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 5, 6, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithJavaSecuritySecureRandom:);
  methods[1].selector = @selector(initWithByteArray:withInt:);
  methods[2].selector = @selector(initWithJavaIoInputStream:);
  methods[3].selector = @selector(encodeWithByteArray:withInt:);
  methods[4].selector = @selector(getEncoded);
  methods[5].selector = @selector(generatePublicKey);
  methods[6].selector = @selector(generateSecretWithLibOrgBouncycastleCryptoParamsX25519PublicKeyParameters:withByteArray:withInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "KEY_SIZE", "I", .constantValue.asInt = LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters_KEY_SIZE, 0x19, -1, -1, -1, -1 },
    { "SECRET_SIZE", "I", .constantValue.asInt = LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters_SECRET_SIZE, 0x19, -1, -1, -1, -1 },
    { "data_", "[B", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaSecuritySecureRandom;", "[BI", "LJavaIoInputStream;", "LJavaIoIOException;", "encode", "generateSecret", "LLibOrgBouncycastleCryptoParamsX25519PublicKeyParameters;[BI" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters = { "X25519PrivateKeyParameters", "lib.org.bouncycastle.crypto.params", ptrTable, methods, fields, 7, 0x11, 7, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters;
}

@end

void LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters_initWithJavaSecuritySecureRandom_(LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters *self, JavaSecuritySecureRandom *random) {
  LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_initWithBoolean_(self, true);
  self->data_ = [IOSByteArray newArrayWithLength:LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters_KEY_SIZE];
  LibOrgBouncycastleMathEcRfc7748X25519_generatePrivateKeyWithJavaSecuritySecureRandom_withByteArray_(random, self->data_);
}

LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters *new_LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters_initWithJavaSecuritySecureRandom_(JavaSecuritySecureRandom *random) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters, initWithJavaSecuritySecureRandom_, random)
}

LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters *create_LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters_initWithJavaSecuritySecureRandom_(JavaSecuritySecureRandom *random) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters, initWithJavaSecuritySecureRandom_, random)
}

void LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters_initWithByteArray_withInt_(LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters *self, IOSByteArray *buf, jint off) {
  LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_initWithBoolean_(self, true);
  self->data_ = [IOSByteArray newArrayWithLength:LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters_KEY_SIZE];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(buf, off, self->data_, 0, LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters_KEY_SIZE);
}

LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters *new_LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters_initWithByteArray_withInt_(IOSByteArray *buf, jint off) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters, initWithByteArray_withInt_, buf, off)
}

LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters *create_LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters_initWithByteArray_withInt_(IOSByteArray *buf, jint off) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters, initWithByteArray_withInt_, buf, off)
}

void LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters_initWithJavaIoInputStream_(LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters *self, JavaIoInputStream *input) {
  LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_initWithBoolean_(self, true);
  self->data_ = [IOSByteArray newArrayWithLength:LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters_KEY_SIZE];
  if (LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters_KEY_SIZE != LibOrgBouncycastleUtilIoStreams_readFullyWithJavaIoInputStream_withByteArray_(input, self->data_)) {
    @throw new_JavaIoEOFException_initWithNSString_(@"EOF encountered in middle of X25519 private key");
  }
}

LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters *new_LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters_initWithJavaIoInputStream_(JavaIoInputStream *input) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters, initWithJavaIoInputStream_, input)
}

LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters *create_LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters_initWithJavaIoInputStream_(JavaIoInputStream *input) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters, initWithJavaIoInputStream_, input)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters)
