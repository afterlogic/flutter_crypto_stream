//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/params/Ed448PrivateKeyParameters.java
//

#include "Arrays.h"
#include "AsymmetricKeyParameter.h"
#include "Ed448.h"
#include "Ed448PrivateKeyParameters.h"
#include "Ed448PublicKeyParameters.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "Streams.h"
#include "java/io/EOFException.h"
#include "java/io/InputStream.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/System.h"
#include "java/security/SecureRandom.h"

@interface LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters () {
 @public
  IOSByteArray *data_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters, data_, IOSByteArray *)

@implementation LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters

+ (jint)KEY_SIZE {
  return LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters_KEY_SIZE;
}

+ (jint)SIGNATURE_SIZE {
  return LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters_SIGNATURE_SIZE;
}

- (instancetype)initWithJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random {
  LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters_initWithJavaSecuritySecureRandom_(self, random);
  return self;
}

- (instancetype)initWithByteArray:(IOSByteArray *)buf
                          withInt:(jint)off {
  LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters_initWithByteArray_withInt_(self, buf, off);
  return self;
}

- (instancetype)initWithJavaIoInputStream:(JavaIoInputStream *)input {
  LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters_initWithJavaIoInputStream_(self, input);
  return self;
}

- (void)encodeWithByteArray:(IOSByteArray *)buf
                    withInt:(jint)off {
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(data_, 0, buf, off, LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters_KEY_SIZE);
}

- (IOSByteArray *)getEncoded {
  return LibOrgBouncycastleUtilArrays_cloneWithByteArray_(data_);
}

- (LibOrgBouncycastleCryptoParamsEd448PublicKeyParameters *)generatePublicKey {
  IOSByteArray *publicKey = [IOSByteArray newArrayWithLength:LibOrgBouncycastleMathEcRfc8032Ed448_PUBLIC_KEY_SIZE];
  LibOrgBouncycastleMathEcRfc8032Ed448_generatePublicKeyWithByteArray_withInt_withByteArray_withInt_(data_, 0, publicKey, 0);
  return new_LibOrgBouncycastleCryptoParamsEd448PublicKeyParameters_initWithByteArray_withInt_(publicKey, 0);
}

- (void)signWithInt:(jint)algorithm
withLibOrgBouncycastleCryptoParamsEd448PublicKeyParameters:(LibOrgBouncycastleCryptoParamsEd448PublicKeyParameters *)publicKey
      withByteArray:(IOSByteArray *)ctx
      withByteArray:(IOSByteArray *)msg
            withInt:(jint)msgOff
            withInt:(jint)msgLen
      withByteArray:(IOSByteArray *)sig
            withInt:(jint)sigOff {
  IOSByteArray *pk = [IOSByteArray newArrayWithLength:LibOrgBouncycastleMathEcRfc8032Ed448_PUBLIC_KEY_SIZE];
  if (nil == publicKey) {
    LibOrgBouncycastleMathEcRfc8032Ed448_generatePublicKeyWithByteArray_withInt_withByteArray_withInt_(data_, 0, pk, 0);
  }
  else {
    [publicKey encodeWithByteArray:pk withInt:0];
  }
  switch (algorithm) {
    case LibOrgBouncycastleMathEcRfc8032Ed448_Algorithm_Ed448:
    {
      LibOrgBouncycastleMathEcRfc8032Ed448_signWithByteArray_withInt_withByteArray_withInt_withByteArray_withByteArray_withInt_withInt_withByteArray_withInt_(data_, 0, pk, 0, ctx, msg, msgOff, msgLen, sig, sigOff);
      break;
    }
    case LibOrgBouncycastleMathEcRfc8032Ed448_Algorithm_Ed448ph:
    {
      if (LibOrgBouncycastleMathEcRfc8032Ed448_PREHASH_SIZE != msgLen) {
        @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"msgLen");
      }
      LibOrgBouncycastleMathEcRfc8032Ed448_signPrehashWithByteArray_withInt_withByteArray_withInt_withByteArray_withByteArray_withInt_withByteArray_withInt_(data_, 0, pk, 0, ctx, msg, msgOff, sig, sigOff);
      break;
    }
    default:
    {
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"algorithm");
    }
  }
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, 3, -1, -1, -1 },
    { NULL, "V", 0x1, 4, 1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoParamsEd448PublicKeyParameters;", 0x1, -1, -1, -1, -1, -1, -1 },
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
  methods[6].selector = @selector(signWithInt:withLibOrgBouncycastleCryptoParamsEd448PublicKeyParameters:withByteArray:withByteArray:withInt:withInt:withByteArray:withInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "KEY_SIZE", "I", .constantValue.asInt = LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters_KEY_SIZE, 0x19, -1, -1, -1, -1 },
    { "SIGNATURE_SIZE", "I", .constantValue.asInt = LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters_SIGNATURE_SIZE, 0x19, -1, -1, -1, -1 },
    { "data_", "[B", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaSecuritySecureRandom;", "[BI", "LJavaIoInputStream;", "LJavaIoIOException;", "encode", "sign", "ILLibOrgBouncycastleCryptoParamsEd448PublicKeyParameters;[B[BII[BI" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters = { "Ed448PrivateKeyParameters", "lib.org.bouncycastle.crypto.params", ptrTable, methods, fields, 7, 0x11, 7, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters;
}

@end

void LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters_initWithJavaSecuritySecureRandom_(LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters *self, JavaSecuritySecureRandom *random) {
  LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_initWithBoolean_(self, true);
  self->data_ = [IOSByteArray newArrayWithLength:LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters_KEY_SIZE];
  LibOrgBouncycastleMathEcRfc8032Ed448_generatePrivateKeyWithJavaSecuritySecureRandom_withByteArray_(random, self->data_);
}

LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters *new_LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters_initWithJavaSecuritySecureRandom_(JavaSecuritySecureRandom *random) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters, initWithJavaSecuritySecureRandom_, random)
}

LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters *create_LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters_initWithJavaSecuritySecureRandom_(JavaSecuritySecureRandom *random) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters, initWithJavaSecuritySecureRandom_, random)
}

void LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters_initWithByteArray_withInt_(LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters *self, IOSByteArray *buf, jint off) {
  LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_initWithBoolean_(self, true);
  self->data_ = [IOSByteArray newArrayWithLength:LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters_KEY_SIZE];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(buf, off, self->data_, 0, LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters_KEY_SIZE);
}

LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters *new_LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters_initWithByteArray_withInt_(IOSByteArray *buf, jint off) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters, initWithByteArray_withInt_, buf, off)
}

LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters *create_LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters_initWithByteArray_withInt_(IOSByteArray *buf, jint off) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters, initWithByteArray_withInt_, buf, off)
}

void LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters_initWithJavaIoInputStream_(LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters *self, JavaIoInputStream *input) {
  LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_initWithBoolean_(self, true);
  self->data_ = [IOSByteArray newArrayWithLength:LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters_KEY_SIZE];
  if (LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters_KEY_SIZE != LibOrgBouncycastleUtilIoStreams_readFullyWithJavaIoInputStream_withByteArray_(input, self->data_)) {
    @throw new_JavaIoEOFException_initWithNSString_(@"EOF encountered in middle of Ed448 private key");
  }
}

LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters *new_LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters_initWithJavaIoInputStream_(JavaIoInputStream *input) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters, initWithJavaIoInputStream_, input)
}

LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters *create_LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters_initWithJavaIoInputStream_(JavaIoInputStream *input) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters, initWithJavaIoInputStream_, input)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters)
