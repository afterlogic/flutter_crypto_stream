//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/params/DHMQVPrivateParameters.java
//

#include "DHMQVPrivateParameters.h"
#include "DHParameters.h"
#include "DHPrivateKeyParameters.h"
#include "DHPublicKeyParameters.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/NullPointerException.h"
#include "java/math/BigInteger.h"

@interface LibOrgBouncycastleCryptoParamsDHMQVPrivateParameters () {
 @public
  LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *staticPrivateKey_;
  LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *ephemeralPrivateKey_;
  LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *ephemeralPublicKey_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoParamsDHMQVPrivateParameters, staticPrivateKey_, LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoParamsDHMQVPrivateParameters, ephemeralPrivateKey_, LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoParamsDHMQVPrivateParameters, ephemeralPublicKey_, LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *)

@implementation LibOrgBouncycastleCryptoParamsDHMQVPrivateParameters

- (instancetype)initWithLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters:(LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *)staticPrivateKey
                    withLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters:(LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *)ephemeralPrivateKey {
  LibOrgBouncycastleCryptoParamsDHMQVPrivateParameters_initWithLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters_withLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters_(self, staticPrivateKey, ephemeralPrivateKey);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters:(LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *)staticPrivateKey
                    withLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters:(LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *)ephemeralPrivateKey
                     withLibOrgBouncycastleCryptoParamsDHPublicKeyParameters:(LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *)ephemeralPublicKey {
  LibOrgBouncycastleCryptoParamsDHMQVPrivateParameters_initWithLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters_withLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters_withLibOrgBouncycastleCryptoParamsDHPublicKeyParameters_(self, staticPrivateKey, ephemeralPrivateKey, ephemeralPublicKey);
  return self;
}

- (LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *)getStaticPrivateKey {
  return staticPrivateKey_;
}

- (LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *)getEphemeralPrivateKey {
  return ephemeralPrivateKey_;
}

- (LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *)getEphemeralPublicKey {
  return ephemeralPublicKey_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoParamsDHPublicKeyParameters;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters:withLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters:withLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters:withLibOrgBouncycastleCryptoParamsDHPublicKeyParameters:);
  methods[2].selector = @selector(getStaticPrivateKey);
  methods[3].selector = @selector(getEphemeralPrivateKey);
  methods[4].selector = @selector(getEphemeralPublicKey);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "staticPrivateKey_", "LLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "ephemeralPrivateKey_", "LLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "ephemeralPublicKey_", "LLibOrgBouncycastleCryptoParamsDHPublicKeyParameters;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters;LLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters;", "LLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters;LLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters;LLibOrgBouncycastleCryptoParamsDHPublicKeyParameters;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoParamsDHMQVPrivateParameters = { "DHMQVPrivateParameters", "lib.org.bouncycastle.crypto.params", ptrTable, methods, fields, 7, 0x1, 5, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoParamsDHMQVPrivateParameters;
}

@end

void LibOrgBouncycastleCryptoParamsDHMQVPrivateParameters_initWithLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters_withLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters_(LibOrgBouncycastleCryptoParamsDHMQVPrivateParameters *self, LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *staticPrivateKey, LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *ephemeralPrivateKey) {
  LibOrgBouncycastleCryptoParamsDHMQVPrivateParameters_initWithLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters_withLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters_withLibOrgBouncycastleCryptoParamsDHPublicKeyParameters_(self, staticPrivateKey, ephemeralPrivateKey, nil);
}

LibOrgBouncycastleCryptoParamsDHMQVPrivateParameters *new_LibOrgBouncycastleCryptoParamsDHMQVPrivateParameters_initWithLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters_withLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters_(LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *staticPrivateKey, LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *ephemeralPrivateKey) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoParamsDHMQVPrivateParameters, initWithLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters_withLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters_, staticPrivateKey, ephemeralPrivateKey)
}

LibOrgBouncycastleCryptoParamsDHMQVPrivateParameters *create_LibOrgBouncycastleCryptoParamsDHMQVPrivateParameters_initWithLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters_withLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters_(LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *staticPrivateKey, LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *ephemeralPrivateKey) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoParamsDHMQVPrivateParameters, initWithLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters_withLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters_, staticPrivateKey, ephemeralPrivateKey)
}

void LibOrgBouncycastleCryptoParamsDHMQVPrivateParameters_initWithLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters_withLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters_withLibOrgBouncycastleCryptoParamsDHPublicKeyParameters_(LibOrgBouncycastleCryptoParamsDHMQVPrivateParameters *self, LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *staticPrivateKey, LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *ephemeralPrivateKey, LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *ephemeralPublicKey) {
  NSObject_init(self);
  if (staticPrivateKey == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"staticPrivateKey cannot be null");
  }
  if (ephemeralPrivateKey == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"ephemeralPrivateKey cannot be null");
  }
  LibOrgBouncycastleCryptoParamsDHParameters *parameters = [staticPrivateKey getParameters];
  if (![((LibOrgBouncycastleCryptoParamsDHParameters *) nil_chk(parameters)) isEqual:[ephemeralPrivateKey getParameters]]) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Static and ephemeral private keys have different domain parameters");
  }
  if (ephemeralPublicKey == nil) {
    ephemeralPublicKey = new_LibOrgBouncycastleCryptoParamsDHPublicKeyParameters_initWithJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsDHParameters_([((JavaMathBigInteger *) nil_chk([parameters getG])) multiplyWithJavaMathBigInteger:[ephemeralPrivateKey getX]], parameters);
  }
  else if (![parameters isEqual:[ephemeralPublicKey getParameters]]) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Ephemeral public key has different domain parameters");
  }
  self->staticPrivateKey_ = staticPrivateKey;
  self->ephemeralPrivateKey_ = ephemeralPrivateKey;
  self->ephemeralPublicKey_ = ephemeralPublicKey;
}

LibOrgBouncycastleCryptoParamsDHMQVPrivateParameters *new_LibOrgBouncycastleCryptoParamsDHMQVPrivateParameters_initWithLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters_withLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters_withLibOrgBouncycastleCryptoParamsDHPublicKeyParameters_(LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *staticPrivateKey, LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *ephemeralPrivateKey, LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *ephemeralPublicKey) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoParamsDHMQVPrivateParameters, initWithLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters_withLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters_withLibOrgBouncycastleCryptoParamsDHPublicKeyParameters_, staticPrivateKey, ephemeralPrivateKey, ephemeralPublicKey)
}

LibOrgBouncycastleCryptoParamsDHMQVPrivateParameters *create_LibOrgBouncycastleCryptoParamsDHMQVPrivateParameters_initWithLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters_withLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters_withLibOrgBouncycastleCryptoParamsDHPublicKeyParameters_(LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *staticPrivateKey, LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *ephemeralPrivateKey, LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *ephemeralPublicKey) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoParamsDHMQVPrivateParameters, initWithLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters_withLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters_withLibOrgBouncycastleCryptoParamsDHPublicKeyParameters_, staticPrivateKey, ephemeralPrivateKey, ephemeralPublicKey)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoParamsDHMQVPrivateParameters)