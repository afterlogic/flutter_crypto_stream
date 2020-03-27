//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/crypto/ntru/NTRUEncryptionKeyParameters.java
//

#include "AsymmetricKeyParameter.h"
#include "J2ObjC_source.h"
#include "NTRUEncryptionKeyParameters.h"
#include "NTRUEncryptionParameters.h"

@implementation LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionKeyParameters

- (instancetype)initWithBoolean:(jboolean)privateKey
withLibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters:(LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters *)params {
  LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionKeyParameters_initWithBoolean_withLibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters_(self, privateKey, params);
  return self;
}

- (LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters *)getParameters {
  return params_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithBoolean:withLibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters:);
  methods[1].selector = @selector(getParameters);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "params_", "LLibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters;", .constantValue.asLong = 0, 0x14, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "ZLLibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters;" };
  static const J2ObjcClassInfo _LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionKeyParameters = { "NTRUEncryptionKeyParameters", "lib.org.bouncycastle.pqc.crypto.ntru", ptrTable, methods, fields, 7, 0x1, 2, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionKeyParameters;
}

@end

void LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionKeyParameters_initWithBoolean_withLibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters_(LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionKeyParameters *self, jboolean privateKey, LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters *params) {
  LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_initWithBoolean_(self, privateKey);
  self->params_ = params;
}

LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionKeyParameters *new_LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionKeyParameters_initWithBoolean_withLibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters_(jboolean privateKey, LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters *params) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionKeyParameters, initWithBoolean_withLibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters_, privateKey, params)
}

LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionKeyParameters *create_LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionKeyParameters_initWithBoolean_withLibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters_(jboolean privateKey, LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters *params) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionKeyParameters, initWithBoolean_withLibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters_, privateKey, params)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionKeyParameters)