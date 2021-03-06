//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/crypto/newhope/NHPublicKeyParameters.java
//

#include "Arrays.h"
#include "AsymmetricKeyParameter.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "NHPublicKeyParameters.h"

@implementation LibOrgBouncycastlePqcCryptoNewhopeNHPublicKeyParameters

- (instancetype)initWithByteArray:(IOSByteArray *)pubData {
  LibOrgBouncycastlePqcCryptoNewhopeNHPublicKeyParameters_initWithByteArray_(self, pubData);
  return self;
}

- (IOSByteArray *)getPubData {
  return LibOrgBouncycastleUtilArrays_cloneWithByteArray_(pubData_);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithByteArray:);
  methods[1].selector = @selector(getPubData);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "pubData_", "[B", .constantValue.asLong = 0, 0x10, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "[B" };
  static const J2ObjcClassInfo _LibOrgBouncycastlePqcCryptoNewhopeNHPublicKeyParameters = { "NHPublicKeyParameters", "lib.org.bouncycastle.pqc.crypto.newhope", ptrTable, methods, fields, 7, 0x1, 2, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastlePqcCryptoNewhopeNHPublicKeyParameters;
}

@end

void LibOrgBouncycastlePqcCryptoNewhopeNHPublicKeyParameters_initWithByteArray_(LibOrgBouncycastlePqcCryptoNewhopeNHPublicKeyParameters *self, IOSByteArray *pubData) {
  LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_initWithBoolean_(self, false);
  self->pubData_ = LibOrgBouncycastleUtilArrays_cloneWithByteArray_(pubData);
}

LibOrgBouncycastlePqcCryptoNewhopeNHPublicKeyParameters *new_LibOrgBouncycastlePqcCryptoNewhopeNHPublicKeyParameters_initWithByteArray_(IOSByteArray *pubData) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcCryptoNewhopeNHPublicKeyParameters, initWithByteArray_, pubData)
}

LibOrgBouncycastlePqcCryptoNewhopeNHPublicKeyParameters *create_LibOrgBouncycastlePqcCryptoNewhopeNHPublicKeyParameters_initWithByteArray_(IOSByteArray *pubData) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcCryptoNewhopeNHPublicKeyParameters, initWithByteArray_, pubData)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastlePqcCryptoNewhopeNHPublicKeyParameters)
