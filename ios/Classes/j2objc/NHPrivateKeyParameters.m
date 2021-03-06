//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/crypto/newhope/NHPrivateKeyParameters.java
//

#include "Arrays.h"
#include "AsymmetricKeyParameter.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "NHPrivateKeyParameters.h"

@implementation LibOrgBouncycastlePqcCryptoNewhopeNHPrivateKeyParameters

- (instancetype)initWithShortArray:(IOSShortArray *)secData {
  LibOrgBouncycastlePqcCryptoNewhopeNHPrivateKeyParameters_initWithShortArray_(self, secData);
  return self;
}

- (IOSShortArray *)getSecData {
  return LibOrgBouncycastleUtilArrays_cloneWithShortArray_(secData_);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "[S", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithShortArray:);
  methods[1].selector = @selector(getSecData);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "secData_", "[S", .constantValue.asLong = 0, 0x10, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "[S" };
  static const J2ObjcClassInfo _LibOrgBouncycastlePqcCryptoNewhopeNHPrivateKeyParameters = { "NHPrivateKeyParameters", "lib.org.bouncycastle.pqc.crypto.newhope", ptrTable, methods, fields, 7, 0x1, 2, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastlePqcCryptoNewhopeNHPrivateKeyParameters;
}

@end

void LibOrgBouncycastlePqcCryptoNewhopeNHPrivateKeyParameters_initWithShortArray_(LibOrgBouncycastlePqcCryptoNewhopeNHPrivateKeyParameters *self, IOSShortArray *secData) {
  LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_initWithBoolean_(self, true);
  self->secData_ = LibOrgBouncycastleUtilArrays_cloneWithShortArray_(secData);
}

LibOrgBouncycastlePqcCryptoNewhopeNHPrivateKeyParameters *new_LibOrgBouncycastlePqcCryptoNewhopeNHPrivateKeyParameters_initWithShortArray_(IOSShortArray *secData) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcCryptoNewhopeNHPrivateKeyParameters, initWithShortArray_, secData)
}

LibOrgBouncycastlePqcCryptoNewhopeNHPrivateKeyParameters *create_LibOrgBouncycastlePqcCryptoNewhopeNHPrivateKeyParameters_initWithShortArray_(IOSShortArray *secData) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcCryptoNewhopeNHPrivateKeyParameters, initWithShortArray_, secData)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastlePqcCryptoNewhopeNHPrivateKeyParameters)
