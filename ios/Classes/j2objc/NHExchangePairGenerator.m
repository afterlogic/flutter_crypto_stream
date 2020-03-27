//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/crypto/newhope/NHExchangePairGenerator.java
//

#include "AsymmetricKeyParameter.h"
#include "ExchangePair.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "NHExchangePairGenerator.h"
#include "NHPublicKeyParameters.h"
#include "NewHope.h"
#include "java/security/SecureRandom.h"

@interface LibOrgBouncycastlePqcCryptoNewhopeNHExchangePairGenerator () {
 @public
  JavaSecuritySecureRandom *random_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoNewhopeNHExchangePairGenerator, random_, JavaSecuritySecureRandom *)

@implementation LibOrgBouncycastlePqcCryptoNewhopeNHExchangePairGenerator

- (instancetype)initWithJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random {
  LibOrgBouncycastlePqcCryptoNewhopeNHExchangePairGenerator_initWithJavaSecuritySecureRandom_(self, random);
  return self;
}

- (LibOrgBouncycastlePqcCryptoExchangePair *)GenerateExchangeWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)senderPublicKey {
  return [self generateExchangeWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:senderPublicKey];
}

- (LibOrgBouncycastlePqcCryptoExchangePair *)generateExchangeWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)senderPublicKey {
  LibOrgBouncycastlePqcCryptoNewhopeNHPublicKeyParameters *pubKey = (LibOrgBouncycastlePqcCryptoNewhopeNHPublicKeyParameters *) cast_chk(senderPublicKey, [LibOrgBouncycastlePqcCryptoNewhopeNHPublicKeyParameters class]);
  IOSByteArray *sharedValue = [IOSByteArray newArrayWithLength:LibOrgBouncycastlePqcCryptoNewhopeNewHope_AGREEMENT_SIZE];
  IOSByteArray *publicKeyValue = [IOSByteArray newArrayWithLength:LibOrgBouncycastlePqcCryptoNewhopeNewHope_SENDB_BYTES];
  LibOrgBouncycastlePqcCryptoNewhopeNewHope_sharedBWithJavaSecuritySecureRandom_withByteArray_withByteArray_withByteArray_(random_, sharedValue, publicKeyValue, ((LibOrgBouncycastlePqcCryptoNewhopeNHPublicKeyParameters *) nil_chk(pubKey))->pubData_);
  return new_LibOrgBouncycastlePqcCryptoExchangePair_initWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_withByteArray_(new_LibOrgBouncycastlePqcCryptoNewhopeNHPublicKeyParameters_initWithByteArray_(publicKeyValue), sharedValue);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastlePqcCryptoExchangePair;", 0x1, 1, 2, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastlePqcCryptoExchangePair;", 0x1, 3, 2, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithJavaSecuritySecureRandom:);
  methods[1].selector = @selector(GenerateExchangeWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:);
  methods[2].selector = @selector(generateExchangeWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "random_", "LJavaSecuritySecureRandom;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaSecuritySecureRandom;", "GenerateExchange", "LLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter;", "generateExchange" };
  static const J2ObjcClassInfo _LibOrgBouncycastlePqcCryptoNewhopeNHExchangePairGenerator = { "NHExchangePairGenerator", "lib.org.bouncycastle.pqc.crypto.newhope", ptrTable, methods, fields, 7, 0x1, 3, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastlePqcCryptoNewhopeNHExchangePairGenerator;
}

@end

void LibOrgBouncycastlePqcCryptoNewhopeNHExchangePairGenerator_initWithJavaSecuritySecureRandom_(LibOrgBouncycastlePqcCryptoNewhopeNHExchangePairGenerator *self, JavaSecuritySecureRandom *random) {
  NSObject_init(self);
  self->random_ = random;
}

LibOrgBouncycastlePqcCryptoNewhopeNHExchangePairGenerator *new_LibOrgBouncycastlePqcCryptoNewhopeNHExchangePairGenerator_initWithJavaSecuritySecureRandom_(JavaSecuritySecureRandom *random) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcCryptoNewhopeNHExchangePairGenerator, initWithJavaSecuritySecureRandom_, random)
}

LibOrgBouncycastlePqcCryptoNewhopeNHExchangePairGenerator *create_LibOrgBouncycastlePqcCryptoNewhopeNHExchangePairGenerator_initWithJavaSecuritySecureRandom_(JavaSecuritySecureRandom *random) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcCryptoNewhopeNHExchangePairGenerator, initWithJavaSecuritySecureRandom_, random)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastlePqcCryptoNewhopeNHExchangePairGenerator)