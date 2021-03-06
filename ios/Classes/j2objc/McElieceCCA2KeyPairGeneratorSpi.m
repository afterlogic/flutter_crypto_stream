//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/jcajce/provider/mceliece/McElieceCCA2KeyPairGeneratorSpi.java
//

#include "AsymmetricCipherKeyPair.h"
#include "AsymmetricKeyParameter.h"
#include "BCMcElieceCCA2PrivateKey.h"
#include "BCMcElieceCCA2PublicKey.h"
#include "CryptoServicesRegistrar.h"
#include "J2ObjC_source.h"
#include "McElieceCCA2KeyGenParameterSpec.h"
#include "McElieceCCA2KeyGenerationParameters.h"
#include "McElieceCCA2KeyPairGenerator.h"
#include "McElieceCCA2KeyPairGeneratorSpi.h"
#include "McElieceCCA2Parameters.h"
#include "McElieceCCA2PrivateKeyParameters.h"
#include "McElieceCCA2PublicKeyParameters.h"
#include "java/security/KeyPair.h"
#include "java/security/KeyPairGenerator.h"
#include "java/security/SecureRandom.h"
#include "java/security/spec/AlgorithmParameterSpec.h"

@interface LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceCCA2KeyPairGeneratorSpi () {
 @public
  LibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2KeyPairGenerator *kpg_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceCCA2KeyPairGeneratorSpi, kpg_, LibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2KeyPairGenerator *)

@implementation LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceCCA2KeyPairGeneratorSpi

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceCCA2KeyPairGeneratorSpi_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)initialize__WithJavaSecuritySpecAlgorithmParameterSpec:(id<JavaSecuritySpecAlgorithmParameterSpec>)params
                                  withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random {
  kpg_ = new_LibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2KeyPairGenerator_init();
  LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec *ecc = (LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec *) cast_chk(params, [LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec class]);
  LibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2KeyGenerationParameters *mccca2KGParams = new_LibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2KeyGenerationParameters_initWithJavaSecuritySecureRandom_withLibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2Parameters_(random, new_LibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2Parameters_initWithInt_withInt_withNSString_([((LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec *) nil_chk(ecc)) getM], [ecc getT], [ecc getDigest]));
  [((LibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2KeyPairGenerator *) nil_chk(kpg_)) init__WithLibOrgBouncycastleCryptoKeyGenerationParameters:mccca2KGParams];
}

- (void)initialize__WithJavaSecuritySpecAlgorithmParameterSpec:(id<JavaSecuritySpecAlgorithmParameterSpec>)params {
  kpg_ = new_LibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2KeyPairGenerator_init();
  LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec *ecc = (LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec *) cast_chk(params, [LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec class]);
  LibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2KeyGenerationParameters *mccca2KGParams = new_LibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2KeyGenerationParameters_initWithJavaSecuritySecureRandom_withLibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2Parameters_(LibOrgBouncycastleCryptoCryptoServicesRegistrar_getSecureRandom(), new_LibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2Parameters_initWithInt_withInt_withNSString_([((LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec *) nil_chk(ecc)) getM], [ecc getT], [ecc getDigest]));
  [((LibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2KeyPairGenerator *) nil_chk(kpg_)) init__WithLibOrgBouncycastleCryptoKeyGenerationParameters:mccca2KGParams];
}

- (void)initialize__WithInt:(jint)keySize
withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random {
  kpg_ = new_LibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2KeyPairGenerator_init();
  LibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2KeyGenerationParameters *mccca2KGParams = new_LibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2KeyGenerationParameters_initWithJavaSecuritySecureRandom_withLibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2Parameters_(random, new_LibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2Parameters_init());
  [((LibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2KeyPairGenerator *) nil_chk(kpg_)) init__WithLibOrgBouncycastleCryptoKeyGenerationParameters:mccca2KGParams];
}

- (JavaSecurityKeyPair *)generateKeyPair {
  LibOrgBouncycastleCryptoAsymmetricCipherKeyPair *generateKeyPair = [((LibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2KeyPairGenerator *) nil_chk(kpg_)) generateKeyPair];
  LibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2PrivateKeyParameters *sk = (LibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2PrivateKeyParameters *) cast_chk([((LibOrgBouncycastleCryptoAsymmetricCipherKeyPair *) nil_chk(generateKeyPair)) getPrivate], [LibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2PrivateKeyParameters class]);
  LibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2PublicKeyParameters *pk = (LibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2PublicKeyParameters *) cast_chk([generateKeyPair getPublic], [LibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2PublicKeyParameters class]);
  return new_JavaSecurityKeyPair_initWithJavaSecurityPublicKey_withJavaSecurityPrivateKey_(new_LibOrgBouncycastlePqcJcajceProviderMcelieceBCMcElieceCCA2PublicKey_initWithLibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2PublicKeyParameters_(pk), new_LibOrgBouncycastlePqcJcajceProviderMcelieceBCMcElieceCCA2PrivateKey_initWithLibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2PrivateKeyParameters_(sk));
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 1, 2, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 3, 2, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 4, -1, -1, -1, -1 },
    { NULL, "LJavaSecurityKeyPair;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(initialize__WithJavaSecuritySpecAlgorithmParameterSpec:withJavaSecuritySecureRandom:);
  methods[2].selector = @selector(initialize__WithJavaSecuritySpecAlgorithmParameterSpec:);
  methods[3].selector = @selector(initialize__WithInt:withJavaSecuritySecureRandom:);
  methods[4].selector = @selector(generateKeyPair);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "kpg_", "LLibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2KeyPairGenerator;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "initialize", "LJavaSecuritySpecAlgorithmParameterSpec;LJavaSecuritySecureRandom;", "LJavaSecurityInvalidAlgorithmParameterException;", "LJavaSecuritySpecAlgorithmParameterSpec;", "ILJavaSecuritySecureRandom;" };
  static const J2ObjcClassInfo _LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceCCA2KeyPairGeneratorSpi = { "McElieceCCA2KeyPairGeneratorSpi", "lib.org.bouncycastle.pqc.jcajce.provider.mceliece", ptrTable, methods, fields, 7, 0x1, 5, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceCCA2KeyPairGeneratorSpi;
}

@end

void LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceCCA2KeyPairGeneratorSpi_init(LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceCCA2KeyPairGeneratorSpi *self) {
  JavaSecurityKeyPairGenerator_initWithNSString_(self, @"McEliece-CCA2");
}

LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceCCA2KeyPairGeneratorSpi *new_LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceCCA2KeyPairGeneratorSpi_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceCCA2KeyPairGeneratorSpi, init)
}

LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceCCA2KeyPairGeneratorSpi *create_LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceCCA2KeyPairGeneratorSpi_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceCCA2KeyPairGeneratorSpi, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceCCA2KeyPairGeneratorSpi)
