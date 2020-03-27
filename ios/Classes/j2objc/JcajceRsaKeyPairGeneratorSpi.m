//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/asymmetric/rsa/JcajceRsaKeyPairGeneratorSpi.java
//

#include "AsymmetricCipherKeyPair.h"
#include "AsymmetricKeyParameter.h"
#include "BCRSAPrivateCrtKey.h"
#include "BCRSAPublicKey.h"
#include "CryptoRSAKeyPairGenerator.h"
#include "CryptoServicesRegistrar.h"
#include "J2ObjC_source.h"
#include "JcajceRsaKeyPairGeneratorSpi.h"
#include "PrimeCertaintyCalculator.h"
#include "RSAKeyGenerationParameters.h"
#include "RSAKeyParameters.h"
#include "RSAPrivateCrtKeyParameters.h"
#include "java/math/BigInteger.h"
#include "java/security/InvalidAlgorithmParameterException.h"
#include "java/security/KeyPair.h"
#include "java/security/KeyPairGenerator.h"
#include "java/security/SecureRandom.h"
#include "java/security/spec/AlgorithmParameterSpec.h"
#include "java/security/spec/RSAKeyGenParameterSpec.h"

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleJcajceProviderAsymmetricRsaJcajceRsaKeyPairGeneratorSpi)

JavaMathBigInteger *LibOrgBouncycastleJcajceProviderAsymmetricRsaJcajceRsaKeyPairGeneratorSpi_defaultPublicExponent;

@implementation LibOrgBouncycastleJcajceProviderAsymmetricRsaJcajceRsaKeyPairGeneratorSpi

+ (JavaMathBigInteger *)defaultPublicExponent {
  return LibOrgBouncycastleJcajceProviderAsymmetricRsaJcajceRsaKeyPairGeneratorSpi_defaultPublicExponent;
}

- (instancetype)initWithNSString:(NSString *)algorithmName {
  LibOrgBouncycastleJcajceProviderAsymmetricRsaJcajceRsaKeyPairGeneratorSpi_initWithNSString_(self, algorithmName);
  return self;
}

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderAsymmetricRsaJcajceRsaKeyPairGeneratorSpi_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)initialize__WithInt:(jint)strength
withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random {
  param_ = new_LibOrgBouncycastleCryptoParamsRSAKeyGenerationParameters_initWithJavaMathBigInteger_withJavaSecuritySecureRandom_withInt_withInt_(LibOrgBouncycastleJcajceProviderAsymmetricRsaJcajceRsaKeyPairGeneratorSpi_defaultPublicExponent, random, strength, LibOrgBouncycastleJcajceProviderAsymmetricUtilPrimeCertaintyCalculator_getDefaultCertaintyWithInt_(strength));
  [((LibOrgBouncycastleCryptoGeneratorsCryptoRSAKeyPairGenerator *) nil_chk(engine_)) init__WithLibOrgBouncycastleCryptoKeyGenerationParameters:param_];
}

- (void)initialize__WithJavaSecuritySpecAlgorithmParameterSpec:(id<JavaSecuritySpecAlgorithmParameterSpec>)params
                                  withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random {
  if (!([params isKindOfClass:[JavaSecuritySpecRSAKeyGenParameterSpec class]])) {
    @throw new_JavaSecurityInvalidAlgorithmParameterException_initWithNSString_(@"parameter object not a RSAKeyGenParameterSpec");
  }
  JavaSecuritySpecRSAKeyGenParameterSpec *rsaParams = (JavaSecuritySpecRSAKeyGenParameterSpec *) cast_chk(params, [JavaSecuritySpecRSAKeyGenParameterSpec class]);
  param_ = new_LibOrgBouncycastleCryptoParamsRSAKeyGenerationParameters_initWithJavaMathBigInteger_withJavaSecuritySecureRandom_withInt_withInt_([((JavaSecuritySpecRSAKeyGenParameterSpec *) nil_chk(rsaParams)) getPublicExponent], random, [rsaParams getKeysize], LibOrgBouncycastleJcajceProviderAsymmetricUtilPrimeCertaintyCalculator_getDefaultCertaintyWithInt_(2048));
  [((LibOrgBouncycastleCryptoGeneratorsCryptoRSAKeyPairGenerator *) nil_chk(engine_)) init__WithLibOrgBouncycastleCryptoKeyGenerationParameters:param_];
}

- (JavaSecurityKeyPair *)generateKeyPair {
  LibOrgBouncycastleCryptoAsymmetricCipherKeyPair *pair = [((LibOrgBouncycastleCryptoGeneratorsCryptoRSAKeyPairGenerator *) nil_chk(engine_)) generateKeyPair];
  LibOrgBouncycastleCryptoParamsRSAKeyParameters *pub = (LibOrgBouncycastleCryptoParamsRSAKeyParameters *) cast_chk([((LibOrgBouncycastleCryptoAsymmetricCipherKeyPair *) nil_chk(pair)) getPublic], [LibOrgBouncycastleCryptoParamsRSAKeyParameters class]);
  LibOrgBouncycastleCryptoParamsRSAPrivateCrtKeyParameters *priv = (LibOrgBouncycastleCryptoParamsRSAPrivateCrtKeyParameters *) cast_chk([pair getPrivate], [LibOrgBouncycastleCryptoParamsRSAPrivateCrtKeyParameters class]);
  return new_JavaSecurityKeyPair_initWithJavaSecurityPublicKey_withJavaSecurityPrivateKey_(new_LibOrgBouncycastleJcajceProviderAsymmetricRsaBCRSAPublicKey_initWithLibOrgBouncycastleCryptoParamsRSAKeyParameters_(pub), new_LibOrgBouncycastleJcajceProviderAsymmetricRsaBCRSAPrivateCrtKey_initWithLibOrgBouncycastleCryptoParamsRSAPrivateCrtKeyParameters_(priv));
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 1, 2, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 1, 3, 4, -1, -1, -1 },
    { NULL, "LJavaSecurityKeyPair;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithNSString:);
  methods[1].selector = @selector(init);
  methods[2].selector = @selector(initialize__WithInt:withJavaSecuritySecureRandom:);
  methods[3].selector = @selector(initialize__WithJavaSecuritySpecAlgorithmParameterSpec:withJavaSecuritySecureRandom:);
  methods[4].selector = @selector(generateKeyPair);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "defaultPublicExponent", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x18, -1, 5, -1, -1 },
    { "param_", "LLibOrgBouncycastleCryptoParamsRSAKeyGenerationParameters;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "engine_", "LLibOrgBouncycastleCryptoGeneratorsCryptoRSAKeyPairGenerator;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LNSString;", "initialize", "ILJavaSecuritySecureRandom;", "LJavaSecuritySpecAlgorithmParameterSpec;LJavaSecuritySecureRandom;", "LJavaSecurityInvalidAlgorithmParameterException;", &LibOrgBouncycastleJcajceProviderAsymmetricRsaJcajceRsaKeyPairGeneratorSpi_defaultPublicExponent };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderAsymmetricRsaJcajceRsaKeyPairGeneratorSpi = { "JcajceRsaKeyPairGeneratorSpi", "lib.org.bouncycastle.jcajce.provider.asymmetric.rsa", ptrTable, methods, fields, 7, 0x1, 5, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderAsymmetricRsaJcajceRsaKeyPairGeneratorSpi;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleJcajceProviderAsymmetricRsaJcajceRsaKeyPairGeneratorSpi class]) {
    LibOrgBouncycastleJcajceProviderAsymmetricRsaJcajceRsaKeyPairGeneratorSpi_defaultPublicExponent = JavaMathBigInteger_valueOfWithLong_((jint) 0x10001);
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleJcajceProviderAsymmetricRsaJcajceRsaKeyPairGeneratorSpi)
  }
}

@end

void LibOrgBouncycastleJcajceProviderAsymmetricRsaJcajceRsaKeyPairGeneratorSpi_initWithNSString_(LibOrgBouncycastleJcajceProviderAsymmetricRsaJcajceRsaKeyPairGeneratorSpi *self, NSString *algorithmName) {
  JavaSecurityKeyPairGenerator_initWithNSString_(self, algorithmName);
}

LibOrgBouncycastleJcajceProviderAsymmetricRsaJcajceRsaKeyPairGeneratorSpi *new_LibOrgBouncycastleJcajceProviderAsymmetricRsaJcajceRsaKeyPairGeneratorSpi_initWithNSString_(NSString *algorithmName) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricRsaJcajceRsaKeyPairGeneratorSpi, initWithNSString_, algorithmName)
}

LibOrgBouncycastleJcajceProviderAsymmetricRsaJcajceRsaKeyPairGeneratorSpi *create_LibOrgBouncycastleJcajceProviderAsymmetricRsaJcajceRsaKeyPairGeneratorSpi_initWithNSString_(NSString *algorithmName) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricRsaJcajceRsaKeyPairGeneratorSpi, initWithNSString_, algorithmName)
}

void LibOrgBouncycastleJcajceProviderAsymmetricRsaJcajceRsaKeyPairGeneratorSpi_init(LibOrgBouncycastleJcajceProviderAsymmetricRsaJcajceRsaKeyPairGeneratorSpi *self) {
  JavaSecurityKeyPairGenerator_initWithNSString_(self, @"RSA");
  self->engine_ = new_LibOrgBouncycastleCryptoGeneratorsCryptoRSAKeyPairGenerator_init();
  self->param_ = new_LibOrgBouncycastleCryptoParamsRSAKeyGenerationParameters_initWithJavaMathBigInteger_withJavaSecuritySecureRandom_withInt_withInt_(LibOrgBouncycastleJcajceProviderAsymmetricRsaJcajceRsaKeyPairGeneratorSpi_defaultPublicExponent, LibOrgBouncycastleCryptoCryptoServicesRegistrar_getSecureRandom(), 2048, LibOrgBouncycastleJcajceProviderAsymmetricUtilPrimeCertaintyCalculator_getDefaultCertaintyWithInt_(2048));
  [((LibOrgBouncycastleCryptoGeneratorsCryptoRSAKeyPairGenerator *) nil_chk(self->engine_)) init__WithLibOrgBouncycastleCryptoKeyGenerationParameters:self->param_];
}

LibOrgBouncycastleJcajceProviderAsymmetricRsaJcajceRsaKeyPairGeneratorSpi *new_LibOrgBouncycastleJcajceProviderAsymmetricRsaJcajceRsaKeyPairGeneratorSpi_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricRsaJcajceRsaKeyPairGeneratorSpi, init)
}

LibOrgBouncycastleJcajceProviderAsymmetricRsaJcajceRsaKeyPairGeneratorSpi *create_LibOrgBouncycastleJcajceProviderAsymmetricRsaJcajceRsaKeyPairGeneratorSpi_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricRsaJcajceRsaKeyPairGeneratorSpi, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderAsymmetricRsaJcajceRsaKeyPairGeneratorSpi)