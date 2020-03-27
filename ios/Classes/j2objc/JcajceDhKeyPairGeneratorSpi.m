//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/asymmetric/dh/JcajceDhKeyPairGeneratorSpi.java
//

#include "AsymmetricCipherKeyPair.h"
#include "AsymmetricKeyParameter.h"
#include "BCDHPrivateKey.h"
#include "BCDHPublicKey.h"
#include "BouncyCastleProvider.h"
#include "CryptoServicesRegistrar.h"
#include "DHBasicKeyPairGenerator.h"
#include "DHDomainParameterSpec.h"
#include "DHKeyGenerationParameters.h"
#include "DHParameters.h"
#include "DHParametersGenerator.h"
#include "DHPrivateKeyParameters.h"
#include "DHPublicKeyParameters.h"
#include "Integers.h"
#include "J2ObjC_source.h"
#include "JcajceDhKeyPairGeneratorSpi.h"
#include "PrimeCertaintyCalculator.h"
#include "ProviderConfiguration.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/Integer.h"
#include "java/math/BigInteger.h"
#include "java/security/InvalidAlgorithmParameterException.h"
#include "java/security/KeyPair.h"
#include "java/security/KeyPairGenerator.h"
#include "java/security/SecureRandom.h"
#include "java/security/spec/AlgorithmParameterSpec.h"
#include "java/util/Hashtable.h"
#include "javax/crypto/spec/DHParameterSpec.h"

@interface LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhKeyPairGeneratorSpi ()

- (LibOrgBouncycastleCryptoParamsDHKeyGenerationParameters *)convertParamsWithJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random
                                                                    withJavaxCryptoSpecDHParameterSpec:(JavaxCryptoSpecDHParameterSpec *)dhParams;

@end

inline JavaUtilHashtable *LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhKeyPairGeneratorSpi_get_params(void);
inline JavaUtilHashtable *LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhKeyPairGeneratorSpi_set_params(JavaUtilHashtable *value);
static JavaUtilHashtable *LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhKeyPairGeneratorSpi_params;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhKeyPairGeneratorSpi, params, JavaUtilHashtable *)

inline id LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhKeyPairGeneratorSpi_get_lock(void);
inline id LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhKeyPairGeneratorSpi_set_lock(id value);
static id LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhKeyPairGeneratorSpi_lock;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhKeyPairGeneratorSpi, lock, id)

__attribute__((unused)) static LibOrgBouncycastleCryptoParamsDHKeyGenerationParameters *LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhKeyPairGeneratorSpi_convertParamsWithJavaSecuritySecureRandom_withJavaxCryptoSpecDHParameterSpec_(LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhKeyPairGeneratorSpi *self, JavaSecuritySecureRandom *random, JavaxCryptoSpecDHParameterSpec *dhParams);

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhKeyPairGeneratorSpi)

@implementation LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhKeyPairGeneratorSpi

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhKeyPairGeneratorSpi_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)initialize__WithInt:(jint)strength
withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random {
  self->strength_ = strength;
  self->random_ = random;
  self->initialised_ = false;
}

- (void)initialize__WithJavaSecuritySpecAlgorithmParameterSpec:(id<JavaSecuritySpecAlgorithmParameterSpec>)params
                                  withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random {
  if (!([params isKindOfClass:[JavaxCryptoSpecDHParameterSpec class]])) {
    @throw new_JavaSecurityInvalidAlgorithmParameterException_initWithNSString_(@"parameter object not a DHParameterSpec");
  }
  JavaxCryptoSpecDHParameterSpec *dhParams = (JavaxCryptoSpecDHParameterSpec *) cast_chk(params, [JavaxCryptoSpecDHParameterSpec class]);
  @try {
    param_ = LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhKeyPairGeneratorSpi_convertParamsWithJavaSecuritySecureRandom_withJavaxCryptoSpecDHParameterSpec_(self, random, dhParams);
  }
  @catch (JavaLangIllegalArgumentException *e) {
    @throw new_JavaSecurityInvalidAlgorithmParameterException_initWithNSString_withJavaLangThrowable_([e getMessage], e);
  }
  [((LibOrgBouncycastleCryptoGeneratorsDHBasicKeyPairGenerator *) nil_chk(engine_)) init__WithLibOrgBouncycastleCryptoKeyGenerationParameters:param_];
  initialised_ = true;
}

- (LibOrgBouncycastleCryptoParamsDHKeyGenerationParameters *)convertParamsWithJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random
                                                                    withJavaxCryptoSpecDHParameterSpec:(JavaxCryptoSpecDHParameterSpec *)dhParams {
  return LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhKeyPairGeneratorSpi_convertParamsWithJavaSecuritySecureRandom_withJavaxCryptoSpecDHParameterSpec_(self, random, dhParams);
}

- (JavaSecurityKeyPair *)generateKeyPair {
  if (!initialised_) {
    JavaLangInteger *paramStrength = LibOrgBouncycastleUtilIntegers_valueOfWithInt_(strength_);
    if ([((JavaUtilHashtable *) nil_chk(LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhKeyPairGeneratorSpi_params)) containsKeyWithId:paramStrength]) {
      param_ = (LibOrgBouncycastleCryptoParamsDHKeyGenerationParameters *) cast_chk([((JavaUtilHashtable *) nil_chk(LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhKeyPairGeneratorSpi_params)) getWithId:paramStrength], [LibOrgBouncycastleCryptoParamsDHKeyGenerationParameters class]);
    }
    else {
      JavaxCryptoSpecDHParameterSpec *dhParams = [((id<LibOrgBouncycastleJcajceProviderConfigProviderConfiguration>) nil_chk(JreLoadStatic(LibOrgBouncycastleJceProviderBouncyCastleProvider, CONFIGURATION))) getDHDefaultParametersWithInt:strength_];
      if (dhParams != nil) {
        param_ = LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhKeyPairGeneratorSpi_convertParamsWithJavaSecuritySecureRandom_withJavaxCryptoSpecDHParameterSpec_(self, random_, dhParams);
      }
      else {
        @synchronized(LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhKeyPairGeneratorSpi_lock) {
          if ([((JavaUtilHashtable *) nil_chk(LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhKeyPairGeneratorSpi_params)) containsKeyWithId:paramStrength]) {
            param_ = (LibOrgBouncycastleCryptoParamsDHKeyGenerationParameters *) cast_chk([((JavaUtilHashtable *) nil_chk(LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhKeyPairGeneratorSpi_params)) getWithId:paramStrength], [LibOrgBouncycastleCryptoParamsDHKeyGenerationParameters class]);
          }
          else {
            LibOrgBouncycastleCryptoGeneratorsDHParametersGenerator *pGen = new_LibOrgBouncycastleCryptoGeneratorsDHParametersGenerator_init();
            [pGen init__WithInt:strength_ withInt:LibOrgBouncycastleJcajceProviderAsymmetricUtilPrimeCertaintyCalculator_getDefaultCertaintyWithInt_(strength_) withJavaSecuritySecureRandom:random_];
            param_ = new_LibOrgBouncycastleCryptoParamsDHKeyGenerationParameters_initWithJavaSecuritySecureRandom_withLibOrgBouncycastleCryptoParamsDHParameters_(random_, [pGen generateParameters]);
            (void) [((JavaUtilHashtable *) nil_chk(LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhKeyPairGeneratorSpi_params)) putWithId:paramStrength withId:param_];
          }
        }
      }
    }
    [((LibOrgBouncycastleCryptoGeneratorsDHBasicKeyPairGenerator *) nil_chk(engine_)) init__WithLibOrgBouncycastleCryptoKeyGenerationParameters:param_];
    initialised_ = true;
  }
  LibOrgBouncycastleCryptoAsymmetricCipherKeyPair *pair = [((LibOrgBouncycastleCryptoGeneratorsDHBasicKeyPairGenerator *) nil_chk(engine_)) generateKeyPair];
  LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *pub = (LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *) cast_chk([((LibOrgBouncycastleCryptoAsymmetricCipherKeyPair *) nil_chk(pair)) getPublic], [LibOrgBouncycastleCryptoParamsDHPublicKeyParameters class]);
  LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *priv = (LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *) cast_chk([pair getPrivate], [LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters class]);
  return new_JavaSecurityKeyPair_initWithJavaSecurityPublicKey_withJavaSecurityPrivateKey_(new_LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey_initWithLibOrgBouncycastleCryptoParamsDHPublicKeyParameters_(pub), new_LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey_initWithLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters_(priv));
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 2, 3, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoParamsDHKeyGenerationParameters;", 0x2, 4, 5, -1, -1, -1, -1 },
    { NULL, "LJavaSecurityKeyPair;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(initialize__WithInt:withJavaSecuritySecureRandom:);
  methods[2].selector = @selector(initialize__WithJavaSecuritySpecAlgorithmParameterSpec:withJavaSecuritySecureRandom:);
  methods[3].selector = @selector(convertParamsWithJavaSecuritySecureRandom:withJavaxCryptoSpecDHParameterSpec:);
  methods[4].selector = @selector(generateKeyPair);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "params", "LJavaUtilHashtable;", .constantValue.asLong = 0, 0xa, -1, 6, -1, -1 },
    { "lock", "LNSObject;", .constantValue.asLong = 0, 0xa, -1, 7, -1, -1 },
    { "param_", "LLibOrgBouncycastleCryptoParamsDHKeyGenerationParameters;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "engine_", "LLibOrgBouncycastleCryptoGeneratorsDHBasicKeyPairGenerator;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "strength_", "I", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "random_", "LJavaSecuritySecureRandom;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "initialised_", "Z", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "initialize", "ILJavaSecuritySecureRandom;", "LJavaSecuritySpecAlgorithmParameterSpec;LJavaSecuritySecureRandom;", "LJavaSecurityInvalidAlgorithmParameterException;", "convertParams", "LJavaSecuritySecureRandom;LJavaxCryptoSpecDHParameterSpec;", &LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhKeyPairGeneratorSpi_params, &LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhKeyPairGeneratorSpi_lock };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhKeyPairGeneratorSpi = { "JcajceDhKeyPairGeneratorSpi", "lib.org.bouncycastle.jcajce.provider.asymmetric.dh", ptrTable, methods, fields, 7, 0x1, 5, 7, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhKeyPairGeneratorSpi;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhKeyPairGeneratorSpi class]) {
    LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhKeyPairGeneratorSpi_params = new_JavaUtilHashtable_init();
    LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhKeyPairGeneratorSpi_lock = new_NSObject_init();
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhKeyPairGeneratorSpi)
  }
}

@end

void LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhKeyPairGeneratorSpi_init(LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhKeyPairGeneratorSpi *self) {
  JavaSecurityKeyPairGenerator_initWithNSString_(self, @"DH");
  self->engine_ = new_LibOrgBouncycastleCryptoGeneratorsDHBasicKeyPairGenerator_init();
  self->strength_ = 2048;
  self->random_ = LibOrgBouncycastleCryptoCryptoServicesRegistrar_getSecureRandom();
  self->initialised_ = false;
}

LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhKeyPairGeneratorSpi *new_LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhKeyPairGeneratorSpi_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhKeyPairGeneratorSpi, init)
}

LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhKeyPairGeneratorSpi *create_LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhKeyPairGeneratorSpi_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhKeyPairGeneratorSpi, init)
}

LibOrgBouncycastleCryptoParamsDHKeyGenerationParameters *LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhKeyPairGeneratorSpi_convertParamsWithJavaSecuritySecureRandom_withJavaxCryptoSpecDHParameterSpec_(LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhKeyPairGeneratorSpi *self, JavaSecuritySecureRandom *random, JavaxCryptoSpecDHParameterSpec *dhParams) {
  if ([dhParams isKindOfClass:[LibOrgBouncycastleJcajceSpecDHDomainParameterSpec class]]) {
    return new_LibOrgBouncycastleCryptoParamsDHKeyGenerationParameters_initWithJavaSecuritySecureRandom_withLibOrgBouncycastleCryptoParamsDHParameters_(random, [((LibOrgBouncycastleJcajceSpecDHDomainParameterSpec *) nil_chk(((LibOrgBouncycastleJcajceSpecDHDomainParameterSpec *) dhParams))) getDomainParameters]);
  }
  return new_LibOrgBouncycastleCryptoParamsDHKeyGenerationParameters_initWithJavaSecuritySecureRandom_withLibOrgBouncycastleCryptoParamsDHParameters_(random, new_LibOrgBouncycastleCryptoParamsDHParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withInt_([((JavaxCryptoSpecDHParameterSpec *) nil_chk(dhParams)) getP], [dhParams getG], nil, [dhParams getL]));
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhKeyPairGeneratorSpi)