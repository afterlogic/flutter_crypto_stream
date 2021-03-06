//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/asymmetric/ecgost/JcajceEcgostKeyAgreementSpi.java
//

#include "AsymmetricKeyParameter.h"
#include "BCECGOST3410PublicKey.h"
#include "BCECPublicKey.h"
#include "BaseAgreementSpi.h"
#include "CipherParameters.h"
#include "DerivationFunction.h"
#include "ECDomainParameters.h"
#include "ECPrivateKeyParameters.h"
#include "ECPublicKey.h"
#include "ECPublicKeyParameters.h"
#include "ECVKOAgreement.h"
#include "GOST3411Digest.h"
#include "IOSClass.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "JcajceEcgostKeyAgreementSpi.h"
#include "JcajceUtilECUtil.h"
#include "JceECPrivateKey.h"
#include "ParametersWithUKM.h"
#include "UserKeyingMaterialSpec.h"
#include "X9IntegerConverter.h"
#include "java/lang/Exception.h"
#include "java/lang/IllegalStateException.h"
#include "java/lang/Throwable.h"
#include "java/security/InvalidAlgorithmParameterException.h"
#include "java/security/InvalidKeyException.h"
#include "java/security/Key.h"
#include "java/security/PrivateKey.h"
#include "java/security/PublicKey.h"
#include "java/security/SecureRandom.h"
#include "java/security/spec/AlgorithmParameterSpec.h"

@interface LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi () {
 @public
  NSString *kaAlgorithm_JcajceEcgostKeyAgreementSpi_;
  LibOrgBouncycastleCryptoParamsECDomainParameters *parameters_;
  LibOrgBouncycastleCryptoAgreementECVKOAgreement *agreement_;
  IOSByteArray *result_;
}

- (void)initFromKeyWithJavaSecurityKey:(id<JavaSecurityKey>)key
withJavaSecuritySpecAlgorithmParameterSpec:(id<JavaSecuritySpecAlgorithmParameterSpec>)parameterSpec OBJC_METHOD_FAMILY_NONE;

+ (NSString *)getSimpleNameWithIOSClass:(IOSClass *)clazz;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi, kaAlgorithm_JcajceEcgostKeyAgreementSpi_, NSString *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi, parameters_, LibOrgBouncycastleCryptoParamsECDomainParameters *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi, agreement_, LibOrgBouncycastleCryptoAgreementECVKOAgreement *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi, result_, IOSByteArray *)

inline LibOrgBouncycastleAsn1X9X9IntegerConverter *LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi_get_converter(void);
static LibOrgBouncycastleAsn1X9X9IntegerConverter *LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi_converter;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi, converter, LibOrgBouncycastleAsn1X9X9IntegerConverter *)

__attribute__((unused)) static void LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi_initFromKeyWithJavaSecurityKey_withJavaSecuritySpecAlgorithmParameterSpec_(LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi *self, id<JavaSecurityKey> key, id<JavaSecuritySpecAlgorithmParameterSpec> parameterSpec);

__attribute__((unused)) static NSString *LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi_getSimpleNameWithIOSClass_(IOSClass *clazz);

@interface LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi_1 : JavaSecurityInvalidKeyException {
 @public
  JavaLangException *val$e_;
}

- (instancetype)initWithJavaLangException:(JavaLangException *)capture$0
                             withNSString:(NSString *)x0;

- (JavaLangThrowable *)getCause;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi_1)

__attribute__((unused)) static void LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi_1_initWithJavaLangException_withNSString_(LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi_1 *self, JavaLangException *capture$0, NSString *x0);

__attribute__((unused)) static LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi_1 *new_LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi_1_initWithJavaLangException_withNSString_(JavaLangException *capture$0, NSString *x0) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi_1 *create_LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi_1_initWithJavaLangException_withNSString_(JavaLangException *capture$0, NSString *x0);

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi)

@implementation LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi

- (instancetype)initWithNSString:(NSString *)kaAlgorithm
withLibOrgBouncycastleCryptoAgreementECVKOAgreement:(LibOrgBouncycastleCryptoAgreementECVKOAgreement *)agreement
withLibOrgBouncycastleCryptoDerivationFunction:(id<LibOrgBouncycastleCryptoDerivationFunction>)kdf {
  LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi_initWithNSString_withLibOrgBouncycastleCryptoAgreementECVKOAgreement_withLibOrgBouncycastleCryptoDerivationFunction_(self, kaAlgorithm, agreement, kdf);
  return self;
}

- (id<JavaSecurityKey>)engineDoPhaseWithJavaSecurityKey:(id<JavaSecurityKey>)key
                                            withBoolean:(jboolean)lastPhase {
  if (parameters_ == nil) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(JreStrcat("$$", kaAlgorithm_JcajceEcgostKeyAgreementSpi_, @" not initialised."));
  }
  if (!lastPhase) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(JreStrcat("$$", kaAlgorithm_JcajceEcgostKeyAgreementSpi_, @" can only be between two parties."));
  }
  id<LibOrgBouncycastleCryptoCipherParameters> pubKey;
  {
    if (!([JavaSecurityPublicKey_class_() isInstance:key])) {
      @throw new_JavaSecurityInvalidKeyException_initWithNSString_(JreStrcat("$$$$", kaAlgorithm_JcajceEcgostKeyAgreementSpi_, @" key agreement requires ", LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi_getSimpleNameWithIOSClass_(LibOrgBouncycastleJceInterfacesECPublicKey_class_()), @" for doPhase"));
    }
    pubKey = LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi_generatePublicKeyParameterWithJavaSecurityPublicKey_((id<JavaSecurityPublicKey>) cast_check(key, JavaSecurityPublicKey_class_()));
  }
  @try {
    result_ = [((LibOrgBouncycastleCryptoAgreementECVKOAgreement *) nil_chk(agreement_)) calculateAgreementWithLibOrgBouncycastleCryptoCipherParameters:pubKey];
  }
  @catch (JavaLangException *e) {
    @throw new_LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi_1_initWithJavaLangException_withNSString_(e, JreStrcat("$$", @"calculation failed: ", [e getMessage]));
  }
  return nil;
}

- (void)engineInitWithJavaSecurityKey:(id<JavaSecurityKey>)key
withJavaSecuritySpecAlgorithmParameterSpec:(id<JavaSecuritySpecAlgorithmParameterSpec>)params
         withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random {
  if (params != nil && !([params isKindOfClass:[LibOrgBouncycastleJcajceSpecUserKeyingMaterialSpec class]])) {
    @throw new_JavaSecurityInvalidAlgorithmParameterException_initWithNSString_(@"No algorithm parameters supported");
  }
  LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi_initFromKeyWithJavaSecurityKey_withJavaSecuritySpecAlgorithmParameterSpec_(self, key, params);
}

- (void)engineInitWithJavaSecurityKey:(id<JavaSecurityKey>)key
         withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random {
  LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi_initFromKeyWithJavaSecurityKey_withJavaSecuritySpecAlgorithmParameterSpec_(self, key, nil);
}

- (void)initFromKeyWithJavaSecurityKey:(id<JavaSecurityKey>)key
withJavaSecuritySpecAlgorithmParameterSpec:(id<JavaSecuritySpecAlgorithmParameterSpec>)parameterSpec {
  LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi_initFromKeyWithJavaSecurityKey_withJavaSecuritySpecAlgorithmParameterSpec_(self, key, parameterSpec);
}

+ (NSString *)getSimpleNameWithIOSClass:(IOSClass *)clazz {
  return LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi_getSimpleNameWithIOSClass_(clazz);
}

- (IOSByteArray *)calcSecret {
  return result_;
}

+ (LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)generatePublicKeyParameterWithJavaSecurityPublicKey:(id<JavaSecurityPublicKey>)key {
  return LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi_generatePublicKeyParameterWithJavaSecurityPublicKey_(key);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x4, -1, 0, -1, -1, -1, -1 },
    { NULL, "LJavaSecurityKey;", 0x4, 1, 2, 3, -1, -1, -1 },
    { NULL, "V", 0x4, 4, 5, 6, -1, -1, -1 },
    { NULL, "V", 0x4, 4, 7, 8, -1, -1, -1 },
    { NULL, "V", 0x2, 9, 10, 8, -1, -1, -1 },
    { NULL, "LNSString;", 0xa, 11, 12, -1, -1, -1, -1 },
    { NULL, "[B", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter;", 0x8, 13, 14, 8, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithNSString:withLibOrgBouncycastleCryptoAgreementECVKOAgreement:withLibOrgBouncycastleCryptoDerivationFunction:);
  methods[1].selector = @selector(engineDoPhaseWithJavaSecurityKey:withBoolean:);
  methods[2].selector = @selector(engineInitWithJavaSecurityKey:withJavaSecuritySpecAlgorithmParameterSpec:withJavaSecuritySecureRandom:);
  methods[3].selector = @selector(engineInitWithJavaSecurityKey:withJavaSecuritySecureRandom:);
  methods[4].selector = @selector(initFromKeyWithJavaSecurityKey:withJavaSecuritySpecAlgorithmParameterSpec:);
  methods[5].selector = @selector(getSimpleNameWithIOSClass:);
  methods[6].selector = @selector(calcSecret);
  methods[7].selector = @selector(generatePublicKeyParameterWithJavaSecurityPublicKey:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "converter", "LLibOrgBouncycastleAsn1X9X9IntegerConverter;", .constantValue.asLong = 0, 0x1a, -1, 15, -1, -1 },
    { "kaAlgorithm_JcajceEcgostKeyAgreementSpi_", "LNSString;", .constantValue.asLong = 0, 0x2, 16, -1, -1, -1 },
    { "parameters_", "LLibOrgBouncycastleCryptoParamsECDomainParameters;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "agreement_", "LLibOrgBouncycastleCryptoAgreementECVKOAgreement;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "result_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LNSString;LLibOrgBouncycastleCryptoAgreementECVKOAgreement;LLibOrgBouncycastleCryptoDerivationFunction;", "engineDoPhase", "LJavaSecurityKey;Z", "LJavaSecurityInvalidKeyException;LJavaLangIllegalStateException;", "engineInit", "LJavaSecurityKey;LJavaSecuritySpecAlgorithmParameterSpec;LJavaSecuritySecureRandom;", "LJavaSecurityInvalidKeyException;LJavaSecurityInvalidAlgorithmParameterException;", "LJavaSecurityKey;LJavaSecuritySecureRandom;", "LJavaSecurityInvalidKeyException;", "initFromKey", "LJavaSecurityKey;LJavaSecuritySpecAlgorithmParameterSpec;", "getSimpleName", "LIOSClass;", "generatePublicKeyParameter", "LJavaSecurityPublicKey;", &LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi_converter, "kaAlgorithm", "LLibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi_ECVKO;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi = { "JcajceEcgostKeyAgreementSpi", "lib.org.bouncycastle.jcajce.provider.asymmetric.ecgost", ptrTable, methods, fields, 7, 0x1, 8, 5, -1, 17, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi class]) {
    LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi_converter = new_LibOrgBouncycastleAsn1X9X9IntegerConverter_init();
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi)
  }
}

@end

void LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi_initWithNSString_withLibOrgBouncycastleCryptoAgreementECVKOAgreement_withLibOrgBouncycastleCryptoDerivationFunction_(LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi *self, NSString *kaAlgorithm, LibOrgBouncycastleCryptoAgreementECVKOAgreement *agreement, id<LibOrgBouncycastleCryptoDerivationFunction> kdf) {
  LibOrgBouncycastleJcajceProviderAsymmetricUtilBaseAgreementSpi_initWithNSString_withLibOrgBouncycastleCryptoDerivationFunction_(self, kaAlgorithm, kdf);
  self->kaAlgorithm_JcajceEcgostKeyAgreementSpi_ = kaAlgorithm;
  self->agreement_ = agreement;
}

LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi *new_LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi_initWithNSString_withLibOrgBouncycastleCryptoAgreementECVKOAgreement_withLibOrgBouncycastleCryptoDerivationFunction_(NSString *kaAlgorithm, LibOrgBouncycastleCryptoAgreementECVKOAgreement *agreement, id<LibOrgBouncycastleCryptoDerivationFunction> kdf) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi, initWithNSString_withLibOrgBouncycastleCryptoAgreementECVKOAgreement_withLibOrgBouncycastleCryptoDerivationFunction_, kaAlgorithm, agreement, kdf)
}

LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi *create_LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi_initWithNSString_withLibOrgBouncycastleCryptoAgreementECVKOAgreement_withLibOrgBouncycastleCryptoDerivationFunction_(NSString *kaAlgorithm, LibOrgBouncycastleCryptoAgreementECVKOAgreement *agreement, id<LibOrgBouncycastleCryptoDerivationFunction> kdf) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi, initWithNSString_withLibOrgBouncycastleCryptoAgreementECVKOAgreement_withLibOrgBouncycastleCryptoDerivationFunction_, kaAlgorithm, agreement, kdf)
}

void LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi_initFromKeyWithJavaSecurityKey_withJavaSecuritySpecAlgorithmParameterSpec_(LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi *self, id<JavaSecurityKey> key, id<JavaSecuritySpecAlgorithmParameterSpec> parameterSpec) {
  {
    if (!([JavaSecurityPrivateKey_class_() isInstance:key])) {
      @throw new_JavaSecurityInvalidKeyException_initWithNSString_(JreStrcat("$$$$", self->kaAlgorithm_JcajceEcgostKeyAgreementSpi_, @" key agreement requires ", LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi_getSimpleNameWithIOSClass_(LibOrgBouncycastleJceInterfacesJceECPrivateKey_class_()), @" for initialisation"));
    }
    LibOrgBouncycastleCryptoParamsECPrivateKeyParameters *privKey = (LibOrgBouncycastleCryptoParamsECPrivateKeyParameters *) cast_chk(LibOrgBouncycastleJcajceProviderAsymmetricUtilJcajceUtilECUtil_generatePrivateKeyParameterWithJavaSecurityPrivateKey_((id<JavaSecurityPrivateKey>) cast_check(key, JavaSecurityPrivateKey_class_())), [LibOrgBouncycastleCryptoParamsECPrivateKeyParameters class]);
    self->parameters_ = [((LibOrgBouncycastleCryptoParamsECPrivateKeyParameters *) nil_chk(privKey)) getParameters];
    self->ukmParameters_ = ([parameterSpec isKindOfClass:[LibOrgBouncycastleJcajceSpecUserKeyingMaterialSpec class]]) ? [((LibOrgBouncycastleJcajceSpecUserKeyingMaterialSpec *) nil_chk(((LibOrgBouncycastleJcajceSpecUserKeyingMaterialSpec *) cast_chk(parameterSpec, [LibOrgBouncycastleJcajceSpecUserKeyingMaterialSpec class])))) getUserKeyingMaterial] : nil;
    [((LibOrgBouncycastleCryptoAgreementECVKOAgreement *) nil_chk(self->agreement_)) init__WithLibOrgBouncycastleCryptoCipherParameters:new_LibOrgBouncycastleCryptoParamsParametersWithUKM_initWithLibOrgBouncycastleCryptoCipherParameters_withByteArray_(privKey, self->ukmParameters_)];
  }
}

NSString *LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi_getSimpleNameWithIOSClass_(IOSClass *clazz) {
  LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi_initialize();
  NSString *fullName = [((IOSClass *) nil_chk(clazz)) getName];
  return [((NSString *) nil_chk(fullName)) java_substring:[fullName java_lastIndexOf:'.'] + 1];
}

LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi_generatePublicKeyParameterWithJavaSecurityPublicKey_(id<JavaSecurityPublicKey> key) {
  LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi_initialize();
  return ([key isKindOfClass:[LibOrgBouncycastleJcajceProviderAsymmetricEcBCECPublicKey class]]) ? [((LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PublicKey *) nil_chk(((LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PublicKey *) cast_chk(key, [LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PublicKey class])))) engineGetKeyParameters] : LibOrgBouncycastleJcajceProviderAsymmetricUtilJcajceUtilECUtil_generatePublicKeyParameterWithJavaSecurityPublicKey_(key);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi)

@implementation LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi_1

- (instancetype)initWithJavaLangException:(JavaLangException *)capture$0
                             withNSString:(NSString *)x0 {
  LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi_1_initWithJavaLangException_withNSString_(self, capture$0, x0);
  return self;
}

- (JavaLangThrowable *)getCause {
  return val$e_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, 0, -1, -1, -1, -1 },
    { NULL, "LJavaLangThrowable;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithJavaLangException:withNSString:);
  methods[1].selector = @selector(getCause);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "val$e_", "LJavaLangException;", .constantValue.asLong = 0, 0x1012, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LNSString;", "LLibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi;", "engineDoPhaseWithJavaSecurityKey:withBoolean:" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi_1 = { "", "lib.org.bouncycastle.jcajce.provider.asymmetric.ecgost", ptrTable, methods, fields, 7, 0x8010, 2, 1, 1, -1, 2, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi_1;
}

@end

void LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi_1_initWithJavaLangException_withNSString_(LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi_1 *self, JavaLangException *capture$0, NSString *x0) {
  self->val$e_ = capture$0;
  JavaSecurityInvalidKeyException_initWithNSString_(self, x0);
}

LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi_1 *new_LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi_1_initWithJavaLangException_withNSString_(JavaLangException *capture$0, NSString *x0) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi_1, initWithJavaLangException_withNSString_, capture$0, x0)
}

LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi_1 *create_LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi_1_initWithJavaLangException_withNSString_(JavaLangException *capture$0, NSString *x0) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi_1, initWithJavaLangException_withNSString_, capture$0, x0)
}

@implementation LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi_ECVKO

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi_ECVKO_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi_ECVKO = { "ECVKO", "lib.org.bouncycastle.jcajce.provider.asymmetric.ecgost", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi_ECVKO;
}

@end

void LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi_ECVKO_init(LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi_ECVKO *self) {
  LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi_initWithNSString_withLibOrgBouncycastleCryptoAgreementECVKOAgreement_withLibOrgBouncycastleCryptoDerivationFunction_(self, @"ECGOST3410", new_LibOrgBouncycastleCryptoAgreementECVKOAgreement_initWithLibOrgBouncycastleCryptoDigest_(new_LibOrgBouncycastleCryptoDigestsGOST3411Digest_init()), nil);
}

LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi_ECVKO *new_LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi_ECVKO_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi_ECVKO, init)
}

LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi_ECVKO *create_LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi_ECVKO_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi_ECVKO, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyAgreementSpi_ECVKO)
