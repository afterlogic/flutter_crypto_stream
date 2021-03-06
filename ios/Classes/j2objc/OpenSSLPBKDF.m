//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/symmetric/OpenSSLPBKDF.java
//

#include "AlgorithmProvider.h"
#include "BaseSecretKeyFactory.h"
#include "CipherParameters.h"
#include "ConfigurableProvider.h"
#include "IOSClass.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "KeyParameter.h"
#include "OpenSSLPBEParametersGenerator.h"
#include "OpenSSLPBKDF.h"
#include "Strings.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/security/spec/InvalidKeySpecException.h"
#include "java/security/spec/KeySpec.h"
#include "javax/crypto/SecretKey.h"
#include "javax/crypto/spec/PBEKeySpec.h"
#include "javax/crypto/spec/SecretKeySpec.h"

@interface LibOrgBouncycastleJcajceProviderSymmetricOpenSSLPBKDF ()

- (instancetype)init;

@end

__attribute__((unused)) static void LibOrgBouncycastleJcajceProviderSymmetricOpenSSLPBKDF_init(LibOrgBouncycastleJcajceProviderSymmetricOpenSSLPBKDF *self);

__attribute__((unused)) static LibOrgBouncycastleJcajceProviderSymmetricOpenSSLPBKDF *new_LibOrgBouncycastleJcajceProviderSymmetricOpenSSLPBKDF_init(void) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleJcajceProviderSymmetricOpenSSLPBKDF *create_LibOrgBouncycastleJcajceProviderSymmetricOpenSSLPBKDF_init(void);

inline NSString *LibOrgBouncycastleJcajceProviderSymmetricOpenSSLPBKDF_Mappings_get_PREFIX(void);
static NSString *LibOrgBouncycastleJcajceProviderSymmetricOpenSSLPBKDF_Mappings_PREFIX;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleJcajceProviderSymmetricOpenSSLPBKDF_Mappings, PREFIX, NSString *)

@implementation LibOrgBouncycastleJcajceProviderSymmetricOpenSSLPBKDF

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricOpenSSLPBKDF_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderSymmetricOpenSSLPBKDF_PBKDF;LLibOrgBouncycastleJcajceProviderSymmetricOpenSSLPBKDF_Mappings;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricOpenSSLPBKDF = { "OpenSSLPBKDF", "lib.org.bouncycastle.jcajce.provider.symmetric", ptrTable, methods, NULL, 7, 0x11, 1, 0, -1, 0, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricOpenSSLPBKDF;
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricOpenSSLPBKDF_init(LibOrgBouncycastleJcajceProviderSymmetricOpenSSLPBKDF *self) {
  NSObject_init(self);
}

LibOrgBouncycastleJcajceProviderSymmetricOpenSSLPBKDF *new_LibOrgBouncycastleJcajceProviderSymmetricOpenSSLPBKDF_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricOpenSSLPBKDF, init)
}

LibOrgBouncycastleJcajceProviderSymmetricOpenSSLPBKDF *create_LibOrgBouncycastleJcajceProviderSymmetricOpenSSLPBKDF_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricOpenSSLPBKDF, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricOpenSSLPBKDF)

@implementation LibOrgBouncycastleJcajceProviderSymmetricOpenSSLPBKDF_PBKDF

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricOpenSSLPBKDF_PBKDF_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (id<JavaxCryptoSecretKey>)engineGenerateSecretWithJavaSecuritySpecKeySpec:(id<JavaSecuritySpecKeySpec>)keySpec {
  if ([keySpec isKindOfClass:[JavaxCryptoSpecPBEKeySpec class]]) {
    JavaxCryptoSpecPBEKeySpec *pbeSpec = (JavaxCryptoSpecPBEKeySpec *) keySpec;
    if ([((JavaxCryptoSpecPBEKeySpec *) nil_chk(pbeSpec)) getSalt] == nil) {
      @throw new_JavaSecuritySpecInvalidKeySpecException_initWithNSString_(@"missing required salt");
    }
    if ([pbeSpec getIterationCount] <= 0) {
      @throw new_JavaSecuritySpecInvalidKeySpecException_initWithNSString_(JreStrcat("$I", @"positive iteration count required: ", [pbeSpec getIterationCount]));
    }
    if ([pbeSpec getKeyLength] <= 0) {
      @throw new_JavaSecuritySpecInvalidKeySpecException_initWithNSString_(JreStrcat("$I", @"positive key length required: ", [pbeSpec getKeyLength]));
    }
    if (((IOSCharArray *) nil_chk([pbeSpec getPassword]))->size_ == 0) {
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"password empty");
    }
    LibOrgBouncycastleCryptoGeneratorsOpenSSLPBEParametersGenerator *pGen = new_LibOrgBouncycastleCryptoGeneratorsOpenSSLPBEParametersGenerator_init();
    [pGen init__WithByteArray:LibOrgBouncycastleUtilStrings_toByteArrayWithCharArray_([pbeSpec getPassword]) withByteArray:[pbeSpec getSalt]];
    return new_JavaxCryptoSpecSecretKeySpec_initWithByteArray_withNSString_([((LibOrgBouncycastleCryptoParamsKeyParameter *) nil_chk(((LibOrgBouncycastleCryptoParamsKeyParameter *) cast_chk([pGen generateDerivedParametersWithInt:[pbeSpec getKeyLength]], [LibOrgBouncycastleCryptoParamsKeyParameter class])))) getKey], @"OpenSSLPBKDF");
  }
  @throw new_JavaSecuritySpecInvalidKeySpecException_initWithNSString_(@"Invalid KeySpec");
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaxCryptoSecretKey;", 0x4, 0, 1, 2, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(engineGenerateSecretWithJavaSecuritySpecKeySpec:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "engineGenerateSecret", "LJavaSecuritySpecKeySpec;", "LJavaSecuritySpecInvalidKeySpecException;", "LLibOrgBouncycastleJcajceProviderSymmetricOpenSSLPBKDF;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricOpenSSLPBKDF_PBKDF = { "PBKDF", "lib.org.bouncycastle.jcajce.provider.symmetric", ptrTable, methods, NULL, 7, 0x9, 2, 0, 3, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricOpenSSLPBKDF_PBKDF;
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricOpenSSLPBKDF_PBKDF_init(LibOrgBouncycastleJcajceProviderSymmetricOpenSSLPBKDF_PBKDF *self) {
  LibOrgBouncycastleJcajceProviderSymmetricUtilBaseSecretKeyFactory_initWithNSString_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(self, @"PBKDF-OpenSSL", nil);
}

LibOrgBouncycastleJcajceProviderSymmetricOpenSSLPBKDF_PBKDF *new_LibOrgBouncycastleJcajceProviderSymmetricOpenSSLPBKDF_PBKDF_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricOpenSSLPBKDF_PBKDF, init)
}

LibOrgBouncycastleJcajceProviderSymmetricOpenSSLPBKDF_PBKDF *create_LibOrgBouncycastleJcajceProviderSymmetricOpenSSLPBKDF_PBKDF_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricOpenSSLPBKDF_PBKDF, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricOpenSSLPBKDF_PBKDF)

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleJcajceProviderSymmetricOpenSSLPBKDF_Mappings)

@implementation LibOrgBouncycastleJcajceProviderSymmetricOpenSSLPBKDF_Mappings

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricOpenSSLPBKDF_Mappings_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)configureWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:(id<LibOrgBouncycastleJcajceProviderConfigConfigurableProvider>)provider {
  [((id<LibOrgBouncycastleJcajceProviderConfigConfigurableProvider>) nil_chk(provider)) addAlgorithmWithNSString:@"SecretKeyFactory.PBKDF-OPENSSL" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderSymmetricOpenSSLPBKDF_Mappings_PREFIX, @"$PBKDF")];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(configureWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "PREFIX", "LNSString;", .constantValue.asLong = 0, 0x1a, -1, 2, -1, -1 },
  };
  static const void *ptrTable[] = { "configure", "LLibOrgBouncycastleJcajceProviderConfigConfigurableProvider;", &LibOrgBouncycastleJcajceProviderSymmetricOpenSSLPBKDF_Mappings_PREFIX, "LLibOrgBouncycastleJcajceProviderSymmetricOpenSSLPBKDF;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricOpenSSLPBKDF_Mappings = { "Mappings", "lib.org.bouncycastle.jcajce.provider.symmetric", ptrTable, methods, fields, 7, 0x9, 2, 1, 3, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricOpenSSLPBKDF_Mappings;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleJcajceProviderSymmetricOpenSSLPBKDF_Mappings class]) {
    LibOrgBouncycastleJcajceProviderSymmetricOpenSSLPBKDF_Mappings_PREFIX = [LibOrgBouncycastleJcajceProviderSymmetricOpenSSLPBKDF_class_() getName];
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleJcajceProviderSymmetricOpenSSLPBKDF_Mappings)
  }
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricOpenSSLPBKDF_Mappings_init(LibOrgBouncycastleJcajceProviderSymmetricOpenSSLPBKDF_Mappings *self) {
  LibOrgBouncycastleJcajceProviderUtilAlgorithmProvider_init(self);
}

LibOrgBouncycastleJcajceProviderSymmetricOpenSSLPBKDF_Mappings *new_LibOrgBouncycastleJcajceProviderSymmetricOpenSSLPBKDF_Mappings_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricOpenSSLPBKDF_Mappings, init)
}

LibOrgBouncycastleJcajceProviderSymmetricOpenSSLPBKDF_Mappings *create_LibOrgBouncycastleJcajceProviderSymmetricOpenSSLPBKDF_Mappings_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricOpenSSLPBKDF_Mappings, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricOpenSSLPBKDF_Mappings)
