//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/symmetric/PBEPKCS12.java
//

#include "ASN1Encoding.h"
#include "ASN1Primitive.h"
#include "AlgorithmProvider.h"
#include "BaseAlgorithmParameters.h"
#include "ConfigurableProvider.h"
#include "IOSClass.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "PBEPKCS12.h"
#include "PKCS12PBEParams.h"
#include "java/io/IOException.h"
#include "java/lang/RuntimeException.h"
#include "java/math/BigInteger.h"
#include "java/security/spec/AlgorithmParameterSpec.h"
#include "java/security/spec/InvalidParameterSpecException.h"
#include "javax/crypto/spec/PBEParameterSpec.h"

@interface LibOrgBouncycastleJcajceProviderSymmetricPBEPKCS12 ()

- (instancetype)init;

@end

__attribute__((unused)) static void LibOrgBouncycastleJcajceProviderSymmetricPBEPKCS12_init(LibOrgBouncycastleJcajceProviderSymmetricPBEPKCS12 *self);

__attribute__((unused)) static LibOrgBouncycastleJcajceProviderSymmetricPBEPKCS12 *new_LibOrgBouncycastleJcajceProviderSymmetricPBEPKCS12_init(void) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleJcajceProviderSymmetricPBEPKCS12 *create_LibOrgBouncycastleJcajceProviderSymmetricPBEPKCS12_init(void);

inline NSString *LibOrgBouncycastleJcajceProviderSymmetricPBEPKCS12_Mappings_get_PREFIX(void);
static NSString *LibOrgBouncycastleJcajceProviderSymmetricPBEPKCS12_Mappings_PREFIX;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleJcajceProviderSymmetricPBEPKCS12_Mappings, PREFIX, NSString *)

@implementation LibOrgBouncycastleJcajceProviderSymmetricPBEPKCS12

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricPBEPKCS12_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderSymmetricPBEPKCS12_AlgParams;LLibOrgBouncycastleJcajceProviderSymmetricPBEPKCS12_Mappings;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricPBEPKCS12 = { "PBEPKCS12", "lib.org.bouncycastle.jcajce.provider.symmetric", ptrTable, methods, NULL, 7, 0x1, 1, 0, -1, 0, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricPBEPKCS12;
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricPBEPKCS12_init(LibOrgBouncycastleJcajceProviderSymmetricPBEPKCS12 *self) {
  NSObject_init(self);
}

LibOrgBouncycastleJcajceProviderSymmetricPBEPKCS12 *new_LibOrgBouncycastleJcajceProviderSymmetricPBEPKCS12_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricPBEPKCS12, init)
}

LibOrgBouncycastleJcajceProviderSymmetricPBEPKCS12 *create_LibOrgBouncycastleJcajceProviderSymmetricPBEPKCS12_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricPBEPKCS12, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricPBEPKCS12)

@implementation LibOrgBouncycastleJcajceProviderSymmetricPBEPKCS12_AlgParams

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricPBEPKCS12_AlgParams_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (IOSByteArray *)engineGetEncoded {
  @try {
    return [((LibOrgBouncycastleAsn1PkcsPKCS12PBEParams *) nil_chk(params_)) getEncodedWithNSString:LibOrgBouncycastleAsn1ASN1Encoding_DER];
  }
  @catch (JavaIoIOException *e) {
    @throw new_JavaLangRuntimeException_initWithNSString_(JreStrcat("$$", @"Oooops! ", [e description]));
  }
}

- (IOSByteArray *)engineGetEncodedWithNSString:(NSString *)format {
  if ([self isASN1FormatStringWithNSString:format]) {
    return [self engineGetEncoded];
  }
  return nil;
}

- (id<JavaSecuritySpecAlgorithmParameterSpec>)localEngineGetParameterSpecWithIOSClass:(IOSClass *)paramSpec {
  if (paramSpec == JavaxCryptoSpecPBEParameterSpec_class_()) {
    return new_JavaxCryptoSpecPBEParameterSpec_initWithByteArray_withInt_([((LibOrgBouncycastleAsn1PkcsPKCS12PBEParams *) nil_chk(params_)) getIV], [((JavaMathBigInteger *) nil_chk([((LibOrgBouncycastleAsn1PkcsPKCS12PBEParams *) nil_chk(params_)) getIterations])) intValue]);
  }
  @throw new_JavaSecuritySpecInvalidParameterSpecException_initWithNSString_(@"unknown parameter spec passed to PKCS12 PBE parameters object.");
}

- (void)engineInitWithJavaSecuritySpecAlgorithmParameterSpec:(id<JavaSecuritySpecAlgorithmParameterSpec>)paramSpec {
  if (!([paramSpec isKindOfClass:[JavaxCryptoSpecPBEParameterSpec class]])) {
    @throw new_JavaSecuritySpecInvalidParameterSpecException_initWithNSString_(@"PBEParameterSpec required to initialise a PKCS12 PBE parameters algorithm parameters object");
  }
  JavaxCryptoSpecPBEParameterSpec *pbeSpec = (JavaxCryptoSpecPBEParameterSpec *) cast_chk(paramSpec, [JavaxCryptoSpecPBEParameterSpec class]);
  self->params_ = new_LibOrgBouncycastleAsn1PkcsPKCS12PBEParams_initWithByteArray_withInt_([((JavaxCryptoSpecPBEParameterSpec *) nil_chk(pbeSpec)) getSalt], [pbeSpec getIterationCount]);
}

- (void)engineInitWithByteArray:(IOSByteArray *)params {
  self->params_ = LibOrgBouncycastleAsn1PkcsPKCS12PBEParams_getInstanceWithId_(LibOrgBouncycastleAsn1ASN1Primitive_fromByteArrayWithByteArray_(params));
}

- (void)engineInitWithByteArray:(IOSByteArray *)params
                   withNSString:(NSString *)format {
  if ([self isASN1FormatStringWithNSString:format]) {
    [self engineInitWithByteArray:params];
    return;
  }
  @throw new_JavaIoIOException_initWithNSString_(@"Unknown parameters format in PKCS12 PBE parameters object");
}

- (NSString *)engineToString {
  return @"PKCS12 PBE Parameters";
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x4, 0, 1, -1, -1, -1, -1 },
    { NULL, "LJavaSecuritySpecAlgorithmParameterSpec;", 0x4, 2, 3, 4, -1, -1, -1 },
    { NULL, "V", 0x4, 5, 6, 4, -1, -1, -1 },
    { NULL, "V", 0x4, 5, 7, 8, -1, -1, -1 },
    { NULL, "V", 0x4, 5, 9, 8, -1, -1, -1 },
    { NULL, "LNSString;", 0x4, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(engineGetEncoded);
  methods[2].selector = @selector(engineGetEncodedWithNSString:);
  methods[3].selector = @selector(localEngineGetParameterSpecWithIOSClass:);
  methods[4].selector = @selector(engineInitWithJavaSecuritySpecAlgorithmParameterSpec:);
  methods[5].selector = @selector(engineInitWithByteArray:);
  methods[6].selector = @selector(engineInitWithByteArray:withNSString:);
  methods[7].selector = @selector(engineToString);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "params_", "LLibOrgBouncycastleAsn1PkcsPKCS12PBEParams;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "engineGetEncoded", "LNSString;", "localEngineGetParameterSpec", "LIOSClass;", "LJavaSecuritySpecInvalidParameterSpecException;", "engineInit", "LJavaSecuritySpecAlgorithmParameterSpec;", "[B", "LJavaIoIOException;", "[BLNSString;", "LLibOrgBouncycastleJcajceProviderSymmetricPBEPKCS12;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricPBEPKCS12_AlgParams = { "AlgParams", "lib.org.bouncycastle.jcajce.provider.symmetric", ptrTable, methods, fields, 7, 0x9, 8, 1, 10, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricPBEPKCS12_AlgParams;
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricPBEPKCS12_AlgParams_init(LibOrgBouncycastleJcajceProviderSymmetricPBEPKCS12_AlgParams *self) {
  LibOrgBouncycastleJcajceProviderSymmetricUtilBaseAlgorithmParameters_init(self);
}

LibOrgBouncycastleJcajceProviderSymmetricPBEPKCS12_AlgParams *new_LibOrgBouncycastleJcajceProviderSymmetricPBEPKCS12_AlgParams_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricPBEPKCS12_AlgParams, init)
}

LibOrgBouncycastleJcajceProviderSymmetricPBEPKCS12_AlgParams *create_LibOrgBouncycastleJcajceProviderSymmetricPBEPKCS12_AlgParams_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricPBEPKCS12_AlgParams, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricPBEPKCS12_AlgParams)

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleJcajceProviderSymmetricPBEPKCS12_Mappings)

@implementation LibOrgBouncycastleJcajceProviderSymmetricPBEPKCS12_Mappings

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricPBEPKCS12_Mappings_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)configureWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:(id<LibOrgBouncycastleJcajceProviderConfigConfigurableProvider>)provider {
  [((id<LibOrgBouncycastleJcajceProviderConfigConfigurableProvider>) nil_chk(provider)) addAlgorithmWithNSString:@"AlgorithmParameters.PKCS12PBE" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderSymmetricPBEPKCS12_Mappings_PREFIX, @"$AlgParams")];
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
  static const void *ptrTable[] = { "configure", "LLibOrgBouncycastleJcajceProviderConfigConfigurableProvider;", &LibOrgBouncycastleJcajceProviderSymmetricPBEPKCS12_Mappings_PREFIX, "LLibOrgBouncycastleJcajceProviderSymmetricPBEPKCS12;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricPBEPKCS12_Mappings = { "Mappings", "lib.org.bouncycastle.jcajce.provider.symmetric", ptrTable, methods, fields, 7, 0x9, 2, 1, 3, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricPBEPKCS12_Mappings;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleJcajceProviderSymmetricPBEPKCS12_Mappings class]) {
    LibOrgBouncycastleJcajceProviderSymmetricPBEPKCS12_Mappings_PREFIX = [LibOrgBouncycastleJcajceProviderSymmetricPBEPKCS12_class_() getName];
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleJcajceProviderSymmetricPBEPKCS12_Mappings)
  }
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricPBEPKCS12_Mappings_init(LibOrgBouncycastleJcajceProviderSymmetricPBEPKCS12_Mappings *self) {
  LibOrgBouncycastleJcajceProviderUtilAlgorithmProvider_init(self);
}

LibOrgBouncycastleJcajceProviderSymmetricPBEPKCS12_Mappings *new_LibOrgBouncycastleJcajceProviderSymmetricPBEPKCS12_Mappings_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricPBEPKCS12_Mappings, init)
}

LibOrgBouncycastleJcajceProviderSymmetricPBEPKCS12_Mappings *create_LibOrgBouncycastleJcajceProviderSymmetricPBEPKCS12_Mappings_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricPBEPKCS12_Mappings, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricPBEPKCS12_Mappings)
