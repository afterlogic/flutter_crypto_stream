//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/symmetric/Salsa20.java
//

#include "AlgorithmProvider.h"
#include "BaseKeyGenerator.h"
#include "BaseStreamCipher.h"
#include "CipherKeyGenerator.h"
#include "ConfigurableProvider.h"
#include "IOSClass.h"
#include "IvAlgorithmParameters.h"
#include "J2ObjC_source.h"
#include "Salsa20.h"
#include "Salsa20Engine.h"

@interface LibOrgBouncycastleJcajceProviderSymmetricSalsa20 ()

- (instancetype)init;

@end

__attribute__((unused)) static void LibOrgBouncycastleJcajceProviderSymmetricSalsa20_init(LibOrgBouncycastleJcajceProviderSymmetricSalsa20 *self);

__attribute__((unused)) static LibOrgBouncycastleJcajceProviderSymmetricSalsa20 *new_LibOrgBouncycastleJcajceProviderSymmetricSalsa20_init(void) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleJcajceProviderSymmetricSalsa20 *create_LibOrgBouncycastleJcajceProviderSymmetricSalsa20_init(void);

inline NSString *LibOrgBouncycastleJcajceProviderSymmetricSalsa20_Mappings_get_PREFIX(void);
static NSString *LibOrgBouncycastleJcajceProviderSymmetricSalsa20_Mappings_PREFIX;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleJcajceProviderSymmetricSalsa20_Mappings, PREFIX, NSString *)

@implementation LibOrgBouncycastleJcajceProviderSymmetricSalsa20

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricSalsa20_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderSymmetricSalsa20_Base;LLibOrgBouncycastleJcajceProviderSymmetricSalsa20_KeyGen;LLibOrgBouncycastleJcajceProviderSymmetricSalsa20_AlgParams;LLibOrgBouncycastleJcajceProviderSymmetricSalsa20_Mappings;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricSalsa20 = { "Salsa20", "lib.org.bouncycastle.jcajce.provider.symmetric", ptrTable, methods, NULL, 7, 0x11, 1, 0, -1, 0, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricSalsa20;
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricSalsa20_init(LibOrgBouncycastleJcajceProviderSymmetricSalsa20 *self) {
  NSObject_init(self);
}

LibOrgBouncycastleJcajceProviderSymmetricSalsa20 *new_LibOrgBouncycastleJcajceProviderSymmetricSalsa20_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricSalsa20, init)
}

LibOrgBouncycastleJcajceProviderSymmetricSalsa20 *create_LibOrgBouncycastleJcajceProviderSymmetricSalsa20_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricSalsa20, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricSalsa20)

@implementation LibOrgBouncycastleJcajceProviderSymmetricSalsa20_Base

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricSalsa20_Base_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderSymmetricSalsa20;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricSalsa20_Base = { "Base", "lib.org.bouncycastle.jcajce.provider.symmetric", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricSalsa20_Base;
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricSalsa20_Base_init(LibOrgBouncycastleJcajceProviderSymmetricSalsa20_Base *self) {
  LibOrgBouncycastleJcajceProviderSymmetricUtilBaseStreamCipher_initWithLibOrgBouncycastleCryptoStreamCipher_withInt_(self, new_LibOrgBouncycastleCryptoEnginesSalsa20Engine_init(), 8);
}

LibOrgBouncycastleJcajceProviderSymmetricSalsa20_Base *new_LibOrgBouncycastleJcajceProviderSymmetricSalsa20_Base_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricSalsa20_Base, init)
}

LibOrgBouncycastleJcajceProviderSymmetricSalsa20_Base *create_LibOrgBouncycastleJcajceProviderSymmetricSalsa20_Base_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricSalsa20_Base, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricSalsa20_Base)

@implementation LibOrgBouncycastleJcajceProviderSymmetricSalsa20_KeyGen

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricSalsa20_KeyGen_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderSymmetricSalsa20;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricSalsa20_KeyGen = { "KeyGen", "lib.org.bouncycastle.jcajce.provider.symmetric", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricSalsa20_KeyGen;
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricSalsa20_KeyGen_init(LibOrgBouncycastleJcajceProviderSymmetricSalsa20_KeyGen *self) {
  LibOrgBouncycastleJcajceProviderSymmetricUtilBaseKeyGenerator_initWithNSString_withInt_withLibOrgBouncycastleCryptoCipherKeyGenerator_(self, @"Salsa20", 128, new_LibOrgBouncycastleCryptoCipherKeyGenerator_init());
}

LibOrgBouncycastleJcajceProviderSymmetricSalsa20_KeyGen *new_LibOrgBouncycastleJcajceProviderSymmetricSalsa20_KeyGen_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricSalsa20_KeyGen, init)
}

LibOrgBouncycastleJcajceProviderSymmetricSalsa20_KeyGen *create_LibOrgBouncycastleJcajceProviderSymmetricSalsa20_KeyGen_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricSalsa20_KeyGen, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricSalsa20_KeyGen)

@implementation LibOrgBouncycastleJcajceProviderSymmetricSalsa20_AlgParams

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricSalsa20_AlgParams_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (NSString *)engineToString {
  return @"Salsa20 IV";
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x4, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(engineToString);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderSymmetricSalsa20;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricSalsa20_AlgParams = { "AlgParams", "lib.org.bouncycastle.jcajce.provider.symmetric", ptrTable, methods, NULL, 7, 0x9, 2, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricSalsa20_AlgParams;
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricSalsa20_AlgParams_init(LibOrgBouncycastleJcajceProviderSymmetricSalsa20_AlgParams *self) {
  LibOrgBouncycastleJcajceProviderSymmetricUtilIvAlgorithmParameters_init(self);
}

LibOrgBouncycastleJcajceProviderSymmetricSalsa20_AlgParams *new_LibOrgBouncycastleJcajceProviderSymmetricSalsa20_AlgParams_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricSalsa20_AlgParams, init)
}

LibOrgBouncycastleJcajceProviderSymmetricSalsa20_AlgParams *create_LibOrgBouncycastleJcajceProviderSymmetricSalsa20_AlgParams_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricSalsa20_AlgParams, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricSalsa20_AlgParams)

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleJcajceProviderSymmetricSalsa20_Mappings)

@implementation LibOrgBouncycastleJcajceProviderSymmetricSalsa20_Mappings

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricSalsa20_Mappings_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)configureWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:(id<LibOrgBouncycastleJcajceProviderConfigConfigurableProvider>)provider {
  [((id<LibOrgBouncycastleJcajceProviderConfigConfigurableProvider>) nil_chk(provider)) addAlgorithmWithNSString:@"Cipher.SALSA20" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderSymmetricSalsa20_Mappings_PREFIX, @"$Base")];
  [provider addAlgorithmWithNSString:@"KeyGenerator.SALSA20" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderSymmetricSalsa20_Mappings_PREFIX, @"$KeyGen")];
  [provider addAlgorithmWithNSString:@"AlgorithmParameters.SALSA20" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderSymmetricSalsa20_Mappings_PREFIX, @"$AlgParams")];
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
  static const void *ptrTable[] = { "configure", "LLibOrgBouncycastleJcajceProviderConfigConfigurableProvider;", &LibOrgBouncycastleJcajceProviderSymmetricSalsa20_Mappings_PREFIX, "LLibOrgBouncycastleJcajceProviderSymmetricSalsa20;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricSalsa20_Mappings = { "Mappings", "lib.org.bouncycastle.jcajce.provider.symmetric", ptrTable, methods, fields, 7, 0x9, 2, 1, 3, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricSalsa20_Mappings;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleJcajceProviderSymmetricSalsa20_Mappings class]) {
    LibOrgBouncycastleJcajceProviderSymmetricSalsa20_Mappings_PREFIX = [LibOrgBouncycastleJcajceProviderSymmetricSalsa20_class_() getName];
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleJcajceProviderSymmetricSalsa20_Mappings)
  }
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricSalsa20_Mappings_init(LibOrgBouncycastleJcajceProviderSymmetricSalsa20_Mappings *self) {
  LibOrgBouncycastleJcajceProviderUtilAlgorithmProvider_init(self);
}

LibOrgBouncycastleJcajceProviderSymmetricSalsa20_Mappings *new_LibOrgBouncycastleJcajceProviderSymmetricSalsa20_Mappings_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricSalsa20_Mappings, init)
}

LibOrgBouncycastleJcajceProviderSymmetricSalsa20_Mappings *create_LibOrgBouncycastleJcajceProviderSymmetricSalsa20_Mappings_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricSalsa20_Mappings, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricSalsa20_Mappings)