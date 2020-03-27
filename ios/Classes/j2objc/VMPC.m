//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/symmetric/VMPC.java
//

#include "AlgorithmProvider.h"
#include "BaseKeyGenerator.h"
#include "BaseMac.h"
#include "BaseStreamCipher.h"
#include "CipherKeyGenerator.h"
#include "ConfigurableProvider.h"
#include "IOSClass.h"
#include "J2ObjC_source.h"
#include "VMPC.h"
#include "VMPCEngine.h"
#include "VMPCMac.h"

@interface LibOrgBouncycastleJcajceProviderSymmetricVMPC ()

- (instancetype)init;

@end

__attribute__((unused)) static void LibOrgBouncycastleJcajceProviderSymmetricVMPC_init(LibOrgBouncycastleJcajceProviderSymmetricVMPC *self);

__attribute__((unused)) static LibOrgBouncycastleJcajceProviderSymmetricVMPC *new_LibOrgBouncycastleJcajceProviderSymmetricVMPC_init(void) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleJcajceProviderSymmetricVMPC *create_LibOrgBouncycastleJcajceProviderSymmetricVMPC_init(void);

inline NSString *LibOrgBouncycastleJcajceProviderSymmetricVMPC_Mappings_get_PREFIX(void);
static NSString *LibOrgBouncycastleJcajceProviderSymmetricVMPC_Mappings_PREFIX;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleJcajceProviderSymmetricVMPC_Mappings, PREFIX, NSString *)

@implementation LibOrgBouncycastleJcajceProviderSymmetricVMPC

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricVMPC_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderSymmetricVMPC_Base;LLibOrgBouncycastleJcajceProviderSymmetricVMPC_KeyGen;LLibOrgBouncycastleJcajceProviderSymmetricVMPC_Mac;LLibOrgBouncycastleJcajceProviderSymmetricVMPC_Mappings;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricVMPC = { "VMPC", "lib.org.bouncycastle.jcajce.provider.symmetric", ptrTable, methods, NULL, 7, 0x11, 1, 0, -1, 0, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricVMPC;
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricVMPC_init(LibOrgBouncycastleJcajceProviderSymmetricVMPC *self) {
  NSObject_init(self);
}

LibOrgBouncycastleJcajceProviderSymmetricVMPC *new_LibOrgBouncycastleJcajceProviderSymmetricVMPC_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricVMPC, init)
}

LibOrgBouncycastleJcajceProviderSymmetricVMPC *create_LibOrgBouncycastleJcajceProviderSymmetricVMPC_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricVMPC, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricVMPC)

@implementation LibOrgBouncycastleJcajceProviderSymmetricVMPC_Base

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricVMPC_Base_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderSymmetricVMPC;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricVMPC_Base = { "Base", "lib.org.bouncycastle.jcajce.provider.symmetric", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricVMPC_Base;
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricVMPC_Base_init(LibOrgBouncycastleJcajceProviderSymmetricVMPC_Base *self) {
  LibOrgBouncycastleJcajceProviderSymmetricUtilBaseStreamCipher_initWithLibOrgBouncycastleCryptoStreamCipher_withInt_(self, new_LibOrgBouncycastleCryptoEnginesVMPCEngine_init(), 16);
}

LibOrgBouncycastleJcajceProviderSymmetricVMPC_Base *new_LibOrgBouncycastleJcajceProviderSymmetricVMPC_Base_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricVMPC_Base, init)
}

LibOrgBouncycastleJcajceProviderSymmetricVMPC_Base *create_LibOrgBouncycastleJcajceProviderSymmetricVMPC_Base_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricVMPC_Base, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricVMPC_Base)

@implementation LibOrgBouncycastleJcajceProviderSymmetricVMPC_KeyGen

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricVMPC_KeyGen_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderSymmetricVMPC;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricVMPC_KeyGen = { "KeyGen", "lib.org.bouncycastle.jcajce.provider.symmetric", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricVMPC_KeyGen;
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricVMPC_KeyGen_init(LibOrgBouncycastleJcajceProviderSymmetricVMPC_KeyGen *self) {
  LibOrgBouncycastleJcajceProviderSymmetricUtilBaseKeyGenerator_initWithNSString_withInt_withLibOrgBouncycastleCryptoCipherKeyGenerator_(self, @"VMPC", 128, new_LibOrgBouncycastleCryptoCipherKeyGenerator_init());
}

LibOrgBouncycastleJcajceProviderSymmetricVMPC_KeyGen *new_LibOrgBouncycastleJcajceProviderSymmetricVMPC_KeyGen_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricVMPC_KeyGen, init)
}

LibOrgBouncycastleJcajceProviderSymmetricVMPC_KeyGen *create_LibOrgBouncycastleJcajceProviderSymmetricVMPC_KeyGen_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricVMPC_KeyGen, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricVMPC_KeyGen)

@implementation LibOrgBouncycastleJcajceProviderSymmetricVMPC_Mac

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricVMPC_Mac_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderSymmetricVMPC;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricVMPC_Mac = { "Mac", "lib.org.bouncycastle.jcajce.provider.symmetric", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricVMPC_Mac;
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricVMPC_Mac_init(LibOrgBouncycastleJcajceProviderSymmetricVMPC_Mac *self) {
  LibOrgBouncycastleJcajceProviderSymmetricUtilBaseMac_initWithLibOrgBouncycastleCryptoMac_(self, new_LibOrgBouncycastleCryptoMacsVMPCMac_init());
}

LibOrgBouncycastleJcajceProviderSymmetricVMPC_Mac *new_LibOrgBouncycastleJcajceProviderSymmetricVMPC_Mac_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricVMPC_Mac, init)
}

LibOrgBouncycastleJcajceProviderSymmetricVMPC_Mac *create_LibOrgBouncycastleJcajceProviderSymmetricVMPC_Mac_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricVMPC_Mac, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricVMPC_Mac)

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleJcajceProviderSymmetricVMPC_Mappings)

@implementation LibOrgBouncycastleJcajceProviderSymmetricVMPC_Mappings

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricVMPC_Mappings_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)configureWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:(id<LibOrgBouncycastleJcajceProviderConfigConfigurableProvider>)provider {
  [((id<LibOrgBouncycastleJcajceProviderConfigConfigurableProvider>) nil_chk(provider)) addAlgorithmWithNSString:@"Cipher.VMPC" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderSymmetricVMPC_Mappings_PREFIX, @"$Base")];
  [provider addAlgorithmWithNSString:@"KeyGenerator.VMPC" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderSymmetricVMPC_Mappings_PREFIX, @"$KeyGen")];
  [provider addAlgorithmWithNSString:@"Mac.VMPCMAC" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderSymmetricVMPC_Mappings_PREFIX, @"$Mac")];
  [provider addAlgorithmWithNSString:@"Alg.Alias.Mac.VMPC" withNSString:@"VMPCMAC"];
  [provider addAlgorithmWithNSString:@"Alg.Alias.Mac.VMPC-MAC" withNSString:@"VMPCMAC"];
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
  static const void *ptrTable[] = { "configure", "LLibOrgBouncycastleJcajceProviderConfigConfigurableProvider;", &LibOrgBouncycastleJcajceProviderSymmetricVMPC_Mappings_PREFIX, "LLibOrgBouncycastleJcajceProviderSymmetricVMPC;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricVMPC_Mappings = { "Mappings", "lib.org.bouncycastle.jcajce.provider.symmetric", ptrTable, methods, fields, 7, 0x9, 2, 1, 3, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricVMPC_Mappings;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleJcajceProviderSymmetricVMPC_Mappings class]) {
    LibOrgBouncycastleJcajceProviderSymmetricVMPC_Mappings_PREFIX = [LibOrgBouncycastleJcajceProviderSymmetricVMPC_class_() getName];
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleJcajceProviderSymmetricVMPC_Mappings)
  }
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricVMPC_Mappings_init(LibOrgBouncycastleJcajceProviderSymmetricVMPC_Mappings *self) {
  LibOrgBouncycastleJcajceProviderUtilAlgorithmProvider_init(self);
}

LibOrgBouncycastleJcajceProviderSymmetricVMPC_Mappings *new_LibOrgBouncycastleJcajceProviderSymmetricVMPC_Mappings_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricVMPC_Mappings, init)
}

LibOrgBouncycastleJcajceProviderSymmetricVMPC_Mappings *create_LibOrgBouncycastleJcajceProviderSymmetricVMPC_Mappings_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricVMPC_Mappings, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricVMPC_Mappings)