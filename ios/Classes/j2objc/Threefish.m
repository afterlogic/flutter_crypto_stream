//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/symmetric/Threefish.java
//

#include "AlgorithmProvider.h"
#include "BaseBlockCipher.h"
#include "BaseKeyGenerator.h"
#include "BaseMac.h"
#include "CMac.h"
#include "CipherKeyGenerator.h"
#include "ConfigurableProvider.h"
#include "IOSClass.h"
#include "IvAlgorithmParameters.h"
#include "J2ObjC_source.h"
#include "Threefish.h"
#include "ThreefishEngine.h"

@interface LibOrgBouncycastleJcajceProviderSymmetricThreefish ()

- (instancetype)init;

@end

__attribute__((unused)) static void LibOrgBouncycastleJcajceProviderSymmetricThreefish_init(LibOrgBouncycastleJcajceProviderSymmetricThreefish *self);

__attribute__((unused)) static LibOrgBouncycastleJcajceProviderSymmetricThreefish *new_LibOrgBouncycastleJcajceProviderSymmetricThreefish_init(void) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleJcajceProviderSymmetricThreefish *create_LibOrgBouncycastleJcajceProviderSymmetricThreefish_init(void);

inline NSString *LibOrgBouncycastleJcajceProviderSymmetricThreefish_Mappings_get_PREFIX(void);
static NSString *LibOrgBouncycastleJcajceProviderSymmetricThreefish_Mappings_PREFIX;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleJcajceProviderSymmetricThreefish_Mappings, PREFIX, NSString *)

@implementation LibOrgBouncycastleJcajceProviderSymmetricThreefish

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricThreefish_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderSymmetricThreefish_ECB_256;LLibOrgBouncycastleJcajceProviderSymmetricThreefish_ECB_512;LLibOrgBouncycastleJcajceProviderSymmetricThreefish_ECB_1024;LLibOrgBouncycastleJcajceProviderSymmetricThreefish_KeyGen_256;LLibOrgBouncycastleJcajceProviderSymmetricThreefish_KeyGen_512;LLibOrgBouncycastleJcajceProviderSymmetricThreefish_KeyGen_1024;LLibOrgBouncycastleJcajceProviderSymmetricThreefish_AlgParams_256;LLibOrgBouncycastleJcajceProviderSymmetricThreefish_AlgParams_512;LLibOrgBouncycastleJcajceProviderSymmetricThreefish_AlgParams_1024;LLibOrgBouncycastleJcajceProviderSymmetricThreefish_CMAC_256;LLibOrgBouncycastleJcajceProviderSymmetricThreefish_CMAC_512;LLibOrgBouncycastleJcajceProviderSymmetricThreefish_CMAC_1024;LLibOrgBouncycastleJcajceProviderSymmetricThreefish_Mappings;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricThreefish = { "Threefish", "lib.org.bouncycastle.jcajce.provider.symmetric", ptrTable, methods, NULL, 7, 0x11, 1, 0, -1, 0, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricThreefish;
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricThreefish_init(LibOrgBouncycastleJcajceProviderSymmetricThreefish *self) {
  NSObject_init(self);
}

LibOrgBouncycastleJcajceProviderSymmetricThreefish *new_LibOrgBouncycastleJcajceProviderSymmetricThreefish_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricThreefish, init)
}

LibOrgBouncycastleJcajceProviderSymmetricThreefish *create_LibOrgBouncycastleJcajceProviderSymmetricThreefish_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricThreefish, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricThreefish)

@implementation LibOrgBouncycastleJcajceProviderSymmetricThreefish_ECB_256

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricThreefish_ECB_256_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderSymmetricThreefish;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricThreefish_ECB_256 = { "ECB_256", "lib.org.bouncycastle.jcajce.provider.symmetric", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricThreefish_ECB_256;
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricThreefish_ECB_256_init(LibOrgBouncycastleJcajceProviderSymmetricThreefish_ECB_256 *self) {
  LibOrgBouncycastleJcajceProviderSymmetricUtilBaseBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_(self, new_LibOrgBouncycastleCryptoEnginesThreefishEngine_initWithInt_(LibOrgBouncycastleCryptoEnginesThreefishEngine_BLOCKSIZE_256));
}

LibOrgBouncycastleJcajceProviderSymmetricThreefish_ECB_256 *new_LibOrgBouncycastleJcajceProviderSymmetricThreefish_ECB_256_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricThreefish_ECB_256, init)
}

LibOrgBouncycastleJcajceProviderSymmetricThreefish_ECB_256 *create_LibOrgBouncycastleJcajceProviderSymmetricThreefish_ECB_256_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricThreefish_ECB_256, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricThreefish_ECB_256)

@implementation LibOrgBouncycastleJcajceProviderSymmetricThreefish_ECB_512

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricThreefish_ECB_512_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderSymmetricThreefish;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricThreefish_ECB_512 = { "ECB_512", "lib.org.bouncycastle.jcajce.provider.symmetric", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricThreefish_ECB_512;
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricThreefish_ECB_512_init(LibOrgBouncycastleJcajceProviderSymmetricThreefish_ECB_512 *self) {
  LibOrgBouncycastleJcajceProviderSymmetricUtilBaseBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_(self, new_LibOrgBouncycastleCryptoEnginesThreefishEngine_initWithInt_(LibOrgBouncycastleCryptoEnginesThreefishEngine_BLOCKSIZE_512));
}

LibOrgBouncycastleJcajceProviderSymmetricThreefish_ECB_512 *new_LibOrgBouncycastleJcajceProviderSymmetricThreefish_ECB_512_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricThreefish_ECB_512, init)
}

LibOrgBouncycastleJcajceProviderSymmetricThreefish_ECB_512 *create_LibOrgBouncycastleJcajceProviderSymmetricThreefish_ECB_512_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricThreefish_ECB_512, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricThreefish_ECB_512)

@implementation LibOrgBouncycastleJcajceProviderSymmetricThreefish_ECB_1024

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricThreefish_ECB_1024_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderSymmetricThreefish;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricThreefish_ECB_1024 = { "ECB_1024", "lib.org.bouncycastle.jcajce.provider.symmetric", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricThreefish_ECB_1024;
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricThreefish_ECB_1024_init(LibOrgBouncycastleJcajceProviderSymmetricThreefish_ECB_1024 *self) {
  LibOrgBouncycastleJcajceProviderSymmetricUtilBaseBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_(self, new_LibOrgBouncycastleCryptoEnginesThreefishEngine_initWithInt_(LibOrgBouncycastleCryptoEnginesThreefishEngine_BLOCKSIZE_1024));
}

LibOrgBouncycastleJcajceProviderSymmetricThreefish_ECB_1024 *new_LibOrgBouncycastleJcajceProviderSymmetricThreefish_ECB_1024_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricThreefish_ECB_1024, init)
}

LibOrgBouncycastleJcajceProviderSymmetricThreefish_ECB_1024 *create_LibOrgBouncycastleJcajceProviderSymmetricThreefish_ECB_1024_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricThreefish_ECB_1024, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricThreefish_ECB_1024)

@implementation LibOrgBouncycastleJcajceProviderSymmetricThreefish_KeyGen_256

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricThreefish_KeyGen_256_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderSymmetricThreefish;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricThreefish_KeyGen_256 = { "KeyGen_256", "lib.org.bouncycastle.jcajce.provider.symmetric", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricThreefish_KeyGen_256;
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricThreefish_KeyGen_256_init(LibOrgBouncycastleJcajceProviderSymmetricThreefish_KeyGen_256 *self) {
  LibOrgBouncycastleJcajceProviderSymmetricUtilBaseKeyGenerator_initWithNSString_withInt_withLibOrgBouncycastleCryptoCipherKeyGenerator_(self, @"Threefish-256", 256, new_LibOrgBouncycastleCryptoCipherKeyGenerator_init());
}

LibOrgBouncycastleJcajceProviderSymmetricThreefish_KeyGen_256 *new_LibOrgBouncycastleJcajceProviderSymmetricThreefish_KeyGen_256_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricThreefish_KeyGen_256, init)
}

LibOrgBouncycastleJcajceProviderSymmetricThreefish_KeyGen_256 *create_LibOrgBouncycastleJcajceProviderSymmetricThreefish_KeyGen_256_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricThreefish_KeyGen_256, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricThreefish_KeyGen_256)

@implementation LibOrgBouncycastleJcajceProviderSymmetricThreefish_KeyGen_512

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricThreefish_KeyGen_512_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderSymmetricThreefish;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricThreefish_KeyGen_512 = { "KeyGen_512", "lib.org.bouncycastle.jcajce.provider.symmetric", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricThreefish_KeyGen_512;
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricThreefish_KeyGen_512_init(LibOrgBouncycastleJcajceProviderSymmetricThreefish_KeyGen_512 *self) {
  LibOrgBouncycastleJcajceProviderSymmetricUtilBaseKeyGenerator_initWithNSString_withInt_withLibOrgBouncycastleCryptoCipherKeyGenerator_(self, @"Threefish-512", 512, new_LibOrgBouncycastleCryptoCipherKeyGenerator_init());
}

LibOrgBouncycastleJcajceProviderSymmetricThreefish_KeyGen_512 *new_LibOrgBouncycastleJcajceProviderSymmetricThreefish_KeyGen_512_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricThreefish_KeyGen_512, init)
}

LibOrgBouncycastleJcajceProviderSymmetricThreefish_KeyGen_512 *create_LibOrgBouncycastleJcajceProviderSymmetricThreefish_KeyGen_512_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricThreefish_KeyGen_512, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricThreefish_KeyGen_512)

@implementation LibOrgBouncycastleJcajceProviderSymmetricThreefish_KeyGen_1024

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricThreefish_KeyGen_1024_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderSymmetricThreefish;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricThreefish_KeyGen_1024 = { "KeyGen_1024", "lib.org.bouncycastle.jcajce.provider.symmetric", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricThreefish_KeyGen_1024;
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricThreefish_KeyGen_1024_init(LibOrgBouncycastleJcajceProviderSymmetricThreefish_KeyGen_1024 *self) {
  LibOrgBouncycastleJcajceProviderSymmetricUtilBaseKeyGenerator_initWithNSString_withInt_withLibOrgBouncycastleCryptoCipherKeyGenerator_(self, @"Threefish-1024", 1024, new_LibOrgBouncycastleCryptoCipherKeyGenerator_init());
}

LibOrgBouncycastleJcajceProviderSymmetricThreefish_KeyGen_1024 *new_LibOrgBouncycastleJcajceProviderSymmetricThreefish_KeyGen_1024_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricThreefish_KeyGen_1024, init)
}

LibOrgBouncycastleJcajceProviderSymmetricThreefish_KeyGen_1024 *create_LibOrgBouncycastleJcajceProviderSymmetricThreefish_KeyGen_1024_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricThreefish_KeyGen_1024, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricThreefish_KeyGen_1024)

@implementation LibOrgBouncycastleJcajceProviderSymmetricThreefish_AlgParams_256

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricThreefish_AlgParams_256_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (NSString *)engineToString {
  return @"Threefish-256 IV";
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderSymmetricThreefish;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricThreefish_AlgParams_256 = { "AlgParams_256", "lib.org.bouncycastle.jcajce.provider.symmetric", ptrTable, methods, NULL, 7, 0x9, 2, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricThreefish_AlgParams_256;
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricThreefish_AlgParams_256_init(LibOrgBouncycastleJcajceProviderSymmetricThreefish_AlgParams_256 *self) {
  LibOrgBouncycastleJcajceProviderSymmetricUtilIvAlgorithmParameters_init(self);
}

LibOrgBouncycastleJcajceProviderSymmetricThreefish_AlgParams_256 *new_LibOrgBouncycastleJcajceProviderSymmetricThreefish_AlgParams_256_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricThreefish_AlgParams_256, init)
}

LibOrgBouncycastleJcajceProviderSymmetricThreefish_AlgParams_256 *create_LibOrgBouncycastleJcajceProviderSymmetricThreefish_AlgParams_256_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricThreefish_AlgParams_256, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricThreefish_AlgParams_256)

@implementation LibOrgBouncycastleJcajceProviderSymmetricThreefish_AlgParams_512

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricThreefish_AlgParams_512_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (NSString *)engineToString {
  return @"Threefish-512 IV";
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderSymmetricThreefish;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricThreefish_AlgParams_512 = { "AlgParams_512", "lib.org.bouncycastle.jcajce.provider.symmetric", ptrTable, methods, NULL, 7, 0x9, 2, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricThreefish_AlgParams_512;
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricThreefish_AlgParams_512_init(LibOrgBouncycastleJcajceProviderSymmetricThreefish_AlgParams_512 *self) {
  LibOrgBouncycastleJcajceProviderSymmetricUtilIvAlgorithmParameters_init(self);
}

LibOrgBouncycastleJcajceProviderSymmetricThreefish_AlgParams_512 *new_LibOrgBouncycastleJcajceProviderSymmetricThreefish_AlgParams_512_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricThreefish_AlgParams_512, init)
}

LibOrgBouncycastleJcajceProviderSymmetricThreefish_AlgParams_512 *create_LibOrgBouncycastleJcajceProviderSymmetricThreefish_AlgParams_512_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricThreefish_AlgParams_512, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricThreefish_AlgParams_512)

@implementation LibOrgBouncycastleJcajceProviderSymmetricThreefish_AlgParams_1024

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricThreefish_AlgParams_1024_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (NSString *)engineToString {
  return @"Threefish-1024 IV";
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderSymmetricThreefish;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricThreefish_AlgParams_1024 = { "AlgParams_1024", "lib.org.bouncycastle.jcajce.provider.symmetric", ptrTable, methods, NULL, 7, 0x9, 2, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricThreefish_AlgParams_1024;
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricThreefish_AlgParams_1024_init(LibOrgBouncycastleJcajceProviderSymmetricThreefish_AlgParams_1024 *self) {
  LibOrgBouncycastleJcajceProviderSymmetricUtilIvAlgorithmParameters_init(self);
}

LibOrgBouncycastleJcajceProviderSymmetricThreefish_AlgParams_1024 *new_LibOrgBouncycastleJcajceProviderSymmetricThreefish_AlgParams_1024_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricThreefish_AlgParams_1024, init)
}

LibOrgBouncycastleJcajceProviderSymmetricThreefish_AlgParams_1024 *create_LibOrgBouncycastleJcajceProviderSymmetricThreefish_AlgParams_1024_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricThreefish_AlgParams_1024, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricThreefish_AlgParams_1024)

@implementation LibOrgBouncycastleJcajceProviderSymmetricThreefish_CMAC_256

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricThreefish_CMAC_256_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderSymmetricThreefish;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricThreefish_CMAC_256 = { "CMAC_256", "lib.org.bouncycastle.jcajce.provider.symmetric", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricThreefish_CMAC_256;
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricThreefish_CMAC_256_init(LibOrgBouncycastleJcajceProviderSymmetricThreefish_CMAC_256 *self) {
  LibOrgBouncycastleJcajceProviderSymmetricUtilBaseMac_initWithLibOrgBouncycastleCryptoMac_(self, new_LibOrgBouncycastleCryptoMacsCMac_initWithLibOrgBouncycastleCryptoBlockCipher_(new_LibOrgBouncycastleCryptoEnginesThreefishEngine_initWithInt_(256)));
}

LibOrgBouncycastleJcajceProviderSymmetricThreefish_CMAC_256 *new_LibOrgBouncycastleJcajceProviderSymmetricThreefish_CMAC_256_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricThreefish_CMAC_256, init)
}

LibOrgBouncycastleJcajceProviderSymmetricThreefish_CMAC_256 *create_LibOrgBouncycastleJcajceProviderSymmetricThreefish_CMAC_256_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricThreefish_CMAC_256, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricThreefish_CMAC_256)

@implementation LibOrgBouncycastleJcajceProviderSymmetricThreefish_CMAC_512

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricThreefish_CMAC_512_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderSymmetricThreefish;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricThreefish_CMAC_512 = { "CMAC_512", "lib.org.bouncycastle.jcajce.provider.symmetric", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricThreefish_CMAC_512;
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricThreefish_CMAC_512_init(LibOrgBouncycastleJcajceProviderSymmetricThreefish_CMAC_512 *self) {
  LibOrgBouncycastleJcajceProviderSymmetricUtilBaseMac_initWithLibOrgBouncycastleCryptoMac_(self, new_LibOrgBouncycastleCryptoMacsCMac_initWithLibOrgBouncycastleCryptoBlockCipher_(new_LibOrgBouncycastleCryptoEnginesThreefishEngine_initWithInt_(512)));
}

LibOrgBouncycastleJcajceProviderSymmetricThreefish_CMAC_512 *new_LibOrgBouncycastleJcajceProviderSymmetricThreefish_CMAC_512_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricThreefish_CMAC_512, init)
}

LibOrgBouncycastleJcajceProviderSymmetricThreefish_CMAC_512 *create_LibOrgBouncycastleJcajceProviderSymmetricThreefish_CMAC_512_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricThreefish_CMAC_512, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricThreefish_CMAC_512)

@implementation LibOrgBouncycastleJcajceProviderSymmetricThreefish_CMAC_1024

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricThreefish_CMAC_1024_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderSymmetricThreefish;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricThreefish_CMAC_1024 = { "CMAC_1024", "lib.org.bouncycastle.jcajce.provider.symmetric", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricThreefish_CMAC_1024;
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricThreefish_CMAC_1024_init(LibOrgBouncycastleJcajceProviderSymmetricThreefish_CMAC_1024 *self) {
  LibOrgBouncycastleJcajceProviderSymmetricUtilBaseMac_initWithLibOrgBouncycastleCryptoMac_(self, new_LibOrgBouncycastleCryptoMacsCMac_initWithLibOrgBouncycastleCryptoBlockCipher_(new_LibOrgBouncycastleCryptoEnginesThreefishEngine_initWithInt_(1024)));
}

LibOrgBouncycastleJcajceProviderSymmetricThreefish_CMAC_1024 *new_LibOrgBouncycastleJcajceProviderSymmetricThreefish_CMAC_1024_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricThreefish_CMAC_1024, init)
}

LibOrgBouncycastleJcajceProviderSymmetricThreefish_CMAC_1024 *create_LibOrgBouncycastleJcajceProviderSymmetricThreefish_CMAC_1024_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricThreefish_CMAC_1024, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricThreefish_CMAC_1024)

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleJcajceProviderSymmetricThreefish_Mappings)

@implementation LibOrgBouncycastleJcajceProviderSymmetricThreefish_Mappings

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricThreefish_Mappings_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)configureWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:(id<LibOrgBouncycastleJcajceProviderConfigConfigurableProvider>)provider {
  [((id<LibOrgBouncycastleJcajceProviderConfigConfigurableProvider>) nil_chk(provider)) addAlgorithmWithNSString:@"Mac.Threefish-256CMAC" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderSymmetricThreefish_Mappings_PREFIX, @"$CMAC_256")];
  [provider addAlgorithmWithNSString:@"Mac.Threefish-512CMAC" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderSymmetricThreefish_Mappings_PREFIX, @"$CMAC_512")];
  [provider addAlgorithmWithNSString:@"Mac.Threefish-1024CMAC" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderSymmetricThreefish_Mappings_PREFIX, @"$CMAC_1024")];
  [provider addAlgorithmWithNSString:@"Cipher.Threefish-256" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderSymmetricThreefish_Mappings_PREFIX, @"$ECB_256")];
  [provider addAlgorithmWithNSString:@"Cipher.Threefish-512" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderSymmetricThreefish_Mappings_PREFIX, @"$ECB_512")];
  [provider addAlgorithmWithNSString:@"Cipher.Threefish-1024" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderSymmetricThreefish_Mappings_PREFIX, @"$ECB_1024")];
  [provider addAlgorithmWithNSString:@"KeyGenerator.Threefish-256" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderSymmetricThreefish_Mappings_PREFIX, @"$KeyGen_256")];
  [provider addAlgorithmWithNSString:@"KeyGenerator.Threefish-512" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderSymmetricThreefish_Mappings_PREFIX, @"$KeyGen_512")];
  [provider addAlgorithmWithNSString:@"KeyGenerator.Threefish-1024" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderSymmetricThreefish_Mappings_PREFIX, @"$KeyGen_1024")];
  [provider addAlgorithmWithNSString:@"AlgorithmParameters.Threefish-256" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderSymmetricThreefish_Mappings_PREFIX, @"$AlgParams_256")];
  [provider addAlgorithmWithNSString:@"AlgorithmParameters.Threefish-512" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderSymmetricThreefish_Mappings_PREFIX, @"$AlgParams_512")];
  [provider addAlgorithmWithNSString:@"AlgorithmParameters.Threefish-1024" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderSymmetricThreefish_Mappings_PREFIX, @"$AlgParams_1024")];
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
  static const void *ptrTable[] = { "configure", "LLibOrgBouncycastleJcajceProviderConfigConfigurableProvider;", &LibOrgBouncycastleJcajceProviderSymmetricThreefish_Mappings_PREFIX, "LLibOrgBouncycastleJcajceProviderSymmetricThreefish;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricThreefish_Mappings = { "Mappings", "lib.org.bouncycastle.jcajce.provider.symmetric", ptrTable, methods, fields, 7, 0x9, 2, 1, 3, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricThreefish_Mappings;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleJcajceProviderSymmetricThreefish_Mappings class]) {
    LibOrgBouncycastleJcajceProviderSymmetricThreefish_Mappings_PREFIX = [LibOrgBouncycastleJcajceProviderSymmetricThreefish_class_() getName];
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleJcajceProviderSymmetricThreefish_Mappings)
  }
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricThreefish_Mappings_init(LibOrgBouncycastleJcajceProviderSymmetricThreefish_Mappings *self) {
  LibOrgBouncycastleJcajceProviderUtilAlgorithmProvider_init(self);
}

LibOrgBouncycastleJcajceProviderSymmetricThreefish_Mappings *new_LibOrgBouncycastleJcajceProviderSymmetricThreefish_Mappings_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricThreefish_Mappings, init)
}

LibOrgBouncycastleJcajceProviderSymmetricThreefish_Mappings *create_LibOrgBouncycastleJcajceProviderSymmetricThreefish_Mappings_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricThreefish_Mappings, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricThreefish_Mappings)