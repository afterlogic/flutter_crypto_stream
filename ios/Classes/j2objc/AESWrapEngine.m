//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/engines/AESWrapEngine.java
//

#include "AESEngine.h"
#include "AESWrapEngine.h"
#include "J2ObjC_source.h"
#include "RFC3394WrapEngine.h"

@implementation LibOrgBouncycastleCryptoEnginesAESWrapEngine

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoEnginesAESWrapEngine_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (instancetype)initWithBoolean:(jboolean)useReverseDirection {
  LibOrgBouncycastleCryptoEnginesAESWrapEngine_initWithBoolean_(self, useReverseDirection);
  return self;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(initWithBoolean:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "Z" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoEnginesAESWrapEngine = { "AESWrapEngine", "lib.org.bouncycastle.crypto.engines", ptrTable, methods, NULL, 7, 0x1, 2, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoEnginesAESWrapEngine;
}

@end

void LibOrgBouncycastleCryptoEnginesAESWrapEngine_init(LibOrgBouncycastleCryptoEnginesAESWrapEngine *self) {
  LibOrgBouncycastleCryptoEnginesRFC3394WrapEngine_initWithLibOrgBouncycastleCryptoBlockCipher_(self, new_LibOrgBouncycastleCryptoEnginesAESEngine_init());
}

LibOrgBouncycastleCryptoEnginesAESWrapEngine *new_LibOrgBouncycastleCryptoEnginesAESWrapEngine_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoEnginesAESWrapEngine, init)
}

LibOrgBouncycastleCryptoEnginesAESWrapEngine *create_LibOrgBouncycastleCryptoEnginesAESWrapEngine_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoEnginesAESWrapEngine, init)
}

void LibOrgBouncycastleCryptoEnginesAESWrapEngine_initWithBoolean_(LibOrgBouncycastleCryptoEnginesAESWrapEngine *self, jboolean useReverseDirection) {
  LibOrgBouncycastleCryptoEnginesRFC3394WrapEngine_initWithLibOrgBouncycastleCryptoBlockCipher_withBoolean_(self, new_LibOrgBouncycastleCryptoEnginesAESEngine_init(), useReverseDirection);
}

LibOrgBouncycastleCryptoEnginesAESWrapEngine *new_LibOrgBouncycastleCryptoEnginesAESWrapEngine_initWithBoolean_(jboolean useReverseDirection) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoEnginesAESWrapEngine, initWithBoolean_, useReverseDirection)
}

LibOrgBouncycastleCryptoEnginesAESWrapEngine *create_LibOrgBouncycastleCryptoEnginesAESWrapEngine_initWithBoolean_(jboolean useReverseDirection) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoEnginesAESWrapEngine, initWithBoolean_, useReverseDirection)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoEnginesAESWrapEngine)
