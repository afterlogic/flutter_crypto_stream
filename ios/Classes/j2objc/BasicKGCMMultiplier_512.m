//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/modes/kgcm/BasicKGCMMultiplier_512.java
//

#include "BasicKGCMMultiplier_512.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "KGCMUtil_512.h"

@interface LibOrgBouncycastleCryptoModesKgcmBasicKGCMMultiplier_512 () {
 @public
  IOSLongArray *H_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoModesKgcmBasicKGCMMultiplier_512, H_, IOSLongArray *)

@implementation LibOrgBouncycastleCryptoModesKgcmBasicKGCMMultiplier_512

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoModesKgcmBasicKGCMMultiplier_512_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)init__WithLongArray:(IOSLongArray *)H {
  LibOrgBouncycastleCryptoModesKgcmKGCMUtil_512_copy__WithLongArray_withLongArray_(H, self->H_);
}

- (void)multiplyHWithLongArray:(IOSLongArray *)z {
  LibOrgBouncycastleCryptoModesKgcmKGCMUtil_512_multiplyWithLongArray_withLongArray_withLongArray_(z, H_, z);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 2, 1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(init__WithLongArray:);
  methods[2].selector = @selector(multiplyHWithLongArray:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "H_", "[J", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "init", "[J", "multiplyH" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoModesKgcmBasicKGCMMultiplier_512 = { "BasicKGCMMultiplier_512", "lib.org.bouncycastle.crypto.modes.kgcm", ptrTable, methods, fields, 7, 0x1, 3, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoModesKgcmBasicKGCMMultiplier_512;
}

@end

void LibOrgBouncycastleCryptoModesKgcmBasicKGCMMultiplier_512_init(LibOrgBouncycastleCryptoModesKgcmBasicKGCMMultiplier_512 *self) {
  NSObject_init(self);
  self->H_ = [IOSLongArray newArrayWithLength:LibOrgBouncycastleCryptoModesKgcmKGCMUtil_512_SIZE];
}

LibOrgBouncycastleCryptoModesKgcmBasicKGCMMultiplier_512 *new_LibOrgBouncycastleCryptoModesKgcmBasicKGCMMultiplier_512_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoModesKgcmBasicKGCMMultiplier_512, init)
}

LibOrgBouncycastleCryptoModesKgcmBasicKGCMMultiplier_512 *create_LibOrgBouncycastleCryptoModesKgcmBasicKGCMMultiplier_512_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoModesKgcmBasicKGCMMultiplier_512, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoModesKgcmBasicKGCMMultiplier_512)
