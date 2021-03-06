//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/digests/GOST3411_2012_256Digest.java
//

#include "GOST3411_2012Digest.h"
#include "GOST3411_2012_256Digest.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "Memoable.h"
#include "java/lang/System.h"

inline IOSByteArray *LibOrgBouncycastleCryptoDigestsGOST3411_2012_256Digest_get_IV(void);
static IOSByteArray *LibOrgBouncycastleCryptoDigestsGOST3411_2012_256Digest_IV;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoDigestsGOST3411_2012_256Digest, IV, IOSByteArray *)

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleCryptoDigestsGOST3411_2012_256Digest)

@implementation LibOrgBouncycastleCryptoDigestsGOST3411_2012_256Digest

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoDigestsGOST3411_2012_256Digest_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (instancetype)initWithLibOrgBouncycastleCryptoDigestsGOST3411_2012_256Digest:(LibOrgBouncycastleCryptoDigestsGOST3411_2012_256Digest *)other {
  LibOrgBouncycastleCryptoDigestsGOST3411_2012_256Digest_initWithLibOrgBouncycastleCryptoDigestsGOST3411_2012_256Digest_(self, other);
  return self;
}

- (NSString *)getAlgorithmName {
  return @"GOST3411-2012-256";
}

- (jint)getDigestSize {
  return 32;
}

- (jint)doFinalWithByteArray:(IOSByteArray *)outArg
                     withInt:(jint)outOff {
  IOSByteArray *result = [IOSByteArray newArrayWithLength:64];
  [super doFinalWithByteArray:result withInt:0];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(result, 32, outArg, outOff, 32);
  return 32;
}

- (id<LibOrgBouncycastleUtilMemoable>)copy__ {
  return new_LibOrgBouncycastleCryptoDigestsGOST3411_2012_256Digest_initWithLibOrgBouncycastleCryptoDigestsGOST3411_2012_256Digest_(self);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 1, 2, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleUtilMemoable;", 0x1, 3, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(initWithLibOrgBouncycastleCryptoDigestsGOST3411_2012_256Digest:);
  methods[2].selector = @selector(getAlgorithmName);
  methods[3].selector = @selector(getDigestSize);
  methods[4].selector = @selector(doFinalWithByteArray:withInt:);
  methods[5].selector = @selector(copy__);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "IV", "[B", .constantValue.asLong = 0, 0x1a, -1, 4, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleCryptoDigestsGOST3411_2012_256Digest;", "doFinal", "[BI", "copy", &LibOrgBouncycastleCryptoDigestsGOST3411_2012_256Digest_IV };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoDigestsGOST3411_2012_256Digest = { "GOST3411_2012_256Digest", "lib.org.bouncycastle.crypto.digests", ptrTable, methods, fields, 7, 0x11, 6, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoDigestsGOST3411_2012_256Digest;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleCryptoDigestsGOST3411_2012_256Digest class]) {
    LibOrgBouncycastleCryptoDigestsGOST3411_2012_256Digest_IV = [IOSByteArray newArrayWithBytes:(jbyte[]){ (jint) 0x01, (jint) 0x01, (jint) 0x01, (jint) 0x01, (jint) 0x01, (jint) 0x01, (jint) 0x01, (jint) 0x01, (jint) 0x01, (jint) 0x01, (jint) 0x01, (jint) 0x01, (jint) 0x01, (jint) 0x01, (jint) 0x01, (jint) 0x01, (jint) 0x01, (jint) 0x01, (jint) 0x01, (jint) 0x01, (jint) 0x01, (jint) 0x01, (jint) 0x01, (jint) 0x01, (jint) 0x01, (jint) 0x01, (jint) 0x01, (jint) 0x01, (jint) 0x01, (jint) 0x01, (jint) 0x01, (jint) 0x01, (jint) 0x01, (jint) 0x01, (jint) 0x01, (jint) 0x01, (jint) 0x01, (jint) 0x01, (jint) 0x01, (jint) 0x01, (jint) 0x01, (jint) 0x01, (jint) 0x01, (jint) 0x01, (jint) 0x01, (jint) 0x01, (jint) 0x01, (jint) 0x01, (jint) 0x01, (jint) 0x01, (jint) 0x01, (jint) 0x01, (jint) 0x01, (jint) 0x01, (jint) 0x01, (jint) 0x01, (jint) 0x01, (jint) 0x01, (jint) 0x01, (jint) 0x01, (jint) 0x01, (jint) 0x01, (jint) 0x01, (jint) 0x01 } count:64];
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleCryptoDigestsGOST3411_2012_256Digest)
  }
}

@end

void LibOrgBouncycastleCryptoDigestsGOST3411_2012_256Digest_init(LibOrgBouncycastleCryptoDigestsGOST3411_2012_256Digest *self) {
  LibOrgBouncycastleCryptoDigestsGOST3411_2012Digest_initWithByteArray_(self, LibOrgBouncycastleCryptoDigestsGOST3411_2012_256Digest_IV);
}

LibOrgBouncycastleCryptoDigestsGOST3411_2012_256Digest *new_LibOrgBouncycastleCryptoDigestsGOST3411_2012_256Digest_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoDigestsGOST3411_2012_256Digest, init)
}

LibOrgBouncycastleCryptoDigestsGOST3411_2012_256Digest *create_LibOrgBouncycastleCryptoDigestsGOST3411_2012_256Digest_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoDigestsGOST3411_2012_256Digest, init)
}

void LibOrgBouncycastleCryptoDigestsGOST3411_2012_256Digest_initWithLibOrgBouncycastleCryptoDigestsGOST3411_2012_256Digest_(LibOrgBouncycastleCryptoDigestsGOST3411_2012_256Digest *self, LibOrgBouncycastleCryptoDigestsGOST3411_2012_256Digest *other) {
  LibOrgBouncycastleCryptoDigestsGOST3411_2012Digest_initWithByteArray_(self, LibOrgBouncycastleCryptoDigestsGOST3411_2012_256Digest_IV);
  [self resetWithLibOrgBouncycastleUtilMemoable:other];
}

LibOrgBouncycastleCryptoDigestsGOST3411_2012_256Digest *new_LibOrgBouncycastleCryptoDigestsGOST3411_2012_256Digest_initWithLibOrgBouncycastleCryptoDigestsGOST3411_2012_256Digest_(LibOrgBouncycastleCryptoDigestsGOST3411_2012_256Digest *other) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoDigestsGOST3411_2012_256Digest, initWithLibOrgBouncycastleCryptoDigestsGOST3411_2012_256Digest_, other)
}

LibOrgBouncycastleCryptoDigestsGOST3411_2012_256Digest *create_LibOrgBouncycastleCryptoDigestsGOST3411_2012_256Digest_initWithLibOrgBouncycastleCryptoDigestsGOST3411_2012_256Digest_(LibOrgBouncycastleCryptoDigestsGOST3411_2012_256Digest *other) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoDigestsGOST3411_2012_256Digest, initWithLibOrgBouncycastleCryptoDigestsGOST3411_2012_256Digest_, other)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoDigestsGOST3411_2012_256Digest)
