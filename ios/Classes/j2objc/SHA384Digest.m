//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/digests/SHA384Digest.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "LongDigest.h"
#include "Memoable.h"
#include "Pack.h"
#include "SHA384Digest.h"

inline jint LibOrgBouncycastleCryptoDigestsSHA384Digest_get_DIGEST_LENGTH(void);
#define LibOrgBouncycastleCryptoDigestsSHA384Digest_DIGEST_LENGTH 48
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoDigestsSHA384Digest, DIGEST_LENGTH, jint)

@implementation LibOrgBouncycastleCryptoDigestsSHA384Digest

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoDigestsSHA384Digest_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (instancetype)initWithLibOrgBouncycastleCryptoDigestsSHA384Digest:(LibOrgBouncycastleCryptoDigestsSHA384Digest *)t {
  LibOrgBouncycastleCryptoDigestsSHA384Digest_initWithLibOrgBouncycastleCryptoDigestsSHA384Digest_(self, t);
  return self;
}

- (instancetype)initWithByteArray:(IOSByteArray *)encodedState {
  LibOrgBouncycastleCryptoDigestsSHA384Digest_initWithByteArray_(self, encodedState);
  return self;
}

- (NSString *)getAlgorithmName {
  return @"SHA-384";
}

- (jint)getDigestSize {
  return LibOrgBouncycastleCryptoDigestsSHA384Digest_DIGEST_LENGTH;
}

- (jint)doFinalWithByteArray:(IOSByteArray *)outArg
                     withInt:(jint)outOff {
  [self finish];
  LibOrgBouncycastleUtilPack_longToBigEndianWithLong_withByteArray_withInt_(H1_, outArg, outOff);
  LibOrgBouncycastleUtilPack_longToBigEndianWithLong_withByteArray_withInt_(H2_, outArg, outOff + 8);
  LibOrgBouncycastleUtilPack_longToBigEndianWithLong_withByteArray_withInt_(H3_, outArg, outOff + 16);
  LibOrgBouncycastleUtilPack_longToBigEndianWithLong_withByteArray_withInt_(H4_, outArg, outOff + 24);
  LibOrgBouncycastleUtilPack_longToBigEndianWithLong_withByteArray_withInt_(H5_, outArg, outOff + 32);
  LibOrgBouncycastleUtilPack_longToBigEndianWithLong_withByteArray_withInt_(H6_, outArg, outOff + 40);
  [self reset];
  return LibOrgBouncycastleCryptoDigestsSHA384Digest_DIGEST_LENGTH;
}

- (void)reset {
  [super reset];
  H1_ = (jlong) 0xcbbb9d5dc1059ed8l;
  H2_ = (jlong) 0x629a292a367cd507l;
  H3_ = (jlong) 0x9159015a3070dd17l;
  H4_ = (jlong) 0x152fecd8f70e5939l;
  H5_ = (jlong) 0x67332667ffc00b31l;
  H6_ = (jlong) 0x8eb44a8768581511l;
  H7_ = (jlong) 0xdb0c2e0d64f98fa7l;
  H8_ = (jlong) 0x47b5481dbefa4fa4l;
}

- (id<LibOrgBouncycastleUtilMemoable>)copy__ {
  return new_LibOrgBouncycastleCryptoDigestsSHA384Digest_initWithLibOrgBouncycastleCryptoDigestsSHA384Digest_(self);
}

- (void)resetWithLibOrgBouncycastleUtilMemoable:(id<LibOrgBouncycastleUtilMemoable>)other {
  LibOrgBouncycastleCryptoDigestsSHA384Digest *d = (LibOrgBouncycastleCryptoDigestsSHA384Digest *) cast_chk(other, [LibOrgBouncycastleCryptoDigestsSHA384Digest class]);
  [super copyInWithLibOrgBouncycastleCryptoDigestsLongDigest:d];
}

- (IOSByteArray *)getEncodedState {
  IOSByteArray *encoded = [IOSByteArray newArrayWithLength:[self getEncodedStateSize]];
  [super populateStateWithByteArray:encoded];
  return encoded;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 2, 3, -1, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleUtilMemoable;", 0x1, 4, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 5, 6, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(initWithLibOrgBouncycastleCryptoDigestsSHA384Digest:);
  methods[2].selector = @selector(initWithByteArray:);
  methods[3].selector = @selector(getAlgorithmName);
  methods[4].selector = @selector(getDigestSize);
  methods[5].selector = @selector(doFinalWithByteArray:withInt:);
  methods[6].selector = @selector(reset);
  methods[7].selector = @selector(copy__);
  methods[8].selector = @selector(resetWithLibOrgBouncycastleUtilMemoable:);
  methods[9].selector = @selector(getEncodedState);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "DIGEST_LENGTH", "I", .constantValue.asInt = LibOrgBouncycastleCryptoDigestsSHA384Digest_DIGEST_LENGTH, 0x1a, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleCryptoDigestsSHA384Digest;", "[B", "doFinal", "[BI", "copy", "reset", "LLibOrgBouncycastleUtilMemoable;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoDigestsSHA384Digest = { "SHA384Digest", "lib.org.bouncycastle.crypto.digests", ptrTable, methods, fields, 7, 0x1, 10, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoDigestsSHA384Digest;
}

@end

void LibOrgBouncycastleCryptoDigestsSHA384Digest_init(LibOrgBouncycastleCryptoDigestsSHA384Digest *self) {
  LibOrgBouncycastleCryptoDigestsLongDigest_init(self);
}

LibOrgBouncycastleCryptoDigestsSHA384Digest *new_LibOrgBouncycastleCryptoDigestsSHA384Digest_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoDigestsSHA384Digest, init)
}

LibOrgBouncycastleCryptoDigestsSHA384Digest *create_LibOrgBouncycastleCryptoDigestsSHA384Digest_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoDigestsSHA384Digest, init)
}

void LibOrgBouncycastleCryptoDigestsSHA384Digest_initWithLibOrgBouncycastleCryptoDigestsSHA384Digest_(LibOrgBouncycastleCryptoDigestsSHA384Digest *self, LibOrgBouncycastleCryptoDigestsSHA384Digest *t) {
  LibOrgBouncycastleCryptoDigestsLongDigest_initWithLibOrgBouncycastleCryptoDigestsLongDigest_(self, t);
}

LibOrgBouncycastleCryptoDigestsSHA384Digest *new_LibOrgBouncycastleCryptoDigestsSHA384Digest_initWithLibOrgBouncycastleCryptoDigestsSHA384Digest_(LibOrgBouncycastleCryptoDigestsSHA384Digest *t) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoDigestsSHA384Digest, initWithLibOrgBouncycastleCryptoDigestsSHA384Digest_, t)
}

LibOrgBouncycastleCryptoDigestsSHA384Digest *create_LibOrgBouncycastleCryptoDigestsSHA384Digest_initWithLibOrgBouncycastleCryptoDigestsSHA384Digest_(LibOrgBouncycastleCryptoDigestsSHA384Digest *t) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoDigestsSHA384Digest, initWithLibOrgBouncycastleCryptoDigestsSHA384Digest_, t)
}

void LibOrgBouncycastleCryptoDigestsSHA384Digest_initWithByteArray_(LibOrgBouncycastleCryptoDigestsSHA384Digest *self, IOSByteArray *encodedState) {
  LibOrgBouncycastleCryptoDigestsLongDigest_init(self);
  [self restoreStateWithByteArray:encodedState];
}

LibOrgBouncycastleCryptoDigestsSHA384Digest *new_LibOrgBouncycastleCryptoDigestsSHA384Digest_initWithByteArray_(IOSByteArray *encodedState) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoDigestsSHA384Digest, initWithByteArray_, encodedState)
}

LibOrgBouncycastleCryptoDigestsSHA384Digest *create_LibOrgBouncycastleCryptoDigestsSHA384Digest_initWithByteArray_(IOSByteArray *encodedState) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoDigestsSHA384Digest, initWithByteArray_, encodedState)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoDigestsSHA384Digest)
