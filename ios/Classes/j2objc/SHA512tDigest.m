//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/digests/SHA512tDigest.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "LongDigest.h"
#include "Memoable.h"
#include "MemoableResetException.h"
#include "Pack.h"
#include "SHA512tDigest.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/Integer.h"
#include "java/lang/Math.h"

@interface LibOrgBouncycastleCryptoDigestsSHA512tDigest () {
 @public
  jint digestLength_;
  jlong H1t_;
  jlong H2t_;
  jlong H3t_;
  jlong H4t_;
  jlong H5t_;
  jlong H6t_;
  jlong H7t_;
  jlong H8t_;
}

+ (jint)readDigestLengthWithByteArray:(IOSByteArray *)encodedState;

- (void)tIvGenerateWithInt:(jint)bitLength;

+ (void)longToBigEndianWithLong:(jlong)n
                  withByteArray:(IOSByteArray *)bs
                        withInt:(jint)off
                        withInt:(jint)max;

+ (void)intToBigEndianWithInt:(jint)n
                withByteArray:(IOSByteArray *)bs
                      withInt:(jint)off
                      withInt:(jint)max;

@end

__attribute__((unused)) static jint LibOrgBouncycastleCryptoDigestsSHA512tDigest_readDigestLengthWithByteArray_(IOSByteArray *encodedState);

__attribute__((unused)) static void LibOrgBouncycastleCryptoDigestsSHA512tDigest_tIvGenerateWithInt_(LibOrgBouncycastleCryptoDigestsSHA512tDigest *self, jint bitLength);

__attribute__((unused)) static void LibOrgBouncycastleCryptoDigestsSHA512tDigest_longToBigEndianWithLong_withByteArray_withInt_withInt_(jlong n, IOSByteArray *bs, jint off, jint max);

__attribute__((unused)) static void LibOrgBouncycastleCryptoDigestsSHA512tDigest_intToBigEndianWithInt_withByteArray_withInt_withInt_(jint n, IOSByteArray *bs, jint off, jint max);

@implementation LibOrgBouncycastleCryptoDigestsSHA512tDigest

- (instancetype)initWithInt:(jint)bitLength {
  LibOrgBouncycastleCryptoDigestsSHA512tDigest_initWithInt_(self, bitLength);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleCryptoDigestsSHA512tDigest:(LibOrgBouncycastleCryptoDigestsSHA512tDigest *)t {
  LibOrgBouncycastleCryptoDigestsSHA512tDigest_initWithLibOrgBouncycastleCryptoDigestsSHA512tDigest_(self, t);
  return self;
}

- (instancetype)initWithByteArray:(IOSByteArray *)encodedState {
  LibOrgBouncycastleCryptoDigestsSHA512tDigest_initWithByteArray_(self, encodedState);
  return self;
}

+ (jint)readDigestLengthWithByteArray:(IOSByteArray *)encodedState {
  return LibOrgBouncycastleCryptoDigestsSHA512tDigest_readDigestLengthWithByteArray_(encodedState);
}

- (NSString *)getAlgorithmName {
  return JreStrcat("$$", @"SHA-512/", JavaLangInteger_toStringWithInt_(digestLength_ * 8));
}

- (jint)getDigestSize {
  return digestLength_;
}

- (jint)doFinalWithByteArray:(IOSByteArray *)outArg
                     withInt:(jint)outOff {
  [self finish];
  LibOrgBouncycastleCryptoDigestsSHA512tDigest_longToBigEndianWithLong_withByteArray_withInt_withInt_(H1_, outArg, outOff, digestLength_);
  LibOrgBouncycastleCryptoDigestsSHA512tDigest_longToBigEndianWithLong_withByteArray_withInt_withInt_(H2_, outArg, outOff + 8, digestLength_ - 8);
  LibOrgBouncycastleCryptoDigestsSHA512tDigest_longToBigEndianWithLong_withByteArray_withInt_withInt_(H3_, outArg, outOff + 16, digestLength_ - 16);
  LibOrgBouncycastleCryptoDigestsSHA512tDigest_longToBigEndianWithLong_withByteArray_withInt_withInt_(H4_, outArg, outOff + 24, digestLength_ - 24);
  LibOrgBouncycastleCryptoDigestsSHA512tDigest_longToBigEndianWithLong_withByteArray_withInt_withInt_(H5_, outArg, outOff + 32, digestLength_ - 32);
  LibOrgBouncycastleCryptoDigestsSHA512tDigest_longToBigEndianWithLong_withByteArray_withInt_withInt_(H6_, outArg, outOff + 40, digestLength_ - 40);
  LibOrgBouncycastleCryptoDigestsSHA512tDigest_longToBigEndianWithLong_withByteArray_withInt_withInt_(H7_, outArg, outOff + 48, digestLength_ - 48);
  LibOrgBouncycastleCryptoDigestsSHA512tDigest_longToBigEndianWithLong_withByteArray_withInt_withInt_(H8_, outArg, outOff + 56, digestLength_ - 56);
  [self reset];
  return digestLength_;
}

- (void)reset {
  [super reset];
  H1_ = H1t_;
  H2_ = H2t_;
  H3_ = H3t_;
  H4_ = H4t_;
  H5_ = H5t_;
  H6_ = H6t_;
  H7_ = H7t_;
  H8_ = H8t_;
}

- (void)tIvGenerateWithInt:(jint)bitLength {
  LibOrgBouncycastleCryptoDigestsSHA512tDigest_tIvGenerateWithInt_(self, bitLength);
}

+ (void)longToBigEndianWithLong:(jlong)n
                  withByteArray:(IOSByteArray *)bs
                        withInt:(jint)off
                        withInt:(jint)max {
  LibOrgBouncycastleCryptoDigestsSHA512tDigest_longToBigEndianWithLong_withByteArray_withInt_withInt_(n, bs, off, max);
}

+ (void)intToBigEndianWithInt:(jint)n
                withByteArray:(IOSByteArray *)bs
                      withInt:(jint)off
                      withInt:(jint)max {
  LibOrgBouncycastleCryptoDigestsSHA512tDigest_intToBigEndianWithInt_withByteArray_withInt_withInt_(n, bs, off, max);
}

- (id<LibOrgBouncycastleUtilMemoable>)copy__ {
  return new_LibOrgBouncycastleCryptoDigestsSHA512tDigest_initWithLibOrgBouncycastleCryptoDigestsSHA512tDigest_(self);
}

- (void)resetWithLibOrgBouncycastleUtilMemoable:(id<LibOrgBouncycastleUtilMemoable>)other {
  LibOrgBouncycastleCryptoDigestsSHA512tDigest *t = (LibOrgBouncycastleCryptoDigestsSHA512tDigest *) cast_chk(other, [LibOrgBouncycastleCryptoDigestsSHA512tDigest class]);
  if (self->digestLength_ != ((LibOrgBouncycastleCryptoDigestsSHA512tDigest *) nil_chk(t))->digestLength_) {
    @throw new_LibOrgBouncycastleUtilMemoableResetException_initWithNSString_(@"digestLength inappropriate in other");
  }
  [super copyInWithLibOrgBouncycastleCryptoDigestsLongDigest:t];
  self->H1t_ = t->H1t_;
  self->H2t_ = t->H2t_;
  self->H3t_ = t->H3t_;
  self->H4t_ = t->H4t_;
  self->H5t_ = t->H5t_;
  self->H6t_ = t->H6t_;
  self->H7t_ = t->H7t_;
  self->H8t_ = t->H8t_;
}

- (IOSByteArray *)getEncodedState {
  jint baseSize = [self getEncodedStateSize];
  IOSByteArray *encoded = [IOSByteArray newArrayWithLength:baseSize + 4];
  [self populateStateWithByteArray:encoded];
  LibOrgBouncycastleUtilPack_intToBigEndianWithInt_withByteArray_withInt_(digestLength_ * 8, encoded, baseSize);
  return encoded;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, -1, -1, -1 },
    { NULL, "I", 0xa, 3, 2, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 4, 5, -1, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 6, 0, -1, -1, -1, -1 },
    { NULL, "V", 0xa, 7, 8, -1, -1, -1, -1 },
    { NULL, "V", 0xa, 9, 10, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleUtilMemoable;", 0x1, 11, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 12, 13, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithInt:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleCryptoDigestsSHA512tDigest:);
  methods[2].selector = @selector(initWithByteArray:);
  methods[3].selector = @selector(readDigestLengthWithByteArray:);
  methods[4].selector = @selector(getAlgorithmName);
  methods[5].selector = @selector(getDigestSize);
  methods[6].selector = @selector(doFinalWithByteArray:withInt:);
  methods[7].selector = @selector(reset);
  methods[8].selector = @selector(tIvGenerateWithInt:);
  methods[9].selector = @selector(longToBigEndianWithLong:withByteArray:withInt:withInt:);
  methods[10].selector = @selector(intToBigEndianWithInt:withByteArray:withInt:withInt:);
  methods[11].selector = @selector(copy__);
  methods[12].selector = @selector(resetWithLibOrgBouncycastleUtilMemoable:);
  methods[13].selector = @selector(getEncodedState);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "digestLength_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "H1t_", "J", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "H2t_", "J", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "H3t_", "J", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "H4t_", "J", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "H5t_", "J", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "H6t_", "J", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "H7t_", "J", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "H8t_", "J", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "I", "LLibOrgBouncycastleCryptoDigestsSHA512tDigest;", "[B", "readDigestLength", "doFinal", "[BI", "tIvGenerate", "longToBigEndian", "J[BII", "intToBigEndian", "I[BII", "copy", "reset", "LLibOrgBouncycastleUtilMemoable;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoDigestsSHA512tDigest = { "SHA512tDigest", "lib.org.bouncycastle.crypto.digests", ptrTable, methods, fields, 7, 0x1, 14, 9, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoDigestsSHA512tDigest;
}

@end

void LibOrgBouncycastleCryptoDigestsSHA512tDigest_initWithInt_(LibOrgBouncycastleCryptoDigestsSHA512tDigest *self, jint bitLength) {
  LibOrgBouncycastleCryptoDigestsLongDigest_init(self);
  if (bitLength >= 512) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"bitLength cannot be >= 512");
  }
  if (bitLength % 8 != 0) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"bitLength needs to be a multiple of 8");
  }
  if (bitLength == 384) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"bitLength cannot be 384 use SHA384 instead");
  }
  self->digestLength_ = bitLength / 8;
  LibOrgBouncycastleCryptoDigestsSHA512tDigest_tIvGenerateWithInt_(self, self->digestLength_ * 8);
  [self reset];
}

LibOrgBouncycastleCryptoDigestsSHA512tDigest *new_LibOrgBouncycastleCryptoDigestsSHA512tDigest_initWithInt_(jint bitLength) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoDigestsSHA512tDigest, initWithInt_, bitLength)
}

LibOrgBouncycastleCryptoDigestsSHA512tDigest *create_LibOrgBouncycastleCryptoDigestsSHA512tDigest_initWithInt_(jint bitLength) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoDigestsSHA512tDigest, initWithInt_, bitLength)
}

void LibOrgBouncycastleCryptoDigestsSHA512tDigest_initWithLibOrgBouncycastleCryptoDigestsSHA512tDigest_(LibOrgBouncycastleCryptoDigestsSHA512tDigest *self, LibOrgBouncycastleCryptoDigestsSHA512tDigest *t) {
  LibOrgBouncycastleCryptoDigestsLongDigest_initWithLibOrgBouncycastleCryptoDigestsLongDigest_(self, t);
  self->digestLength_ = ((LibOrgBouncycastleCryptoDigestsSHA512tDigest *) nil_chk(t))->digestLength_;
  [self resetWithLibOrgBouncycastleUtilMemoable:t];
}

LibOrgBouncycastleCryptoDigestsSHA512tDigest *new_LibOrgBouncycastleCryptoDigestsSHA512tDigest_initWithLibOrgBouncycastleCryptoDigestsSHA512tDigest_(LibOrgBouncycastleCryptoDigestsSHA512tDigest *t) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoDigestsSHA512tDigest, initWithLibOrgBouncycastleCryptoDigestsSHA512tDigest_, t)
}

LibOrgBouncycastleCryptoDigestsSHA512tDigest *create_LibOrgBouncycastleCryptoDigestsSHA512tDigest_initWithLibOrgBouncycastleCryptoDigestsSHA512tDigest_(LibOrgBouncycastleCryptoDigestsSHA512tDigest *t) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoDigestsSHA512tDigest, initWithLibOrgBouncycastleCryptoDigestsSHA512tDigest_, t)
}

void LibOrgBouncycastleCryptoDigestsSHA512tDigest_initWithByteArray_(LibOrgBouncycastleCryptoDigestsSHA512tDigest *self, IOSByteArray *encodedState) {
  LibOrgBouncycastleCryptoDigestsSHA512tDigest_initWithInt_(self, LibOrgBouncycastleCryptoDigestsSHA512tDigest_readDigestLengthWithByteArray_(encodedState));
  [self restoreStateWithByteArray:encodedState];
}

LibOrgBouncycastleCryptoDigestsSHA512tDigest *new_LibOrgBouncycastleCryptoDigestsSHA512tDigest_initWithByteArray_(IOSByteArray *encodedState) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoDigestsSHA512tDigest, initWithByteArray_, encodedState)
}

LibOrgBouncycastleCryptoDigestsSHA512tDigest *create_LibOrgBouncycastleCryptoDigestsSHA512tDigest_initWithByteArray_(IOSByteArray *encodedState) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoDigestsSHA512tDigest, initWithByteArray_, encodedState)
}

jint LibOrgBouncycastleCryptoDigestsSHA512tDigest_readDigestLengthWithByteArray_(IOSByteArray *encodedState) {
  LibOrgBouncycastleCryptoDigestsSHA512tDigest_initialize();
  return LibOrgBouncycastleUtilPack_bigEndianToIntWithByteArray_withInt_(encodedState, ((IOSByteArray *) nil_chk(encodedState))->size_ - 4);
}

void LibOrgBouncycastleCryptoDigestsSHA512tDigest_tIvGenerateWithInt_(LibOrgBouncycastleCryptoDigestsSHA512tDigest *self, jint bitLength) {
  self->H1_ = (jlong) 0x6a09e667f3bcc908LL ^ (jlong) 0xa5a5a5a5a5a5a5a5LL;
  self->H2_ = (jlong) 0xbb67ae8584caa73bLL ^ (jlong) 0xa5a5a5a5a5a5a5a5LL;
  self->H3_ = (jlong) 0x3c6ef372fe94f82bLL ^ (jlong) 0xa5a5a5a5a5a5a5a5LL;
  self->H4_ = (jlong) 0xa54ff53a5f1d36f1LL ^ (jlong) 0xa5a5a5a5a5a5a5a5LL;
  self->H5_ = (jlong) 0x510e527fade682d1LL ^ (jlong) 0xa5a5a5a5a5a5a5a5LL;
  self->H6_ = (jlong) 0x9b05688c2b3e6c1fLL ^ (jlong) 0xa5a5a5a5a5a5a5a5LL;
  self->H7_ = (jlong) 0x1f83d9abfb41bd6bLL ^ (jlong) 0xa5a5a5a5a5a5a5a5LL;
  self->H8_ = (jlong) 0x5be0cd19137e2179LL ^ (jlong) 0xa5a5a5a5a5a5a5a5LL;
  [self updateWithByte:(jbyte) (jint) 0x53];
  [self updateWithByte:(jbyte) (jint) 0x48];
  [self updateWithByte:(jbyte) (jint) 0x41];
  [self updateWithByte:(jbyte) (jint) 0x2D];
  [self updateWithByte:(jbyte) (jint) 0x35];
  [self updateWithByte:(jbyte) (jint) 0x31];
  [self updateWithByte:(jbyte) (jint) 0x32];
  [self updateWithByte:(jbyte) (jint) 0x2F];
  if (bitLength > 100) {
    [self updateWithByte:(jbyte) (bitLength / 100 + (jint) 0x30)];
    bitLength = bitLength % 100;
    [self updateWithByte:(jbyte) (bitLength / 10 + (jint) 0x30)];
    bitLength = bitLength % 10;
    [self updateWithByte:(jbyte) (bitLength + (jint) 0x30)];
  }
  else if (bitLength > 10) {
    [self updateWithByte:(jbyte) (bitLength / 10 + (jint) 0x30)];
    bitLength = bitLength % 10;
    [self updateWithByte:(jbyte) (bitLength + (jint) 0x30)];
  }
  else {
    [self updateWithByte:(jbyte) (bitLength + (jint) 0x30)];
  }
  [self finish];
  self->H1t_ = self->H1_;
  self->H2t_ = self->H2_;
  self->H3t_ = self->H3_;
  self->H4t_ = self->H4_;
  self->H5t_ = self->H5_;
  self->H6t_ = self->H6_;
  self->H7t_ = self->H7_;
  self->H8t_ = self->H8_;
}

void LibOrgBouncycastleCryptoDigestsSHA512tDigest_longToBigEndianWithLong_withByteArray_withInt_withInt_(jlong n, IOSByteArray *bs, jint off, jint max) {
  LibOrgBouncycastleCryptoDigestsSHA512tDigest_initialize();
  if (max > 0) {
    LibOrgBouncycastleCryptoDigestsSHA512tDigest_intToBigEndianWithInt_withByteArray_withInt_withInt_((jint) (JreURShift64(n, 32)), bs, off, max);
    if (max > 4) {
      LibOrgBouncycastleCryptoDigestsSHA512tDigest_intToBigEndianWithInt_withByteArray_withInt_withInt_((jint) (n & (jlong) 0xffffffffLL), bs, off + 4, max - 4);
    }
  }
}

void LibOrgBouncycastleCryptoDigestsSHA512tDigest_intToBigEndianWithInt_withByteArray_withInt_withInt_(jint n, IOSByteArray *bs, jint off, jint max) {
  LibOrgBouncycastleCryptoDigestsSHA512tDigest_initialize();
  jint num = JavaLangMath_minWithInt_withInt_(4, max);
  while (--num >= 0) {
    jint shift = 8 * (3 - num);
    *IOSByteArray_GetRef(nil_chk(bs), off + num) = (jbyte) (JreURShift32(n, shift));
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoDigestsSHA512tDigest)
