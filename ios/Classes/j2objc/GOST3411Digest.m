//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/digests/GOST3411Digest.java
//

#include "Arrays.h"
#include "BlockCipher.h"
#include "GOST28147Engine.h"
#include "GOST3411Digest.h"
#include "IOSObjectArray.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "KeyParameter.h"
#include "Memoable.h"
#include "Pack.h"
#include "ParametersWithSBox.h"
#include "java/lang/System.h"

@interface LibOrgBouncycastleCryptoDigestsGOST3411Digest () {
 @public
  IOSByteArray *H_;
  IOSByteArray *L_;
  IOSByteArray *M_;
  IOSByteArray *Sum_;
  IOSObjectArray *C_;
  IOSByteArray *xBuf_;
  jint xBufOff_;
  jlong byteCount_;
  id<LibOrgBouncycastleCryptoBlockCipher> cipher_;
  IOSByteArray *sBox_;
  IOSByteArray *K_;
}

- (IOSByteArray *)PWithByteArray:(IOSByteArray *)inArg;

- (IOSByteArray *)AWithByteArray:(IOSByteArray *)inArg;

- (void)EWithByteArray:(IOSByteArray *)key
         withByteArray:(IOSByteArray *)s
               withInt:(jint)sOff
         withByteArray:(IOSByteArray *)inArg
               withInt:(jint)inOff;

- (void)fwWithByteArray:(IOSByteArray *)inArg;

- (void)finish;

- (void)sumByteArrayWithByteArray:(IOSByteArray *)inArg;

- (void)cpyBytesToShortWithByteArray:(IOSByteArray *)S
                      withShortArray:(IOSShortArray *)wS;

- (void)cpyShortToBytesWithShortArray:(IOSShortArray *)wS
                        withByteArray:(IOSByteArray *)S;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoDigestsGOST3411Digest, H_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoDigestsGOST3411Digest, L_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoDigestsGOST3411Digest, M_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoDigestsGOST3411Digest, Sum_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoDigestsGOST3411Digest, C_, IOSObjectArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoDigestsGOST3411Digest, xBuf_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoDigestsGOST3411Digest, cipher_, id<LibOrgBouncycastleCryptoBlockCipher>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoDigestsGOST3411Digest, sBox_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoDigestsGOST3411Digest, K_, IOSByteArray *)

inline jint LibOrgBouncycastleCryptoDigestsGOST3411Digest_get_DIGEST_LENGTH(void);
#define LibOrgBouncycastleCryptoDigestsGOST3411Digest_DIGEST_LENGTH 32
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoDigestsGOST3411Digest, DIGEST_LENGTH, jint)

inline IOSByteArray *LibOrgBouncycastleCryptoDigestsGOST3411Digest_get_C2(void);
static IOSByteArray *LibOrgBouncycastleCryptoDigestsGOST3411Digest_C2;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoDigestsGOST3411Digest, C2, IOSByteArray *)

__attribute__((unused)) static IOSByteArray *LibOrgBouncycastleCryptoDigestsGOST3411Digest_PWithByteArray_(LibOrgBouncycastleCryptoDigestsGOST3411Digest *self, IOSByteArray *inArg);

__attribute__((unused)) static IOSByteArray *LibOrgBouncycastleCryptoDigestsGOST3411Digest_AWithByteArray_(LibOrgBouncycastleCryptoDigestsGOST3411Digest *self, IOSByteArray *inArg);

__attribute__((unused)) static void LibOrgBouncycastleCryptoDigestsGOST3411Digest_EWithByteArray_withByteArray_withInt_withByteArray_withInt_(LibOrgBouncycastleCryptoDigestsGOST3411Digest *self, IOSByteArray *key, IOSByteArray *s, jint sOff, IOSByteArray *inArg, jint inOff);

__attribute__((unused)) static void LibOrgBouncycastleCryptoDigestsGOST3411Digest_fwWithByteArray_(LibOrgBouncycastleCryptoDigestsGOST3411Digest *self, IOSByteArray *inArg);

__attribute__((unused)) static void LibOrgBouncycastleCryptoDigestsGOST3411Digest_finish(LibOrgBouncycastleCryptoDigestsGOST3411Digest *self);

__attribute__((unused)) static void LibOrgBouncycastleCryptoDigestsGOST3411Digest_sumByteArrayWithByteArray_(LibOrgBouncycastleCryptoDigestsGOST3411Digest *self, IOSByteArray *inArg);

__attribute__((unused)) static void LibOrgBouncycastleCryptoDigestsGOST3411Digest_cpyBytesToShortWithByteArray_withShortArray_(LibOrgBouncycastleCryptoDigestsGOST3411Digest *self, IOSByteArray *S, IOSShortArray *wS);

__attribute__((unused)) static void LibOrgBouncycastleCryptoDigestsGOST3411Digest_cpyShortToBytesWithShortArray_withByteArray_(LibOrgBouncycastleCryptoDigestsGOST3411Digest *self, IOSShortArray *wS, IOSByteArray *S);

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleCryptoDigestsGOST3411Digest)

@implementation LibOrgBouncycastleCryptoDigestsGOST3411Digest

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoDigestsGOST3411Digest_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (instancetype)initWithByteArray:(IOSByteArray *)sBoxParam {
  LibOrgBouncycastleCryptoDigestsGOST3411Digest_initWithByteArray_(self, sBoxParam);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleCryptoDigestsGOST3411Digest:(LibOrgBouncycastleCryptoDigestsGOST3411Digest *)t {
  LibOrgBouncycastleCryptoDigestsGOST3411Digest_initWithLibOrgBouncycastleCryptoDigestsGOST3411Digest_(self, t);
  return self;
}

- (NSString *)getAlgorithmName {
  return @"GOST3411";
}

- (jint)getDigestSize {
  return LibOrgBouncycastleCryptoDigestsGOST3411Digest_DIGEST_LENGTH;
}

- (void)updateWithByte:(jbyte)inArg {
  *IOSByteArray_GetRef(nil_chk(xBuf_), xBufOff_++) = inArg;
  if (xBufOff_ == xBuf_->size_) {
    LibOrgBouncycastleCryptoDigestsGOST3411Digest_sumByteArrayWithByteArray_(self, xBuf_);
    [self processBlockWithByteArray:xBuf_ withInt:0];
    xBufOff_ = 0;
  }
  byteCount_++;
}

- (void)updateWithByteArray:(IOSByteArray *)inArg
                    withInt:(jint)inOff
                    withInt:(jint)len {
  while ((xBufOff_ != 0) && (len > 0)) {
    [self updateWithByte:IOSByteArray_Get(nil_chk(inArg), inOff)];
    inOff++;
    len--;
  }
  while (len > ((IOSByteArray *) nil_chk(xBuf_))->size_) {
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(inArg, inOff, xBuf_, 0, xBuf_->size_);
    LibOrgBouncycastleCryptoDigestsGOST3411Digest_sumByteArrayWithByteArray_(self, xBuf_);
    [self processBlockWithByteArray:xBuf_ withInt:0];
    inOff += ((IOSByteArray *) nil_chk(xBuf_))->size_;
    len -= xBuf_->size_;
    byteCount_ += xBuf_->size_;
  }
  while (len > 0) {
    [self updateWithByte:IOSByteArray_Get(nil_chk(inArg), inOff)];
    inOff++;
    len--;
  }
}

- (IOSByteArray *)PWithByteArray:(IOSByteArray *)inArg {
  return LibOrgBouncycastleCryptoDigestsGOST3411Digest_PWithByteArray_(self, inArg);
}

- (IOSByteArray *)AWithByteArray:(IOSByteArray *)inArg {
  return LibOrgBouncycastleCryptoDigestsGOST3411Digest_AWithByteArray_(self, inArg);
}

- (void)EWithByteArray:(IOSByteArray *)key
         withByteArray:(IOSByteArray *)s
               withInt:(jint)sOff
         withByteArray:(IOSByteArray *)inArg
               withInt:(jint)inOff {
  LibOrgBouncycastleCryptoDigestsGOST3411Digest_EWithByteArray_withByteArray_withInt_withByteArray_withInt_(self, key, s, sOff, inArg, inOff);
}

- (void)fwWithByteArray:(IOSByteArray *)inArg {
  LibOrgBouncycastleCryptoDigestsGOST3411Digest_fwWithByteArray_(self, inArg);
}

- (void)processBlockWithByteArray:(IOSByteArray *)inArg
                          withInt:(jint)inOff {
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(inArg, inOff, M_, 0, 32);
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(H_, 0, U_, 0, 32);
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(M_, 0, V_, 0, 32);
  for (jint j = 0; j < 32; j++) {
    *IOSByteArray_GetRef(nil_chk(W_), j) = (jbyte) (IOSByteArray_Get(nil_chk(U_), j) ^ IOSByteArray_Get(nil_chk(V_), j));
  }
  LibOrgBouncycastleCryptoDigestsGOST3411Digest_EWithByteArray_withByteArray_withInt_withByteArray_withInt_(self, LibOrgBouncycastleCryptoDigestsGOST3411Digest_PWithByteArray_(self, W_), S_, 0, H_, 0);
  for (jint i = 1; i < 4; i++) {
    IOSByteArray *tmpA = LibOrgBouncycastleCryptoDigestsGOST3411Digest_AWithByteArray_(self, U_);
    for (jint j = 0; j < 32; j++) {
      *IOSByteArray_GetRef(nil_chk(U_), j) = (jbyte) (IOSByteArray_Get(nil_chk(tmpA), j) ^ IOSByteArray_Get(nil_chk(IOSObjectArray_Get(nil_chk(C_), i)), j));
    }
    V_ = LibOrgBouncycastleCryptoDigestsGOST3411Digest_AWithByteArray_(self, LibOrgBouncycastleCryptoDigestsGOST3411Digest_AWithByteArray_(self, V_));
    for (jint j = 0; j < 32; j++) {
      *IOSByteArray_GetRef(nil_chk(W_), j) = (jbyte) (IOSByteArray_Get(nil_chk(U_), j) ^ IOSByteArray_Get(nil_chk(V_), j));
    }
    LibOrgBouncycastleCryptoDigestsGOST3411Digest_EWithByteArray_withByteArray_withInt_withByteArray_withInt_(self, LibOrgBouncycastleCryptoDigestsGOST3411Digest_PWithByteArray_(self, W_), S_, i * 8, H_, i * 8);
  }
  for (jint n = 0; n < 12; n++) {
    LibOrgBouncycastleCryptoDigestsGOST3411Digest_fwWithByteArray_(self, S_);
  }
  for (jint n = 0; n < 32; n++) {
    *IOSByteArray_GetRef(nil_chk(S_), n) = (jbyte) (IOSByteArray_Get(S_, n) ^ IOSByteArray_Get(nil_chk(M_), n));
  }
  LibOrgBouncycastleCryptoDigestsGOST3411Digest_fwWithByteArray_(self, S_);
  for (jint n = 0; n < 32; n++) {
    *IOSByteArray_GetRef(nil_chk(S_), n) = (jbyte) (IOSByteArray_Get(nil_chk(H_), n) ^ IOSByteArray_Get(S_, n));
  }
  for (jint n = 0; n < 61; n++) {
    LibOrgBouncycastleCryptoDigestsGOST3411Digest_fwWithByteArray_(self, S_);
  }
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(S_, 0, H_, 0, ((IOSByteArray *) nil_chk(H_))->size_);
}

- (void)finish {
  LibOrgBouncycastleCryptoDigestsGOST3411Digest_finish(self);
}

- (jint)doFinalWithByteArray:(IOSByteArray *)outArg
                     withInt:(jint)outOff {
  LibOrgBouncycastleCryptoDigestsGOST3411Digest_finish(self);
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(H_, 0, outArg, outOff, ((IOSByteArray *) nil_chk(H_))->size_);
  [self reset];
  return LibOrgBouncycastleCryptoDigestsGOST3411Digest_DIGEST_LENGTH;
}

- (void)reset {
  byteCount_ = 0;
  xBufOff_ = 0;
  for (jint i = 0; i < ((IOSByteArray *) nil_chk(H_))->size_; i++) {
    *IOSByteArray_GetRef(H_, i) = 0;
  }
  for (jint i = 0; i < ((IOSByteArray *) nil_chk(L_))->size_; i++) {
    *IOSByteArray_GetRef(L_, i) = 0;
  }
  for (jint i = 0; i < ((IOSByteArray *) nil_chk(M_))->size_; i++) {
    *IOSByteArray_GetRef(M_, i) = 0;
  }
  for (jint i = 0; i < ((IOSByteArray *) nil_chk(IOSObjectArray_Get(nil_chk(C_), 1)))->size_; i++) {
    *IOSByteArray_GetRef(nil_chk(IOSObjectArray_Get(C_, 1)), i) = 0;
  }
  for (jint i = 0; i < ((IOSByteArray *) nil_chk(IOSObjectArray_Get(C_, 3)))->size_; i++) {
    *IOSByteArray_GetRef(nil_chk(IOSObjectArray_Get(C_, 3)), i) = 0;
  }
  for (jint i = 0; i < ((IOSByteArray *) nil_chk(Sum_))->size_; i++) {
    *IOSByteArray_GetRef(Sum_, i) = 0;
  }
  for (jint i = 0; i < ((IOSByteArray *) nil_chk(xBuf_))->size_; i++) {
    *IOSByteArray_GetRef(xBuf_, i) = 0;
  }
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(LibOrgBouncycastleCryptoDigestsGOST3411Digest_C2, 0, IOSObjectArray_Get(C_, 2), 0, ((IOSByteArray *) nil_chk(LibOrgBouncycastleCryptoDigestsGOST3411Digest_C2))->size_);
}

- (void)sumByteArrayWithByteArray:(IOSByteArray *)inArg {
  LibOrgBouncycastleCryptoDigestsGOST3411Digest_sumByteArrayWithByteArray_(self, inArg);
}

- (void)cpyBytesToShortWithByteArray:(IOSByteArray *)S
                      withShortArray:(IOSShortArray *)wS {
  LibOrgBouncycastleCryptoDigestsGOST3411Digest_cpyBytesToShortWithByteArray_withShortArray_(self, S, wS);
}

- (void)cpyShortToBytesWithShortArray:(IOSShortArray *)wS
                        withByteArray:(IOSByteArray *)S {
  LibOrgBouncycastleCryptoDigestsGOST3411Digest_cpyShortToBytesWithShortArray_withByteArray_(self, wS, S);
}

- (jint)getByteLength {
  return 32;
}

- (id<LibOrgBouncycastleUtilMemoable>)copy__ {
  return new_LibOrgBouncycastleCryptoDigestsGOST3411Digest_initWithLibOrgBouncycastleCryptoDigestsGOST3411Digest_(self);
}

- (void)resetWithLibOrgBouncycastleUtilMemoable:(id<LibOrgBouncycastleUtilMemoable>)other {
  LibOrgBouncycastleCryptoDigestsGOST3411Digest *t = (LibOrgBouncycastleCryptoDigestsGOST3411Digest *) cast_chk(other, [LibOrgBouncycastleCryptoDigestsGOST3411Digest class]);
  self->sBox_ = ((LibOrgBouncycastleCryptoDigestsGOST3411Digest *) nil_chk(t))->sBox_;
  [((id<LibOrgBouncycastleCryptoBlockCipher>) nil_chk(cipher_)) init__WithBoolean:true withLibOrgBouncycastleCryptoCipherParameters:new_LibOrgBouncycastleCryptoParamsParametersWithSBox_initWithLibOrgBouncycastleCryptoCipherParameters_withByteArray_(nil, sBox_)];
  [self reset];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(t->H_, 0, self->H_, 0, ((IOSByteArray *) nil_chk(t->H_))->size_);
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(t->L_, 0, self->L_, 0, ((IOSByteArray *) nil_chk(t->L_))->size_);
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(t->M_, 0, self->M_, 0, ((IOSByteArray *) nil_chk(t->M_))->size_);
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(t->Sum_, 0, self->Sum_, 0, ((IOSByteArray *) nil_chk(t->Sum_))->size_);
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(IOSObjectArray_Get(nil_chk(t->C_), 1), 0, IOSObjectArray_Get(self->C_, 1), 0, ((IOSByteArray *) nil_chk(IOSObjectArray_Get(t->C_, 1)))->size_);
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(IOSObjectArray_Get(nil_chk(t->C_), 2), 0, IOSObjectArray_Get(self->C_, 2), 0, ((IOSByteArray *) nil_chk(IOSObjectArray_Get(t->C_, 2)))->size_);
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(IOSObjectArray_Get(nil_chk(t->C_), 3), 0, IOSObjectArray_Get(self->C_, 3), 0, ((IOSByteArray *) nil_chk(IOSObjectArray_Get(t->C_, 3)))->size_);
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(t->xBuf_, 0, self->xBuf_, 0, ((IOSByteArray *) nil_chk(t->xBuf_))->size_);
  self->xBufOff_ = t->xBufOff_;
  self->byteCount_ = t->byteCount_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 2, 3, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 2, 4, -1, -1, -1, -1 },
    { NULL, "[B", 0x2, 5, 0, -1, -1, -1, -1 },
    { NULL, "[B", 0x2, 6, 0, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 7, 8, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 9, 0, -1, -1, -1, -1 },
    { NULL, "V", 0x4, 10, 11, -1, -1, -1, -1 },
    { NULL, "V", 0x2, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 12, 11, -1, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 13, 0, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 14, 15, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 16, 17, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleUtilMemoable;", 0x1, 18, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 19, 20, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(initWithByteArray:);
  methods[2].selector = @selector(initWithLibOrgBouncycastleCryptoDigestsGOST3411Digest:);
  methods[3].selector = @selector(getAlgorithmName);
  methods[4].selector = @selector(getDigestSize);
  methods[5].selector = @selector(updateWithByte:);
  methods[6].selector = @selector(updateWithByteArray:withInt:withInt:);
  methods[7].selector = @selector(PWithByteArray:);
  methods[8].selector = @selector(AWithByteArray:);
  methods[9].selector = @selector(EWithByteArray:withByteArray:withInt:withByteArray:withInt:);
  methods[10].selector = @selector(fwWithByteArray:);
  methods[11].selector = @selector(processBlockWithByteArray:withInt:);
  methods[12].selector = @selector(finish);
  methods[13].selector = @selector(doFinalWithByteArray:withInt:);
  methods[14].selector = @selector(reset);
  methods[15].selector = @selector(sumByteArrayWithByteArray:);
  methods[16].selector = @selector(cpyBytesToShortWithByteArray:withShortArray:);
  methods[17].selector = @selector(cpyShortToBytesWithShortArray:withByteArray:);
  methods[18].selector = @selector(getByteLength);
  methods[19].selector = @selector(copy__);
  methods[20].selector = @selector(resetWithLibOrgBouncycastleUtilMemoable:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "DIGEST_LENGTH", "I", .constantValue.asInt = LibOrgBouncycastleCryptoDigestsGOST3411Digest_DIGEST_LENGTH, 0x1a, -1, -1, -1, -1 },
    { "H_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "L_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "M_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "Sum_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "C_", "[[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "xBuf_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "xBufOff_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "byteCount_", "J", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "cipher_", "LLibOrgBouncycastleCryptoBlockCipher;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "sBox_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "K_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "a_", "[B", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "wS_", "[S", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "w_S_", "[S", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "S_", "[B", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "U_", "[B", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "V_", "[B", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "W_", "[B", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "C2", "[B", .constantValue.asLong = 0, 0x1a, -1, 21, -1, -1 },
  };
  static const void *ptrTable[] = { "[B", "LLibOrgBouncycastleCryptoDigestsGOST3411Digest;", "update", "B", "[BII", "P", "A", "E", "[B[BI[BI", "fw", "processBlock", "[BI", "doFinal", "sumByteArray", "cpyBytesToShort", "[B[S", "cpyShortToBytes", "[S[B", "copy", "reset", "LLibOrgBouncycastleUtilMemoable;", &LibOrgBouncycastleCryptoDigestsGOST3411Digest_C2 };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoDigestsGOST3411Digest = { "GOST3411Digest", "lib.org.bouncycastle.crypto.digests", ptrTable, methods, fields, 7, 0x1, 21, 20, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoDigestsGOST3411Digest;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleCryptoDigestsGOST3411Digest class]) {
    LibOrgBouncycastleCryptoDigestsGOST3411Digest_C2 = [IOSByteArray newArrayWithBytes:(jbyte[]){ (jint) 0x00, (jbyte) (jint) 0xFF, (jint) 0x00, (jbyte) (jint) 0xFF, (jint) 0x00, (jbyte) (jint) 0xFF, (jint) 0x00, (jbyte) (jint) 0xFF, (jbyte) (jint) 0xFF, (jint) 0x00, (jbyte) (jint) 0xFF, (jint) 0x00, (jbyte) (jint) 0xFF, (jint) 0x00, (jbyte) (jint) 0xFF, (jint) 0x00, (jint) 0x00, (jbyte) (jint) 0xFF, (jbyte) (jint) 0xFF, (jint) 0x00, (jbyte) (jint) 0xFF, (jint) 0x00, (jint) 0x00, (jbyte) (jint) 0xFF, (jbyte) (jint) 0xFF, (jint) 0x00, (jint) 0x00, (jint) 0x00, (jbyte) (jint) 0xFF, (jbyte) (jint) 0xFF, (jint) 0x00, (jbyte) (jint) 0xFF } count:32];
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleCryptoDigestsGOST3411Digest)
  }
}

@end

void LibOrgBouncycastleCryptoDigestsGOST3411Digest_init(LibOrgBouncycastleCryptoDigestsGOST3411Digest *self) {
  NSObject_init(self);
  self->H_ = [IOSByteArray newArrayWithLength:32];
  self->L_ = [IOSByteArray newArrayWithLength:32];
  self->M_ = [IOSByteArray newArrayWithLength:32];
  self->Sum_ = [IOSByteArray newArrayWithLength:32];
  self->C_ = [IOSByteArray newArrayWithDimensions:2 lengths:(jint[]){ 4, 32 }];
  self->xBuf_ = [IOSByteArray newArrayWithLength:32];
  self->cipher_ = new_LibOrgBouncycastleCryptoEnginesGOST28147Engine_init();
  self->K_ = [IOSByteArray newArrayWithLength:32];
  self->a_ = [IOSByteArray newArrayWithLength:8];
  self->wS_ = [IOSShortArray newArrayWithLength:16];
  self->w_S_ = [IOSShortArray newArrayWithLength:16];
  self->S_ = [IOSByteArray newArrayWithLength:32];
  self->U_ = [IOSByteArray newArrayWithLength:32];
  self->V_ = [IOSByteArray newArrayWithLength:32];
  self->W_ = [IOSByteArray newArrayWithLength:32];
  self->sBox_ = LibOrgBouncycastleCryptoEnginesGOST28147Engine_getSBoxWithNSString_(@"D-A");
  [((id<LibOrgBouncycastleCryptoBlockCipher>) nil_chk(self->cipher_)) init__WithBoolean:true withLibOrgBouncycastleCryptoCipherParameters:new_LibOrgBouncycastleCryptoParamsParametersWithSBox_initWithLibOrgBouncycastleCryptoCipherParameters_withByteArray_(nil, self->sBox_)];
  [self reset];
}

LibOrgBouncycastleCryptoDigestsGOST3411Digest *new_LibOrgBouncycastleCryptoDigestsGOST3411Digest_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoDigestsGOST3411Digest, init)
}

LibOrgBouncycastleCryptoDigestsGOST3411Digest *create_LibOrgBouncycastleCryptoDigestsGOST3411Digest_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoDigestsGOST3411Digest, init)
}

void LibOrgBouncycastleCryptoDigestsGOST3411Digest_initWithByteArray_(LibOrgBouncycastleCryptoDigestsGOST3411Digest *self, IOSByteArray *sBoxParam) {
  NSObject_init(self);
  self->H_ = [IOSByteArray newArrayWithLength:32];
  self->L_ = [IOSByteArray newArrayWithLength:32];
  self->M_ = [IOSByteArray newArrayWithLength:32];
  self->Sum_ = [IOSByteArray newArrayWithLength:32];
  self->C_ = [IOSByteArray newArrayWithDimensions:2 lengths:(jint[]){ 4, 32 }];
  self->xBuf_ = [IOSByteArray newArrayWithLength:32];
  self->cipher_ = new_LibOrgBouncycastleCryptoEnginesGOST28147Engine_init();
  self->K_ = [IOSByteArray newArrayWithLength:32];
  self->a_ = [IOSByteArray newArrayWithLength:8];
  self->wS_ = [IOSShortArray newArrayWithLength:16];
  self->w_S_ = [IOSShortArray newArrayWithLength:16];
  self->S_ = [IOSByteArray newArrayWithLength:32];
  self->U_ = [IOSByteArray newArrayWithLength:32];
  self->V_ = [IOSByteArray newArrayWithLength:32];
  self->W_ = [IOSByteArray newArrayWithLength:32];
  self->sBox_ = LibOrgBouncycastleUtilArrays_cloneWithByteArray_(sBoxParam);
  [((id<LibOrgBouncycastleCryptoBlockCipher>) nil_chk(self->cipher_)) init__WithBoolean:true withLibOrgBouncycastleCryptoCipherParameters:new_LibOrgBouncycastleCryptoParamsParametersWithSBox_initWithLibOrgBouncycastleCryptoCipherParameters_withByteArray_(nil, self->sBox_)];
  [self reset];
}

LibOrgBouncycastleCryptoDigestsGOST3411Digest *new_LibOrgBouncycastleCryptoDigestsGOST3411Digest_initWithByteArray_(IOSByteArray *sBoxParam) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoDigestsGOST3411Digest, initWithByteArray_, sBoxParam)
}

LibOrgBouncycastleCryptoDigestsGOST3411Digest *create_LibOrgBouncycastleCryptoDigestsGOST3411Digest_initWithByteArray_(IOSByteArray *sBoxParam) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoDigestsGOST3411Digest, initWithByteArray_, sBoxParam)
}

void LibOrgBouncycastleCryptoDigestsGOST3411Digest_initWithLibOrgBouncycastleCryptoDigestsGOST3411Digest_(LibOrgBouncycastleCryptoDigestsGOST3411Digest *self, LibOrgBouncycastleCryptoDigestsGOST3411Digest *t) {
  NSObject_init(self);
  self->H_ = [IOSByteArray newArrayWithLength:32];
  self->L_ = [IOSByteArray newArrayWithLength:32];
  self->M_ = [IOSByteArray newArrayWithLength:32];
  self->Sum_ = [IOSByteArray newArrayWithLength:32];
  self->C_ = [IOSByteArray newArrayWithDimensions:2 lengths:(jint[]){ 4, 32 }];
  self->xBuf_ = [IOSByteArray newArrayWithLength:32];
  self->cipher_ = new_LibOrgBouncycastleCryptoEnginesGOST28147Engine_init();
  self->K_ = [IOSByteArray newArrayWithLength:32];
  self->a_ = [IOSByteArray newArrayWithLength:8];
  self->wS_ = [IOSShortArray newArrayWithLength:16];
  self->w_S_ = [IOSShortArray newArrayWithLength:16];
  self->S_ = [IOSByteArray newArrayWithLength:32];
  self->U_ = [IOSByteArray newArrayWithLength:32];
  self->V_ = [IOSByteArray newArrayWithLength:32];
  self->W_ = [IOSByteArray newArrayWithLength:32];
  [self resetWithLibOrgBouncycastleUtilMemoable:t];
}

LibOrgBouncycastleCryptoDigestsGOST3411Digest *new_LibOrgBouncycastleCryptoDigestsGOST3411Digest_initWithLibOrgBouncycastleCryptoDigestsGOST3411Digest_(LibOrgBouncycastleCryptoDigestsGOST3411Digest *t) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoDigestsGOST3411Digest, initWithLibOrgBouncycastleCryptoDigestsGOST3411Digest_, t)
}

LibOrgBouncycastleCryptoDigestsGOST3411Digest *create_LibOrgBouncycastleCryptoDigestsGOST3411Digest_initWithLibOrgBouncycastleCryptoDigestsGOST3411Digest_(LibOrgBouncycastleCryptoDigestsGOST3411Digest *t) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoDigestsGOST3411Digest, initWithLibOrgBouncycastleCryptoDigestsGOST3411Digest_, t)
}

IOSByteArray *LibOrgBouncycastleCryptoDigestsGOST3411Digest_PWithByteArray_(LibOrgBouncycastleCryptoDigestsGOST3411Digest *self, IOSByteArray *inArg) {
  for (jint k = 0; k < 8; k++) {
    *IOSByteArray_GetRef(nil_chk(self->K_), 4 * k) = IOSByteArray_Get(nil_chk(inArg), k);
    *IOSByteArray_GetRef(self->K_, 1 + 4 * k) = IOSByteArray_Get(inArg, 8 + k);
    *IOSByteArray_GetRef(self->K_, 2 + 4 * k) = IOSByteArray_Get(inArg, 16 + k);
    *IOSByteArray_GetRef(self->K_, 3 + 4 * k) = IOSByteArray_Get(inArg, 24 + k);
  }
  return self->K_;
}

IOSByteArray *LibOrgBouncycastleCryptoDigestsGOST3411Digest_AWithByteArray_(LibOrgBouncycastleCryptoDigestsGOST3411Digest *self, IOSByteArray *inArg) {
  for (jint j = 0; j < 8; j++) {
    *IOSByteArray_GetRef(nil_chk(self->a_), j) = (jbyte) (IOSByteArray_Get(nil_chk(inArg), j) ^ IOSByteArray_Get(inArg, j + 8));
  }
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(inArg, 8, inArg, 0, 24);
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(self->a_, 0, inArg, 24, 8);
  return inArg;
}

void LibOrgBouncycastleCryptoDigestsGOST3411Digest_EWithByteArray_withByteArray_withInt_withByteArray_withInt_(LibOrgBouncycastleCryptoDigestsGOST3411Digest *self, IOSByteArray *key, IOSByteArray *s, jint sOff, IOSByteArray *inArg, jint inOff) {
  [((id<LibOrgBouncycastleCryptoBlockCipher>) nil_chk(self->cipher_)) init__WithBoolean:true withLibOrgBouncycastleCryptoCipherParameters:new_LibOrgBouncycastleCryptoParamsKeyParameter_initWithByteArray_(key)];
  [((id<LibOrgBouncycastleCryptoBlockCipher>) nil_chk(self->cipher_)) processBlockWithByteArray:inArg withInt:inOff withByteArray:s withInt:sOff];
}

void LibOrgBouncycastleCryptoDigestsGOST3411Digest_fwWithByteArray_(LibOrgBouncycastleCryptoDigestsGOST3411Digest *self, IOSByteArray *inArg) {
  LibOrgBouncycastleCryptoDigestsGOST3411Digest_cpyBytesToShortWithByteArray_withShortArray_(self, inArg, self->wS_);
  *IOSShortArray_GetRef(nil_chk(self->w_S_), 15) = (jshort) (IOSShortArray_Get(nil_chk(self->wS_), 0) ^ IOSShortArray_Get(self->wS_, 1) ^ IOSShortArray_Get(self->wS_, 2) ^ IOSShortArray_Get(self->wS_, 3) ^ IOSShortArray_Get(self->wS_, 12) ^ IOSShortArray_Get(self->wS_, 15));
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(self->wS_, 1, self->w_S_, 0, 15);
  LibOrgBouncycastleCryptoDigestsGOST3411Digest_cpyShortToBytesWithShortArray_withByteArray_(self, self->w_S_, inArg);
}

void LibOrgBouncycastleCryptoDigestsGOST3411Digest_finish(LibOrgBouncycastleCryptoDigestsGOST3411Digest *self) {
  LibOrgBouncycastleUtilPack_longToLittleEndianWithLong_withByteArray_withInt_(self->byteCount_ * 8, self->L_, 0);
  while (self->xBufOff_ != 0) {
    [self updateWithByte:(jbyte) 0];
  }
  [self processBlockWithByteArray:self->L_ withInt:0];
  [self processBlockWithByteArray:self->Sum_ withInt:0];
}

void LibOrgBouncycastleCryptoDigestsGOST3411Digest_sumByteArrayWithByteArray_(LibOrgBouncycastleCryptoDigestsGOST3411Digest *self, IOSByteArray *inArg) {
  jint carry = 0;
  for (jint i = 0; i != ((IOSByteArray *) nil_chk(self->Sum_))->size_; i++) {
    jint sum = (IOSByteArray_Get(self->Sum_, i) & (jint) 0xff) + (IOSByteArray_Get(nil_chk(inArg), i) & (jint) 0xff) + carry;
    *IOSByteArray_GetRef(self->Sum_, i) = (jbyte) sum;
    carry = JreURShift32(sum, 8);
  }
}

void LibOrgBouncycastleCryptoDigestsGOST3411Digest_cpyBytesToShortWithByteArray_withShortArray_(LibOrgBouncycastleCryptoDigestsGOST3411Digest *self, IOSByteArray *S, IOSShortArray *wS) {
  for (jint i = 0; i < ((IOSByteArray *) nil_chk(S))->size_ / 2; i++) {
    *IOSShortArray_GetRef(nil_chk(wS), i) = (jshort) (((JreLShift32(IOSByteArray_Get(S, i * 2 + 1), 8)) & (jint) 0xFF00) | (IOSByteArray_Get(S, i * 2) & (jint) 0xFF));
  }
}

void LibOrgBouncycastleCryptoDigestsGOST3411Digest_cpyShortToBytesWithShortArray_withByteArray_(LibOrgBouncycastleCryptoDigestsGOST3411Digest *self, IOSShortArray *wS, IOSByteArray *S) {
  for (jint i = 0; i < ((IOSByteArray *) nil_chk(S))->size_ / 2; i++) {
    *IOSByteArray_GetRef(S, i * 2 + 1) = (jbyte) (JreRShift32(IOSShortArray_Get(nil_chk(wS), i), 8));
    *IOSByteArray_GetRef(S, i * 2) = (jbyte) IOSShortArray_Get(wS, i);
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoDigestsGOST3411Digest)
