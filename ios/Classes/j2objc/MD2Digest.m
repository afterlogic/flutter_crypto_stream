//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/digests/MD2Digest.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "MD2Digest.h"
#include "Memoable.h"
#include "java/lang/System.h"

@interface LibOrgBouncycastleCryptoDigestsMD2Digest () {
 @public
  IOSByteArray *X_;
  jint xOff_;
  IOSByteArray *M_;
  jint mOff_;
  IOSByteArray *C_;
  jint COff_;
}

- (void)copyInWithLibOrgBouncycastleCryptoDigestsMD2Digest:(LibOrgBouncycastleCryptoDigestsMD2Digest *)t OBJC_METHOD_FAMILY_NONE;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoDigestsMD2Digest, X_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoDigestsMD2Digest, M_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoDigestsMD2Digest, C_, IOSByteArray *)

inline jint LibOrgBouncycastleCryptoDigestsMD2Digest_get_DIGEST_LENGTH(void);
#define LibOrgBouncycastleCryptoDigestsMD2Digest_DIGEST_LENGTH 16
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoDigestsMD2Digest, DIGEST_LENGTH, jint)

inline IOSByteArray *LibOrgBouncycastleCryptoDigestsMD2Digest_get_S(void);
static IOSByteArray *LibOrgBouncycastleCryptoDigestsMD2Digest_S;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoDigestsMD2Digest, S, IOSByteArray *)

__attribute__((unused)) static void LibOrgBouncycastleCryptoDigestsMD2Digest_copyInWithLibOrgBouncycastleCryptoDigestsMD2Digest_(LibOrgBouncycastleCryptoDigestsMD2Digest *self, LibOrgBouncycastleCryptoDigestsMD2Digest *t);

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleCryptoDigestsMD2Digest)

@implementation LibOrgBouncycastleCryptoDigestsMD2Digest

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoDigestsMD2Digest_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (instancetype)initWithLibOrgBouncycastleCryptoDigestsMD2Digest:(LibOrgBouncycastleCryptoDigestsMD2Digest *)t {
  LibOrgBouncycastleCryptoDigestsMD2Digest_initWithLibOrgBouncycastleCryptoDigestsMD2Digest_(self, t);
  return self;
}

- (void)copyInWithLibOrgBouncycastleCryptoDigestsMD2Digest:(LibOrgBouncycastleCryptoDigestsMD2Digest *)t {
  LibOrgBouncycastleCryptoDigestsMD2Digest_copyInWithLibOrgBouncycastleCryptoDigestsMD2Digest_(self, t);
}

- (NSString *)getAlgorithmName {
  return @"MD2";
}

- (jint)getDigestSize {
  return LibOrgBouncycastleCryptoDigestsMD2Digest_DIGEST_LENGTH;
}

- (jint)doFinalWithByteArray:(IOSByteArray *)outArg
                     withInt:(jint)outOff {
  jbyte paddingByte = (jbyte) (((IOSByteArray *) nil_chk(M_))->size_ - mOff_);
  for (jint i = mOff_; i < M_->size_; i++) {
    *IOSByteArray_GetRef(M_, i) = paddingByte;
  }
  [self processCheckSumWithByteArray:M_];
  [self processBlockWithByteArray:M_];
  [self processBlockWithByteArray:C_];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(X_, xOff_, outArg, outOff, 16);
  [self reset];
  return LibOrgBouncycastleCryptoDigestsMD2Digest_DIGEST_LENGTH;
}

- (void)reset {
  xOff_ = 0;
  for (jint i = 0; i != ((IOSByteArray *) nil_chk(X_))->size_; i++) {
    *IOSByteArray_GetRef(X_, i) = 0;
  }
  mOff_ = 0;
  for (jint i = 0; i != ((IOSByteArray *) nil_chk(M_))->size_; i++) {
    *IOSByteArray_GetRef(M_, i) = 0;
  }
  COff_ = 0;
  for (jint i = 0; i != ((IOSByteArray *) nil_chk(C_))->size_; i++) {
    *IOSByteArray_GetRef(C_, i) = 0;
  }
}

- (void)updateWithByte:(jbyte)inArg {
  *IOSByteArray_GetRef(nil_chk(M_), mOff_++) = inArg;
  if (mOff_ == 16) {
    [self processCheckSumWithByteArray:M_];
    [self processBlockWithByteArray:M_];
    mOff_ = 0;
  }
}

- (void)updateWithByteArray:(IOSByteArray *)inArg
                    withInt:(jint)inOff
                    withInt:(jint)len {
  while ((mOff_ != 0) && (len > 0)) {
    [self updateWithByte:IOSByteArray_Get(nil_chk(inArg), inOff)];
    inOff++;
    len--;
  }
  while (len > 16) {
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(inArg, inOff, M_, 0, 16);
    [self processCheckSumWithByteArray:M_];
    [self processBlockWithByteArray:M_];
    len -= 16;
    inOff += 16;
  }
  while (len > 0) {
    [self updateWithByte:IOSByteArray_Get(nil_chk(inArg), inOff)];
    inOff++;
    len--;
  }
}

- (void)processCheckSumWithByteArray:(IOSByteArray *)m {
  jint L = IOSByteArray_Get(nil_chk(C_), 15);
  for (jint i = 0; i < 16; i++) {
    *IOSByteArray_GetRef(C_, i) ^= IOSByteArray_Get(nil_chk(LibOrgBouncycastleCryptoDigestsMD2Digest_S), (IOSByteArray_Get(nil_chk(m), i) ^ L) & (jint) 0xff);
    L = IOSByteArray_Get(C_, i);
  }
}

- (void)processBlockWithByteArray:(IOSByteArray *)m {
  for (jint i = 0; i < 16; i++) {
    *IOSByteArray_GetRef(nil_chk(X_), i + 16) = IOSByteArray_Get(nil_chk(m), i);
    *IOSByteArray_GetRef(X_, i + 32) = (jbyte) (IOSByteArray_Get(m, i) ^ IOSByteArray_Get(X_, i));
  }
  jint t = 0;
  for (jint j = 0; j < 18; j++) {
    for (jint k = 0; k < 48; k++) {
      t = *IOSByteArray_GetRef(nil_chk(X_), k) ^= IOSByteArray_Get(nil_chk(LibOrgBouncycastleCryptoDigestsMD2Digest_S), t);
      t = t & (jint) 0xff;
    }
    t = (t + j) % 256;
  }
}

- (jint)getByteLength {
  return 16;
}

- (id<LibOrgBouncycastleUtilMemoable>)copy__ {
  return new_LibOrgBouncycastleCryptoDigestsMD2Digest_initWithLibOrgBouncycastleCryptoDigestsMD2Digest_(self);
}

- (void)resetWithLibOrgBouncycastleUtilMemoable:(id<LibOrgBouncycastleUtilMemoable>)other {
  LibOrgBouncycastleCryptoDigestsMD2Digest *d = (LibOrgBouncycastleCryptoDigestsMD2Digest *) cast_chk(other, [LibOrgBouncycastleCryptoDigestsMD2Digest class]);
  LibOrgBouncycastleCryptoDigestsMD2Digest_copyInWithLibOrgBouncycastleCryptoDigestsMD2Digest_(self, d);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 1, 0, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 2, 3, -1, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 4, 5, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 4, 6, -1, -1, -1, -1 },
    { NULL, "V", 0x4, 7, 8, -1, -1, -1, -1 },
    { NULL, "V", 0x4, 9, 8, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleUtilMemoable;", 0x1, 10, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 11, 12, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(initWithLibOrgBouncycastleCryptoDigestsMD2Digest:);
  methods[2].selector = @selector(copyInWithLibOrgBouncycastleCryptoDigestsMD2Digest:);
  methods[3].selector = @selector(getAlgorithmName);
  methods[4].selector = @selector(getDigestSize);
  methods[5].selector = @selector(doFinalWithByteArray:withInt:);
  methods[6].selector = @selector(reset);
  methods[7].selector = @selector(updateWithByte:);
  methods[8].selector = @selector(updateWithByteArray:withInt:withInt:);
  methods[9].selector = @selector(processCheckSumWithByteArray:);
  methods[10].selector = @selector(processBlockWithByteArray:);
  methods[11].selector = @selector(getByteLength);
  methods[12].selector = @selector(copy__);
  methods[13].selector = @selector(resetWithLibOrgBouncycastleUtilMemoable:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "DIGEST_LENGTH", "I", .constantValue.asInt = LibOrgBouncycastleCryptoDigestsMD2Digest_DIGEST_LENGTH, 0x1a, -1, -1, -1, -1 },
    { "X_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "xOff_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "M_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "mOff_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "C_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "COff_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "S", "[B", .constantValue.asLong = 0, 0x1a, -1, 13, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleCryptoDigestsMD2Digest;", "copyIn", "doFinal", "[BI", "update", "B", "[BII", "processCheckSum", "[B", "processBlock", "copy", "reset", "LLibOrgBouncycastleUtilMemoable;", &LibOrgBouncycastleCryptoDigestsMD2Digest_S };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoDigestsMD2Digest = { "MD2Digest", "lib.org.bouncycastle.crypto.digests", ptrTable, methods, fields, 7, 0x1, 14, 8, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoDigestsMD2Digest;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleCryptoDigestsMD2Digest class]) {
    LibOrgBouncycastleCryptoDigestsMD2Digest_S = [IOSByteArray newArrayWithBytes:(jbyte[]){ (jbyte) 41, (jbyte) 46, (jbyte) 67, (jbyte) 201, (jbyte) 162, (jbyte) 216, (jbyte) 124, (jbyte) 1, (jbyte) 61, (jbyte) 54, (jbyte) 84, (jbyte) 161, (jbyte) 236, (jbyte) 240, (jbyte) 6, (jbyte) 19, (jbyte) 98, (jbyte) 167, (jbyte) 5, (jbyte) 243, (jbyte) 192, (jbyte) 199, (jbyte) 115, (jbyte) 140, (jbyte) 152, (jbyte) 147, (jbyte) 43, (jbyte) 217, (jbyte) 188, (jbyte) 76, (jbyte) 130, (jbyte) 202, (jbyte) 30, (jbyte) 155, (jbyte) 87, (jbyte) 60, (jbyte) 253, (jbyte) 212, (jbyte) 224, (jbyte) 22, (jbyte) 103, (jbyte) 66, (jbyte) 111, (jbyte) 24, (jbyte) 138, (jbyte) 23, (jbyte) 229, (jbyte) 18, (jbyte) 190, (jbyte) 78, (jbyte) 196, (jbyte) 214, (jbyte) 218, (jbyte) 158, (jbyte) 222, (jbyte) 73, (jbyte) 160, (jbyte) 251, (jbyte) 245, (jbyte) 142, (jbyte) 187, (jbyte) 47, (jbyte) 238, (jbyte) 122, (jbyte) 169, (jbyte) 104, (jbyte) 121, (jbyte) 145, (jbyte) 21, (jbyte) 178, (jbyte) 7, (jbyte) 63, (jbyte) 148, (jbyte) 194, (jbyte) 16, (jbyte) 137, (jbyte) 11, (jbyte) 34, (jbyte) 95, (jbyte) 33, (jbyte) 128, (jbyte) 127, (jbyte) 93, (jbyte) 154, (jbyte) 90, (jbyte) 144, (jbyte) 50, (jbyte) 39, (jbyte) 53, (jbyte) 62, (jbyte) 204, (jbyte) 231, (jbyte) 191, (jbyte) 247, (jbyte) 151, (jbyte) 3, (jbyte) 255, (jbyte) 25, (jbyte) 48, (jbyte) 179, (jbyte) 72, (jbyte) 165, (jbyte) 181, (jbyte) 209, (jbyte) 215, (jbyte) 94, (jbyte) 146, (jbyte) 42, (jbyte) 172, (jbyte) 86, (jbyte) 170, (jbyte) 198, (jbyte) 79, (jbyte) 184, (jbyte) 56, (jbyte) 210, (jbyte) 150, (jbyte) 164, (jbyte) 125, (jbyte) 182, (jbyte) 118, (jbyte) 252, (jbyte) 107, (jbyte) 226, (jbyte) 156, (jbyte) 116, (jbyte) 4, (jbyte) 241, (jbyte) 69, (jbyte) 157, (jbyte) 112, (jbyte) 89, (jbyte) 100, (jbyte) 113, (jbyte) 135, (jbyte) 32, (jbyte) 134, (jbyte) 91, (jbyte) 207, (jbyte) 101, (jbyte) 230, (jbyte) 45, (jbyte) 168, (jbyte) 2, (jbyte) 27, (jbyte) 96, (jbyte) 37, (jbyte) 173, (jbyte) 174, (jbyte) 176, (jbyte) 185, (jbyte) 246, (jbyte) 28, (jbyte) 70, (jbyte) 97, (jbyte) 105, (jbyte) 52, (jbyte) 64, (jbyte) 126, (jbyte) 15, (jbyte) 85, (jbyte) 71, (jbyte) 163, (jbyte) 35, (jbyte) 221, (jbyte) 81, (jbyte) 175, (jbyte) 58, (jbyte) 195, (jbyte) 92, (jbyte) 249, (jbyte) 206, (jbyte) 186, (jbyte) 197, (jbyte) 234, (jbyte) 38, (jbyte) 44, (jbyte) 83, (jbyte) 13, (jbyte) 110, (jbyte) 133, (jbyte) 40, (jbyte) 132, 9, (jbyte) 211, (jbyte) 223, (jbyte) 205, (jbyte) 244, (jbyte) 65, (jbyte) 129, (jbyte) 77, (jbyte) 82, (jbyte) 106, (jbyte) 220, (jbyte) 55, (jbyte) 200, (jbyte) 108, (jbyte) 193, (jbyte) 171, (jbyte) 250, (jbyte) 36, (jbyte) 225, (jbyte) 123, (jbyte) 8, (jbyte) 12, (jbyte) 189, (jbyte) 177, (jbyte) 74, (jbyte) 120, (jbyte) 136, (jbyte) 149, (jbyte) 139, (jbyte) 227, (jbyte) 99, (jbyte) 232, (jbyte) 109, (jbyte) 233, (jbyte) 203, (jbyte) 213, (jbyte) 254, (jbyte) 59, (jbyte) 0, (jbyte) 29, (jbyte) 57, (jbyte) 242, (jbyte) 239, (jbyte) 183, (jbyte) 14, (jbyte) 102, (jbyte) 88, (jbyte) 208, (jbyte) 228, (jbyte) 166, (jbyte) 119, (jbyte) 114, (jbyte) 248, (jbyte) 235, (jbyte) 117, (jbyte) 75, (jbyte) 10, (jbyte) 49, (jbyte) 68, (jbyte) 80, (jbyte) 180, (jbyte) 143, (jbyte) 237, (jbyte) 31, (jbyte) 26, (jbyte) 219, (jbyte) 153, (jbyte) 141, (jbyte) 51, (jbyte) 159, (jbyte) 17, (jbyte) 131, (jbyte) 20 } count:256];
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleCryptoDigestsMD2Digest)
  }
}

@end

void LibOrgBouncycastleCryptoDigestsMD2Digest_init(LibOrgBouncycastleCryptoDigestsMD2Digest *self) {
  NSObject_init(self);
  self->X_ = [IOSByteArray newArrayWithLength:48];
  self->M_ = [IOSByteArray newArrayWithLength:16];
  self->C_ = [IOSByteArray newArrayWithLength:16];
  [self reset];
}

LibOrgBouncycastleCryptoDigestsMD2Digest *new_LibOrgBouncycastleCryptoDigestsMD2Digest_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoDigestsMD2Digest, init)
}

LibOrgBouncycastleCryptoDigestsMD2Digest *create_LibOrgBouncycastleCryptoDigestsMD2Digest_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoDigestsMD2Digest, init)
}

void LibOrgBouncycastleCryptoDigestsMD2Digest_initWithLibOrgBouncycastleCryptoDigestsMD2Digest_(LibOrgBouncycastleCryptoDigestsMD2Digest *self, LibOrgBouncycastleCryptoDigestsMD2Digest *t) {
  NSObject_init(self);
  self->X_ = [IOSByteArray newArrayWithLength:48];
  self->M_ = [IOSByteArray newArrayWithLength:16];
  self->C_ = [IOSByteArray newArrayWithLength:16];
  LibOrgBouncycastleCryptoDigestsMD2Digest_copyInWithLibOrgBouncycastleCryptoDigestsMD2Digest_(self, t);
}

LibOrgBouncycastleCryptoDigestsMD2Digest *new_LibOrgBouncycastleCryptoDigestsMD2Digest_initWithLibOrgBouncycastleCryptoDigestsMD2Digest_(LibOrgBouncycastleCryptoDigestsMD2Digest *t) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoDigestsMD2Digest, initWithLibOrgBouncycastleCryptoDigestsMD2Digest_, t)
}

LibOrgBouncycastleCryptoDigestsMD2Digest *create_LibOrgBouncycastleCryptoDigestsMD2Digest_initWithLibOrgBouncycastleCryptoDigestsMD2Digest_(LibOrgBouncycastleCryptoDigestsMD2Digest *t) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoDigestsMD2Digest, initWithLibOrgBouncycastleCryptoDigestsMD2Digest_, t)
}

void LibOrgBouncycastleCryptoDigestsMD2Digest_copyInWithLibOrgBouncycastleCryptoDigestsMD2Digest_(LibOrgBouncycastleCryptoDigestsMD2Digest *self, LibOrgBouncycastleCryptoDigestsMD2Digest *t) {
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(((LibOrgBouncycastleCryptoDigestsMD2Digest *) nil_chk(t))->X_, 0, self->X_, 0, ((IOSByteArray *) nil_chk(t->X_))->size_);
  self->xOff_ = t->xOff_;
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(t->M_, 0, self->M_, 0, ((IOSByteArray *) nil_chk(t->M_))->size_);
  self->mOff_ = t->mOff_;
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(t->C_, 0, self->C_, 0, ((IOSByteArray *) nil_chk(t->C_))->size_);
  self->COff_ = t->COff_;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoDigestsMD2Digest)
