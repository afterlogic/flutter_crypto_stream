//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/math/raw/Nat320.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "Nat320.h"
#include "Pack.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/math/BigInteger.h"

@implementation LibOrgBouncycastleMathRawNat320

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleMathRawNat320_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (void)copy64WithLongArray:(IOSLongArray *)x
              withLongArray:(IOSLongArray *)z {
  LibOrgBouncycastleMathRawNat320_copy64WithLongArray_withLongArray_(x, z);
}

+ (void)copy64WithLongArray:(IOSLongArray *)x
                    withInt:(jint)xOff
              withLongArray:(IOSLongArray *)z
                    withInt:(jint)zOff {
  LibOrgBouncycastleMathRawNat320_copy64WithLongArray_withInt_withLongArray_withInt_(x, xOff, z, zOff);
}

+ (IOSLongArray *)create64 {
  return LibOrgBouncycastleMathRawNat320_create64();
}

+ (IOSLongArray *)createExt64 {
  return LibOrgBouncycastleMathRawNat320_createExt64();
}

+ (jboolean)eq64WithLongArray:(IOSLongArray *)x
                withLongArray:(IOSLongArray *)y {
  return LibOrgBouncycastleMathRawNat320_eq64WithLongArray_withLongArray_(x, y);
}

+ (IOSLongArray *)fromBigInteger64WithJavaMathBigInteger:(JavaMathBigInteger *)x {
  return LibOrgBouncycastleMathRawNat320_fromBigInteger64WithJavaMathBigInteger_(x);
}

+ (jboolean)isOne64WithLongArray:(IOSLongArray *)x {
  return LibOrgBouncycastleMathRawNat320_isOne64WithLongArray_(x);
}

+ (jboolean)isZero64WithLongArray:(IOSLongArray *)x {
  return LibOrgBouncycastleMathRawNat320_isZero64WithLongArray_(x);
}

+ (JavaMathBigInteger *)toBigInteger64WithLongArray:(IOSLongArray *)x {
  return LibOrgBouncycastleMathRawNat320_toBigInteger64WithLongArray_(x);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 0, 2, -1, -1, -1, -1 },
    { NULL, "[J", 0x9, -1, -1, -1, -1, -1, -1 },
    { NULL, "[J", 0x9, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x9, 3, 1, -1, -1, -1, -1 },
    { NULL, "[J", 0x9, 4, 5, -1, -1, -1, -1 },
    { NULL, "Z", 0x9, 6, 7, -1, -1, -1, -1 },
    { NULL, "Z", 0x9, 8, 7, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x9, 9, 7, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(copy64WithLongArray:withLongArray:);
  methods[2].selector = @selector(copy64WithLongArray:withInt:withLongArray:withInt:);
  methods[3].selector = @selector(create64);
  methods[4].selector = @selector(createExt64);
  methods[5].selector = @selector(eq64WithLongArray:withLongArray:);
  methods[6].selector = @selector(fromBigInteger64WithJavaMathBigInteger:);
  methods[7].selector = @selector(isOne64WithLongArray:);
  methods[8].selector = @selector(isZero64WithLongArray:);
  methods[9].selector = @selector(toBigInteger64WithLongArray:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "copy64", "[J[J", "[JI[JI", "eq64", "fromBigInteger64", "LJavaMathBigInteger;", "isOne64", "[J", "isZero64", "toBigInteger64" };
  static const J2ObjcClassInfo _LibOrgBouncycastleMathRawNat320 = { "Nat320", "lib.org.bouncycastle.math.raw", ptrTable, methods, NULL, 7, 0x401, 10, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleMathRawNat320;
}

@end

void LibOrgBouncycastleMathRawNat320_init(LibOrgBouncycastleMathRawNat320 *self) {
  NSObject_init(self);
}

void LibOrgBouncycastleMathRawNat320_copy64WithLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *z) {
  LibOrgBouncycastleMathRawNat320_initialize();
  *IOSLongArray_GetRef(nil_chk(z), 0) = IOSLongArray_Get(nil_chk(x), 0);
  *IOSLongArray_GetRef(z, 1) = IOSLongArray_Get(x, 1);
  *IOSLongArray_GetRef(z, 2) = IOSLongArray_Get(x, 2);
  *IOSLongArray_GetRef(z, 3) = IOSLongArray_Get(x, 3);
  *IOSLongArray_GetRef(z, 4) = IOSLongArray_Get(x, 4);
}

void LibOrgBouncycastleMathRawNat320_copy64WithLongArray_withInt_withLongArray_withInt_(IOSLongArray *x, jint xOff, IOSLongArray *z, jint zOff) {
  LibOrgBouncycastleMathRawNat320_initialize();
  *IOSLongArray_GetRef(nil_chk(z), zOff + 0) = IOSLongArray_Get(nil_chk(x), xOff + 0);
  *IOSLongArray_GetRef(z, zOff + 1) = IOSLongArray_Get(x, xOff + 1);
  *IOSLongArray_GetRef(z, zOff + 2) = IOSLongArray_Get(x, xOff + 2);
  *IOSLongArray_GetRef(z, zOff + 3) = IOSLongArray_Get(x, xOff + 3);
  *IOSLongArray_GetRef(z, zOff + 4) = IOSLongArray_Get(x, xOff + 4);
}

IOSLongArray *LibOrgBouncycastleMathRawNat320_create64() {
  LibOrgBouncycastleMathRawNat320_initialize();
  return [IOSLongArray newArrayWithLength:5];
}

IOSLongArray *LibOrgBouncycastleMathRawNat320_createExt64() {
  LibOrgBouncycastleMathRawNat320_initialize();
  return [IOSLongArray newArrayWithLength:10];
}

jboolean LibOrgBouncycastleMathRawNat320_eq64WithLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *y) {
  LibOrgBouncycastleMathRawNat320_initialize();
  for (jint i = 4; i >= 0; --i) {
    if (IOSLongArray_Get(nil_chk(x), i) != IOSLongArray_Get(nil_chk(y), i)) {
      return false;
    }
  }
  return true;
}

IOSLongArray *LibOrgBouncycastleMathRawNat320_fromBigInteger64WithJavaMathBigInteger_(JavaMathBigInteger *x) {
  LibOrgBouncycastleMathRawNat320_initialize();
  if ([((JavaMathBigInteger *) nil_chk(x)) signum] < 0 || [x bitLength] > 320) {
    @throw new_JavaLangIllegalArgumentException_init();
  }
  IOSLongArray *z = LibOrgBouncycastleMathRawNat320_create64();
  jint i = 0;
  while ([((JavaMathBigInteger *) nil_chk(x)) signum] != 0) {
    *IOSLongArray_GetRef(nil_chk(z), i++) = [x longLongValue];
    x = [x shiftRightWithInt:64];
  }
  return z;
}

jboolean LibOrgBouncycastleMathRawNat320_isOne64WithLongArray_(IOSLongArray *x) {
  LibOrgBouncycastleMathRawNat320_initialize();
  if (IOSLongArray_Get(nil_chk(x), 0) != 1LL) {
    return false;
  }
  for (jint i = 1; i < 5; ++i) {
    if (IOSLongArray_Get(x, i) != 0LL) {
      return false;
    }
  }
  return true;
}

jboolean LibOrgBouncycastleMathRawNat320_isZero64WithLongArray_(IOSLongArray *x) {
  LibOrgBouncycastleMathRawNat320_initialize();
  for (jint i = 0; i < 5; ++i) {
    if (IOSLongArray_Get(nil_chk(x), i) != 0LL) {
      return false;
    }
  }
  return true;
}

JavaMathBigInteger *LibOrgBouncycastleMathRawNat320_toBigInteger64WithLongArray_(IOSLongArray *x) {
  LibOrgBouncycastleMathRawNat320_initialize();
  IOSByteArray *bs = [IOSByteArray newArrayWithLength:40];
  for (jint i = 0; i < 5; ++i) {
    jlong x_i = IOSLongArray_Get(nil_chk(x), i);
    if (x_i != 0LL) {
      LibOrgBouncycastleUtilPack_longToBigEndianWithLong_withByteArray_withInt_(x_i, bs, JreLShift32((4 - i), 3));
    }
  }
  return new_JavaMathBigInteger_initWithInt_withByteArray_(1, bs);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleMathRawNat320)