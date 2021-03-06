//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/math/ec/custom/sec/SecT113Field.java
//

#include "IOSPrimitiveArray.h"
#include "Interleave.h"
#include "J2ObjC_source.h"
#include "Nat128.h"
#include "SecT113Field.h"
#include "java/lang/IllegalStateException.h"
#include "java/math/BigInteger.h"

inline jlong LibOrgBouncycastleMathEcCustomSecSecT113Field_get_M49(void);
#define LibOrgBouncycastleMathEcCustomSecSecT113Field_M49 562949953421311LL
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleMathEcCustomSecSecT113Field, M49, jlong)

inline jlong LibOrgBouncycastleMathEcCustomSecSecT113Field_get_M57(void);
#define LibOrgBouncycastleMathEcCustomSecSecT113Field_M57 144115188075855871LL
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleMathEcCustomSecSecT113Field, M57, jlong)

@implementation LibOrgBouncycastleMathEcCustomSecSecT113Field

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleMathEcCustomSecSecT113Field_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (void)addWithLongArray:(IOSLongArray *)x
           withLongArray:(IOSLongArray *)y
           withLongArray:(IOSLongArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecT113Field_addWithLongArray_withLongArray_withLongArray_(x, y, z);
}

+ (void)addExtWithLongArray:(IOSLongArray *)xx
              withLongArray:(IOSLongArray *)yy
              withLongArray:(IOSLongArray *)zz {
  LibOrgBouncycastleMathEcCustomSecSecT113Field_addExtWithLongArray_withLongArray_withLongArray_(xx, yy, zz);
}

+ (void)addOneWithLongArray:(IOSLongArray *)x
              withLongArray:(IOSLongArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecT113Field_addOneWithLongArray_withLongArray_(x, z);
}

+ (IOSLongArray *)fromBigIntegerWithJavaMathBigInteger:(JavaMathBigInteger *)x {
  return LibOrgBouncycastleMathEcCustomSecSecT113Field_fromBigIntegerWithJavaMathBigInteger_(x);
}

+ (void)invertWithLongArray:(IOSLongArray *)x
              withLongArray:(IOSLongArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecT113Field_invertWithLongArray_withLongArray_(x, z);
}

+ (void)multiplyWithLongArray:(IOSLongArray *)x
                withLongArray:(IOSLongArray *)y
                withLongArray:(IOSLongArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecT113Field_multiplyWithLongArray_withLongArray_withLongArray_(x, y, z);
}

+ (void)multiplyAddToExtWithLongArray:(IOSLongArray *)x
                        withLongArray:(IOSLongArray *)y
                        withLongArray:(IOSLongArray *)zz {
  LibOrgBouncycastleMathEcCustomSecSecT113Field_multiplyAddToExtWithLongArray_withLongArray_withLongArray_(x, y, zz);
}

+ (void)reduceWithLongArray:(IOSLongArray *)xx
              withLongArray:(IOSLongArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecT113Field_reduceWithLongArray_withLongArray_(xx, z);
}

+ (void)reduce15WithLongArray:(IOSLongArray *)z
                      withInt:(jint)zOff {
  LibOrgBouncycastleMathEcCustomSecSecT113Field_reduce15WithLongArray_withInt_(z, zOff);
}

+ (void)sqrtWithLongArray:(IOSLongArray *)x
            withLongArray:(IOSLongArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecT113Field_sqrtWithLongArray_withLongArray_(x, z);
}

+ (void)squareWithLongArray:(IOSLongArray *)x
              withLongArray:(IOSLongArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecT113Field_squareWithLongArray_withLongArray_(x, z);
}

+ (void)squareAddToExtWithLongArray:(IOSLongArray *)x
                      withLongArray:(IOSLongArray *)zz {
  LibOrgBouncycastleMathEcCustomSecSecT113Field_squareAddToExtWithLongArray_withLongArray_(x, zz);
}

+ (void)squareNWithLongArray:(IOSLongArray *)x
                     withInt:(jint)n
               withLongArray:(IOSLongArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecT113Field_squareNWithLongArray_withInt_withLongArray_(x, n, z);
}

+ (jint)traceWithLongArray:(IOSLongArray *)x {
  return LibOrgBouncycastleMathEcCustomSecSecT113Field_traceWithLongArray_(x);
}

+ (void)implMultiplyWithLongArray:(IOSLongArray *)x
                    withLongArray:(IOSLongArray *)y
                    withLongArray:(IOSLongArray *)zz {
  LibOrgBouncycastleMathEcCustomSecSecT113Field_implMultiplyWithLongArray_withLongArray_withLongArray_(x, y, zz);
}

+ (void)implMulwWithLong:(jlong)x
                withLong:(jlong)y
           withLongArray:(IOSLongArray *)z
                 withInt:(jint)zOff {
  LibOrgBouncycastleMathEcCustomSecSecT113Field_implMulwWithLong_withLong_withLongArray_withInt_(x, y, z, zOff);
}

+ (void)implSquareWithLongArray:(IOSLongArray *)x
                  withLongArray:(IOSLongArray *)zz {
  LibOrgBouncycastleMathEcCustomSecSecT113Field_implSquareWithLongArray_withLongArray_(x, zz);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 2, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 3, 4, -1, -1, -1, -1 },
    { NULL, "[J", 0x9, 5, 6, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 7, 4, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 8, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 9, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 10, 4, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 11, 12, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 13, 4, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 14, 4, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 15, 4, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 16, 17, -1, -1, -1, -1 },
    { NULL, "I", 0x9, 18, 19, -1, -1, -1, -1 },
    { NULL, "V", 0xc, 20, 1, -1, -1, -1, -1 },
    { NULL, "V", 0xc, 21, 22, -1, -1, -1, -1 },
    { NULL, "V", 0xc, 23, 4, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(addWithLongArray:withLongArray:withLongArray:);
  methods[2].selector = @selector(addExtWithLongArray:withLongArray:withLongArray:);
  methods[3].selector = @selector(addOneWithLongArray:withLongArray:);
  methods[4].selector = @selector(fromBigIntegerWithJavaMathBigInteger:);
  methods[5].selector = @selector(invertWithLongArray:withLongArray:);
  methods[6].selector = @selector(multiplyWithLongArray:withLongArray:withLongArray:);
  methods[7].selector = @selector(multiplyAddToExtWithLongArray:withLongArray:withLongArray:);
  methods[8].selector = @selector(reduceWithLongArray:withLongArray:);
  methods[9].selector = @selector(reduce15WithLongArray:withInt:);
  methods[10].selector = @selector(sqrtWithLongArray:withLongArray:);
  methods[11].selector = @selector(squareWithLongArray:withLongArray:);
  methods[12].selector = @selector(squareAddToExtWithLongArray:withLongArray:);
  methods[13].selector = @selector(squareNWithLongArray:withInt:withLongArray:);
  methods[14].selector = @selector(traceWithLongArray:);
  methods[15].selector = @selector(implMultiplyWithLongArray:withLongArray:withLongArray:);
  methods[16].selector = @selector(implMulwWithLong:withLong:withLongArray:withInt:);
  methods[17].selector = @selector(implSquareWithLongArray:withLongArray:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "M49", "J", .constantValue.asLong = LibOrgBouncycastleMathEcCustomSecSecT113Field_M49, 0x1a, -1, -1, -1, -1 },
    { "M57", "J", .constantValue.asLong = LibOrgBouncycastleMathEcCustomSecSecT113Field_M57, 0x1a, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "add", "[J[J[J", "addExt", "addOne", "[J[J", "fromBigInteger", "LJavaMathBigInteger;", "invert", "multiply", "multiplyAddToExt", "reduce", "reduce15", "[JI", "sqrt", "square", "squareAddToExt", "squareN", "[JI[J", "trace", "[J", "implMultiply", "implMulw", "JJ[JI", "implSquare" };
  static const J2ObjcClassInfo _LibOrgBouncycastleMathEcCustomSecSecT113Field = { "SecT113Field", "lib.org.bouncycastle.math.ec.custom.sec", ptrTable, methods, fields, 7, 0x1, 18, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleMathEcCustomSecSecT113Field;
}

@end

void LibOrgBouncycastleMathEcCustomSecSecT113Field_init(LibOrgBouncycastleMathEcCustomSecSecT113Field *self) {
  NSObject_init(self);
}

LibOrgBouncycastleMathEcCustomSecSecT113Field *new_LibOrgBouncycastleMathEcCustomSecSecT113Field_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleMathEcCustomSecSecT113Field, init)
}

LibOrgBouncycastleMathEcCustomSecSecT113Field *create_LibOrgBouncycastleMathEcCustomSecSecT113Field_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleMathEcCustomSecSecT113Field, init)
}

void LibOrgBouncycastleMathEcCustomSecSecT113Field_addWithLongArray_withLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *y, IOSLongArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecT113Field_initialize();
  *IOSLongArray_GetRef(nil_chk(z), 0) = IOSLongArray_Get(nil_chk(x), 0) ^ IOSLongArray_Get(nil_chk(y), 0);
  *IOSLongArray_GetRef(z, 1) = IOSLongArray_Get(x, 1) ^ IOSLongArray_Get(y, 1);
}

void LibOrgBouncycastleMathEcCustomSecSecT113Field_addExtWithLongArray_withLongArray_withLongArray_(IOSLongArray *xx, IOSLongArray *yy, IOSLongArray *zz) {
  LibOrgBouncycastleMathEcCustomSecSecT113Field_initialize();
  *IOSLongArray_GetRef(nil_chk(zz), 0) = IOSLongArray_Get(nil_chk(xx), 0) ^ IOSLongArray_Get(nil_chk(yy), 0);
  *IOSLongArray_GetRef(zz, 1) = IOSLongArray_Get(xx, 1) ^ IOSLongArray_Get(yy, 1);
  *IOSLongArray_GetRef(zz, 2) = IOSLongArray_Get(xx, 2) ^ IOSLongArray_Get(yy, 2);
  *IOSLongArray_GetRef(zz, 3) = IOSLongArray_Get(xx, 3) ^ IOSLongArray_Get(yy, 3);
}

void LibOrgBouncycastleMathEcCustomSecSecT113Field_addOneWithLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecT113Field_initialize();
  *IOSLongArray_GetRef(nil_chk(z), 0) = IOSLongArray_Get(nil_chk(x), 0) ^ 1LL;
  *IOSLongArray_GetRef(z, 1) = IOSLongArray_Get(x, 1);
}

IOSLongArray *LibOrgBouncycastleMathEcCustomSecSecT113Field_fromBigIntegerWithJavaMathBigInteger_(JavaMathBigInteger *x) {
  LibOrgBouncycastleMathEcCustomSecSecT113Field_initialize();
  IOSLongArray *z = LibOrgBouncycastleMathRawNat128_fromBigInteger64WithJavaMathBigInteger_(x);
  LibOrgBouncycastleMathEcCustomSecSecT113Field_reduce15WithLongArray_withInt_(z, 0);
  return z;
}

void LibOrgBouncycastleMathEcCustomSecSecT113Field_invertWithLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecT113Field_initialize();
  if (LibOrgBouncycastleMathRawNat128_isZero64WithLongArray_(x)) {
    @throw new_JavaLangIllegalStateException_init();
  }
  IOSLongArray *t0 = LibOrgBouncycastleMathRawNat128_create64();
  IOSLongArray *t1 = LibOrgBouncycastleMathRawNat128_create64();
  LibOrgBouncycastleMathEcCustomSecSecT113Field_squareWithLongArray_withLongArray_(x, t0);
  LibOrgBouncycastleMathEcCustomSecSecT113Field_multiplyWithLongArray_withLongArray_withLongArray_(t0, x, t0);
  LibOrgBouncycastleMathEcCustomSecSecT113Field_squareWithLongArray_withLongArray_(t0, t0);
  LibOrgBouncycastleMathEcCustomSecSecT113Field_multiplyWithLongArray_withLongArray_withLongArray_(t0, x, t0);
  LibOrgBouncycastleMathEcCustomSecSecT113Field_squareNWithLongArray_withInt_withLongArray_(t0, 3, t1);
  LibOrgBouncycastleMathEcCustomSecSecT113Field_multiplyWithLongArray_withLongArray_withLongArray_(t1, t0, t1);
  LibOrgBouncycastleMathEcCustomSecSecT113Field_squareWithLongArray_withLongArray_(t1, t1);
  LibOrgBouncycastleMathEcCustomSecSecT113Field_multiplyWithLongArray_withLongArray_withLongArray_(t1, x, t1);
  LibOrgBouncycastleMathEcCustomSecSecT113Field_squareNWithLongArray_withInt_withLongArray_(t1, 7, t0);
  LibOrgBouncycastleMathEcCustomSecSecT113Field_multiplyWithLongArray_withLongArray_withLongArray_(t0, t1, t0);
  LibOrgBouncycastleMathEcCustomSecSecT113Field_squareNWithLongArray_withInt_withLongArray_(t0, 14, t1);
  LibOrgBouncycastleMathEcCustomSecSecT113Field_multiplyWithLongArray_withLongArray_withLongArray_(t1, t0, t1);
  LibOrgBouncycastleMathEcCustomSecSecT113Field_squareNWithLongArray_withInt_withLongArray_(t1, 28, t0);
  LibOrgBouncycastleMathEcCustomSecSecT113Field_multiplyWithLongArray_withLongArray_withLongArray_(t0, t1, t0);
  LibOrgBouncycastleMathEcCustomSecSecT113Field_squareNWithLongArray_withInt_withLongArray_(t0, 56, t1);
  LibOrgBouncycastleMathEcCustomSecSecT113Field_multiplyWithLongArray_withLongArray_withLongArray_(t1, t0, t1);
  LibOrgBouncycastleMathEcCustomSecSecT113Field_squareWithLongArray_withLongArray_(t1, z);
}

void LibOrgBouncycastleMathEcCustomSecSecT113Field_multiplyWithLongArray_withLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *y, IOSLongArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecT113Field_initialize();
  IOSLongArray *tt = LibOrgBouncycastleMathRawNat128_createExt64();
  LibOrgBouncycastleMathEcCustomSecSecT113Field_implMultiplyWithLongArray_withLongArray_withLongArray_(x, y, tt);
  LibOrgBouncycastleMathEcCustomSecSecT113Field_reduceWithLongArray_withLongArray_(tt, z);
}

void LibOrgBouncycastleMathEcCustomSecSecT113Field_multiplyAddToExtWithLongArray_withLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *y, IOSLongArray *zz) {
  LibOrgBouncycastleMathEcCustomSecSecT113Field_initialize();
  IOSLongArray *tt = LibOrgBouncycastleMathRawNat128_createExt64();
  LibOrgBouncycastleMathEcCustomSecSecT113Field_implMultiplyWithLongArray_withLongArray_withLongArray_(x, y, tt);
  LibOrgBouncycastleMathEcCustomSecSecT113Field_addExtWithLongArray_withLongArray_withLongArray_(zz, tt, zz);
}

void LibOrgBouncycastleMathEcCustomSecSecT113Field_reduceWithLongArray_withLongArray_(IOSLongArray *xx, IOSLongArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecT113Field_initialize();
  jlong x0 = IOSLongArray_Get(nil_chk(xx), 0);
  jlong x1 = IOSLongArray_Get(xx, 1);
  jlong x2 = IOSLongArray_Get(xx, 2);
  jlong x3 = IOSLongArray_Get(xx, 3);
  x1 ^= (JreLShift64(x3, 15)) ^ (JreLShift64(x3, 24));
  x2 ^= (JreURShift64(x3, 49)) ^ (JreURShift64(x3, 40));
  x0 ^= (JreLShift64(x2, 15)) ^ (JreLShift64(x2, 24));
  x1 ^= (JreURShift64(x2, 49)) ^ (JreURShift64(x2, 40));
  jlong t = JreURShift64(x1, 49);
  *IOSLongArray_GetRef(nil_chk(z), 0) = x0 ^ t ^ (JreLShift64(t, 9));
  *IOSLongArray_GetRef(z, 1) = x1 & LibOrgBouncycastleMathEcCustomSecSecT113Field_M49;
}

void LibOrgBouncycastleMathEcCustomSecSecT113Field_reduce15WithLongArray_withInt_(IOSLongArray *z, jint zOff) {
  LibOrgBouncycastleMathEcCustomSecSecT113Field_initialize();
  jlong z1 = IOSLongArray_Get(nil_chk(z), zOff + 1);
  jlong t = JreURShift64(z1, 49);
  *IOSLongArray_GetRef(z, zOff) ^= t ^ (JreLShift64(t, 9));
  *IOSLongArray_GetRef(z, zOff + 1) = z1 & LibOrgBouncycastleMathEcCustomSecSecT113Field_M49;
}

void LibOrgBouncycastleMathEcCustomSecSecT113Field_sqrtWithLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecT113Field_initialize();
  jlong u0 = LibOrgBouncycastleMathRawInterleave_unshuffleWithLong_(IOSLongArray_Get(nil_chk(x), 0));
  jlong u1 = LibOrgBouncycastleMathRawInterleave_unshuffleWithLong_(IOSLongArray_Get(x, 1));
  jlong e0 = (u0 & (jlong) 0x00000000FFFFFFFFLL) | (JreLShift64(u1, 32));
  jlong c0 = (JreURShift64(u0, 32)) | (u1 & (jlong) 0xFFFFFFFF00000000LL);
  *IOSLongArray_GetRef(nil_chk(z), 0) = e0 ^ (JreLShift64(c0, 57)) ^ (JreLShift64(c0, 5));
  *IOSLongArray_GetRef(z, 1) = (JreURShift64(c0, 7)) ^ (JreURShift64(c0, 59));
}

void LibOrgBouncycastleMathEcCustomSecSecT113Field_squareWithLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecT113Field_initialize();
  IOSLongArray *tt = LibOrgBouncycastleMathRawNat128_createExt64();
  LibOrgBouncycastleMathEcCustomSecSecT113Field_implSquareWithLongArray_withLongArray_(x, tt);
  LibOrgBouncycastleMathEcCustomSecSecT113Field_reduceWithLongArray_withLongArray_(tt, z);
}

void LibOrgBouncycastleMathEcCustomSecSecT113Field_squareAddToExtWithLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *zz) {
  LibOrgBouncycastleMathEcCustomSecSecT113Field_initialize();
  IOSLongArray *tt = LibOrgBouncycastleMathRawNat128_createExt64();
  LibOrgBouncycastleMathEcCustomSecSecT113Field_implSquareWithLongArray_withLongArray_(x, tt);
  LibOrgBouncycastleMathEcCustomSecSecT113Field_addExtWithLongArray_withLongArray_withLongArray_(zz, tt, zz);
}

void LibOrgBouncycastleMathEcCustomSecSecT113Field_squareNWithLongArray_withInt_withLongArray_(IOSLongArray *x, jint n, IOSLongArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecT113Field_initialize();
  IOSLongArray *tt = LibOrgBouncycastleMathRawNat128_createExt64();
  LibOrgBouncycastleMathEcCustomSecSecT113Field_implSquareWithLongArray_withLongArray_(x, tt);
  LibOrgBouncycastleMathEcCustomSecSecT113Field_reduceWithLongArray_withLongArray_(tt, z);
  while (--n > 0) {
    LibOrgBouncycastleMathEcCustomSecSecT113Field_implSquareWithLongArray_withLongArray_(z, tt);
    LibOrgBouncycastleMathEcCustomSecSecT113Field_reduceWithLongArray_withLongArray_(tt, z);
  }
}

jint LibOrgBouncycastleMathEcCustomSecSecT113Field_traceWithLongArray_(IOSLongArray *x) {
  LibOrgBouncycastleMathEcCustomSecSecT113Field_initialize();
  return (jint) (IOSLongArray_Get(nil_chk(x), 0)) & 1;
}

void LibOrgBouncycastleMathEcCustomSecSecT113Field_implMultiplyWithLongArray_withLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *y, IOSLongArray *zz) {
  LibOrgBouncycastleMathEcCustomSecSecT113Field_initialize();
  jlong f0 = IOSLongArray_Get(nil_chk(x), 0);
  jlong f1 = IOSLongArray_Get(x, 1);
  f1 = ((JreURShift64(f0, 57)) ^ (JreLShift64(f1, 7))) & LibOrgBouncycastleMathEcCustomSecSecT113Field_M57;
  f0 &= LibOrgBouncycastleMathEcCustomSecSecT113Field_M57;
  jlong g0 = IOSLongArray_Get(nil_chk(y), 0);
  jlong g1 = IOSLongArray_Get(y, 1);
  g1 = ((JreURShift64(g0, 57)) ^ (JreLShift64(g1, 7))) & LibOrgBouncycastleMathEcCustomSecSecT113Field_M57;
  g0 &= LibOrgBouncycastleMathEcCustomSecSecT113Field_M57;
  IOSLongArray *H = [IOSLongArray newArrayWithLength:6];
  LibOrgBouncycastleMathEcCustomSecSecT113Field_implMulwWithLong_withLong_withLongArray_withInt_(f0, g0, H, 0);
  LibOrgBouncycastleMathEcCustomSecSecT113Field_implMulwWithLong_withLong_withLongArray_withInt_(f1, g1, H, 2);
  LibOrgBouncycastleMathEcCustomSecSecT113Field_implMulwWithLong_withLong_withLongArray_withInt_(f0 ^ f1, g0 ^ g1, H, 4);
  jlong r = IOSLongArray_Get(H, 1) ^ IOSLongArray_Get(H, 2);
  jlong z0 = IOSLongArray_Get(H, 0);
  jlong z3 = IOSLongArray_Get(H, 3);
  jlong z1 = IOSLongArray_Get(H, 4) ^ z0 ^ r;
  jlong z2 = IOSLongArray_Get(H, 5) ^ z3 ^ r;
  *IOSLongArray_GetRef(nil_chk(zz), 0) = z0 ^ (JreLShift64(z1, 57));
  *IOSLongArray_GetRef(zz, 1) = (JreURShift64(z1, 7)) ^ (JreLShift64(z2, 50));
  *IOSLongArray_GetRef(zz, 2) = (JreURShift64(z2, 14)) ^ (JreLShift64(z3, 43));
  *IOSLongArray_GetRef(zz, 3) = (JreURShift64(z3, 21));
}

void LibOrgBouncycastleMathEcCustomSecSecT113Field_implMulwWithLong_withLong_withLongArray_withInt_(jlong x, jlong y, IOSLongArray *z, jint zOff) {
  LibOrgBouncycastleMathEcCustomSecSecT113Field_initialize();
  IOSLongArray *u = [IOSLongArray newArrayWithLength:8];
  *IOSLongArray_GetRef(u, 1) = y;
  *IOSLongArray_GetRef(u, 2) = JreLShift64(IOSLongArray_Get(u, 1), 1);
  *IOSLongArray_GetRef(u, 3) = IOSLongArray_Get(u, 2) ^ y;
  *IOSLongArray_GetRef(u, 4) = JreLShift64(IOSLongArray_Get(u, 2), 1);
  *IOSLongArray_GetRef(u, 5) = IOSLongArray_Get(u, 4) ^ y;
  *IOSLongArray_GetRef(u, 6) = JreLShift64(IOSLongArray_Get(u, 3), 1);
  *IOSLongArray_GetRef(u, 7) = IOSLongArray_Get(u, 6) ^ y;
  jint j = (jint) x;
  jlong g;
  jlong h = 0;
  jlong l = IOSLongArray_Get(u, j & 7);
  jint k = 48;
  do {
    j = (jint) (JreURShift64(x, k));
    g = IOSLongArray_Get(u, j & 7) ^ JreLShift64(IOSLongArray_Get(u, (JreURShift32(j, 3)) & 7), 3) ^ JreLShift64(IOSLongArray_Get(u, (JreURShift32(j, 6)) & 7), 6);
    l ^= (JreLShift64(g, k));
    h ^= (JreURShift64(g, -k));
  }
  while ((k -= 9) > 0);
  h ^= JreURShift64(((x & (jlong) 0x0100804020100800LL) & (JreRShift64((JreLShift64(y, 7)), 63))), 8);
  *IOSLongArray_GetRef(nil_chk(z), zOff) = l & LibOrgBouncycastleMathEcCustomSecSecT113Field_M57;
  *IOSLongArray_GetRef(z, zOff + 1) = (JreURShift64(l, 57)) ^ (JreLShift64(h, 7));
}

void LibOrgBouncycastleMathEcCustomSecSecT113Field_implSquareWithLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *zz) {
  LibOrgBouncycastleMathEcCustomSecSecT113Field_initialize();
  LibOrgBouncycastleMathRawInterleave_expand64To128WithLong_withLongArray_withInt_(IOSLongArray_Get(nil_chk(x), 0), zz, 0);
  LibOrgBouncycastleMathRawInterleave_expand64To128WithLong_withLongArray_withInt_(IOSLongArray_Get(x, 1), zz, 2);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleMathEcCustomSecSecT113Field)
