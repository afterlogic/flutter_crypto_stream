//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/math/ec/custom/sec/SecT131Field.java
//

#include "IOSPrimitiveArray.h"
#include "Interleave.h"
#include "J2ObjC_source.h"
#include "Nat.h"
#include "Nat192.h"
#include "SecT131Field.h"
#include "java/lang/IllegalStateException.h"
#include "java/math/BigInteger.h"

inline jlong LibOrgBouncycastleMathEcCustomSecSecT131Field_get_M03(void);
#define LibOrgBouncycastleMathEcCustomSecSecT131Field_M03 7LL
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleMathEcCustomSecSecT131Field, M03, jlong)

inline jlong LibOrgBouncycastleMathEcCustomSecSecT131Field_get_M44(void);
#define LibOrgBouncycastleMathEcCustomSecSecT131Field_M44 17592186044415LL
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleMathEcCustomSecSecT131Field, M44, jlong)

inline IOSLongArray *LibOrgBouncycastleMathEcCustomSecSecT131Field_get_ROOT_Z(void);
static IOSLongArray *LibOrgBouncycastleMathEcCustomSecSecT131Field_ROOT_Z;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleMathEcCustomSecSecT131Field, ROOT_Z, IOSLongArray *)

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleMathEcCustomSecSecT131Field)

@implementation LibOrgBouncycastleMathEcCustomSecSecT131Field

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleMathEcCustomSecSecT131Field_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (void)addWithLongArray:(IOSLongArray *)x
           withLongArray:(IOSLongArray *)y
           withLongArray:(IOSLongArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecT131Field_addWithLongArray_withLongArray_withLongArray_(x, y, z);
}

+ (void)addExtWithLongArray:(IOSLongArray *)xx
              withLongArray:(IOSLongArray *)yy
              withLongArray:(IOSLongArray *)zz {
  LibOrgBouncycastleMathEcCustomSecSecT131Field_addExtWithLongArray_withLongArray_withLongArray_(xx, yy, zz);
}

+ (void)addOneWithLongArray:(IOSLongArray *)x
              withLongArray:(IOSLongArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecT131Field_addOneWithLongArray_withLongArray_(x, z);
}

+ (IOSLongArray *)fromBigIntegerWithJavaMathBigInteger:(JavaMathBigInteger *)x {
  return LibOrgBouncycastleMathEcCustomSecSecT131Field_fromBigIntegerWithJavaMathBigInteger_(x);
}

+ (void)invertWithLongArray:(IOSLongArray *)x
              withLongArray:(IOSLongArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecT131Field_invertWithLongArray_withLongArray_(x, z);
}

+ (void)multiplyWithLongArray:(IOSLongArray *)x
                withLongArray:(IOSLongArray *)y
                withLongArray:(IOSLongArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecT131Field_multiplyWithLongArray_withLongArray_withLongArray_(x, y, z);
}

+ (void)multiplyAddToExtWithLongArray:(IOSLongArray *)x
                        withLongArray:(IOSLongArray *)y
                        withLongArray:(IOSLongArray *)zz {
  LibOrgBouncycastleMathEcCustomSecSecT131Field_multiplyAddToExtWithLongArray_withLongArray_withLongArray_(x, y, zz);
}

+ (void)reduceWithLongArray:(IOSLongArray *)xx
              withLongArray:(IOSLongArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecT131Field_reduceWithLongArray_withLongArray_(xx, z);
}

+ (void)reduce61WithLongArray:(IOSLongArray *)z
                      withInt:(jint)zOff {
  LibOrgBouncycastleMathEcCustomSecSecT131Field_reduce61WithLongArray_withInt_(z, zOff);
}

+ (void)sqrtWithLongArray:(IOSLongArray *)x
            withLongArray:(IOSLongArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecT131Field_sqrtWithLongArray_withLongArray_(x, z);
}

+ (void)squareWithLongArray:(IOSLongArray *)x
              withLongArray:(IOSLongArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecT131Field_squareWithLongArray_withLongArray_(x, z);
}

+ (void)squareAddToExtWithLongArray:(IOSLongArray *)x
                      withLongArray:(IOSLongArray *)zz {
  LibOrgBouncycastleMathEcCustomSecSecT131Field_squareAddToExtWithLongArray_withLongArray_(x, zz);
}

+ (void)squareNWithLongArray:(IOSLongArray *)x
                     withInt:(jint)n
               withLongArray:(IOSLongArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecT131Field_squareNWithLongArray_withInt_withLongArray_(x, n, z);
}

+ (jint)traceWithLongArray:(IOSLongArray *)x {
  return LibOrgBouncycastleMathEcCustomSecSecT131Field_traceWithLongArray_(x);
}

+ (void)implCompactExtWithLongArray:(IOSLongArray *)zz {
  LibOrgBouncycastleMathEcCustomSecSecT131Field_implCompactExtWithLongArray_(zz);
}

+ (void)implMultiplyWithLongArray:(IOSLongArray *)x
                    withLongArray:(IOSLongArray *)y
                    withLongArray:(IOSLongArray *)zz {
  LibOrgBouncycastleMathEcCustomSecSecT131Field_implMultiplyWithLongArray_withLongArray_withLongArray_(x, y, zz);
}

+ (void)implMulwWithLong:(jlong)x
                withLong:(jlong)y
           withLongArray:(IOSLongArray *)z
                 withInt:(jint)zOff {
  LibOrgBouncycastleMathEcCustomSecSecT131Field_implMulwWithLong_withLong_withLongArray_withInt_(x, y, z, zOff);
}

+ (void)implSquareWithLongArray:(IOSLongArray *)x
                  withLongArray:(IOSLongArray *)zz {
  LibOrgBouncycastleMathEcCustomSecSecT131Field_implSquareWithLongArray_withLongArray_(x, zz);
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
    { NULL, "V", 0xc, 20, 19, -1, -1, -1, -1 },
    { NULL, "V", 0xc, 21, 1, -1, -1, -1, -1 },
    { NULL, "V", 0xc, 22, 23, -1, -1, -1, -1 },
    { NULL, "V", 0xc, 24, 4, -1, -1, -1, -1 },
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
  methods[9].selector = @selector(reduce61WithLongArray:withInt:);
  methods[10].selector = @selector(sqrtWithLongArray:withLongArray:);
  methods[11].selector = @selector(squareWithLongArray:withLongArray:);
  methods[12].selector = @selector(squareAddToExtWithLongArray:withLongArray:);
  methods[13].selector = @selector(squareNWithLongArray:withInt:withLongArray:);
  methods[14].selector = @selector(traceWithLongArray:);
  methods[15].selector = @selector(implCompactExtWithLongArray:);
  methods[16].selector = @selector(implMultiplyWithLongArray:withLongArray:withLongArray:);
  methods[17].selector = @selector(implMulwWithLong:withLong:withLongArray:withInt:);
  methods[18].selector = @selector(implSquareWithLongArray:withLongArray:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "M03", "J", .constantValue.asLong = LibOrgBouncycastleMathEcCustomSecSecT131Field_M03, 0x1a, -1, -1, -1, -1 },
    { "M44", "J", .constantValue.asLong = LibOrgBouncycastleMathEcCustomSecSecT131Field_M44, 0x1a, -1, -1, -1, -1 },
    { "ROOT_Z", "[J", .constantValue.asLong = 0, 0x1a, -1, 25, -1, -1 },
  };
  static const void *ptrTable[] = { "add", "[J[J[J", "addExt", "addOne", "[J[J", "fromBigInteger", "LJavaMathBigInteger;", "invert", "multiply", "multiplyAddToExt", "reduce", "reduce61", "[JI", "sqrt", "square", "squareAddToExt", "squareN", "[JI[J", "trace", "[J", "implCompactExt", "implMultiply", "implMulw", "JJ[JI", "implSquare", &LibOrgBouncycastleMathEcCustomSecSecT131Field_ROOT_Z };
  static const J2ObjcClassInfo _LibOrgBouncycastleMathEcCustomSecSecT131Field = { "SecT131Field", "lib.org.bouncycastle.math.ec.custom.sec", ptrTable, methods, fields, 7, 0x1, 19, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleMathEcCustomSecSecT131Field;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleMathEcCustomSecSecT131Field class]) {
    LibOrgBouncycastleMathEcCustomSecSecT131Field_ROOT_Z = [IOSLongArray newArrayWithLongs:(jlong[]){ (jlong) 0x26BC4D789AF13523LL, (jlong) 0x26BC4D789AF135E2LL, (jlong) 0x6LL } count:3];
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleMathEcCustomSecSecT131Field)
  }
}

@end

void LibOrgBouncycastleMathEcCustomSecSecT131Field_init(LibOrgBouncycastleMathEcCustomSecSecT131Field *self) {
  NSObject_init(self);
}

LibOrgBouncycastleMathEcCustomSecSecT131Field *new_LibOrgBouncycastleMathEcCustomSecSecT131Field_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleMathEcCustomSecSecT131Field, init)
}

LibOrgBouncycastleMathEcCustomSecSecT131Field *create_LibOrgBouncycastleMathEcCustomSecSecT131Field_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleMathEcCustomSecSecT131Field, init)
}

void LibOrgBouncycastleMathEcCustomSecSecT131Field_addWithLongArray_withLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *y, IOSLongArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecT131Field_initialize();
  *IOSLongArray_GetRef(nil_chk(z), 0) = IOSLongArray_Get(nil_chk(x), 0) ^ IOSLongArray_Get(nil_chk(y), 0);
  *IOSLongArray_GetRef(z, 1) = IOSLongArray_Get(x, 1) ^ IOSLongArray_Get(y, 1);
  *IOSLongArray_GetRef(z, 2) = IOSLongArray_Get(x, 2) ^ IOSLongArray_Get(y, 2);
}

void LibOrgBouncycastleMathEcCustomSecSecT131Field_addExtWithLongArray_withLongArray_withLongArray_(IOSLongArray *xx, IOSLongArray *yy, IOSLongArray *zz) {
  LibOrgBouncycastleMathEcCustomSecSecT131Field_initialize();
  *IOSLongArray_GetRef(nil_chk(zz), 0) = IOSLongArray_Get(nil_chk(xx), 0) ^ IOSLongArray_Get(nil_chk(yy), 0);
  *IOSLongArray_GetRef(zz, 1) = IOSLongArray_Get(xx, 1) ^ IOSLongArray_Get(yy, 1);
  *IOSLongArray_GetRef(zz, 2) = IOSLongArray_Get(xx, 2) ^ IOSLongArray_Get(yy, 2);
  *IOSLongArray_GetRef(zz, 3) = IOSLongArray_Get(xx, 3) ^ IOSLongArray_Get(yy, 3);
  *IOSLongArray_GetRef(zz, 4) = IOSLongArray_Get(xx, 4) ^ IOSLongArray_Get(yy, 4);
}

void LibOrgBouncycastleMathEcCustomSecSecT131Field_addOneWithLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecT131Field_initialize();
  *IOSLongArray_GetRef(nil_chk(z), 0) = IOSLongArray_Get(nil_chk(x), 0) ^ 1LL;
  *IOSLongArray_GetRef(z, 1) = IOSLongArray_Get(x, 1);
  *IOSLongArray_GetRef(z, 2) = IOSLongArray_Get(x, 2);
}

IOSLongArray *LibOrgBouncycastleMathEcCustomSecSecT131Field_fromBigIntegerWithJavaMathBigInteger_(JavaMathBigInteger *x) {
  LibOrgBouncycastleMathEcCustomSecSecT131Field_initialize();
  IOSLongArray *z = LibOrgBouncycastleMathRawNat192_fromBigInteger64WithJavaMathBigInteger_(x);
  LibOrgBouncycastleMathEcCustomSecSecT131Field_reduce61WithLongArray_withInt_(z, 0);
  return z;
}

void LibOrgBouncycastleMathEcCustomSecSecT131Field_invertWithLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecT131Field_initialize();
  if (LibOrgBouncycastleMathRawNat192_isZero64WithLongArray_(x)) {
    @throw new_JavaLangIllegalStateException_init();
  }
  IOSLongArray *t0 = LibOrgBouncycastleMathRawNat192_create64();
  IOSLongArray *t1 = LibOrgBouncycastleMathRawNat192_create64();
  LibOrgBouncycastleMathEcCustomSecSecT131Field_squareWithLongArray_withLongArray_(x, t0);
  LibOrgBouncycastleMathEcCustomSecSecT131Field_multiplyWithLongArray_withLongArray_withLongArray_(t0, x, t0);
  LibOrgBouncycastleMathEcCustomSecSecT131Field_squareNWithLongArray_withInt_withLongArray_(t0, 2, t1);
  LibOrgBouncycastleMathEcCustomSecSecT131Field_multiplyWithLongArray_withLongArray_withLongArray_(t1, t0, t1);
  LibOrgBouncycastleMathEcCustomSecSecT131Field_squareNWithLongArray_withInt_withLongArray_(t1, 4, t0);
  LibOrgBouncycastleMathEcCustomSecSecT131Field_multiplyWithLongArray_withLongArray_withLongArray_(t0, t1, t0);
  LibOrgBouncycastleMathEcCustomSecSecT131Field_squareNWithLongArray_withInt_withLongArray_(t0, 8, t1);
  LibOrgBouncycastleMathEcCustomSecSecT131Field_multiplyWithLongArray_withLongArray_withLongArray_(t1, t0, t1);
  LibOrgBouncycastleMathEcCustomSecSecT131Field_squareNWithLongArray_withInt_withLongArray_(t1, 16, t0);
  LibOrgBouncycastleMathEcCustomSecSecT131Field_multiplyWithLongArray_withLongArray_withLongArray_(t0, t1, t0);
  LibOrgBouncycastleMathEcCustomSecSecT131Field_squareNWithLongArray_withInt_withLongArray_(t0, 32, t1);
  LibOrgBouncycastleMathEcCustomSecSecT131Field_multiplyWithLongArray_withLongArray_withLongArray_(t1, t0, t1);
  LibOrgBouncycastleMathEcCustomSecSecT131Field_squareWithLongArray_withLongArray_(t1, t1);
  LibOrgBouncycastleMathEcCustomSecSecT131Field_multiplyWithLongArray_withLongArray_withLongArray_(t1, x, t1);
  LibOrgBouncycastleMathEcCustomSecSecT131Field_squareNWithLongArray_withInt_withLongArray_(t1, 65, t0);
  LibOrgBouncycastleMathEcCustomSecSecT131Field_multiplyWithLongArray_withLongArray_withLongArray_(t0, t1, t0);
  LibOrgBouncycastleMathEcCustomSecSecT131Field_squareWithLongArray_withLongArray_(t0, z);
}

void LibOrgBouncycastleMathEcCustomSecSecT131Field_multiplyWithLongArray_withLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *y, IOSLongArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecT131Field_initialize();
  IOSLongArray *tt = LibOrgBouncycastleMathRawNat192_createExt64();
  LibOrgBouncycastleMathEcCustomSecSecT131Field_implMultiplyWithLongArray_withLongArray_withLongArray_(x, y, tt);
  LibOrgBouncycastleMathEcCustomSecSecT131Field_reduceWithLongArray_withLongArray_(tt, z);
}

void LibOrgBouncycastleMathEcCustomSecSecT131Field_multiplyAddToExtWithLongArray_withLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *y, IOSLongArray *zz) {
  LibOrgBouncycastleMathEcCustomSecSecT131Field_initialize();
  IOSLongArray *tt = LibOrgBouncycastleMathRawNat192_createExt64();
  LibOrgBouncycastleMathEcCustomSecSecT131Field_implMultiplyWithLongArray_withLongArray_withLongArray_(x, y, tt);
  LibOrgBouncycastleMathEcCustomSecSecT131Field_addExtWithLongArray_withLongArray_withLongArray_(zz, tt, zz);
}

void LibOrgBouncycastleMathEcCustomSecSecT131Field_reduceWithLongArray_withLongArray_(IOSLongArray *xx, IOSLongArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecT131Field_initialize();
  jlong x0 = IOSLongArray_Get(nil_chk(xx), 0);
  jlong x1 = IOSLongArray_Get(xx, 1);
  jlong x2 = IOSLongArray_Get(xx, 2);
  jlong x3 = IOSLongArray_Get(xx, 3);
  jlong x4 = IOSLongArray_Get(xx, 4);
  x1 ^= (JreLShift64(x4, 61)) ^ (JreLShift64(x4, 63));
  x2 ^= (JreURShift64(x4, 3)) ^ (JreURShift64(x4, 1)) ^ x4 ^ (JreLShift64(x4, 5));
  x3 ^= (JreURShift64(x4, 59));
  x0 ^= (JreLShift64(x3, 61)) ^ (JreLShift64(x3, 63));
  x1 ^= (JreURShift64(x3, 3)) ^ (JreURShift64(x3, 1)) ^ x3 ^ (JreLShift64(x3, 5));
  x2 ^= (JreURShift64(x3, 59));
  jlong t = JreURShift64(x2, 3);
  *IOSLongArray_GetRef(nil_chk(z), 0) = x0 ^ t ^ (JreLShift64(t, 2)) ^ (JreLShift64(t, 3)) ^ (JreLShift64(t, 8));
  *IOSLongArray_GetRef(z, 1) = x1 ^ (JreURShift64(t, 56));
  *IOSLongArray_GetRef(z, 2) = x2 & LibOrgBouncycastleMathEcCustomSecSecT131Field_M03;
}

void LibOrgBouncycastleMathEcCustomSecSecT131Field_reduce61WithLongArray_withInt_(IOSLongArray *z, jint zOff) {
  LibOrgBouncycastleMathEcCustomSecSecT131Field_initialize();
  jlong z2 = IOSLongArray_Get(nil_chk(z), zOff + 2);
  jlong t = JreURShift64(z2, 3);
  *IOSLongArray_GetRef(z, zOff) ^= t ^ (JreLShift64(t, 2)) ^ (JreLShift64(t, 3)) ^ (JreLShift64(t, 8));
  *IOSLongArray_GetRef(z, zOff + 1) ^= (JreURShift64(t, 56));
  *IOSLongArray_GetRef(z, zOff + 2) = z2 & LibOrgBouncycastleMathEcCustomSecSecT131Field_M03;
}

void LibOrgBouncycastleMathEcCustomSecSecT131Field_sqrtWithLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecT131Field_initialize();
  IOSLongArray *odd = LibOrgBouncycastleMathRawNat192_create64();
  jlong u0;
  jlong u1;
  u0 = LibOrgBouncycastleMathRawInterleave_unshuffleWithLong_(IOSLongArray_Get(nil_chk(x), 0));
  u1 = LibOrgBouncycastleMathRawInterleave_unshuffleWithLong_(IOSLongArray_Get(x, 1));
  jlong e0 = (u0 & (jlong) 0x00000000FFFFFFFFLL) | (JreLShift64(u1, 32));
  *IOSLongArray_GetRef(nil_chk(odd), 0) = (JreURShift64(u0, 32)) | (u1 & (jlong) 0xFFFFFFFF00000000LL);
  u0 = LibOrgBouncycastleMathRawInterleave_unshuffleWithLong_(IOSLongArray_Get(x, 2));
  jlong e1 = (u0 & (jlong) 0x00000000FFFFFFFFLL);
  *IOSLongArray_GetRef(odd, 1) = (JreURShift64(u0, 32));
  LibOrgBouncycastleMathEcCustomSecSecT131Field_multiplyWithLongArray_withLongArray_withLongArray_(odd, LibOrgBouncycastleMathEcCustomSecSecT131Field_ROOT_Z, z);
  *IOSLongArray_GetRef(nil_chk(z), 0) ^= e0;
  *IOSLongArray_GetRef(z, 1) ^= e1;
}

void LibOrgBouncycastleMathEcCustomSecSecT131Field_squareWithLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecT131Field_initialize();
  IOSLongArray *tt = LibOrgBouncycastleMathRawNat_create64WithInt_(5);
  LibOrgBouncycastleMathEcCustomSecSecT131Field_implSquareWithLongArray_withLongArray_(x, tt);
  LibOrgBouncycastleMathEcCustomSecSecT131Field_reduceWithLongArray_withLongArray_(tt, z);
}

void LibOrgBouncycastleMathEcCustomSecSecT131Field_squareAddToExtWithLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *zz) {
  LibOrgBouncycastleMathEcCustomSecSecT131Field_initialize();
  IOSLongArray *tt = LibOrgBouncycastleMathRawNat_create64WithInt_(5);
  LibOrgBouncycastleMathEcCustomSecSecT131Field_implSquareWithLongArray_withLongArray_(x, tt);
  LibOrgBouncycastleMathEcCustomSecSecT131Field_addExtWithLongArray_withLongArray_withLongArray_(zz, tt, zz);
}

void LibOrgBouncycastleMathEcCustomSecSecT131Field_squareNWithLongArray_withInt_withLongArray_(IOSLongArray *x, jint n, IOSLongArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecT131Field_initialize();
  IOSLongArray *tt = LibOrgBouncycastleMathRawNat_create64WithInt_(5);
  LibOrgBouncycastleMathEcCustomSecSecT131Field_implSquareWithLongArray_withLongArray_(x, tt);
  LibOrgBouncycastleMathEcCustomSecSecT131Field_reduceWithLongArray_withLongArray_(tt, z);
  while (--n > 0) {
    LibOrgBouncycastleMathEcCustomSecSecT131Field_implSquareWithLongArray_withLongArray_(z, tt);
    LibOrgBouncycastleMathEcCustomSecSecT131Field_reduceWithLongArray_withLongArray_(tt, z);
  }
}

jint LibOrgBouncycastleMathEcCustomSecSecT131Field_traceWithLongArray_(IOSLongArray *x) {
  LibOrgBouncycastleMathEcCustomSecSecT131Field_initialize();
  return (jint) (IOSLongArray_Get(nil_chk(x), 0) ^ (JreURShift64(IOSLongArray_Get(x, 1), 59)) ^ (JreURShift64(IOSLongArray_Get(x, 2), 1))) & 1;
}

void LibOrgBouncycastleMathEcCustomSecSecT131Field_implCompactExtWithLongArray_(IOSLongArray *zz) {
  LibOrgBouncycastleMathEcCustomSecSecT131Field_initialize();
  jlong z0 = IOSLongArray_Get(nil_chk(zz), 0);
  jlong z1 = IOSLongArray_Get(zz, 1);
  jlong z2 = IOSLongArray_Get(zz, 2);
  jlong z3 = IOSLongArray_Get(zz, 3);
  jlong z4 = IOSLongArray_Get(zz, 4);
  jlong z5 = IOSLongArray_Get(zz, 5);
  *IOSLongArray_GetRef(zz, 0) = z0 ^ (JreLShift64(z1, 44));
  *IOSLongArray_GetRef(zz, 1) = (JreURShift64(z1, 20)) ^ (JreLShift64(z2, 24));
  *IOSLongArray_GetRef(zz, 2) = (JreURShift64(z2, 40)) ^ (JreLShift64(z3, 4)) ^ (JreLShift64(z4, 48));
  *IOSLongArray_GetRef(zz, 3) = (JreURShift64(z3, 60)) ^ (JreLShift64(z5, 28)) ^ (JreURShift64(z4, 16));
  *IOSLongArray_GetRef(zz, 4) = (JreURShift64(z5, 36));
  *IOSLongArray_GetRef(zz, 5) = 0;
}

void LibOrgBouncycastleMathEcCustomSecSecT131Field_implMultiplyWithLongArray_withLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *y, IOSLongArray *zz) {
  LibOrgBouncycastleMathEcCustomSecSecT131Field_initialize();
  jlong f0 = IOSLongArray_Get(nil_chk(x), 0);
  jlong f1 = IOSLongArray_Get(x, 1);
  jlong f2 = IOSLongArray_Get(x, 2);
  f2 = ((JreURShift64(f1, 24)) ^ (JreLShift64(f2, 40))) & LibOrgBouncycastleMathEcCustomSecSecT131Field_M44;
  f1 = ((JreURShift64(f0, 44)) ^ (JreLShift64(f1, 20))) & LibOrgBouncycastleMathEcCustomSecSecT131Field_M44;
  f0 &= LibOrgBouncycastleMathEcCustomSecSecT131Field_M44;
  jlong g0 = IOSLongArray_Get(nil_chk(y), 0);
  jlong g1 = IOSLongArray_Get(y, 1);
  jlong g2 = IOSLongArray_Get(y, 2);
  g2 = ((JreURShift64(g1, 24)) ^ (JreLShift64(g2, 40))) & LibOrgBouncycastleMathEcCustomSecSecT131Field_M44;
  g1 = ((JreURShift64(g0, 44)) ^ (JreLShift64(g1, 20))) & LibOrgBouncycastleMathEcCustomSecSecT131Field_M44;
  g0 &= LibOrgBouncycastleMathEcCustomSecSecT131Field_M44;
  IOSLongArray *H = [IOSLongArray newArrayWithLength:10];
  LibOrgBouncycastleMathEcCustomSecSecT131Field_implMulwWithLong_withLong_withLongArray_withInt_(f0, g0, H, 0);
  LibOrgBouncycastleMathEcCustomSecSecT131Field_implMulwWithLong_withLong_withLongArray_withInt_(f2, g2, H, 2);
  jlong t0 = f0 ^ f1 ^ f2;
  jlong t1 = g0 ^ g1 ^ g2;
  LibOrgBouncycastleMathEcCustomSecSecT131Field_implMulwWithLong_withLong_withLongArray_withInt_(t0, t1, H, 4);
  jlong t2 = (JreLShift64(f1, 1)) ^ (JreLShift64(f2, 2));
  jlong t3 = (JreLShift64(g1, 1)) ^ (JreLShift64(g2, 2));
  LibOrgBouncycastleMathEcCustomSecSecT131Field_implMulwWithLong_withLong_withLongArray_withInt_(f0 ^ t2, g0 ^ t3, H, 6);
  LibOrgBouncycastleMathEcCustomSecSecT131Field_implMulwWithLong_withLong_withLongArray_withInt_(t0 ^ t2, t1 ^ t3, H, 8);
  jlong t4 = IOSLongArray_Get(H, 6) ^ IOSLongArray_Get(H, 8);
  jlong t5 = IOSLongArray_Get(H, 7) ^ IOSLongArray_Get(H, 9);
  jlong v0 = (JreLShift64(t4, 1)) ^ IOSLongArray_Get(H, 6);
  jlong v1 = t4 ^ (JreLShift64(t5, 1)) ^ IOSLongArray_Get(H, 7);
  jlong v2 = t5;
  jlong u0 = IOSLongArray_Get(H, 0);
  jlong u1 = IOSLongArray_Get(H, 1) ^ IOSLongArray_Get(H, 0) ^ IOSLongArray_Get(H, 4);
  jlong u2 = IOSLongArray_Get(H, 1) ^ IOSLongArray_Get(H, 5);
  jlong w0 = u0 ^ v0 ^ (JreLShift64(IOSLongArray_Get(H, 2), 4)) ^ (JreLShift64(IOSLongArray_Get(H, 2), 1));
  jlong w1 = u1 ^ v1 ^ (JreLShift64(IOSLongArray_Get(H, 3), 4)) ^ (JreLShift64(IOSLongArray_Get(H, 3), 1));
  jlong w2 = u2 ^ v2;
  w1 ^= (JreURShift64(w0, 44));
  w0 &= LibOrgBouncycastleMathEcCustomSecSecT131Field_M44;
  w2 ^= (JreURShift64(w1, 44));
  w1 &= LibOrgBouncycastleMathEcCustomSecSecT131Field_M44;
  w0 = (JreURShift64(w0, 1)) ^ (JreLShift64((w1 & 1LL), 43));
  w1 = (JreURShift64(w1, 1)) ^ (JreLShift64((w2 & 1LL), 43));
  w2 = (JreURShift64(w2, 1));
  w0 ^= (JreLShift64(w0, 1));
  w0 ^= (JreLShift64(w0, 2));
  w0 ^= (JreLShift64(w0, 4));
  w0 ^= (JreLShift64(w0, 8));
  w0 ^= (JreLShift64(w0, 16));
  w0 ^= (JreLShift64(w0, 32));
  w0 &= LibOrgBouncycastleMathEcCustomSecSecT131Field_M44;
  w1 ^= (JreURShift64(w0, 43));
  w1 ^= (JreLShift64(w1, 1));
  w1 ^= (JreLShift64(w1, 2));
  w1 ^= (JreLShift64(w1, 4));
  w1 ^= (JreLShift64(w1, 8));
  w1 ^= (JreLShift64(w1, 16));
  w1 ^= (JreLShift64(w1, 32));
  w1 &= LibOrgBouncycastleMathEcCustomSecSecT131Field_M44;
  w2 ^= (JreURShift64(w1, 43));
  w2 ^= (JreLShift64(w2, 1));
  w2 ^= (JreLShift64(w2, 2));
  w2 ^= (JreLShift64(w2, 4));
  w2 ^= (JreLShift64(w2, 8));
  w2 ^= (JreLShift64(w2, 16));
  w2 ^= (JreLShift64(w2, 32));
  *IOSLongArray_GetRef(nil_chk(zz), 0) = u0;
  *IOSLongArray_GetRef(zz, 1) = u1 ^ w0 ^ IOSLongArray_Get(H, 2);
  *IOSLongArray_GetRef(zz, 2) = u2 ^ w1 ^ w0 ^ IOSLongArray_Get(H, 3);
  *IOSLongArray_GetRef(zz, 3) = w2 ^ w1;
  *IOSLongArray_GetRef(zz, 4) = w2 ^ IOSLongArray_Get(H, 2);
  *IOSLongArray_GetRef(zz, 5) = IOSLongArray_Get(H, 3);
  LibOrgBouncycastleMathEcCustomSecSecT131Field_implCompactExtWithLongArray_(zz);
}

void LibOrgBouncycastleMathEcCustomSecSecT131Field_implMulwWithLong_withLong_withLongArray_withInt_(jlong x, jlong y, IOSLongArray *z, jint zOff) {
  LibOrgBouncycastleMathEcCustomSecSecT131Field_initialize();
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
  jlong l = IOSLongArray_Get(u, j & 7) ^ JreLShift64(IOSLongArray_Get(u, (JreURShift32(j, 3)) & 7), 3) ^ JreLShift64(IOSLongArray_Get(u, (JreURShift32(j, 6)) & 7), 6);
  jint k = 33;
  do {
    j = (jint) (JreURShift64(x, k));
    g = IOSLongArray_Get(u, j & 7) ^ JreLShift64(IOSLongArray_Get(u, (JreURShift32(j, 3)) & 7), 3) ^ JreLShift64(IOSLongArray_Get(u, (JreURShift32(j, 6)) & 7), 6) ^ JreLShift64(IOSLongArray_Get(u, (JreURShift32(j, 9)) & 7), 9);
    l ^= (JreLShift64(g, k));
    h ^= (JreURShift64(g, -k));
  }
  while ((k -= 12) > 0);
  *IOSLongArray_GetRef(nil_chk(z), zOff) = l & LibOrgBouncycastleMathEcCustomSecSecT131Field_M44;
  *IOSLongArray_GetRef(z, zOff + 1) = (JreURShift64(l, 44)) ^ (JreLShift64(h, 20));
}

void LibOrgBouncycastleMathEcCustomSecSecT131Field_implSquareWithLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *zz) {
  LibOrgBouncycastleMathEcCustomSecSecT131Field_initialize();
  LibOrgBouncycastleMathRawInterleave_expand64To128WithLong_withLongArray_withInt_(IOSLongArray_Get(nil_chk(x), 0), zz, 0);
  LibOrgBouncycastleMathRawInterleave_expand64To128WithLong_withLongArray_withInt_(IOSLongArray_Get(x, 1), zz, 2);
  *IOSLongArray_GetRef(nil_chk(zz), 4) = LibOrgBouncycastleMathRawInterleave_expand8to16WithInt_((jint) IOSLongArray_Get(x, 2)) & (jlong) 0xFFFFFFFFLL;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleMathEcCustomSecSecT131Field)
