//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/math/ec/custom/sec/SecP256R1Field.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "Nat.h"
#include "Nat256.h"
#include "SecP256R1Field.h"
#include "java/math/BigInteger.h"

@interface LibOrgBouncycastleMathEcCustomSecSecP256R1Field ()

+ (void)addPInvToWithIntArray:(IOSIntArray *)z;

+ (void)subPInvFromWithIntArray:(IOSIntArray *)z;

@end

inline jlong LibOrgBouncycastleMathEcCustomSecSecP256R1Field_get_M(void);
#define LibOrgBouncycastleMathEcCustomSecSecP256R1Field_M 4294967295LL
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleMathEcCustomSecSecP256R1Field, M, jlong)

inline jint LibOrgBouncycastleMathEcCustomSecSecP256R1Field_get_P7(void);
#define LibOrgBouncycastleMathEcCustomSecSecP256R1Field_P7 -1
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleMathEcCustomSecSecP256R1Field, P7, jint)

inline jint LibOrgBouncycastleMathEcCustomSecSecP256R1Field_get_PExt15s1(void);
#define LibOrgBouncycastleMathEcCustomSecSecP256R1Field_PExt15s1 2147483647
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleMathEcCustomSecSecP256R1Field, PExt15s1, jint)

__attribute__((unused)) static void LibOrgBouncycastleMathEcCustomSecSecP256R1Field_addPInvToWithIntArray_(IOSIntArray *z);

__attribute__((unused)) static void LibOrgBouncycastleMathEcCustomSecSecP256R1Field_subPInvFromWithIntArray_(IOSIntArray *z);

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleMathEcCustomSecSecP256R1Field)

IOSIntArray *LibOrgBouncycastleMathEcCustomSecSecP256R1Field_P;
IOSIntArray *LibOrgBouncycastleMathEcCustomSecSecP256R1Field_PExt;

@implementation LibOrgBouncycastleMathEcCustomSecSecP256R1Field

+ (IOSIntArray *)P {
  return LibOrgBouncycastleMathEcCustomSecSecP256R1Field_P;
}

+ (IOSIntArray *)PExt {
  return LibOrgBouncycastleMathEcCustomSecSecP256R1Field_PExt;
}

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleMathEcCustomSecSecP256R1Field_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (void)addWithIntArray:(IOSIntArray *)x
           withIntArray:(IOSIntArray *)y
           withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP256R1Field_addWithIntArray_withIntArray_withIntArray_(x, y, z);
}

+ (void)addExtWithIntArray:(IOSIntArray *)xx
              withIntArray:(IOSIntArray *)yy
              withIntArray:(IOSIntArray *)zz {
  LibOrgBouncycastleMathEcCustomSecSecP256R1Field_addExtWithIntArray_withIntArray_withIntArray_(xx, yy, zz);
}

+ (void)addOneWithIntArray:(IOSIntArray *)x
              withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP256R1Field_addOneWithIntArray_withIntArray_(x, z);
}

+ (IOSIntArray *)fromBigIntegerWithJavaMathBigInteger:(JavaMathBigInteger *)x {
  return LibOrgBouncycastleMathEcCustomSecSecP256R1Field_fromBigIntegerWithJavaMathBigInteger_(x);
}

+ (void)halfWithIntArray:(IOSIntArray *)x
            withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP256R1Field_halfWithIntArray_withIntArray_(x, z);
}

+ (void)multiplyWithIntArray:(IOSIntArray *)x
                withIntArray:(IOSIntArray *)y
                withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP256R1Field_multiplyWithIntArray_withIntArray_withIntArray_(x, y, z);
}

+ (void)multiplyAddToExtWithIntArray:(IOSIntArray *)x
                        withIntArray:(IOSIntArray *)y
                        withIntArray:(IOSIntArray *)zz {
  LibOrgBouncycastleMathEcCustomSecSecP256R1Field_multiplyAddToExtWithIntArray_withIntArray_withIntArray_(x, y, zz);
}

+ (void)negateWithIntArray:(IOSIntArray *)x
              withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP256R1Field_negateWithIntArray_withIntArray_(x, z);
}

+ (void)reduceWithIntArray:(IOSIntArray *)xx
              withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP256R1Field_reduceWithIntArray_withIntArray_(xx, z);
}

+ (void)reduce32WithInt:(jint)x
           withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP256R1Field_reduce32WithInt_withIntArray_(x, z);
}

+ (void)squareWithIntArray:(IOSIntArray *)x
              withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP256R1Field_squareWithIntArray_withIntArray_(x, z);
}

+ (void)squareNWithIntArray:(IOSIntArray *)x
                    withInt:(jint)n
               withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP256R1Field_squareNWithIntArray_withInt_withIntArray_(x, n, z);
}

+ (void)subtractWithIntArray:(IOSIntArray *)x
                withIntArray:(IOSIntArray *)y
                withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP256R1Field_subtractWithIntArray_withIntArray_withIntArray_(x, y, z);
}

+ (void)subtractExtWithIntArray:(IOSIntArray *)xx
                   withIntArray:(IOSIntArray *)yy
                   withIntArray:(IOSIntArray *)zz {
  LibOrgBouncycastleMathEcCustomSecSecP256R1Field_subtractExtWithIntArray_withIntArray_withIntArray_(xx, yy, zz);
}

+ (void)twiceWithIntArray:(IOSIntArray *)x
             withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP256R1Field_twiceWithIntArray_withIntArray_(x, z);
}

+ (void)addPInvToWithIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP256R1Field_addPInvToWithIntArray_(z);
}

+ (void)subPInvFromWithIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP256R1Field_subPInvFromWithIntArray_(z);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 2, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 3, 4, -1, -1, -1, -1 },
    { NULL, "[I", 0x9, 5, 6, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 7, 4, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 8, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 9, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 10, 4, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 11, 4, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 12, 13, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 14, 4, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 15, 16, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 17, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 18, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 19, 4, -1, -1, -1, -1 },
    { NULL, "V", 0xa, 20, 21, -1, -1, -1, -1 },
    { NULL, "V", 0xa, 22, 21, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(addWithIntArray:withIntArray:withIntArray:);
  methods[2].selector = @selector(addExtWithIntArray:withIntArray:withIntArray:);
  methods[3].selector = @selector(addOneWithIntArray:withIntArray:);
  methods[4].selector = @selector(fromBigIntegerWithJavaMathBigInteger:);
  methods[5].selector = @selector(halfWithIntArray:withIntArray:);
  methods[6].selector = @selector(multiplyWithIntArray:withIntArray:withIntArray:);
  methods[7].selector = @selector(multiplyAddToExtWithIntArray:withIntArray:withIntArray:);
  methods[8].selector = @selector(negateWithIntArray:withIntArray:);
  methods[9].selector = @selector(reduceWithIntArray:withIntArray:);
  methods[10].selector = @selector(reduce32WithInt:withIntArray:);
  methods[11].selector = @selector(squareWithIntArray:withIntArray:);
  methods[12].selector = @selector(squareNWithIntArray:withInt:withIntArray:);
  methods[13].selector = @selector(subtractWithIntArray:withIntArray:withIntArray:);
  methods[14].selector = @selector(subtractExtWithIntArray:withIntArray:withIntArray:);
  methods[15].selector = @selector(twiceWithIntArray:withIntArray:);
  methods[16].selector = @selector(addPInvToWithIntArray:);
  methods[17].selector = @selector(subPInvFromWithIntArray:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "M", "J", .constantValue.asLong = LibOrgBouncycastleMathEcCustomSecSecP256R1Field_M, 0x1a, -1, -1, -1, -1 },
    { "P", "[I", .constantValue.asLong = 0, 0x18, -1, 23, -1, -1 },
    { "PExt", "[I", .constantValue.asLong = 0, 0x18, -1, 24, -1, -1 },
    { "P7", "I", .constantValue.asInt = LibOrgBouncycastleMathEcCustomSecSecP256R1Field_P7, 0x1a, -1, -1, -1, -1 },
    { "PExt15s1", "I", .constantValue.asInt = LibOrgBouncycastleMathEcCustomSecSecP256R1Field_PExt15s1, 0x1a, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "add", "[I[I[I", "addExt", "addOne", "[I[I", "fromBigInteger", "LJavaMathBigInteger;", "half", "multiply", "multiplyAddToExt", "negate", "reduce", "reduce32", "I[I", "square", "squareN", "[II[I", "subtract", "subtractExt", "twice", "addPInvTo", "[I", "subPInvFrom", &LibOrgBouncycastleMathEcCustomSecSecP256R1Field_P, &LibOrgBouncycastleMathEcCustomSecSecP256R1Field_PExt };
  static const J2ObjcClassInfo _LibOrgBouncycastleMathEcCustomSecSecP256R1Field = { "SecP256R1Field", "lib.org.bouncycastle.math.ec.custom.sec", ptrTable, methods, fields, 7, 0x1, 18, 5, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleMathEcCustomSecSecP256R1Field;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleMathEcCustomSecSecP256R1Field class]) {
    LibOrgBouncycastleMathEcCustomSecSecP256R1Field_P = [IOSIntArray newArrayWithInts:(jint[]){ (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFF, (jint) 0x00000000, (jint) 0x00000000, (jint) 0x00000000, (jint) 0x00000001, (jint) 0xFFFFFFFF } count:8];
    LibOrgBouncycastleMathEcCustomSecSecP256R1Field_PExt = [IOSIntArray newArrayWithInts:(jint[]){ (jint) 0x00000001, (jint) 0x00000000, (jint) 0x00000000, (jint) 0xFFFFFFFE, (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFE, (jint) 0x00000001, (jint) 0xFFFFFFFE, (jint) 0x00000001, (jint) 0xFFFFFFFE, (jint) 0x00000001, (jint) 0x00000001, (jint) 0xFFFFFFFE, (jint) 0x00000002, (jint) 0xFFFFFFFE } count:16];
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleMathEcCustomSecSecP256R1Field)
  }
}

@end

void LibOrgBouncycastleMathEcCustomSecSecP256R1Field_init(LibOrgBouncycastleMathEcCustomSecSecP256R1Field *self) {
  NSObject_init(self);
}

LibOrgBouncycastleMathEcCustomSecSecP256R1Field *new_LibOrgBouncycastleMathEcCustomSecSecP256R1Field_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleMathEcCustomSecSecP256R1Field, init)
}

LibOrgBouncycastleMathEcCustomSecSecP256R1Field *create_LibOrgBouncycastleMathEcCustomSecSecP256R1Field_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleMathEcCustomSecSecP256R1Field, init)
}

void LibOrgBouncycastleMathEcCustomSecSecP256R1Field_addWithIntArray_withIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *y, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP256R1Field_initialize();
  jint c = LibOrgBouncycastleMathRawNat256_addWithIntArray_withIntArray_withIntArray_(x, y, z);
  if (c != 0 || (IOSIntArray_Get(nil_chk(z), 7) == LibOrgBouncycastleMathEcCustomSecSecP256R1Field_P7 && LibOrgBouncycastleMathRawNat256_gteWithIntArray_withIntArray_(z, LibOrgBouncycastleMathEcCustomSecSecP256R1Field_P))) {
    LibOrgBouncycastleMathEcCustomSecSecP256R1Field_addPInvToWithIntArray_(z);
  }
}

void LibOrgBouncycastleMathEcCustomSecSecP256R1Field_addExtWithIntArray_withIntArray_withIntArray_(IOSIntArray *xx, IOSIntArray *yy, IOSIntArray *zz) {
  LibOrgBouncycastleMathEcCustomSecSecP256R1Field_initialize();
  jint c = LibOrgBouncycastleMathRawNat_addWithInt_withIntArray_withIntArray_withIntArray_(16, xx, yy, zz);
  if (c != 0 || ((JreURShift32(IOSIntArray_Get(nil_chk(zz), 15), 1)) >= LibOrgBouncycastleMathEcCustomSecSecP256R1Field_PExt15s1 && LibOrgBouncycastleMathRawNat_gteWithInt_withIntArray_withIntArray_(16, zz, LibOrgBouncycastleMathEcCustomSecSecP256R1Field_PExt))) {
    LibOrgBouncycastleMathRawNat_subFromWithInt_withIntArray_withIntArray_(16, LibOrgBouncycastleMathEcCustomSecSecP256R1Field_PExt, zz);
  }
}

void LibOrgBouncycastleMathEcCustomSecSecP256R1Field_addOneWithIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP256R1Field_initialize();
  jint c = LibOrgBouncycastleMathRawNat_incWithInt_withIntArray_withIntArray_(8, x, z);
  if (c != 0 || (IOSIntArray_Get(nil_chk(z), 7) == LibOrgBouncycastleMathEcCustomSecSecP256R1Field_P7 && LibOrgBouncycastleMathRawNat256_gteWithIntArray_withIntArray_(z, LibOrgBouncycastleMathEcCustomSecSecP256R1Field_P))) {
    LibOrgBouncycastleMathEcCustomSecSecP256R1Field_addPInvToWithIntArray_(z);
  }
}

IOSIntArray *LibOrgBouncycastleMathEcCustomSecSecP256R1Field_fromBigIntegerWithJavaMathBigInteger_(JavaMathBigInteger *x) {
  LibOrgBouncycastleMathEcCustomSecSecP256R1Field_initialize();
  IOSIntArray *z = LibOrgBouncycastleMathRawNat256_fromBigIntegerWithJavaMathBigInteger_(x);
  if (IOSIntArray_Get(nil_chk(z), 7) == LibOrgBouncycastleMathEcCustomSecSecP256R1Field_P7 && LibOrgBouncycastleMathRawNat256_gteWithIntArray_withIntArray_(z, LibOrgBouncycastleMathEcCustomSecSecP256R1Field_P)) {
    LibOrgBouncycastleMathRawNat256_subFromWithIntArray_withIntArray_(LibOrgBouncycastleMathEcCustomSecSecP256R1Field_P, z);
  }
  return z;
}

void LibOrgBouncycastleMathEcCustomSecSecP256R1Field_halfWithIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP256R1Field_initialize();
  if ((IOSIntArray_Get(nil_chk(x), 0) & 1) == 0) {
    LibOrgBouncycastleMathRawNat_shiftDownBitWithInt_withIntArray_withInt_withIntArray_(8, x, 0, z);
  }
  else {
    jint c = LibOrgBouncycastleMathRawNat256_addWithIntArray_withIntArray_withIntArray_(x, LibOrgBouncycastleMathEcCustomSecSecP256R1Field_P, z);
    LibOrgBouncycastleMathRawNat_shiftDownBitWithInt_withIntArray_withInt_(8, z, c);
  }
}

void LibOrgBouncycastleMathEcCustomSecSecP256R1Field_multiplyWithIntArray_withIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *y, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP256R1Field_initialize();
  IOSIntArray *tt = LibOrgBouncycastleMathRawNat256_createExt();
  LibOrgBouncycastleMathRawNat256_mulWithIntArray_withIntArray_withIntArray_(x, y, tt);
  LibOrgBouncycastleMathEcCustomSecSecP256R1Field_reduceWithIntArray_withIntArray_(tt, z);
}

void LibOrgBouncycastleMathEcCustomSecSecP256R1Field_multiplyAddToExtWithIntArray_withIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *y, IOSIntArray *zz) {
  LibOrgBouncycastleMathEcCustomSecSecP256R1Field_initialize();
  jint c = LibOrgBouncycastleMathRawNat256_mulAddToWithIntArray_withIntArray_withIntArray_(x, y, zz);
  if (c != 0 || ((JreURShift32(IOSIntArray_Get(nil_chk(zz), 15), 1)) >= LibOrgBouncycastleMathEcCustomSecSecP256R1Field_PExt15s1 && LibOrgBouncycastleMathRawNat_gteWithInt_withIntArray_withIntArray_(16, zz, LibOrgBouncycastleMathEcCustomSecSecP256R1Field_PExt))) {
    LibOrgBouncycastleMathRawNat_subFromWithInt_withIntArray_withIntArray_(16, LibOrgBouncycastleMathEcCustomSecSecP256R1Field_PExt, zz);
  }
}

void LibOrgBouncycastleMathEcCustomSecSecP256R1Field_negateWithIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP256R1Field_initialize();
  if (LibOrgBouncycastleMathRawNat256_isZeroWithIntArray_(x)) {
    LibOrgBouncycastleMathRawNat256_zeroWithIntArray_(z);
  }
  else {
    LibOrgBouncycastleMathRawNat256_subWithIntArray_withIntArray_withIntArray_(LibOrgBouncycastleMathEcCustomSecSecP256R1Field_P, x, z);
  }
}

void LibOrgBouncycastleMathEcCustomSecSecP256R1Field_reduceWithIntArray_withIntArray_(IOSIntArray *xx, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP256R1Field_initialize();
  jlong xx08 = IOSIntArray_Get(nil_chk(xx), 8) & LibOrgBouncycastleMathEcCustomSecSecP256R1Field_M;
  jlong xx09 = IOSIntArray_Get(xx, 9) & LibOrgBouncycastleMathEcCustomSecSecP256R1Field_M;
  jlong xx10 = IOSIntArray_Get(xx, 10) & LibOrgBouncycastleMathEcCustomSecSecP256R1Field_M;
  jlong xx11 = IOSIntArray_Get(xx, 11) & LibOrgBouncycastleMathEcCustomSecSecP256R1Field_M;
  jlong xx12 = IOSIntArray_Get(xx, 12) & LibOrgBouncycastleMathEcCustomSecSecP256R1Field_M;
  jlong xx13 = IOSIntArray_Get(xx, 13) & LibOrgBouncycastleMathEcCustomSecSecP256R1Field_M;
  jlong xx14 = IOSIntArray_Get(xx, 14) & LibOrgBouncycastleMathEcCustomSecSecP256R1Field_M;
  jlong xx15 = IOSIntArray_Get(xx, 15) & LibOrgBouncycastleMathEcCustomSecSecP256R1Field_M;
  jlong n = 6;
  xx08 -= n;
  jlong t0 = xx08 + xx09;
  jlong t1 = xx09 + xx10;
  jlong t2 = xx10 + xx11 - xx15;
  jlong t3 = xx11 + xx12;
  jlong t4 = xx12 + xx13;
  jlong t5 = xx13 + xx14;
  jlong t6 = xx14 + xx15;
  jlong t7 = t5 - t0;
  jlong cc = 0;
  cc += (IOSIntArray_Get(xx, 0) & LibOrgBouncycastleMathEcCustomSecSecP256R1Field_M) - t3 - t7;
  *IOSIntArray_GetRef(nil_chk(z), 0) = (jint) cc;
  JreRShiftAssignLong(&cc, 32);
  cc += (IOSIntArray_Get(xx, 1) & LibOrgBouncycastleMathEcCustomSecSecP256R1Field_M) + t1 - t4 - t6;
  *IOSIntArray_GetRef(z, 1) = (jint) cc;
  JreRShiftAssignLong(&cc, 32);
  cc += (IOSIntArray_Get(xx, 2) & LibOrgBouncycastleMathEcCustomSecSecP256R1Field_M) + t2 - t5;
  *IOSIntArray_GetRef(z, 2) = (jint) cc;
  JreRShiftAssignLong(&cc, 32);
  cc += (IOSIntArray_Get(xx, 3) & LibOrgBouncycastleMathEcCustomSecSecP256R1Field_M) + (JreLShift64(t3, 1)) + t7 - t6;
  *IOSIntArray_GetRef(z, 3) = (jint) cc;
  JreRShiftAssignLong(&cc, 32);
  cc += (IOSIntArray_Get(xx, 4) & LibOrgBouncycastleMathEcCustomSecSecP256R1Field_M) + (JreLShift64(t4, 1)) + xx14 - t1;
  *IOSIntArray_GetRef(z, 4) = (jint) cc;
  JreRShiftAssignLong(&cc, 32);
  cc += (IOSIntArray_Get(xx, 5) & LibOrgBouncycastleMathEcCustomSecSecP256R1Field_M) + (JreLShift64(t5, 1)) - t2;
  *IOSIntArray_GetRef(z, 5) = (jint) cc;
  JreRShiftAssignLong(&cc, 32);
  cc += (IOSIntArray_Get(xx, 6) & LibOrgBouncycastleMathEcCustomSecSecP256R1Field_M) + (JreLShift64(t6, 1)) + t7;
  *IOSIntArray_GetRef(z, 6) = (jint) cc;
  JreRShiftAssignLong(&cc, 32);
  cc += (IOSIntArray_Get(xx, 7) & LibOrgBouncycastleMathEcCustomSecSecP256R1Field_M) + (JreLShift64(xx15, 1)) + xx08 - t2 - t4;
  *IOSIntArray_GetRef(z, 7) = (jint) cc;
  JreRShiftAssignLong(&cc, 32);
  cc += n;
  LibOrgBouncycastleMathEcCustomSecSecP256R1Field_reduce32WithInt_withIntArray_((jint) cc, z);
}

void LibOrgBouncycastleMathEcCustomSecSecP256R1Field_reduce32WithInt_withIntArray_(jint x, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP256R1Field_initialize();
  jlong cc = 0;
  if (x != 0) {
    jlong xx08 = x & LibOrgBouncycastleMathEcCustomSecSecP256R1Field_M;
    cc += (IOSIntArray_Get(nil_chk(z), 0) & LibOrgBouncycastleMathEcCustomSecSecP256R1Field_M) + xx08;
    *IOSIntArray_GetRef(z, 0) = (jint) cc;
    JreRShiftAssignLong(&cc, 32);
    if (cc != 0) {
      cc += (IOSIntArray_Get(z, 1) & LibOrgBouncycastleMathEcCustomSecSecP256R1Field_M);
      *IOSIntArray_GetRef(z, 1) = (jint) cc;
      JreRShiftAssignLong(&cc, 32);
      cc += (IOSIntArray_Get(z, 2) & LibOrgBouncycastleMathEcCustomSecSecP256R1Field_M);
      *IOSIntArray_GetRef(z, 2) = (jint) cc;
      JreRShiftAssignLong(&cc, 32);
    }
    cc += (IOSIntArray_Get(z, 3) & LibOrgBouncycastleMathEcCustomSecSecP256R1Field_M) - xx08;
    *IOSIntArray_GetRef(z, 3) = (jint) cc;
    JreRShiftAssignLong(&cc, 32);
    if (cc != 0) {
      cc += (IOSIntArray_Get(z, 4) & LibOrgBouncycastleMathEcCustomSecSecP256R1Field_M);
      *IOSIntArray_GetRef(z, 4) = (jint) cc;
      JreRShiftAssignLong(&cc, 32);
      cc += (IOSIntArray_Get(z, 5) & LibOrgBouncycastleMathEcCustomSecSecP256R1Field_M);
      *IOSIntArray_GetRef(z, 5) = (jint) cc;
      JreRShiftAssignLong(&cc, 32);
    }
    cc += (IOSIntArray_Get(z, 6) & LibOrgBouncycastleMathEcCustomSecSecP256R1Field_M) - xx08;
    *IOSIntArray_GetRef(z, 6) = (jint) cc;
    JreRShiftAssignLong(&cc, 32);
    cc += (IOSIntArray_Get(z, 7) & LibOrgBouncycastleMathEcCustomSecSecP256R1Field_M) + xx08;
    *IOSIntArray_GetRef(z, 7) = (jint) cc;
    JreRShiftAssignLong(&cc, 32);
  }
  if (cc != 0 || (IOSIntArray_Get(nil_chk(z), 7) == LibOrgBouncycastleMathEcCustomSecSecP256R1Field_P7 && LibOrgBouncycastleMathRawNat256_gteWithIntArray_withIntArray_(z, LibOrgBouncycastleMathEcCustomSecSecP256R1Field_P))) {
    LibOrgBouncycastleMathEcCustomSecSecP256R1Field_addPInvToWithIntArray_(z);
  }
}

void LibOrgBouncycastleMathEcCustomSecSecP256R1Field_squareWithIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP256R1Field_initialize();
  IOSIntArray *tt = LibOrgBouncycastleMathRawNat256_createExt();
  LibOrgBouncycastleMathRawNat256_squareWithIntArray_withIntArray_(x, tt);
  LibOrgBouncycastleMathEcCustomSecSecP256R1Field_reduceWithIntArray_withIntArray_(tt, z);
}

void LibOrgBouncycastleMathEcCustomSecSecP256R1Field_squareNWithIntArray_withInt_withIntArray_(IOSIntArray *x, jint n, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP256R1Field_initialize();
  IOSIntArray *tt = LibOrgBouncycastleMathRawNat256_createExt();
  LibOrgBouncycastleMathRawNat256_squareWithIntArray_withIntArray_(x, tt);
  LibOrgBouncycastleMathEcCustomSecSecP256R1Field_reduceWithIntArray_withIntArray_(tt, z);
  while (--n > 0) {
    LibOrgBouncycastleMathRawNat256_squareWithIntArray_withIntArray_(z, tt);
    LibOrgBouncycastleMathEcCustomSecSecP256R1Field_reduceWithIntArray_withIntArray_(tt, z);
  }
}

void LibOrgBouncycastleMathEcCustomSecSecP256R1Field_subtractWithIntArray_withIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *y, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP256R1Field_initialize();
  jint c = LibOrgBouncycastleMathRawNat256_subWithIntArray_withIntArray_withIntArray_(x, y, z);
  if (c != 0) {
    LibOrgBouncycastleMathEcCustomSecSecP256R1Field_subPInvFromWithIntArray_(z);
  }
}

void LibOrgBouncycastleMathEcCustomSecSecP256R1Field_subtractExtWithIntArray_withIntArray_withIntArray_(IOSIntArray *xx, IOSIntArray *yy, IOSIntArray *zz) {
  LibOrgBouncycastleMathEcCustomSecSecP256R1Field_initialize();
  jint c = LibOrgBouncycastleMathRawNat_subWithInt_withIntArray_withIntArray_withIntArray_(16, xx, yy, zz);
  if (c != 0) {
    LibOrgBouncycastleMathRawNat_addToWithInt_withIntArray_withIntArray_(16, LibOrgBouncycastleMathEcCustomSecSecP256R1Field_PExt, zz);
  }
}

void LibOrgBouncycastleMathEcCustomSecSecP256R1Field_twiceWithIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP256R1Field_initialize();
  jint c = LibOrgBouncycastleMathRawNat_shiftUpBitWithInt_withIntArray_withInt_withIntArray_(8, x, 0, z);
  if (c != 0 || (IOSIntArray_Get(nil_chk(z), 7) == LibOrgBouncycastleMathEcCustomSecSecP256R1Field_P7 && LibOrgBouncycastleMathRawNat256_gteWithIntArray_withIntArray_(z, LibOrgBouncycastleMathEcCustomSecSecP256R1Field_P))) {
    LibOrgBouncycastleMathEcCustomSecSecP256R1Field_addPInvToWithIntArray_(z);
  }
}

void LibOrgBouncycastleMathEcCustomSecSecP256R1Field_addPInvToWithIntArray_(IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP256R1Field_initialize();
  jlong c = (IOSIntArray_Get(nil_chk(z), 0) & LibOrgBouncycastleMathEcCustomSecSecP256R1Field_M) + 1;
  *IOSIntArray_GetRef(z, 0) = (jint) c;
  JreRShiftAssignLong(&c, 32);
  if (c != 0) {
    c += (IOSIntArray_Get(z, 1) & LibOrgBouncycastleMathEcCustomSecSecP256R1Field_M);
    *IOSIntArray_GetRef(z, 1) = (jint) c;
    JreRShiftAssignLong(&c, 32);
    c += (IOSIntArray_Get(z, 2) & LibOrgBouncycastleMathEcCustomSecSecP256R1Field_M);
    *IOSIntArray_GetRef(z, 2) = (jint) c;
    JreRShiftAssignLong(&c, 32);
  }
  c += (IOSIntArray_Get(z, 3) & LibOrgBouncycastleMathEcCustomSecSecP256R1Field_M) - 1;
  *IOSIntArray_GetRef(z, 3) = (jint) c;
  JreRShiftAssignLong(&c, 32);
  if (c != 0) {
    c += (IOSIntArray_Get(z, 4) & LibOrgBouncycastleMathEcCustomSecSecP256R1Field_M);
    *IOSIntArray_GetRef(z, 4) = (jint) c;
    JreRShiftAssignLong(&c, 32);
    c += (IOSIntArray_Get(z, 5) & LibOrgBouncycastleMathEcCustomSecSecP256R1Field_M);
    *IOSIntArray_GetRef(z, 5) = (jint) c;
    JreRShiftAssignLong(&c, 32);
  }
  c += (IOSIntArray_Get(z, 6) & LibOrgBouncycastleMathEcCustomSecSecP256R1Field_M) - 1;
  *IOSIntArray_GetRef(z, 6) = (jint) c;
  JreRShiftAssignLong(&c, 32);
  c += (IOSIntArray_Get(z, 7) & LibOrgBouncycastleMathEcCustomSecSecP256R1Field_M) + 1;
  *IOSIntArray_GetRef(z, 7) = (jint) c;
}

void LibOrgBouncycastleMathEcCustomSecSecP256R1Field_subPInvFromWithIntArray_(IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP256R1Field_initialize();
  jlong c = (IOSIntArray_Get(nil_chk(z), 0) & LibOrgBouncycastleMathEcCustomSecSecP256R1Field_M) - 1;
  *IOSIntArray_GetRef(z, 0) = (jint) c;
  JreRShiftAssignLong(&c, 32);
  if (c != 0) {
    c += (IOSIntArray_Get(z, 1) & LibOrgBouncycastleMathEcCustomSecSecP256R1Field_M);
    *IOSIntArray_GetRef(z, 1) = (jint) c;
    JreRShiftAssignLong(&c, 32);
    c += (IOSIntArray_Get(z, 2) & LibOrgBouncycastleMathEcCustomSecSecP256R1Field_M);
    *IOSIntArray_GetRef(z, 2) = (jint) c;
    JreRShiftAssignLong(&c, 32);
  }
  c += (IOSIntArray_Get(z, 3) & LibOrgBouncycastleMathEcCustomSecSecP256R1Field_M) + 1;
  *IOSIntArray_GetRef(z, 3) = (jint) c;
  JreRShiftAssignLong(&c, 32);
  if (c != 0) {
    c += (IOSIntArray_Get(z, 4) & LibOrgBouncycastleMathEcCustomSecSecP256R1Field_M);
    *IOSIntArray_GetRef(z, 4) = (jint) c;
    JreRShiftAssignLong(&c, 32);
    c += (IOSIntArray_Get(z, 5) & LibOrgBouncycastleMathEcCustomSecSecP256R1Field_M);
    *IOSIntArray_GetRef(z, 5) = (jint) c;
    JreRShiftAssignLong(&c, 32);
  }
  c += (IOSIntArray_Get(z, 6) & LibOrgBouncycastleMathEcCustomSecSecP256R1Field_M) + 1;
  *IOSIntArray_GetRef(z, 6) = (jint) c;
  JreRShiftAssignLong(&c, 32);
  c += (IOSIntArray_Get(z, 7) & LibOrgBouncycastleMathEcCustomSecSecP256R1Field_M) - 1;
  *IOSIntArray_GetRef(z, 7) = (jint) c;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleMathEcCustomSecSecP256R1Field)