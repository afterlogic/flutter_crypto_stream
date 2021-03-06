//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/math/ec/custom/sec/SecP192K1Field.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "Nat.h"
#include "Nat192.h"
#include "SecP192K1Field.h"
#include "java/math/BigInteger.h"

inline IOSIntArray *LibOrgBouncycastleMathEcCustomSecSecP192K1Field_get_PExtInv(void);
static IOSIntArray *LibOrgBouncycastleMathEcCustomSecSecP192K1Field_PExtInv;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleMathEcCustomSecSecP192K1Field, PExtInv, IOSIntArray *)

inline jint LibOrgBouncycastleMathEcCustomSecSecP192K1Field_get_P5(void);
#define LibOrgBouncycastleMathEcCustomSecSecP192K1Field_P5 -1
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleMathEcCustomSecSecP192K1Field, P5, jint)

inline jint LibOrgBouncycastleMathEcCustomSecSecP192K1Field_get_PExt11(void);
#define LibOrgBouncycastleMathEcCustomSecSecP192K1Field_PExt11 -1
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleMathEcCustomSecSecP192K1Field, PExt11, jint)

inline jint LibOrgBouncycastleMathEcCustomSecSecP192K1Field_get_PInv33(void);
#define LibOrgBouncycastleMathEcCustomSecSecP192K1Field_PInv33 4553
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleMathEcCustomSecSecP192K1Field, PInv33, jint)

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleMathEcCustomSecSecP192K1Field)

IOSIntArray *LibOrgBouncycastleMathEcCustomSecSecP192K1Field_P;
IOSIntArray *LibOrgBouncycastleMathEcCustomSecSecP192K1Field_PExt;

@implementation LibOrgBouncycastleMathEcCustomSecSecP192K1Field

+ (IOSIntArray *)P {
  return LibOrgBouncycastleMathEcCustomSecSecP192K1Field_P;
}

+ (IOSIntArray *)PExt {
  return LibOrgBouncycastleMathEcCustomSecSecP192K1Field_PExt;
}

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleMathEcCustomSecSecP192K1Field_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (void)addWithIntArray:(IOSIntArray *)x
           withIntArray:(IOSIntArray *)y
           withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP192K1Field_addWithIntArray_withIntArray_withIntArray_(x, y, z);
}

+ (void)addExtWithIntArray:(IOSIntArray *)xx
              withIntArray:(IOSIntArray *)yy
              withIntArray:(IOSIntArray *)zz {
  LibOrgBouncycastleMathEcCustomSecSecP192K1Field_addExtWithIntArray_withIntArray_withIntArray_(xx, yy, zz);
}

+ (void)addOneWithIntArray:(IOSIntArray *)x
              withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP192K1Field_addOneWithIntArray_withIntArray_(x, z);
}

+ (IOSIntArray *)fromBigIntegerWithJavaMathBigInteger:(JavaMathBigInteger *)x {
  return LibOrgBouncycastleMathEcCustomSecSecP192K1Field_fromBigIntegerWithJavaMathBigInteger_(x);
}

+ (void)halfWithIntArray:(IOSIntArray *)x
            withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP192K1Field_halfWithIntArray_withIntArray_(x, z);
}

+ (void)multiplyWithIntArray:(IOSIntArray *)x
                withIntArray:(IOSIntArray *)y
                withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP192K1Field_multiplyWithIntArray_withIntArray_withIntArray_(x, y, z);
}

+ (void)multiplyAddToExtWithIntArray:(IOSIntArray *)x
                        withIntArray:(IOSIntArray *)y
                        withIntArray:(IOSIntArray *)zz {
  LibOrgBouncycastleMathEcCustomSecSecP192K1Field_multiplyAddToExtWithIntArray_withIntArray_withIntArray_(x, y, zz);
}

+ (void)negateWithIntArray:(IOSIntArray *)x
              withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP192K1Field_negateWithIntArray_withIntArray_(x, z);
}

+ (void)reduceWithIntArray:(IOSIntArray *)xx
              withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP192K1Field_reduceWithIntArray_withIntArray_(xx, z);
}

+ (void)reduce32WithInt:(jint)x
           withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP192K1Field_reduce32WithInt_withIntArray_(x, z);
}

+ (void)squareWithIntArray:(IOSIntArray *)x
              withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP192K1Field_squareWithIntArray_withIntArray_(x, z);
}

+ (void)squareNWithIntArray:(IOSIntArray *)x
                    withInt:(jint)n
               withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP192K1Field_squareNWithIntArray_withInt_withIntArray_(x, n, z);
}

+ (void)subtractWithIntArray:(IOSIntArray *)x
                withIntArray:(IOSIntArray *)y
                withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP192K1Field_subtractWithIntArray_withIntArray_withIntArray_(x, y, z);
}

+ (void)subtractExtWithIntArray:(IOSIntArray *)xx
                   withIntArray:(IOSIntArray *)yy
                   withIntArray:(IOSIntArray *)zz {
  LibOrgBouncycastleMathEcCustomSecSecP192K1Field_subtractExtWithIntArray_withIntArray_withIntArray_(xx, yy, zz);
}

+ (void)twiceWithIntArray:(IOSIntArray *)x
             withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP192K1Field_twiceWithIntArray_withIntArray_(x, z);
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
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "P", "[I", .constantValue.asLong = 0, 0x18, -1, 20, -1, -1 },
    { "PExt", "[I", .constantValue.asLong = 0, 0x18, -1, 21, -1, -1 },
    { "PExtInv", "[I", .constantValue.asLong = 0, 0x1a, -1, 22, -1, -1 },
    { "P5", "I", .constantValue.asInt = LibOrgBouncycastleMathEcCustomSecSecP192K1Field_P5, 0x1a, -1, -1, -1, -1 },
    { "PExt11", "I", .constantValue.asInt = LibOrgBouncycastleMathEcCustomSecSecP192K1Field_PExt11, 0x1a, -1, -1, -1, -1 },
    { "PInv33", "I", .constantValue.asInt = LibOrgBouncycastleMathEcCustomSecSecP192K1Field_PInv33, 0x1a, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "add", "[I[I[I", "addExt", "addOne", "[I[I", "fromBigInteger", "LJavaMathBigInteger;", "half", "multiply", "multiplyAddToExt", "negate", "reduce", "reduce32", "I[I", "square", "squareN", "[II[I", "subtract", "subtractExt", "twice", &LibOrgBouncycastleMathEcCustomSecSecP192K1Field_P, &LibOrgBouncycastleMathEcCustomSecSecP192K1Field_PExt, &LibOrgBouncycastleMathEcCustomSecSecP192K1Field_PExtInv };
  static const J2ObjcClassInfo _LibOrgBouncycastleMathEcCustomSecSecP192K1Field = { "SecP192K1Field", "lib.org.bouncycastle.math.ec.custom.sec", ptrTable, methods, fields, 7, 0x1, 16, 6, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleMathEcCustomSecSecP192K1Field;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleMathEcCustomSecSecP192K1Field class]) {
    LibOrgBouncycastleMathEcCustomSecSecP192K1Field_P = [IOSIntArray newArrayWithInts:(jint[]){ (jint) 0xFFFFEE37, (jint) 0xFFFFFFFE, (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFF } count:6];
    LibOrgBouncycastleMathEcCustomSecSecP192K1Field_PExt = [IOSIntArray newArrayWithInts:(jint[]){ (jint) 0x013C4FD1, (jint) 0x00002392, (jint) 0x00000001, (jint) 0x00000000, (jint) 0x00000000, (jint) 0x00000000, (jint) 0xFFFFDC6E, (jint) 0xFFFFFFFD, (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFF } count:12];
    LibOrgBouncycastleMathEcCustomSecSecP192K1Field_PExtInv = [IOSIntArray newArrayWithInts:(jint[]){ (jint) 0xFEC3B02F, (jint) 0xFFFFDC6D, (jint) 0xFFFFFFFE, (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFF, (jint) 0x00002391, (jint) 0x00000002 } count:8];
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleMathEcCustomSecSecP192K1Field)
  }
}

@end

void LibOrgBouncycastleMathEcCustomSecSecP192K1Field_init(LibOrgBouncycastleMathEcCustomSecSecP192K1Field *self) {
  NSObject_init(self);
}

LibOrgBouncycastleMathEcCustomSecSecP192K1Field *new_LibOrgBouncycastleMathEcCustomSecSecP192K1Field_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleMathEcCustomSecSecP192K1Field, init)
}

LibOrgBouncycastleMathEcCustomSecSecP192K1Field *create_LibOrgBouncycastleMathEcCustomSecSecP192K1Field_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleMathEcCustomSecSecP192K1Field, init)
}

void LibOrgBouncycastleMathEcCustomSecSecP192K1Field_addWithIntArray_withIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *y, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP192K1Field_initialize();
  jint c = LibOrgBouncycastleMathRawNat192_addWithIntArray_withIntArray_withIntArray_(x, y, z);
  if (c != 0 || (IOSIntArray_Get(nil_chk(z), 5) == LibOrgBouncycastleMathEcCustomSecSecP192K1Field_P5 && LibOrgBouncycastleMathRawNat192_gteWithIntArray_withIntArray_(z, LibOrgBouncycastleMathEcCustomSecSecP192K1Field_P))) {
    LibOrgBouncycastleMathRawNat_add33ToWithInt_withInt_withIntArray_(6, LibOrgBouncycastleMathEcCustomSecSecP192K1Field_PInv33, z);
  }
}

void LibOrgBouncycastleMathEcCustomSecSecP192K1Field_addExtWithIntArray_withIntArray_withIntArray_(IOSIntArray *xx, IOSIntArray *yy, IOSIntArray *zz) {
  LibOrgBouncycastleMathEcCustomSecSecP192K1Field_initialize();
  jint c = LibOrgBouncycastleMathRawNat_addWithInt_withIntArray_withIntArray_withIntArray_(12, xx, yy, zz);
  if (c != 0 || (IOSIntArray_Get(nil_chk(zz), 11) == LibOrgBouncycastleMathEcCustomSecSecP192K1Field_PExt11 && LibOrgBouncycastleMathRawNat_gteWithInt_withIntArray_withIntArray_(12, zz, LibOrgBouncycastleMathEcCustomSecSecP192K1Field_PExt))) {
    if (LibOrgBouncycastleMathRawNat_addToWithInt_withIntArray_withIntArray_(((IOSIntArray *) nil_chk(LibOrgBouncycastleMathEcCustomSecSecP192K1Field_PExtInv))->size_, LibOrgBouncycastleMathEcCustomSecSecP192K1Field_PExtInv, zz) != 0) {
      LibOrgBouncycastleMathRawNat_incAtWithInt_withIntArray_withInt_(12, zz, LibOrgBouncycastleMathEcCustomSecSecP192K1Field_PExtInv->size_);
    }
  }
}

void LibOrgBouncycastleMathEcCustomSecSecP192K1Field_addOneWithIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP192K1Field_initialize();
  jint c = LibOrgBouncycastleMathRawNat_incWithInt_withIntArray_withIntArray_(6, x, z);
  if (c != 0 || (IOSIntArray_Get(nil_chk(z), 5) == LibOrgBouncycastleMathEcCustomSecSecP192K1Field_P5 && LibOrgBouncycastleMathRawNat192_gteWithIntArray_withIntArray_(z, LibOrgBouncycastleMathEcCustomSecSecP192K1Field_P))) {
    LibOrgBouncycastleMathRawNat_add33ToWithInt_withInt_withIntArray_(6, LibOrgBouncycastleMathEcCustomSecSecP192K1Field_PInv33, z);
  }
}

IOSIntArray *LibOrgBouncycastleMathEcCustomSecSecP192K1Field_fromBigIntegerWithJavaMathBigInteger_(JavaMathBigInteger *x) {
  LibOrgBouncycastleMathEcCustomSecSecP192K1Field_initialize();
  IOSIntArray *z = LibOrgBouncycastleMathRawNat192_fromBigIntegerWithJavaMathBigInteger_(x);
  if (IOSIntArray_Get(nil_chk(z), 5) == LibOrgBouncycastleMathEcCustomSecSecP192K1Field_P5 && LibOrgBouncycastleMathRawNat192_gteWithIntArray_withIntArray_(z, LibOrgBouncycastleMathEcCustomSecSecP192K1Field_P)) {
    LibOrgBouncycastleMathRawNat192_subFromWithIntArray_withIntArray_(LibOrgBouncycastleMathEcCustomSecSecP192K1Field_P, z);
  }
  return z;
}

void LibOrgBouncycastleMathEcCustomSecSecP192K1Field_halfWithIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP192K1Field_initialize();
  if ((IOSIntArray_Get(nil_chk(x), 0) & 1) == 0) {
    LibOrgBouncycastleMathRawNat_shiftDownBitWithInt_withIntArray_withInt_withIntArray_(6, x, 0, z);
  }
  else {
    jint c = LibOrgBouncycastleMathRawNat192_addWithIntArray_withIntArray_withIntArray_(x, LibOrgBouncycastleMathEcCustomSecSecP192K1Field_P, z);
    LibOrgBouncycastleMathRawNat_shiftDownBitWithInt_withIntArray_withInt_(6, z, c);
  }
}

void LibOrgBouncycastleMathEcCustomSecSecP192K1Field_multiplyWithIntArray_withIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *y, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP192K1Field_initialize();
  IOSIntArray *tt = LibOrgBouncycastleMathRawNat192_createExt();
  LibOrgBouncycastleMathRawNat192_mulWithIntArray_withIntArray_withIntArray_(x, y, tt);
  LibOrgBouncycastleMathEcCustomSecSecP192K1Field_reduceWithIntArray_withIntArray_(tt, z);
}

void LibOrgBouncycastleMathEcCustomSecSecP192K1Field_multiplyAddToExtWithIntArray_withIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *y, IOSIntArray *zz) {
  LibOrgBouncycastleMathEcCustomSecSecP192K1Field_initialize();
  jint c = LibOrgBouncycastleMathRawNat192_mulAddToWithIntArray_withIntArray_withIntArray_(x, y, zz);
  if (c != 0 || (IOSIntArray_Get(nil_chk(zz), 11) == LibOrgBouncycastleMathEcCustomSecSecP192K1Field_PExt11 && LibOrgBouncycastleMathRawNat_gteWithInt_withIntArray_withIntArray_(12, zz, LibOrgBouncycastleMathEcCustomSecSecP192K1Field_PExt))) {
    if (LibOrgBouncycastleMathRawNat_addToWithInt_withIntArray_withIntArray_(((IOSIntArray *) nil_chk(LibOrgBouncycastleMathEcCustomSecSecP192K1Field_PExtInv))->size_, LibOrgBouncycastleMathEcCustomSecSecP192K1Field_PExtInv, zz) != 0) {
      LibOrgBouncycastleMathRawNat_incAtWithInt_withIntArray_withInt_(12, zz, LibOrgBouncycastleMathEcCustomSecSecP192K1Field_PExtInv->size_);
    }
  }
}

void LibOrgBouncycastleMathEcCustomSecSecP192K1Field_negateWithIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP192K1Field_initialize();
  if (LibOrgBouncycastleMathRawNat192_isZeroWithIntArray_(x)) {
    LibOrgBouncycastleMathRawNat192_zeroWithIntArray_(z);
  }
  else {
    LibOrgBouncycastleMathRawNat192_subWithIntArray_withIntArray_withIntArray_(LibOrgBouncycastleMathEcCustomSecSecP192K1Field_P, x, z);
  }
}

void LibOrgBouncycastleMathEcCustomSecSecP192K1Field_reduceWithIntArray_withIntArray_(IOSIntArray *xx, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP192K1Field_initialize();
  jlong cc = LibOrgBouncycastleMathRawNat192_mul33AddWithInt_withIntArray_withInt_withIntArray_withInt_withIntArray_withInt_(LibOrgBouncycastleMathEcCustomSecSecP192K1Field_PInv33, xx, 6, xx, 0, z, 0);
  jint c = LibOrgBouncycastleMathRawNat192_mul33DWordAddWithInt_withLong_withIntArray_withInt_(LibOrgBouncycastleMathEcCustomSecSecP192K1Field_PInv33, cc, z, 0);
  if (c != 0 || (IOSIntArray_Get(nil_chk(z), 5) == LibOrgBouncycastleMathEcCustomSecSecP192K1Field_P5 && LibOrgBouncycastleMathRawNat192_gteWithIntArray_withIntArray_(z, LibOrgBouncycastleMathEcCustomSecSecP192K1Field_P))) {
    LibOrgBouncycastleMathRawNat_add33ToWithInt_withInt_withIntArray_(6, LibOrgBouncycastleMathEcCustomSecSecP192K1Field_PInv33, z);
  }
}

void LibOrgBouncycastleMathEcCustomSecSecP192K1Field_reduce32WithInt_withIntArray_(jint x, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP192K1Field_initialize();
  if ((x != 0 && LibOrgBouncycastleMathRawNat192_mul33WordAddWithInt_withInt_withIntArray_withInt_(LibOrgBouncycastleMathEcCustomSecSecP192K1Field_PInv33, x, z, 0) != 0) || (IOSIntArray_Get(nil_chk(z), 5) == LibOrgBouncycastleMathEcCustomSecSecP192K1Field_P5 && LibOrgBouncycastleMathRawNat192_gteWithIntArray_withIntArray_(z, LibOrgBouncycastleMathEcCustomSecSecP192K1Field_P))) {
    LibOrgBouncycastleMathRawNat_add33ToWithInt_withInt_withIntArray_(6, LibOrgBouncycastleMathEcCustomSecSecP192K1Field_PInv33, z);
  }
}

void LibOrgBouncycastleMathEcCustomSecSecP192K1Field_squareWithIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP192K1Field_initialize();
  IOSIntArray *tt = LibOrgBouncycastleMathRawNat192_createExt();
  LibOrgBouncycastleMathRawNat192_squareWithIntArray_withIntArray_(x, tt);
  LibOrgBouncycastleMathEcCustomSecSecP192K1Field_reduceWithIntArray_withIntArray_(tt, z);
}

void LibOrgBouncycastleMathEcCustomSecSecP192K1Field_squareNWithIntArray_withInt_withIntArray_(IOSIntArray *x, jint n, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP192K1Field_initialize();
  IOSIntArray *tt = LibOrgBouncycastleMathRawNat192_createExt();
  LibOrgBouncycastleMathRawNat192_squareWithIntArray_withIntArray_(x, tt);
  LibOrgBouncycastleMathEcCustomSecSecP192K1Field_reduceWithIntArray_withIntArray_(tt, z);
  while (--n > 0) {
    LibOrgBouncycastleMathRawNat192_squareWithIntArray_withIntArray_(z, tt);
    LibOrgBouncycastleMathEcCustomSecSecP192K1Field_reduceWithIntArray_withIntArray_(tt, z);
  }
}

void LibOrgBouncycastleMathEcCustomSecSecP192K1Field_subtractWithIntArray_withIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *y, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP192K1Field_initialize();
  jint c = LibOrgBouncycastleMathRawNat192_subWithIntArray_withIntArray_withIntArray_(x, y, z);
  if (c != 0) {
    LibOrgBouncycastleMathRawNat_sub33FromWithInt_withInt_withIntArray_(6, LibOrgBouncycastleMathEcCustomSecSecP192K1Field_PInv33, z);
  }
}

void LibOrgBouncycastleMathEcCustomSecSecP192K1Field_subtractExtWithIntArray_withIntArray_withIntArray_(IOSIntArray *xx, IOSIntArray *yy, IOSIntArray *zz) {
  LibOrgBouncycastleMathEcCustomSecSecP192K1Field_initialize();
  jint c = LibOrgBouncycastleMathRawNat_subWithInt_withIntArray_withIntArray_withIntArray_(12, xx, yy, zz);
  if (c != 0) {
    if (LibOrgBouncycastleMathRawNat_subFromWithInt_withIntArray_withIntArray_(((IOSIntArray *) nil_chk(LibOrgBouncycastleMathEcCustomSecSecP192K1Field_PExtInv))->size_, LibOrgBouncycastleMathEcCustomSecSecP192K1Field_PExtInv, zz) != 0) {
      LibOrgBouncycastleMathRawNat_decAtWithInt_withIntArray_withInt_(12, zz, LibOrgBouncycastleMathEcCustomSecSecP192K1Field_PExtInv->size_);
    }
  }
}

void LibOrgBouncycastleMathEcCustomSecSecP192K1Field_twiceWithIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP192K1Field_initialize();
  jint c = LibOrgBouncycastleMathRawNat_shiftUpBitWithInt_withIntArray_withInt_withIntArray_(6, x, 0, z);
  if (c != 0 || (IOSIntArray_Get(nil_chk(z), 5) == LibOrgBouncycastleMathEcCustomSecSecP192K1Field_P5 && LibOrgBouncycastleMathRawNat192_gteWithIntArray_withIntArray_(z, LibOrgBouncycastleMathEcCustomSecSecP192K1Field_P))) {
    LibOrgBouncycastleMathRawNat_add33ToWithInt_withInt_withIntArray_(6, LibOrgBouncycastleMathEcCustomSecSecP192K1Field_PInv33, z);
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleMathEcCustomSecSecP192K1Field)
