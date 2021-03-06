//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/math/ec/custom/sec/SecP256K1Field.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "Nat.h"
#include "Nat256.h"
#include "SecP256K1Field.h"
#include "java/math/BigInteger.h"

inline IOSIntArray *LibOrgBouncycastleMathEcCustomSecSecP256K1Field_get_PExtInv(void);
static IOSIntArray *LibOrgBouncycastleMathEcCustomSecSecP256K1Field_PExtInv;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleMathEcCustomSecSecP256K1Field, PExtInv, IOSIntArray *)

inline jint LibOrgBouncycastleMathEcCustomSecSecP256K1Field_get_P7(void);
#define LibOrgBouncycastleMathEcCustomSecSecP256K1Field_P7 -1
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleMathEcCustomSecSecP256K1Field, P7, jint)

inline jint LibOrgBouncycastleMathEcCustomSecSecP256K1Field_get_PExt15(void);
#define LibOrgBouncycastleMathEcCustomSecSecP256K1Field_PExt15 -1
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleMathEcCustomSecSecP256K1Field, PExt15, jint)

inline jint LibOrgBouncycastleMathEcCustomSecSecP256K1Field_get_PInv33(void);
#define LibOrgBouncycastleMathEcCustomSecSecP256K1Field_PInv33 977
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleMathEcCustomSecSecP256K1Field, PInv33, jint)

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleMathEcCustomSecSecP256K1Field)

IOSIntArray *LibOrgBouncycastleMathEcCustomSecSecP256K1Field_P;
IOSIntArray *LibOrgBouncycastleMathEcCustomSecSecP256K1Field_PExt;

@implementation LibOrgBouncycastleMathEcCustomSecSecP256K1Field

+ (IOSIntArray *)P {
  return LibOrgBouncycastleMathEcCustomSecSecP256K1Field_P;
}

+ (IOSIntArray *)PExt {
  return LibOrgBouncycastleMathEcCustomSecSecP256K1Field_PExt;
}

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleMathEcCustomSecSecP256K1Field_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (void)addWithIntArray:(IOSIntArray *)x
           withIntArray:(IOSIntArray *)y
           withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP256K1Field_addWithIntArray_withIntArray_withIntArray_(x, y, z);
}

+ (void)addExtWithIntArray:(IOSIntArray *)xx
              withIntArray:(IOSIntArray *)yy
              withIntArray:(IOSIntArray *)zz {
  LibOrgBouncycastleMathEcCustomSecSecP256K1Field_addExtWithIntArray_withIntArray_withIntArray_(xx, yy, zz);
}

+ (void)addOneWithIntArray:(IOSIntArray *)x
              withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP256K1Field_addOneWithIntArray_withIntArray_(x, z);
}

+ (IOSIntArray *)fromBigIntegerWithJavaMathBigInteger:(JavaMathBigInteger *)x {
  return LibOrgBouncycastleMathEcCustomSecSecP256K1Field_fromBigIntegerWithJavaMathBigInteger_(x);
}

+ (void)halfWithIntArray:(IOSIntArray *)x
            withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP256K1Field_halfWithIntArray_withIntArray_(x, z);
}

+ (void)multiplyWithIntArray:(IOSIntArray *)x
                withIntArray:(IOSIntArray *)y
                withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP256K1Field_multiplyWithIntArray_withIntArray_withIntArray_(x, y, z);
}

+ (void)multiplyAddToExtWithIntArray:(IOSIntArray *)x
                        withIntArray:(IOSIntArray *)y
                        withIntArray:(IOSIntArray *)zz {
  LibOrgBouncycastleMathEcCustomSecSecP256K1Field_multiplyAddToExtWithIntArray_withIntArray_withIntArray_(x, y, zz);
}

+ (void)negateWithIntArray:(IOSIntArray *)x
              withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP256K1Field_negateWithIntArray_withIntArray_(x, z);
}

+ (void)reduceWithIntArray:(IOSIntArray *)xx
              withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP256K1Field_reduceWithIntArray_withIntArray_(xx, z);
}

+ (void)reduce32WithInt:(jint)x
           withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP256K1Field_reduce32WithInt_withIntArray_(x, z);
}

+ (void)squareWithIntArray:(IOSIntArray *)x
              withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP256K1Field_squareWithIntArray_withIntArray_(x, z);
}

+ (void)squareNWithIntArray:(IOSIntArray *)x
                    withInt:(jint)n
               withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP256K1Field_squareNWithIntArray_withInt_withIntArray_(x, n, z);
}

+ (void)subtractWithIntArray:(IOSIntArray *)x
                withIntArray:(IOSIntArray *)y
                withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP256K1Field_subtractWithIntArray_withIntArray_withIntArray_(x, y, z);
}

+ (void)subtractExtWithIntArray:(IOSIntArray *)xx
                   withIntArray:(IOSIntArray *)yy
                   withIntArray:(IOSIntArray *)zz {
  LibOrgBouncycastleMathEcCustomSecSecP256K1Field_subtractExtWithIntArray_withIntArray_withIntArray_(xx, yy, zz);
}

+ (void)twiceWithIntArray:(IOSIntArray *)x
             withIntArray:(IOSIntArray *)z {
  LibOrgBouncycastleMathEcCustomSecSecP256K1Field_twiceWithIntArray_withIntArray_(x, z);
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
    { "P7", "I", .constantValue.asInt = LibOrgBouncycastleMathEcCustomSecSecP256K1Field_P7, 0x1a, -1, -1, -1, -1 },
    { "PExt15", "I", .constantValue.asInt = LibOrgBouncycastleMathEcCustomSecSecP256K1Field_PExt15, 0x1a, -1, -1, -1, -1 },
    { "PInv33", "I", .constantValue.asInt = LibOrgBouncycastleMathEcCustomSecSecP256K1Field_PInv33, 0x1a, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "add", "[I[I[I", "addExt", "addOne", "[I[I", "fromBigInteger", "LJavaMathBigInteger;", "half", "multiply", "multiplyAddToExt", "negate", "reduce", "reduce32", "I[I", "square", "squareN", "[II[I", "subtract", "subtractExt", "twice", &LibOrgBouncycastleMathEcCustomSecSecP256K1Field_P, &LibOrgBouncycastleMathEcCustomSecSecP256K1Field_PExt, &LibOrgBouncycastleMathEcCustomSecSecP256K1Field_PExtInv };
  static const J2ObjcClassInfo _LibOrgBouncycastleMathEcCustomSecSecP256K1Field = { "SecP256K1Field", "lib.org.bouncycastle.math.ec.custom.sec", ptrTable, methods, fields, 7, 0x1, 16, 6, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleMathEcCustomSecSecP256K1Field;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleMathEcCustomSecSecP256K1Field class]) {
    LibOrgBouncycastleMathEcCustomSecSecP256K1Field_P = [IOSIntArray newArrayWithInts:(jint[]){ (jint) 0xFFFFFC2F, (jint) 0xFFFFFFFE, (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFF } count:8];
    LibOrgBouncycastleMathEcCustomSecSecP256K1Field_PExt = [IOSIntArray newArrayWithInts:(jint[]){ (jint) 0x000E90A1, (jint) 0x000007A2, (jint) 0x00000001, (jint) 0x00000000, (jint) 0x00000000, (jint) 0x00000000, (jint) 0x00000000, (jint) 0x00000000, (jint) 0xFFFFF85E, (jint) 0xFFFFFFFD, (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFF } count:16];
    LibOrgBouncycastleMathEcCustomSecSecP256K1Field_PExtInv = [IOSIntArray newArrayWithInts:(jint[]){ (jint) 0xFFF16F5F, (jint) 0xFFFFF85D, (jint) 0xFFFFFFFE, (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFF, (jint) 0xFFFFFFFF, (jint) 0x000007A1, (jint) 0x00000002 } count:10];
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleMathEcCustomSecSecP256K1Field)
  }
}

@end

void LibOrgBouncycastleMathEcCustomSecSecP256K1Field_init(LibOrgBouncycastleMathEcCustomSecSecP256K1Field *self) {
  NSObject_init(self);
}

LibOrgBouncycastleMathEcCustomSecSecP256K1Field *new_LibOrgBouncycastleMathEcCustomSecSecP256K1Field_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleMathEcCustomSecSecP256K1Field, init)
}

LibOrgBouncycastleMathEcCustomSecSecP256K1Field *create_LibOrgBouncycastleMathEcCustomSecSecP256K1Field_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleMathEcCustomSecSecP256K1Field, init)
}

void LibOrgBouncycastleMathEcCustomSecSecP256K1Field_addWithIntArray_withIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *y, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP256K1Field_initialize();
  jint c = LibOrgBouncycastleMathRawNat256_addWithIntArray_withIntArray_withIntArray_(x, y, z);
  if (c != 0 || (IOSIntArray_Get(nil_chk(z), 7) == LibOrgBouncycastleMathEcCustomSecSecP256K1Field_P7 && LibOrgBouncycastleMathRawNat256_gteWithIntArray_withIntArray_(z, LibOrgBouncycastleMathEcCustomSecSecP256K1Field_P))) {
    LibOrgBouncycastleMathRawNat_add33ToWithInt_withInt_withIntArray_(8, LibOrgBouncycastleMathEcCustomSecSecP256K1Field_PInv33, z);
  }
}

void LibOrgBouncycastleMathEcCustomSecSecP256K1Field_addExtWithIntArray_withIntArray_withIntArray_(IOSIntArray *xx, IOSIntArray *yy, IOSIntArray *zz) {
  LibOrgBouncycastleMathEcCustomSecSecP256K1Field_initialize();
  jint c = LibOrgBouncycastleMathRawNat_addWithInt_withIntArray_withIntArray_withIntArray_(16, xx, yy, zz);
  if (c != 0 || (IOSIntArray_Get(nil_chk(zz), 15) == LibOrgBouncycastleMathEcCustomSecSecP256K1Field_PExt15 && LibOrgBouncycastleMathRawNat_gteWithInt_withIntArray_withIntArray_(16, zz, LibOrgBouncycastleMathEcCustomSecSecP256K1Field_PExt))) {
    if (LibOrgBouncycastleMathRawNat_addToWithInt_withIntArray_withIntArray_(((IOSIntArray *) nil_chk(LibOrgBouncycastleMathEcCustomSecSecP256K1Field_PExtInv))->size_, LibOrgBouncycastleMathEcCustomSecSecP256K1Field_PExtInv, zz) != 0) {
      LibOrgBouncycastleMathRawNat_incAtWithInt_withIntArray_withInt_(16, zz, LibOrgBouncycastleMathEcCustomSecSecP256K1Field_PExtInv->size_);
    }
  }
}

void LibOrgBouncycastleMathEcCustomSecSecP256K1Field_addOneWithIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP256K1Field_initialize();
  jint c = LibOrgBouncycastleMathRawNat_incWithInt_withIntArray_withIntArray_(8, x, z);
  if (c != 0 || (IOSIntArray_Get(nil_chk(z), 7) == LibOrgBouncycastleMathEcCustomSecSecP256K1Field_P7 && LibOrgBouncycastleMathRawNat256_gteWithIntArray_withIntArray_(z, LibOrgBouncycastleMathEcCustomSecSecP256K1Field_P))) {
    LibOrgBouncycastleMathRawNat_add33ToWithInt_withInt_withIntArray_(8, LibOrgBouncycastleMathEcCustomSecSecP256K1Field_PInv33, z);
  }
}

IOSIntArray *LibOrgBouncycastleMathEcCustomSecSecP256K1Field_fromBigIntegerWithJavaMathBigInteger_(JavaMathBigInteger *x) {
  LibOrgBouncycastleMathEcCustomSecSecP256K1Field_initialize();
  IOSIntArray *z = LibOrgBouncycastleMathRawNat256_fromBigIntegerWithJavaMathBigInteger_(x);
  if (IOSIntArray_Get(nil_chk(z), 7) == LibOrgBouncycastleMathEcCustomSecSecP256K1Field_P7 && LibOrgBouncycastleMathRawNat256_gteWithIntArray_withIntArray_(z, LibOrgBouncycastleMathEcCustomSecSecP256K1Field_P)) {
    LibOrgBouncycastleMathRawNat256_subFromWithIntArray_withIntArray_(LibOrgBouncycastleMathEcCustomSecSecP256K1Field_P, z);
  }
  return z;
}

void LibOrgBouncycastleMathEcCustomSecSecP256K1Field_halfWithIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP256K1Field_initialize();
  if ((IOSIntArray_Get(nil_chk(x), 0) & 1) == 0) {
    LibOrgBouncycastleMathRawNat_shiftDownBitWithInt_withIntArray_withInt_withIntArray_(8, x, 0, z);
  }
  else {
    jint c = LibOrgBouncycastleMathRawNat256_addWithIntArray_withIntArray_withIntArray_(x, LibOrgBouncycastleMathEcCustomSecSecP256K1Field_P, z);
    LibOrgBouncycastleMathRawNat_shiftDownBitWithInt_withIntArray_withInt_(8, z, c);
  }
}

void LibOrgBouncycastleMathEcCustomSecSecP256K1Field_multiplyWithIntArray_withIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *y, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP256K1Field_initialize();
  IOSIntArray *tt = LibOrgBouncycastleMathRawNat256_createExt();
  LibOrgBouncycastleMathRawNat256_mulWithIntArray_withIntArray_withIntArray_(x, y, tt);
  LibOrgBouncycastleMathEcCustomSecSecP256K1Field_reduceWithIntArray_withIntArray_(tt, z);
}

void LibOrgBouncycastleMathEcCustomSecSecP256K1Field_multiplyAddToExtWithIntArray_withIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *y, IOSIntArray *zz) {
  LibOrgBouncycastleMathEcCustomSecSecP256K1Field_initialize();
  jint c = LibOrgBouncycastleMathRawNat256_mulAddToWithIntArray_withIntArray_withIntArray_(x, y, zz);
  if (c != 0 || (IOSIntArray_Get(nil_chk(zz), 15) == LibOrgBouncycastleMathEcCustomSecSecP256K1Field_PExt15 && LibOrgBouncycastleMathRawNat_gteWithInt_withIntArray_withIntArray_(16, zz, LibOrgBouncycastleMathEcCustomSecSecP256K1Field_PExt))) {
    if (LibOrgBouncycastleMathRawNat_addToWithInt_withIntArray_withIntArray_(((IOSIntArray *) nil_chk(LibOrgBouncycastleMathEcCustomSecSecP256K1Field_PExtInv))->size_, LibOrgBouncycastleMathEcCustomSecSecP256K1Field_PExtInv, zz) != 0) {
      LibOrgBouncycastleMathRawNat_incAtWithInt_withIntArray_withInt_(16, zz, LibOrgBouncycastleMathEcCustomSecSecP256K1Field_PExtInv->size_);
    }
  }
}

void LibOrgBouncycastleMathEcCustomSecSecP256K1Field_negateWithIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP256K1Field_initialize();
  if (LibOrgBouncycastleMathRawNat256_isZeroWithIntArray_(x)) {
    LibOrgBouncycastleMathRawNat256_zeroWithIntArray_(z);
  }
  else {
    LibOrgBouncycastleMathRawNat256_subWithIntArray_withIntArray_withIntArray_(LibOrgBouncycastleMathEcCustomSecSecP256K1Field_P, x, z);
  }
}

void LibOrgBouncycastleMathEcCustomSecSecP256K1Field_reduceWithIntArray_withIntArray_(IOSIntArray *xx, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP256K1Field_initialize();
  jlong cc = LibOrgBouncycastleMathRawNat256_mul33AddWithInt_withIntArray_withInt_withIntArray_withInt_withIntArray_withInt_(LibOrgBouncycastleMathEcCustomSecSecP256K1Field_PInv33, xx, 8, xx, 0, z, 0);
  jint c = LibOrgBouncycastleMathRawNat256_mul33DWordAddWithInt_withLong_withIntArray_withInt_(LibOrgBouncycastleMathEcCustomSecSecP256K1Field_PInv33, cc, z, 0);
  if (c != 0 || (IOSIntArray_Get(nil_chk(z), 7) == LibOrgBouncycastleMathEcCustomSecSecP256K1Field_P7 && LibOrgBouncycastleMathRawNat256_gteWithIntArray_withIntArray_(z, LibOrgBouncycastleMathEcCustomSecSecP256K1Field_P))) {
    LibOrgBouncycastleMathRawNat_add33ToWithInt_withInt_withIntArray_(8, LibOrgBouncycastleMathEcCustomSecSecP256K1Field_PInv33, z);
  }
}

void LibOrgBouncycastleMathEcCustomSecSecP256K1Field_reduce32WithInt_withIntArray_(jint x, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP256K1Field_initialize();
  if ((x != 0 && LibOrgBouncycastleMathRawNat256_mul33WordAddWithInt_withInt_withIntArray_withInt_(LibOrgBouncycastleMathEcCustomSecSecP256K1Field_PInv33, x, z, 0) != 0) || (IOSIntArray_Get(nil_chk(z), 7) == LibOrgBouncycastleMathEcCustomSecSecP256K1Field_P7 && LibOrgBouncycastleMathRawNat256_gteWithIntArray_withIntArray_(z, LibOrgBouncycastleMathEcCustomSecSecP256K1Field_P))) {
    LibOrgBouncycastleMathRawNat_add33ToWithInt_withInt_withIntArray_(8, LibOrgBouncycastleMathEcCustomSecSecP256K1Field_PInv33, z);
  }
}

void LibOrgBouncycastleMathEcCustomSecSecP256K1Field_squareWithIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP256K1Field_initialize();
  IOSIntArray *tt = LibOrgBouncycastleMathRawNat256_createExt();
  LibOrgBouncycastleMathRawNat256_squareWithIntArray_withIntArray_(x, tt);
  LibOrgBouncycastleMathEcCustomSecSecP256K1Field_reduceWithIntArray_withIntArray_(tt, z);
}

void LibOrgBouncycastleMathEcCustomSecSecP256K1Field_squareNWithIntArray_withInt_withIntArray_(IOSIntArray *x, jint n, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP256K1Field_initialize();
  IOSIntArray *tt = LibOrgBouncycastleMathRawNat256_createExt();
  LibOrgBouncycastleMathRawNat256_squareWithIntArray_withIntArray_(x, tt);
  LibOrgBouncycastleMathEcCustomSecSecP256K1Field_reduceWithIntArray_withIntArray_(tt, z);
  while (--n > 0) {
    LibOrgBouncycastleMathRawNat256_squareWithIntArray_withIntArray_(z, tt);
    LibOrgBouncycastleMathEcCustomSecSecP256K1Field_reduceWithIntArray_withIntArray_(tt, z);
  }
}

void LibOrgBouncycastleMathEcCustomSecSecP256K1Field_subtractWithIntArray_withIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *y, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP256K1Field_initialize();
  jint c = LibOrgBouncycastleMathRawNat256_subWithIntArray_withIntArray_withIntArray_(x, y, z);
  if (c != 0) {
    LibOrgBouncycastleMathRawNat_sub33FromWithInt_withInt_withIntArray_(8, LibOrgBouncycastleMathEcCustomSecSecP256K1Field_PInv33, z);
  }
}

void LibOrgBouncycastleMathEcCustomSecSecP256K1Field_subtractExtWithIntArray_withIntArray_withIntArray_(IOSIntArray *xx, IOSIntArray *yy, IOSIntArray *zz) {
  LibOrgBouncycastleMathEcCustomSecSecP256K1Field_initialize();
  jint c = LibOrgBouncycastleMathRawNat_subWithInt_withIntArray_withIntArray_withIntArray_(16, xx, yy, zz);
  if (c != 0) {
    if (LibOrgBouncycastleMathRawNat_subFromWithInt_withIntArray_withIntArray_(((IOSIntArray *) nil_chk(LibOrgBouncycastleMathEcCustomSecSecP256K1Field_PExtInv))->size_, LibOrgBouncycastleMathEcCustomSecSecP256K1Field_PExtInv, zz) != 0) {
      LibOrgBouncycastleMathRawNat_decAtWithInt_withIntArray_withInt_(16, zz, LibOrgBouncycastleMathEcCustomSecSecP256K1Field_PExtInv->size_);
    }
  }
}

void LibOrgBouncycastleMathEcCustomSecSecP256K1Field_twiceWithIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *z) {
  LibOrgBouncycastleMathEcCustomSecSecP256K1Field_initialize();
  jint c = LibOrgBouncycastleMathRawNat_shiftUpBitWithInt_withIntArray_withInt_withIntArray_(8, x, 0, z);
  if (c != 0 || (IOSIntArray_Get(nil_chk(z), 7) == LibOrgBouncycastleMathEcCustomSecSecP256K1Field_P7 && LibOrgBouncycastleMathRawNat256_gteWithIntArray_withIntArray_(z, LibOrgBouncycastleMathEcCustomSecSecP256K1Field_P))) {
    LibOrgBouncycastleMathRawNat_add33ToWithInt_withInt_withIntArray_(8, LibOrgBouncycastleMathEcCustomSecSecP256K1Field_PInv33, z);
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleMathEcCustomSecSecP256K1Field)
