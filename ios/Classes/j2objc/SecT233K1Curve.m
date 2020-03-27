//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/math/ec/custom/sec/SecT233K1Curve.java
//

#include "ECCurve.h"
#include "ECFieldElement.h"
#include "ECLookupTable.h"
#include "ECMultiplier.h"
#include "ECPoint.h"
#include "Hex.h"
#include "IOSObjectArray.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "Nat256.h"
#include "SecT233FieldElement.h"
#include "SecT233K1Curve.h"
#include "SecT233K1Point.h"
#include "WTauNafMultiplier.h"
#include "java/math/BigInteger.h"

inline jint LibOrgBouncycastleMathEcCustomSecSecT233K1Curve_get_SecT233K1_DEFAULT_COORDS(void);
#define LibOrgBouncycastleMathEcCustomSecSecT233K1Curve_SecT233K1_DEFAULT_COORDS 6
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleMathEcCustomSecSecT233K1Curve, SecT233K1_DEFAULT_COORDS, jint)

@interface LibOrgBouncycastleMathEcCustomSecSecT233K1Curve_1 : NSObject < LibOrgBouncycastleMathEcECLookupTable > {
 @public
  LibOrgBouncycastleMathEcCustomSecSecT233K1Curve *this$0_;
  jint val$len_;
  IOSLongArray *val$table_;
}

- (instancetype)initWithLibOrgBouncycastleMathEcCustomSecSecT233K1Curve:(LibOrgBouncycastleMathEcCustomSecSecT233K1Curve *)outer$
                                                                withInt:(jint)capture$0
                                                          withLongArray:(IOSLongArray *)capture$1;

- (jint)getSize;

- (LibOrgBouncycastleMathEcECPoint *)lookupWithInt:(jint)index;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleMathEcCustomSecSecT233K1Curve_1)

__attribute__((unused)) static void LibOrgBouncycastleMathEcCustomSecSecT233K1Curve_1_initWithLibOrgBouncycastleMathEcCustomSecSecT233K1Curve_withInt_withLongArray_(LibOrgBouncycastleMathEcCustomSecSecT233K1Curve_1 *self, LibOrgBouncycastleMathEcCustomSecSecT233K1Curve *outer$, jint capture$0, IOSLongArray *capture$1);

__attribute__((unused)) static LibOrgBouncycastleMathEcCustomSecSecT233K1Curve_1 *new_LibOrgBouncycastleMathEcCustomSecSecT233K1Curve_1_initWithLibOrgBouncycastleMathEcCustomSecSecT233K1Curve_withInt_withLongArray_(LibOrgBouncycastleMathEcCustomSecSecT233K1Curve *outer$, jint capture$0, IOSLongArray *capture$1) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleMathEcCustomSecSecT233K1Curve_1 *create_LibOrgBouncycastleMathEcCustomSecSecT233K1Curve_1_initWithLibOrgBouncycastleMathEcCustomSecSecT233K1Curve_withInt_withLongArray_(LibOrgBouncycastleMathEcCustomSecSecT233K1Curve *outer$, jint capture$0, IOSLongArray *capture$1);

@implementation LibOrgBouncycastleMathEcCustomSecSecT233K1Curve

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleMathEcCustomSecSecT233K1Curve_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (LibOrgBouncycastleMathEcECCurve *)cloneCurve {
  return new_LibOrgBouncycastleMathEcCustomSecSecT233K1Curve_init();
}

- (jboolean)supportsCoordinateSystemWithInt:(jint)coord {
  switch (coord) {
    case LibOrgBouncycastleMathEcECCurve_COORD_LAMBDA_PROJECTIVE:
    return true;
    default:
    return false;
  }
}

- (id<LibOrgBouncycastleMathEcECMultiplier>)createDefaultMultiplier {
  return new_LibOrgBouncycastleMathEcWTauNafMultiplier_init();
}

- (jint)getFieldSize {
  return 233;
}

- (LibOrgBouncycastleMathEcECFieldElement *)fromBigIntegerWithJavaMathBigInteger:(JavaMathBigInteger *)x {
  return new_LibOrgBouncycastleMathEcCustomSecSecT233FieldElement_initWithJavaMathBigInteger_(x);
}

- (LibOrgBouncycastleMathEcECPoint *)createRawPointWithLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)x
                                                   withLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)y
                                                                                  withBoolean:(jboolean)withCompression {
  return new_LibOrgBouncycastleMathEcCustomSecSecT233K1Point_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElement_withBoolean_(self, x, y, withCompression);
}

- (LibOrgBouncycastleMathEcECPoint *)createRawPointWithLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)x
                                                   withLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)y
                                              withLibOrgBouncycastleMathEcECFieldElementArray:(IOSObjectArray *)zs
                                                                                  withBoolean:(jboolean)withCompression {
  return new_LibOrgBouncycastleMathEcCustomSecSecT233K1Point_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElementArray_withBoolean_(self, x, y, zs, withCompression);
}

- (LibOrgBouncycastleMathEcECPoint *)getInfinity {
  return infinity_;
}

- (jboolean)isKoblitz {
  return true;
}

- (jint)getM {
  return 233;
}

- (jboolean)isTrinomial {
  return true;
}

- (jint)getK1 {
  return 74;
}

- (jint)getK2 {
  return 0;
}

- (jint)getK3 {
  return 0;
}

- (id<LibOrgBouncycastleMathEcECLookupTable>)createCacheSafeLookupTableWithLibOrgBouncycastleMathEcECPointArray:(IOSObjectArray *)points
                                                                                                        withInt:(jint)off
                                                                                                        withInt:(jint)len {
  jint FE_LONGS = 4;
  IOSLongArray *table = [IOSLongArray newArrayWithLength:len * FE_LONGS * 2];
  {
    jint pos = 0;
    for (jint i = 0; i < len; ++i) {
      LibOrgBouncycastleMathEcECPoint *p = IOSObjectArray_Get(nil_chk(points), off + i);
      LibOrgBouncycastleMathRawNat256_copy64WithLongArray_withInt_withLongArray_withInt_(((LibOrgBouncycastleMathEcCustomSecSecT233FieldElement *) nil_chk(((LibOrgBouncycastleMathEcCustomSecSecT233FieldElement *) cast_chk([((LibOrgBouncycastleMathEcECPoint *) nil_chk(p)) getRawXCoord], [LibOrgBouncycastleMathEcCustomSecSecT233FieldElement class]))))->x_, 0, table, pos);
      pos += FE_LONGS;
      LibOrgBouncycastleMathRawNat256_copy64WithLongArray_withInt_withLongArray_withInt_(((LibOrgBouncycastleMathEcCustomSecSecT233FieldElement *) nil_chk(((LibOrgBouncycastleMathEcCustomSecSecT233FieldElement *) cast_chk([p getRawYCoord], [LibOrgBouncycastleMathEcCustomSecSecT233FieldElement class]))))->x_, 0, table, pos);
      pos += FE_LONGS;
    }
  }
  return new_LibOrgBouncycastleMathEcCustomSecSecT233K1Curve_1_initWithLibOrgBouncycastleMathEcCustomSecSecT233K1Curve_withInt_withLongArray_(self, len, table);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECCurve;", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 0, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECMultiplier;", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECFieldElement;", 0x1, 2, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECPoint;", 0x4, 4, 5, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECPoint;", 0x4, 4, 6, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECPoint;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECLookupTable;", 0x1, 7, 8, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(cloneCurve);
  methods[2].selector = @selector(supportsCoordinateSystemWithInt:);
  methods[3].selector = @selector(createDefaultMultiplier);
  methods[4].selector = @selector(getFieldSize);
  methods[5].selector = @selector(fromBigIntegerWithJavaMathBigInteger:);
  methods[6].selector = @selector(createRawPointWithLibOrgBouncycastleMathEcECFieldElement:withLibOrgBouncycastleMathEcECFieldElement:withBoolean:);
  methods[7].selector = @selector(createRawPointWithLibOrgBouncycastleMathEcECFieldElement:withLibOrgBouncycastleMathEcECFieldElement:withLibOrgBouncycastleMathEcECFieldElementArray:withBoolean:);
  methods[8].selector = @selector(getInfinity);
  methods[9].selector = @selector(isKoblitz);
  methods[10].selector = @selector(getM);
  methods[11].selector = @selector(isTrinomial);
  methods[12].selector = @selector(getK1);
  methods[13].selector = @selector(getK2);
  methods[14].selector = @selector(getK3);
  methods[15].selector = @selector(createCacheSafeLookupTableWithLibOrgBouncycastleMathEcECPointArray:withInt:withInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "SecT233K1_DEFAULT_COORDS", "I", .constantValue.asInt = LibOrgBouncycastleMathEcCustomSecSecT233K1Curve_SecT233K1_DEFAULT_COORDS, 0x1a, -1, -1, -1, -1 },
    { "infinity_", "LLibOrgBouncycastleMathEcCustomSecSecT233K1Point;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "supportsCoordinateSystem", "I", "fromBigInteger", "LJavaMathBigInteger;", "createRawPoint", "LLibOrgBouncycastleMathEcECFieldElement;LLibOrgBouncycastleMathEcECFieldElement;Z", "LLibOrgBouncycastleMathEcECFieldElement;LLibOrgBouncycastleMathEcECFieldElement;[LLibOrgBouncycastleMathEcECFieldElement;Z", "createCacheSafeLookupTable", "[LLibOrgBouncycastleMathEcECPoint;II" };
  static const J2ObjcClassInfo _LibOrgBouncycastleMathEcCustomSecSecT233K1Curve = { "SecT233K1Curve", "lib.org.bouncycastle.math.ec.custom.sec", ptrTable, methods, fields, 7, 0x1, 16, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleMathEcCustomSecSecT233K1Curve;
}

@end

void LibOrgBouncycastleMathEcCustomSecSecT233K1Curve_init(LibOrgBouncycastleMathEcCustomSecSecT233K1Curve *self) {
  LibOrgBouncycastleMathEcECCurve_AbstractF2m_initWithInt_withInt_withInt_withInt_(self, 233, 74, 0, 0);
  self->infinity_ = new_LibOrgBouncycastleMathEcCustomSecSecT233K1Point_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElement_(self, nil, nil);
  self->a_ = [self fromBigIntegerWithJavaMathBigInteger:JavaMathBigInteger_valueOfWithLong_(0)];
  self->b_ = [self fromBigIntegerWithJavaMathBigInteger:JavaMathBigInteger_valueOfWithLong_(1)];
  self->order_ = new_JavaMathBigInteger_initWithInt_withByteArray_(1, LibOrgBouncycastleUtilEncodersHex_decodeWithNSString_(@"8000000000000000000000000000069D5BB915BCD46EFB1AD5F173ABDF"));
  self->cofactor_ = JavaMathBigInteger_valueOfWithLong_(4);
  self->coord_ = LibOrgBouncycastleMathEcCustomSecSecT233K1Curve_SecT233K1_DEFAULT_COORDS;
}

LibOrgBouncycastleMathEcCustomSecSecT233K1Curve *new_LibOrgBouncycastleMathEcCustomSecSecT233K1Curve_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleMathEcCustomSecSecT233K1Curve, init)
}

LibOrgBouncycastleMathEcCustomSecSecT233K1Curve *create_LibOrgBouncycastleMathEcCustomSecSecT233K1Curve_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleMathEcCustomSecSecT233K1Curve, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleMathEcCustomSecSecT233K1Curve)

@implementation LibOrgBouncycastleMathEcCustomSecSecT233K1Curve_1

- (instancetype)initWithLibOrgBouncycastleMathEcCustomSecSecT233K1Curve:(LibOrgBouncycastleMathEcCustomSecSecT233K1Curve *)outer$
                                                                withInt:(jint)capture$0
                                                          withLongArray:(IOSLongArray *)capture$1 {
  LibOrgBouncycastleMathEcCustomSecSecT233K1Curve_1_initWithLibOrgBouncycastleMathEcCustomSecSecT233K1Curve_withInt_withLongArray_(self, outer$, capture$0, capture$1);
  return self;
}

- (jint)getSize {
  return val$len_;
}

- (LibOrgBouncycastleMathEcECPoint *)lookupWithInt:(jint)index {
  IOSLongArray *x = LibOrgBouncycastleMathRawNat256_create64();
  IOSLongArray *y = LibOrgBouncycastleMathRawNat256_create64();
  jint pos = 0;
  for (jint i = 0; i < val$len_; ++i) {
    jlong MASK = JreRShift32(((i ^ index) - 1), 31);
    for (jint j = 0; j < 4; ++j) {
      *IOSLongArray_GetRef(nil_chk(x), j) ^= IOSLongArray_Get(nil_chk(val$table_), pos + j) & MASK;
      *IOSLongArray_GetRef(nil_chk(y), j) ^= IOSLongArray_Get(val$table_, pos + 4 + j) & MASK;
    }
    pos += (4 * 2);
  }
  return [this$0_ createRawPointWithLibOrgBouncycastleMathEcECFieldElement:new_LibOrgBouncycastleMathEcCustomSecSecT233FieldElement_initWithLongArray_(x) withLibOrgBouncycastleMathEcECFieldElement:new_LibOrgBouncycastleMathEcCustomSecSecT233FieldElement_initWithLongArray_(y) withBoolean:false];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECPoint;", 0x1, 0, 1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleMathEcCustomSecSecT233K1Curve:withInt:withLongArray:);
  methods[1].selector = @selector(getSize);
  methods[2].selector = @selector(lookupWithInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "this$0_", "LLibOrgBouncycastleMathEcCustomSecSecT233K1Curve;", .constantValue.asLong = 0, 0x1012, -1, -1, -1, -1 },
    { "val$len_", "I", .constantValue.asLong = 0, 0x1012, -1, -1, -1, -1 },
    { "val$table_", "[J", .constantValue.asLong = 0, 0x1012, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "lookup", "I", "LLibOrgBouncycastleMathEcCustomSecSecT233K1Curve;", "createCacheSafeLookupTableWithLibOrgBouncycastleMathEcECPointArray:withInt:withInt:" };
  static const J2ObjcClassInfo _LibOrgBouncycastleMathEcCustomSecSecT233K1Curve_1 = { "", "lib.org.bouncycastle.math.ec.custom.sec", ptrTable, methods, fields, 7, 0x8010, 3, 3, 2, -1, 3, -1, -1 };
  return &_LibOrgBouncycastleMathEcCustomSecSecT233K1Curve_1;
}

@end

void LibOrgBouncycastleMathEcCustomSecSecT233K1Curve_1_initWithLibOrgBouncycastleMathEcCustomSecSecT233K1Curve_withInt_withLongArray_(LibOrgBouncycastleMathEcCustomSecSecT233K1Curve_1 *self, LibOrgBouncycastleMathEcCustomSecSecT233K1Curve *outer$, jint capture$0, IOSLongArray *capture$1) {
  self->this$0_ = outer$;
  self->val$len_ = capture$0;
  self->val$table_ = capture$1;
  NSObject_init(self);
}

LibOrgBouncycastleMathEcCustomSecSecT233K1Curve_1 *new_LibOrgBouncycastleMathEcCustomSecSecT233K1Curve_1_initWithLibOrgBouncycastleMathEcCustomSecSecT233K1Curve_withInt_withLongArray_(LibOrgBouncycastleMathEcCustomSecSecT233K1Curve *outer$, jint capture$0, IOSLongArray *capture$1) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleMathEcCustomSecSecT233K1Curve_1, initWithLibOrgBouncycastleMathEcCustomSecSecT233K1Curve_withInt_withLongArray_, outer$, capture$0, capture$1)
}

LibOrgBouncycastleMathEcCustomSecSecT233K1Curve_1 *create_LibOrgBouncycastleMathEcCustomSecSecT233K1Curve_1_initWithLibOrgBouncycastleMathEcCustomSecSecT233K1Curve_withInt_withLongArray_(LibOrgBouncycastleMathEcCustomSecSecT233K1Curve *outer$, jint capture$0, IOSLongArray *capture$1) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleMathEcCustomSecSecT233K1Curve_1, initWithLibOrgBouncycastleMathEcCustomSecSecT233K1Curve_withInt_withLongArray_, outer$, capture$0, capture$1)
}