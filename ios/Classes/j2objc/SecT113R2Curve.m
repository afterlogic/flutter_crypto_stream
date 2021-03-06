//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/math/ec/custom/sec/SecT113R2Curve.java
//

#include "ECCurve.h"
#include "ECFieldElement.h"
#include "ECLookupTable.h"
#include "ECPoint.h"
#include "Hex.h"
#include "IOSObjectArray.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "Nat128.h"
#include "SecT113FieldElement.h"
#include "SecT113R2Curve.h"
#include "SecT113R2Point.h"
#include "java/math/BigInteger.h"

inline jint LibOrgBouncycastleMathEcCustomSecSecT113R2Curve_get_SecT113R2_DEFAULT_COORDS(void);
#define LibOrgBouncycastleMathEcCustomSecSecT113R2Curve_SecT113R2_DEFAULT_COORDS 6
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleMathEcCustomSecSecT113R2Curve, SecT113R2_DEFAULT_COORDS, jint)

@interface LibOrgBouncycastleMathEcCustomSecSecT113R2Curve_1 : NSObject < LibOrgBouncycastleMathEcECLookupTable > {
 @public
  LibOrgBouncycastleMathEcCustomSecSecT113R2Curve *this$0_;
  jint val$len_;
  IOSLongArray *val$table_;
}

- (instancetype)initWithLibOrgBouncycastleMathEcCustomSecSecT113R2Curve:(LibOrgBouncycastleMathEcCustomSecSecT113R2Curve *)outer$
                                                                withInt:(jint)capture$0
                                                          withLongArray:(IOSLongArray *)capture$1;

- (jint)getSize;

- (LibOrgBouncycastleMathEcECPoint *)lookupWithInt:(jint)index;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleMathEcCustomSecSecT113R2Curve_1)

__attribute__((unused)) static void LibOrgBouncycastleMathEcCustomSecSecT113R2Curve_1_initWithLibOrgBouncycastleMathEcCustomSecSecT113R2Curve_withInt_withLongArray_(LibOrgBouncycastleMathEcCustomSecSecT113R2Curve_1 *self, LibOrgBouncycastleMathEcCustomSecSecT113R2Curve *outer$, jint capture$0, IOSLongArray *capture$1);

__attribute__((unused)) static LibOrgBouncycastleMathEcCustomSecSecT113R2Curve_1 *new_LibOrgBouncycastleMathEcCustomSecSecT113R2Curve_1_initWithLibOrgBouncycastleMathEcCustomSecSecT113R2Curve_withInt_withLongArray_(LibOrgBouncycastleMathEcCustomSecSecT113R2Curve *outer$, jint capture$0, IOSLongArray *capture$1) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleMathEcCustomSecSecT113R2Curve_1 *create_LibOrgBouncycastleMathEcCustomSecSecT113R2Curve_1_initWithLibOrgBouncycastleMathEcCustomSecSecT113R2Curve_withInt_withLongArray_(LibOrgBouncycastleMathEcCustomSecSecT113R2Curve *outer$, jint capture$0, IOSLongArray *capture$1);

@implementation LibOrgBouncycastleMathEcCustomSecSecT113R2Curve

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleMathEcCustomSecSecT113R2Curve_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (LibOrgBouncycastleMathEcECCurve *)cloneCurve {
  return new_LibOrgBouncycastleMathEcCustomSecSecT113R2Curve_init();
}

- (jboolean)supportsCoordinateSystemWithInt:(jint)coord {
  switch (coord) {
    case LibOrgBouncycastleMathEcECCurve_COORD_LAMBDA_PROJECTIVE:
    return true;
    default:
    return false;
  }
}

- (jint)getFieldSize {
  return 113;
}

- (LibOrgBouncycastleMathEcECFieldElement *)fromBigIntegerWithJavaMathBigInteger:(JavaMathBigInteger *)x {
  return new_LibOrgBouncycastleMathEcCustomSecSecT113FieldElement_initWithJavaMathBigInteger_(x);
}

- (LibOrgBouncycastleMathEcECPoint *)createRawPointWithLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)x
                                                   withLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)y
                                                                                  withBoolean:(jboolean)withCompression {
  return new_LibOrgBouncycastleMathEcCustomSecSecT113R2Point_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElement_withBoolean_(self, x, y, withCompression);
}

- (LibOrgBouncycastleMathEcECPoint *)createRawPointWithLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)x
                                                   withLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)y
                                              withLibOrgBouncycastleMathEcECFieldElementArray:(IOSObjectArray *)zs
                                                                                  withBoolean:(jboolean)withCompression {
  return new_LibOrgBouncycastleMathEcCustomSecSecT113R2Point_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElementArray_withBoolean_(self, x, y, zs, withCompression);
}

- (LibOrgBouncycastleMathEcECPoint *)getInfinity {
  return infinity_;
}

- (jboolean)isKoblitz {
  return false;
}

- (jint)getM {
  return 113;
}

- (jboolean)isTrinomial {
  return true;
}

- (jint)getK1 {
  return 9;
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
  jint FE_LONGS = 2;
  IOSLongArray *table = [IOSLongArray newArrayWithLength:len * FE_LONGS * 2];
  {
    jint pos = 0;
    for (jint i = 0; i < len; ++i) {
      LibOrgBouncycastleMathEcECPoint *p = IOSObjectArray_Get(nil_chk(points), off + i);
      LibOrgBouncycastleMathRawNat128_copy64WithLongArray_withInt_withLongArray_withInt_(((LibOrgBouncycastleMathEcCustomSecSecT113FieldElement *) nil_chk(((LibOrgBouncycastleMathEcCustomSecSecT113FieldElement *) cast_chk([((LibOrgBouncycastleMathEcECPoint *) nil_chk(p)) getRawXCoord], [LibOrgBouncycastleMathEcCustomSecSecT113FieldElement class]))))->x_, 0, table, pos);
      pos += FE_LONGS;
      LibOrgBouncycastleMathRawNat128_copy64WithLongArray_withInt_withLongArray_withInt_(((LibOrgBouncycastleMathEcCustomSecSecT113FieldElement *) nil_chk(((LibOrgBouncycastleMathEcCustomSecSecT113FieldElement *) cast_chk([p getRawYCoord], [LibOrgBouncycastleMathEcCustomSecSecT113FieldElement class]))))->x_, 0, table, pos);
      pos += FE_LONGS;
    }
  }
  return new_LibOrgBouncycastleMathEcCustomSecSecT113R2Curve_1_initWithLibOrgBouncycastleMathEcCustomSecSecT113R2Curve_withInt_withLongArray_(self, len, table);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECCurve;", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 0, 1, -1, -1, -1, -1 },
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
  methods[3].selector = @selector(getFieldSize);
  methods[4].selector = @selector(fromBigIntegerWithJavaMathBigInteger:);
  methods[5].selector = @selector(createRawPointWithLibOrgBouncycastleMathEcECFieldElement:withLibOrgBouncycastleMathEcECFieldElement:withBoolean:);
  methods[6].selector = @selector(createRawPointWithLibOrgBouncycastleMathEcECFieldElement:withLibOrgBouncycastleMathEcECFieldElement:withLibOrgBouncycastleMathEcECFieldElementArray:withBoolean:);
  methods[7].selector = @selector(getInfinity);
  methods[8].selector = @selector(isKoblitz);
  methods[9].selector = @selector(getM);
  methods[10].selector = @selector(isTrinomial);
  methods[11].selector = @selector(getK1);
  methods[12].selector = @selector(getK2);
  methods[13].selector = @selector(getK3);
  methods[14].selector = @selector(createCacheSafeLookupTableWithLibOrgBouncycastleMathEcECPointArray:withInt:withInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "SecT113R2_DEFAULT_COORDS", "I", .constantValue.asInt = LibOrgBouncycastleMathEcCustomSecSecT113R2Curve_SecT113R2_DEFAULT_COORDS, 0x1a, -1, -1, -1, -1 },
    { "infinity_", "LLibOrgBouncycastleMathEcCustomSecSecT113R2Point;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "supportsCoordinateSystem", "I", "fromBigInteger", "LJavaMathBigInteger;", "createRawPoint", "LLibOrgBouncycastleMathEcECFieldElement;LLibOrgBouncycastleMathEcECFieldElement;Z", "LLibOrgBouncycastleMathEcECFieldElement;LLibOrgBouncycastleMathEcECFieldElement;[LLibOrgBouncycastleMathEcECFieldElement;Z", "createCacheSafeLookupTable", "[LLibOrgBouncycastleMathEcECPoint;II" };
  static const J2ObjcClassInfo _LibOrgBouncycastleMathEcCustomSecSecT113R2Curve = { "SecT113R2Curve", "lib.org.bouncycastle.math.ec.custom.sec", ptrTable, methods, fields, 7, 0x1, 15, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleMathEcCustomSecSecT113R2Curve;
}

@end

void LibOrgBouncycastleMathEcCustomSecSecT113R2Curve_init(LibOrgBouncycastleMathEcCustomSecSecT113R2Curve *self) {
  LibOrgBouncycastleMathEcECCurve_AbstractF2m_initWithInt_withInt_withInt_withInt_(self, 113, 9, 0, 0);
  self->infinity_ = new_LibOrgBouncycastleMathEcCustomSecSecT113R2Point_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElement_(self, nil, nil);
  self->a_ = [self fromBigIntegerWithJavaMathBigInteger:new_JavaMathBigInteger_initWithInt_withByteArray_(1, LibOrgBouncycastleUtilEncodersHex_decodeWithNSString_(@"00689918DBEC7E5A0DD6DFC0AA55C7"))];
  self->b_ = [self fromBigIntegerWithJavaMathBigInteger:new_JavaMathBigInteger_initWithInt_withByteArray_(1, LibOrgBouncycastleUtilEncodersHex_decodeWithNSString_(@"0095E9A9EC9B297BD4BF36E059184F"))];
  self->order_ = new_JavaMathBigInteger_initWithInt_withByteArray_(1, LibOrgBouncycastleUtilEncodersHex_decodeWithNSString_(@"010000000000000108789B2496AF93"));
  self->cofactor_ = JavaMathBigInteger_valueOfWithLong_(2);
  self->coord_ = LibOrgBouncycastleMathEcCustomSecSecT113R2Curve_SecT113R2_DEFAULT_COORDS;
}

LibOrgBouncycastleMathEcCustomSecSecT113R2Curve *new_LibOrgBouncycastleMathEcCustomSecSecT113R2Curve_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleMathEcCustomSecSecT113R2Curve, init)
}

LibOrgBouncycastleMathEcCustomSecSecT113R2Curve *create_LibOrgBouncycastleMathEcCustomSecSecT113R2Curve_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleMathEcCustomSecSecT113R2Curve, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleMathEcCustomSecSecT113R2Curve)

@implementation LibOrgBouncycastleMathEcCustomSecSecT113R2Curve_1

- (instancetype)initWithLibOrgBouncycastleMathEcCustomSecSecT113R2Curve:(LibOrgBouncycastleMathEcCustomSecSecT113R2Curve *)outer$
                                                                withInt:(jint)capture$0
                                                          withLongArray:(IOSLongArray *)capture$1 {
  LibOrgBouncycastleMathEcCustomSecSecT113R2Curve_1_initWithLibOrgBouncycastleMathEcCustomSecSecT113R2Curve_withInt_withLongArray_(self, outer$, capture$0, capture$1);
  return self;
}

- (jint)getSize {
  return val$len_;
}

- (LibOrgBouncycastleMathEcECPoint *)lookupWithInt:(jint)index {
  IOSLongArray *x = LibOrgBouncycastleMathRawNat128_create64();
  IOSLongArray *y = LibOrgBouncycastleMathRawNat128_create64();
  jint pos = 0;
  for (jint i = 0; i < val$len_; ++i) {
    jlong MASK = JreRShift32(((i ^ index) - 1), 31);
    for (jint j = 0; j < 2; ++j) {
      *IOSLongArray_GetRef(nil_chk(x), j) ^= IOSLongArray_Get(nil_chk(val$table_), pos + j) & MASK;
      *IOSLongArray_GetRef(nil_chk(y), j) ^= IOSLongArray_Get(val$table_, pos + 2 + j) & MASK;
    }
    pos += (2 * 2);
  }
  return [this$0_ createRawPointWithLibOrgBouncycastleMathEcECFieldElement:new_LibOrgBouncycastleMathEcCustomSecSecT113FieldElement_initWithLongArray_(x) withLibOrgBouncycastleMathEcECFieldElement:new_LibOrgBouncycastleMathEcCustomSecSecT113FieldElement_initWithLongArray_(y) withBoolean:false];
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
  methods[0].selector = @selector(initWithLibOrgBouncycastleMathEcCustomSecSecT113R2Curve:withInt:withLongArray:);
  methods[1].selector = @selector(getSize);
  methods[2].selector = @selector(lookupWithInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "this$0_", "LLibOrgBouncycastleMathEcCustomSecSecT113R2Curve;", .constantValue.asLong = 0, 0x1012, -1, -1, -1, -1 },
    { "val$len_", "I", .constantValue.asLong = 0, 0x1012, -1, -1, -1, -1 },
    { "val$table_", "[J", .constantValue.asLong = 0, 0x1012, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "lookup", "I", "LLibOrgBouncycastleMathEcCustomSecSecT113R2Curve;", "createCacheSafeLookupTableWithLibOrgBouncycastleMathEcECPointArray:withInt:withInt:" };
  static const J2ObjcClassInfo _LibOrgBouncycastleMathEcCustomSecSecT113R2Curve_1 = { "", "lib.org.bouncycastle.math.ec.custom.sec", ptrTable, methods, fields, 7, 0x8010, 3, 3, 2, -1, 3, -1, -1 };
  return &_LibOrgBouncycastleMathEcCustomSecSecT113R2Curve_1;
}

@end

void LibOrgBouncycastleMathEcCustomSecSecT113R2Curve_1_initWithLibOrgBouncycastleMathEcCustomSecSecT113R2Curve_withInt_withLongArray_(LibOrgBouncycastleMathEcCustomSecSecT113R2Curve_1 *self, LibOrgBouncycastleMathEcCustomSecSecT113R2Curve *outer$, jint capture$0, IOSLongArray *capture$1) {
  self->this$0_ = outer$;
  self->val$len_ = capture$0;
  self->val$table_ = capture$1;
  NSObject_init(self);
}

LibOrgBouncycastleMathEcCustomSecSecT113R2Curve_1 *new_LibOrgBouncycastleMathEcCustomSecSecT113R2Curve_1_initWithLibOrgBouncycastleMathEcCustomSecSecT113R2Curve_withInt_withLongArray_(LibOrgBouncycastleMathEcCustomSecSecT113R2Curve *outer$, jint capture$0, IOSLongArray *capture$1) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleMathEcCustomSecSecT113R2Curve_1, initWithLibOrgBouncycastleMathEcCustomSecSecT113R2Curve_withInt_withLongArray_, outer$, capture$0, capture$1)
}

LibOrgBouncycastleMathEcCustomSecSecT113R2Curve_1 *create_LibOrgBouncycastleMathEcCustomSecSecT113R2Curve_1_initWithLibOrgBouncycastleMathEcCustomSecSecT113R2Curve_withInt_withLongArray_(LibOrgBouncycastleMathEcCustomSecSecT113R2Curve *outer$, jint capture$0, IOSLongArray *capture$1) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleMathEcCustomSecSecT113R2Curve_1, initWithLibOrgBouncycastleMathEcCustomSecSecT113R2Curve_withInt_withLongArray_, outer$, capture$0, capture$1)
}
