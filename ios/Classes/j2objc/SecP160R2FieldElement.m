//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/math/ec/custom/sec/SecP160R2FieldElement.java
//

#include "Arrays.h"
#include "ECFieldElement.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "Mod.h"
#include "Nat160.h"
#include "SecP160R2Curve.h"
#include "SecP160R2Field.h"
#include "SecP160R2FieldElement.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/math/BigInteger.h"

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement)

JavaMathBigInteger *LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement_Q;

@implementation LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement

+ (JavaMathBigInteger *)Q {
  return LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement_Q;
}

- (instancetype)initWithJavaMathBigInteger:(JavaMathBigInteger *)x {
  LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement_initWithJavaMathBigInteger_(self, x);
  return self;
}

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (instancetype)initWithIntArray:(IOSIntArray *)x {
  LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement_initWithIntArray_(self, x);
  return self;
}

- (jboolean)isZero {
  return LibOrgBouncycastleMathRawNat160_isZeroWithIntArray_(x_);
}

- (jboolean)isOne {
  return LibOrgBouncycastleMathRawNat160_isOneWithIntArray_(x_);
}

- (jboolean)testBitZero {
  return LibOrgBouncycastleMathRawNat160_getBitWithIntArray_withInt_(x_, 0) == 1;
}

- (JavaMathBigInteger *)toBigInteger {
  return LibOrgBouncycastleMathRawNat160_toBigIntegerWithIntArray_(x_);
}

- (NSString *)getFieldName {
  return @"SecP160R2Field";
}

- (jint)getFieldSize {
  return [((JavaMathBigInteger *) nil_chk(LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement_Q)) bitLength];
}

- (LibOrgBouncycastleMathEcECFieldElement *)addWithLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)b {
  IOSIntArray *z = LibOrgBouncycastleMathRawNat160_create();
  LibOrgBouncycastleMathEcCustomSecSecP160R2Field_addWithIntArray_withIntArray_withIntArray_(x_, ((LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement *) nil_chk(((LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement *) cast_chk(b, [LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement class]))))->x_, z);
  return new_LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement_initWithIntArray_(z);
}

- (LibOrgBouncycastleMathEcECFieldElement *)addOne {
  IOSIntArray *z = LibOrgBouncycastleMathRawNat160_create();
  LibOrgBouncycastleMathEcCustomSecSecP160R2Field_addOneWithIntArray_withIntArray_(x_, z);
  return new_LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement_initWithIntArray_(z);
}

- (LibOrgBouncycastleMathEcECFieldElement *)subtractWithLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)b {
  IOSIntArray *z = LibOrgBouncycastleMathRawNat160_create();
  LibOrgBouncycastleMathEcCustomSecSecP160R2Field_subtractWithIntArray_withIntArray_withIntArray_(x_, ((LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement *) nil_chk(((LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement *) cast_chk(b, [LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement class]))))->x_, z);
  return new_LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement_initWithIntArray_(z);
}

- (LibOrgBouncycastleMathEcECFieldElement *)multiplyWithLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)b {
  IOSIntArray *z = LibOrgBouncycastleMathRawNat160_create();
  LibOrgBouncycastleMathEcCustomSecSecP160R2Field_multiplyWithIntArray_withIntArray_withIntArray_(x_, ((LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement *) nil_chk(((LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement *) cast_chk(b, [LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement class]))))->x_, z);
  return new_LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement_initWithIntArray_(z);
}

- (LibOrgBouncycastleMathEcECFieldElement *)divideWithLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)b {
  IOSIntArray *z = LibOrgBouncycastleMathRawNat160_create();
  LibOrgBouncycastleMathRawMod_invertWithIntArray_withIntArray_withIntArray_(JreLoadStatic(LibOrgBouncycastleMathEcCustomSecSecP160R2Field, P), ((LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement *) nil_chk(((LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement *) cast_chk(b, [LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement class]))))->x_, z);
  LibOrgBouncycastleMathEcCustomSecSecP160R2Field_multiplyWithIntArray_withIntArray_withIntArray_(z, x_, z);
  return new_LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement_initWithIntArray_(z);
}

- (LibOrgBouncycastleMathEcECFieldElement *)negate {
  IOSIntArray *z = LibOrgBouncycastleMathRawNat160_create();
  LibOrgBouncycastleMathEcCustomSecSecP160R2Field_negateWithIntArray_withIntArray_(x_, z);
  return new_LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement_initWithIntArray_(z);
}

- (LibOrgBouncycastleMathEcECFieldElement *)square {
  IOSIntArray *z = LibOrgBouncycastleMathRawNat160_create();
  LibOrgBouncycastleMathEcCustomSecSecP160R2Field_squareWithIntArray_withIntArray_(x_, z);
  return new_LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement_initWithIntArray_(z);
}

- (LibOrgBouncycastleMathEcECFieldElement *)invert {
  IOSIntArray *z = LibOrgBouncycastleMathRawNat160_create();
  LibOrgBouncycastleMathRawMod_invertWithIntArray_withIntArray_withIntArray_(JreLoadStatic(LibOrgBouncycastleMathEcCustomSecSecP160R2Field, P), x_, z);
  return new_LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement_initWithIntArray_(z);
}

- (LibOrgBouncycastleMathEcECFieldElement *)sqrt {
  IOSIntArray *x1 = self->x_;
  if (LibOrgBouncycastleMathRawNat160_isZeroWithIntArray_(x1) || LibOrgBouncycastleMathRawNat160_isOneWithIntArray_(x1)) {
    return self;
  }
  IOSIntArray *x2 = LibOrgBouncycastleMathRawNat160_create();
  LibOrgBouncycastleMathEcCustomSecSecP160R2Field_squareWithIntArray_withIntArray_(x1, x2);
  LibOrgBouncycastleMathEcCustomSecSecP160R2Field_multiplyWithIntArray_withIntArray_withIntArray_(x2, x1, x2);
  IOSIntArray *x3 = LibOrgBouncycastleMathRawNat160_create();
  LibOrgBouncycastleMathEcCustomSecSecP160R2Field_squareWithIntArray_withIntArray_(x2, x3);
  LibOrgBouncycastleMathEcCustomSecSecP160R2Field_multiplyWithIntArray_withIntArray_withIntArray_(x3, x1, x3);
  IOSIntArray *x4 = LibOrgBouncycastleMathRawNat160_create();
  LibOrgBouncycastleMathEcCustomSecSecP160R2Field_squareWithIntArray_withIntArray_(x3, x4);
  LibOrgBouncycastleMathEcCustomSecSecP160R2Field_multiplyWithIntArray_withIntArray_withIntArray_(x4, x1, x4);
  IOSIntArray *x7 = LibOrgBouncycastleMathRawNat160_create();
  LibOrgBouncycastleMathEcCustomSecSecP160R2Field_squareNWithIntArray_withInt_withIntArray_(x4, 3, x7);
  LibOrgBouncycastleMathEcCustomSecSecP160R2Field_multiplyWithIntArray_withIntArray_withIntArray_(x7, x3, x7);
  IOSIntArray *x14 = x4;
  LibOrgBouncycastleMathEcCustomSecSecP160R2Field_squareNWithIntArray_withInt_withIntArray_(x7, 7, x14);
  LibOrgBouncycastleMathEcCustomSecSecP160R2Field_multiplyWithIntArray_withIntArray_withIntArray_(x14, x7, x14);
  IOSIntArray *x17 = x7;
  LibOrgBouncycastleMathEcCustomSecSecP160R2Field_squareNWithIntArray_withInt_withIntArray_(x14, 3, x17);
  LibOrgBouncycastleMathEcCustomSecSecP160R2Field_multiplyWithIntArray_withIntArray_withIntArray_(x17, x3, x17);
  IOSIntArray *x31 = LibOrgBouncycastleMathRawNat160_create();
  LibOrgBouncycastleMathEcCustomSecSecP160R2Field_squareNWithIntArray_withInt_withIntArray_(x17, 14, x31);
  LibOrgBouncycastleMathEcCustomSecSecP160R2Field_multiplyWithIntArray_withIntArray_withIntArray_(x31, x14, x31);
  IOSIntArray *x62 = x14;
  LibOrgBouncycastleMathEcCustomSecSecP160R2Field_squareNWithIntArray_withInt_withIntArray_(x31, 31, x62);
  LibOrgBouncycastleMathEcCustomSecSecP160R2Field_multiplyWithIntArray_withIntArray_withIntArray_(x62, x31, x62);
  IOSIntArray *x124 = x31;
  LibOrgBouncycastleMathEcCustomSecSecP160R2Field_squareNWithIntArray_withInt_withIntArray_(x62, 62, x124);
  LibOrgBouncycastleMathEcCustomSecSecP160R2Field_multiplyWithIntArray_withIntArray_withIntArray_(x124, x62, x124);
  IOSIntArray *x127 = x62;
  LibOrgBouncycastleMathEcCustomSecSecP160R2Field_squareNWithIntArray_withInt_withIntArray_(x124, 3, x127);
  LibOrgBouncycastleMathEcCustomSecSecP160R2Field_multiplyWithIntArray_withIntArray_withIntArray_(x127, x3, x127);
  IOSIntArray *t1 = x127;
  LibOrgBouncycastleMathEcCustomSecSecP160R2Field_squareNWithIntArray_withInt_withIntArray_(t1, 18, t1);
  LibOrgBouncycastleMathEcCustomSecSecP160R2Field_multiplyWithIntArray_withIntArray_withIntArray_(t1, x17, t1);
  LibOrgBouncycastleMathEcCustomSecSecP160R2Field_squareNWithIntArray_withInt_withIntArray_(t1, 2, t1);
  LibOrgBouncycastleMathEcCustomSecSecP160R2Field_multiplyWithIntArray_withIntArray_withIntArray_(t1, x1, t1);
  LibOrgBouncycastleMathEcCustomSecSecP160R2Field_squareNWithIntArray_withInt_withIntArray_(t1, 3, t1);
  LibOrgBouncycastleMathEcCustomSecSecP160R2Field_multiplyWithIntArray_withIntArray_withIntArray_(t1, x2, t1);
  LibOrgBouncycastleMathEcCustomSecSecP160R2Field_squareNWithIntArray_withInt_withIntArray_(t1, 6, t1);
  LibOrgBouncycastleMathEcCustomSecSecP160R2Field_multiplyWithIntArray_withIntArray_withIntArray_(t1, x3, t1);
  LibOrgBouncycastleMathEcCustomSecSecP160R2Field_squareNWithIntArray_withInt_withIntArray_(t1, 2, t1);
  LibOrgBouncycastleMathEcCustomSecSecP160R2Field_multiplyWithIntArray_withIntArray_withIntArray_(t1, x1, t1);
  IOSIntArray *t2 = x2;
  LibOrgBouncycastleMathEcCustomSecSecP160R2Field_squareWithIntArray_withIntArray_(t1, t2);
  return LibOrgBouncycastleMathRawNat160_eqWithIntArray_withIntArray_(x1, t2) ? new_LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement_initWithIntArray_(t1) : nil;
}

- (jboolean)isEqual:(id)other {
  if (other == self) {
    return true;
  }
  if (!([other isKindOfClass:[LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement class]])) {
    return false;
  }
  LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement *o = (LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement *) cast_chk(other, [LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement class]);
  return LibOrgBouncycastleMathRawNat160_eqWithIntArray_withIntArray_(x_, ((LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement *) nil_chk(o))->x_);
}

- (NSUInteger)hash {
  return ((jint) [((JavaMathBigInteger *) nil_chk(LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement_Q)) hash]) ^ LibOrgBouncycastleUtilArrays_hashCodeWithIntArray_withInt_withInt_(x_, 0, 5);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, NULL, 0x4, -1, 1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECFieldElement;", 0x1, 2, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECFieldElement;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECFieldElement;", 0x1, 4, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECFieldElement;", 0x1, 5, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECFieldElement;", 0x1, 6, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECFieldElement;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECFieldElement;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECFieldElement;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECFieldElement;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 7, 8, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 9, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithJavaMathBigInteger:);
  methods[1].selector = @selector(init);
  methods[2].selector = @selector(initWithIntArray:);
  methods[3].selector = @selector(isZero);
  methods[4].selector = @selector(isOne);
  methods[5].selector = @selector(testBitZero);
  methods[6].selector = @selector(toBigInteger);
  methods[7].selector = @selector(getFieldName);
  methods[8].selector = @selector(getFieldSize);
  methods[9].selector = @selector(addWithLibOrgBouncycastleMathEcECFieldElement:);
  methods[10].selector = @selector(addOne);
  methods[11].selector = @selector(subtractWithLibOrgBouncycastleMathEcECFieldElement:);
  methods[12].selector = @selector(multiplyWithLibOrgBouncycastleMathEcECFieldElement:);
  methods[13].selector = @selector(divideWithLibOrgBouncycastleMathEcECFieldElement:);
  methods[14].selector = @selector(negate);
  methods[15].selector = @selector(square);
  methods[16].selector = @selector(invert);
  methods[17].selector = @selector(sqrt);
  methods[18].selector = @selector(isEqual:);
  methods[19].selector = @selector(hash);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "Q", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x19, -1, 10, -1, -1 },
    { "x_", "[I", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaMathBigInteger;", "[I", "add", "LLibOrgBouncycastleMathEcECFieldElement;", "subtract", "multiply", "divide", "equals", "LNSObject;", "hashCode", &LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement_Q };
  static const J2ObjcClassInfo _LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement = { "SecP160R2FieldElement", "lib.org.bouncycastle.math.ec.custom.sec", ptrTable, methods, fields, 7, 0x1, 20, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement class]) {
    LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement_Q = JreLoadStatic(LibOrgBouncycastleMathEcCustomSecSecP160R2Curve, q);
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement)
  }
}

@end

void LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement_initWithJavaMathBigInteger_(LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement *self, JavaMathBigInteger *x) {
  LibOrgBouncycastleMathEcECFieldElement_AbstractFp_init(self);
  if (x == nil || [x signum] < 0 || [x compareToWithId:LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement_Q] >= 0) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"x value invalid for SecP160R2FieldElement");
  }
  self->x_ = LibOrgBouncycastleMathEcCustomSecSecP160R2Field_fromBigIntegerWithJavaMathBigInteger_(x);
}

LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement *new_LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement_initWithJavaMathBigInteger_(JavaMathBigInteger *x) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement, initWithJavaMathBigInteger_, x)
}

LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement *create_LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement_initWithJavaMathBigInteger_(JavaMathBigInteger *x) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement, initWithJavaMathBigInteger_, x)
}

void LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement_init(LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement *self) {
  LibOrgBouncycastleMathEcECFieldElement_AbstractFp_init(self);
  self->x_ = LibOrgBouncycastleMathRawNat160_create();
}

LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement *new_LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement, init)
}

LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement *create_LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement, init)
}

void LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement_initWithIntArray_(LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement *self, IOSIntArray *x) {
  LibOrgBouncycastleMathEcECFieldElement_AbstractFp_init(self);
  self->x_ = x;
}

LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement *new_LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement_initWithIntArray_(IOSIntArray *x) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement, initWithIntArray_, x)
}

LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement *create_LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement_initWithIntArray_(IOSIntArray *x) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement, initWithIntArray_, x)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleMathEcCustomSecSecP160R2FieldElement)