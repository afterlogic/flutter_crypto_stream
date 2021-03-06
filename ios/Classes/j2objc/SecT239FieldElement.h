//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/math/ec/custom/sec/SecT239FieldElement.java
//

#ifndef SecT239FieldElement_H
#define SecT239FieldElement_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ECFieldElement.h"
#include "J2ObjC_header.h"

@class IOSLongArray;
@class JavaMathBigInteger;

@interface LibOrgBouncycastleMathEcCustomSecSecT239FieldElement : LibOrgBouncycastleMathEcECFieldElement_AbstractF2m {
 @public
  IOSLongArray *x_;
}

#pragma mark Public

- (instancetype __nonnull)init;

- (instancetype __nonnull)initWithJavaMathBigInteger:(JavaMathBigInteger *)x;

- (LibOrgBouncycastleMathEcECFieldElement *)addWithLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)b;

- (LibOrgBouncycastleMathEcECFieldElement *)addOne;

- (LibOrgBouncycastleMathEcECFieldElement *)divideWithLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)b;

- (jboolean)isEqual:(id)other;

- (NSString *)getFieldName;

- (jint)getFieldSize;

- (jint)getK1;

- (jint)getK2;

- (jint)getK3;

- (jint)getM;

- (jint)getRepresentation;

- (NSUInteger)hash;

- (LibOrgBouncycastleMathEcECFieldElement *)invert;

- (jboolean)isOne;

- (jboolean)isZero;

- (LibOrgBouncycastleMathEcECFieldElement *)multiplyWithLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)b;

- (LibOrgBouncycastleMathEcECFieldElement *)multiplyMinusProductWithLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)b
                                                                withLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)x
                                                                withLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)y;

- (LibOrgBouncycastleMathEcECFieldElement *)multiplyPlusProductWithLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)b
                                                               withLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)x
                                                               withLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)y;

- (LibOrgBouncycastleMathEcECFieldElement *)negate;

- (LibOrgBouncycastleMathEcECFieldElement *)sqrt;

- (LibOrgBouncycastleMathEcECFieldElement *)square;

- (LibOrgBouncycastleMathEcECFieldElement *)squareMinusProductWithLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)x
                                                              withLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)y;

- (LibOrgBouncycastleMathEcECFieldElement *)squarePlusProductWithLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)x
                                                             withLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)y;

- (LibOrgBouncycastleMathEcECFieldElement *)squarePowWithInt:(jint)pow;

- (LibOrgBouncycastleMathEcECFieldElement *)subtractWithLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)b;

- (jboolean)testBitZero;

- (JavaMathBigInteger *)toBigInteger;

- (jint)trace;

#pragma mark Protected

- (instancetype __nonnull)initWithLongArray:(IOSLongArray *)x;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleMathEcCustomSecSecT239FieldElement)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleMathEcCustomSecSecT239FieldElement, x_, IOSLongArray *)

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcCustomSecSecT239FieldElement_initWithJavaMathBigInteger_(LibOrgBouncycastleMathEcCustomSecSecT239FieldElement *self, JavaMathBigInteger *x);

FOUNDATION_EXPORT LibOrgBouncycastleMathEcCustomSecSecT239FieldElement *new_LibOrgBouncycastleMathEcCustomSecSecT239FieldElement_initWithJavaMathBigInteger_(JavaMathBigInteger *x) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleMathEcCustomSecSecT239FieldElement *create_LibOrgBouncycastleMathEcCustomSecSecT239FieldElement_initWithJavaMathBigInteger_(JavaMathBigInteger *x);

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcCustomSecSecT239FieldElement_init(LibOrgBouncycastleMathEcCustomSecSecT239FieldElement *self);

FOUNDATION_EXPORT LibOrgBouncycastleMathEcCustomSecSecT239FieldElement *new_LibOrgBouncycastleMathEcCustomSecSecT239FieldElement_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleMathEcCustomSecSecT239FieldElement *create_LibOrgBouncycastleMathEcCustomSecSecT239FieldElement_init(void);

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcCustomSecSecT239FieldElement_initWithLongArray_(LibOrgBouncycastleMathEcCustomSecSecT239FieldElement *self, IOSLongArray *x);

FOUNDATION_EXPORT LibOrgBouncycastleMathEcCustomSecSecT239FieldElement *new_LibOrgBouncycastleMathEcCustomSecSecT239FieldElement_initWithLongArray_(IOSLongArray *x) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleMathEcCustomSecSecT239FieldElement *create_LibOrgBouncycastleMathEcCustomSecSecT239FieldElement_initWithLongArray_(IOSLongArray *x);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleMathEcCustomSecSecT239FieldElement)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // SecT239FieldElement_H
