//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/math/ec/custom/sec/SecP128R1FieldElement.java
//

#ifndef SecP128R1FieldElement_H
#define SecP128R1FieldElement_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ECFieldElement.h"
#include "J2ObjC_header.h"

@class IOSIntArray;
@class JavaMathBigInteger;

@interface LibOrgBouncycastleMathEcCustomSecSecP128R1FieldElement : LibOrgBouncycastleMathEcECFieldElement_AbstractFp {
 @public
  IOSIntArray *x_;
}
@property (readonly, class) JavaMathBigInteger *Q NS_SWIFT_NAME(Q);

+ (JavaMathBigInteger *)Q;

#pragma mark Public

- (instancetype __nonnull)init;

- (instancetype __nonnull)initWithJavaMathBigInteger:(JavaMathBigInteger *)x;

- (LibOrgBouncycastleMathEcECFieldElement *)addWithLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)b;

- (LibOrgBouncycastleMathEcECFieldElement *)addOne;

- (LibOrgBouncycastleMathEcECFieldElement *)divideWithLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)b;

- (jboolean)isEqual:(id)other;

- (NSString *)getFieldName;

- (jint)getFieldSize;

- (NSUInteger)hash;

- (LibOrgBouncycastleMathEcECFieldElement *)invert;

- (jboolean)isOne;

- (jboolean)isZero;

- (LibOrgBouncycastleMathEcECFieldElement *)multiplyWithLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)b;

- (LibOrgBouncycastleMathEcECFieldElement *)negate;

- (LibOrgBouncycastleMathEcECFieldElement *)sqrt;

- (LibOrgBouncycastleMathEcECFieldElement *)square;

- (LibOrgBouncycastleMathEcECFieldElement *)subtractWithLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)b;

- (jboolean)testBitZero;

- (JavaMathBigInteger *)toBigInteger;

#pragma mark Protected

- (instancetype __nonnull)initWithIntArray:(IOSIntArray *)x;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleMathEcCustomSecSecP128R1FieldElement)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleMathEcCustomSecSecP128R1FieldElement, x_, IOSIntArray *)

inline JavaMathBigInteger *LibOrgBouncycastleMathEcCustomSecSecP128R1FieldElement_get_Q(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT JavaMathBigInteger *LibOrgBouncycastleMathEcCustomSecSecP128R1FieldElement_Q;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleMathEcCustomSecSecP128R1FieldElement, Q, JavaMathBigInteger *)

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcCustomSecSecP128R1FieldElement_initWithJavaMathBigInteger_(LibOrgBouncycastleMathEcCustomSecSecP128R1FieldElement *self, JavaMathBigInteger *x);

FOUNDATION_EXPORT LibOrgBouncycastleMathEcCustomSecSecP128R1FieldElement *new_LibOrgBouncycastleMathEcCustomSecSecP128R1FieldElement_initWithJavaMathBigInteger_(JavaMathBigInteger *x) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleMathEcCustomSecSecP128R1FieldElement *create_LibOrgBouncycastleMathEcCustomSecSecP128R1FieldElement_initWithJavaMathBigInteger_(JavaMathBigInteger *x);

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcCustomSecSecP128R1FieldElement_init(LibOrgBouncycastleMathEcCustomSecSecP128R1FieldElement *self);

FOUNDATION_EXPORT LibOrgBouncycastleMathEcCustomSecSecP128R1FieldElement *new_LibOrgBouncycastleMathEcCustomSecSecP128R1FieldElement_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleMathEcCustomSecSecP128R1FieldElement *create_LibOrgBouncycastleMathEcCustomSecSecP128R1FieldElement_init(void);

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcCustomSecSecP128R1FieldElement_initWithIntArray_(LibOrgBouncycastleMathEcCustomSecSecP128R1FieldElement *self, IOSIntArray *x);

FOUNDATION_EXPORT LibOrgBouncycastleMathEcCustomSecSecP128R1FieldElement *new_LibOrgBouncycastleMathEcCustomSecSecP128R1FieldElement_initWithIntArray_(IOSIntArray *x) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleMathEcCustomSecSecP128R1FieldElement *create_LibOrgBouncycastleMathEcCustomSecSecP128R1FieldElement_initWithIntArray_(IOSIntArray *x);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleMathEcCustomSecSecP128R1FieldElement)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // SecP128R1FieldElement_H
