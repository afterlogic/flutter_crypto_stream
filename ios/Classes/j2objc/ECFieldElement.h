//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/math/ec/ECFieldElement.java
//

#ifndef ECFieldElement_H
#define ECFieldElement_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ECConstants.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@class IOSIntArray;
@class JavaMathBigInteger;
@class LibOrgBouncycastleMathEcLongArray;

@interface LibOrgBouncycastleMathEcECFieldElement : NSObject < LibOrgBouncycastleMathEcECConstants >

#pragma mark Public

- (instancetype __nonnull)init;

- (LibOrgBouncycastleMathEcECFieldElement *)addWithLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)b;

- (LibOrgBouncycastleMathEcECFieldElement *)addOne;

- (jint)bitLength;

- (LibOrgBouncycastleMathEcECFieldElement *)divideWithLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)b;

- (IOSByteArray *)getEncoded;

- (NSString *)getFieldName;

- (jint)getFieldSize;

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

- (NSString *)description;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleMathEcECFieldElement)

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcECFieldElement_init(LibOrgBouncycastleMathEcECFieldElement *self);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleMathEcECFieldElement)

@interface LibOrgBouncycastleMathEcECFieldElement_AbstractFp : LibOrgBouncycastleMathEcECFieldElement

#pragma mark Public

- (instancetype __nonnull)init;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleMathEcECFieldElement_AbstractFp)

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcECFieldElement_AbstractFp_init(LibOrgBouncycastleMathEcECFieldElement_AbstractFp *self);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleMathEcECFieldElement_AbstractFp)

@interface LibOrgBouncycastleMathEcECFieldElement_Fp : LibOrgBouncycastleMathEcECFieldElement_AbstractFp {
 @public
  JavaMathBigInteger *q_;
  JavaMathBigInteger *r_;
  JavaMathBigInteger *x_;
}

#pragma mark Public

- (instancetype __nonnull)initWithJavaMathBigInteger:(JavaMathBigInteger *)q
                              withJavaMathBigInteger:(JavaMathBigInteger *)x;

- (LibOrgBouncycastleMathEcECFieldElement *)addWithLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)b;

- (LibOrgBouncycastleMathEcECFieldElement *)addOne;

- (LibOrgBouncycastleMathEcECFieldElement *)divideWithLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)b;

- (jboolean)isEqual:(id)other;

- (NSString *)getFieldName;

- (jint)getFieldSize;

- (JavaMathBigInteger *)getQ;

- (NSUInteger)hash;

- (LibOrgBouncycastleMathEcECFieldElement *)invert;

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

- (LibOrgBouncycastleMathEcECFieldElement *)subtractWithLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)b;

- (JavaMathBigInteger *)toBigInteger;

#pragma mark Protected

- (JavaMathBigInteger *)modAddWithJavaMathBigInteger:(JavaMathBigInteger *)x1
                              withJavaMathBigInteger:(JavaMathBigInteger *)x2;

- (JavaMathBigInteger *)modDoubleWithJavaMathBigInteger:(JavaMathBigInteger *)x;

- (JavaMathBigInteger *)modHalfWithJavaMathBigInteger:(JavaMathBigInteger *)x;

- (JavaMathBigInteger *)modHalfAbsWithJavaMathBigInteger:(JavaMathBigInteger *)x;

- (JavaMathBigInteger *)modInverseWithJavaMathBigInteger:(JavaMathBigInteger *)x;

- (JavaMathBigInteger *)modMultWithJavaMathBigInteger:(JavaMathBigInteger *)x1
                               withJavaMathBigInteger:(JavaMathBigInteger *)x2;

- (JavaMathBigInteger *)modReduceWithJavaMathBigInteger:(JavaMathBigInteger *)x;

- (JavaMathBigInteger *)modSubtractWithJavaMathBigInteger:(JavaMathBigInteger *)x1
                                   withJavaMathBigInteger:(JavaMathBigInteger *)x2;

#pragma mark Package-Private

- (instancetype __nonnull)initWithJavaMathBigInteger:(JavaMathBigInteger *)q
                              withJavaMathBigInteger:(JavaMathBigInteger *)r
                              withJavaMathBigInteger:(JavaMathBigInteger *)x;

+ (JavaMathBigInteger *)calculateResidueWithJavaMathBigInteger:(JavaMathBigInteger *)p;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleMathEcECFieldElement_Fp)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleMathEcECFieldElement_Fp, q_, JavaMathBigInteger *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleMathEcECFieldElement_Fp, r_, JavaMathBigInteger *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleMathEcECFieldElement_Fp, x_, JavaMathBigInteger *)

FOUNDATION_EXPORT JavaMathBigInteger *LibOrgBouncycastleMathEcECFieldElement_Fp_calculateResidueWithJavaMathBigInteger_(JavaMathBigInteger *p);

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcECFieldElement_Fp_initWithJavaMathBigInteger_withJavaMathBigInteger_(LibOrgBouncycastleMathEcECFieldElement_Fp *self, JavaMathBigInteger *q, JavaMathBigInteger *x);

FOUNDATION_EXPORT LibOrgBouncycastleMathEcECFieldElement_Fp *new_LibOrgBouncycastleMathEcECFieldElement_Fp_initWithJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *q, JavaMathBigInteger *x) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleMathEcECFieldElement_Fp *create_LibOrgBouncycastleMathEcECFieldElement_Fp_initWithJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *q, JavaMathBigInteger *x);

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcECFieldElement_Fp_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(LibOrgBouncycastleMathEcECFieldElement_Fp *self, JavaMathBigInteger *q, JavaMathBigInteger *r, JavaMathBigInteger *x);

FOUNDATION_EXPORT LibOrgBouncycastleMathEcECFieldElement_Fp *new_LibOrgBouncycastleMathEcECFieldElement_Fp_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *q, JavaMathBigInteger *r, JavaMathBigInteger *x) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleMathEcECFieldElement_Fp *create_LibOrgBouncycastleMathEcECFieldElement_Fp_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *q, JavaMathBigInteger *r, JavaMathBigInteger *x);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleMathEcECFieldElement_Fp)

@interface LibOrgBouncycastleMathEcECFieldElement_AbstractF2m : LibOrgBouncycastleMathEcECFieldElement

#pragma mark Public

- (instancetype __nonnull)init;

- (LibOrgBouncycastleMathEcECFieldElement *)halfTrace;

- (jint)trace;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleMathEcECFieldElement_AbstractF2m)

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcECFieldElement_AbstractF2m_init(LibOrgBouncycastleMathEcECFieldElement_AbstractF2m *self);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleMathEcECFieldElement_AbstractF2m)

@interface LibOrgBouncycastleMathEcECFieldElement_F2m : LibOrgBouncycastleMathEcECFieldElement_AbstractF2m {
 @public
  LibOrgBouncycastleMathEcLongArray *x_;
}
@property (readonly, class) jint GNB NS_SWIFT_NAME(GNB);
@property (readonly, class) jint TPB NS_SWIFT_NAME(TPB);
@property (readonly, class) jint PPB NS_SWIFT_NAME(PPB);

+ (jint)GNB;

+ (jint)TPB;

+ (jint)PPB;

#pragma mark Public

- (instancetype __nonnull)initWithInt:(jint)m
                              withInt:(jint)k1
                              withInt:(jint)k2
                              withInt:(jint)k3
               withJavaMathBigInteger:(JavaMathBigInteger *)x;

- (LibOrgBouncycastleMathEcECFieldElement *)addWithLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)b;

- (LibOrgBouncycastleMathEcECFieldElement *)addOne;

- (jint)bitLength;

+ (void)checkFieldElementsWithLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)a
                          withLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)b;

- (LibOrgBouncycastleMathEcECFieldElement *)divideWithLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)b;

- (jboolean)isEqual:(id)anObject;

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

#pragma mark Package-Private

- (instancetype __nonnull)initWithInt:(jint)m
                         withIntArray:(IOSIntArray *)ks
withLibOrgBouncycastleMathEcLongArray:(LibOrgBouncycastleMathEcLongArray *)x;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleMathEcECFieldElement_F2m)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleMathEcECFieldElement_F2m, x_, LibOrgBouncycastleMathEcLongArray *)

inline jint LibOrgBouncycastleMathEcECFieldElement_F2m_get_GNB(void);
#define LibOrgBouncycastleMathEcECFieldElement_F2m_GNB 1
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleMathEcECFieldElement_F2m, GNB, jint)

inline jint LibOrgBouncycastleMathEcECFieldElement_F2m_get_TPB(void);
#define LibOrgBouncycastleMathEcECFieldElement_F2m_TPB 2
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleMathEcECFieldElement_F2m, TPB, jint)

inline jint LibOrgBouncycastleMathEcECFieldElement_F2m_get_PPB(void);
#define LibOrgBouncycastleMathEcECFieldElement_F2m_PPB 3
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleMathEcECFieldElement_F2m, PPB, jint)

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcECFieldElement_F2m_initWithInt_withInt_withInt_withInt_withJavaMathBigInteger_(LibOrgBouncycastleMathEcECFieldElement_F2m *self, jint m, jint k1, jint k2, jint k3, JavaMathBigInteger *x);

FOUNDATION_EXPORT LibOrgBouncycastleMathEcECFieldElement_F2m *new_LibOrgBouncycastleMathEcECFieldElement_F2m_initWithInt_withInt_withInt_withInt_withJavaMathBigInteger_(jint m, jint k1, jint k2, jint k3, JavaMathBigInteger *x) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleMathEcECFieldElement_F2m *create_LibOrgBouncycastleMathEcECFieldElement_F2m_initWithInt_withInt_withInt_withInt_withJavaMathBigInteger_(jint m, jint k1, jint k2, jint k3, JavaMathBigInteger *x);

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcECFieldElement_F2m_initWithInt_withIntArray_withLibOrgBouncycastleMathEcLongArray_(LibOrgBouncycastleMathEcECFieldElement_F2m *self, jint m, IOSIntArray *ks, LibOrgBouncycastleMathEcLongArray *x);

FOUNDATION_EXPORT LibOrgBouncycastleMathEcECFieldElement_F2m *new_LibOrgBouncycastleMathEcECFieldElement_F2m_initWithInt_withIntArray_withLibOrgBouncycastleMathEcLongArray_(jint m, IOSIntArray *ks, LibOrgBouncycastleMathEcLongArray *x) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleMathEcECFieldElement_F2m *create_LibOrgBouncycastleMathEcECFieldElement_F2m_initWithInt_withIntArray_withLibOrgBouncycastleMathEcLongArray_(jint m, IOSIntArray *ks, LibOrgBouncycastleMathEcLongArray *x);

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcECFieldElement_F2m_checkFieldElementsWithLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElement_(LibOrgBouncycastleMathEcECFieldElement *a, LibOrgBouncycastleMathEcECFieldElement *b);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleMathEcECFieldElement_F2m)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ECFieldElement_H
