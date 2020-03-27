//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/math/ec/custom/sec/SecT233Field.java
//

#ifndef SecT233Field_H
#define SecT233Field_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSLongArray;
@class JavaMathBigInteger;

@interface LibOrgBouncycastleMathEcCustomSecSecT233Field : NSObject

#pragma mark Public

- (instancetype __nonnull)init;

+ (void)addWithLongArray:(IOSLongArray *)x
           withLongArray:(IOSLongArray *)y
           withLongArray:(IOSLongArray *)z;

+ (void)addExtWithLongArray:(IOSLongArray *)xx
              withLongArray:(IOSLongArray *)yy
              withLongArray:(IOSLongArray *)zz;

+ (void)addOneWithLongArray:(IOSLongArray *)x
              withLongArray:(IOSLongArray *)z;

+ (IOSLongArray *)fromBigIntegerWithJavaMathBigInteger:(JavaMathBigInteger *)x;

+ (void)invertWithLongArray:(IOSLongArray *)x
              withLongArray:(IOSLongArray *)z;

+ (void)multiplyWithLongArray:(IOSLongArray *)x
                withLongArray:(IOSLongArray *)y
                withLongArray:(IOSLongArray *)z;

+ (void)multiplyAddToExtWithLongArray:(IOSLongArray *)x
                        withLongArray:(IOSLongArray *)y
                        withLongArray:(IOSLongArray *)zz;

+ (void)reduceWithLongArray:(IOSLongArray *)xx
              withLongArray:(IOSLongArray *)z;

+ (void)reduce23WithLongArray:(IOSLongArray *)z
                      withInt:(jint)zOff;

+ (void)sqrtWithLongArray:(IOSLongArray *)x
            withLongArray:(IOSLongArray *)z;

+ (void)squareWithLongArray:(IOSLongArray *)x
              withLongArray:(IOSLongArray *)z;

+ (void)squareAddToExtWithLongArray:(IOSLongArray *)x
                      withLongArray:(IOSLongArray *)zz;

+ (void)squareNWithLongArray:(IOSLongArray *)x
                     withInt:(jint)n
               withLongArray:(IOSLongArray *)z;

+ (jint)traceWithLongArray:(IOSLongArray *)x;

#pragma mark Protected

+ (void)implCompactExtWithLongArray:(IOSLongArray *)zz;

+ (void)implExpandWithLongArray:(IOSLongArray *)x
                  withLongArray:(IOSLongArray *)z;

+ (void)implMultiplyWithLongArray:(IOSLongArray *)x
                    withLongArray:(IOSLongArray *)y
                    withLongArray:(IOSLongArray *)zz;

+ (void)implMulwAccWithLong:(jlong)x
                   withLong:(jlong)y
              withLongArray:(IOSLongArray *)z
                    withInt:(jint)zOff;

+ (void)implSquareWithLongArray:(IOSLongArray *)x
                  withLongArray:(IOSLongArray *)zz;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleMathEcCustomSecSecT233Field)

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcCustomSecSecT233Field_init(LibOrgBouncycastleMathEcCustomSecSecT233Field *self);

FOUNDATION_EXPORT LibOrgBouncycastleMathEcCustomSecSecT233Field *new_LibOrgBouncycastleMathEcCustomSecSecT233Field_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleMathEcCustomSecSecT233Field *create_LibOrgBouncycastleMathEcCustomSecSecT233Field_init(void);

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcCustomSecSecT233Field_addWithLongArray_withLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *y, IOSLongArray *z);

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcCustomSecSecT233Field_addExtWithLongArray_withLongArray_withLongArray_(IOSLongArray *xx, IOSLongArray *yy, IOSLongArray *zz);

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcCustomSecSecT233Field_addOneWithLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *z);

FOUNDATION_EXPORT IOSLongArray *LibOrgBouncycastleMathEcCustomSecSecT233Field_fromBigIntegerWithJavaMathBigInteger_(JavaMathBigInteger *x);

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcCustomSecSecT233Field_invertWithLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *z);

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcCustomSecSecT233Field_multiplyWithLongArray_withLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *y, IOSLongArray *z);

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcCustomSecSecT233Field_multiplyAddToExtWithLongArray_withLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *y, IOSLongArray *zz);

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcCustomSecSecT233Field_reduceWithLongArray_withLongArray_(IOSLongArray *xx, IOSLongArray *z);

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcCustomSecSecT233Field_reduce23WithLongArray_withInt_(IOSLongArray *z, jint zOff);

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcCustomSecSecT233Field_sqrtWithLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *z);

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcCustomSecSecT233Field_squareWithLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *z);

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcCustomSecSecT233Field_squareAddToExtWithLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *zz);

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcCustomSecSecT233Field_squareNWithLongArray_withInt_withLongArray_(IOSLongArray *x, jint n, IOSLongArray *z);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathEcCustomSecSecT233Field_traceWithLongArray_(IOSLongArray *x);

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcCustomSecSecT233Field_implCompactExtWithLongArray_(IOSLongArray *zz);

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcCustomSecSecT233Field_implExpandWithLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *z);

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcCustomSecSecT233Field_implMultiplyWithLongArray_withLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *y, IOSLongArray *zz);

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcCustomSecSecT233Field_implMulwAccWithLong_withLong_withLongArray_withInt_(jlong x, jlong y, IOSLongArray *z, jint zOff);

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcCustomSecSecT233Field_implSquareWithLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *zz);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleMathEcCustomSecSecT233Field)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // SecT233Field_H