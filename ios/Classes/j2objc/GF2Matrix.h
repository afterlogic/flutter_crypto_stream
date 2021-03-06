//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/math/linearalgebra/GF2Matrix.java
//

#ifndef GF2Matrix_H
#define GF2Matrix_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "Matrix.h"

@class IOSByteArray;
@class IOSIntArray;
@class IOSObjectArray;
@class JavaSecuritySecureRandom;
@class LibOrgBouncycastlePqcMathLinearalgebraPermutation;
@class LibOrgBouncycastlePqcMathLinearalgebraVector;

@interface LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix : LibOrgBouncycastlePqcMathLinearalgebraMatrix

#pragma mark Public

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)enc;

- (instancetype __nonnull)initWithLibOrgBouncycastlePqcMathLinearalgebraGF2Matrix:(LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix *)a;

- (instancetype __nonnull)initWithInt:(jint)n
                             withChar:(jchar)typeOfMatrix;

- (instancetype __nonnull)initWithInt:(jint)n
                             withChar:(jchar)typeOfMatrix
         withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)sr;

- (instancetype __nonnull)initWithInt:(jint)numColumns
                        withIntArray2:(IOSObjectArray *)matrix;

- (LibOrgBouncycastlePqcMathLinearalgebraMatrix *)computeInverse;

- (LibOrgBouncycastlePqcMathLinearalgebraMatrix *)computeTranspose;

+ (IOSObjectArray *)createRandomRegularMatrixAndItsInverseWithInt:(jint)n
                                     withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)sr;

- (jboolean)isEqual:(id)other;

- (LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix *)extendLeftCompactForm;

- (LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix *)extendRightCompactForm;

- (IOSByteArray *)getEncoded;

- (jdouble)getHammingWeight;

- (IOSObjectArray *)getIntArray;

- (LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix *)getLeftSubMatrix;

- (jint)getLength;

- (LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix *)getRightSubMatrix;

- (IOSIntArray *)getRowWithInt:(jint)index;

- (NSUInteger)hash;

- (jboolean)isZero;

- (LibOrgBouncycastlePqcMathLinearalgebraMatrix *)leftMultiplyWithLibOrgBouncycastlePqcMathLinearalgebraPermutation:(LibOrgBouncycastlePqcMathLinearalgebraPermutation *)p;

- (LibOrgBouncycastlePqcMathLinearalgebraVector *)leftMultiplyWithLibOrgBouncycastlePqcMathLinearalgebraVector:(LibOrgBouncycastlePqcMathLinearalgebraVector *)vec;

- (LibOrgBouncycastlePqcMathLinearalgebraVector *)leftMultiplyLeftCompactFormWithLibOrgBouncycastlePqcMathLinearalgebraVector:(LibOrgBouncycastlePqcMathLinearalgebraVector *)vec;

- (LibOrgBouncycastlePqcMathLinearalgebraMatrix *)rightMultiplyWithLibOrgBouncycastlePqcMathLinearalgebraMatrix:(LibOrgBouncycastlePqcMathLinearalgebraMatrix *)mat;

- (LibOrgBouncycastlePqcMathLinearalgebraMatrix *)rightMultiplyWithLibOrgBouncycastlePqcMathLinearalgebraPermutation:(LibOrgBouncycastlePqcMathLinearalgebraPermutation *)p;

- (LibOrgBouncycastlePqcMathLinearalgebraVector *)rightMultiplyWithLibOrgBouncycastlePqcMathLinearalgebraVector:(LibOrgBouncycastlePqcMathLinearalgebraVector *)vec;

- (LibOrgBouncycastlePqcMathLinearalgebraVector *)rightMultiplyRightCompactFormWithLibOrgBouncycastlePqcMathLinearalgebraVector:(LibOrgBouncycastlePqcMathLinearalgebraVector *)vec;

- (NSString *)description;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix_initWithByteArray_(LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix *self, IOSByteArray *enc);

FOUNDATION_EXPORT LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix *new_LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix_initWithByteArray_(IOSByteArray *enc) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix *create_LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix_initWithByteArray_(IOSByteArray *enc);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix_initWithInt_withIntArray2_(LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix *self, jint numColumns, IOSObjectArray *matrix);

FOUNDATION_EXPORT LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix *new_LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix_initWithInt_withIntArray2_(jint numColumns, IOSObjectArray *matrix) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix *create_LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix_initWithInt_withIntArray2_(jint numColumns, IOSObjectArray *matrix);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix_initWithInt_withChar_(LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix *self, jint n, jchar typeOfMatrix);

FOUNDATION_EXPORT LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix *new_LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix_initWithInt_withChar_(jint n, jchar typeOfMatrix) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix *create_LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix_initWithInt_withChar_(jint n, jchar typeOfMatrix);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix_initWithInt_withChar_withJavaSecuritySecureRandom_(LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix *self, jint n, jchar typeOfMatrix, JavaSecuritySecureRandom *sr);

FOUNDATION_EXPORT LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix *new_LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix_initWithInt_withChar_withJavaSecuritySecureRandom_(jint n, jchar typeOfMatrix, JavaSecuritySecureRandom *sr) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix *create_LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix_initWithInt_withChar_withJavaSecuritySecureRandom_(jint n, jchar typeOfMatrix, JavaSecuritySecureRandom *sr);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix_initWithLibOrgBouncycastlePqcMathLinearalgebraGF2Matrix_(LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix *self, LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix *a);

FOUNDATION_EXPORT LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix *new_LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix_initWithLibOrgBouncycastlePqcMathLinearalgebraGF2Matrix_(LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix *a) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix *create_LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix_initWithLibOrgBouncycastlePqcMathLinearalgebraGF2Matrix_(LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix *a);

FOUNDATION_EXPORT IOSObjectArray *LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix_createRandomRegularMatrixAndItsInverseWithInt_withJavaSecuritySecureRandom_(jint n, JavaSecuritySecureRandom *sr);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // GF2Matrix_H
