//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/math/linearalgebra/CharUtils.java
//

#ifndef CharUtils_H
#define CharUtils_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;
@class IOSCharArray;

@interface LibOrgBouncycastlePqcMathLinearalgebraCharUtils : NSObject

#pragma mark Public

+ (IOSCharArray *)cloneWithCharArray:(IOSCharArray *)array;

+ (jboolean)equalsWithCharArray:(IOSCharArray *)left
                  withCharArray:(IOSCharArray *)right;

+ (IOSByteArray *)toByteArrayWithCharArray:(IOSCharArray *)chars;

+ (IOSByteArray *)toByteArrayForPBEWithCharArray:(IOSCharArray *)chars;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcMathLinearalgebraCharUtils)

FOUNDATION_EXPORT IOSCharArray *LibOrgBouncycastlePqcMathLinearalgebraCharUtils_cloneWithCharArray_(IOSCharArray *array);

FOUNDATION_EXPORT IOSByteArray *LibOrgBouncycastlePqcMathLinearalgebraCharUtils_toByteArrayWithCharArray_(IOSCharArray *chars);

FOUNDATION_EXPORT IOSByteArray *LibOrgBouncycastlePqcMathLinearalgebraCharUtils_toByteArrayForPBEWithCharArray_(IOSCharArray *chars);

FOUNDATION_EXPORT jboolean LibOrgBouncycastlePqcMathLinearalgebraCharUtils_equalsWithCharArray_withCharArray_(IOSCharArray *left, IOSCharArray *right);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcMathLinearalgebraCharUtils)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // CharUtils_H
