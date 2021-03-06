//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/math/linearalgebra/ByteUtils.java
//

#ifndef ByteUtils_H
#define ByteUtils_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;
@class IOSCharArray;
@class IOSObjectArray;

@interface LibOrgBouncycastlePqcMathLinearalgebraByteUtils : NSObject

#pragma mark Public

+ (IOSByteArray *)cloneWithByteArray:(IOSByteArray *)array;

+ (IOSByteArray *)concatenateWithByteArray:(IOSByteArray *)x1
                             withByteArray:(IOSByteArray *)x2;

+ (IOSByteArray *)concatenateWithByteArray2:(IOSObjectArray *)array;

+ (jint)deepHashCodeWithByteArray:(IOSByteArray *)array;

+ (jint)deepHashCodeWithByteArray2:(IOSObjectArray *)array;

+ (jint)deepHashCodeWithByteArray3:(IOSObjectArray *)array;

+ (jboolean)equalsWithByteArray:(IOSByteArray *)left
                  withByteArray:(IOSByteArray *)right;

+ (jboolean)equalsWithByteArray2:(IOSObjectArray *)left
                  withByteArray2:(IOSObjectArray *)right;

+ (jboolean)equalsWithByteArray3:(IOSObjectArray *)left
                  withByteArray3:(IOSObjectArray *)right;

+ (IOSByteArray *)fromHexStringWithNSString:(NSString *)s;

+ (IOSObjectArray *)splitWithByteArray:(IOSByteArray *)input
                               withInt:(jint)index;

+ (IOSByteArray *)subArrayWithByteArray:(IOSByteArray *)input
                                withInt:(jint)start;

+ (IOSByteArray *)subArrayWithByteArray:(IOSByteArray *)input
                                withInt:(jint)start
                                withInt:(jint)end;

+ (NSString *)toBinaryStringWithByteArray:(IOSByteArray *)input;

+ (IOSCharArray *)toCharArrayWithByteArray:(IOSByteArray *)input;

+ (NSString *)toHexStringWithByteArray:(IOSByteArray *)input;

+ (NSString *)toHexStringWithByteArray:(IOSByteArray *)input
                          withNSString:(NSString *)prefix
                          withNSString:(NSString *)seperator;

+ (IOSByteArray *)xor__WithByteArray:(IOSByteArray *)x1
                       withByteArray:(IOSByteArray *)x2;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastlePqcMathLinearalgebraByteUtils)

FOUNDATION_EXPORT jboolean LibOrgBouncycastlePqcMathLinearalgebraByteUtils_equalsWithByteArray_withByteArray_(IOSByteArray *left, IOSByteArray *right);

FOUNDATION_EXPORT jboolean LibOrgBouncycastlePqcMathLinearalgebraByteUtils_equalsWithByteArray2_withByteArray2_(IOSObjectArray *left, IOSObjectArray *right);

FOUNDATION_EXPORT jboolean LibOrgBouncycastlePqcMathLinearalgebraByteUtils_equalsWithByteArray3_withByteArray3_(IOSObjectArray *left, IOSObjectArray *right);

FOUNDATION_EXPORT jint LibOrgBouncycastlePqcMathLinearalgebraByteUtils_deepHashCodeWithByteArray_(IOSByteArray *array);

FOUNDATION_EXPORT jint LibOrgBouncycastlePqcMathLinearalgebraByteUtils_deepHashCodeWithByteArray2_(IOSObjectArray *array);

FOUNDATION_EXPORT jint LibOrgBouncycastlePqcMathLinearalgebraByteUtils_deepHashCodeWithByteArray3_(IOSObjectArray *array);

FOUNDATION_EXPORT IOSByteArray *LibOrgBouncycastlePqcMathLinearalgebraByteUtils_cloneWithByteArray_(IOSByteArray *array);

FOUNDATION_EXPORT IOSByteArray *LibOrgBouncycastlePqcMathLinearalgebraByteUtils_fromHexStringWithNSString_(NSString *s);

FOUNDATION_EXPORT NSString *LibOrgBouncycastlePqcMathLinearalgebraByteUtils_toHexStringWithByteArray_(IOSByteArray *input);

FOUNDATION_EXPORT NSString *LibOrgBouncycastlePqcMathLinearalgebraByteUtils_toHexStringWithByteArray_withNSString_withNSString_(IOSByteArray *input, NSString *prefix, NSString *seperator);

FOUNDATION_EXPORT NSString *LibOrgBouncycastlePqcMathLinearalgebraByteUtils_toBinaryStringWithByteArray_(IOSByteArray *input);

FOUNDATION_EXPORT IOSByteArray *LibOrgBouncycastlePqcMathLinearalgebraByteUtils_xor__WithByteArray_withByteArray_(IOSByteArray *x1, IOSByteArray *x2);

FOUNDATION_EXPORT IOSByteArray *LibOrgBouncycastlePqcMathLinearalgebraByteUtils_concatenateWithByteArray_withByteArray_(IOSByteArray *x1, IOSByteArray *x2);

FOUNDATION_EXPORT IOSByteArray *LibOrgBouncycastlePqcMathLinearalgebraByteUtils_concatenateWithByteArray2_(IOSObjectArray *array);

FOUNDATION_EXPORT IOSObjectArray *LibOrgBouncycastlePqcMathLinearalgebraByteUtils_splitWithByteArray_withInt_(IOSByteArray *input, jint index);

FOUNDATION_EXPORT IOSByteArray *LibOrgBouncycastlePqcMathLinearalgebraByteUtils_subArrayWithByteArray_withInt_withInt_(IOSByteArray *input, jint start, jint end);

FOUNDATION_EXPORT IOSByteArray *LibOrgBouncycastlePqcMathLinearalgebraByteUtils_subArrayWithByteArray_withInt_(IOSByteArray *input, jint start);

FOUNDATION_EXPORT IOSCharArray *LibOrgBouncycastlePqcMathLinearalgebraByteUtils_toCharArrayWithByteArray_(IOSByteArray *input);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcMathLinearalgebraByteUtils)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ByteUtils_H
