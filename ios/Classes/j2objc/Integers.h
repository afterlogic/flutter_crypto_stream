//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/util/Integers.java
//

#ifndef Integers_H
#define Integers_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class JavaLangInteger;

@interface LibOrgBouncycastleUtilIntegers : NSObject

#pragma mark Public

- (instancetype __nonnull)init;

+ (jint)rotateLeftWithInt:(jint)i
                  withInt:(jint)distance;

+ (jint)rotateRightWithInt:(jint)i
                   withInt:(jint)distance;

+ (JavaLangInteger *)valueOfWithInt:(jint)value;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleUtilIntegers)

FOUNDATION_EXPORT void LibOrgBouncycastleUtilIntegers_init(LibOrgBouncycastleUtilIntegers *self);

FOUNDATION_EXPORT LibOrgBouncycastleUtilIntegers *new_LibOrgBouncycastleUtilIntegers_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleUtilIntegers *create_LibOrgBouncycastleUtilIntegers_init(void);

FOUNDATION_EXPORT jint LibOrgBouncycastleUtilIntegers_rotateLeftWithInt_withInt_(jint i, jint distance);

FOUNDATION_EXPORT jint LibOrgBouncycastleUtilIntegers_rotateRightWithInt_withInt_(jint i, jint distance);

FOUNDATION_EXPORT JavaLangInteger *LibOrgBouncycastleUtilIntegers_valueOfWithInt_(jint value);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleUtilIntegers)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // Integers_H
