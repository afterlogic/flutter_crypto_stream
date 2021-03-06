//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jce/provider/PKIXNameConstraintValidatorException.java
//

#ifndef PKIXNameConstraintValidatorException_H
#define PKIXNameConstraintValidatorException_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "java/lang/Exception.h"

@class JavaLangThrowable;

@interface LibOrgBouncycastleJceProviderPKIXNameConstraintValidatorException : JavaLangException

#pragma mark Public

- (instancetype __nonnull)initWithNSString:(NSString *)msg;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

- (instancetype __nonnull)initWithJavaLangThrowable:(JavaLangThrowable *)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithNSString:(NSString *)arg0
                     withJavaLangThrowable:(JavaLangThrowable *)arg1 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithNSString:(NSString *)arg0
                     withJavaLangThrowable:(JavaLangThrowable *)arg1
                               withBoolean:(jboolean)arg2
                               withBoolean:(jboolean)arg3 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJceProviderPKIXNameConstraintValidatorException)

FOUNDATION_EXPORT void LibOrgBouncycastleJceProviderPKIXNameConstraintValidatorException_initWithNSString_(LibOrgBouncycastleJceProviderPKIXNameConstraintValidatorException *self, NSString *msg);

FOUNDATION_EXPORT LibOrgBouncycastleJceProviderPKIXNameConstraintValidatorException *new_LibOrgBouncycastleJceProviderPKIXNameConstraintValidatorException_initWithNSString_(NSString *msg) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJceProviderPKIXNameConstraintValidatorException *create_LibOrgBouncycastleJceProviderPKIXNameConstraintValidatorException_initWithNSString_(NSString *msg);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJceProviderPKIXNameConstraintValidatorException)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // PKIXNameConstraintValidatorException_H
