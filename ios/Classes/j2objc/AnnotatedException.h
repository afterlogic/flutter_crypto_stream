//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jce/provider/AnnotatedException.java
//

#ifndef AnnotatedException_H
#define AnnotatedException_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ExtException.h"
#include "J2ObjC_header.h"
#include "java/lang/Exception.h"

@class JavaLangThrowable;

@interface LibOrgBouncycastleJceProviderAnnotatedException : JavaLangException < LibOrgBouncycastleJceExceptionExtException >

#pragma mark Public

- (instancetype __nonnull)initWithNSString:(NSString *)string;

- (instancetype __nonnull)initWithNSString:(NSString *)string
                     withJavaLangThrowable:(JavaLangThrowable *)e;

- (JavaLangThrowable *)getCause;

#pragma mark Package-Private

- (JavaLangThrowable *)getUnderlyingException;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

- (instancetype __nonnull)initWithJavaLangThrowable:(JavaLangThrowable *)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithNSString:(NSString *)arg0
                     withJavaLangThrowable:(JavaLangThrowable *)arg1
                               withBoolean:(jboolean)arg2
                               withBoolean:(jboolean)arg3 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJceProviderAnnotatedException)

FOUNDATION_EXPORT void LibOrgBouncycastleJceProviderAnnotatedException_initWithNSString_withJavaLangThrowable_(LibOrgBouncycastleJceProviderAnnotatedException *self, NSString *string, JavaLangThrowable *e);

FOUNDATION_EXPORT LibOrgBouncycastleJceProviderAnnotatedException *new_LibOrgBouncycastleJceProviderAnnotatedException_initWithNSString_withJavaLangThrowable_(NSString *string, JavaLangThrowable *e) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJceProviderAnnotatedException *create_LibOrgBouncycastleJceProviderAnnotatedException_initWithNSString_withJavaLangThrowable_(NSString *string, JavaLangThrowable *e);

FOUNDATION_EXPORT void LibOrgBouncycastleJceProviderAnnotatedException_initWithNSString_(LibOrgBouncycastleJceProviderAnnotatedException *self, NSString *string);

FOUNDATION_EXPORT LibOrgBouncycastleJceProviderAnnotatedException *new_LibOrgBouncycastleJceProviderAnnotatedException_initWithNSString_(NSString *string) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJceProviderAnnotatedException *create_LibOrgBouncycastleJceProviderAnnotatedException_initWithNSString_(NSString *string);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJceProviderAnnotatedException)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // AnnotatedException_H
