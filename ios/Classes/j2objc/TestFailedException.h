//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/util/test/TestFailedException.java
//

#ifndef TestFailedException_H
#define TestFailedException_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "java/lang/RuntimeException.h"

@class JavaLangThrowable;
@protocol LibOrgBouncycastleUtilTestTestResult;

@interface LibOrgBouncycastleUtilTestTestFailedException : JavaLangRuntimeException

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleUtilTestTestResult:(id<LibOrgBouncycastleUtilTestTestResult>)result;

- (id<LibOrgBouncycastleUtilTestTestResult>)getResult;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

- (instancetype __nonnull)initWithJavaLangThrowable:(JavaLangThrowable *)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithNSString:(NSString *)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithNSString:(NSString *)arg0
                     withJavaLangThrowable:(JavaLangThrowable *)arg1 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithNSString:(NSString *)arg0
                     withJavaLangThrowable:(JavaLangThrowable *)arg1
                               withBoolean:(jboolean)arg2
                               withBoolean:(jboolean)arg3 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleUtilTestTestFailedException)

FOUNDATION_EXPORT void LibOrgBouncycastleUtilTestTestFailedException_initWithLibOrgBouncycastleUtilTestTestResult_(LibOrgBouncycastleUtilTestTestFailedException *self, id<LibOrgBouncycastleUtilTestTestResult> result);

FOUNDATION_EXPORT LibOrgBouncycastleUtilTestTestFailedException *new_LibOrgBouncycastleUtilTestTestFailedException_initWithLibOrgBouncycastleUtilTestTestResult_(id<LibOrgBouncycastleUtilTestTestResult> result) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleUtilTestTestFailedException *create_LibOrgBouncycastleUtilTestTestFailedException_initWithLibOrgBouncycastleUtilTestTestResult_(id<LibOrgBouncycastleUtilTestTestResult> result);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleUtilTestTestFailedException)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // TestFailedException_H
