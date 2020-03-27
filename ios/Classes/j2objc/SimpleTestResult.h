//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/util/test/SimpleTestResult.java
//

#ifndef SimpleTestResult_H
#define SimpleTestResult_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "TestResult.h"

@class JavaLangThrowable;
@protocol LibOrgBouncycastleUtilTestTest;

@interface LibOrgBouncycastleUtilTestSimpleTestResult : NSObject < LibOrgBouncycastleUtilTestTestResult >

#pragma mark Public

- (instancetype __nonnull)initWithBoolean:(jboolean)success
                             withNSString:(NSString *)message;

- (instancetype __nonnull)initWithBoolean:(jboolean)success
                             withNSString:(NSString *)message
                    withJavaLangThrowable:(JavaLangThrowable *)exception;

+ (id<LibOrgBouncycastleUtilTestTestResult>)failedWithLibOrgBouncycastleUtilTestTest:(id<LibOrgBouncycastleUtilTestTest>)test
                                                                        withNSString:(NSString *)message;

+ (id<LibOrgBouncycastleUtilTestTestResult>)failedWithLibOrgBouncycastleUtilTestTest:(id<LibOrgBouncycastleUtilTestTest>)test
                                                                        withNSString:(NSString *)message
                                                                              withId:(id)expected
                                                                              withId:(id)found;

+ (id<LibOrgBouncycastleUtilTestTestResult>)failedWithLibOrgBouncycastleUtilTestTest:(id<LibOrgBouncycastleUtilTestTest>)test
                                                                        withNSString:(NSString *)message
                                                               withJavaLangThrowable:(JavaLangThrowable *)t;

+ (NSString *)failedMessageWithNSString:(NSString *)algorithm
                           withNSString:(NSString *)testName
                           withNSString:(NSString *)expected
                           withNSString:(NSString *)actual;

- (JavaLangThrowable *)getException;

- (jboolean)isSuccessful;

+ (id<LibOrgBouncycastleUtilTestTestResult>)successfulWithLibOrgBouncycastleUtilTestTest:(id<LibOrgBouncycastleUtilTestTest>)test
                                                                            withNSString:(NSString *)message;

- (NSString *)description;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleUtilTestSimpleTestResult)

FOUNDATION_EXPORT void LibOrgBouncycastleUtilTestSimpleTestResult_initWithBoolean_withNSString_(LibOrgBouncycastleUtilTestSimpleTestResult *self, jboolean success, NSString *message);

FOUNDATION_EXPORT LibOrgBouncycastleUtilTestSimpleTestResult *new_LibOrgBouncycastleUtilTestSimpleTestResult_initWithBoolean_withNSString_(jboolean success, NSString *message) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleUtilTestSimpleTestResult *create_LibOrgBouncycastleUtilTestSimpleTestResult_initWithBoolean_withNSString_(jboolean success, NSString *message);

FOUNDATION_EXPORT void LibOrgBouncycastleUtilTestSimpleTestResult_initWithBoolean_withNSString_withJavaLangThrowable_(LibOrgBouncycastleUtilTestSimpleTestResult *self, jboolean success, NSString *message, JavaLangThrowable *exception);

FOUNDATION_EXPORT LibOrgBouncycastleUtilTestSimpleTestResult *new_LibOrgBouncycastleUtilTestSimpleTestResult_initWithBoolean_withNSString_withJavaLangThrowable_(jboolean success, NSString *message, JavaLangThrowable *exception) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleUtilTestSimpleTestResult *create_LibOrgBouncycastleUtilTestSimpleTestResult_initWithBoolean_withNSString_withJavaLangThrowable_(jboolean success, NSString *message, JavaLangThrowable *exception);

FOUNDATION_EXPORT id<LibOrgBouncycastleUtilTestTestResult> LibOrgBouncycastleUtilTestSimpleTestResult_successfulWithLibOrgBouncycastleUtilTestTest_withNSString_(id<LibOrgBouncycastleUtilTestTest> test, NSString *message);

FOUNDATION_EXPORT id<LibOrgBouncycastleUtilTestTestResult> LibOrgBouncycastleUtilTestSimpleTestResult_failedWithLibOrgBouncycastleUtilTestTest_withNSString_(id<LibOrgBouncycastleUtilTestTest> test, NSString *message);

FOUNDATION_EXPORT id<LibOrgBouncycastleUtilTestTestResult> LibOrgBouncycastleUtilTestSimpleTestResult_failedWithLibOrgBouncycastleUtilTestTest_withNSString_withJavaLangThrowable_(id<LibOrgBouncycastleUtilTestTest> test, NSString *message, JavaLangThrowable *t);

FOUNDATION_EXPORT id<LibOrgBouncycastleUtilTestTestResult> LibOrgBouncycastleUtilTestSimpleTestResult_failedWithLibOrgBouncycastleUtilTestTest_withNSString_withId_withId_(id<LibOrgBouncycastleUtilTestTest> test, NSString *message, id expected, id found);

FOUNDATION_EXPORT NSString *LibOrgBouncycastleUtilTestSimpleTestResult_failedMessageWithNSString_withNSString_withNSString_withNSString_(NSString *algorithm, NSString *testName, NSString *expected, NSString *actual);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleUtilTestSimpleTestResult)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // SimpleTestResult_H