//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/util/StoreException.java
//

#ifndef StoreException_H
#define StoreException_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "java/lang/RuntimeException.h"

@class JavaLangThrowable;

@interface LibOrgBouncycastleUtilStoreException : JavaLangRuntimeException

#pragma mark Public

- (instancetype __nonnull)initWithNSString:(NSString *)msg
                     withJavaLangThrowable:(JavaLangThrowable *)cause;

- (JavaLangThrowable *)getCause;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

- (instancetype __nonnull)initWithJavaLangThrowable:(JavaLangThrowable *)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithNSString:(NSString *)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithNSString:(NSString *)arg0
                     withJavaLangThrowable:(JavaLangThrowable *)arg1
                               withBoolean:(jboolean)arg2
                               withBoolean:(jboolean)arg3 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleUtilStoreException)

FOUNDATION_EXPORT void LibOrgBouncycastleUtilStoreException_initWithNSString_withJavaLangThrowable_(LibOrgBouncycastleUtilStoreException *self, NSString *msg, JavaLangThrowable *cause);

FOUNDATION_EXPORT LibOrgBouncycastleUtilStoreException *new_LibOrgBouncycastleUtilStoreException_initWithNSString_withJavaLangThrowable_(NSString *msg, JavaLangThrowable *cause) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleUtilStoreException *create_LibOrgBouncycastleUtilStoreException_initWithNSString_withJavaLangThrowable_(NSString *msg, JavaLangThrowable *cause);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleUtilStoreException)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // StoreException_H
