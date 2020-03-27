//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jce/exception/JceExtCertificateEncodingException.java
//

#ifndef JceExtCertificateEncodingException_H
#define JceExtCertificateEncodingException_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ExtException.h"
#include "J2ObjC_header.h"
#include "java/security/cert/CertificateEncodingException.h"

@class JavaLangThrowable;

@interface LibOrgBouncycastleJceExceptionJceExtCertificateEncodingException : JavaSecurityCertCertificateEncodingException < LibOrgBouncycastleJceExceptionExtException >

#pragma mark Public

- (instancetype __nonnull)initWithNSString:(NSString *)message
                     withJavaLangThrowable:(JavaLangThrowable *)cause;

- (JavaLangThrowable *)getCause;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

- (instancetype __nonnull)initWithJavaLangThrowable:(JavaLangThrowable *)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithNSString:(NSString *)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJceExceptionJceExtCertificateEncodingException)

FOUNDATION_EXPORT void LibOrgBouncycastleJceExceptionJceExtCertificateEncodingException_initWithNSString_withJavaLangThrowable_(LibOrgBouncycastleJceExceptionJceExtCertificateEncodingException *self, NSString *message, JavaLangThrowable *cause);

FOUNDATION_EXPORT LibOrgBouncycastleJceExceptionJceExtCertificateEncodingException *new_LibOrgBouncycastleJceExceptionJceExtCertificateEncodingException_initWithNSString_withJavaLangThrowable_(NSString *message, JavaLangThrowable *cause) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJceExceptionJceExtCertificateEncodingException *create_LibOrgBouncycastleJceExceptionJceExtCertificateEncodingException_initWithNSString_withJavaLangThrowable_(NSString *message, JavaLangThrowable *cause);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJceExceptionJceExtCertificateEncodingException)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // JceExtCertificateEncodingException_H