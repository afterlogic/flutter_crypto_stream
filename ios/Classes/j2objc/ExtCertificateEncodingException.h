//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/x509/ExtCertificateEncodingException.java
//

#ifndef ExtCertificateEncodingException_H
#define ExtCertificateEncodingException_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "java/security/cert/CertificateEncodingException.h"

@class JavaLangThrowable;

@interface LibOrgBouncycastleX509ExtCertificateEncodingException : JavaSecurityCertCertificateEncodingException {
 @public
  JavaLangThrowable *cause_ExtCertificateEncodingException_;
}

#pragma mark Public

- (JavaLangThrowable *)getCause;

#pragma mark Package-Private

- (instancetype __nonnull)initWithNSString:(NSString *)message
                     withJavaLangThrowable:(JavaLangThrowable *)cause;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

- (instancetype __nonnull)initWithJavaLangThrowable:(JavaLangThrowable *)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithNSString:(NSString *)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleX509ExtCertificateEncodingException)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleX509ExtCertificateEncodingException, cause_ExtCertificateEncodingException_, JavaLangThrowable *)

FOUNDATION_EXPORT void LibOrgBouncycastleX509ExtCertificateEncodingException_initWithNSString_withJavaLangThrowable_(LibOrgBouncycastleX509ExtCertificateEncodingException *self, NSString *message, JavaLangThrowable *cause);

FOUNDATION_EXPORT LibOrgBouncycastleX509ExtCertificateEncodingException *new_LibOrgBouncycastleX509ExtCertificateEncodingException_initWithNSString_withJavaLangThrowable_(NSString *message, JavaLangThrowable *cause) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleX509ExtCertificateEncodingException *create_LibOrgBouncycastleX509ExtCertificateEncodingException_initWithNSString_withJavaLangThrowable_(NSString *message, JavaLangThrowable *cause);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleX509ExtCertificateEncodingException)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ExtCertificateEncodingException_H
