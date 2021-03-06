//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/x509/CertPathReviewerException.java
//

#ifndef CertPathReviewerException_H
#define CertPathReviewerException_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "LocalizedException.h"

@class JavaLangThrowable;
@class JavaSecurityCertCertPath;
@class LibOrgBouncycastleI18nErrorBundle;

@interface LibOrgBouncycastleX509CertPathReviewerException : LibOrgBouncycastleI18nLocalizedException

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleI18nErrorBundle:(LibOrgBouncycastleI18nErrorBundle *)errorMessage;

- (instancetype __nonnull)initWithLibOrgBouncycastleI18nErrorBundle:(LibOrgBouncycastleI18nErrorBundle *)errorMessage
                                       withJavaSecurityCertCertPath:(JavaSecurityCertCertPath *)certPath
                                                            withInt:(jint)index;

- (instancetype __nonnull)initWithLibOrgBouncycastleI18nErrorBundle:(LibOrgBouncycastleI18nErrorBundle *)errorMessage
                                              withJavaLangThrowable:(JavaLangThrowable *)throwable;

- (instancetype __nonnull)initWithLibOrgBouncycastleI18nErrorBundle:(LibOrgBouncycastleI18nErrorBundle *)errorMessage
                                              withJavaLangThrowable:(JavaLangThrowable *)throwable
                                       withJavaSecurityCertCertPath:(JavaSecurityCertCertPath *)certPath
                                                            withInt:(jint)index;

- (JavaSecurityCertCertPath *)getCertPath;

- (jint)getIndex;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleX509CertPathReviewerException)

FOUNDATION_EXPORT void LibOrgBouncycastleX509CertPathReviewerException_initWithLibOrgBouncycastleI18nErrorBundle_withJavaLangThrowable_(LibOrgBouncycastleX509CertPathReviewerException *self, LibOrgBouncycastleI18nErrorBundle *errorMessage, JavaLangThrowable *throwable);

FOUNDATION_EXPORT LibOrgBouncycastleX509CertPathReviewerException *new_LibOrgBouncycastleX509CertPathReviewerException_initWithLibOrgBouncycastleI18nErrorBundle_withJavaLangThrowable_(LibOrgBouncycastleI18nErrorBundle *errorMessage, JavaLangThrowable *throwable) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleX509CertPathReviewerException *create_LibOrgBouncycastleX509CertPathReviewerException_initWithLibOrgBouncycastleI18nErrorBundle_withJavaLangThrowable_(LibOrgBouncycastleI18nErrorBundle *errorMessage, JavaLangThrowable *throwable);

FOUNDATION_EXPORT void LibOrgBouncycastleX509CertPathReviewerException_initWithLibOrgBouncycastleI18nErrorBundle_(LibOrgBouncycastleX509CertPathReviewerException *self, LibOrgBouncycastleI18nErrorBundle *errorMessage);

FOUNDATION_EXPORT LibOrgBouncycastleX509CertPathReviewerException *new_LibOrgBouncycastleX509CertPathReviewerException_initWithLibOrgBouncycastleI18nErrorBundle_(LibOrgBouncycastleI18nErrorBundle *errorMessage) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleX509CertPathReviewerException *create_LibOrgBouncycastleX509CertPathReviewerException_initWithLibOrgBouncycastleI18nErrorBundle_(LibOrgBouncycastleI18nErrorBundle *errorMessage);

FOUNDATION_EXPORT void LibOrgBouncycastleX509CertPathReviewerException_initWithLibOrgBouncycastleI18nErrorBundle_withJavaLangThrowable_withJavaSecurityCertCertPath_withInt_(LibOrgBouncycastleX509CertPathReviewerException *self, LibOrgBouncycastleI18nErrorBundle *errorMessage, JavaLangThrowable *throwable, JavaSecurityCertCertPath *certPath, jint index);

FOUNDATION_EXPORT LibOrgBouncycastleX509CertPathReviewerException *new_LibOrgBouncycastleX509CertPathReviewerException_initWithLibOrgBouncycastleI18nErrorBundle_withJavaLangThrowable_withJavaSecurityCertCertPath_withInt_(LibOrgBouncycastleI18nErrorBundle *errorMessage, JavaLangThrowable *throwable, JavaSecurityCertCertPath *certPath, jint index) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleX509CertPathReviewerException *create_LibOrgBouncycastleX509CertPathReviewerException_initWithLibOrgBouncycastleI18nErrorBundle_withJavaLangThrowable_withJavaSecurityCertCertPath_withInt_(LibOrgBouncycastleI18nErrorBundle *errorMessage, JavaLangThrowable *throwable, JavaSecurityCertCertPath *certPath, jint index);

FOUNDATION_EXPORT void LibOrgBouncycastleX509CertPathReviewerException_initWithLibOrgBouncycastleI18nErrorBundle_withJavaSecurityCertCertPath_withInt_(LibOrgBouncycastleX509CertPathReviewerException *self, LibOrgBouncycastleI18nErrorBundle *errorMessage, JavaSecurityCertCertPath *certPath, jint index);

FOUNDATION_EXPORT LibOrgBouncycastleX509CertPathReviewerException *new_LibOrgBouncycastleX509CertPathReviewerException_initWithLibOrgBouncycastleI18nErrorBundle_withJavaSecurityCertCertPath_withInt_(LibOrgBouncycastleI18nErrorBundle *errorMessage, JavaSecurityCertCertPath *certPath, jint index) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleX509CertPathReviewerException *create_LibOrgBouncycastleX509CertPathReviewerException_initWithLibOrgBouncycastleI18nErrorBundle_withJavaSecurityCertCertPath_withInt_(LibOrgBouncycastleI18nErrorBundle *errorMessage, JavaSecurityCertCertPath *certPath, jint index);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleX509CertPathReviewerException)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // CertPathReviewerException_H
