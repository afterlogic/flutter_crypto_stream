//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jce/provider/RFC3281CertPathUtilities.java
//

#ifndef RFC3281CertPathUtilities_H
#define RFC3281CertPathUtilities_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class JavaSecurityCertCertPath;
@class JavaSecurityCertX509Certificate;
@class JavaUtilDate;
@class LibOrgBouncycastleJcajcePKIXExtendedParameters;
@protocol JavaSecurityCertCertPathValidatorResult;
@protocol JavaUtilList;
@protocol JavaUtilSet;
@protocol LibOrgBouncycastleJcajceUtilJcaJceHelper;
@protocol LibOrgBouncycastleX509X509AttributeCertificate;

@interface LibOrgBouncycastleJceProviderRFC3281CertPathUtilities : NSObject

#pragma mark Protected

+ (void)additionalChecksWithLibOrgBouncycastleX509X509AttributeCertificate:(id<LibOrgBouncycastleX509X509AttributeCertificate>)attrCert
                                                           withJavaUtilSet:(id<JavaUtilSet>)prohibitedACAttributes
                                                           withJavaUtilSet:(id<JavaUtilSet>)necessaryACAttributes;

+ (void)checkCRLsWithLibOrgBouncycastleX509X509AttributeCertificate:(id<LibOrgBouncycastleX509X509AttributeCertificate>)attrCert
                 withLibOrgBouncycastleJcajcePKIXExtendedParameters:(LibOrgBouncycastleJcajcePKIXExtendedParameters *)paramsPKIX
                                withJavaSecurityCertX509Certificate:(JavaSecurityCertX509Certificate *)issuerCert
                                                   withJavaUtilDate:(JavaUtilDate *)validDate
                                                   withJavaUtilList:(id<JavaUtilList>)certPathCerts
                       withLibOrgBouncycastleJcajceUtilJcaJceHelper:(id<LibOrgBouncycastleJcajceUtilJcaJceHelper>)helper;

+ (JavaSecurityCertCertPath *)processAttrCert1WithLibOrgBouncycastleX509X509AttributeCertificate:(id<LibOrgBouncycastleX509X509AttributeCertificate>)attrCert
                                              withLibOrgBouncycastleJcajcePKIXExtendedParameters:(LibOrgBouncycastleJcajcePKIXExtendedParameters *)pkixParams;

+ (id<JavaSecurityCertCertPathValidatorResult>)processAttrCert2WithJavaSecurityCertCertPath:(JavaSecurityCertCertPath *)certPath
                                         withLibOrgBouncycastleJcajcePKIXExtendedParameters:(LibOrgBouncycastleJcajcePKIXExtendedParameters *)pkixParams;

+ (void)processAttrCert3WithJavaSecurityCertX509Certificate:(JavaSecurityCertX509Certificate *)acIssuerCert
         withLibOrgBouncycastleJcajcePKIXExtendedParameters:(LibOrgBouncycastleJcajcePKIXExtendedParameters *)pkixParams;

+ (void)processAttrCert4WithJavaSecurityCertX509Certificate:(JavaSecurityCertX509Certificate *)acIssuerCert
                                            withJavaUtilSet:(id<JavaUtilSet>)trustedACIssuers;

+ (void)processAttrCert5WithLibOrgBouncycastleX509X509AttributeCertificate:(id<LibOrgBouncycastleX509X509AttributeCertificate>)attrCert
                        withLibOrgBouncycastleJcajcePKIXExtendedParameters:(LibOrgBouncycastleJcajcePKIXExtendedParameters *)pkixParams;

+ (void)processAttrCert7WithLibOrgBouncycastleX509X509AttributeCertificate:(id<LibOrgBouncycastleX509X509AttributeCertificate>)attrCert
                                              withJavaSecurityCertCertPath:(JavaSecurityCertCertPath *)certPath
                                              withJavaSecurityCertCertPath:(JavaSecurityCertCertPath *)holderCertPath
                        withLibOrgBouncycastleJcajcePKIXExtendedParameters:(LibOrgBouncycastleJcajcePKIXExtendedParameters *)pkixParams
                                                           withJavaUtilSet:(id<JavaUtilSet>)attrCertCheckers;

#pragma mark Package-Private

- (instancetype __nonnull)init;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleJceProviderRFC3281CertPathUtilities)

FOUNDATION_EXPORT void LibOrgBouncycastleJceProviderRFC3281CertPathUtilities_init(LibOrgBouncycastleJceProviderRFC3281CertPathUtilities *self);

FOUNDATION_EXPORT LibOrgBouncycastleJceProviderRFC3281CertPathUtilities *new_LibOrgBouncycastleJceProviderRFC3281CertPathUtilities_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJceProviderRFC3281CertPathUtilities *create_LibOrgBouncycastleJceProviderRFC3281CertPathUtilities_init(void);

FOUNDATION_EXPORT void LibOrgBouncycastleJceProviderRFC3281CertPathUtilities_processAttrCert7WithLibOrgBouncycastleX509X509AttributeCertificate_withJavaSecurityCertCertPath_withJavaSecurityCertCertPath_withLibOrgBouncycastleJcajcePKIXExtendedParameters_withJavaUtilSet_(id<LibOrgBouncycastleX509X509AttributeCertificate> attrCert, JavaSecurityCertCertPath *certPath, JavaSecurityCertCertPath *holderCertPath, LibOrgBouncycastleJcajcePKIXExtendedParameters *pkixParams, id<JavaUtilSet> attrCertCheckers);

FOUNDATION_EXPORT void LibOrgBouncycastleJceProviderRFC3281CertPathUtilities_checkCRLsWithLibOrgBouncycastleX509X509AttributeCertificate_withLibOrgBouncycastleJcajcePKIXExtendedParameters_withJavaSecurityCertX509Certificate_withJavaUtilDate_withJavaUtilList_withLibOrgBouncycastleJcajceUtilJcaJceHelper_(id<LibOrgBouncycastleX509X509AttributeCertificate> attrCert, LibOrgBouncycastleJcajcePKIXExtendedParameters *paramsPKIX, JavaSecurityCertX509Certificate *issuerCert, JavaUtilDate *validDate, id<JavaUtilList> certPathCerts, id<LibOrgBouncycastleJcajceUtilJcaJceHelper> helper);

FOUNDATION_EXPORT void LibOrgBouncycastleJceProviderRFC3281CertPathUtilities_additionalChecksWithLibOrgBouncycastleX509X509AttributeCertificate_withJavaUtilSet_withJavaUtilSet_(id<LibOrgBouncycastleX509X509AttributeCertificate> attrCert, id<JavaUtilSet> prohibitedACAttributes, id<JavaUtilSet> necessaryACAttributes);

FOUNDATION_EXPORT void LibOrgBouncycastleJceProviderRFC3281CertPathUtilities_processAttrCert5WithLibOrgBouncycastleX509X509AttributeCertificate_withLibOrgBouncycastleJcajcePKIXExtendedParameters_(id<LibOrgBouncycastleX509X509AttributeCertificate> attrCert, LibOrgBouncycastleJcajcePKIXExtendedParameters *pkixParams);

FOUNDATION_EXPORT void LibOrgBouncycastleJceProviderRFC3281CertPathUtilities_processAttrCert4WithJavaSecurityCertX509Certificate_withJavaUtilSet_(JavaSecurityCertX509Certificate *acIssuerCert, id<JavaUtilSet> trustedACIssuers);

FOUNDATION_EXPORT void LibOrgBouncycastleJceProviderRFC3281CertPathUtilities_processAttrCert3WithJavaSecurityCertX509Certificate_withLibOrgBouncycastleJcajcePKIXExtendedParameters_(JavaSecurityCertX509Certificate *acIssuerCert, LibOrgBouncycastleJcajcePKIXExtendedParameters *pkixParams);

FOUNDATION_EXPORT id<JavaSecurityCertCertPathValidatorResult> LibOrgBouncycastleJceProviderRFC3281CertPathUtilities_processAttrCert2WithJavaSecurityCertCertPath_withLibOrgBouncycastleJcajcePKIXExtendedParameters_(JavaSecurityCertCertPath *certPath, LibOrgBouncycastleJcajcePKIXExtendedParameters *pkixParams);

FOUNDATION_EXPORT JavaSecurityCertCertPath *LibOrgBouncycastleJceProviderRFC3281CertPathUtilities_processAttrCert1WithLibOrgBouncycastleX509X509AttributeCertificate_withLibOrgBouncycastleJcajcePKIXExtendedParameters_(id<LibOrgBouncycastleX509X509AttributeCertificate> attrCert, LibOrgBouncycastleJcajcePKIXExtendedParameters *pkixParams);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJceProviderRFC3281CertPathUtilities)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // RFC3281CertPathUtilities_H
