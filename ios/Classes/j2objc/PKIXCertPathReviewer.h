//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/x509/PKIXCertPathReviewer.java
//

#ifndef PKIXCertPathReviewer_H
#define PKIXCertPathReviewer_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "CertPathValidatorUtilities.h"
#include "J2ObjC_header.h"

@class IOSObjectArray;
@class JavaSecurityCertCertPath;
@class JavaSecurityCertPKIXParameters;
@class JavaSecurityCertTrustAnchor;
@class JavaSecurityCertX509Certificate;
@class JavaUtilDate;
@class JavaUtilVector;
@class LibOrgBouncycastleAsn1X509AuthorityInformationAccess;
@class LibOrgBouncycastleAsn1X509CRLDistPoint;
@class LibOrgBouncycastleI18nErrorBundle;
@protocol JavaSecurityCertPolicyNode;
@protocol JavaSecurityPublicKey;
@protocol JavaUtilCollection;
@protocol JavaUtilList;
@protocol JavaUtilSet;

@interface LibOrgBouncycastleX509PKIXCertPathReviewer : LibOrgBouncycastleX509CertPathValidatorUtilities {
 @public
  JavaSecurityCertCertPath *certPath_;
  JavaSecurityCertPKIXParameters *pkixParams_;
  JavaUtilDate *validDate_;
  id<JavaUtilList> certs_;
  jint n_;
  IOSObjectArray *notifications_;
  IOSObjectArray *errors_;
  JavaSecurityCertTrustAnchor *trustAnchor_;
  id<JavaSecurityPublicKey> subjectPublicKey_;
  id<JavaSecurityCertPolicyNode> policyTree_;
}

#pragma mark Public

- (instancetype __nonnull)init;

- (instancetype __nonnull)initWithJavaSecurityCertCertPath:(JavaSecurityCertCertPath *)certPath
                        withJavaSecurityCertPKIXParameters:(JavaSecurityCertPKIXParameters *)params;

- (JavaSecurityCertCertPath *)getCertPath;

- (jint)getCertPathSize;

- (IOSObjectArray *)getErrors;

- (id<JavaUtilList>)getErrorsWithInt:(jint)index;

- (IOSObjectArray *)getNotifications;

- (id<JavaUtilList>)getNotificationsWithInt:(jint)index;

- (id<JavaSecurityCertPolicyNode>)getPolicyTree;

- (id<JavaSecurityPublicKey>)getSubjectPublicKey;

- (JavaSecurityCertTrustAnchor *)getTrustAnchor;

- (void)init__WithJavaSecurityCertCertPath:(JavaSecurityCertCertPath *)certPath
        withJavaSecurityCertPKIXParameters:(JavaSecurityCertPKIXParameters *)params OBJC_METHOD_FAMILY_NONE;

- (jboolean)isValidCertPath;

#pragma mark Protected

- (void)addErrorWithLibOrgBouncycastleI18nErrorBundle:(LibOrgBouncycastleI18nErrorBundle *)msg;

- (void)addErrorWithLibOrgBouncycastleI18nErrorBundle:(LibOrgBouncycastleI18nErrorBundle *)msg
                                              withInt:(jint)index;

- (void)addNotificationWithLibOrgBouncycastleI18nErrorBundle:(LibOrgBouncycastleI18nErrorBundle *)msg;

- (void)addNotificationWithLibOrgBouncycastleI18nErrorBundle:(LibOrgBouncycastleI18nErrorBundle *)msg
                                                     withInt:(jint)index;

- (void)checkCRLsWithJavaSecurityCertPKIXParameters:(JavaSecurityCertPKIXParameters *)paramsPKIX
                withJavaSecurityCertX509Certificate:(JavaSecurityCertX509Certificate *)cert
                                   withJavaUtilDate:(JavaUtilDate *)validDate
                withJavaSecurityCertX509Certificate:(JavaSecurityCertX509Certificate *)sign
                          withJavaSecurityPublicKey:(id<JavaSecurityPublicKey>)workingPublicKey
                                 withJavaUtilVector:(JavaUtilVector *)crlDistPointUrls
                                            withInt:(jint)index;

- (void)checkRevocationWithJavaSecurityCertPKIXParameters:(JavaSecurityCertPKIXParameters *)paramsPKIX
                      withJavaSecurityCertX509Certificate:(JavaSecurityCertX509Certificate *)cert
                                         withJavaUtilDate:(JavaUtilDate *)validDate
                      withJavaSecurityCertX509Certificate:(JavaSecurityCertX509Certificate *)sign
                                withJavaSecurityPublicKey:(id<JavaSecurityPublicKey>)workingPublicKey
                                       withJavaUtilVector:(JavaUtilVector *)crlDistPointUrls
                                       withJavaUtilVector:(JavaUtilVector *)ocspUrls
                                                  withInt:(jint)index;

- (void)doChecks;

- (JavaUtilVector *)getCRLDistUrlsWithLibOrgBouncycastleAsn1X509CRLDistPoint:(LibOrgBouncycastleAsn1X509CRLDistPoint *)crlDistPoints;

- (JavaUtilVector *)getOCSPUrlsWithLibOrgBouncycastleAsn1X509AuthorityInformationAccess:(LibOrgBouncycastleAsn1X509AuthorityInformationAccess *)authInfoAccess;

- (id<JavaUtilCollection>)getTrustAnchorsWithJavaSecurityCertX509Certificate:(JavaSecurityCertX509Certificate *)cert
                                                             withJavaUtilSet:(id<JavaUtilSet>)trustanchors;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleX509PKIXCertPathReviewer)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleX509PKIXCertPathReviewer, certPath_, JavaSecurityCertCertPath *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleX509PKIXCertPathReviewer, pkixParams_, JavaSecurityCertPKIXParameters *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleX509PKIXCertPathReviewer, validDate_, JavaUtilDate *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleX509PKIXCertPathReviewer, certs_, id<JavaUtilList>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleX509PKIXCertPathReviewer, notifications_, IOSObjectArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleX509PKIXCertPathReviewer, errors_, IOSObjectArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleX509PKIXCertPathReviewer, trustAnchor_, JavaSecurityCertTrustAnchor *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleX509PKIXCertPathReviewer, subjectPublicKey_, id<JavaSecurityPublicKey>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleX509PKIXCertPathReviewer, policyTree_, id<JavaSecurityCertPolicyNode>)

FOUNDATION_EXPORT void LibOrgBouncycastleX509PKIXCertPathReviewer_initWithJavaSecurityCertCertPath_withJavaSecurityCertPKIXParameters_(LibOrgBouncycastleX509PKIXCertPathReviewer *self, JavaSecurityCertCertPath *certPath, JavaSecurityCertPKIXParameters *params);

FOUNDATION_EXPORT LibOrgBouncycastleX509PKIXCertPathReviewer *new_LibOrgBouncycastleX509PKIXCertPathReviewer_initWithJavaSecurityCertCertPath_withJavaSecurityCertPKIXParameters_(JavaSecurityCertCertPath *certPath, JavaSecurityCertPKIXParameters *params) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleX509PKIXCertPathReviewer *create_LibOrgBouncycastleX509PKIXCertPathReviewer_initWithJavaSecurityCertCertPath_withJavaSecurityCertPKIXParameters_(JavaSecurityCertCertPath *certPath, JavaSecurityCertPKIXParameters *params);

FOUNDATION_EXPORT void LibOrgBouncycastleX509PKIXCertPathReviewer_init(LibOrgBouncycastleX509PKIXCertPathReviewer *self);

FOUNDATION_EXPORT LibOrgBouncycastleX509PKIXCertPathReviewer *new_LibOrgBouncycastleX509PKIXCertPathReviewer_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleX509PKIXCertPathReviewer *create_LibOrgBouncycastleX509PKIXCertPathReviewer_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleX509PKIXCertPathReviewer)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // PKIXCertPathReviewer_H
