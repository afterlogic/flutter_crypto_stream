//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/x509/X509V1CertificateGenerator.java
//

#ifndef X509V1CertificateGenerator_H
#define X509V1CertificateGenerator_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class JavaMathBigInteger;
@class JavaSecurityCertX509Certificate;
@class JavaSecuritySecureRandom;
@class JavaUtilDate;
@class JavaxSecurityAuthX500X500Principal;
@class LibOrgBouncycastleAsn1X509X509Name;
@protocol JavaSecurityPrivateKey;
@protocol JavaSecurityPublicKey;
@protocol JavaUtilIterator;

@interface LibOrgBouncycastleX509X509V1CertificateGenerator : NSObject

#pragma mark Public

- (instancetype __nonnull)init;

- (JavaSecurityCertX509Certificate *)generateWithJavaSecurityPrivateKey:(id<JavaSecurityPrivateKey>)key;

- (JavaSecurityCertX509Certificate *)generateWithJavaSecurityPrivateKey:(id<JavaSecurityPrivateKey>)key
                                           withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random;

- (JavaSecurityCertX509Certificate *)generateWithJavaSecurityPrivateKey:(id<JavaSecurityPrivateKey>)key
                                                           withNSString:(NSString *)provider;

- (JavaSecurityCertX509Certificate *)generateWithJavaSecurityPrivateKey:(id<JavaSecurityPrivateKey>)key
                                                           withNSString:(NSString *)provider
                                           withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random;

- (JavaSecurityCertX509Certificate *)generateX509CertificateWithJavaSecurityPrivateKey:(id<JavaSecurityPrivateKey>)key;

- (JavaSecurityCertX509Certificate *)generateX509CertificateWithJavaSecurityPrivateKey:(id<JavaSecurityPrivateKey>)key
                                                          withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random;

- (JavaSecurityCertX509Certificate *)generateX509CertificateWithJavaSecurityPrivateKey:(id<JavaSecurityPrivateKey>)key
                                                                          withNSString:(NSString *)provider;

- (JavaSecurityCertX509Certificate *)generateX509CertificateWithJavaSecurityPrivateKey:(id<JavaSecurityPrivateKey>)key
                                                                          withNSString:(NSString *)provider
                                                          withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random;

- (id<JavaUtilIterator>)getSignatureAlgNames;

- (void)reset;

- (void)setIssuerDNWithJavaxSecurityAuthX500X500Principal:(JavaxSecurityAuthX500X500Principal *)issuer;

- (void)setIssuerDNWithLibOrgBouncycastleAsn1X509X509Name:(LibOrgBouncycastleAsn1X509X509Name *)issuer;

- (void)setNotAfterWithJavaUtilDate:(JavaUtilDate *)date;

- (void)setNotBeforeWithJavaUtilDate:(JavaUtilDate *)date;

- (void)setPublicKeyWithJavaSecurityPublicKey:(id<JavaSecurityPublicKey>)key;

- (void)setSerialNumberWithJavaMathBigInteger:(JavaMathBigInteger *)serialNumber;

- (void)setSignatureAlgorithmWithNSString:(NSString *)signatureAlgorithm;

- (void)setSubjectDNWithJavaxSecurityAuthX500X500Principal:(JavaxSecurityAuthX500X500Principal *)subject;

- (void)setSubjectDNWithLibOrgBouncycastleAsn1X509X509Name:(LibOrgBouncycastleAsn1X509X509Name *)subject;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleX509X509V1CertificateGenerator)

FOUNDATION_EXPORT void LibOrgBouncycastleX509X509V1CertificateGenerator_init(LibOrgBouncycastleX509X509V1CertificateGenerator *self);

FOUNDATION_EXPORT LibOrgBouncycastleX509X509V1CertificateGenerator *new_LibOrgBouncycastleX509X509V1CertificateGenerator_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleX509X509V1CertificateGenerator *create_LibOrgBouncycastleX509X509V1CertificateGenerator_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleX509X509V1CertificateGenerator)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // X509V1CertificateGenerator_H
