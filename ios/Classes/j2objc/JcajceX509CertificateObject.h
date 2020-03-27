//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/asymmetric/x509/JcajceX509CertificateObject.java
//

#ifndef JcajceX509CertificateObject_H
#define JcajceX509CertificateObject_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "PKCS12BagAttributeCarrier.h"
#include "java/security/cert/X509Certificate.h"

@class IOSBooleanArray;
@class IOSByteArray;
@class JavaMathBigInteger;
@class JavaSecurityProvider;
@class JavaUtilDate;
@class JavaxSecurityAuthX500X500Principal;
@class LibOrgBouncycastleAsn1ASN1ObjectIdentifier;
@class LibOrgBouncycastleAsn1X509X509Certificate;
@protocol JavaSecurityPrincipal;
@protocol JavaSecurityPublicKey;
@protocol JavaUtilCollection;
@protocol JavaUtilEnumeration;
@protocol JavaUtilList;
@protocol JavaUtilSet;
@protocol LibOrgBouncycastleAsn1ASN1Encodable;
@protocol LibOrgBouncycastleJcajceUtilJcaJceHelper;

@interface LibOrgBouncycastleJcajceProviderAsymmetricX509JcajceX509CertificateObject : JavaSecurityCertX509Certificate < LibOrgBouncycastleJceInterfacesPKCS12BagAttributeCarrier >

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleJcajceUtilJcaJceHelper:(id<LibOrgBouncycastleJcajceUtilJcaJceHelper>)bcHelper
                             withLibOrgBouncycastleAsn1X509X509Certificate:(LibOrgBouncycastleAsn1X509X509Certificate *)c;

- (void)checkValidity;

- (void)checkValidityWithJavaUtilDate:(JavaUtilDate *)date;

- (jboolean)isEqual:(id)o;

- (id<LibOrgBouncycastleAsn1ASN1Encodable>)getBagAttributeWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)oid;

- (id<JavaUtilEnumeration>)getBagAttributeKeys;

- (jint)getBasicConstraints;

- (id<JavaUtilSet>)getCriticalExtensionOIDs;

- (IOSByteArray *)getEncoded;

- (id<JavaUtilList>)getExtendedKeyUsage;

- (IOSByteArray *)getExtensionValueWithNSString:(NSString *)oid;

- (id<JavaUtilCollection>)getIssuerAlternativeNames;

- (id<JavaSecurityPrincipal>)getIssuerDN;

- (IOSBooleanArray *)getIssuerUniqueID;

- (JavaxSecurityAuthX500X500Principal *)getIssuerX500Principal;

- (IOSBooleanArray *)getKeyUsage;

- (id<JavaUtilSet>)getNonCriticalExtensionOIDs;

- (JavaUtilDate *)getNotAfter;

- (JavaUtilDate *)getNotBefore;

- (id<JavaSecurityPublicKey>)getPublicKey;

- (JavaMathBigInteger *)getSerialNumber;

- (NSString *)getSigAlgName;

- (NSString *)getSigAlgOID;

- (IOSByteArray *)getSigAlgParams;

- (IOSByteArray *)getSignature;

- (id<JavaUtilCollection>)getSubjectAlternativeNames;

- (id<JavaSecurityPrincipal>)getSubjectDN;

- (IOSBooleanArray *)getSubjectUniqueID;

- (JavaxSecurityAuthX500X500Principal *)getSubjectX500Principal;

- (IOSByteArray *)getTBSCertificate;

- (jint)getVersion;

- (NSUInteger)hash;

- (jboolean)hasUnsupportedCriticalExtension;

- (jint)originalHashCode;

- (void)setBagAttributeWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)oid
                              withLibOrgBouncycastleAsn1ASN1Encodable:(id<LibOrgBouncycastleAsn1ASN1Encodable>)attribute;

- (NSString *)description;

- (void)verifyWithJavaSecurityPublicKey:(id<JavaSecurityPublicKey>)key;

- (void)verifyWithJavaSecurityPublicKey:(id<JavaSecurityPublicKey>)key
               withJavaSecurityProvider:(JavaSecurityProvider *)sigProvider;

- (void)verifyWithJavaSecurityPublicKey:(id<JavaSecurityPublicKey>)key
                           withNSString:(NSString *)sigProvider;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricX509JcajceX509CertificateObject)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricX509JcajceX509CertificateObject_initWithLibOrgBouncycastleJcajceUtilJcaJceHelper_withLibOrgBouncycastleAsn1X509X509Certificate_(LibOrgBouncycastleJcajceProviderAsymmetricX509JcajceX509CertificateObject *self, id<LibOrgBouncycastleJcajceUtilJcaJceHelper> bcHelper, LibOrgBouncycastleAsn1X509X509Certificate *c);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricX509JcajceX509CertificateObject *new_LibOrgBouncycastleJcajceProviderAsymmetricX509JcajceX509CertificateObject_initWithLibOrgBouncycastleJcajceUtilJcaJceHelper_withLibOrgBouncycastleAsn1X509X509Certificate_(id<LibOrgBouncycastleJcajceUtilJcaJceHelper> bcHelper, LibOrgBouncycastleAsn1X509X509Certificate *c) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricX509JcajceX509CertificateObject *create_LibOrgBouncycastleJcajceProviderAsymmetricX509JcajceX509CertificateObject_initWithLibOrgBouncycastleJcajceUtilJcaJceHelper_withLibOrgBouncycastleAsn1X509X509Certificate_(id<LibOrgBouncycastleJcajceUtilJcaJceHelper> bcHelper, LibOrgBouncycastleAsn1X509X509Certificate *c);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricX509JcajceX509CertificateObject)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // JcajceX509CertificateObject_H