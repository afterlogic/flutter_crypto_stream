//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/x509/X509Extensions.java
//

#ifndef X509Extensions_H
#define X509Extensions_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class IOSObjectArray;
@class JavaUtilHashtable;
@class JavaUtilVector;
@class LibOrgBouncycastleAsn1ASN1ObjectIdentifier;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1ASN1Sequence;
@class LibOrgBouncycastleAsn1ASN1TaggedObject;
@class LibOrgBouncycastleAsn1X509X509Extension;
@protocol JavaUtilEnumeration;

@interface LibOrgBouncycastleAsn1X509X509Extensions : LibOrgBouncycastleAsn1ASN1Object
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *SubjectDirectoryAttributes NS_SWIFT_NAME(SubjectDirectoryAttributes);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *SubjectKeyIdentifier NS_SWIFT_NAME(SubjectKeyIdentifier);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *KeyUsage NS_SWIFT_NAME(KeyUsage);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *PrivateKeyUsagePeriod NS_SWIFT_NAME(PrivateKeyUsagePeriod);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *SubjectAlternativeName NS_SWIFT_NAME(SubjectAlternativeName);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *IssuerAlternativeName NS_SWIFT_NAME(IssuerAlternativeName);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *BasicConstraints NS_SWIFT_NAME(BasicConstraints);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *CRLNumber NS_SWIFT_NAME(CRLNumber);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *ReasonCode NS_SWIFT_NAME(ReasonCode);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *InstructionCode NS_SWIFT_NAME(InstructionCode);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *InvalidityDate NS_SWIFT_NAME(InvalidityDate);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *DeltaCRLIndicator NS_SWIFT_NAME(DeltaCRLIndicator);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *IssuingDistributionPoint NS_SWIFT_NAME(IssuingDistributionPoint);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *CertificateIssuer NS_SWIFT_NAME(CertificateIssuer);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *NameConstraints NS_SWIFT_NAME(NameConstraints);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *CRLDistributionPoints NS_SWIFT_NAME(CRLDistributionPoints);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *CertificatePolicies NS_SWIFT_NAME(CertificatePolicies);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *PolicyMappings NS_SWIFT_NAME(PolicyMappings);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *AuthorityKeyIdentifier NS_SWIFT_NAME(AuthorityKeyIdentifier);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *PolicyConstraints NS_SWIFT_NAME(PolicyConstraints);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *ExtendedKeyUsage NS_SWIFT_NAME(ExtendedKeyUsage);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *FreshestCRL NS_SWIFT_NAME(FreshestCRL);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *InhibitAnyPolicy NS_SWIFT_NAME(InhibitAnyPolicy);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *AuthorityInfoAccess NS_SWIFT_NAME(AuthorityInfoAccess);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *SubjectInfoAccess NS_SWIFT_NAME(SubjectInfoAccess);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LogoType NS_SWIFT_NAME(LogoType);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *BiometricInfo NS_SWIFT_NAME(BiometricInfo);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *QCStatements NS_SWIFT_NAME(QCStatements);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *AuditIdentity NS_SWIFT_NAME(AuditIdentity);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *NoRevAvail NS_SWIFT_NAME(NoRevAvail);
@property (readonly, class) LibOrgBouncycastleAsn1ASN1ObjectIdentifier *TargetInformation NS_SWIFT_NAME(TargetInformation);

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)SubjectDirectoryAttributes;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)SubjectKeyIdentifier;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)KeyUsage;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)PrivateKeyUsagePeriod;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)SubjectAlternativeName;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)IssuerAlternativeName;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)BasicConstraints;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)CRLNumber;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)ReasonCode;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)InstructionCode;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)InvalidityDate;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)DeltaCRLIndicator;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)IssuingDistributionPoint;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)CertificateIssuer;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)NameConstraints;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)CRLDistributionPoints;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)CertificatePolicies;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)PolicyMappings;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)AuthorityKeyIdentifier;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)PolicyConstraints;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)ExtendedKeyUsage;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)FreshestCRL;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)InhibitAnyPolicy;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)AuthorityInfoAccess;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)SubjectInfoAccess;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)LogoType;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)BiometricInfo;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)QCStatements;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)AuditIdentity;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)NoRevAvail;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)TargetInformation;

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

- (instancetype __nonnull)initWithJavaUtilHashtable:(JavaUtilHashtable *)extensions;

- (instancetype __nonnull)initWithJavaUtilVector:(JavaUtilVector *)ordering
                           withJavaUtilHashtable:(JavaUtilHashtable *)extensions;

- (instancetype __nonnull)initWithJavaUtilVector:(JavaUtilVector *)objectIDs
                              withJavaUtilVector:(JavaUtilVector *)values;

- (jboolean)equivalentWithLibOrgBouncycastleAsn1X509X509Extensions:(LibOrgBouncycastleAsn1X509X509Extensions *)other;

- (IOSObjectArray *)getCriticalExtensionOIDs;

- (LibOrgBouncycastleAsn1X509X509Extension *)getExtensionWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)oid;

- (IOSObjectArray *)getExtensionOIDs;

+ (LibOrgBouncycastleAsn1X509X509Extensions *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                        withBoolean:(jboolean)explicit_;

+ (LibOrgBouncycastleAsn1X509X509Extensions *)getInstanceWithId:(id)obj;

- (IOSObjectArray *)getNonCriticalExtensionOIDs;

- (id<JavaUtilEnumeration>)oids;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleAsn1X509X509Extensions)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_get_SubjectDirectoryAttributes(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_SubjectDirectoryAttributes;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509X509Extensions, SubjectDirectoryAttributes, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_get_SubjectKeyIdentifier(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_SubjectKeyIdentifier;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509X509Extensions, SubjectKeyIdentifier, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_get_KeyUsage(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_KeyUsage;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509X509Extensions, KeyUsage, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_get_PrivateKeyUsagePeriod(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_PrivateKeyUsagePeriod;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509X509Extensions, PrivateKeyUsagePeriod, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_get_SubjectAlternativeName(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_SubjectAlternativeName;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509X509Extensions, SubjectAlternativeName, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_get_IssuerAlternativeName(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_IssuerAlternativeName;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509X509Extensions, IssuerAlternativeName, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_get_BasicConstraints(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_BasicConstraints;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509X509Extensions, BasicConstraints, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_get_CRLNumber(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_CRLNumber;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509X509Extensions, CRLNumber, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_get_ReasonCode(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_ReasonCode;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509X509Extensions, ReasonCode, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_get_InstructionCode(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_InstructionCode;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509X509Extensions, InstructionCode, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_get_InvalidityDate(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_InvalidityDate;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509X509Extensions, InvalidityDate, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_get_DeltaCRLIndicator(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_DeltaCRLIndicator;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509X509Extensions, DeltaCRLIndicator, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_get_IssuingDistributionPoint(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_IssuingDistributionPoint;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509X509Extensions, IssuingDistributionPoint, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_get_CertificateIssuer(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_CertificateIssuer;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509X509Extensions, CertificateIssuer, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_get_NameConstraints(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_NameConstraints;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509X509Extensions, NameConstraints, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_get_CRLDistributionPoints(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_CRLDistributionPoints;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509X509Extensions, CRLDistributionPoints, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_get_CertificatePolicies(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_CertificatePolicies;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509X509Extensions, CertificatePolicies, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_get_PolicyMappings(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_PolicyMappings;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509X509Extensions, PolicyMappings, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_get_AuthorityKeyIdentifier(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_AuthorityKeyIdentifier;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509X509Extensions, AuthorityKeyIdentifier, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_get_PolicyConstraints(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_PolicyConstraints;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509X509Extensions, PolicyConstraints, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_get_ExtendedKeyUsage(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_ExtendedKeyUsage;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509X509Extensions, ExtendedKeyUsage, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_get_FreshestCRL(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_FreshestCRL;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509X509Extensions, FreshestCRL, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_get_InhibitAnyPolicy(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_InhibitAnyPolicy;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509X509Extensions, InhibitAnyPolicy, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_get_AuthorityInfoAccess(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_AuthorityInfoAccess;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509X509Extensions, AuthorityInfoAccess, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_get_SubjectInfoAccess(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_SubjectInfoAccess;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509X509Extensions, SubjectInfoAccess, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_get_LogoType(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_LogoType;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509X509Extensions, LogoType, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_get_BiometricInfo(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_BiometricInfo;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509X509Extensions, BiometricInfo, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_get_QCStatements(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_QCStatements;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509X509Extensions, QCStatements, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_get_AuditIdentity(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_AuditIdentity;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509X509Extensions, AuditIdentity, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_get_NoRevAvail(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_NoRevAvail;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509X509Extensions, NoRevAvail, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

inline LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_get_TargetInformation(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_TargetInformation;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1X509X509Extensions, TargetInformation, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509X509Extensions *LibOrgBouncycastleAsn1X509X509Extensions_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509X509Extensions *LibOrgBouncycastleAsn1X509X509Extensions_getInstanceWithId_(id obj);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1X509X509Extensions_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1X509X509Extensions *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509X509Extensions *new_LibOrgBouncycastleAsn1X509X509Extensions_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509X509Extensions *create_LibOrgBouncycastleAsn1X509X509Extensions_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1X509X509Extensions_initWithJavaUtilHashtable_(LibOrgBouncycastleAsn1X509X509Extensions *self, JavaUtilHashtable *extensions);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509X509Extensions *new_LibOrgBouncycastleAsn1X509X509Extensions_initWithJavaUtilHashtable_(JavaUtilHashtable *extensions) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509X509Extensions *create_LibOrgBouncycastleAsn1X509X509Extensions_initWithJavaUtilHashtable_(JavaUtilHashtable *extensions);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1X509X509Extensions_initWithJavaUtilVector_withJavaUtilHashtable_(LibOrgBouncycastleAsn1X509X509Extensions *self, JavaUtilVector *ordering, JavaUtilHashtable *extensions);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509X509Extensions *new_LibOrgBouncycastleAsn1X509X509Extensions_initWithJavaUtilVector_withJavaUtilHashtable_(JavaUtilVector *ordering, JavaUtilHashtable *extensions) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509X509Extensions *create_LibOrgBouncycastleAsn1X509X509Extensions_initWithJavaUtilVector_withJavaUtilHashtable_(JavaUtilVector *ordering, JavaUtilHashtable *extensions);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1X509X509Extensions_initWithJavaUtilVector_withJavaUtilVector_(LibOrgBouncycastleAsn1X509X509Extensions *self, JavaUtilVector *objectIDs, JavaUtilVector *values);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509X509Extensions *new_LibOrgBouncycastleAsn1X509X509Extensions_initWithJavaUtilVector_withJavaUtilVector_(JavaUtilVector *objectIDs, JavaUtilVector *values) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509X509Extensions *create_LibOrgBouncycastleAsn1X509X509Extensions_initWithJavaUtilVector_withJavaUtilVector_(JavaUtilVector *objectIDs, JavaUtilVector *values);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1X509X509Extensions)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // X509Extensions_H
