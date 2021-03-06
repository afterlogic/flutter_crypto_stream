//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/x509/X509Extensions.java
//

#include "ASN1Boolean.h"
#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1Object.h"
#include "ASN1ObjectIdentifier.h"
#include "ASN1OctetString.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "ASN1TaggedObject.h"
#include "DERSequence.h"
#include "Extensions.h"
#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "J2ObjC_source.h"
#include "X509Extension.h"
#include "X509Extensions.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/util/Enumeration.h"
#include "java/util/Hashtable.h"
#include "java/util/Vector.h"

@interface LibOrgBouncycastleAsn1X509X509Extensions () {
 @public
  JavaUtilHashtable *extensions_;
  JavaUtilVector *ordering_;
}

- (IOSObjectArray *)getExtensionOIDsWithBoolean:(jboolean)isCritical;

- (IOSObjectArray *)toOidArrayWithJavaUtilVector:(JavaUtilVector *)oidVec;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509X509Extensions, extensions_, JavaUtilHashtable *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509X509Extensions, ordering_, JavaUtilVector *)

__attribute__((unused)) static IOSObjectArray *LibOrgBouncycastleAsn1X509X509Extensions_getExtensionOIDsWithBoolean_(LibOrgBouncycastleAsn1X509X509Extensions *self, jboolean isCritical);

__attribute__((unused)) static IOSObjectArray *LibOrgBouncycastleAsn1X509X509Extensions_toOidArrayWithJavaUtilVector_(LibOrgBouncycastleAsn1X509X509Extensions *self, JavaUtilVector *oidVec);

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleAsn1X509X509Extensions)

LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_SubjectDirectoryAttributes;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_SubjectKeyIdentifier;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_KeyUsage;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_PrivateKeyUsagePeriod;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_SubjectAlternativeName;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_IssuerAlternativeName;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_BasicConstraints;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_CRLNumber;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_ReasonCode;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_InstructionCode;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_InvalidityDate;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_DeltaCRLIndicator;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_IssuingDistributionPoint;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_CertificateIssuer;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_NameConstraints;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_CRLDistributionPoints;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_CertificatePolicies;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_PolicyMappings;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_AuthorityKeyIdentifier;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_PolicyConstraints;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_ExtendedKeyUsage;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_FreshestCRL;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_InhibitAnyPolicy;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_AuthorityInfoAccess;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_SubjectInfoAccess;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_LogoType;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_BiometricInfo;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_QCStatements;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_AuditIdentity;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_NoRevAvail;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509X509Extensions_TargetInformation;

@implementation LibOrgBouncycastleAsn1X509X509Extensions

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)SubjectDirectoryAttributes {
  return LibOrgBouncycastleAsn1X509X509Extensions_SubjectDirectoryAttributes;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)SubjectKeyIdentifier {
  return LibOrgBouncycastleAsn1X509X509Extensions_SubjectKeyIdentifier;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)KeyUsage {
  return LibOrgBouncycastleAsn1X509X509Extensions_KeyUsage;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)PrivateKeyUsagePeriod {
  return LibOrgBouncycastleAsn1X509X509Extensions_PrivateKeyUsagePeriod;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)SubjectAlternativeName {
  return LibOrgBouncycastleAsn1X509X509Extensions_SubjectAlternativeName;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)IssuerAlternativeName {
  return LibOrgBouncycastleAsn1X509X509Extensions_IssuerAlternativeName;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)BasicConstraints {
  return LibOrgBouncycastleAsn1X509X509Extensions_BasicConstraints;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)CRLNumber {
  return LibOrgBouncycastleAsn1X509X509Extensions_CRLNumber;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)ReasonCode {
  return LibOrgBouncycastleAsn1X509X509Extensions_ReasonCode;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)InstructionCode {
  return LibOrgBouncycastleAsn1X509X509Extensions_InstructionCode;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)InvalidityDate {
  return LibOrgBouncycastleAsn1X509X509Extensions_InvalidityDate;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)DeltaCRLIndicator {
  return LibOrgBouncycastleAsn1X509X509Extensions_DeltaCRLIndicator;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)IssuingDistributionPoint {
  return LibOrgBouncycastleAsn1X509X509Extensions_IssuingDistributionPoint;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)CertificateIssuer {
  return LibOrgBouncycastleAsn1X509X509Extensions_CertificateIssuer;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)NameConstraints {
  return LibOrgBouncycastleAsn1X509X509Extensions_NameConstraints;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)CRLDistributionPoints {
  return LibOrgBouncycastleAsn1X509X509Extensions_CRLDistributionPoints;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)CertificatePolicies {
  return LibOrgBouncycastleAsn1X509X509Extensions_CertificatePolicies;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)PolicyMappings {
  return LibOrgBouncycastleAsn1X509X509Extensions_PolicyMappings;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)AuthorityKeyIdentifier {
  return LibOrgBouncycastleAsn1X509X509Extensions_AuthorityKeyIdentifier;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)PolicyConstraints {
  return LibOrgBouncycastleAsn1X509X509Extensions_PolicyConstraints;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)ExtendedKeyUsage {
  return LibOrgBouncycastleAsn1X509X509Extensions_ExtendedKeyUsage;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)FreshestCRL {
  return LibOrgBouncycastleAsn1X509X509Extensions_FreshestCRL;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)InhibitAnyPolicy {
  return LibOrgBouncycastleAsn1X509X509Extensions_InhibitAnyPolicy;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)AuthorityInfoAccess {
  return LibOrgBouncycastleAsn1X509X509Extensions_AuthorityInfoAccess;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)SubjectInfoAccess {
  return LibOrgBouncycastleAsn1X509X509Extensions_SubjectInfoAccess;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)LogoType {
  return LibOrgBouncycastleAsn1X509X509Extensions_LogoType;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)BiometricInfo {
  return LibOrgBouncycastleAsn1X509X509Extensions_BiometricInfo;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)QCStatements {
  return LibOrgBouncycastleAsn1X509X509Extensions_QCStatements;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)AuditIdentity {
  return LibOrgBouncycastleAsn1X509X509Extensions_AuditIdentity;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)NoRevAvail {
  return LibOrgBouncycastleAsn1X509X509Extensions_NoRevAvail;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)TargetInformation {
  return LibOrgBouncycastleAsn1X509X509Extensions_TargetInformation;
}

+ (LibOrgBouncycastleAsn1X509X509Extensions *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                        withBoolean:(jboolean)explicit_ {
  return LibOrgBouncycastleAsn1X509X509Extensions_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_);
}

+ (LibOrgBouncycastleAsn1X509X509Extensions *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1X509X509Extensions_getInstanceWithId_(obj);
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1X509X509Extensions_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

- (instancetype)initWithJavaUtilHashtable:(JavaUtilHashtable *)extensions {
  LibOrgBouncycastleAsn1X509X509Extensions_initWithJavaUtilHashtable_(self, extensions);
  return self;
}

- (instancetype)initWithJavaUtilVector:(JavaUtilVector *)ordering
                 withJavaUtilHashtable:(JavaUtilHashtable *)extensions {
  LibOrgBouncycastleAsn1X509X509Extensions_initWithJavaUtilVector_withJavaUtilHashtable_(self, ordering, extensions);
  return self;
}

- (instancetype)initWithJavaUtilVector:(JavaUtilVector *)objectIDs
                    withJavaUtilVector:(JavaUtilVector *)values {
  LibOrgBouncycastleAsn1X509X509Extensions_initWithJavaUtilVector_withJavaUtilVector_(self, objectIDs, values);
  return self;
}

- (id<JavaUtilEnumeration>)oids {
  return [((JavaUtilVector *) nil_chk(ordering_)) elements];
}

- (LibOrgBouncycastleAsn1X509X509Extension *)getExtensionWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)oid {
  return (LibOrgBouncycastleAsn1X509X509Extension *) cast_chk([((JavaUtilHashtable *) nil_chk(extensions_)) getWithId:oid], [LibOrgBouncycastleAsn1X509X509Extension class]);
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *vec = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  id<JavaUtilEnumeration> e = [((JavaUtilVector *) nil_chk(ordering_)) elements];
  while ([((id<JavaUtilEnumeration>) nil_chk(e)) hasMoreElements]) {
    LibOrgBouncycastleAsn1ASN1ObjectIdentifier *oid = (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) cast_chk([e nextElement], [LibOrgBouncycastleAsn1ASN1ObjectIdentifier class]);
    LibOrgBouncycastleAsn1X509X509Extension *ext = (LibOrgBouncycastleAsn1X509X509Extension *) cast_chk([((JavaUtilHashtable *) nil_chk(extensions_)) getWithId:oid], [LibOrgBouncycastleAsn1X509X509Extension class]);
    LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:oid];
    if ([((LibOrgBouncycastleAsn1X509X509Extension *) nil_chk(ext)) isCritical]) {
      [v addWithLibOrgBouncycastleAsn1ASN1Encodable:JreLoadStatic(LibOrgBouncycastleAsn1ASN1Boolean, TRUE)];
    }
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:[ext getValue]];
    [vec addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v)];
  }
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(vec);
}

- (jboolean)equivalentWithLibOrgBouncycastleAsn1X509X509Extensions:(LibOrgBouncycastleAsn1X509X509Extensions *)other {
  if ([((JavaUtilHashtable *) nil_chk(extensions_)) size] != [((JavaUtilHashtable *) nil_chk(((LibOrgBouncycastleAsn1X509X509Extensions *) nil_chk(other))->extensions_)) size]) {
    return false;
  }
  id<JavaUtilEnumeration> e1 = [((JavaUtilHashtable *) nil_chk(extensions_)) keys];
  while ([((id<JavaUtilEnumeration>) nil_chk(e1)) hasMoreElements]) {
    id key = [e1 nextElement];
    if (![nil_chk([((JavaUtilHashtable *) nil_chk(extensions_)) getWithId:key]) isEqual:[((JavaUtilHashtable *) nil_chk(other->extensions_)) getWithId:key]]) {
      return false;
    }
  }
  return true;
}

- (IOSObjectArray *)getExtensionOIDs {
  return LibOrgBouncycastleAsn1X509X509Extensions_toOidArrayWithJavaUtilVector_(self, ordering_);
}

- (IOSObjectArray *)getNonCriticalExtensionOIDs {
  return LibOrgBouncycastleAsn1X509X509Extensions_getExtensionOIDsWithBoolean_(self, false);
}

- (IOSObjectArray *)getCriticalExtensionOIDs {
  return LibOrgBouncycastleAsn1X509X509Extensions_getExtensionOIDsWithBoolean_(self, true);
}

- (IOSObjectArray *)getExtensionOIDsWithBoolean:(jboolean)isCritical {
  return LibOrgBouncycastleAsn1X509X509Extensions_getExtensionOIDsWithBoolean_(self, isCritical);
}

- (IOSObjectArray *)toOidArrayWithJavaUtilVector:(JavaUtilVector *)oidVec {
  return LibOrgBouncycastleAsn1X509X509Extensions_toOidArrayWithJavaUtilVector_(self, oidVec);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LLibOrgBouncycastleAsn1X509X509Extensions;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509X509Extensions;", 0x9, 0, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 5, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 6, -1, -1, -1, -1 },
    { NULL, "LJavaUtilEnumeration;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509X509Extension;", 0x1, 7, 8, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 9, 10, -1, -1, -1, -1 },
    { NULL, "[LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", 0x2, 11, 12, -1, -1, -1, -1 },
    { NULL, "[LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", 0x2, 13, 14, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:withBoolean:);
  methods[1].selector = @selector(getInstanceWithId:);
  methods[2].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[3].selector = @selector(initWithJavaUtilHashtable:);
  methods[4].selector = @selector(initWithJavaUtilVector:withJavaUtilHashtable:);
  methods[5].selector = @selector(initWithJavaUtilVector:withJavaUtilVector:);
  methods[6].selector = @selector(oids);
  methods[7].selector = @selector(getExtensionWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:);
  methods[8].selector = @selector(toASN1Primitive);
  methods[9].selector = @selector(equivalentWithLibOrgBouncycastleAsn1X509X509Extensions:);
  methods[10].selector = @selector(getExtensionOIDs);
  methods[11].selector = @selector(getNonCriticalExtensionOIDs);
  methods[12].selector = @selector(getCriticalExtensionOIDs);
  methods[13].selector = @selector(getExtensionOIDsWithBoolean:);
  methods[14].selector = @selector(toOidArrayWithJavaUtilVector:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "SubjectDirectoryAttributes", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 15, -1, -1 },
    { "SubjectKeyIdentifier", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 16, -1, -1 },
    { "KeyUsage", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 17, -1, -1 },
    { "PrivateKeyUsagePeriod", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 18, -1, -1 },
    { "SubjectAlternativeName", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 19, -1, -1 },
    { "IssuerAlternativeName", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 20, -1, -1 },
    { "BasicConstraints", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 21, -1, -1 },
    { "CRLNumber", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 22, -1, -1 },
    { "ReasonCode", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 23, -1, -1 },
    { "InstructionCode", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 24, -1, -1 },
    { "InvalidityDate", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 25, -1, -1 },
    { "DeltaCRLIndicator", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 26, -1, -1 },
    { "IssuingDistributionPoint", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 27, -1, -1 },
    { "CertificateIssuer", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 28, -1, -1 },
    { "NameConstraints", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 29, -1, -1 },
    { "CRLDistributionPoints", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 30, -1, -1 },
    { "CertificatePolicies", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 31, -1, -1 },
    { "PolicyMappings", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 32, -1, -1 },
    { "AuthorityKeyIdentifier", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 33, -1, -1 },
    { "PolicyConstraints", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 34, -1, -1 },
    { "ExtendedKeyUsage", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 35, -1, -1 },
    { "FreshestCRL", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 36, -1, -1 },
    { "InhibitAnyPolicy", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 37, -1, -1 },
    { "AuthorityInfoAccess", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 38, -1, -1 },
    { "SubjectInfoAccess", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 39, -1, -1 },
    { "LogoType", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 40, -1, -1 },
    { "BiometricInfo", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 41, -1, -1 },
    { "QCStatements", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 42, -1, -1 },
    { "AuditIdentity", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 43, -1, -1 },
    { "NoRevAvail", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 44, -1, -1 },
    { "TargetInformation", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 45, -1, -1 },
    { "extensions_", "LJavaUtilHashtable;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "ordering_", "LJavaUtilVector;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LLibOrgBouncycastleAsn1ASN1TaggedObject;Z", "LNSObject;", "LLibOrgBouncycastleAsn1ASN1Sequence;", "LJavaUtilHashtable;", "LJavaUtilVector;LJavaUtilHashtable;", "LJavaUtilVector;LJavaUtilVector;", "getExtension", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", "equivalent", "LLibOrgBouncycastleAsn1X509X509Extensions;", "getExtensionOIDs", "Z", "toOidArray", "LJavaUtilVector;", &LibOrgBouncycastleAsn1X509X509Extensions_SubjectDirectoryAttributes, &LibOrgBouncycastleAsn1X509X509Extensions_SubjectKeyIdentifier, &LibOrgBouncycastleAsn1X509X509Extensions_KeyUsage, &LibOrgBouncycastleAsn1X509X509Extensions_PrivateKeyUsagePeriod, &LibOrgBouncycastleAsn1X509X509Extensions_SubjectAlternativeName, &LibOrgBouncycastleAsn1X509X509Extensions_IssuerAlternativeName, &LibOrgBouncycastleAsn1X509X509Extensions_BasicConstraints, &LibOrgBouncycastleAsn1X509X509Extensions_CRLNumber, &LibOrgBouncycastleAsn1X509X509Extensions_ReasonCode, &LibOrgBouncycastleAsn1X509X509Extensions_InstructionCode, &LibOrgBouncycastleAsn1X509X509Extensions_InvalidityDate, &LibOrgBouncycastleAsn1X509X509Extensions_DeltaCRLIndicator, &LibOrgBouncycastleAsn1X509X509Extensions_IssuingDistributionPoint, &LibOrgBouncycastleAsn1X509X509Extensions_CertificateIssuer, &LibOrgBouncycastleAsn1X509X509Extensions_NameConstraints, &LibOrgBouncycastleAsn1X509X509Extensions_CRLDistributionPoints, &LibOrgBouncycastleAsn1X509X509Extensions_CertificatePolicies, &LibOrgBouncycastleAsn1X509X509Extensions_PolicyMappings, &LibOrgBouncycastleAsn1X509X509Extensions_AuthorityKeyIdentifier, &LibOrgBouncycastleAsn1X509X509Extensions_PolicyConstraints, &LibOrgBouncycastleAsn1X509X509Extensions_ExtendedKeyUsage, &LibOrgBouncycastleAsn1X509X509Extensions_FreshestCRL, &LibOrgBouncycastleAsn1X509X509Extensions_InhibitAnyPolicy, &LibOrgBouncycastleAsn1X509X509Extensions_AuthorityInfoAccess, &LibOrgBouncycastleAsn1X509X509Extensions_SubjectInfoAccess, &LibOrgBouncycastleAsn1X509X509Extensions_LogoType, &LibOrgBouncycastleAsn1X509X509Extensions_BiometricInfo, &LibOrgBouncycastleAsn1X509X509Extensions_QCStatements, &LibOrgBouncycastleAsn1X509X509Extensions_AuditIdentity, &LibOrgBouncycastleAsn1X509X509Extensions_NoRevAvail, &LibOrgBouncycastleAsn1X509X509Extensions_TargetInformation };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1X509X509Extensions = { "X509Extensions", "lib.org.bouncycastle.asn1.x509", ptrTable, methods, fields, 7, 0x1, 15, 33, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1X509X509Extensions;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleAsn1X509X509Extensions class]) {
    LibOrgBouncycastleAsn1X509X509Extensions_SubjectDirectoryAttributes = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.9");
    LibOrgBouncycastleAsn1X509X509Extensions_SubjectKeyIdentifier = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.14");
    LibOrgBouncycastleAsn1X509X509Extensions_KeyUsage = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.15");
    LibOrgBouncycastleAsn1X509X509Extensions_PrivateKeyUsagePeriod = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.16");
    LibOrgBouncycastleAsn1X509X509Extensions_SubjectAlternativeName = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.17");
    LibOrgBouncycastleAsn1X509X509Extensions_IssuerAlternativeName = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.18");
    LibOrgBouncycastleAsn1X509X509Extensions_BasicConstraints = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.19");
    LibOrgBouncycastleAsn1X509X509Extensions_CRLNumber = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.20");
    LibOrgBouncycastleAsn1X509X509Extensions_ReasonCode = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.21");
    LibOrgBouncycastleAsn1X509X509Extensions_InstructionCode = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.23");
    LibOrgBouncycastleAsn1X509X509Extensions_InvalidityDate = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.24");
    LibOrgBouncycastleAsn1X509X509Extensions_DeltaCRLIndicator = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.27");
    LibOrgBouncycastleAsn1X509X509Extensions_IssuingDistributionPoint = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.28");
    LibOrgBouncycastleAsn1X509X509Extensions_CertificateIssuer = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.29");
    LibOrgBouncycastleAsn1X509X509Extensions_NameConstraints = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.30");
    LibOrgBouncycastleAsn1X509X509Extensions_CRLDistributionPoints = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.31");
    LibOrgBouncycastleAsn1X509X509Extensions_CertificatePolicies = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.32");
    LibOrgBouncycastleAsn1X509X509Extensions_PolicyMappings = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.33");
    LibOrgBouncycastleAsn1X509X509Extensions_AuthorityKeyIdentifier = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.35");
    LibOrgBouncycastleAsn1X509X509Extensions_PolicyConstraints = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.36");
    LibOrgBouncycastleAsn1X509X509Extensions_ExtendedKeyUsage = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.37");
    LibOrgBouncycastleAsn1X509X509Extensions_FreshestCRL = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.46");
    LibOrgBouncycastleAsn1X509X509Extensions_InhibitAnyPolicy = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.54");
    LibOrgBouncycastleAsn1X509X509Extensions_AuthorityInfoAccess = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"1.3.6.1.5.5.7.1.1");
    LibOrgBouncycastleAsn1X509X509Extensions_SubjectInfoAccess = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"1.3.6.1.5.5.7.1.11");
    LibOrgBouncycastleAsn1X509X509Extensions_LogoType = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"1.3.6.1.5.5.7.1.12");
    LibOrgBouncycastleAsn1X509X509Extensions_BiometricInfo = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"1.3.6.1.5.5.7.1.2");
    LibOrgBouncycastleAsn1X509X509Extensions_QCStatements = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"1.3.6.1.5.5.7.1.3");
    LibOrgBouncycastleAsn1X509X509Extensions_AuditIdentity = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"1.3.6.1.5.5.7.1.4");
    LibOrgBouncycastleAsn1X509X509Extensions_NoRevAvail = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.56");
    LibOrgBouncycastleAsn1X509X509Extensions_TargetInformation = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.55");
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleAsn1X509X509Extensions)
  }
}

@end

LibOrgBouncycastleAsn1X509X509Extensions *LibOrgBouncycastleAsn1X509X509Extensions_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_) {
  LibOrgBouncycastleAsn1X509X509Extensions_initialize();
  return LibOrgBouncycastleAsn1X509X509Extensions_getInstanceWithId_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_));
}

LibOrgBouncycastleAsn1X509X509Extensions *LibOrgBouncycastleAsn1X509X509Extensions_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1X509X509Extensions_initialize();
  if (obj == nil || [obj isKindOfClass:[LibOrgBouncycastleAsn1X509X509Extensions class]]) {
    return (LibOrgBouncycastleAsn1X509X509Extensions *) cast_chk(obj, [LibOrgBouncycastleAsn1X509X509Extensions class]);
  }
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1ASN1Sequence class]]) {
    return new_LibOrgBouncycastleAsn1X509X509Extensions_initWithLibOrgBouncycastleAsn1ASN1Sequence_((LibOrgBouncycastleAsn1ASN1Sequence *) obj);
  }
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1X509Extensions class]]) {
    return new_LibOrgBouncycastleAsn1X509X509Extensions_initWithLibOrgBouncycastleAsn1ASN1Sequence_((LibOrgBouncycastleAsn1ASN1Sequence *) cast_chk([((LibOrgBouncycastleAsn1X509Extensions *) obj) toASN1Primitive], [LibOrgBouncycastleAsn1ASN1Sequence class]));
  }
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1ASN1TaggedObject class]]) {
    return LibOrgBouncycastleAsn1X509X509Extensions_getInstanceWithId_([((LibOrgBouncycastleAsn1ASN1TaggedObject *) obj) getObject]);
  }
  @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$", @"illegal object in getInstance: ", [[obj java_getClass] getName]));
}

void LibOrgBouncycastleAsn1X509X509Extensions_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1X509X509Extensions *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->extensions_ = new_JavaUtilHashtable_init();
  self->ordering_ = new_JavaUtilVector_init();
  id<JavaUtilEnumeration> e = [((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjects];
  while ([((id<JavaUtilEnumeration>) nil_chk(e)) hasMoreElements]) {
    LibOrgBouncycastleAsn1ASN1Sequence *s = LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_([e nextElement]);
    if ([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(s)) size] == 3) {
      (void) [((JavaUtilHashtable *) nil_chk(self->extensions_)) putWithId:[s getObjectAtWithInt:0] withId:new_LibOrgBouncycastleAsn1X509X509Extension_initWithLibOrgBouncycastleAsn1ASN1Boolean_withLibOrgBouncycastleAsn1ASN1OctetString_(LibOrgBouncycastleAsn1ASN1Boolean_getInstanceWithId_([s getObjectAtWithInt:1]), LibOrgBouncycastleAsn1ASN1OctetString_getInstanceWithId_([s getObjectAtWithInt:2]))];
    }
    else if ([s size] == 2) {
      (void) [((JavaUtilHashtable *) nil_chk(self->extensions_)) putWithId:[s getObjectAtWithInt:0] withId:new_LibOrgBouncycastleAsn1X509X509Extension_initWithBoolean_withLibOrgBouncycastleAsn1ASN1OctetString_(false, LibOrgBouncycastleAsn1ASN1OctetString_getInstanceWithId_([s getObjectAtWithInt:1]))];
    }
    else {
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$I", @"Bad sequence size: ", [s size]));
    }
    [((JavaUtilVector *) nil_chk(self->ordering_)) addElementWithId:[s getObjectAtWithInt:0]];
  }
}

LibOrgBouncycastleAsn1X509X509Extensions *new_LibOrgBouncycastleAsn1X509X509Extensions_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1X509X509Extensions, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1X509X509Extensions *create_LibOrgBouncycastleAsn1X509X509Extensions_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1X509X509Extensions, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

void LibOrgBouncycastleAsn1X509X509Extensions_initWithJavaUtilHashtable_(LibOrgBouncycastleAsn1X509X509Extensions *self, JavaUtilHashtable *extensions) {
  LibOrgBouncycastleAsn1X509X509Extensions_initWithJavaUtilVector_withJavaUtilHashtable_(self, nil, extensions);
}

LibOrgBouncycastleAsn1X509X509Extensions *new_LibOrgBouncycastleAsn1X509X509Extensions_initWithJavaUtilHashtable_(JavaUtilHashtable *extensions) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1X509X509Extensions, initWithJavaUtilHashtable_, extensions)
}

LibOrgBouncycastleAsn1X509X509Extensions *create_LibOrgBouncycastleAsn1X509X509Extensions_initWithJavaUtilHashtable_(JavaUtilHashtable *extensions) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1X509X509Extensions, initWithJavaUtilHashtable_, extensions)
}

void LibOrgBouncycastleAsn1X509X509Extensions_initWithJavaUtilVector_withJavaUtilHashtable_(LibOrgBouncycastleAsn1X509X509Extensions *self, JavaUtilVector *ordering, JavaUtilHashtable *extensions) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->extensions_ = new_JavaUtilHashtable_init();
  self->ordering_ = new_JavaUtilVector_init();
  id<JavaUtilEnumeration> e;
  if (ordering == nil) {
    e = [((JavaUtilHashtable *) nil_chk(extensions)) keys];
  }
  else {
    e = [ordering elements];
  }
  while ([((id<JavaUtilEnumeration>) nil_chk(e)) hasMoreElements]) {
    [((JavaUtilVector *) nil_chk(self->ordering_)) addElementWithId:LibOrgBouncycastleAsn1ASN1ObjectIdentifier_getInstanceWithId_([e nextElement])];
  }
  e = [((JavaUtilVector *) nil_chk(self->ordering_)) elements];
  while ([((id<JavaUtilEnumeration>) nil_chk(e)) hasMoreElements]) {
    LibOrgBouncycastleAsn1ASN1ObjectIdentifier *oid = LibOrgBouncycastleAsn1ASN1ObjectIdentifier_getInstanceWithId_([e nextElement]);
    LibOrgBouncycastleAsn1X509X509Extension *ext = (LibOrgBouncycastleAsn1X509X509Extension *) cast_chk([((JavaUtilHashtable *) nil_chk(extensions)) getWithId:oid], [LibOrgBouncycastleAsn1X509X509Extension class]);
    (void) [((JavaUtilHashtable *) nil_chk(self->extensions_)) putWithId:oid withId:ext];
  }
}

LibOrgBouncycastleAsn1X509X509Extensions *new_LibOrgBouncycastleAsn1X509X509Extensions_initWithJavaUtilVector_withJavaUtilHashtable_(JavaUtilVector *ordering, JavaUtilHashtable *extensions) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1X509X509Extensions, initWithJavaUtilVector_withJavaUtilHashtable_, ordering, extensions)
}

LibOrgBouncycastleAsn1X509X509Extensions *create_LibOrgBouncycastleAsn1X509X509Extensions_initWithJavaUtilVector_withJavaUtilHashtable_(JavaUtilVector *ordering, JavaUtilHashtable *extensions) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1X509X509Extensions, initWithJavaUtilVector_withJavaUtilHashtable_, ordering, extensions)
}

void LibOrgBouncycastleAsn1X509X509Extensions_initWithJavaUtilVector_withJavaUtilVector_(LibOrgBouncycastleAsn1X509X509Extensions *self, JavaUtilVector *objectIDs, JavaUtilVector *values) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->extensions_ = new_JavaUtilHashtable_init();
  self->ordering_ = new_JavaUtilVector_init();
  id<JavaUtilEnumeration> e = [((JavaUtilVector *) nil_chk(objectIDs)) elements];
  while ([((id<JavaUtilEnumeration>) nil_chk(e)) hasMoreElements]) {
    [((JavaUtilVector *) nil_chk(self->ordering_)) addElementWithId:[e nextElement]];
  }
  jint count = 0;
  e = [((JavaUtilVector *) nil_chk(self->ordering_)) elements];
  while ([((id<JavaUtilEnumeration>) nil_chk(e)) hasMoreElements]) {
    LibOrgBouncycastleAsn1ASN1ObjectIdentifier *oid = (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) cast_chk([e nextElement], [LibOrgBouncycastleAsn1ASN1ObjectIdentifier class]);
    LibOrgBouncycastleAsn1X509X509Extension *ext = (LibOrgBouncycastleAsn1X509X509Extension *) cast_chk([((JavaUtilVector *) nil_chk(values)) elementAtWithInt:count], [LibOrgBouncycastleAsn1X509X509Extension class]);
    (void) [((JavaUtilHashtable *) nil_chk(self->extensions_)) putWithId:oid withId:ext];
    count++;
  }
}

LibOrgBouncycastleAsn1X509X509Extensions *new_LibOrgBouncycastleAsn1X509X509Extensions_initWithJavaUtilVector_withJavaUtilVector_(JavaUtilVector *objectIDs, JavaUtilVector *values) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1X509X509Extensions, initWithJavaUtilVector_withJavaUtilVector_, objectIDs, values)
}

LibOrgBouncycastleAsn1X509X509Extensions *create_LibOrgBouncycastleAsn1X509X509Extensions_initWithJavaUtilVector_withJavaUtilVector_(JavaUtilVector *objectIDs, JavaUtilVector *values) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1X509X509Extensions, initWithJavaUtilVector_withJavaUtilVector_, objectIDs, values)
}

IOSObjectArray *LibOrgBouncycastleAsn1X509X509Extensions_getExtensionOIDsWithBoolean_(LibOrgBouncycastleAsn1X509X509Extensions *self, jboolean isCritical) {
  JavaUtilVector *oidVec = new_JavaUtilVector_init();
  for (jint i = 0; i != [((JavaUtilVector *) nil_chk(self->ordering_)) size]; i++) {
    id oid = [((JavaUtilVector *) nil_chk(self->ordering_)) elementAtWithInt:i];
    if ([((LibOrgBouncycastleAsn1X509X509Extension *) nil_chk(((LibOrgBouncycastleAsn1X509X509Extension *) cast_chk([((JavaUtilHashtable *) nil_chk(self->extensions_)) getWithId:oid], [LibOrgBouncycastleAsn1X509X509Extension class])))) isCritical] == isCritical) {
      [oidVec addElementWithId:oid];
    }
  }
  return LibOrgBouncycastleAsn1X509X509Extensions_toOidArrayWithJavaUtilVector_(self, oidVec);
}

IOSObjectArray *LibOrgBouncycastleAsn1X509X509Extensions_toOidArrayWithJavaUtilVector_(LibOrgBouncycastleAsn1X509X509Extensions *self, JavaUtilVector *oidVec) {
  IOSObjectArray *oids = [IOSObjectArray newArrayWithLength:[((JavaUtilVector *) nil_chk(oidVec)) size] type:LibOrgBouncycastleAsn1ASN1ObjectIdentifier_class_()];
  for (jint i = 0; i != oids->size_; i++) {
    (void) IOSObjectArray_Set(oids, i, (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) cast_chk([oidVec elementAtWithInt:i], [LibOrgBouncycastleAsn1ASN1ObjectIdentifier class]));
  }
  return oids;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1X509X509Extensions)
