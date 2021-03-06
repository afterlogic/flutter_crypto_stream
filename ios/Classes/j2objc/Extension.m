//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/x509/Extension.java
//

#include "ASN1Boolean.h"
#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1Object.h"
#include "ASN1ObjectIdentifier.h"
#include "ASN1OctetString.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "DEROctetString.h"
#include "DERSequence.h"
#include "Extension.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/io/IOException.h"
#include "java/lang/IllegalArgumentException.h"

@interface LibOrgBouncycastleAsn1X509Extension () {
 @public
  LibOrgBouncycastleAsn1ASN1ObjectIdentifier *extnId_;
  jboolean critical_;
  LibOrgBouncycastleAsn1ASN1OctetString *value_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

+ (LibOrgBouncycastleAsn1ASN1Primitive *)convertValueToObjectWithLibOrgBouncycastleAsn1X509Extension:(LibOrgBouncycastleAsn1X509Extension *)ext;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509Extension, extnId_, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509Extension, value_, LibOrgBouncycastleAsn1ASN1OctetString *)

__attribute__((unused)) static void LibOrgBouncycastleAsn1X509Extension_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1X509Extension *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1X509Extension *new_LibOrgBouncycastleAsn1X509Extension_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1X509Extension *create_LibOrgBouncycastleAsn1X509Extension_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1ASN1Primitive *LibOrgBouncycastleAsn1X509Extension_convertValueToObjectWithLibOrgBouncycastleAsn1X509Extension_(LibOrgBouncycastleAsn1X509Extension *ext);

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleAsn1X509Extension)

LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_subjectDirectoryAttributes;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_subjectKeyIdentifier;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_keyUsage;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_privateKeyUsagePeriod;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_subjectAlternativeName;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_issuerAlternativeName;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_basicConstraints;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_cRLNumber;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_reasonCode;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_instructionCode;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_invalidityDate;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_deltaCRLIndicator;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_issuingDistributionPoint;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_certificateIssuer;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_nameConstraints;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_cRLDistributionPoints;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_certificatePolicies;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_policyMappings;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_authorityKeyIdentifier;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_policyConstraints;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_extendedKeyUsage;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_freshestCRL;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_inhibitAnyPolicy;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_authorityInfoAccess;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_subjectInfoAccess;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_logoType;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_biometricInfo;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_qCStatements;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_auditIdentity;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_noRevAvail;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_targetInformation;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X509Extension_expiredCertsOnCRL;

@implementation LibOrgBouncycastleAsn1X509Extension

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)subjectDirectoryAttributes {
  return LibOrgBouncycastleAsn1X509Extension_subjectDirectoryAttributes;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)subjectKeyIdentifier {
  return LibOrgBouncycastleAsn1X509Extension_subjectKeyIdentifier;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)keyUsage {
  return LibOrgBouncycastleAsn1X509Extension_keyUsage;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)privateKeyUsagePeriod {
  return LibOrgBouncycastleAsn1X509Extension_privateKeyUsagePeriod;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)subjectAlternativeName {
  return LibOrgBouncycastleAsn1X509Extension_subjectAlternativeName;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)issuerAlternativeName {
  return LibOrgBouncycastleAsn1X509Extension_issuerAlternativeName;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)basicConstraints {
  return LibOrgBouncycastleAsn1X509Extension_basicConstraints;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)cRLNumber {
  return LibOrgBouncycastleAsn1X509Extension_cRLNumber;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)reasonCode {
  return LibOrgBouncycastleAsn1X509Extension_reasonCode;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)instructionCode {
  return LibOrgBouncycastleAsn1X509Extension_instructionCode;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)invalidityDate {
  return LibOrgBouncycastleAsn1X509Extension_invalidityDate;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)deltaCRLIndicator {
  return LibOrgBouncycastleAsn1X509Extension_deltaCRLIndicator;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)issuingDistributionPoint {
  return LibOrgBouncycastleAsn1X509Extension_issuingDistributionPoint;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)certificateIssuer {
  return LibOrgBouncycastleAsn1X509Extension_certificateIssuer;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)nameConstraints {
  return LibOrgBouncycastleAsn1X509Extension_nameConstraints;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)cRLDistributionPoints {
  return LibOrgBouncycastleAsn1X509Extension_cRLDistributionPoints;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)certificatePolicies {
  return LibOrgBouncycastleAsn1X509Extension_certificatePolicies;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)policyMappings {
  return LibOrgBouncycastleAsn1X509Extension_policyMappings;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)authorityKeyIdentifier {
  return LibOrgBouncycastleAsn1X509Extension_authorityKeyIdentifier;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)policyConstraints {
  return LibOrgBouncycastleAsn1X509Extension_policyConstraints;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)extendedKeyUsage {
  return LibOrgBouncycastleAsn1X509Extension_extendedKeyUsage;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)freshestCRL {
  return LibOrgBouncycastleAsn1X509Extension_freshestCRL;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)inhibitAnyPolicy {
  return LibOrgBouncycastleAsn1X509Extension_inhibitAnyPolicy;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)authorityInfoAccess {
  return LibOrgBouncycastleAsn1X509Extension_authorityInfoAccess;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)subjectInfoAccess {
  return LibOrgBouncycastleAsn1X509Extension_subjectInfoAccess;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)logoType {
  return LibOrgBouncycastleAsn1X509Extension_logoType;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)biometricInfo {
  return LibOrgBouncycastleAsn1X509Extension_biometricInfo;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)qCStatements {
  return LibOrgBouncycastleAsn1X509Extension_qCStatements;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)auditIdentity {
  return LibOrgBouncycastleAsn1X509Extension_auditIdentity;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)noRevAvail {
  return LibOrgBouncycastleAsn1X509Extension_noRevAvail;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)targetInformation {
  return LibOrgBouncycastleAsn1X509Extension_targetInformation;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)expiredCertsOnCRL {
  return LibOrgBouncycastleAsn1X509Extension_expiredCertsOnCRL;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)extnId
                             withLibOrgBouncycastleAsn1ASN1Boolean:(LibOrgBouncycastleAsn1ASN1Boolean *)critical
                         withLibOrgBouncycastleAsn1ASN1OctetString:(LibOrgBouncycastleAsn1ASN1OctetString *)value {
  LibOrgBouncycastleAsn1X509Extension_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Boolean_withLibOrgBouncycastleAsn1ASN1OctetString_(self, extnId, critical, value);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)extnId
                                                       withBoolean:(jboolean)critical
                                                     withByteArray:(IOSByteArray *)value {
  LibOrgBouncycastleAsn1X509Extension_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withBoolean_withByteArray_(self, extnId, critical, value);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)extnId
                                                       withBoolean:(jboolean)critical
                         withLibOrgBouncycastleAsn1ASN1OctetString:(LibOrgBouncycastleAsn1ASN1OctetString *)value {
  LibOrgBouncycastleAsn1X509Extension_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withBoolean_withLibOrgBouncycastleAsn1ASN1OctetString_(self, extnId, critical, value);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1X509Extension_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

+ (LibOrgBouncycastleAsn1X509Extension *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1X509Extension_getInstanceWithId_(obj);
}

- (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)getExtnId {
  return extnId_;
}

- (jboolean)isCritical {
  return critical_;
}

- (LibOrgBouncycastleAsn1ASN1OctetString *)getExtnValue {
  return value_;
}

- (id<LibOrgBouncycastleAsn1ASN1Encodable>)getParsedValue {
  return LibOrgBouncycastleAsn1X509Extension_convertValueToObjectWithLibOrgBouncycastleAsn1X509Extension_(self);
}

- (NSUInteger)hash {
  if ([self isCritical]) {
    return ((jint) [((LibOrgBouncycastleAsn1ASN1OctetString *) nil_chk([self getExtnValue])) hash]) ^ ((jint) [((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk([self getExtnId])) hash]);
  }
  return ~(((jint) [((LibOrgBouncycastleAsn1ASN1OctetString *) nil_chk([self getExtnValue])) hash]) ^ ((jint) [((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk([self getExtnId])) hash]));
}

- (jboolean)isEqual:(id)o {
  if (!([o isKindOfClass:[LibOrgBouncycastleAsn1X509Extension class]])) {
    return false;
  }
  LibOrgBouncycastleAsn1X509Extension *other = (LibOrgBouncycastleAsn1X509Extension *) cast_chk(o, [LibOrgBouncycastleAsn1X509Extension class]);
  return [((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk([((LibOrgBouncycastleAsn1X509Extension *) nil_chk(other)) getExtnId])) isEqual:[self getExtnId]] && [((LibOrgBouncycastleAsn1ASN1OctetString *) nil_chk([other getExtnValue])) isEqual:[self getExtnValue]] && ([other isCritical] == [self isCritical]);
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:extnId_];
  if (critical_) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:LibOrgBouncycastleAsn1ASN1Boolean_getInstanceWithBoolean_(true)];
  }
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:value_];
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

+ (LibOrgBouncycastleAsn1ASN1Primitive *)convertValueToObjectWithLibOrgBouncycastleAsn1X509Extension:(LibOrgBouncycastleAsn1X509Extension *)ext {
  return LibOrgBouncycastleAsn1X509Extension_convertValueToObjectWithLibOrgBouncycastleAsn1X509Extension_(ext);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509Extension;", 0x9, 4, 5, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1OctetString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Encodable;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 6, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 7, 5, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0xa, 8, 9, 10, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:withLibOrgBouncycastleAsn1ASN1Boolean:withLibOrgBouncycastleAsn1ASN1OctetString:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:withBoolean:withByteArray:);
  methods[2].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:withBoolean:withLibOrgBouncycastleAsn1ASN1OctetString:);
  methods[3].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[4].selector = @selector(getInstanceWithId:);
  methods[5].selector = @selector(getExtnId);
  methods[6].selector = @selector(isCritical);
  methods[7].selector = @selector(getExtnValue);
  methods[8].selector = @selector(getParsedValue);
  methods[9].selector = @selector(hash);
  methods[10].selector = @selector(isEqual:);
  methods[11].selector = @selector(toASN1Primitive);
  methods[12].selector = @selector(convertValueToObjectWithLibOrgBouncycastleAsn1X509Extension:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "subjectDirectoryAttributes", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 11, -1, -1 },
    { "subjectKeyIdentifier", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 12, -1, -1 },
    { "keyUsage", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 13, -1, -1 },
    { "privateKeyUsagePeriod", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 14, -1, -1 },
    { "subjectAlternativeName", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 15, -1, -1 },
    { "issuerAlternativeName", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 16, -1, -1 },
    { "basicConstraints", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 17, -1, -1 },
    { "cRLNumber", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 18, -1, -1 },
    { "reasonCode", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 19, -1, -1 },
    { "instructionCode", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 20, -1, -1 },
    { "invalidityDate", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 21, -1, -1 },
    { "deltaCRLIndicator", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 22, -1, -1 },
    { "issuingDistributionPoint", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 23, -1, -1 },
    { "certificateIssuer", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 24, -1, -1 },
    { "nameConstraints", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 25, -1, -1 },
    { "cRLDistributionPoints", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 26, -1, -1 },
    { "certificatePolicies", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 27, -1, -1 },
    { "policyMappings", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 28, -1, -1 },
    { "authorityKeyIdentifier", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 29, -1, -1 },
    { "policyConstraints", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 30, -1, -1 },
    { "extendedKeyUsage", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 31, -1, -1 },
    { "freshestCRL", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 32, -1, -1 },
    { "inhibitAnyPolicy", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 33, -1, -1 },
    { "authorityInfoAccess", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 34, -1, -1 },
    { "subjectInfoAccess", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 35, -1, -1 },
    { "logoType", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 36, -1, -1 },
    { "biometricInfo", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 37, -1, -1 },
    { "qCStatements", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 38, -1, -1 },
    { "auditIdentity", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 39, -1, -1 },
    { "noRevAvail", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 40, -1, -1 },
    { "targetInformation", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 41, -1, -1 },
    { "expiredCertsOnCRL", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 42, -1, -1 },
    { "extnId_", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "critical_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "value_", "LLibOrgBouncycastleAsn1ASN1OctetString;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;LLibOrgBouncycastleAsn1ASN1Boolean;LLibOrgBouncycastleAsn1ASN1OctetString;", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;Z[B", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;ZLLibOrgBouncycastleAsn1ASN1OctetString;", "LLibOrgBouncycastleAsn1ASN1Sequence;", "getInstance", "LNSObject;", "hashCode", "equals", "convertValueToObject", "LLibOrgBouncycastleAsn1X509Extension;", "LJavaLangIllegalArgumentException;", &LibOrgBouncycastleAsn1X509Extension_subjectDirectoryAttributes, &LibOrgBouncycastleAsn1X509Extension_subjectKeyIdentifier, &LibOrgBouncycastleAsn1X509Extension_keyUsage, &LibOrgBouncycastleAsn1X509Extension_privateKeyUsagePeriod, &LibOrgBouncycastleAsn1X509Extension_subjectAlternativeName, &LibOrgBouncycastleAsn1X509Extension_issuerAlternativeName, &LibOrgBouncycastleAsn1X509Extension_basicConstraints, &LibOrgBouncycastleAsn1X509Extension_cRLNumber, &LibOrgBouncycastleAsn1X509Extension_reasonCode, &LibOrgBouncycastleAsn1X509Extension_instructionCode, &LibOrgBouncycastleAsn1X509Extension_invalidityDate, &LibOrgBouncycastleAsn1X509Extension_deltaCRLIndicator, &LibOrgBouncycastleAsn1X509Extension_issuingDistributionPoint, &LibOrgBouncycastleAsn1X509Extension_certificateIssuer, &LibOrgBouncycastleAsn1X509Extension_nameConstraints, &LibOrgBouncycastleAsn1X509Extension_cRLDistributionPoints, &LibOrgBouncycastleAsn1X509Extension_certificatePolicies, &LibOrgBouncycastleAsn1X509Extension_policyMappings, &LibOrgBouncycastleAsn1X509Extension_authorityKeyIdentifier, &LibOrgBouncycastleAsn1X509Extension_policyConstraints, &LibOrgBouncycastleAsn1X509Extension_extendedKeyUsage, &LibOrgBouncycastleAsn1X509Extension_freshestCRL, &LibOrgBouncycastleAsn1X509Extension_inhibitAnyPolicy, &LibOrgBouncycastleAsn1X509Extension_authorityInfoAccess, &LibOrgBouncycastleAsn1X509Extension_subjectInfoAccess, &LibOrgBouncycastleAsn1X509Extension_logoType, &LibOrgBouncycastleAsn1X509Extension_biometricInfo, &LibOrgBouncycastleAsn1X509Extension_qCStatements, &LibOrgBouncycastleAsn1X509Extension_auditIdentity, &LibOrgBouncycastleAsn1X509Extension_noRevAvail, &LibOrgBouncycastleAsn1X509Extension_targetInformation, &LibOrgBouncycastleAsn1X509Extension_expiredCertsOnCRL };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1X509Extension = { "Extension", "lib.org.bouncycastle.asn1.x509", ptrTable, methods, fields, 7, 0x1, 13, 35, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1X509Extension;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleAsn1X509Extension class]) {
    LibOrgBouncycastleAsn1X509Extension_subjectDirectoryAttributes = [new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.9") intern];
    LibOrgBouncycastleAsn1X509Extension_subjectKeyIdentifier = [new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.14") intern];
    LibOrgBouncycastleAsn1X509Extension_keyUsage = [new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.15") intern];
    LibOrgBouncycastleAsn1X509Extension_privateKeyUsagePeriod = [new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.16") intern];
    LibOrgBouncycastleAsn1X509Extension_subjectAlternativeName = [new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.17") intern];
    LibOrgBouncycastleAsn1X509Extension_issuerAlternativeName = [new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.18") intern];
    LibOrgBouncycastleAsn1X509Extension_basicConstraints = [new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.19") intern];
    LibOrgBouncycastleAsn1X509Extension_cRLNumber = [new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.20") intern];
    LibOrgBouncycastleAsn1X509Extension_reasonCode = [new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.21") intern];
    LibOrgBouncycastleAsn1X509Extension_instructionCode = [new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.23") intern];
    LibOrgBouncycastleAsn1X509Extension_invalidityDate = [new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.24") intern];
    LibOrgBouncycastleAsn1X509Extension_deltaCRLIndicator = [new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.27") intern];
    LibOrgBouncycastleAsn1X509Extension_issuingDistributionPoint = [new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.28") intern];
    LibOrgBouncycastleAsn1X509Extension_certificateIssuer = [new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.29") intern];
    LibOrgBouncycastleAsn1X509Extension_nameConstraints = [new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.30") intern];
    LibOrgBouncycastleAsn1X509Extension_cRLDistributionPoints = [new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.31") intern];
    LibOrgBouncycastleAsn1X509Extension_certificatePolicies = [new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.32") intern];
    LibOrgBouncycastleAsn1X509Extension_policyMappings = [new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.33") intern];
    LibOrgBouncycastleAsn1X509Extension_authorityKeyIdentifier = [new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.35") intern];
    LibOrgBouncycastleAsn1X509Extension_policyConstraints = [new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.36") intern];
    LibOrgBouncycastleAsn1X509Extension_extendedKeyUsage = [new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.37") intern];
    LibOrgBouncycastleAsn1X509Extension_freshestCRL = [new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.46") intern];
    LibOrgBouncycastleAsn1X509Extension_inhibitAnyPolicy = [new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.54") intern];
    LibOrgBouncycastleAsn1X509Extension_authorityInfoAccess = [new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"1.3.6.1.5.5.7.1.1") intern];
    LibOrgBouncycastleAsn1X509Extension_subjectInfoAccess = [new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"1.3.6.1.5.5.7.1.11") intern];
    LibOrgBouncycastleAsn1X509Extension_logoType = [new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"1.3.6.1.5.5.7.1.12") intern];
    LibOrgBouncycastleAsn1X509Extension_biometricInfo = [new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"1.3.6.1.5.5.7.1.2") intern];
    LibOrgBouncycastleAsn1X509Extension_qCStatements = [new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"1.3.6.1.5.5.7.1.3") intern];
    LibOrgBouncycastleAsn1X509Extension_auditIdentity = [new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"1.3.6.1.5.5.7.1.4") intern];
    LibOrgBouncycastleAsn1X509Extension_noRevAvail = [new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.56") intern];
    LibOrgBouncycastleAsn1X509Extension_targetInformation = [new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.55") intern];
    LibOrgBouncycastleAsn1X509Extension_expiredCertsOnCRL = [new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"2.5.29.60") intern];
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleAsn1X509Extension)
  }
}

@end

void LibOrgBouncycastleAsn1X509Extension_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Boolean_withLibOrgBouncycastleAsn1ASN1OctetString_(LibOrgBouncycastleAsn1X509Extension *self, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *extnId, LibOrgBouncycastleAsn1ASN1Boolean *critical, LibOrgBouncycastleAsn1ASN1OctetString *value) {
  LibOrgBouncycastleAsn1X509Extension_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withBoolean_withLibOrgBouncycastleAsn1ASN1OctetString_(self, extnId, [((LibOrgBouncycastleAsn1ASN1Boolean *) nil_chk(critical)) isTrue], value);
}

LibOrgBouncycastleAsn1X509Extension *new_LibOrgBouncycastleAsn1X509Extension_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Boolean_withLibOrgBouncycastleAsn1ASN1OctetString_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *extnId, LibOrgBouncycastleAsn1ASN1Boolean *critical, LibOrgBouncycastleAsn1ASN1OctetString *value) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1X509Extension, initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Boolean_withLibOrgBouncycastleAsn1ASN1OctetString_, extnId, critical, value)
}

LibOrgBouncycastleAsn1X509Extension *create_LibOrgBouncycastleAsn1X509Extension_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Boolean_withLibOrgBouncycastleAsn1ASN1OctetString_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *extnId, LibOrgBouncycastleAsn1ASN1Boolean *critical, LibOrgBouncycastleAsn1ASN1OctetString *value) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1X509Extension, initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Boolean_withLibOrgBouncycastleAsn1ASN1OctetString_, extnId, critical, value)
}

void LibOrgBouncycastleAsn1X509Extension_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withBoolean_withByteArray_(LibOrgBouncycastleAsn1X509Extension *self, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *extnId, jboolean critical, IOSByteArray *value) {
  LibOrgBouncycastleAsn1X509Extension_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withBoolean_withLibOrgBouncycastleAsn1ASN1OctetString_(self, extnId, critical, new_LibOrgBouncycastleAsn1DEROctetString_initWithByteArray_(value));
}

LibOrgBouncycastleAsn1X509Extension *new_LibOrgBouncycastleAsn1X509Extension_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withBoolean_withByteArray_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *extnId, jboolean critical, IOSByteArray *value) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1X509Extension, initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withBoolean_withByteArray_, extnId, critical, value)
}

LibOrgBouncycastleAsn1X509Extension *create_LibOrgBouncycastleAsn1X509Extension_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withBoolean_withByteArray_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *extnId, jboolean critical, IOSByteArray *value) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1X509Extension, initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withBoolean_withByteArray_, extnId, critical, value)
}

void LibOrgBouncycastleAsn1X509Extension_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withBoolean_withLibOrgBouncycastleAsn1ASN1OctetString_(LibOrgBouncycastleAsn1X509Extension *self, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *extnId, jboolean critical, LibOrgBouncycastleAsn1ASN1OctetString *value) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->extnId_ = extnId;
  self->critical_ = critical;
  self->value_ = value;
}

LibOrgBouncycastleAsn1X509Extension *new_LibOrgBouncycastleAsn1X509Extension_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withBoolean_withLibOrgBouncycastleAsn1ASN1OctetString_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *extnId, jboolean critical, LibOrgBouncycastleAsn1ASN1OctetString *value) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1X509Extension, initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withBoolean_withLibOrgBouncycastleAsn1ASN1OctetString_, extnId, critical, value)
}

LibOrgBouncycastleAsn1X509Extension *create_LibOrgBouncycastleAsn1X509Extension_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withBoolean_withLibOrgBouncycastleAsn1ASN1OctetString_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *extnId, jboolean critical, LibOrgBouncycastleAsn1ASN1OctetString *value) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1X509Extension, initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withBoolean_withLibOrgBouncycastleAsn1ASN1OctetString_, extnId, critical, value)
}

void LibOrgBouncycastleAsn1X509Extension_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1X509Extension *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  if ([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) size] == 2) {
    self->extnId_ = LibOrgBouncycastleAsn1ASN1ObjectIdentifier_getInstanceWithId_([seq getObjectAtWithInt:0]);
    self->critical_ = false;
    self->value_ = LibOrgBouncycastleAsn1ASN1OctetString_getInstanceWithId_([seq getObjectAtWithInt:1]);
  }
  else if ([seq size] == 3) {
    self->extnId_ = LibOrgBouncycastleAsn1ASN1ObjectIdentifier_getInstanceWithId_([seq getObjectAtWithInt:0]);
    self->critical_ = [((LibOrgBouncycastleAsn1ASN1Boolean *) nil_chk(LibOrgBouncycastleAsn1ASN1Boolean_getInstanceWithId_([seq getObjectAtWithInt:1]))) isTrue];
    self->value_ = LibOrgBouncycastleAsn1ASN1OctetString_getInstanceWithId_([seq getObjectAtWithInt:2]);
  }
  else {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$I", @"Bad sequence size: ", [seq size]));
  }
}

LibOrgBouncycastleAsn1X509Extension *new_LibOrgBouncycastleAsn1X509Extension_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1X509Extension, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1X509Extension *create_LibOrgBouncycastleAsn1X509Extension_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1X509Extension, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1X509Extension *LibOrgBouncycastleAsn1X509Extension_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1X509Extension_initialize();
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1X509Extension class]]) {
    return (LibOrgBouncycastleAsn1X509Extension *) obj;
  }
  else if (obj != nil) {
    return new_LibOrgBouncycastleAsn1X509Extension_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(obj));
  }
  return nil;
}

LibOrgBouncycastleAsn1ASN1Primitive *LibOrgBouncycastleAsn1X509Extension_convertValueToObjectWithLibOrgBouncycastleAsn1X509Extension_(LibOrgBouncycastleAsn1X509Extension *ext) {
  LibOrgBouncycastleAsn1X509Extension_initialize();
  @try {
    return LibOrgBouncycastleAsn1ASN1Primitive_fromByteArrayWithByteArray_([((LibOrgBouncycastleAsn1ASN1OctetString *) nil_chk([((LibOrgBouncycastleAsn1X509Extension *) nil_chk(ext)) getExtnValue])) getOctets]);
  }
  @catch (JavaIoIOException *e) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$@", @"can't convert extension: ", e));
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1X509Extension)
