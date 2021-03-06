//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/pkcs/SignerInfo.java
//

#include "ASN1EncodableVector.h"
#include "ASN1Integer.h"
#include "ASN1Object.h"
#include "ASN1OctetString.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "ASN1Set.h"
#include "ASN1TaggedObject.h"
#include "AlgorithmIdentifier.h"
#include "DERSequence.h"
#include "DERTaggedObject.h"
#include "IOSClass.h"
#include "IssuerAndSerialNumber.h"
#include "J2ObjC_source.h"
#include "SignerInfo.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/util/Enumeration.h"

@interface LibOrgBouncycastleAsn1PkcsSignerInfo () {
 @public
  LibOrgBouncycastleAsn1ASN1Integer *version__;
  LibOrgBouncycastleAsn1PkcsIssuerAndSerialNumber *issuerAndSerialNumber_;
  LibOrgBouncycastleAsn1X509AlgorithmIdentifier *digAlgorithm_;
  LibOrgBouncycastleAsn1ASN1Set *authenticatedAttributes_;
  LibOrgBouncycastleAsn1X509AlgorithmIdentifier *digEncryptionAlgorithm_;
  LibOrgBouncycastleAsn1ASN1OctetString *encryptedDigest_;
  LibOrgBouncycastleAsn1ASN1Set *unauthenticatedAttributes_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1PkcsSignerInfo, version__, LibOrgBouncycastleAsn1ASN1Integer *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1PkcsSignerInfo, issuerAndSerialNumber_, LibOrgBouncycastleAsn1PkcsIssuerAndSerialNumber *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1PkcsSignerInfo, digAlgorithm_, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1PkcsSignerInfo, authenticatedAttributes_, LibOrgBouncycastleAsn1ASN1Set *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1PkcsSignerInfo, digEncryptionAlgorithm_, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1PkcsSignerInfo, encryptedDigest_, LibOrgBouncycastleAsn1ASN1OctetString *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1PkcsSignerInfo, unauthenticatedAttributes_, LibOrgBouncycastleAsn1ASN1Set *)

@implementation LibOrgBouncycastleAsn1PkcsSignerInfo

+ (LibOrgBouncycastleAsn1PkcsSignerInfo *)getInstanceWithId:(id)o {
  return LibOrgBouncycastleAsn1PkcsSignerInfo_getInstanceWithId_(o);
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Integer:(LibOrgBouncycastleAsn1ASN1Integer *)version_
      withLibOrgBouncycastleAsn1PkcsIssuerAndSerialNumber:(LibOrgBouncycastleAsn1PkcsIssuerAndSerialNumber *)issuerAndSerialNumber
        withLibOrgBouncycastleAsn1X509AlgorithmIdentifier:(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)digAlgorithm
                        withLibOrgBouncycastleAsn1ASN1Set:(LibOrgBouncycastleAsn1ASN1Set *)authenticatedAttributes
        withLibOrgBouncycastleAsn1X509AlgorithmIdentifier:(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)digEncryptionAlgorithm
                withLibOrgBouncycastleAsn1ASN1OctetString:(LibOrgBouncycastleAsn1ASN1OctetString *)encryptedDigest
                        withLibOrgBouncycastleAsn1ASN1Set:(LibOrgBouncycastleAsn1ASN1Set *)unauthenticatedAttributes {
  LibOrgBouncycastleAsn1PkcsSignerInfo_initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1PkcsIssuerAndSerialNumber_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1ASN1Set_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1ASN1OctetString_withLibOrgBouncycastleAsn1ASN1Set_(self, version_, issuerAndSerialNumber, digAlgorithm, authenticatedAttributes, digEncryptionAlgorithm, encryptedDigest, unauthenticatedAttributes);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1PkcsSignerInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

- (LibOrgBouncycastleAsn1ASN1Integer *)getVersion {
  return version__;
}

- (LibOrgBouncycastleAsn1PkcsIssuerAndSerialNumber *)getIssuerAndSerialNumber {
  return issuerAndSerialNumber_;
}

- (LibOrgBouncycastleAsn1ASN1Set *)getAuthenticatedAttributes {
  return authenticatedAttributes_;
}

- (LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)getDigestAlgorithm {
  return digAlgorithm_;
}

- (LibOrgBouncycastleAsn1ASN1OctetString *)getEncryptedDigest {
  return encryptedDigest_;
}

- (LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)getDigestEncryptionAlgorithm {
  return digEncryptionAlgorithm_;
}

- (LibOrgBouncycastleAsn1ASN1Set *)getUnauthenticatedAttributes {
  return unauthenticatedAttributes_;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:version__];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:issuerAndSerialNumber_];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:digAlgorithm_];
  if (authenticatedAttributes_ != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERTaggedObject_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(false, 0, authenticatedAttributes_)];
  }
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:digEncryptionAlgorithm_];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:encryptedDigest_];
  if (unauthenticatedAttributes_ != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERTaggedObject_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(false, 1, unauthenticatedAttributes_)];
  }
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LLibOrgBouncycastleAsn1PkcsSignerInfo;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Integer;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1PkcsIssuerAndSerialNumber;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Set;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509AlgorithmIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1OctetString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509AlgorithmIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Set;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithId:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Integer:withLibOrgBouncycastleAsn1PkcsIssuerAndSerialNumber:withLibOrgBouncycastleAsn1X509AlgorithmIdentifier:withLibOrgBouncycastleAsn1ASN1Set:withLibOrgBouncycastleAsn1X509AlgorithmIdentifier:withLibOrgBouncycastleAsn1ASN1OctetString:withLibOrgBouncycastleAsn1ASN1Set:);
  methods[2].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[3].selector = @selector(getVersion);
  methods[4].selector = @selector(getIssuerAndSerialNumber);
  methods[5].selector = @selector(getAuthenticatedAttributes);
  methods[6].selector = @selector(getDigestAlgorithm);
  methods[7].selector = @selector(getEncryptedDigest);
  methods[8].selector = @selector(getDigestEncryptionAlgorithm);
  methods[9].selector = @selector(getUnauthenticatedAttributes);
  methods[10].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "version__", "LLibOrgBouncycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x2, 4, -1, -1, -1 },
    { "issuerAndSerialNumber_", "LLibOrgBouncycastleAsn1PkcsIssuerAndSerialNumber;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "digAlgorithm_", "LLibOrgBouncycastleAsn1X509AlgorithmIdentifier;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "authenticatedAttributes_", "LLibOrgBouncycastleAsn1ASN1Set;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "digEncryptionAlgorithm_", "LLibOrgBouncycastleAsn1X509AlgorithmIdentifier;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "encryptedDigest_", "LLibOrgBouncycastleAsn1ASN1OctetString;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "unauthenticatedAttributes_", "LLibOrgBouncycastleAsn1ASN1Set;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LNSObject;", "LLibOrgBouncycastleAsn1ASN1Integer;LLibOrgBouncycastleAsn1PkcsIssuerAndSerialNumber;LLibOrgBouncycastleAsn1X509AlgorithmIdentifier;LLibOrgBouncycastleAsn1ASN1Set;LLibOrgBouncycastleAsn1X509AlgorithmIdentifier;LLibOrgBouncycastleAsn1ASN1OctetString;LLibOrgBouncycastleAsn1ASN1Set;", "LLibOrgBouncycastleAsn1ASN1Sequence;", "version" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1PkcsSignerInfo = { "SignerInfo", "lib.org.bouncycastle.asn1.pkcs", ptrTable, methods, fields, 7, 0x1, 11, 7, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1PkcsSignerInfo;
}

@end

LibOrgBouncycastleAsn1PkcsSignerInfo *LibOrgBouncycastleAsn1PkcsSignerInfo_getInstanceWithId_(id o) {
  LibOrgBouncycastleAsn1PkcsSignerInfo_initialize();
  if ([o isKindOfClass:[LibOrgBouncycastleAsn1PkcsSignerInfo class]]) {
    return (LibOrgBouncycastleAsn1PkcsSignerInfo *) o;
  }
  else if ([o isKindOfClass:[LibOrgBouncycastleAsn1ASN1Sequence class]]) {
    return new_LibOrgBouncycastleAsn1PkcsSignerInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_((LibOrgBouncycastleAsn1ASN1Sequence *) o);
  }
  @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$", @"unknown object in factory: ", [[nil_chk(o) java_getClass] getName]));
}

void LibOrgBouncycastleAsn1PkcsSignerInfo_initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1PkcsIssuerAndSerialNumber_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1ASN1Set_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1ASN1OctetString_withLibOrgBouncycastleAsn1ASN1Set_(LibOrgBouncycastleAsn1PkcsSignerInfo *self, LibOrgBouncycastleAsn1ASN1Integer *version_, LibOrgBouncycastleAsn1PkcsIssuerAndSerialNumber *issuerAndSerialNumber, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *digAlgorithm, LibOrgBouncycastleAsn1ASN1Set *authenticatedAttributes, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *digEncryptionAlgorithm, LibOrgBouncycastleAsn1ASN1OctetString *encryptedDigest, LibOrgBouncycastleAsn1ASN1Set *unauthenticatedAttributes) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->version__ = version_;
  self->issuerAndSerialNumber_ = issuerAndSerialNumber;
  self->digAlgorithm_ = digAlgorithm;
  self->authenticatedAttributes_ = authenticatedAttributes;
  self->digEncryptionAlgorithm_ = digEncryptionAlgorithm;
  self->encryptedDigest_ = encryptedDigest;
  self->unauthenticatedAttributes_ = unauthenticatedAttributes;
}

LibOrgBouncycastleAsn1PkcsSignerInfo *new_LibOrgBouncycastleAsn1PkcsSignerInfo_initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1PkcsIssuerAndSerialNumber_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1ASN1Set_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1ASN1OctetString_withLibOrgBouncycastleAsn1ASN1Set_(LibOrgBouncycastleAsn1ASN1Integer *version_, LibOrgBouncycastleAsn1PkcsIssuerAndSerialNumber *issuerAndSerialNumber, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *digAlgorithm, LibOrgBouncycastleAsn1ASN1Set *authenticatedAttributes, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *digEncryptionAlgorithm, LibOrgBouncycastleAsn1ASN1OctetString *encryptedDigest, LibOrgBouncycastleAsn1ASN1Set *unauthenticatedAttributes) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1PkcsSignerInfo, initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1PkcsIssuerAndSerialNumber_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1ASN1Set_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1ASN1OctetString_withLibOrgBouncycastleAsn1ASN1Set_, version_, issuerAndSerialNumber, digAlgorithm, authenticatedAttributes, digEncryptionAlgorithm, encryptedDigest, unauthenticatedAttributes)
}

LibOrgBouncycastleAsn1PkcsSignerInfo *create_LibOrgBouncycastleAsn1PkcsSignerInfo_initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1PkcsIssuerAndSerialNumber_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1ASN1Set_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1ASN1OctetString_withLibOrgBouncycastleAsn1ASN1Set_(LibOrgBouncycastleAsn1ASN1Integer *version_, LibOrgBouncycastleAsn1PkcsIssuerAndSerialNumber *issuerAndSerialNumber, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *digAlgorithm, LibOrgBouncycastleAsn1ASN1Set *authenticatedAttributes, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *digEncryptionAlgorithm, LibOrgBouncycastleAsn1ASN1OctetString *encryptedDigest, LibOrgBouncycastleAsn1ASN1Set *unauthenticatedAttributes) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1PkcsSignerInfo, initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1PkcsIssuerAndSerialNumber_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1ASN1Set_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1ASN1OctetString_withLibOrgBouncycastleAsn1ASN1Set_, version_, issuerAndSerialNumber, digAlgorithm, authenticatedAttributes, digEncryptionAlgorithm, encryptedDigest, unauthenticatedAttributes)
}

void LibOrgBouncycastleAsn1PkcsSignerInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1PkcsSignerInfo *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  id<JavaUtilEnumeration> e = [((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjects];
  self->version__ = (LibOrgBouncycastleAsn1ASN1Integer *) cast_chk([((id<JavaUtilEnumeration>) nil_chk(e)) nextElement], [LibOrgBouncycastleAsn1ASN1Integer class]);
  self->issuerAndSerialNumber_ = LibOrgBouncycastleAsn1PkcsIssuerAndSerialNumber_getInstanceWithId_([e nextElement]);
  self->digAlgorithm_ = LibOrgBouncycastleAsn1X509AlgorithmIdentifier_getInstanceWithId_([e nextElement]);
  id obj = [e nextElement];
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1ASN1TaggedObject class]]) {
    self->authenticatedAttributes_ = LibOrgBouncycastleAsn1ASN1Set_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_((LibOrgBouncycastleAsn1ASN1TaggedObject *) obj, false);
    self->digEncryptionAlgorithm_ = LibOrgBouncycastleAsn1X509AlgorithmIdentifier_getInstanceWithId_([e nextElement]);
  }
  else {
    self->authenticatedAttributes_ = nil;
    self->digEncryptionAlgorithm_ = LibOrgBouncycastleAsn1X509AlgorithmIdentifier_getInstanceWithId_(obj);
  }
  self->encryptedDigest_ = LibOrgBouncycastleAsn1ASN1OctetString_getInstanceWithId_([e nextElement]);
  if ([e hasMoreElements]) {
    self->unauthenticatedAttributes_ = LibOrgBouncycastleAsn1ASN1Set_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_((LibOrgBouncycastleAsn1ASN1TaggedObject *) cast_chk([e nextElement], [LibOrgBouncycastleAsn1ASN1TaggedObject class]), false);
  }
  else {
    self->unauthenticatedAttributes_ = nil;
  }
}

LibOrgBouncycastleAsn1PkcsSignerInfo *new_LibOrgBouncycastleAsn1PkcsSignerInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1PkcsSignerInfo, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1PkcsSignerInfo *create_LibOrgBouncycastleAsn1PkcsSignerInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1PkcsSignerInfo, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1PkcsSignerInfo)
