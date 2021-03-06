//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/ess/OtherCertID.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1Object.h"
#include "ASN1ObjectIdentifier.h"
#include "ASN1OctetString.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "AlgorithmIdentifier.h"
#include "DERSequence.h"
#include "DigestInfo.h"
#include "IOSPrimitiveArray.h"
#include "IssuerSerial.h"
#include "J2ObjC_source.h"
#include "OIWObjectIdentifiers.h"
#include "OtherCertID.h"
#include "java/lang/IllegalArgumentException.h"

@interface LibOrgBouncycastleAsn1EssOtherCertID () {
 @public
  id<LibOrgBouncycastleAsn1ASN1Encodable> otherCertHash_;
  LibOrgBouncycastleAsn1X509IssuerSerial *issuerSerial_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1EssOtherCertID, otherCertHash_, id<LibOrgBouncycastleAsn1ASN1Encodable>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1EssOtherCertID, issuerSerial_, LibOrgBouncycastleAsn1X509IssuerSerial *)

__attribute__((unused)) static void LibOrgBouncycastleAsn1EssOtherCertID_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1EssOtherCertID *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1EssOtherCertID *new_LibOrgBouncycastleAsn1EssOtherCertID_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1EssOtherCertID *create_LibOrgBouncycastleAsn1EssOtherCertID_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

@implementation LibOrgBouncycastleAsn1EssOtherCertID

+ (LibOrgBouncycastleAsn1EssOtherCertID *)getInstanceWithId:(id)o {
  return LibOrgBouncycastleAsn1EssOtherCertID_getInstanceWithId_(o);
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1EssOtherCertID_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier:(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)algId
                                                        withByteArray:(IOSByteArray *)digest {
  LibOrgBouncycastleAsn1EssOtherCertID_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_(self, algId, digest);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier:(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)algId
                                                        withByteArray:(IOSByteArray *)digest
                           withLibOrgBouncycastleAsn1X509IssuerSerial:(LibOrgBouncycastleAsn1X509IssuerSerial *)issuerSerial {
  LibOrgBouncycastleAsn1EssOtherCertID_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_withLibOrgBouncycastleAsn1X509IssuerSerial_(self, algId, digest, issuerSerial);
  return self;
}

- (LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)getAlgorithmHash {
  if ([[((id<LibOrgBouncycastleAsn1ASN1Encodable>) nil_chk(otherCertHash_)) toASN1Primitive] isKindOfClass:[LibOrgBouncycastleAsn1ASN1OctetString class]]) {
    return new_LibOrgBouncycastleAsn1X509AlgorithmIdentifier_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(JreLoadStatic(LibOrgBouncycastleAsn1OiwOIWObjectIdentifiers, idSHA1));
  }
  else {
    return [((LibOrgBouncycastleAsn1X509DigestInfo *) nil_chk(LibOrgBouncycastleAsn1X509DigestInfo_getInstanceWithId_(otherCertHash_))) getAlgorithmId];
  }
}

- (IOSByteArray *)getCertHash {
  if ([[((id<LibOrgBouncycastleAsn1ASN1Encodable>) nil_chk(otherCertHash_)) toASN1Primitive] isKindOfClass:[LibOrgBouncycastleAsn1ASN1OctetString class]]) {
    return [((LibOrgBouncycastleAsn1ASN1OctetString *) nil_chk(((LibOrgBouncycastleAsn1ASN1OctetString *) cast_chk([((id<LibOrgBouncycastleAsn1ASN1Encodable>) nil_chk(otherCertHash_)) toASN1Primitive], [LibOrgBouncycastleAsn1ASN1OctetString class])))) getOctets];
  }
  else {
    return [((LibOrgBouncycastleAsn1X509DigestInfo *) nil_chk(LibOrgBouncycastleAsn1X509DigestInfo_getInstanceWithId_(otherCertHash_))) getDigest];
  }
}

- (LibOrgBouncycastleAsn1X509IssuerSerial *)getIssuerSerial {
  return issuerSerial_;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:otherCertHash_];
  if (issuerSerial_ != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:issuerSerial_];
  }
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LLibOrgBouncycastleAsn1EssOtherCertID;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509AlgorithmIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509IssuerSerial;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithId:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[2].selector = @selector(initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier:withByteArray:);
  methods[3].selector = @selector(initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier:withByteArray:withLibOrgBouncycastleAsn1X509IssuerSerial:);
  methods[4].selector = @selector(getAlgorithmHash);
  methods[5].selector = @selector(getCertHash);
  methods[6].selector = @selector(getIssuerSerial);
  methods[7].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "otherCertHash_", "LLibOrgBouncycastleAsn1ASN1Encodable;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "issuerSerial_", "LLibOrgBouncycastleAsn1X509IssuerSerial;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LNSObject;", "LLibOrgBouncycastleAsn1ASN1Sequence;", "LLibOrgBouncycastleAsn1X509AlgorithmIdentifier;[B", "LLibOrgBouncycastleAsn1X509AlgorithmIdentifier;[BLLibOrgBouncycastleAsn1X509IssuerSerial;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1EssOtherCertID = { "OtherCertID", "lib.org.bouncycastle.asn1.ess", ptrTable, methods, fields, 7, 0x1, 8, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1EssOtherCertID;
}

@end

LibOrgBouncycastleAsn1EssOtherCertID *LibOrgBouncycastleAsn1EssOtherCertID_getInstanceWithId_(id o) {
  LibOrgBouncycastleAsn1EssOtherCertID_initialize();
  if ([o isKindOfClass:[LibOrgBouncycastleAsn1EssOtherCertID class]]) {
    return (LibOrgBouncycastleAsn1EssOtherCertID *) o;
  }
  else if (o != nil) {
    return new_LibOrgBouncycastleAsn1EssOtherCertID_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(o));
  }
  return nil;
}

void LibOrgBouncycastleAsn1EssOtherCertID_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1EssOtherCertID *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  if ([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) size] < 1 || [seq size] > 2) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$I", @"Bad sequence size: ", [seq size]));
  }
  if ([[((id<LibOrgBouncycastleAsn1ASN1Encodable>) nil_chk([seq getObjectAtWithInt:0])) toASN1Primitive] isKindOfClass:[LibOrgBouncycastleAsn1ASN1OctetString class]]) {
    self->otherCertHash_ = LibOrgBouncycastleAsn1ASN1OctetString_getInstanceWithId_([seq getObjectAtWithInt:0]);
  }
  else {
    self->otherCertHash_ = LibOrgBouncycastleAsn1X509DigestInfo_getInstanceWithId_([seq getObjectAtWithInt:0]);
  }
  if ([seq size] > 1) {
    self->issuerSerial_ = LibOrgBouncycastleAsn1X509IssuerSerial_getInstanceWithId_([seq getObjectAtWithInt:1]);
  }
}

LibOrgBouncycastleAsn1EssOtherCertID *new_LibOrgBouncycastleAsn1EssOtherCertID_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1EssOtherCertID, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1EssOtherCertID *create_LibOrgBouncycastleAsn1EssOtherCertID_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1EssOtherCertID, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

void LibOrgBouncycastleAsn1EssOtherCertID_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_(LibOrgBouncycastleAsn1EssOtherCertID *self, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *algId, IOSByteArray *digest) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->otherCertHash_ = new_LibOrgBouncycastleAsn1X509DigestInfo_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_(algId, digest);
}

LibOrgBouncycastleAsn1EssOtherCertID *new_LibOrgBouncycastleAsn1EssOtherCertID_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *algId, IOSByteArray *digest) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1EssOtherCertID, initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_, algId, digest)
}

LibOrgBouncycastleAsn1EssOtherCertID *create_LibOrgBouncycastleAsn1EssOtherCertID_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *algId, IOSByteArray *digest) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1EssOtherCertID, initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_, algId, digest)
}

void LibOrgBouncycastleAsn1EssOtherCertID_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_withLibOrgBouncycastleAsn1X509IssuerSerial_(LibOrgBouncycastleAsn1EssOtherCertID *self, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *algId, IOSByteArray *digest, LibOrgBouncycastleAsn1X509IssuerSerial *issuerSerial) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->otherCertHash_ = new_LibOrgBouncycastleAsn1X509DigestInfo_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_(algId, digest);
  self->issuerSerial_ = issuerSerial;
}

LibOrgBouncycastleAsn1EssOtherCertID *new_LibOrgBouncycastleAsn1EssOtherCertID_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_withLibOrgBouncycastleAsn1X509IssuerSerial_(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *algId, IOSByteArray *digest, LibOrgBouncycastleAsn1X509IssuerSerial *issuerSerial) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1EssOtherCertID, initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_withLibOrgBouncycastleAsn1X509IssuerSerial_, algId, digest, issuerSerial)
}

LibOrgBouncycastleAsn1EssOtherCertID *create_LibOrgBouncycastleAsn1EssOtherCertID_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_withLibOrgBouncycastleAsn1X509IssuerSerial_(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *algId, IOSByteArray *digest, LibOrgBouncycastleAsn1X509IssuerSerial *issuerSerial) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1EssOtherCertID, initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_withLibOrgBouncycastleAsn1X509IssuerSerial_, algId, digest, issuerSerial)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1EssOtherCertID)
