//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cmc/IdentityProofV2.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1Object.h"
#include "ASN1OctetString.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "AlgorithmIdentifier.h"
#include "Arrays.h"
#include "DEROctetString.h"
#include "DERSequence.h"
#include "IOSPrimitiveArray.h"
#include "IdentityProofV2.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"

@interface LibOrgBouncycastleAsn1CmcIdentityProofV2 () {
 @public
  LibOrgBouncycastleAsn1X509AlgorithmIdentifier *proofAlgID_;
  LibOrgBouncycastleAsn1X509AlgorithmIdentifier *macAlgId_;
  IOSByteArray *witness_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmcIdentityProofV2, proofAlgID_, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmcIdentityProofV2, macAlgId_, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmcIdentityProofV2, witness_, IOSByteArray *)

__attribute__((unused)) static void LibOrgBouncycastleAsn1CmcIdentityProofV2_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmcIdentityProofV2 *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1CmcIdentityProofV2 *new_LibOrgBouncycastleAsn1CmcIdentityProofV2_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1CmcIdentityProofV2 *create_LibOrgBouncycastleAsn1CmcIdentityProofV2_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

@implementation LibOrgBouncycastleAsn1CmcIdentityProofV2

- (instancetype)initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier:(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)proofAlgID
                    withLibOrgBouncycastleAsn1X509AlgorithmIdentifier:(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)macAlgId
                                                        withByteArray:(IOSByteArray *)witness {
  LibOrgBouncycastleAsn1CmcIdentityProofV2_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_(self, proofAlgID, macAlgId, witness);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1CmcIdentityProofV2_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

+ (LibOrgBouncycastleAsn1CmcIdentityProofV2 *)getInstanceWithId:(id)o {
  return LibOrgBouncycastleAsn1CmcIdentityProofV2_getInstanceWithId_(o);
}

- (LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)getProofAlgID {
  return proofAlgID_;
}

- (LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)getMacAlgId {
  return macAlgId_;
}

- (IOSByteArray *)getWitness {
  return LibOrgBouncycastleUtilArrays_cloneWithByteArray_(witness_);
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:proofAlgID_];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:macAlgId_];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DEROctetString_initWithByteArray_([self getWitness])];
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmcIdentityProofV2;", 0x9, 2, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509AlgorithmIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509AlgorithmIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier:withLibOrgBouncycastleAsn1X509AlgorithmIdentifier:withByteArray:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[2].selector = @selector(getInstanceWithId:);
  methods[3].selector = @selector(getProofAlgID);
  methods[4].selector = @selector(getMacAlgId);
  methods[5].selector = @selector(getWitness);
  methods[6].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "proofAlgID_", "LLibOrgBouncycastleAsn1X509AlgorithmIdentifier;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "macAlgId_", "LLibOrgBouncycastleAsn1X509AlgorithmIdentifier;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "witness_", "[B", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1X509AlgorithmIdentifier;LLibOrgBouncycastleAsn1X509AlgorithmIdentifier;[B", "LLibOrgBouncycastleAsn1ASN1Sequence;", "getInstance", "LNSObject;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1CmcIdentityProofV2 = { "IdentityProofV2", "lib.org.bouncycastle.asn1.cmc", ptrTable, methods, fields, 7, 0x1, 7, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1CmcIdentityProofV2;
}

@end

void LibOrgBouncycastleAsn1CmcIdentityProofV2_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_(LibOrgBouncycastleAsn1CmcIdentityProofV2 *self, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *proofAlgID, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *macAlgId, IOSByteArray *witness) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->proofAlgID_ = proofAlgID;
  self->macAlgId_ = macAlgId;
  self->witness_ = LibOrgBouncycastleUtilArrays_cloneWithByteArray_(witness);
}

LibOrgBouncycastleAsn1CmcIdentityProofV2 *new_LibOrgBouncycastleAsn1CmcIdentityProofV2_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *proofAlgID, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *macAlgId, IOSByteArray *witness) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmcIdentityProofV2, initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_, proofAlgID, macAlgId, witness)
}

LibOrgBouncycastleAsn1CmcIdentityProofV2 *create_LibOrgBouncycastleAsn1CmcIdentityProofV2_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *proofAlgID, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *macAlgId, IOSByteArray *witness) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmcIdentityProofV2, initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_, proofAlgID, macAlgId, witness)
}

void LibOrgBouncycastleAsn1CmcIdentityProofV2_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmcIdentityProofV2 *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  if ([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) size] != 3) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"incorrect sequence size");
  }
  self->proofAlgID_ = LibOrgBouncycastleAsn1X509AlgorithmIdentifier_getInstanceWithId_([seq getObjectAtWithInt:0]);
  self->macAlgId_ = LibOrgBouncycastleAsn1X509AlgorithmIdentifier_getInstanceWithId_([seq getObjectAtWithInt:1]);
  self->witness_ = LibOrgBouncycastleUtilArrays_cloneWithByteArray_([((LibOrgBouncycastleAsn1ASN1OctetString *) nil_chk(LibOrgBouncycastleAsn1ASN1OctetString_getInstanceWithId_([seq getObjectAtWithInt:2]))) getOctets]);
}

LibOrgBouncycastleAsn1CmcIdentityProofV2 *new_LibOrgBouncycastleAsn1CmcIdentityProofV2_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmcIdentityProofV2, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1CmcIdentityProofV2 *create_LibOrgBouncycastleAsn1CmcIdentityProofV2_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmcIdentityProofV2, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1CmcIdentityProofV2 *LibOrgBouncycastleAsn1CmcIdentityProofV2_getInstanceWithId_(id o) {
  LibOrgBouncycastleAsn1CmcIdentityProofV2_initialize();
  if ([o isKindOfClass:[LibOrgBouncycastleAsn1CmcIdentityProofV2 class]]) {
    return (LibOrgBouncycastleAsn1CmcIdentityProofV2 *) o;
  }
  if (o != nil) {
    return new_LibOrgBouncycastleAsn1CmcIdentityProofV2_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(o));
  }
  return nil;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1CmcIdentityProofV2)
