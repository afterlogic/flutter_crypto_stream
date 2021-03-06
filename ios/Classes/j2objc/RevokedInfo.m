//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/ocsp/RevokedInfo.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1Enumerated.h"
#include "ASN1GeneralizedTime.h"
#include "ASN1Object.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "ASN1TaggedObject.h"
#include "CRLReason.h"
#include "DERSequence.h"
#include "DERTaggedObject.h"
#include "J2ObjC_source.h"
#include "RevokedInfo.h"

@interface LibOrgBouncycastleAsn1OcspRevokedInfo () {
 @public
  LibOrgBouncycastleAsn1ASN1GeneralizedTime *revocationTime_;
  LibOrgBouncycastleAsn1X509CRLReason *revocationReason_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1OcspRevokedInfo, revocationTime_, LibOrgBouncycastleAsn1ASN1GeneralizedTime *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1OcspRevokedInfo, revocationReason_, LibOrgBouncycastleAsn1X509CRLReason *)

__attribute__((unused)) static void LibOrgBouncycastleAsn1OcspRevokedInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1OcspRevokedInfo *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1OcspRevokedInfo *new_LibOrgBouncycastleAsn1OcspRevokedInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1OcspRevokedInfo *create_LibOrgBouncycastleAsn1OcspRevokedInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

@implementation LibOrgBouncycastleAsn1OcspRevokedInfo

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1GeneralizedTime:(LibOrgBouncycastleAsn1ASN1GeneralizedTime *)revocationTime
                          withLibOrgBouncycastleAsn1X509CRLReason:(LibOrgBouncycastleAsn1X509CRLReason *)revocationReason {
  LibOrgBouncycastleAsn1OcspRevokedInfo_initWithLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1X509CRLReason_(self, revocationTime, revocationReason);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1OcspRevokedInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

+ (LibOrgBouncycastleAsn1OcspRevokedInfo *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                     withBoolean:(jboolean)explicit_ {
  return LibOrgBouncycastleAsn1OcspRevokedInfo_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_);
}

+ (LibOrgBouncycastleAsn1OcspRevokedInfo *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1OcspRevokedInfo_getInstanceWithId_(obj);
}

- (LibOrgBouncycastleAsn1ASN1GeneralizedTime *)getRevocationTime {
  return revocationTime_;
}

- (LibOrgBouncycastleAsn1X509CRLReason *)getRevocationReason {
  return revocationReason_;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:revocationTime_];
  if (revocationReason_ != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERTaggedObject_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(true, 0, revocationReason_)];
  }
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1OcspRevokedInfo;", 0x9, 2, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1OcspRevokedInfo;", 0x9, 2, 4, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1GeneralizedTime;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509CRLReason;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1GeneralizedTime:withLibOrgBouncycastleAsn1X509CRLReason:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[2].selector = @selector(getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:withBoolean:);
  methods[3].selector = @selector(getInstanceWithId:);
  methods[4].selector = @selector(getRevocationTime);
  methods[5].selector = @selector(getRevocationReason);
  methods[6].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "revocationTime_", "LLibOrgBouncycastleAsn1ASN1GeneralizedTime;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "revocationReason_", "LLibOrgBouncycastleAsn1X509CRLReason;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1ASN1GeneralizedTime;LLibOrgBouncycastleAsn1X509CRLReason;", "LLibOrgBouncycastleAsn1ASN1Sequence;", "getInstance", "LLibOrgBouncycastleAsn1ASN1TaggedObject;Z", "LNSObject;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1OcspRevokedInfo = { "RevokedInfo", "lib.org.bouncycastle.asn1.ocsp", ptrTable, methods, fields, 7, 0x1, 7, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1OcspRevokedInfo;
}

@end

void LibOrgBouncycastleAsn1OcspRevokedInfo_initWithLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1X509CRLReason_(LibOrgBouncycastleAsn1OcspRevokedInfo *self, LibOrgBouncycastleAsn1ASN1GeneralizedTime *revocationTime, LibOrgBouncycastleAsn1X509CRLReason *revocationReason) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->revocationTime_ = revocationTime;
  self->revocationReason_ = revocationReason;
}

LibOrgBouncycastleAsn1OcspRevokedInfo *new_LibOrgBouncycastleAsn1OcspRevokedInfo_initWithLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1X509CRLReason_(LibOrgBouncycastleAsn1ASN1GeneralizedTime *revocationTime, LibOrgBouncycastleAsn1X509CRLReason *revocationReason) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1OcspRevokedInfo, initWithLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1X509CRLReason_, revocationTime, revocationReason)
}

LibOrgBouncycastleAsn1OcspRevokedInfo *create_LibOrgBouncycastleAsn1OcspRevokedInfo_initWithLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1X509CRLReason_(LibOrgBouncycastleAsn1ASN1GeneralizedTime *revocationTime, LibOrgBouncycastleAsn1X509CRLReason *revocationReason) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1OcspRevokedInfo, initWithLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1X509CRLReason_, revocationTime, revocationReason)
}

void LibOrgBouncycastleAsn1OcspRevokedInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1OcspRevokedInfo *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->revocationTime_ = LibOrgBouncycastleAsn1ASN1GeneralizedTime_getInstanceWithId_([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjectAtWithInt:0]);
  if ([seq size] > 1) {
    self->revocationReason_ = LibOrgBouncycastleAsn1X509CRLReason_getInstanceWithId_(LibOrgBouncycastleAsn1ASN1Enumerated_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_((LibOrgBouncycastleAsn1ASN1TaggedObject *) cast_chk([seq getObjectAtWithInt:1], [LibOrgBouncycastleAsn1ASN1TaggedObject class]), true));
  }
}

LibOrgBouncycastleAsn1OcspRevokedInfo *new_LibOrgBouncycastleAsn1OcspRevokedInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1OcspRevokedInfo, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1OcspRevokedInfo *create_LibOrgBouncycastleAsn1OcspRevokedInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1OcspRevokedInfo, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1OcspRevokedInfo *LibOrgBouncycastleAsn1OcspRevokedInfo_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_) {
  LibOrgBouncycastleAsn1OcspRevokedInfo_initialize();
  return LibOrgBouncycastleAsn1OcspRevokedInfo_getInstanceWithId_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_));
}

LibOrgBouncycastleAsn1OcspRevokedInfo *LibOrgBouncycastleAsn1OcspRevokedInfo_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1OcspRevokedInfo_initialize();
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1OcspRevokedInfo class]]) {
    return (LibOrgBouncycastleAsn1OcspRevokedInfo *) obj;
  }
  else if (obj != nil) {
    return new_LibOrgBouncycastleAsn1OcspRevokedInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(obj));
  }
  return nil;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1OcspRevokedInfo)
