//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/esf/SigPolicyQualifierInfo.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1Object.h"
#include "ASN1ObjectIdentifier.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "DERSequence.h"
#include "J2ObjC_source.h"
#include "SigPolicyQualifierInfo.h"

@interface LibOrgBouncycastleAsn1EsfSigPolicyQualifierInfo () {
 @public
  LibOrgBouncycastleAsn1ASN1ObjectIdentifier *sigPolicyQualifierId_;
  id<LibOrgBouncycastleAsn1ASN1Encodable> sigQualifier_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1EsfSigPolicyQualifierInfo, sigPolicyQualifierId_, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1EsfSigPolicyQualifierInfo, sigQualifier_, id<LibOrgBouncycastleAsn1ASN1Encodable>)

__attribute__((unused)) static void LibOrgBouncycastleAsn1EsfSigPolicyQualifierInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1EsfSigPolicyQualifierInfo *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1EsfSigPolicyQualifierInfo *new_LibOrgBouncycastleAsn1EsfSigPolicyQualifierInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1EsfSigPolicyQualifierInfo *create_LibOrgBouncycastleAsn1EsfSigPolicyQualifierInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

@implementation LibOrgBouncycastleAsn1EsfSigPolicyQualifierInfo

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)sigPolicyQualifierId
                           withLibOrgBouncycastleAsn1ASN1Encodable:(id<LibOrgBouncycastleAsn1ASN1Encodable>)sigQualifier {
  LibOrgBouncycastleAsn1EsfSigPolicyQualifierInfo_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(self, sigPolicyQualifierId, sigQualifier);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1EsfSigPolicyQualifierInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

+ (LibOrgBouncycastleAsn1EsfSigPolicyQualifierInfo *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1EsfSigPolicyQualifierInfo_getInstanceWithId_(obj);
}

- (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)getSigPolicyQualifierId {
  return new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_([((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(sigPolicyQualifierId_)) getId]);
}

- (id<LibOrgBouncycastleAsn1ASN1Encodable>)getSigQualifier {
  return sigQualifier_;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:sigPolicyQualifierId_];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:sigQualifier_];
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1EsfSigPolicyQualifierInfo;", 0x9, 2, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Encodable;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:withLibOrgBouncycastleAsn1ASN1Encodable:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[2].selector = @selector(getInstanceWithId:);
  methods[3].selector = @selector(getSigPolicyQualifierId);
  methods[4].selector = @selector(getSigQualifier);
  methods[5].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "sigPolicyQualifierId_", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "sigQualifier_", "LLibOrgBouncycastleAsn1ASN1Encodable;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;LLibOrgBouncycastleAsn1ASN1Encodable;", "LLibOrgBouncycastleAsn1ASN1Sequence;", "getInstance", "LNSObject;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1EsfSigPolicyQualifierInfo = { "SigPolicyQualifierInfo", "lib.org.bouncycastle.asn1.esf", ptrTable, methods, fields, 7, 0x1, 6, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1EsfSigPolicyQualifierInfo;
}

@end

void LibOrgBouncycastleAsn1EsfSigPolicyQualifierInfo_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1EsfSigPolicyQualifierInfo *self, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *sigPolicyQualifierId, id<LibOrgBouncycastleAsn1ASN1Encodable> sigQualifier) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->sigPolicyQualifierId_ = sigPolicyQualifierId;
  self->sigQualifier_ = sigQualifier;
}

LibOrgBouncycastleAsn1EsfSigPolicyQualifierInfo *new_LibOrgBouncycastleAsn1EsfSigPolicyQualifierInfo_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *sigPolicyQualifierId, id<LibOrgBouncycastleAsn1ASN1Encodable> sigQualifier) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1EsfSigPolicyQualifierInfo, initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_, sigPolicyQualifierId, sigQualifier)
}

LibOrgBouncycastleAsn1EsfSigPolicyQualifierInfo *create_LibOrgBouncycastleAsn1EsfSigPolicyQualifierInfo_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *sigPolicyQualifierId, id<LibOrgBouncycastleAsn1ASN1Encodable> sigQualifier) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1EsfSigPolicyQualifierInfo, initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_, sigPolicyQualifierId, sigQualifier)
}

void LibOrgBouncycastleAsn1EsfSigPolicyQualifierInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1EsfSigPolicyQualifierInfo *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->sigPolicyQualifierId_ = LibOrgBouncycastleAsn1ASN1ObjectIdentifier_getInstanceWithId_([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjectAtWithInt:0]);
  self->sigQualifier_ = [seq getObjectAtWithInt:1];
}

LibOrgBouncycastleAsn1EsfSigPolicyQualifierInfo *new_LibOrgBouncycastleAsn1EsfSigPolicyQualifierInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1EsfSigPolicyQualifierInfo, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1EsfSigPolicyQualifierInfo *create_LibOrgBouncycastleAsn1EsfSigPolicyQualifierInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1EsfSigPolicyQualifierInfo, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1EsfSigPolicyQualifierInfo *LibOrgBouncycastleAsn1EsfSigPolicyQualifierInfo_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1EsfSigPolicyQualifierInfo_initialize();
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1EsfSigPolicyQualifierInfo class]]) {
    return (LibOrgBouncycastleAsn1EsfSigPolicyQualifierInfo *) obj;
  }
  else if (obj != nil) {
    return new_LibOrgBouncycastleAsn1EsfSigPolicyQualifierInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(obj));
  }
  return nil;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1EsfSigPolicyQualifierInfo)
