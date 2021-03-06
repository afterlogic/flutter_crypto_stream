//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cmp/PollRepContent.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1Integer.h"
#include "ASN1Object.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "DERSequence.h"
#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "J2ObjC_source.h"
#include "PKIFreeText.h"
#include "PollRepContent.h"

@interface LibOrgBouncycastleAsn1CmpPollRepContent () {
 @public
  IOSObjectArray *certReqId_;
  IOSObjectArray *checkAfter_;
  IOSObjectArray *reason_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmpPollRepContent, certReqId_, IOSObjectArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmpPollRepContent, checkAfter_, IOSObjectArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmpPollRepContent, reason_, IOSObjectArray *)

__attribute__((unused)) static void LibOrgBouncycastleAsn1CmpPollRepContent_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmpPollRepContent *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1CmpPollRepContent *new_LibOrgBouncycastleAsn1CmpPollRepContent_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1CmpPollRepContent *create_LibOrgBouncycastleAsn1CmpPollRepContent_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

@implementation LibOrgBouncycastleAsn1CmpPollRepContent

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1CmpPollRepContent_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

+ (LibOrgBouncycastleAsn1CmpPollRepContent *)getInstanceWithId:(id)o {
  return LibOrgBouncycastleAsn1CmpPollRepContent_getInstanceWithId_(o);
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Integer:(LibOrgBouncycastleAsn1ASN1Integer *)certReqId
                    withLibOrgBouncycastleAsn1ASN1Integer:(LibOrgBouncycastleAsn1ASN1Integer *)checkAfter {
  LibOrgBouncycastleAsn1CmpPollRepContent_initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Integer_(self, certReqId, checkAfter);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Integer:(LibOrgBouncycastleAsn1ASN1Integer *)certReqId
                    withLibOrgBouncycastleAsn1ASN1Integer:(LibOrgBouncycastleAsn1ASN1Integer *)checkAfter
                 withLibOrgBouncycastleAsn1CmpPKIFreeText:(LibOrgBouncycastleAsn1CmpPKIFreeText *)reason {
  LibOrgBouncycastleAsn1CmpPollRepContent_initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1CmpPKIFreeText_(self, certReqId, checkAfter, reason);
  return self;
}

- (jint)size {
  return ((IOSObjectArray *) nil_chk(certReqId_))->size_;
}

- (LibOrgBouncycastleAsn1ASN1Integer *)getCertReqIdWithInt:(jint)index {
  return IOSObjectArray_Get(nil_chk(certReqId_), index);
}

- (LibOrgBouncycastleAsn1ASN1Integer *)getCheckAfterWithInt:(jint)index {
  return IOSObjectArray_Get(nil_chk(checkAfter_), index);
}

- (LibOrgBouncycastleAsn1CmpPKIFreeText *)getReasonWithInt:(jint)index {
  return IOSObjectArray_Get(nil_chk(reason_), index);
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *outer = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  for (jint i = 0; i != ((IOSObjectArray *) nil_chk(certReqId_))->size_; i++) {
    LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:IOSObjectArray_Get(nil_chk(certReqId_), i)];
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:IOSObjectArray_Get(nil_chk(checkAfter_), i)];
    if (IOSObjectArray_Get(nil_chk(reason_), i) != nil) {
      [v addWithLibOrgBouncycastleAsn1ASN1Encodable:IOSObjectArray_Get(reason_, i)];
    }
    [outer addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v)];
  }
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(outer);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, 0, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmpPollRepContent;", 0x9, 1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Integer;", 0x1, 5, 6, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Integer;", 0x1, 7, 6, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmpPKIFreeText;", 0x1, 8, 6, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[1].selector = @selector(getInstanceWithId:);
  methods[2].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Integer:withLibOrgBouncycastleAsn1ASN1Integer:);
  methods[3].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Integer:withLibOrgBouncycastleAsn1ASN1Integer:withLibOrgBouncycastleAsn1CmpPKIFreeText:);
  methods[4].selector = @selector(size);
  methods[5].selector = @selector(getCertReqIdWithInt:);
  methods[6].selector = @selector(getCheckAfterWithInt:);
  methods[7].selector = @selector(getReasonWithInt:);
  methods[8].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "certReqId_", "[LLibOrgBouncycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "checkAfter_", "[LLibOrgBouncycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "reason_", "[LLibOrgBouncycastleAsn1CmpPKIFreeText;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1ASN1Sequence;", "getInstance", "LNSObject;", "LLibOrgBouncycastleAsn1ASN1Integer;LLibOrgBouncycastleAsn1ASN1Integer;", "LLibOrgBouncycastleAsn1ASN1Integer;LLibOrgBouncycastleAsn1ASN1Integer;LLibOrgBouncycastleAsn1CmpPKIFreeText;", "getCertReqId", "I", "getCheckAfter", "getReason" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1CmpPollRepContent = { "PollRepContent", "lib.org.bouncycastle.asn1.cmp", ptrTable, methods, fields, 7, 0x1, 9, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1CmpPollRepContent;
}

@end

void LibOrgBouncycastleAsn1CmpPollRepContent_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmpPollRepContent *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->certReqId_ = [IOSObjectArray newArrayWithLength:[((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) size] type:LibOrgBouncycastleAsn1ASN1Integer_class_()];
  self->checkAfter_ = [IOSObjectArray newArrayWithLength:[seq size] type:LibOrgBouncycastleAsn1ASN1Integer_class_()];
  self->reason_ = [IOSObjectArray newArrayWithLength:[seq size] type:LibOrgBouncycastleAsn1CmpPKIFreeText_class_()];
  for (jint i = 0; i != [seq size]; i++) {
    LibOrgBouncycastleAsn1ASN1Sequence *s = LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_([seq getObjectAtWithInt:i]);
    (void) IOSObjectArray_Set(nil_chk(self->certReqId_), i, LibOrgBouncycastleAsn1ASN1Integer_getInstanceWithId_([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(s)) getObjectAtWithInt:0]));
    (void) IOSObjectArray_Set(nil_chk(self->checkAfter_), i, LibOrgBouncycastleAsn1ASN1Integer_getInstanceWithId_([s getObjectAtWithInt:1]));
    if ([s size] > 2) {
      (void) IOSObjectArray_Set(nil_chk(self->reason_), i, LibOrgBouncycastleAsn1CmpPKIFreeText_getInstanceWithId_([s getObjectAtWithInt:2]));
    }
  }
}

LibOrgBouncycastleAsn1CmpPollRepContent *new_LibOrgBouncycastleAsn1CmpPollRepContent_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmpPollRepContent, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1CmpPollRepContent *create_LibOrgBouncycastleAsn1CmpPollRepContent_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmpPollRepContent, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1CmpPollRepContent *LibOrgBouncycastleAsn1CmpPollRepContent_getInstanceWithId_(id o) {
  LibOrgBouncycastleAsn1CmpPollRepContent_initialize();
  if ([o isKindOfClass:[LibOrgBouncycastleAsn1CmpPollRepContent class]]) {
    return (LibOrgBouncycastleAsn1CmpPollRepContent *) o;
  }
  if (o != nil) {
    return new_LibOrgBouncycastleAsn1CmpPollRepContent_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(o));
  }
  return nil;
}

void LibOrgBouncycastleAsn1CmpPollRepContent_initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Integer_(LibOrgBouncycastleAsn1CmpPollRepContent *self, LibOrgBouncycastleAsn1ASN1Integer *certReqId, LibOrgBouncycastleAsn1ASN1Integer *checkAfter) {
  LibOrgBouncycastleAsn1CmpPollRepContent_initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1CmpPKIFreeText_(self, certReqId, checkAfter, nil);
}

LibOrgBouncycastleAsn1CmpPollRepContent *new_LibOrgBouncycastleAsn1CmpPollRepContent_initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Integer_(LibOrgBouncycastleAsn1ASN1Integer *certReqId, LibOrgBouncycastleAsn1ASN1Integer *checkAfter) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmpPollRepContent, initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Integer_, certReqId, checkAfter)
}

LibOrgBouncycastleAsn1CmpPollRepContent *create_LibOrgBouncycastleAsn1CmpPollRepContent_initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Integer_(LibOrgBouncycastleAsn1ASN1Integer *certReqId, LibOrgBouncycastleAsn1ASN1Integer *checkAfter) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmpPollRepContent, initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Integer_, certReqId, checkAfter)
}

void LibOrgBouncycastleAsn1CmpPollRepContent_initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1CmpPKIFreeText_(LibOrgBouncycastleAsn1CmpPollRepContent *self, LibOrgBouncycastleAsn1ASN1Integer *certReqId, LibOrgBouncycastleAsn1ASN1Integer *checkAfter, LibOrgBouncycastleAsn1CmpPKIFreeText *reason) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->certReqId_ = [IOSObjectArray newArrayWithLength:1 type:LibOrgBouncycastleAsn1ASN1Integer_class_()];
  self->checkAfter_ = [IOSObjectArray newArrayWithLength:1 type:LibOrgBouncycastleAsn1ASN1Integer_class_()];
  self->reason_ = [IOSObjectArray newArrayWithLength:1 type:LibOrgBouncycastleAsn1CmpPKIFreeText_class_()];
  (void) IOSObjectArray_Set(self->certReqId_, 0, certReqId);
  (void) IOSObjectArray_Set(self->checkAfter_, 0, checkAfter);
  (void) IOSObjectArray_Set(self->reason_, 0, reason);
}

LibOrgBouncycastleAsn1CmpPollRepContent *new_LibOrgBouncycastleAsn1CmpPollRepContent_initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1CmpPKIFreeText_(LibOrgBouncycastleAsn1ASN1Integer *certReqId, LibOrgBouncycastleAsn1ASN1Integer *checkAfter, LibOrgBouncycastleAsn1CmpPKIFreeText *reason) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmpPollRepContent, initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1CmpPKIFreeText_, certReqId, checkAfter, reason)
}

LibOrgBouncycastleAsn1CmpPollRepContent *create_LibOrgBouncycastleAsn1CmpPollRepContent_initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1CmpPKIFreeText_(LibOrgBouncycastleAsn1ASN1Integer *certReqId, LibOrgBouncycastleAsn1ASN1Integer *checkAfter, LibOrgBouncycastleAsn1CmpPKIFreeText *reason) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmpPollRepContent, initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1CmpPKIFreeText_, certReqId, checkAfter, reason)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1CmpPollRepContent)
