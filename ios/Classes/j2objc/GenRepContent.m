//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cmp/GenRepContent.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1Object.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "DERSequence.h"
#include "GenRepContent.h"
#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "InfoTypeAndValue.h"
#include "J2ObjC_source.h"

@interface LibOrgBouncycastleAsn1CmpGenRepContent () {
 @public
  LibOrgBouncycastleAsn1ASN1Sequence *content_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmpGenRepContent, content_, LibOrgBouncycastleAsn1ASN1Sequence *)

__attribute__((unused)) static void LibOrgBouncycastleAsn1CmpGenRepContent_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmpGenRepContent *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1CmpGenRepContent *new_LibOrgBouncycastleAsn1CmpGenRepContent_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1CmpGenRepContent *create_LibOrgBouncycastleAsn1CmpGenRepContent_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

@implementation LibOrgBouncycastleAsn1CmpGenRepContent

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1CmpGenRepContent_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

+ (LibOrgBouncycastleAsn1CmpGenRepContent *)getInstanceWithId:(id)o {
  return LibOrgBouncycastleAsn1CmpGenRepContent_getInstanceWithId_(o);
}

- (instancetype)initWithLibOrgBouncycastleAsn1CmpInfoTypeAndValue:(LibOrgBouncycastleAsn1CmpInfoTypeAndValue *)itv {
  LibOrgBouncycastleAsn1CmpGenRepContent_initWithLibOrgBouncycastleAsn1CmpInfoTypeAndValue_(self, itv);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1CmpInfoTypeAndValueArray:(IOSObjectArray *)itv {
  LibOrgBouncycastleAsn1CmpGenRepContent_initWithLibOrgBouncycastleAsn1CmpInfoTypeAndValueArray_(self, itv);
  return self;
}

- (IOSObjectArray *)toInfoTypeAndValueArray {
  IOSObjectArray *result = [IOSObjectArray newArrayWithLength:[((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(content_)) size] type:LibOrgBouncycastleAsn1CmpInfoTypeAndValue_class_()];
  for (jint i = 0; i != result->size_; i++) {
    (void) IOSObjectArray_Set(result, i, LibOrgBouncycastleAsn1CmpInfoTypeAndValue_getInstanceWithId_([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(content_)) getObjectAtWithInt:i]));
  }
  return result;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  return content_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, 0, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmpGenRepContent;", 0x9, 1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, "[LLibOrgBouncycastleAsn1CmpInfoTypeAndValue;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[1].selector = @selector(getInstanceWithId:);
  methods[2].selector = @selector(initWithLibOrgBouncycastleAsn1CmpInfoTypeAndValue:);
  methods[3].selector = @selector(initWithLibOrgBouncycastleAsn1CmpInfoTypeAndValueArray:);
  methods[4].selector = @selector(toInfoTypeAndValueArray);
  methods[5].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "content_", "LLibOrgBouncycastleAsn1ASN1Sequence;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1ASN1Sequence;", "getInstance", "LNSObject;", "LLibOrgBouncycastleAsn1CmpInfoTypeAndValue;", "[LLibOrgBouncycastleAsn1CmpInfoTypeAndValue;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1CmpGenRepContent = { "GenRepContent", "lib.org.bouncycastle.asn1.cmp", ptrTable, methods, fields, 7, 0x1, 6, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1CmpGenRepContent;
}

@end

void LibOrgBouncycastleAsn1CmpGenRepContent_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmpGenRepContent *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->content_ = seq;
}

LibOrgBouncycastleAsn1CmpGenRepContent *new_LibOrgBouncycastleAsn1CmpGenRepContent_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmpGenRepContent, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1CmpGenRepContent *create_LibOrgBouncycastleAsn1CmpGenRepContent_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmpGenRepContent, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1CmpGenRepContent *LibOrgBouncycastleAsn1CmpGenRepContent_getInstanceWithId_(id o) {
  LibOrgBouncycastleAsn1CmpGenRepContent_initialize();
  if ([o isKindOfClass:[LibOrgBouncycastleAsn1CmpGenRepContent class]]) {
    return (LibOrgBouncycastleAsn1CmpGenRepContent *) o;
  }
  if (o != nil) {
    return new_LibOrgBouncycastleAsn1CmpGenRepContent_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(o));
  }
  return nil;
}

void LibOrgBouncycastleAsn1CmpGenRepContent_initWithLibOrgBouncycastleAsn1CmpInfoTypeAndValue_(LibOrgBouncycastleAsn1CmpGenRepContent *self, LibOrgBouncycastleAsn1CmpInfoTypeAndValue *itv) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->content_ = new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1Encodable_(itv);
}

LibOrgBouncycastleAsn1CmpGenRepContent *new_LibOrgBouncycastleAsn1CmpGenRepContent_initWithLibOrgBouncycastleAsn1CmpInfoTypeAndValue_(LibOrgBouncycastleAsn1CmpInfoTypeAndValue *itv) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmpGenRepContent, initWithLibOrgBouncycastleAsn1CmpInfoTypeAndValue_, itv)
}

LibOrgBouncycastleAsn1CmpGenRepContent *create_LibOrgBouncycastleAsn1CmpGenRepContent_initWithLibOrgBouncycastleAsn1CmpInfoTypeAndValue_(LibOrgBouncycastleAsn1CmpInfoTypeAndValue *itv) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmpGenRepContent, initWithLibOrgBouncycastleAsn1CmpInfoTypeAndValue_, itv)
}

void LibOrgBouncycastleAsn1CmpGenRepContent_initWithLibOrgBouncycastleAsn1CmpInfoTypeAndValueArray_(LibOrgBouncycastleAsn1CmpGenRepContent *self, IOSObjectArray *itv) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  for (jint i = 0; i < ((IOSObjectArray *) nil_chk(itv))->size_; i++) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:IOSObjectArray_Get(itv, i)];
  }
  self->content_ = new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

LibOrgBouncycastleAsn1CmpGenRepContent *new_LibOrgBouncycastleAsn1CmpGenRepContent_initWithLibOrgBouncycastleAsn1CmpInfoTypeAndValueArray_(IOSObjectArray *itv) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmpGenRepContent, initWithLibOrgBouncycastleAsn1CmpInfoTypeAndValueArray_, itv)
}

LibOrgBouncycastleAsn1CmpGenRepContent *create_LibOrgBouncycastleAsn1CmpGenRepContent_initWithLibOrgBouncycastleAsn1CmpInfoTypeAndValueArray_(IOSObjectArray *itv) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmpGenRepContent, initWithLibOrgBouncycastleAsn1CmpInfoTypeAndValueArray_, itv)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1CmpGenRepContent)
