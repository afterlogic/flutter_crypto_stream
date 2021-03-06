//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cmp/InfoTypeAndValue.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1Object.h"
#include "ASN1ObjectIdentifier.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "DERSequence.h"
#include "InfoTypeAndValue.h"
#include "J2ObjC_source.h"

@interface LibOrgBouncycastleAsn1CmpInfoTypeAndValue () {
 @public
  LibOrgBouncycastleAsn1ASN1ObjectIdentifier *infoType_;
  id<LibOrgBouncycastleAsn1ASN1Encodable> infoValue_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmpInfoTypeAndValue, infoType_, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmpInfoTypeAndValue, infoValue_, id<LibOrgBouncycastleAsn1ASN1Encodable>)

__attribute__((unused)) static void LibOrgBouncycastleAsn1CmpInfoTypeAndValue_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmpInfoTypeAndValue *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1CmpInfoTypeAndValue *new_LibOrgBouncycastleAsn1CmpInfoTypeAndValue_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1CmpInfoTypeAndValue *create_LibOrgBouncycastleAsn1CmpInfoTypeAndValue_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

@implementation LibOrgBouncycastleAsn1CmpInfoTypeAndValue

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1CmpInfoTypeAndValue_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

+ (LibOrgBouncycastleAsn1CmpInfoTypeAndValue *)getInstanceWithId:(id)o {
  return LibOrgBouncycastleAsn1CmpInfoTypeAndValue_getInstanceWithId_(o);
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)infoType {
  LibOrgBouncycastleAsn1CmpInfoTypeAndValue_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(self, infoType);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)infoType
                           withLibOrgBouncycastleAsn1ASN1Encodable:(id<LibOrgBouncycastleAsn1ASN1Encodable>)optionalValue {
  LibOrgBouncycastleAsn1CmpInfoTypeAndValue_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(self, infoType, optionalValue);
  return self;
}

- (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)getInfoType {
  return infoType_;
}

- (id<LibOrgBouncycastleAsn1ASN1Encodable>)getInfoValue {
  return infoValue_;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:infoType_];
  if (infoValue_ != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:infoValue_];
  }
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, 0, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmpInfoTypeAndValue;", 0x9, 1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Encodable;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[1].selector = @selector(getInstanceWithId:);
  methods[2].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:);
  methods[3].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:withLibOrgBouncycastleAsn1ASN1Encodable:);
  methods[4].selector = @selector(getInfoType);
  methods[5].selector = @selector(getInfoValue);
  methods[6].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "infoType_", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "infoValue_", "LLibOrgBouncycastleAsn1ASN1Encodable;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1ASN1Sequence;", "getInstance", "LNSObject;", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;LLibOrgBouncycastleAsn1ASN1Encodable;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1CmpInfoTypeAndValue = { "InfoTypeAndValue", "lib.org.bouncycastle.asn1.cmp", ptrTable, methods, fields, 7, 0x1, 7, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1CmpInfoTypeAndValue;
}

@end

void LibOrgBouncycastleAsn1CmpInfoTypeAndValue_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmpInfoTypeAndValue *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->infoType_ = LibOrgBouncycastleAsn1ASN1ObjectIdentifier_getInstanceWithId_([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjectAtWithInt:0]);
  if ([seq size] > 1) {
    self->infoValue_ = [seq getObjectAtWithInt:1];
  }
}

LibOrgBouncycastleAsn1CmpInfoTypeAndValue *new_LibOrgBouncycastleAsn1CmpInfoTypeAndValue_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmpInfoTypeAndValue, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1CmpInfoTypeAndValue *create_LibOrgBouncycastleAsn1CmpInfoTypeAndValue_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmpInfoTypeAndValue, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1CmpInfoTypeAndValue *LibOrgBouncycastleAsn1CmpInfoTypeAndValue_getInstanceWithId_(id o) {
  LibOrgBouncycastleAsn1CmpInfoTypeAndValue_initialize();
  if ([o isKindOfClass:[LibOrgBouncycastleAsn1CmpInfoTypeAndValue class]]) {
    return (LibOrgBouncycastleAsn1CmpInfoTypeAndValue *) o;
  }
  if (o != nil) {
    return new_LibOrgBouncycastleAsn1CmpInfoTypeAndValue_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(o));
  }
  return nil;
}

void LibOrgBouncycastleAsn1CmpInfoTypeAndValue_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleAsn1CmpInfoTypeAndValue *self, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *infoType) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->infoType_ = infoType;
  self->infoValue_ = nil;
}

LibOrgBouncycastleAsn1CmpInfoTypeAndValue *new_LibOrgBouncycastleAsn1CmpInfoTypeAndValue_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *infoType) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmpInfoTypeAndValue, initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_, infoType)
}

LibOrgBouncycastleAsn1CmpInfoTypeAndValue *create_LibOrgBouncycastleAsn1CmpInfoTypeAndValue_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *infoType) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmpInfoTypeAndValue, initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_, infoType)
}

void LibOrgBouncycastleAsn1CmpInfoTypeAndValue_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1CmpInfoTypeAndValue *self, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *infoType, id<LibOrgBouncycastleAsn1ASN1Encodable> optionalValue) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->infoType_ = infoType;
  self->infoValue_ = optionalValue;
}

LibOrgBouncycastleAsn1CmpInfoTypeAndValue *new_LibOrgBouncycastleAsn1CmpInfoTypeAndValue_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *infoType, id<LibOrgBouncycastleAsn1ASN1Encodable> optionalValue) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmpInfoTypeAndValue, initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_, infoType, optionalValue)
}

LibOrgBouncycastleAsn1CmpInfoTypeAndValue *create_LibOrgBouncycastleAsn1CmpInfoTypeAndValue_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *infoType, id<LibOrgBouncycastleAsn1ASN1Encodable> optionalValue) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmpInfoTypeAndValue, initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_, infoType, optionalValue)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1CmpInfoTypeAndValue)
