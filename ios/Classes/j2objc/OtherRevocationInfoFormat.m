//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cms/OtherRevocationInfoFormat.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1Object.h"
#include "ASN1ObjectIdentifier.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "ASN1TaggedObject.h"
#include "DERSequence.h"
#include "J2ObjC_source.h"
#include "OtherRevocationInfoFormat.h"

@interface LibOrgBouncycastleAsn1CmsOtherRevocationInfoFormat () {
 @public
  LibOrgBouncycastleAsn1ASN1ObjectIdentifier *otherRevInfoFormat_;
  id<LibOrgBouncycastleAsn1ASN1Encodable> otherRevInfo_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmsOtherRevocationInfoFormat, otherRevInfoFormat_, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmsOtherRevocationInfoFormat, otherRevInfo_, id<LibOrgBouncycastleAsn1ASN1Encodable>)

__attribute__((unused)) static void LibOrgBouncycastleAsn1CmsOtherRevocationInfoFormat_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmsOtherRevocationInfoFormat *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1CmsOtherRevocationInfoFormat *new_LibOrgBouncycastleAsn1CmsOtherRevocationInfoFormat_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1CmsOtherRevocationInfoFormat *create_LibOrgBouncycastleAsn1CmsOtherRevocationInfoFormat_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

@implementation LibOrgBouncycastleAsn1CmsOtherRevocationInfoFormat

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)otherRevInfoFormat
                           withLibOrgBouncycastleAsn1ASN1Encodable:(id<LibOrgBouncycastleAsn1ASN1Encodable>)otherRevInfo {
  LibOrgBouncycastleAsn1CmsOtherRevocationInfoFormat_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(self, otherRevInfoFormat, otherRevInfo);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1CmsOtherRevocationInfoFormat_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

+ (LibOrgBouncycastleAsn1CmsOtherRevocationInfoFormat *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                                  withBoolean:(jboolean)explicit_ {
  return LibOrgBouncycastleAsn1CmsOtherRevocationInfoFormat_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_);
}

+ (LibOrgBouncycastleAsn1CmsOtherRevocationInfoFormat *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1CmsOtherRevocationInfoFormat_getInstanceWithId_(obj);
}

- (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)getInfoFormat {
  return otherRevInfoFormat_;
}

- (id<LibOrgBouncycastleAsn1ASN1Encodable>)getInfo {
  return otherRevInfo_;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:otherRevInfoFormat_];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:otherRevInfo_];
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmsOtherRevocationInfoFormat;", 0x9, 2, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmsOtherRevocationInfoFormat;", 0x9, 2, 4, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Encodable;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:withLibOrgBouncycastleAsn1ASN1Encodable:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[2].selector = @selector(getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:withBoolean:);
  methods[3].selector = @selector(getInstanceWithId:);
  methods[4].selector = @selector(getInfoFormat);
  methods[5].selector = @selector(getInfo);
  methods[6].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "otherRevInfoFormat_", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "otherRevInfo_", "LLibOrgBouncycastleAsn1ASN1Encodable;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;LLibOrgBouncycastleAsn1ASN1Encodable;", "LLibOrgBouncycastleAsn1ASN1Sequence;", "getInstance", "LLibOrgBouncycastleAsn1ASN1TaggedObject;Z", "LNSObject;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1CmsOtherRevocationInfoFormat = { "OtherRevocationInfoFormat", "lib.org.bouncycastle.asn1.cms", ptrTable, methods, fields, 7, 0x1, 7, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1CmsOtherRevocationInfoFormat;
}

@end

void LibOrgBouncycastleAsn1CmsOtherRevocationInfoFormat_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1CmsOtherRevocationInfoFormat *self, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *otherRevInfoFormat, id<LibOrgBouncycastleAsn1ASN1Encodable> otherRevInfo) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->otherRevInfoFormat_ = otherRevInfoFormat;
  self->otherRevInfo_ = otherRevInfo;
}

LibOrgBouncycastleAsn1CmsOtherRevocationInfoFormat *new_LibOrgBouncycastleAsn1CmsOtherRevocationInfoFormat_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *otherRevInfoFormat, id<LibOrgBouncycastleAsn1ASN1Encodable> otherRevInfo) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmsOtherRevocationInfoFormat, initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_, otherRevInfoFormat, otherRevInfo)
}

LibOrgBouncycastleAsn1CmsOtherRevocationInfoFormat *create_LibOrgBouncycastleAsn1CmsOtherRevocationInfoFormat_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *otherRevInfoFormat, id<LibOrgBouncycastleAsn1ASN1Encodable> otherRevInfo) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmsOtherRevocationInfoFormat, initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_, otherRevInfoFormat, otherRevInfo)
}

void LibOrgBouncycastleAsn1CmsOtherRevocationInfoFormat_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmsOtherRevocationInfoFormat *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->otherRevInfoFormat_ = LibOrgBouncycastleAsn1ASN1ObjectIdentifier_getInstanceWithId_([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjectAtWithInt:0]);
  self->otherRevInfo_ = [seq getObjectAtWithInt:1];
}

LibOrgBouncycastleAsn1CmsOtherRevocationInfoFormat *new_LibOrgBouncycastleAsn1CmsOtherRevocationInfoFormat_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmsOtherRevocationInfoFormat, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1CmsOtherRevocationInfoFormat *create_LibOrgBouncycastleAsn1CmsOtherRevocationInfoFormat_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmsOtherRevocationInfoFormat, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1CmsOtherRevocationInfoFormat *LibOrgBouncycastleAsn1CmsOtherRevocationInfoFormat_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_) {
  LibOrgBouncycastleAsn1CmsOtherRevocationInfoFormat_initialize();
  return LibOrgBouncycastleAsn1CmsOtherRevocationInfoFormat_getInstanceWithId_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_));
}

LibOrgBouncycastleAsn1CmsOtherRevocationInfoFormat *LibOrgBouncycastleAsn1CmsOtherRevocationInfoFormat_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1CmsOtherRevocationInfoFormat_initialize();
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1CmsOtherRevocationInfoFormat class]]) {
    return (LibOrgBouncycastleAsn1CmsOtherRevocationInfoFormat *) obj;
  }
  if (obj != nil) {
    return new_LibOrgBouncycastleAsn1CmsOtherRevocationInfoFormat_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(obj));
  }
  return nil;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1CmsOtherRevocationInfoFormat)
