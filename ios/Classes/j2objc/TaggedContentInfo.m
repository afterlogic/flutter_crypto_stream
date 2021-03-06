//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cmc/TaggedContentInfo.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1Object.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "ASN1TaggedObject.h"
#include "Asn1CmsContentInfo.h"
#include "BodyPartID.h"
#include "DERSequence.h"
#include "J2ObjC_source.h"
#include "TaggedContentInfo.h"
#include "java/lang/IllegalArgumentException.h"

@interface LibOrgBouncycastleAsn1CmcTaggedContentInfo () {
 @public
  LibOrgBouncycastleAsn1CmcBodyPartID *bodyPartID_;
  LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo *contentInfo_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmcTaggedContentInfo, bodyPartID_, LibOrgBouncycastleAsn1CmcBodyPartID *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmcTaggedContentInfo, contentInfo_, LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo *)

__attribute__((unused)) static void LibOrgBouncycastleAsn1CmcTaggedContentInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmcTaggedContentInfo *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1CmcTaggedContentInfo *new_LibOrgBouncycastleAsn1CmcTaggedContentInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1CmcTaggedContentInfo *create_LibOrgBouncycastleAsn1CmcTaggedContentInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

@implementation LibOrgBouncycastleAsn1CmcTaggedContentInfo

- (instancetype)initWithLibOrgBouncycastleAsn1CmcBodyPartID:(LibOrgBouncycastleAsn1CmcBodyPartID *)bodyPartID
            withLibOrgBouncycastleAsn1CmsAsn1CmsContentInfo:(LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo *)contentInfo {
  LibOrgBouncycastleAsn1CmcTaggedContentInfo_initWithLibOrgBouncycastleAsn1CmcBodyPartID_withLibOrgBouncycastleAsn1CmsAsn1CmsContentInfo_(self, bodyPartID, contentInfo);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1CmcTaggedContentInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

+ (LibOrgBouncycastleAsn1CmcTaggedContentInfo *)getInstanceWithId:(id)o {
  return LibOrgBouncycastleAsn1CmcTaggedContentInfo_getInstanceWithId_(o);
}

+ (LibOrgBouncycastleAsn1CmcTaggedContentInfo *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                          withBoolean:(jboolean)explicit_ {
  return LibOrgBouncycastleAsn1CmcTaggedContentInfo_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_);
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:bodyPartID_];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:contentInfo_];
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

- (LibOrgBouncycastleAsn1CmcBodyPartID *)getBodyPartID {
  return bodyPartID_;
}

- (LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo *)getContentInfo {
  return contentInfo_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmcTaggedContentInfo;", 0x9, 2, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmcTaggedContentInfo;", 0x9, 2, 4, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmcBodyPartID;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmsAsn1CmsContentInfo;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1CmcBodyPartID:withLibOrgBouncycastleAsn1CmsAsn1CmsContentInfo:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[2].selector = @selector(getInstanceWithId:);
  methods[3].selector = @selector(getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:withBoolean:);
  methods[4].selector = @selector(toASN1Primitive);
  methods[5].selector = @selector(getBodyPartID);
  methods[6].selector = @selector(getContentInfo);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "bodyPartID_", "LLibOrgBouncycastleAsn1CmcBodyPartID;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "contentInfo_", "LLibOrgBouncycastleAsn1CmsAsn1CmsContentInfo;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1CmcBodyPartID;LLibOrgBouncycastleAsn1CmsAsn1CmsContentInfo;", "LLibOrgBouncycastleAsn1ASN1Sequence;", "getInstance", "LNSObject;", "LLibOrgBouncycastleAsn1ASN1TaggedObject;Z" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1CmcTaggedContentInfo = { "TaggedContentInfo", "lib.org.bouncycastle.asn1.cmc", ptrTable, methods, fields, 7, 0x1, 7, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1CmcTaggedContentInfo;
}

@end

void LibOrgBouncycastleAsn1CmcTaggedContentInfo_initWithLibOrgBouncycastleAsn1CmcBodyPartID_withLibOrgBouncycastleAsn1CmsAsn1CmsContentInfo_(LibOrgBouncycastleAsn1CmcTaggedContentInfo *self, LibOrgBouncycastleAsn1CmcBodyPartID *bodyPartID, LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo *contentInfo) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->bodyPartID_ = bodyPartID;
  self->contentInfo_ = contentInfo;
}

LibOrgBouncycastleAsn1CmcTaggedContentInfo *new_LibOrgBouncycastleAsn1CmcTaggedContentInfo_initWithLibOrgBouncycastleAsn1CmcBodyPartID_withLibOrgBouncycastleAsn1CmsAsn1CmsContentInfo_(LibOrgBouncycastleAsn1CmcBodyPartID *bodyPartID, LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo *contentInfo) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmcTaggedContentInfo, initWithLibOrgBouncycastleAsn1CmcBodyPartID_withLibOrgBouncycastleAsn1CmsAsn1CmsContentInfo_, bodyPartID, contentInfo)
}

LibOrgBouncycastleAsn1CmcTaggedContentInfo *create_LibOrgBouncycastleAsn1CmcTaggedContentInfo_initWithLibOrgBouncycastleAsn1CmcBodyPartID_withLibOrgBouncycastleAsn1CmsAsn1CmsContentInfo_(LibOrgBouncycastleAsn1CmcBodyPartID *bodyPartID, LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo *contentInfo) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmcTaggedContentInfo, initWithLibOrgBouncycastleAsn1CmcBodyPartID_withLibOrgBouncycastleAsn1CmsAsn1CmsContentInfo_, bodyPartID, contentInfo)
}

void LibOrgBouncycastleAsn1CmcTaggedContentInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmcTaggedContentInfo *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  if ([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) size] != 2) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"incorrect sequence size");
  }
  self->bodyPartID_ = LibOrgBouncycastleAsn1CmcBodyPartID_getInstanceWithId_([seq getObjectAtWithInt:0]);
  self->contentInfo_ = LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo_getInstanceWithId_([seq getObjectAtWithInt:1]);
}

LibOrgBouncycastleAsn1CmcTaggedContentInfo *new_LibOrgBouncycastleAsn1CmcTaggedContentInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmcTaggedContentInfo, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1CmcTaggedContentInfo *create_LibOrgBouncycastleAsn1CmcTaggedContentInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmcTaggedContentInfo, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1CmcTaggedContentInfo *LibOrgBouncycastleAsn1CmcTaggedContentInfo_getInstanceWithId_(id o) {
  LibOrgBouncycastleAsn1CmcTaggedContentInfo_initialize();
  if ([o isKindOfClass:[LibOrgBouncycastleAsn1CmcTaggedContentInfo class]]) {
    return (LibOrgBouncycastleAsn1CmcTaggedContentInfo *) o;
  }
  if (o != nil) {
    return new_LibOrgBouncycastleAsn1CmcTaggedContentInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(o));
  }
  return nil;
}

LibOrgBouncycastleAsn1CmcTaggedContentInfo *LibOrgBouncycastleAsn1CmcTaggedContentInfo_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_) {
  LibOrgBouncycastleAsn1CmcTaggedContentInfo_initialize();
  return LibOrgBouncycastleAsn1CmcTaggedContentInfo_getInstanceWithId_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_));
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1CmcTaggedContentInfo)
