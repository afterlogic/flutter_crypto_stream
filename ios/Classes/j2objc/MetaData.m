//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cms/MetaData.java
//

#include "ASN1Boolean.h"
#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1Object.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "Attributes.h"
#include "DERIA5String.h"
#include "DERSequence.h"
#include "DERUTF8String.h"
#include "J2ObjC_source.h"
#include "MetaData.h"

@interface LibOrgBouncycastleAsn1CmsMetaData () {
 @public
  LibOrgBouncycastleAsn1ASN1Boolean *hashProtected_;
  LibOrgBouncycastleAsn1DERUTF8String *fileName_;
  LibOrgBouncycastleAsn1DERIA5String *mediaType_;
  LibOrgBouncycastleAsn1CmsAttributes *otherMetaData_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmsMetaData, hashProtected_, LibOrgBouncycastleAsn1ASN1Boolean *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmsMetaData, fileName_, LibOrgBouncycastleAsn1DERUTF8String *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmsMetaData, mediaType_, LibOrgBouncycastleAsn1DERIA5String *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmsMetaData, otherMetaData_, LibOrgBouncycastleAsn1CmsAttributes *)

__attribute__((unused)) static void LibOrgBouncycastleAsn1CmsMetaData_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmsMetaData *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1CmsMetaData *new_LibOrgBouncycastleAsn1CmsMetaData_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1CmsMetaData *create_LibOrgBouncycastleAsn1CmsMetaData_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

@implementation LibOrgBouncycastleAsn1CmsMetaData

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Boolean:(LibOrgBouncycastleAsn1ASN1Boolean *)hashProtected
                  withLibOrgBouncycastleAsn1DERUTF8String:(LibOrgBouncycastleAsn1DERUTF8String *)fileName
                   withLibOrgBouncycastleAsn1DERIA5String:(LibOrgBouncycastleAsn1DERIA5String *)mediaType
                  withLibOrgBouncycastleAsn1CmsAttributes:(LibOrgBouncycastleAsn1CmsAttributes *)otherMetaData {
  LibOrgBouncycastleAsn1CmsMetaData_initWithLibOrgBouncycastleAsn1ASN1Boolean_withLibOrgBouncycastleAsn1DERUTF8String_withLibOrgBouncycastleAsn1DERIA5String_withLibOrgBouncycastleAsn1CmsAttributes_(self, hashProtected, fileName, mediaType, otherMetaData);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1CmsMetaData_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

+ (LibOrgBouncycastleAsn1CmsMetaData *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1CmsMetaData_getInstanceWithId_(obj);
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:hashProtected_];
  if (fileName_ != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:fileName_];
  }
  if (mediaType_ != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:mediaType_];
  }
  if (otherMetaData_ != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:otherMetaData_];
  }
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

- (jboolean)isHashProtected {
  return [((LibOrgBouncycastleAsn1ASN1Boolean *) nil_chk(hashProtected_)) isTrue];
}

- (LibOrgBouncycastleAsn1DERUTF8String *)getFileName {
  return self->fileName_;
}

- (LibOrgBouncycastleAsn1DERIA5String *)getMediaType {
  return self->mediaType_;
}

- (LibOrgBouncycastleAsn1CmsAttributes *)getOtherMetaData {
  return otherMetaData_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmsMetaData;", 0x9, 2, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1DERUTF8String;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1DERIA5String;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmsAttributes;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Boolean:withLibOrgBouncycastleAsn1DERUTF8String:withLibOrgBouncycastleAsn1DERIA5String:withLibOrgBouncycastleAsn1CmsAttributes:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[2].selector = @selector(getInstanceWithId:);
  methods[3].selector = @selector(toASN1Primitive);
  methods[4].selector = @selector(isHashProtected);
  methods[5].selector = @selector(getFileName);
  methods[6].selector = @selector(getMediaType);
  methods[7].selector = @selector(getOtherMetaData);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "hashProtected_", "LLibOrgBouncycastleAsn1ASN1Boolean;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "fileName_", "LLibOrgBouncycastleAsn1DERUTF8String;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "mediaType_", "LLibOrgBouncycastleAsn1DERIA5String;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "otherMetaData_", "LLibOrgBouncycastleAsn1CmsAttributes;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1ASN1Boolean;LLibOrgBouncycastleAsn1DERUTF8String;LLibOrgBouncycastleAsn1DERIA5String;LLibOrgBouncycastleAsn1CmsAttributes;", "LLibOrgBouncycastleAsn1ASN1Sequence;", "getInstance", "LNSObject;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1CmsMetaData = { "MetaData", "lib.org.bouncycastle.asn1.cms", ptrTable, methods, fields, 7, 0x1, 8, 4, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1CmsMetaData;
}

@end

void LibOrgBouncycastleAsn1CmsMetaData_initWithLibOrgBouncycastleAsn1ASN1Boolean_withLibOrgBouncycastleAsn1DERUTF8String_withLibOrgBouncycastleAsn1DERIA5String_withLibOrgBouncycastleAsn1CmsAttributes_(LibOrgBouncycastleAsn1CmsMetaData *self, LibOrgBouncycastleAsn1ASN1Boolean *hashProtected, LibOrgBouncycastleAsn1DERUTF8String *fileName, LibOrgBouncycastleAsn1DERIA5String *mediaType, LibOrgBouncycastleAsn1CmsAttributes *otherMetaData) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->hashProtected_ = hashProtected;
  self->fileName_ = fileName;
  self->mediaType_ = mediaType;
  self->otherMetaData_ = otherMetaData;
}

LibOrgBouncycastleAsn1CmsMetaData *new_LibOrgBouncycastleAsn1CmsMetaData_initWithLibOrgBouncycastleAsn1ASN1Boolean_withLibOrgBouncycastleAsn1DERUTF8String_withLibOrgBouncycastleAsn1DERIA5String_withLibOrgBouncycastleAsn1CmsAttributes_(LibOrgBouncycastleAsn1ASN1Boolean *hashProtected, LibOrgBouncycastleAsn1DERUTF8String *fileName, LibOrgBouncycastleAsn1DERIA5String *mediaType, LibOrgBouncycastleAsn1CmsAttributes *otherMetaData) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmsMetaData, initWithLibOrgBouncycastleAsn1ASN1Boolean_withLibOrgBouncycastleAsn1DERUTF8String_withLibOrgBouncycastleAsn1DERIA5String_withLibOrgBouncycastleAsn1CmsAttributes_, hashProtected, fileName, mediaType, otherMetaData)
}

LibOrgBouncycastleAsn1CmsMetaData *create_LibOrgBouncycastleAsn1CmsMetaData_initWithLibOrgBouncycastleAsn1ASN1Boolean_withLibOrgBouncycastleAsn1DERUTF8String_withLibOrgBouncycastleAsn1DERIA5String_withLibOrgBouncycastleAsn1CmsAttributes_(LibOrgBouncycastleAsn1ASN1Boolean *hashProtected, LibOrgBouncycastleAsn1DERUTF8String *fileName, LibOrgBouncycastleAsn1DERIA5String *mediaType, LibOrgBouncycastleAsn1CmsAttributes *otherMetaData) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmsMetaData, initWithLibOrgBouncycastleAsn1ASN1Boolean_withLibOrgBouncycastleAsn1DERUTF8String_withLibOrgBouncycastleAsn1DERIA5String_withLibOrgBouncycastleAsn1CmsAttributes_, hashProtected, fileName, mediaType, otherMetaData)
}

void LibOrgBouncycastleAsn1CmsMetaData_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmsMetaData *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->hashProtected_ = LibOrgBouncycastleAsn1ASN1Boolean_getInstanceWithId_([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjectAtWithInt:0]);
  jint index = 1;
  if (index < [seq size] && [[seq getObjectAtWithInt:index] isKindOfClass:[LibOrgBouncycastleAsn1DERUTF8String class]]) {
    self->fileName_ = LibOrgBouncycastleAsn1DERUTF8String_getInstanceWithId_([seq getObjectAtWithInt:index++]);
  }
  if (index < [seq size] && [[seq getObjectAtWithInt:index] isKindOfClass:[LibOrgBouncycastleAsn1DERIA5String class]]) {
    self->mediaType_ = LibOrgBouncycastleAsn1DERIA5String_getInstanceWithId_([seq getObjectAtWithInt:index++]);
  }
  if (index < [seq size]) {
    self->otherMetaData_ = LibOrgBouncycastleAsn1CmsAttributes_getInstanceWithId_([seq getObjectAtWithInt:index++]);
  }
}

LibOrgBouncycastleAsn1CmsMetaData *new_LibOrgBouncycastleAsn1CmsMetaData_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmsMetaData, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1CmsMetaData *create_LibOrgBouncycastleAsn1CmsMetaData_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmsMetaData, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1CmsMetaData *LibOrgBouncycastleAsn1CmsMetaData_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1CmsMetaData_initialize();
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1CmsMetaData class]]) {
    return (LibOrgBouncycastleAsn1CmsMetaData *) obj;
  }
  else if (obj != nil) {
    return new_LibOrgBouncycastleAsn1CmsMetaData_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(obj));
  }
  return nil;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1CmsMetaData)
