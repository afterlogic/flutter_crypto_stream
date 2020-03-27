//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/ocsp/Asn1OcspCertStatus.java
//

#include "ASN1Encodable.h"
#include "ASN1Object.h"
#include "ASN1Primitive.h"
#include "ASN1TaggedObject.h"
#include "Asn1OcspCertStatus.h"
#include "DERNull.h"
#include "DERTaggedObject.h"
#include "IOSClass.h"
#include "J2ObjC_source.h"
#include "RevokedInfo.h"
#include "java/lang/IllegalArgumentException.h"

@interface LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus () {
 @public
  jint tagNo_;
  id<LibOrgBouncycastleAsn1ASN1Encodable> value_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)choice;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus, value_, id<LibOrgBouncycastleAsn1ASN1Encodable>)

__attribute__((unused)) static void LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus_initWithLibOrgBouncycastleAsn1ASN1TaggedObject_(LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus *self, LibOrgBouncycastleAsn1ASN1TaggedObject *choice);

__attribute__((unused)) static LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus *new_LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus_initWithLibOrgBouncycastleAsn1ASN1TaggedObject_(LibOrgBouncycastleAsn1ASN1TaggedObject *choice) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus *create_LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus_initWithLibOrgBouncycastleAsn1ASN1TaggedObject_(LibOrgBouncycastleAsn1ASN1TaggedObject *choice);

@implementation LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (instancetype)initWithLibOrgBouncycastleAsn1OcspRevokedInfo:(LibOrgBouncycastleAsn1OcspRevokedInfo *)info {
  LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus_initWithLibOrgBouncycastleAsn1OcspRevokedInfo_(self, info);
  return self;
}

- (instancetype)initWithInt:(jint)tagNo
withLibOrgBouncycastleAsn1ASN1Encodable:(id<LibOrgBouncycastleAsn1ASN1Encodable>)value {
  LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus_initWithInt_withLibOrgBouncycastleAsn1ASN1Encodable_(self, tagNo, value);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)choice {
  LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus_initWithLibOrgBouncycastleAsn1ASN1TaggedObject_(self, choice);
  return self;
}

+ (LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus_getInstanceWithId_(obj);
}

+ (LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                            withBoolean:(jboolean)explicit_ {
  return LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_);
}

- (jint)getTagNo {
  return tagNo_;
}

- (id<LibOrgBouncycastleAsn1ASN1Encodable>)getStatus {
  return value_;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  return new_LibOrgBouncycastleAsn1DERTaggedObject_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(false, tagNo_, value_);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 2, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1OcspAsn1OcspCertStatus;", 0x9, 3, 4, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1OcspAsn1OcspCertStatus;", 0x9, 3, 5, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Encodable;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1OcspRevokedInfo:);
  methods[2].selector = @selector(initWithInt:withLibOrgBouncycastleAsn1ASN1Encodable:);
  methods[3].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1TaggedObject:);
  methods[4].selector = @selector(getInstanceWithId:);
  methods[5].selector = @selector(getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:withBoolean:);
  methods[6].selector = @selector(getTagNo);
  methods[7].selector = @selector(getStatus);
  methods[8].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "tagNo_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "value_", "LLibOrgBouncycastleAsn1ASN1Encodable;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1OcspRevokedInfo;", "ILLibOrgBouncycastleAsn1ASN1Encodable;", "LLibOrgBouncycastleAsn1ASN1TaggedObject;", "getInstance", "LNSObject;", "LLibOrgBouncycastleAsn1ASN1TaggedObject;Z" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus = { "Asn1OcspCertStatus", "lib.org.bouncycastle.asn1.ocsp", ptrTable, methods, fields, 7, 0x1, 9, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus;
}

@end

void LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus_init(LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus *self) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->tagNo_ = 0;
  self->value_ = JreLoadStatic(LibOrgBouncycastleAsn1DERNull, INSTANCE);
}

LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus *new_LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus, init)
}

LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus *create_LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus, init)
}

void LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus_initWithLibOrgBouncycastleAsn1OcspRevokedInfo_(LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus *self, LibOrgBouncycastleAsn1OcspRevokedInfo *info) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->tagNo_ = 1;
  self->value_ = info;
}

LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus *new_LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus_initWithLibOrgBouncycastleAsn1OcspRevokedInfo_(LibOrgBouncycastleAsn1OcspRevokedInfo *info) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus, initWithLibOrgBouncycastleAsn1OcspRevokedInfo_, info)
}

LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus *create_LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus_initWithLibOrgBouncycastleAsn1OcspRevokedInfo_(LibOrgBouncycastleAsn1OcspRevokedInfo *info) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus, initWithLibOrgBouncycastleAsn1OcspRevokedInfo_, info)
}

void LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus_initWithInt_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus *self, jint tagNo, id<LibOrgBouncycastleAsn1ASN1Encodable> value) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->tagNo_ = tagNo;
  self->value_ = value;
}

LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus *new_LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus_initWithInt_withLibOrgBouncycastleAsn1ASN1Encodable_(jint tagNo, id<LibOrgBouncycastleAsn1ASN1Encodable> value) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus, initWithInt_withLibOrgBouncycastleAsn1ASN1Encodable_, tagNo, value)
}

LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus *create_LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus_initWithInt_withLibOrgBouncycastleAsn1ASN1Encodable_(jint tagNo, id<LibOrgBouncycastleAsn1ASN1Encodable> value) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus, initWithInt_withLibOrgBouncycastleAsn1ASN1Encodable_, tagNo, value)
}

void LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus_initWithLibOrgBouncycastleAsn1ASN1TaggedObject_(LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus *self, LibOrgBouncycastleAsn1ASN1TaggedObject *choice) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->tagNo_ = [((LibOrgBouncycastleAsn1ASN1TaggedObject *) nil_chk(choice)) getTagNo];
  switch ([choice getTagNo]) {
    case 0:
    self->value_ = JreLoadStatic(LibOrgBouncycastleAsn1DERNull, INSTANCE);
    break;
    case 1:
    self->value_ = LibOrgBouncycastleAsn1OcspRevokedInfo_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(choice, false);
    break;
    case 2:
    self->value_ = JreLoadStatic(LibOrgBouncycastleAsn1DERNull, INSTANCE);
    break;
    default:
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$I", @"Unknown tag encountered: ", [choice getTagNo]));
  }
}

LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus *new_LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus_initWithLibOrgBouncycastleAsn1ASN1TaggedObject_(LibOrgBouncycastleAsn1ASN1TaggedObject *choice) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus, initWithLibOrgBouncycastleAsn1ASN1TaggedObject_, choice)
}

LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus *create_LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus_initWithLibOrgBouncycastleAsn1ASN1TaggedObject_(LibOrgBouncycastleAsn1ASN1TaggedObject *choice) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus, initWithLibOrgBouncycastleAsn1ASN1TaggedObject_, choice)
}

LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus *LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus_initialize();
  if (obj == nil || [obj isKindOfClass:[LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus class]]) {
    return (LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus *) cast_chk(obj, [LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus class]);
  }
  else if ([obj isKindOfClass:[LibOrgBouncycastleAsn1ASN1TaggedObject class]]) {
    return new_LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus_initWithLibOrgBouncycastleAsn1ASN1TaggedObject_((LibOrgBouncycastleAsn1ASN1TaggedObject *) obj);
  }
  @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$", @"unknown object in factory: ", [[obj java_getClass] getName]));
}

LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus *LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_) {
  LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus_initialize();
  return LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus_getInstanceWithId_([((LibOrgBouncycastleAsn1ASN1TaggedObject *) nil_chk(obj)) getObject]);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1OcspAsn1OcspCertStatus)