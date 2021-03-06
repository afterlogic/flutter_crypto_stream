//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cmc/ExtendedFailInfo.java
//

#include "ASN1Encodable.h"
#include "ASN1Object.h"
#include "ASN1ObjectIdentifier.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "DERSequence.h"
#include "ExtendedFailInfo.h"
#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"

@interface LibOrgBouncycastleAsn1CmcExtendedFailInfo () {
 @public
  LibOrgBouncycastleAsn1ASN1ObjectIdentifier *failInfoOID_;
  id<LibOrgBouncycastleAsn1ASN1Encodable> failInfoValue_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)s;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmcExtendedFailInfo, failInfoOID_, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmcExtendedFailInfo, failInfoValue_, id<LibOrgBouncycastleAsn1ASN1Encodable>)

__attribute__((unused)) static void LibOrgBouncycastleAsn1CmcExtendedFailInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmcExtendedFailInfo *self, LibOrgBouncycastleAsn1ASN1Sequence *s);

__attribute__((unused)) static LibOrgBouncycastleAsn1CmcExtendedFailInfo *new_LibOrgBouncycastleAsn1CmcExtendedFailInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *s) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1CmcExtendedFailInfo *create_LibOrgBouncycastleAsn1CmcExtendedFailInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *s);

@implementation LibOrgBouncycastleAsn1CmcExtendedFailInfo

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)failInfoOID
                           withLibOrgBouncycastleAsn1ASN1Encodable:(id<LibOrgBouncycastleAsn1ASN1Encodable>)failInfoValue {
  LibOrgBouncycastleAsn1CmcExtendedFailInfo_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(self, failInfoOID, failInfoValue);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)s {
  LibOrgBouncycastleAsn1CmcExtendedFailInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, s);
  return self;
}

+ (LibOrgBouncycastleAsn1CmcExtendedFailInfo *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1CmcExtendedFailInfo_getInstanceWithId_(obj);
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableArray_([IOSObjectArray newArrayWithObjects:(id[]){ failInfoOID_, failInfoValue_ } count:2 type:LibOrgBouncycastleAsn1ASN1Encodable_class_()]);
}

- (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)getFailInfoOID {
  return failInfoOID_;
}

- (id<LibOrgBouncycastleAsn1ASN1Encodable>)getFailInfoValue {
  return failInfoValue_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmcExtendedFailInfo;", 0x9, 2, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Encodable;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:withLibOrgBouncycastleAsn1ASN1Encodable:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[2].selector = @selector(getInstanceWithId:);
  methods[3].selector = @selector(toASN1Primitive);
  methods[4].selector = @selector(getFailInfoOID);
  methods[5].selector = @selector(getFailInfoValue);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "failInfoOID_", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "failInfoValue_", "LLibOrgBouncycastleAsn1ASN1Encodable;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;LLibOrgBouncycastleAsn1ASN1Encodable;", "LLibOrgBouncycastleAsn1ASN1Sequence;", "getInstance", "LNSObject;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1CmcExtendedFailInfo = { "ExtendedFailInfo", "lib.org.bouncycastle.asn1.cmc", ptrTable, methods, fields, 7, 0x1, 6, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1CmcExtendedFailInfo;
}

@end

void LibOrgBouncycastleAsn1CmcExtendedFailInfo_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1CmcExtendedFailInfo *self, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *failInfoOID, id<LibOrgBouncycastleAsn1ASN1Encodable> failInfoValue) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->failInfoOID_ = failInfoOID;
  self->failInfoValue_ = failInfoValue;
}

LibOrgBouncycastleAsn1CmcExtendedFailInfo *new_LibOrgBouncycastleAsn1CmcExtendedFailInfo_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *failInfoOID, id<LibOrgBouncycastleAsn1ASN1Encodable> failInfoValue) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmcExtendedFailInfo, initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_, failInfoOID, failInfoValue)
}

LibOrgBouncycastleAsn1CmcExtendedFailInfo *create_LibOrgBouncycastleAsn1CmcExtendedFailInfo_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *failInfoOID, id<LibOrgBouncycastleAsn1ASN1Encodable> failInfoValue) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmcExtendedFailInfo, initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_, failInfoOID, failInfoValue)
}

void LibOrgBouncycastleAsn1CmcExtendedFailInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmcExtendedFailInfo *self, LibOrgBouncycastleAsn1ASN1Sequence *s) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  if ([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(s)) size] != 2) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Sequence must be 2 elements.");
  }
  self->failInfoOID_ = LibOrgBouncycastleAsn1ASN1ObjectIdentifier_getInstanceWithId_([s getObjectAtWithInt:0]);
  self->failInfoValue_ = [s getObjectAtWithInt:1];
}

LibOrgBouncycastleAsn1CmcExtendedFailInfo *new_LibOrgBouncycastleAsn1CmcExtendedFailInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *s) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmcExtendedFailInfo, initWithLibOrgBouncycastleAsn1ASN1Sequence_, s)
}

LibOrgBouncycastleAsn1CmcExtendedFailInfo *create_LibOrgBouncycastleAsn1CmcExtendedFailInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *s) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmcExtendedFailInfo, initWithLibOrgBouncycastleAsn1ASN1Sequence_, s)
}

LibOrgBouncycastleAsn1CmcExtendedFailInfo *LibOrgBouncycastleAsn1CmcExtendedFailInfo_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1CmcExtendedFailInfo_initialize();
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1CmcExtendedFailInfo class]]) {
    return (LibOrgBouncycastleAsn1CmcExtendedFailInfo *) obj;
  }
  if ([LibOrgBouncycastleAsn1ASN1Encodable_class_() isInstance:obj]) {
    id<LibOrgBouncycastleAsn1ASN1Encodable> asn1Value = [((id<LibOrgBouncycastleAsn1ASN1Encodable>) nil_chk(((id<LibOrgBouncycastleAsn1ASN1Encodable>) cast_check(obj, LibOrgBouncycastleAsn1ASN1Encodable_class_())))) toASN1Primitive];
    if ([asn1Value isKindOfClass:[LibOrgBouncycastleAsn1ASN1Sequence class]]) {
      return new_LibOrgBouncycastleAsn1CmcExtendedFailInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_((LibOrgBouncycastleAsn1ASN1Sequence *) asn1Value);
    }
  }
  else if ([obj isKindOfClass:[IOSByteArray class]]) {
    return LibOrgBouncycastleAsn1CmcExtendedFailInfo_getInstanceWithId_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(obj));
  }
  return nil;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1CmcExtendedFailInfo)
