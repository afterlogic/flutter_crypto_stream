//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/crmf/POPOPrivKey.java
//

#include "ASN1Encodable.h"
#include "ASN1Integer.h"
#include "ASN1Object.h"
#include "ASN1Primitive.h"
#include "ASN1TaggedObject.h"
#include "DERBitString.h"
#include "DERTaggedObject.h"
#include "EnvelopedData.h"
#include "J2ObjC_source.h"
#include "PKMACValue.h"
#include "POPOPrivKey.h"
#include "SubsequentMessage.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/math/BigInteger.h"

@interface LibOrgBouncycastleAsn1CrmfPOPOPrivKey () {
 @public
  jint tagNo_;
  id<LibOrgBouncycastleAsn1ASN1Encodable> obj_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CrmfPOPOPrivKey, obj_, id<LibOrgBouncycastleAsn1ASN1Encodable>)

__attribute__((unused)) static void LibOrgBouncycastleAsn1CrmfPOPOPrivKey_initWithLibOrgBouncycastleAsn1ASN1TaggedObject_(LibOrgBouncycastleAsn1CrmfPOPOPrivKey *self, LibOrgBouncycastleAsn1ASN1TaggedObject *obj);

__attribute__((unused)) static LibOrgBouncycastleAsn1CrmfPOPOPrivKey *new_LibOrgBouncycastleAsn1CrmfPOPOPrivKey_initWithLibOrgBouncycastleAsn1ASN1TaggedObject_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1CrmfPOPOPrivKey *create_LibOrgBouncycastleAsn1CrmfPOPOPrivKey_initWithLibOrgBouncycastleAsn1ASN1TaggedObject_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj);

@implementation LibOrgBouncycastleAsn1CrmfPOPOPrivKey

+ (jint)thisMessage {
  return LibOrgBouncycastleAsn1CrmfPOPOPrivKey_thisMessage;
}

+ (jint)subsequentMessage {
  return LibOrgBouncycastleAsn1CrmfPOPOPrivKey_subsequentMessage;
}

+ (jint)dhMAC {
  return LibOrgBouncycastleAsn1CrmfPOPOPrivKey_dhMAC;
}

+ (jint)agreeMAC {
  return LibOrgBouncycastleAsn1CrmfPOPOPrivKey_agreeMAC;
}

+ (jint)encryptedKey {
  return LibOrgBouncycastleAsn1CrmfPOPOPrivKey_encryptedKey;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj {
  LibOrgBouncycastleAsn1CrmfPOPOPrivKey_initWithLibOrgBouncycastleAsn1ASN1TaggedObject_(self, obj);
  return self;
}

+ (LibOrgBouncycastleAsn1CrmfPOPOPrivKey *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1CrmfPOPOPrivKey_getInstanceWithId_(obj);
}

+ (LibOrgBouncycastleAsn1CrmfPOPOPrivKey *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                     withBoolean:(jboolean)explicit_ {
  return LibOrgBouncycastleAsn1CrmfPOPOPrivKey_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_);
}

- (instancetype)initWithLibOrgBouncycastleAsn1CrmfPKMACValue:(LibOrgBouncycastleAsn1CrmfPKMACValue *)agreeMac {
  LibOrgBouncycastleAsn1CrmfPOPOPrivKey_initWithLibOrgBouncycastleAsn1CrmfPKMACValue_(self, agreeMac);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1CrmfSubsequentMessage:(LibOrgBouncycastleAsn1CrmfSubsequentMessage *)msg {
  LibOrgBouncycastleAsn1CrmfPOPOPrivKey_initWithLibOrgBouncycastleAsn1CrmfSubsequentMessage_(self, msg);
  return self;
}

- (jint)getType {
  return tagNo_;
}

- (id<LibOrgBouncycastleAsn1ASN1Encodable>)getValue {
  return obj_;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  return new_LibOrgBouncycastleAsn1DERTaggedObject_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(false, tagNo_, obj_);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, 0, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CrmfPOPOPrivKey;", 0x9, 1, 2, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CrmfPOPOPrivKey;", 0x9, 1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 5, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Encodable;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1TaggedObject:);
  methods[1].selector = @selector(getInstanceWithId:);
  methods[2].selector = @selector(getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:withBoolean:);
  methods[3].selector = @selector(initWithLibOrgBouncycastleAsn1CrmfPKMACValue:);
  methods[4].selector = @selector(initWithLibOrgBouncycastleAsn1CrmfSubsequentMessage:);
  methods[5].selector = @selector(getType);
  methods[6].selector = @selector(getValue);
  methods[7].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "thisMessage", "I", .constantValue.asInt = LibOrgBouncycastleAsn1CrmfPOPOPrivKey_thisMessage, 0x19, -1, -1, -1, -1 },
    { "subsequentMessage", "I", .constantValue.asInt = LibOrgBouncycastleAsn1CrmfPOPOPrivKey_subsequentMessage, 0x19, -1, -1, -1, -1 },
    { "dhMAC", "I", .constantValue.asInt = LibOrgBouncycastleAsn1CrmfPOPOPrivKey_dhMAC, 0x19, -1, -1, -1, -1 },
    { "agreeMAC", "I", .constantValue.asInt = LibOrgBouncycastleAsn1CrmfPOPOPrivKey_agreeMAC, 0x19, -1, -1, -1, -1 },
    { "encryptedKey", "I", .constantValue.asInt = LibOrgBouncycastleAsn1CrmfPOPOPrivKey_encryptedKey, 0x19, -1, -1, -1, -1 },
    { "tagNo_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "obj_", "LLibOrgBouncycastleAsn1ASN1Encodable;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1ASN1TaggedObject;", "getInstance", "LNSObject;", "LLibOrgBouncycastleAsn1ASN1TaggedObject;Z", "LLibOrgBouncycastleAsn1CrmfPKMACValue;", "LLibOrgBouncycastleAsn1CrmfSubsequentMessage;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1CrmfPOPOPrivKey = { "POPOPrivKey", "lib.org.bouncycastle.asn1.crmf", ptrTable, methods, fields, 7, 0x1, 8, 7, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1CrmfPOPOPrivKey;
}

@end

void LibOrgBouncycastleAsn1CrmfPOPOPrivKey_initWithLibOrgBouncycastleAsn1ASN1TaggedObject_(LibOrgBouncycastleAsn1CrmfPOPOPrivKey *self, LibOrgBouncycastleAsn1ASN1TaggedObject *obj) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->tagNo_ = [((LibOrgBouncycastleAsn1ASN1TaggedObject *) nil_chk(obj)) getTagNo];
  switch (self->tagNo_) {
    case LibOrgBouncycastleAsn1CrmfPOPOPrivKey_thisMessage:
    self->obj_ = LibOrgBouncycastleAsn1DERBitString_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, false);
    break;
    case LibOrgBouncycastleAsn1CrmfPOPOPrivKey_subsequentMessage:
    self->obj_ = LibOrgBouncycastleAsn1CrmfSubsequentMessage_valueOfWithInt_([((JavaMathBigInteger *) nil_chk([((LibOrgBouncycastleAsn1ASN1Integer *) nil_chk(LibOrgBouncycastleAsn1ASN1Integer_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, false))) getValue])) intValue]);
    break;
    case LibOrgBouncycastleAsn1CrmfPOPOPrivKey_dhMAC:
    self->obj_ = LibOrgBouncycastleAsn1DERBitString_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, false);
    break;
    case LibOrgBouncycastleAsn1CrmfPOPOPrivKey_agreeMAC:
    self->obj_ = LibOrgBouncycastleAsn1CrmfPKMACValue_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, false);
    break;
    case LibOrgBouncycastleAsn1CrmfPOPOPrivKey_encryptedKey:
    self->obj_ = LibOrgBouncycastleAsn1CmsEnvelopedData_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, false);
    break;
    default:
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"unknown tag in POPOPrivKey");
  }
}

LibOrgBouncycastleAsn1CrmfPOPOPrivKey *new_LibOrgBouncycastleAsn1CrmfPOPOPrivKey_initWithLibOrgBouncycastleAsn1ASN1TaggedObject_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CrmfPOPOPrivKey, initWithLibOrgBouncycastleAsn1ASN1TaggedObject_, obj)
}

LibOrgBouncycastleAsn1CrmfPOPOPrivKey *create_LibOrgBouncycastleAsn1CrmfPOPOPrivKey_initWithLibOrgBouncycastleAsn1ASN1TaggedObject_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CrmfPOPOPrivKey, initWithLibOrgBouncycastleAsn1ASN1TaggedObject_, obj)
}

LibOrgBouncycastleAsn1CrmfPOPOPrivKey *LibOrgBouncycastleAsn1CrmfPOPOPrivKey_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1CrmfPOPOPrivKey_initialize();
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1CrmfPOPOPrivKey class]]) {
    return (LibOrgBouncycastleAsn1CrmfPOPOPrivKey *) obj;
  }
  if (obj != nil) {
    return new_LibOrgBouncycastleAsn1CrmfPOPOPrivKey_initWithLibOrgBouncycastleAsn1ASN1TaggedObject_(LibOrgBouncycastleAsn1ASN1TaggedObject_getInstanceWithId_(obj));
  }
  return nil;
}

LibOrgBouncycastleAsn1CrmfPOPOPrivKey *LibOrgBouncycastleAsn1CrmfPOPOPrivKey_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_) {
  LibOrgBouncycastleAsn1CrmfPOPOPrivKey_initialize();
  return LibOrgBouncycastleAsn1CrmfPOPOPrivKey_getInstanceWithId_(LibOrgBouncycastleAsn1ASN1TaggedObject_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_));
}

void LibOrgBouncycastleAsn1CrmfPOPOPrivKey_initWithLibOrgBouncycastleAsn1CrmfPKMACValue_(LibOrgBouncycastleAsn1CrmfPOPOPrivKey *self, LibOrgBouncycastleAsn1CrmfPKMACValue *agreeMac) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->tagNo_ = LibOrgBouncycastleAsn1CrmfPOPOPrivKey_agreeMAC;
  self->obj_ = agreeMac;
}

LibOrgBouncycastleAsn1CrmfPOPOPrivKey *new_LibOrgBouncycastleAsn1CrmfPOPOPrivKey_initWithLibOrgBouncycastleAsn1CrmfPKMACValue_(LibOrgBouncycastleAsn1CrmfPKMACValue *agreeMac) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CrmfPOPOPrivKey, initWithLibOrgBouncycastleAsn1CrmfPKMACValue_, agreeMac)
}

LibOrgBouncycastleAsn1CrmfPOPOPrivKey *create_LibOrgBouncycastleAsn1CrmfPOPOPrivKey_initWithLibOrgBouncycastleAsn1CrmfPKMACValue_(LibOrgBouncycastleAsn1CrmfPKMACValue *agreeMac) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CrmfPOPOPrivKey, initWithLibOrgBouncycastleAsn1CrmfPKMACValue_, agreeMac)
}

void LibOrgBouncycastleAsn1CrmfPOPOPrivKey_initWithLibOrgBouncycastleAsn1CrmfSubsequentMessage_(LibOrgBouncycastleAsn1CrmfPOPOPrivKey *self, LibOrgBouncycastleAsn1CrmfSubsequentMessage *msg) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->tagNo_ = LibOrgBouncycastleAsn1CrmfPOPOPrivKey_subsequentMessage;
  self->obj_ = msg;
}

LibOrgBouncycastleAsn1CrmfPOPOPrivKey *new_LibOrgBouncycastleAsn1CrmfPOPOPrivKey_initWithLibOrgBouncycastleAsn1CrmfSubsequentMessage_(LibOrgBouncycastleAsn1CrmfSubsequentMessage *msg) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CrmfPOPOPrivKey, initWithLibOrgBouncycastleAsn1CrmfSubsequentMessage_, msg)
}

LibOrgBouncycastleAsn1CrmfPOPOPrivKey *create_LibOrgBouncycastleAsn1CrmfPOPOPrivKey_initWithLibOrgBouncycastleAsn1CrmfSubsequentMessage_(LibOrgBouncycastleAsn1CrmfSubsequentMessage *msg) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CrmfPOPOPrivKey, initWithLibOrgBouncycastleAsn1CrmfSubsequentMessage_, msg)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1CrmfPOPOPrivKey)
