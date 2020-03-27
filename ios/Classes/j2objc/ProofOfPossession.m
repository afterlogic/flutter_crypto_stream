//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/crmf/ProofOfPossession.java
//

#include "ASN1Encodable.h"
#include "ASN1Object.h"
#include "ASN1Primitive.h"
#include "ASN1TaggedObject.h"
#include "DERNull.h"
#include "DERTaggedObject.h"
#include "IOSClass.h"
#include "J2ObjC_source.h"
#include "POPOPrivKey.h"
#include "POPOSigningKey.h"
#include "ProofOfPossession.h"
#include "java/lang/IllegalArgumentException.h"

@interface LibOrgBouncycastleAsn1CrmfProofOfPossession () {
 @public
  jint tagNo_;
  id<LibOrgBouncycastleAsn1ASN1Encodable> obj_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)tagged;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CrmfProofOfPossession, obj_, id<LibOrgBouncycastleAsn1ASN1Encodable>)

__attribute__((unused)) static void LibOrgBouncycastleAsn1CrmfProofOfPossession_initWithLibOrgBouncycastleAsn1ASN1TaggedObject_(LibOrgBouncycastleAsn1CrmfProofOfPossession *self, LibOrgBouncycastleAsn1ASN1TaggedObject *tagged);

__attribute__((unused)) static LibOrgBouncycastleAsn1CrmfProofOfPossession *new_LibOrgBouncycastleAsn1CrmfProofOfPossession_initWithLibOrgBouncycastleAsn1ASN1TaggedObject_(LibOrgBouncycastleAsn1ASN1TaggedObject *tagged) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1CrmfProofOfPossession *create_LibOrgBouncycastleAsn1CrmfProofOfPossession_initWithLibOrgBouncycastleAsn1ASN1TaggedObject_(LibOrgBouncycastleAsn1ASN1TaggedObject *tagged);

@implementation LibOrgBouncycastleAsn1CrmfProofOfPossession

+ (jint)TYPE_RA_VERIFIED {
  return LibOrgBouncycastleAsn1CrmfProofOfPossession_TYPE_RA_VERIFIED;
}

+ (jint)TYPE_SIGNING_KEY {
  return LibOrgBouncycastleAsn1CrmfProofOfPossession_TYPE_SIGNING_KEY;
}

+ (jint)TYPE_KEY_ENCIPHERMENT {
  return LibOrgBouncycastleAsn1CrmfProofOfPossession_TYPE_KEY_ENCIPHERMENT;
}

+ (jint)TYPE_KEY_AGREEMENT {
  return LibOrgBouncycastleAsn1CrmfProofOfPossession_TYPE_KEY_AGREEMENT;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)tagged {
  LibOrgBouncycastleAsn1CrmfProofOfPossession_initWithLibOrgBouncycastleAsn1ASN1TaggedObject_(self, tagged);
  return self;
}

+ (LibOrgBouncycastleAsn1CrmfProofOfPossession *)getInstanceWithId:(id)o {
  return LibOrgBouncycastleAsn1CrmfProofOfPossession_getInstanceWithId_(o);
}

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleAsn1CrmfProofOfPossession_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (instancetype)initWithLibOrgBouncycastleAsn1CrmfPOPOSigningKey:(LibOrgBouncycastleAsn1CrmfPOPOSigningKey *)poposk {
  LibOrgBouncycastleAsn1CrmfProofOfPossession_initWithLibOrgBouncycastleAsn1CrmfPOPOSigningKey_(self, poposk);
  return self;
}

- (instancetype)initWithInt:(jint)type
withLibOrgBouncycastleAsn1CrmfPOPOPrivKey:(LibOrgBouncycastleAsn1CrmfPOPOPrivKey *)privkey {
  LibOrgBouncycastleAsn1CrmfProofOfPossession_initWithInt_withLibOrgBouncycastleAsn1CrmfPOPOPrivKey_(self, type, privkey);
  return self;
}

- (jint)getType {
  return tagNo_;
}

- (id<LibOrgBouncycastleAsn1ASN1Encodable>)getObject {
  return obj_;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  return new_LibOrgBouncycastleAsn1DERTaggedObject_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(false, tagNo_, obj_);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, 0, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CrmfProofOfPossession;", 0x9, 1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Encodable;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1TaggedObject:);
  methods[1].selector = @selector(getInstanceWithId:);
  methods[2].selector = @selector(init);
  methods[3].selector = @selector(initWithLibOrgBouncycastleAsn1CrmfPOPOSigningKey:);
  methods[4].selector = @selector(initWithInt:withLibOrgBouncycastleAsn1CrmfPOPOPrivKey:);
  methods[5].selector = @selector(getType);
  methods[6].selector = @selector(getObject);
  methods[7].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "TYPE_RA_VERIFIED", "I", .constantValue.asInt = LibOrgBouncycastleAsn1CrmfProofOfPossession_TYPE_RA_VERIFIED, 0x19, -1, -1, -1, -1 },
    { "TYPE_SIGNING_KEY", "I", .constantValue.asInt = LibOrgBouncycastleAsn1CrmfProofOfPossession_TYPE_SIGNING_KEY, 0x19, -1, -1, -1, -1 },
    { "TYPE_KEY_ENCIPHERMENT", "I", .constantValue.asInt = LibOrgBouncycastleAsn1CrmfProofOfPossession_TYPE_KEY_ENCIPHERMENT, 0x19, -1, -1, -1, -1 },
    { "TYPE_KEY_AGREEMENT", "I", .constantValue.asInt = LibOrgBouncycastleAsn1CrmfProofOfPossession_TYPE_KEY_AGREEMENT, 0x19, -1, -1, -1, -1 },
    { "tagNo_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "obj_", "LLibOrgBouncycastleAsn1ASN1Encodable;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1ASN1TaggedObject;", "getInstance", "LNSObject;", "LLibOrgBouncycastleAsn1CrmfPOPOSigningKey;", "ILLibOrgBouncycastleAsn1CrmfPOPOPrivKey;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1CrmfProofOfPossession = { "ProofOfPossession", "lib.org.bouncycastle.asn1.crmf", ptrTable, methods, fields, 7, 0x1, 8, 6, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1CrmfProofOfPossession;
}

@end

void LibOrgBouncycastleAsn1CrmfProofOfPossession_initWithLibOrgBouncycastleAsn1ASN1TaggedObject_(LibOrgBouncycastleAsn1CrmfProofOfPossession *self, LibOrgBouncycastleAsn1ASN1TaggedObject *tagged) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->tagNo_ = [((LibOrgBouncycastleAsn1ASN1TaggedObject *) nil_chk(tagged)) getTagNo];
  switch (self->tagNo_) {
    case 0:
    self->obj_ = JreLoadStatic(LibOrgBouncycastleAsn1DERNull, INSTANCE);
    break;
    case 1:
    self->obj_ = LibOrgBouncycastleAsn1CrmfPOPOSigningKey_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(tagged, false);
    break;
    case 2:
    case 3:
    self->obj_ = LibOrgBouncycastleAsn1CrmfPOPOPrivKey_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(tagged, true);
    break;
    default:
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$I", @"unknown tag: ", self->tagNo_));
  }
}

LibOrgBouncycastleAsn1CrmfProofOfPossession *new_LibOrgBouncycastleAsn1CrmfProofOfPossession_initWithLibOrgBouncycastleAsn1ASN1TaggedObject_(LibOrgBouncycastleAsn1ASN1TaggedObject *tagged) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CrmfProofOfPossession, initWithLibOrgBouncycastleAsn1ASN1TaggedObject_, tagged)
}

LibOrgBouncycastleAsn1CrmfProofOfPossession *create_LibOrgBouncycastleAsn1CrmfProofOfPossession_initWithLibOrgBouncycastleAsn1ASN1TaggedObject_(LibOrgBouncycastleAsn1ASN1TaggedObject *tagged) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CrmfProofOfPossession, initWithLibOrgBouncycastleAsn1ASN1TaggedObject_, tagged)
}

LibOrgBouncycastleAsn1CrmfProofOfPossession *LibOrgBouncycastleAsn1CrmfProofOfPossession_getInstanceWithId_(id o) {
  LibOrgBouncycastleAsn1CrmfProofOfPossession_initialize();
  if (o == nil || [o isKindOfClass:[LibOrgBouncycastleAsn1CrmfProofOfPossession class]]) {
    return (LibOrgBouncycastleAsn1CrmfProofOfPossession *) cast_chk(o, [LibOrgBouncycastleAsn1CrmfProofOfPossession class]);
  }
  if ([o isKindOfClass:[LibOrgBouncycastleAsn1ASN1TaggedObject class]]) {
    return new_LibOrgBouncycastleAsn1CrmfProofOfPossession_initWithLibOrgBouncycastleAsn1ASN1TaggedObject_((LibOrgBouncycastleAsn1ASN1TaggedObject *) o);
  }
  @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$", @"Invalid object: ", [[o java_getClass] getName]));
}

void LibOrgBouncycastleAsn1CrmfProofOfPossession_init(LibOrgBouncycastleAsn1CrmfProofOfPossession *self) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->tagNo_ = LibOrgBouncycastleAsn1CrmfProofOfPossession_TYPE_RA_VERIFIED;
  self->obj_ = JreLoadStatic(LibOrgBouncycastleAsn1DERNull, INSTANCE);
}

LibOrgBouncycastleAsn1CrmfProofOfPossession *new_LibOrgBouncycastleAsn1CrmfProofOfPossession_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CrmfProofOfPossession, init)
}

LibOrgBouncycastleAsn1CrmfProofOfPossession *create_LibOrgBouncycastleAsn1CrmfProofOfPossession_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CrmfProofOfPossession, init)
}

void LibOrgBouncycastleAsn1CrmfProofOfPossession_initWithLibOrgBouncycastleAsn1CrmfPOPOSigningKey_(LibOrgBouncycastleAsn1CrmfProofOfPossession *self, LibOrgBouncycastleAsn1CrmfPOPOSigningKey *poposk) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->tagNo_ = LibOrgBouncycastleAsn1CrmfProofOfPossession_TYPE_SIGNING_KEY;
  self->obj_ = poposk;
}

LibOrgBouncycastleAsn1CrmfProofOfPossession *new_LibOrgBouncycastleAsn1CrmfProofOfPossession_initWithLibOrgBouncycastleAsn1CrmfPOPOSigningKey_(LibOrgBouncycastleAsn1CrmfPOPOSigningKey *poposk) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CrmfProofOfPossession, initWithLibOrgBouncycastleAsn1CrmfPOPOSigningKey_, poposk)
}

LibOrgBouncycastleAsn1CrmfProofOfPossession *create_LibOrgBouncycastleAsn1CrmfProofOfPossession_initWithLibOrgBouncycastleAsn1CrmfPOPOSigningKey_(LibOrgBouncycastleAsn1CrmfPOPOSigningKey *poposk) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CrmfProofOfPossession, initWithLibOrgBouncycastleAsn1CrmfPOPOSigningKey_, poposk)
}

void LibOrgBouncycastleAsn1CrmfProofOfPossession_initWithInt_withLibOrgBouncycastleAsn1CrmfPOPOPrivKey_(LibOrgBouncycastleAsn1CrmfProofOfPossession *self, jint type, LibOrgBouncycastleAsn1CrmfPOPOPrivKey *privkey) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->tagNo_ = type;
  self->obj_ = privkey;
}

LibOrgBouncycastleAsn1CrmfProofOfPossession *new_LibOrgBouncycastleAsn1CrmfProofOfPossession_initWithInt_withLibOrgBouncycastleAsn1CrmfPOPOPrivKey_(jint type, LibOrgBouncycastleAsn1CrmfPOPOPrivKey *privkey) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CrmfProofOfPossession, initWithInt_withLibOrgBouncycastleAsn1CrmfPOPOPrivKey_, type, privkey)
}

LibOrgBouncycastleAsn1CrmfProofOfPossession *create_LibOrgBouncycastleAsn1CrmfProofOfPossession_initWithInt_withLibOrgBouncycastleAsn1CrmfPOPOPrivKey_(jint type, LibOrgBouncycastleAsn1CrmfPOPOPrivKey *privkey) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CrmfProofOfPossession, initWithInt_withLibOrgBouncycastleAsn1CrmfPOPOPrivKey_, type, privkey)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1CrmfProofOfPossession)