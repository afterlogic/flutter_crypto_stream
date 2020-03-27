//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cms/RecipientEncryptedKey.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1Object.h"
#include "ASN1OctetString.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "ASN1TaggedObject.h"
#include "DERSequence.h"
#include "J2ObjC_source.h"
#include "KeyAgreeRecipientIdentifier.h"
#include "RecipientEncryptedKey.h"

@interface LibOrgBouncycastleAsn1CmsRecipientEncryptedKey () {
 @public
  LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier *identifier_;
  LibOrgBouncycastleAsn1ASN1OctetString *encryptedKey_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmsRecipientEncryptedKey, identifier_, LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmsRecipientEncryptedKey, encryptedKey_, LibOrgBouncycastleAsn1ASN1OctetString *)

__attribute__((unused)) static void LibOrgBouncycastleAsn1CmsRecipientEncryptedKey_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmsRecipientEncryptedKey *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1CmsRecipientEncryptedKey *new_LibOrgBouncycastleAsn1CmsRecipientEncryptedKey_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1CmsRecipientEncryptedKey *create_LibOrgBouncycastleAsn1CmsRecipientEncryptedKey_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

@implementation LibOrgBouncycastleAsn1CmsRecipientEncryptedKey

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1CmsRecipientEncryptedKey_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

+ (LibOrgBouncycastleAsn1CmsRecipientEncryptedKey *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                              withBoolean:(jboolean)explicit_ {
  return LibOrgBouncycastleAsn1CmsRecipientEncryptedKey_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_);
}

+ (LibOrgBouncycastleAsn1CmsRecipientEncryptedKey *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1CmsRecipientEncryptedKey_getInstanceWithId_(obj);
}

- (instancetype)initWithLibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier:(LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier *)id_
                                   withLibOrgBouncycastleAsn1ASN1OctetString:(LibOrgBouncycastleAsn1ASN1OctetString *)encryptedKey {
  LibOrgBouncycastleAsn1CmsRecipientEncryptedKey_initWithLibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier_withLibOrgBouncycastleAsn1ASN1OctetString_(self, id_, encryptedKey);
  return self;
}

- (LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier *)getIdentifier {
  return identifier_;
}

- (LibOrgBouncycastleAsn1ASN1OctetString *)getEncryptedKey {
  return encryptedKey_;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:identifier_];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:encryptedKey_];
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, 0, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmsRecipientEncryptedKey;", 0x9, 1, 2, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmsRecipientEncryptedKey;", 0x9, 1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1OctetString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[1].selector = @selector(getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:withBoolean:);
  methods[2].selector = @selector(getInstanceWithId:);
  methods[3].selector = @selector(initWithLibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier:withLibOrgBouncycastleAsn1ASN1OctetString:);
  methods[4].selector = @selector(getIdentifier);
  methods[5].selector = @selector(getEncryptedKey);
  methods[6].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "identifier_", "LLibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "encryptedKey_", "LLibOrgBouncycastleAsn1ASN1OctetString;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1ASN1Sequence;", "getInstance", "LLibOrgBouncycastleAsn1ASN1TaggedObject;Z", "LNSObject;", "LLibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier;LLibOrgBouncycastleAsn1ASN1OctetString;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1CmsRecipientEncryptedKey = { "RecipientEncryptedKey", "lib.org.bouncycastle.asn1.cms", ptrTable, methods, fields, 7, 0x1, 7, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1CmsRecipientEncryptedKey;
}

@end

void LibOrgBouncycastleAsn1CmsRecipientEncryptedKey_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmsRecipientEncryptedKey *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->identifier_ = LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier_getInstanceWithId_([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjectAtWithInt:0]);
  self->encryptedKey_ = (LibOrgBouncycastleAsn1ASN1OctetString *) cast_chk([seq getObjectAtWithInt:1], [LibOrgBouncycastleAsn1ASN1OctetString class]);
}

LibOrgBouncycastleAsn1CmsRecipientEncryptedKey *new_LibOrgBouncycastleAsn1CmsRecipientEncryptedKey_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmsRecipientEncryptedKey, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1CmsRecipientEncryptedKey *create_LibOrgBouncycastleAsn1CmsRecipientEncryptedKey_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmsRecipientEncryptedKey, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1CmsRecipientEncryptedKey *LibOrgBouncycastleAsn1CmsRecipientEncryptedKey_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_) {
  LibOrgBouncycastleAsn1CmsRecipientEncryptedKey_initialize();
  return LibOrgBouncycastleAsn1CmsRecipientEncryptedKey_getInstanceWithId_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_));
}

LibOrgBouncycastleAsn1CmsRecipientEncryptedKey *LibOrgBouncycastleAsn1CmsRecipientEncryptedKey_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1CmsRecipientEncryptedKey_initialize();
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1CmsRecipientEncryptedKey class]]) {
    return (LibOrgBouncycastleAsn1CmsRecipientEncryptedKey *) obj;
  }
  if (obj != nil) {
    return new_LibOrgBouncycastleAsn1CmsRecipientEncryptedKey_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(obj));
  }
  return nil;
}

void LibOrgBouncycastleAsn1CmsRecipientEncryptedKey_initWithLibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier_withLibOrgBouncycastleAsn1ASN1OctetString_(LibOrgBouncycastleAsn1CmsRecipientEncryptedKey *self, LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier *id_, LibOrgBouncycastleAsn1ASN1OctetString *encryptedKey) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->identifier_ = id_;
  self->encryptedKey_ = encryptedKey;
}

LibOrgBouncycastleAsn1CmsRecipientEncryptedKey *new_LibOrgBouncycastleAsn1CmsRecipientEncryptedKey_initWithLibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier_withLibOrgBouncycastleAsn1ASN1OctetString_(LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier *id_, LibOrgBouncycastleAsn1ASN1OctetString *encryptedKey) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmsRecipientEncryptedKey, initWithLibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier_withLibOrgBouncycastleAsn1ASN1OctetString_, id_, encryptedKey)
}

LibOrgBouncycastleAsn1CmsRecipientEncryptedKey *create_LibOrgBouncycastleAsn1CmsRecipientEncryptedKey_initWithLibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier_withLibOrgBouncycastleAsn1ASN1OctetString_(LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier *id_, LibOrgBouncycastleAsn1ASN1OctetString *encryptedKey) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmsRecipientEncryptedKey, initWithLibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier_withLibOrgBouncycastleAsn1ASN1OctetString_, id_, encryptedKey)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1CmsRecipientEncryptedKey)