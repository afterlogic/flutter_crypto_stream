//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cms/RecipientEncryptedKey.java
//

#ifndef RecipientEncryptedKey_H
#define RecipientEncryptedKey_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleAsn1ASN1OctetString;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1ASN1TaggedObject;
@class LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier;

@interface LibOrgBouncycastleAsn1CmsRecipientEncryptedKey : LibOrgBouncycastleAsn1ASN1Object

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier:(LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier *)id_
                                             withLibOrgBouncycastleAsn1ASN1OctetString:(LibOrgBouncycastleAsn1ASN1OctetString *)encryptedKey;

- (LibOrgBouncycastleAsn1ASN1OctetString *)getEncryptedKey;

- (LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier *)getIdentifier;

+ (LibOrgBouncycastleAsn1CmsRecipientEncryptedKey *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                              withBoolean:(jboolean)explicit_;

+ (LibOrgBouncycastleAsn1CmsRecipientEncryptedKey *)getInstanceWithId:(id)obj;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1CmsRecipientEncryptedKey)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmsRecipientEncryptedKey *LibOrgBouncycastleAsn1CmsRecipientEncryptedKey_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmsRecipientEncryptedKey *LibOrgBouncycastleAsn1CmsRecipientEncryptedKey_getInstanceWithId_(id obj);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1CmsRecipientEncryptedKey_initWithLibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier_withLibOrgBouncycastleAsn1ASN1OctetString_(LibOrgBouncycastleAsn1CmsRecipientEncryptedKey *self, LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier *id_, LibOrgBouncycastleAsn1ASN1OctetString *encryptedKey);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmsRecipientEncryptedKey *new_LibOrgBouncycastleAsn1CmsRecipientEncryptedKey_initWithLibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier_withLibOrgBouncycastleAsn1ASN1OctetString_(LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier *id_, LibOrgBouncycastleAsn1ASN1OctetString *encryptedKey) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmsRecipientEncryptedKey *create_LibOrgBouncycastleAsn1CmsRecipientEncryptedKey_initWithLibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier_withLibOrgBouncycastleAsn1ASN1OctetString_(LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier *id_, LibOrgBouncycastleAsn1ASN1OctetString *encryptedKey);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1CmsRecipientEncryptedKey)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // RecipientEncryptedKey_H
