//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cms/KeyTransRecipientInfo.java
//

#ifndef KeyTransRecipientInfo_H
#define KeyTransRecipientInfo_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleAsn1ASN1Integer;
@class LibOrgBouncycastleAsn1ASN1OctetString;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1ASN1Sequence;
@class LibOrgBouncycastleAsn1CmsRecipientIdentifier;
@class LibOrgBouncycastleAsn1X509AlgorithmIdentifier;

@interface LibOrgBouncycastleAsn1CmsKeyTransRecipientInfo : LibOrgBouncycastleAsn1ASN1Object

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1CmsRecipientIdentifier:(LibOrgBouncycastleAsn1CmsRecipientIdentifier *)rid
                             withLibOrgBouncycastleAsn1X509AlgorithmIdentifier:(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)keyEncryptionAlgorithm
                                     withLibOrgBouncycastleAsn1ASN1OctetString:(LibOrgBouncycastleAsn1ASN1OctetString *)encryptedKey;

- (LibOrgBouncycastleAsn1ASN1OctetString *)getEncryptedKey;

+ (LibOrgBouncycastleAsn1CmsKeyTransRecipientInfo *)getInstanceWithId:(id)obj;

- (LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)getKeyEncryptionAlgorithm;

- (LibOrgBouncycastleAsn1CmsRecipientIdentifier *)getRecipientIdentifier;

- (LibOrgBouncycastleAsn1ASN1Integer *)getVersion;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1CmsKeyTransRecipientInfo)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1CmsKeyTransRecipientInfo_initWithLibOrgBouncycastleAsn1CmsRecipientIdentifier_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1ASN1OctetString_(LibOrgBouncycastleAsn1CmsKeyTransRecipientInfo *self, LibOrgBouncycastleAsn1CmsRecipientIdentifier *rid, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *keyEncryptionAlgorithm, LibOrgBouncycastleAsn1ASN1OctetString *encryptedKey);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmsKeyTransRecipientInfo *new_LibOrgBouncycastleAsn1CmsKeyTransRecipientInfo_initWithLibOrgBouncycastleAsn1CmsRecipientIdentifier_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1ASN1OctetString_(LibOrgBouncycastleAsn1CmsRecipientIdentifier *rid, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *keyEncryptionAlgorithm, LibOrgBouncycastleAsn1ASN1OctetString *encryptedKey) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmsKeyTransRecipientInfo *create_LibOrgBouncycastleAsn1CmsKeyTransRecipientInfo_initWithLibOrgBouncycastleAsn1CmsRecipientIdentifier_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1ASN1OctetString_(LibOrgBouncycastleAsn1CmsRecipientIdentifier *rid, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *keyEncryptionAlgorithm, LibOrgBouncycastleAsn1ASN1OctetString *encryptedKey);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1CmsKeyTransRecipientInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmsKeyTransRecipientInfo *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmsKeyTransRecipientInfo *new_LibOrgBouncycastleAsn1CmsKeyTransRecipientInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmsKeyTransRecipientInfo *create_LibOrgBouncycastleAsn1CmsKeyTransRecipientInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmsKeyTransRecipientInfo *LibOrgBouncycastleAsn1CmsKeyTransRecipientInfo_getInstanceWithId_(id obj);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1CmsKeyTransRecipientInfo)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // KeyTransRecipientInfo_H
