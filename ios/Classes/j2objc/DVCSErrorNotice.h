//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/dvcs/DVCSErrorNotice.java
//

#ifndef DVCSErrorNotice_H
#define DVCSErrorNotice_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1ASN1TaggedObject;
@class LibOrgBouncycastleAsn1CmpPKIStatusInfo;
@class LibOrgBouncycastleAsn1X509GeneralName;

@interface LibOrgBouncycastleAsn1DvcsDVCSErrorNotice : LibOrgBouncycastleAsn1ASN1Object

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1CmpPKIStatusInfo:(LibOrgBouncycastleAsn1CmpPKIStatusInfo *)status;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1CmpPKIStatusInfo:(LibOrgBouncycastleAsn1CmpPKIStatusInfo *)status
                               withLibOrgBouncycastleAsn1X509GeneralName:(LibOrgBouncycastleAsn1X509GeneralName *)transactionIdentifier;

+ (LibOrgBouncycastleAsn1DvcsDVCSErrorNotice *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                         withBoolean:(jboolean)explicit_;

+ (LibOrgBouncycastleAsn1DvcsDVCSErrorNotice *)getInstanceWithId:(id)obj;

- (LibOrgBouncycastleAsn1X509GeneralName *)getTransactionIdentifier;

- (LibOrgBouncycastleAsn1CmpPKIStatusInfo *)getTransactionStatus;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

- (NSString *)description;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1DvcsDVCSErrorNotice)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1DvcsDVCSErrorNotice_initWithLibOrgBouncycastleAsn1CmpPKIStatusInfo_(LibOrgBouncycastleAsn1DvcsDVCSErrorNotice *self, LibOrgBouncycastleAsn1CmpPKIStatusInfo *status);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DvcsDVCSErrorNotice *new_LibOrgBouncycastleAsn1DvcsDVCSErrorNotice_initWithLibOrgBouncycastleAsn1CmpPKIStatusInfo_(LibOrgBouncycastleAsn1CmpPKIStatusInfo *status) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DvcsDVCSErrorNotice *create_LibOrgBouncycastleAsn1DvcsDVCSErrorNotice_initWithLibOrgBouncycastleAsn1CmpPKIStatusInfo_(LibOrgBouncycastleAsn1CmpPKIStatusInfo *status);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1DvcsDVCSErrorNotice_initWithLibOrgBouncycastleAsn1CmpPKIStatusInfo_withLibOrgBouncycastleAsn1X509GeneralName_(LibOrgBouncycastleAsn1DvcsDVCSErrorNotice *self, LibOrgBouncycastleAsn1CmpPKIStatusInfo *status, LibOrgBouncycastleAsn1X509GeneralName *transactionIdentifier);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DvcsDVCSErrorNotice *new_LibOrgBouncycastleAsn1DvcsDVCSErrorNotice_initWithLibOrgBouncycastleAsn1CmpPKIStatusInfo_withLibOrgBouncycastleAsn1X509GeneralName_(LibOrgBouncycastleAsn1CmpPKIStatusInfo *status, LibOrgBouncycastleAsn1X509GeneralName *transactionIdentifier) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DvcsDVCSErrorNotice *create_LibOrgBouncycastleAsn1DvcsDVCSErrorNotice_initWithLibOrgBouncycastleAsn1CmpPKIStatusInfo_withLibOrgBouncycastleAsn1X509GeneralName_(LibOrgBouncycastleAsn1CmpPKIStatusInfo *status, LibOrgBouncycastleAsn1X509GeneralName *transactionIdentifier);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DvcsDVCSErrorNotice *LibOrgBouncycastleAsn1DvcsDVCSErrorNotice_getInstanceWithId_(id obj);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DvcsDVCSErrorNotice *LibOrgBouncycastleAsn1DvcsDVCSErrorNotice_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1DvcsDVCSErrorNotice)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // DVCSErrorNotice_H
