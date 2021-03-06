//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cmp/CertRepMessage.java
//

#ifndef CertRepMessage_H
#define CertRepMessage_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class IOSObjectArray;
@class LibOrgBouncycastleAsn1ASN1Primitive;

@interface LibOrgBouncycastleAsn1CmpCertRepMessage : LibOrgBouncycastleAsn1ASN1Object

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1CmpCMPCertificateArray:(IOSObjectArray *)caPubs
                                withLibOrgBouncycastleAsn1CmpCertResponseArray:(IOSObjectArray *)response;

- (IOSObjectArray *)getCaPubs;

+ (LibOrgBouncycastleAsn1CmpCertRepMessage *)getInstanceWithId:(id)o;

- (IOSObjectArray *)getResponse;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1CmpCertRepMessage)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmpCertRepMessage *LibOrgBouncycastleAsn1CmpCertRepMessage_getInstanceWithId_(id o);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1CmpCertRepMessage_initWithLibOrgBouncycastleAsn1CmpCMPCertificateArray_withLibOrgBouncycastleAsn1CmpCertResponseArray_(LibOrgBouncycastleAsn1CmpCertRepMessage *self, IOSObjectArray *caPubs, IOSObjectArray *response);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmpCertRepMessage *new_LibOrgBouncycastleAsn1CmpCertRepMessage_initWithLibOrgBouncycastleAsn1CmpCMPCertificateArray_withLibOrgBouncycastleAsn1CmpCertResponseArray_(IOSObjectArray *caPubs, IOSObjectArray *response) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmpCertRepMessage *create_LibOrgBouncycastleAsn1CmpCertRepMessage_initWithLibOrgBouncycastleAsn1CmpCMPCertificateArray_withLibOrgBouncycastleAsn1CmpCertResponseArray_(IOSObjectArray *caPubs, IOSObjectArray *response);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1CmpCertRepMessage)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // CertRepMessage_H
