//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/ocsp/ResponseBytes.java
//

#ifndef ResponseBytes_H
#define ResponseBytes_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleAsn1ASN1ObjectIdentifier;
@class LibOrgBouncycastleAsn1ASN1OctetString;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1ASN1Sequence;
@class LibOrgBouncycastleAsn1ASN1TaggedObject;

@interface LibOrgBouncycastleAsn1OcspResponseBytes : LibOrgBouncycastleAsn1ASN1Object {
 @public
  LibOrgBouncycastleAsn1ASN1ObjectIdentifier *responseType_;
  LibOrgBouncycastleAsn1ASN1OctetString *response_;
}

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)responseType
                                   withLibOrgBouncycastleAsn1ASN1OctetString:(LibOrgBouncycastleAsn1ASN1OctetString *)response;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

+ (LibOrgBouncycastleAsn1OcspResponseBytes *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                       withBoolean:(jboolean)explicit_;

+ (LibOrgBouncycastleAsn1OcspResponseBytes *)getInstanceWithId:(id)obj;

- (LibOrgBouncycastleAsn1ASN1OctetString *)getResponse;

- (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)getResponseType;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1OcspResponseBytes)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1OcspResponseBytes, responseType_, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1OcspResponseBytes, response_, LibOrgBouncycastleAsn1ASN1OctetString *)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1OcspResponseBytes_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1OctetString_(LibOrgBouncycastleAsn1OcspResponseBytes *self, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *responseType, LibOrgBouncycastleAsn1ASN1OctetString *response);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1OcspResponseBytes *new_LibOrgBouncycastleAsn1OcspResponseBytes_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1OctetString_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *responseType, LibOrgBouncycastleAsn1ASN1OctetString *response) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1OcspResponseBytes *create_LibOrgBouncycastleAsn1OcspResponseBytes_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1OctetString_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *responseType, LibOrgBouncycastleAsn1ASN1OctetString *response);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1OcspResponseBytes_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1OcspResponseBytes *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1OcspResponseBytes *new_LibOrgBouncycastleAsn1OcspResponseBytes_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1OcspResponseBytes *create_LibOrgBouncycastleAsn1OcspResponseBytes_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1OcspResponseBytes *LibOrgBouncycastleAsn1OcspResponseBytes_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1OcspResponseBytes *LibOrgBouncycastleAsn1OcspResponseBytes_getInstanceWithId_(id obj);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1OcspResponseBytes)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ResponseBytes_H
