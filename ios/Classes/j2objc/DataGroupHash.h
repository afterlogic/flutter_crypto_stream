//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/icao/DataGroupHash.java
//

#ifndef DataGroupHash_H
#define DataGroupHash_H

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

@interface LibOrgBouncycastleAsn1IcaoDataGroupHash : LibOrgBouncycastleAsn1ASN1Object {
 @public
  LibOrgBouncycastleAsn1ASN1Integer *dataGroupNumber_;
  LibOrgBouncycastleAsn1ASN1OctetString *dataGroupHashValue_;
}

#pragma mark Public

- (instancetype __nonnull)initWithInt:(jint)dataGroupNumber
withLibOrgBouncycastleAsn1ASN1OctetString:(LibOrgBouncycastleAsn1ASN1OctetString *)dataGroupHashValue;

- (LibOrgBouncycastleAsn1ASN1OctetString *)getDataGroupHashValue;

- (jint)getDataGroupNumber;

+ (LibOrgBouncycastleAsn1IcaoDataGroupHash *)getInstanceWithId:(id)obj;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1IcaoDataGroupHash)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1IcaoDataGroupHash, dataGroupNumber_, LibOrgBouncycastleAsn1ASN1Integer *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1IcaoDataGroupHash, dataGroupHashValue_, LibOrgBouncycastleAsn1ASN1OctetString *)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1IcaoDataGroupHash *LibOrgBouncycastleAsn1IcaoDataGroupHash_getInstanceWithId_(id obj);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1IcaoDataGroupHash_initWithInt_withLibOrgBouncycastleAsn1ASN1OctetString_(LibOrgBouncycastleAsn1IcaoDataGroupHash *self, jint dataGroupNumber, LibOrgBouncycastleAsn1ASN1OctetString *dataGroupHashValue);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1IcaoDataGroupHash *new_LibOrgBouncycastleAsn1IcaoDataGroupHash_initWithInt_withLibOrgBouncycastleAsn1ASN1OctetString_(jint dataGroupNumber, LibOrgBouncycastleAsn1ASN1OctetString *dataGroupHashValue) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1IcaoDataGroupHash *create_LibOrgBouncycastleAsn1IcaoDataGroupHash_initWithInt_withLibOrgBouncycastleAsn1ASN1OctetString_(jint dataGroupNumber, LibOrgBouncycastleAsn1ASN1OctetString *dataGroupHashValue);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1IcaoDataGroupHash)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // DataGroupHash_H
