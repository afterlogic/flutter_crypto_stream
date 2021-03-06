//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/x509/AttCertValidityPeriod.java
//

#ifndef AttCertValidityPeriod_H
#define AttCertValidityPeriod_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleAsn1ASN1GeneralizedTime;
@class LibOrgBouncycastleAsn1ASN1Primitive;

@interface LibOrgBouncycastleAsn1X509AttCertValidityPeriod : LibOrgBouncycastleAsn1ASN1Object {
 @public
  LibOrgBouncycastleAsn1ASN1GeneralizedTime *notBeforeTime_;
  LibOrgBouncycastleAsn1ASN1GeneralizedTime *notAfterTime_;
}

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1GeneralizedTime:(LibOrgBouncycastleAsn1ASN1GeneralizedTime *)notBeforeTime
                              withLibOrgBouncycastleAsn1ASN1GeneralizedTime:(LibOrgBouncycastleAsn1ASN1GeneralizedTime *)notAfterTime;

+ (LibOrgBouncycastleAsn1X509AttCertValidityPeriod *)getInstanceWithId:(id)obj;

- (LibOrgBouncycastleAsn1ASN1GeneralizedTime *)getNotAfterTime;

- (LibOrgBouncycastleAsn1ASN1GeneralizedTime *)getNotBeforeTime;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1X509AttCertValidityPeriod)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509AttCertValidityPeriod, notBeforeTime_, LibOrgBouncycastleAsn1ASN1GeneralizedTime *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509AttCertValidityPeriod, notAfterTime_, LibOrgBouncycastleAsn1ASN1GeneralizedTime *)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509AttCertValidityPeriod *LibOrgBouncycastleAsn1X509AttCertValidityPeriod_getInstanceWithId_(id obj);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1X509AttCertValidityPeriod_initWithLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_(LibOrgBouncycastleAsn1X509AttCertValidityPeriod *self, LibOrgBouncycastleAsn1ASN1GeneralizedTime *notBeforeTime, LibOrgBouncycastleAsn1ASN1GeneralizedTime *notAfterTime);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509AttCertValidityPeriod *new_LibOrgBouncycastleAsn1X509AttCertValidityPeriod_initWithLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_(LibOrgBouncycastleAsn1ASN1GeneralizedTime *notBeforeTime, LibOrgBouncycastleAsn1ASN1GeneralizedTime *notAfterTime) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509AttCertValidityPeriod *create_LibOrgBouncycastleAsn1X509AttCertValidityPeriod_initWithLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_(LibOrgBouncycastleAsn1ASN1GeneralizedTime *notBeforeTime, LibOrgBouncycastleAsn1ASN1GeneralizedTime *notAfterTime);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1X509AttCertValidityPeriod)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // AttCertValidityPeriod_H
