//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cmc/GetCert.java
//

#ifndef GetCert_H
#define GetCert_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class JavaMathBigInteger;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1X509GeneralName;

@interface LibOrgBouncycastleAsn1CmcGetCert : LibOrgBouncycastleAsn1ASN1Object

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1X509GeneralName:(LibOrgBouncycastleAsn1X509GeneralName *)issuerName
                                                 withJavaMathBigInteger:(JavaMathBigInteger *)serialNumber;

+ (LibOrgBouncycastleAsn1CmcGetCert *)getInstanceWithId:(id)o;

- (LibOrgBouncycastleAsn1X509GeneralName *)getIssuerName;

- (JavaMathBigInteger *)getSerialNumber;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1CmcGetCert)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1CmcGetCert_initWithLibOrgBouncycastleAsn1X509GeneralName_withJavaMathBigInteger_(LibOrgBouncycastleAsn1CmcGetCert *self, LibOrgBouncycastleAsn1X509GeneralName *issuerName, JavaMathBigInteger *serialNumber);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmcGetCert *new_LibOrgBouncycastleAsn1CmcGetCert_initWithLibOrgBouncycastleAsn1X509GeneralName_withJavaMathBigInteger_(LibOrgBouncycastleAsn1X509GeneralName *issuerName, JavaMathBigInteger *serialNumber) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmcGetCert *create_LibOrgBouncycastleAsn1CmcGetCert_initWithLibOrgBouncycastleAsn1X509GeneralName_withJavaMathBigInteger_(LibOrgBouncycastleAsn1X509GeneralName *issuerName, JavaMathBigInteger *serialNumber);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmcGetCert *LibOrgBouncycastleAsn1CmcGetCert_getInstanceWithId_(id o);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1CmcGetCert)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // GetCert_H