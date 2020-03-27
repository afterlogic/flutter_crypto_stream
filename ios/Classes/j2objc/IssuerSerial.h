//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/x509/IssuerSerial.java
//

#ifndef IssuerSerial_H
#define IssuerSerial_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class JavaMathBigInteger;
@class LibOrgBouncycastleAsn1ASN1Integer;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1ASN1TaggedObject;
@class LibOrgBouncycastleAsn1DERBitString;
@class LibOrgBouncycastleAsn1X500X500Name;
@class LibOrgBouncycastleAsn1X509GeneralNames;

@interface LibOrgBouncycastleAsn1X509IssuerSerial : LibOrgBouncycastleAsn1ASN1Object {
 @public
  LibOrgBouncycastleAsn1X509GeneralNames *issuer_;
  LibOrgBouncycastleAsn1ASN1Integer *serial_;
  LibOrgBouncycastleAsn1DERBitString *issuerUID_;
}

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1X509GeneralNames:(LibOrgBouncycastleAsn1X509GeneralNames *)issuer
                                   withLibOrgBouncycastleAsn1ASN1Integer:(LibOrgBouncycastleAsn1ASN1Integer *)serial;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1X509GeneralNames:(LibOrgBouncycastleAsn1X509GeneralNames *)issuer
                                                  withJavaMathBigInteger:(JavaMathBigInteger *)serial;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1X500X500Name:(LibOrgBouncycastleAsn1X500X500Name *)issuer
                                              withJavaMathBigInteger:(JavaMathBigInteger *)serial;

+ (LibOrgBouncycastleAsn1X509IssuerSerial *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                      withBoolean:(jboolean)explicit_;

+ (LibOrgBouncycastleAsn1X509IssuerSerial *)getInstanceWithId:(id)obj;

- (LibOrgBouncycastleAsn1X509GeneralNames *)getIssuer;

- (LibOrgBouncycastleAsn1DERBitString *)getIssuerUID;

- (LibOrgBouncycastleAsn1ASN1Integer *)getSerial;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1X509IssuerSerial)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509IssuerSerial, issuer_, LibOrgBouncycastleAsn1X509GeneralNames *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509IssuerSerial, serial_, LibOrgBouncycastleAsn1ASN1Integer *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509IssuerSerial, issuerUID_, LibOrgBouncycastleAsn1DERBitString *)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509IssuerSerial *LibOrgBouncycastleAsn1X509IssuerSerial_getInstanceWithId_(id obj);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509IssuerSerial *LibOrgBouncycastleAsn1X509IssuerSerial_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1X509IssuerSerial_initWithLibOrgBouncycastleAsn1X500X500Name_withJavaMathBigInteger_(LibOrgBouncycastleAsn1X509IssuerSerial *self, LibOrgBouncycastleAsn1X500X500Name *issuer, JavaMathBigInteger *serial);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509IssuerSerial *new_LibOrgBouncycastleAsn1X509IssuerSerial_initWithLibOrgBouncycastleAsn1X500X500Name_withJavaMathBigInteger_(LibOrgBouncycastleAsn1X500X500Name *issuer, JavaMathBigInteger *serial) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509IssuerSerial *create_LibOrgBouncycastleAsn1X509IssuerSerial_initWithLibOrgBouncycastleAsn1X500X500Name_withJavaMathBigInteger_(LibOrgBouncycastleAsn1X500X500Name *issuer, JavaMathBigInteger *serial);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1X509IssuerSerial_initWithLibOrgBouncycastleAsn1X509GeneralNames_withJavaMathBigInteger_(LibOrgBouncycastleAsn1X509IssuerSerial *self, LibOrgBouncycastleAsn1X509GeneralNames *issuer, JavaMathBigInteger *serial);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509IssuerSerial *new_LibOrgBouncycastleAsn1X509IssuerSerial_initWithLibOrgBouncycastleAsn1X509GeneralNames_withJavaMathBigInteger_(LibOrgBouncycastleAsn1X509GeneralNames *issuer, JavaMathBigInteger *serial) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509IssuerSerial *create_LibOrgBouncycastleAsn1X509IssuerSerial_initWithLibOrgBouncycastleAsn1X509GeneralNames_withJavaMathBigInteger_(LibOrgBouncycastleAsn1X509GeneralNames *issuer, JavaMathBigInteger *serial);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1X509IssuerSerial_initWithLibOrgBouncycastleAsn1X509GeneralNames_withLibOrgBouncycastleAsn1ASN1Integer_(LibOrgBouncycastleAsn1X509IssuerSerial *self, LibOrgBouncycastleAsn1X509GeneralNames *issuer, LibOrgBouncycastleAsn1ASN1Integer *serial);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509IssuerSerial *new_LibOrgBouncycastleAsn1X509IssuerSerial_initWithLibOrgBouncycastleAsn1X509GeneralNames_withLibOrgBouncycastleAsn1ASN1Integer_(LibOrgBouncycastleAsn1X509GeneralNames *issuer, LibOrgBouncycastleAsn1ASN1Integer *serial) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509IssuerSerial *create_LibOrgBouncycastleAsn1X509IssuerSerial_initWithLibOrgBouncycastleAsn1X509GeneralNames_withLibOrgBouncycastleAsn1ASN1Integer_(LibOrgBouncycastleAsn1X509GeneralNames *issuer, LibOrgBouncycastleAsn1ASN1Integer *serial);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1X509IssuerSerial)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // IssuerSerial_H