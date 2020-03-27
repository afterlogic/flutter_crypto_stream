//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/bcpg/ECDSAPublicBCPGKey.java
//

#ifndef ECDSAPublicBCPGKey_H
#define ECDSAPublicBCPGKey_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ECPublicBCPGKey.h"
#include "J2ObjC_header.h"

@class JavaMathBigInteger;
@class LibOrgBouncycastleAsn1ASN1ObjectIdentifier;
@class LibOrgBouncycastleBcpgBCPGInputStream;
@class LibOrgBouncycastleMathEcECPoint;

@interface LibOrgBouncycastleBcpgECDSAPublicBCPGKey : LibOrgBouncycastleBcpgECPublicBCPGKey

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)oid
                                                      withJavaMathBigInteger:(JavaMathBigInteger *)encodedPoint;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)oid
                                         withLibOrgBouncycastleMathEcECPoint:(LibOrgBouncycastleMathEcECPoint *)point;

#pragma mark Protected

- (instancetype __nonnull)initWithLibOrgBouncycastleBcpgBCPGInputStream:(LibOrgBouncycastleBcpgBCPGInputStream *)inArg;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleBcpgECDSAPublicBCPGKey)

FOUNDATION_EXPORT void LibOrgBouncycastleBcpgECDSAPublicBCPGKey_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgECDSAPublicBCPGKey *self, LibOrgBouncycastleBcpgBCPGInputStream *inArg);

FOUNDATION_EXPORT LibOrgBouncycastleBcpgECDSAPublicBCPGKey *new_LibOrgBouncycastleBcpgECDSAPublicBCPGKey_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgBCPGInputStream *inArg) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleBcpgECDSAPublicBCPGKey *create_LibOrgBouncycastleBcpgECDSAPublicBCPGKey_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgBCPGInputStream *inArg);

FOUNDATION_EXPORT void LibOrgBouncycastleBcpgECDSAPublicBCPGKey_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleMathEcECPoint_(LibOrgBouncycastleBcpgECDSAPublicBCPGKey *self, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *oid, LibOrgBouncycastleMathEcECPoint *point);

FOUNDATION_EXPORT LibOrgBouncycastleBcpgECDSAPublicBCPGKey *new_LibOrgBouncycastleBcpgECDSAPublicBCPGKey_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleMathEcECPoint_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *oid, LibOrgBouncycastleMathEcECPoint *point) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleBcpgECDSAPublicBCPGKey *create_LibOrgBouncycastleBcpgECDSAPublicBCPGKey_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleMathEcECPoint_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *oid, LibOrgBouncycastleMathEcECPoint *point);

FOUNDATION_EXPORT void LibOrgBouncycastleBcpgECDSAPublicBCPGKey_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withJavaMathBigInteger_(LibOrgBouncycastleBcpgECDSAPublicBCPGKey *self, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *oid, JavaMathBigInteger *encodedPoint);

FOUNDATION_EXPORT LibOrgBouncycastleBcpgECDSAPublicBCPGKey *new_LibOrgBouncycastleBcpgECDSAPublicBCPGKey_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withJavaMathBigInteger_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *oid, JavaMathBigInteger *encodedPoint) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleBcpgECDSAPublicBCPGKey *create_LibOrgBouncycastleBcpgECDSAPublicBCPGKey_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withJavaMathBigInteger_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *oid, JavaMathBigInteger *encodedPoint);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleBcpgECDSAPublicBCPGKey)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ECDSAPublicBCPGKey_H