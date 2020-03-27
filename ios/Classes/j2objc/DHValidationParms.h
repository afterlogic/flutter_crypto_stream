//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/x9/DHValidationParms.java
//

#ifndef DHValidationParms_H
#define DHValidationParms_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleAsn1ASN1Integer;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1ASN1TaggedObject;
@class LibOrgBouncycastleAsn1DERBitString;

@interface LibOrgBouncycastleAsn1X9DHValidationParms : LibOrgBouncycastleAsn1ASN1Object

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1DERBitString:(LibOrgBouncycastleAsn1DERBitString *)seed
                               withLibOrgBouncycastleAsn1ASN1Integer:(LibOrgBouncycastleAsn1ASN1Integer *)pgenCounter;

+ (LibOrgBouncycastleAsn1X9DHValidationParms *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                         withBoolean:(jboolean)explicit_;

+ (LibOrgBouncycastleAsn1X9DHValidationParms *)getInstanceWithId:(id)obj;

- (LibOrgBouncycastleAsn1ASN1Integer *)getPgenCounter;

- (LibOrgBouncycastleAsn1DERBitString *)getSeed;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1X9DHValidationParms)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X9DHValidationParms *LibOrgBouncycastleAsn1X9DHValidationParms_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X9DHValidationParms *LibOrgBouncycastleAsn1X9DHValidationParms_getInstanceWithId_(id obj);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1X9DHValidationParms_initWithLibOrgBouncycastleAsn1DERBitString_withLibOrgBouncycastleAsn1ASN1Integer_(LibOrgBouncycastleAsn1X9DHValidationParms *self, LibOrgBouncycastleAsn1DERBitString *seed, LibOrgBouncycastleAsn1ASN1Integer *pgenCounter);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X9DHValidationParms *new_LibOrgBouncycastleAsn1X9DHValidationParms_initWithLibOrgBouncycastleAsn1DERBitString_withLibOrgBouncycastleAsn1ASN1Integer_(LibOrgBouncycastleAsn1DERBitString *seed, LibOrgBouncycastleAsn1ASN1Integer *pgenCounter) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X9DHValidationParms *create_LibOrgBouncycastleAsn1X9DHValidationParms_initWithLibOrgBouncycastleAsn1DERBitString_withLibOrgBouncycastleAsn1ASN1Integer_(LibOrgBouncycastleAsn1DERBitString *seed, LibOrgBouncycastleAsn1ASN1Integer *pgenCounter);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1X9DHValidationParms)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // DHValidationParms_H