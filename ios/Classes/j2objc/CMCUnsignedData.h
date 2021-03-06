//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cmc/CMCUnsignedData.java
//

#ifndef CMCUnsignedData_H
#define CMCUnsignedData_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleAsn1ASN1ObjectIdentifier;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1CmcBodyPartPath;
@protocol LibOrgBouncycastleAsn1ASN1Encodable;

@interface LibOrgBouncycastleAsn1CmcCMCUnsignedData : LibOrgBouncycastleAsn1ASN1Object

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1CmcBodyPartPath:(LibOrgBouncycastleAsn1CmcBodyPartPath *)bodyPartPath
                         withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)identifier
                                withLibOrgBouncycastleAsn1ASN1Encodable:(id<LibOrgBouncycastleAsn1ASN1Encodable>)content;

- (LibOrgBouncycastleAsn1CmcBodyPartPath *)getBodyPartPath;

- (id<LibOrgBouncycastleAsn1ASN1Encodable>)getContent;

- (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)getIdentifier;

+ (LibOrgBouncycastleAsn1CmcCMCUnsignedData *)getInstanceWithId:(id)o;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1CmcCMCUnsignedData)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1CmcCMCUnsignedData_initWithLibOrgBouncycastleAsn1CmcBodyPartPath_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1CmcCMCUnsignedData *self, LibOrgBouncycastleAsn1CmcBodyPartPath *bodyPartPath, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *identifier, id<LibOrgBouncycastleAsn1ASN1Encodable> content);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmcCMCUnsignedData *new_LibOrgBouncycastleAsn1CmcCMCUnsignedData_initWithLibOrgBouncycastleAsn1CmcBodyPartPath_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1CmcBodyPartPath *bodyPartPath, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *identifier, id<LibOrgBouncycastleAsn1ASN1Encodable> content) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmcCMCUnsignedData *create_LibOrgBouncycastleAsn1CmcCMCUnsignedData_initWithLibOrgBouncycastleAsn1CmcBodyPartPath_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1CmcBodyPartPath *bodyPartPath, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *identifier, id<LibOrgBouncycastleAsn1ASN1Encodable> content);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmcCMCUnsignedData *LibOrgBouncycastleAsn1CmcCMCUnsignedData_getInstanceWithId_(id o);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1CmcCMCUnsignedData)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // CMCUnsignedData_H
