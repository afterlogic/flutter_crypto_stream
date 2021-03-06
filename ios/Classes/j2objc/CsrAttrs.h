//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/est/CsrAttrs.java
//

#ifndef CsrAttrs_H
#define CsrAttrs_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class IOSObjectArray;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1ASN1TaggedObject;
@class LibOrgBouncycastleAsn1EstAttrOrOID;

@interface LibOrgBouncycastleAsn1EstCsrAttrs : LibOrgBouncycastleAsn1ASN1Object

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1EstAttrOrOID:(LibOrgBouncycastleAsn1EstAttrOrOID *)attrOrOID;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1EstAttrOrOIDArray:(IOSObjectArray *)attrOrOIDs;

- (IOSObjectArray *)getAttrOrOIDs;

+ (LibOrgBouncycastleAsn1EstCsrAttrs *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                 withBoolean:(jboolean)explicit_;

+ (LibOrgBouncycastleAsn1EstCsrAttrs *)getInstanceWithId:(id)obj;

- (jint)size;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1EstCsrAttrs)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EstCsrAttrs *LibOrgBouncycastleAsn1EstCsrAttrs_getInstanceWithId_(id obj);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EstCsrAttrs *LibOrgBouncycastleAsn1EstCsrAttrs_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1EstCsrAttrs_initWithLibOrgBouncycastleAsn1EstAttrOrOID_(LibOrgBouncycastleAsn1EstCsrAttrs *self, LibOrgBouncycastleAsn1EstAttrOrOID *attrOrOID);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EstCsrAttrs *new_LibOrgBouncycastleAsn1EstCsrAttrs_initWithLibOrgBouncycastleAsn1EstAttrOrOID_(LibOrgBouncycastleAsn1EstAttrOrOID *attrOrOID) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EstCsrAttrs *create_LibOrgBouncycastleAsn1EstCsrAttrs_initWithLibOrgBouncycastleAsn1EstAttrOrOID_(LibOrgBouncycastleAsn1EstAttrOrOID *attrOrOID);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1EstCsrAttrs_initWithLibOrgBouncycastleAsn1EstAttrOrOIDArray_(LibOrgBouncycastleAsn1EstCsrAttrs *self, IOSObjectArray *attrOrOIDs);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EstCsrAttrs *new_LibOrgBouncycastleAsn1EstCsrAttrs_initWithLibOrgBouncycastleAsn1EstAttrOrOIDArray_(IOSObjectArray *attrOrOIDs) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EstCsrAttrs *create_LibOrgBouncycastleAsn1EstCsrAttrs_initWithLibOrgBouncycastleAsn1EstAttrOrOIDArray_(IOSObjectArray *attrOrOIDs);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1EstCsrAttrs)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // CsrAttrs_H
