//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/LazyConstructionEnumeration.java
//

#ifndef LazyConstructionEnumeration_H
#define LazyConstructionEnumeration_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "java/util/Enumeration.h"

@class IOSByteArray;

@interface LibOrgBouncycastleAsn1LazyConstructionEnumeration : NSObject < JavaUtilEnumeration >

#pragma mark Public

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)encoded;

- (jboolean)hasMoreElements;

- (id)nextElement;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1LazyConstructionEnumeration)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1LazyConstructionEnumeration_initWithByteArray_(LibOrgBouncycastleAsn1LazyConstructionEnumeration *self, IOSByteArray *encoded);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1LazyConstructionEnumeration *new_LibOrgBouncycastleAsn1LazyConstructionEnumeration_initWithByteArray_(IOSByteArray *encoded) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1LazyConstructionEnumeration *create_LibOrgBouncycastleAsn1LazyConstructionEnumeration_initWithByteArray_(IOSByteArray *encoded);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1LazyConstructionEnumeration)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // LazyConstructionEnumeration_H
