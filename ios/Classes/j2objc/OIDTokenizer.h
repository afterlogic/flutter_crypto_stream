//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/OIDTokenizer.java
//

#ifndef OIDTokenizer_H
#define OIDTokenizer_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@interface LibOrgBouncycastleAsn1OIDTokenizer : NSObject

#pragma mark Public

- (instancetype __nonnull)initWithNSString:(NSString *)oid;

- (jboolean)hasMoreTokens;

- (NSString *)nextToken;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1OIDTokenizer)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1OIDTokenizer_initWithNSString_(LibOrgBouncycastleAsn1OIDTokenizer *self, NSString *oid);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1OIDTokenizer *new_LibOrgBouncycastleAsn1OIDTokenizer_initWithNSString_(NSString *oid) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1OIDTokenizer *create_LibOrgBouncycastleAsn1OIDTokenizer_initWithNSString_(NSString *oid);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1OIDTokenizer)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // OIDTokenizer_H
