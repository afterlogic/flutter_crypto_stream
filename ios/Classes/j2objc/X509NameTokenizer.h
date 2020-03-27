//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/x509/X509NameTokenizer.java
//

#ifndef X509NameTokenizer_H
#define X509NameTokenizer_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@interface LibOrgBouncycastleAsn1X509X509NameTokenizer : NSObject

#pragma mark Public

- (instancetype __nonnull)initWithNSString:(NSString *)oid;

- (instancetype __nonnull)initWithNSString:(NSString *)oid
                                  withChar:(jchar)separator;

- (jboolean)hasMoreTokens;

- (NSString *)nextToken;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1X509X509NameTokenizer)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1X509X509NameTokenizer_initWithNSString_(LibOrgBouncycastleAsn1X509X509NameTokenizer *self, NSString *oid);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509X509NameTokenizer *new_LibOrgBouncycastleAsn1X509X509NameTokenizer_initWithNSString_(NSString *oid) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509X509NameTokenizer *create_LibOrgBouncycastleAsn1X509X509NameTokenizer_initWithNSString_(NSString *oid);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1X509X509NameTokenizer_initWithNSString_withChar_(LibOrgBouncycastleAsn1X509X509NameTokenizer *self, NSString *oid, jchar separator);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509X509NameTokenizer *new_LibOrgBouncycastleAsn1X509X509NameTokenizer_initWithNSString_withChar_(NSString *oid, jchar separator) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509X509NameTokenizer *create_LibOrgBouncycastleAsn1X509X509NameTokenizer_initWithNSString_withChar_(NSString *oid, jchar separator);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1X509X509NameTokenizer)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // X509NameTokenizer_H