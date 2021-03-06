//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/ConstructedOctetStream.java
//

#ifndef ConstructedOctetStream_H
#define ConstructedOctetStream_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "java/io/InputStream.h"

@class IOSByteArray;
@class LibOrgBouncycastleAsn1ASN1StreamParser;

@interface LibOrgBouncycastleAsn1ConstructedOctetStream : JavaIoInputStream

#pragma mark Public

- (jint)read;

- (jint)readWithByteArray:(IOSByteArray *)b
                  withInt:(jint)off
                  withInt:(jint)len;

#pragma mark Package-Private

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1StreamParser:(LibOrgBouncycastleAsn1ASN1StreamParser *)parser;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1ConstructedOctetStream)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1ConstructedOctetStream_initWithLibOrgBouncycastleAsn1ASN1StreamParser_(LibOrgBouncycastleAsn1ConstructedOctetStream *self, LibOrgBouncycastleAsn1ASN1StreamParser *parser);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1ConstructedOctetStream *new_LibOrgBouncycastleAsn1ConstructedOctetStream_initWithLibOrgBouncycastleAsn1ASN1StreamParser_(LibOrgBouncycastleAsn1ASN1StreamParser *parser) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1ConstructedOctetStream *create_LibOrgBouncycastleAsn1ConstructedOctetStream_initWithLibOrgBouncycastleAsn1ASN1StreamParser_(LibOrgBouncycastleAsn1ASN1StreamParser *parser);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1ConstructedOctetStream)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ConstructedOctetStream_H
