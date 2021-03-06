//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/ASN1StreamParser.java
//

#ifndef ASN1StreamParser_H
#define ASN1StreamParser_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;
@class JavaIoInputStream;
@class LibOrgBouncycastleAsn1ASN1EncodableVector;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@protocol LibOrgBouncycastleAsn1ASN1Encodable;

@interface LibOrgBouncycastleAsn1ASN1StreamParser : NSObject

#pragma mark Public

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)encoding;

- (instancetype __nonnull)initWithJavaIoInputStream:(JavaIoInputStream *)inArg;

- (instancetype __nonnull)initWithJavaIoInputStream:(JavaIoInputStream *)inArg
                                            withInt:(jint)limit;

- (id<LibOrgBouncycastleAsn1ASN1Encodable>)readObject;

#pragma mark Package-Private

- (id<LibOrgBouncycastleAsn1ASN1Encodable>)readImplicitWithBoolean:(jboolean)constructed
                                                           withInt:(jint)tag;

- (id<LibOrgBouncycastleAsn1ASN1Encodable>)readIndefWithInt:(jint)tagValue;

- (LibOrgBouncycastleAsn1ASN1Primitive *)readTaggedObjectWithBoolean:(jboolean)constructed
                                                             withInt:(jint)tag;

- (LibOrgBouncycastleAsn1ASN1EncodableVector *)readVector;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1ASN1StreamParser)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1ASN1StreamParser_initWithJavaIoInputStream_(LibOrgBouncycastleAsn1ASN1StreamParser *self, JavaIoInputStream *inArg);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1StreamParser *new_LibOrgBouncycastleAsn1ASN1StreamParser_initWithJavaIoInputStream_(JavaIoInputStream *inArg) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1StreamParser *create_LibOrgBouncycastleAsn1ASN1StreamParser_initWithJavaIoInputStream_(JavaIoInputStream *inArg);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1ASN1StreamParser_initWithJavaIoInputStream_withInt_(LibOrgBouncycastleAsn1ASN1StreamParser *self, JavaIoInputStream *inArg, jint limit);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1StreamParser *new_LibOrgBouncycastleAsn1ASN1StreamParser_initWithJavaIoInputStream_withInt_(JavaIoInputStream *inArg, jint limit) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1StreamParser *create_LibOrgBouncycastleAsn1ASN1StreamParser_initWithJavaIoInputStream_withInt_(JavaIoInputStream *inArg, jint limit);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1ASN1StreamParser_initWithByteArray_(LibOrgBouncycastleAsn1ASN1StreamParser *self, IOSByteArray *encoding);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1StreamParser *new_LibOrgBouncycastleAsn1ASN1StreamParser_initWithByteArray_(IOSByteArray *encoding) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1StreamParser *create_LibOrgBouncycastleAsn1ASN1StreamParser_initWithByteArray_(IOSByteArray *encoding);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1ASN1StreamParser)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ASN1StreamParser_H
