//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/ASN1TaggedObjectParser.java
//

#ifndef ASN1TaggedObjectParser_H
#define ASN1TaggedObjectParser_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Encodable.h"
#include "InMemoryRepresentable.h"
#include "J2ObjC_header.h"

@protocol LibOrgBouncycastleAsn1ASN1TaggedObjectParser < LibOrgBouncycastleAsn1ASN1Encodable, LibOrgBouncycastleAsn1InMemoryRepresentable, JavaObject >

- (jint)getTagNo;

- (id<LibOrgBouncycastleAsn1ASN1Encodable>)getObjectParserWithInt:(jint)tag
                                                      withBoolean:(jboolean)isExplicit;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1ASN1TaggedObjectParser)

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1ASN1TaggedObjectParser)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ASN1TaggedObjectParser_H
