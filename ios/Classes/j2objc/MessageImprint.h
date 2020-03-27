//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/tsp/MessageImprint.java
//

#ifndef MessageImprint_H
#define MessageImprint_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1X509AlgorithmIdentifier;

@interface LibOrgBouncycastleAsn1TspMessageImprint : LibOrgBouncycastleAsn1ASN1Object {
 @public
  LibOrgBouncycastleAsn1X509AlgorithmIdentifier *hashAlgorithm_;
  IOSByteArray *hashedMessage_;
}

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier:(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)hashAlgorithm
                                                                  withByteArray:(IOSByteArray *)hashedMessage;

- (LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)getHashAlgorithm;

- (IOSByteArray *)getHashedMessage;

+ (LibOrgBouncycastleAsn1TspMessageImprint *)getInstanceWithId:(id)o;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1TspMessageImprint)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1TspMessageImprint, hashAlgorithm_, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1TspMessageImprint, hashedMessage_, IOSByteArray *)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1TspMessageImprint *LibOrgBouncycastleAsn1TspMessageImprint_getInstanceWithId_(id o);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1TspMessageImprint_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_(LibOrgBouncycastleAsn1TspMessageImprint *self, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *hashAlgorithm, IOSByteArray *hashedMessage);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1TspMessageImprint *new_LibOrgBouncycastleAsn1TspMessageImprint_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *hashAlgorithm, IOSByteArray *hashedMessage) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1TspMessageImprint *create_LibOrgBouncycastleAsn1TspMessageImprint_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *hashAlgorithm, IOSByteArray *hashedMessage);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1TspMessageImprint)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // MessageImprint_H