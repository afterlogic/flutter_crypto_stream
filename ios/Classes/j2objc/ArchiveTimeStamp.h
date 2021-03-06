//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/tsp/ArchiveTimeStamp.java
//

#ifndef ArchiveTimeStamp_H
#define ArchiveTimeStamp_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class IOSObjectArray;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo;
@class LibOrgBouncycastleAsn1CmsAttributes;
@class LibOrgBouncycastleAsn1X509AlgorithmIdentifier;

@interface LibOrgBouncycastleAsn1TspArchiveTimeStamp : LibOrgBouncycastleAsn1ASN1Object

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier:(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)digestAlgorithm
                                        withLibOrgBouncycastleAsn1CmsAttributes:(LibOrgBouncycastleAsn1CmsAttributes *)attributes
                              withLibOrgBouncycastleAsn1TspPartialHashtreeArray:(IOSObjectArray *)reducedHashTree
                                withLibOrgBouncycastleAsn1CmsAsn1CmsContentInfo:(LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo *)timeStamp;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier:(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)digestAlgorithm
                              withLibOrgBouncycastleAsn1TspPartialHashtreeArray:(IOSObjectArray *)reducedHashTree
                                withLibOrgBouncycastleAsn1CmsAsn1CmsContentInfo:(LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo *)timeStamp;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1CmsAsn1CmsContentInfo:(LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo *)timeStamp;

- (LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)getDigestAlgorithm;

- (LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)getDigestAlgorithmIdentifier;

+ (LibOrgBouncycastleAsn1TspArchiveTimeStamp *)getInstanceWithId:(id)obj;

- (IOSObjectArray *)getReducedHashTree;

- (LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo *)getTimeStamp;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1TspArchiveTimeStamp)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1TspArchiveTimeStamp *LibOrgBouncycastleAsn1TspArchiveTimeStamp_getInstanceWithId_(id obj);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1TspArchiveTimeStamp_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1TspPartialHashtreeArray_withLibOrgBouncycastleAsn1CmsAsn1CmsContentInfo_(LibOrgBouncycastleAsn1TspArchiveTimeStamp *self, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *digestAlgorithm, IOSObjectArray *reducedHashTree, LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo *timeStamp);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1TspArchiveTimeStamp *new_LibOrgBouncycastleAsn1TspArchiveTimeStamp_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1TspPartialHashtreeArray_withLibOrgBouncycastleAsn1CmsAsn1CmsContentInfo_(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *digestAlgorithm, IOSObjectArray *reducedHashTree, LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo *timeStamp) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1TspArchiveTimeStamp *create_LibOrgBouncycastleAsn1TspArchiveTimeStamp_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1TspPartialHashtreeArray_withLibOrgBouncycastleAsn1CmsAsn1CmsContentInfo_(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *digestAlgorithm, IOSObjectArray *reducedHashTree, LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo *timeStamp);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1TspArchiveTimeStamp_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1CmsAttributes_withLibOrgBouncycastleAsn1TspPartialHashtreeArray_withLibOrgBouncycastleAsn1CmsAsn1CmsContentInfo_(LibOrgBouncycastleAsn1TspArchiveTimeStamp *self, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *digestAlgorithm, LibOrgBouncycastleAsn1CmsAttributes *attributes, IOSObjectArray *reducedHashTree, LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo *timeStamp);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1TspArchiveTimeStamp *new_LibOrgBouncycastleAsn1TspArchiveTimeStamp_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1CmsAttributes_withLibOrgBouncycastleAsn1TspPartialHashtreeArray_withLibOrgBouncycastleAsn1CmsAsn1CmsContentInfo_(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *digestAlgorithm, LibOrgBouncycastleAsn1CmsAttributes *attributes, IOSObjectArray *reducedHashTree, LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo *timeStamp) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1TspArchiveTimeStamp *create_LibOrgBouncycastleAsn1TspArchiveTimeStamp_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1CmsAttributes_withLibOrgBouncycastleAsn1TspPartialHashtreeArray_withLibOrgBouncycastleAsn1CmsAsn1CmsContentInfo_(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *digestAlgorithm, LibOrgBouncycastleAsn1CmsAttributes *attributes, IOSObjectArray *reducedHashTree, LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo *timeStamp);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1TspArchiveTimeStamp_initWithLibOrgBouncycastleAsn1CmsAsn1CmsContentInfo_(LibOrgBouncycastleAsn1TspArchiveTimeStamp *self, LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo *timeStamp);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1TspArchiveTimeStamp *new_LibOrgBouncycastleAsn1TspArchiveTimeStamp_initWithLibOrgBouncycastleAsn1CmsAsn1CmsContentInfo_(LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo *timeStamp) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1TspArchiveTimeStamp *create_LibOrgBouncycastleAsn1TspArchiveTimeStamp_initWithLibOrgBouncycastleAsn1CmsAsn1CmsContentInfo_(LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo *timeStamp);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1TspArchiveTimeStamp)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ArchiveTimeStamp_H
