//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/tsp/EvidenceRecord.java
//

#ifndef EvidenceRecord_H
#define EvidenceRecord_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class IOSObjectArray;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1TspArchiveTimeStamp;
@class LibOrgBouncycastleAsn1TspArchiveTimeStampSequence;
@class LibOrgBouncycastleAsn1TspCryptoInfos;
@class LibOrgBouncycastleAsn1TspEncryptionInfo;

@interface LibOrgBouncycastleAsn1TspEvidenceRecord : LibOrgBouncycastleAsn1ASN1Object

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifierArray:(IOSObjectArray *)digestAlgorithms
                                            withLibOrgBouncycastleAsn1TspCryptoInfos:(LibOrgBouncycastleAsn1TspCryptoInfos *)cryptoInfos
                                         withLibOrgBouncycastleAsn1TspEncryptionInfo:(LibOrgBouncycastleAsn1TspEncryptionInfo *)encryptionInfo
                               withLibOrgBouncycastleAsn1TspArchiveTimeStampSequence:(LibOrgBouncycastleAsn1TspArchiveTimeStampSequence *)archiveTimeStampSequence;

- (LibOrgBouncycastleAsn1TspEvidenceRecord *)addArchiveTimeStampWithLibOrgBouncycastleAsn1TspArchiveTimeStamp:(LibOrgBouncycastleAsn1TspArchiveTimeStamp *)ats
                                                                                                  withBoolean:(jboolean)newChain;

- (LibOrgBouncycastleAsn1TspArchiveTimeStampSequence *)getArchiveTimeStampSequence;

- (IOSObjectArray *)getDigestAlgorithms;

+ (LibOrgBouncycastleAsn1TspEvidenceRecord *)getInstanceWithId:(id)obj;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

- (NSString *)description;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleAsn1TspEvidenceRecord)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1TspEvidenceRecord *LibOrgBouncycastleAsn1TspEvidenceRecord_getInstanceWithId_(id obj);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1TspEvidenceRecord_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifierArray_withLibOrgBouncycastleAsn1TspCryptoInfos_withLibOrgBouncycastleAsn1TspEncryptionInfo_withLibOrgBouncycastleAsn1TspArchiveTimeStampSequence_(LibOrgBouncycastleAsn1TspEvidenceRecord *self, IOSObjectArray *digestAlgorithms, LibOrgBouncycastleAsn1TspCryptoInfos *cryptoInfos, LibOrgBouncycastleAsn1TspEncryptionInfo *encryptionInfo, LibOrgBouncycastleAsn1TspArchiveTimeStampSequence *archiveTimeStampSequence);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1TspEvidenceRecord *new_LibOrgBouncycastleAsn1TspEvidenceRecord_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifierArray_withLibOrgBouncycastleAsn1TspCryptoInfos_withLibOrgBouncycastleAsn1TspEncryptionInfo_withLibOrgBouncycastleAsn1TspArchiveTimeStampSequence_(IOSObjectArray *digestAlgorithms, LibOrgBouncycastleAsn1TspCryptoInfos *cryptoInfos, LibOrgBouncycastleAsn1TspEncryptionInfo *encryptionInfo, LibOrgBouncycastleAsn1TspArchiveTimeStampSequence *archiveTimeStampSequence) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1TspEvidenceRecord *create_LibOrgBouncycastleAsn1TspEvidenceRecord_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifierArray_withLibOrgBouncycastleAsn1TspCryptoInfos_withLibOrgBouncycastleAsn1TspEncryptionInfo_withLibOrgBouncycastleAsn1TspArchiveTimeStampSequence_(IOSObjectArray *digestAlgorithms, LibOrgBouncycastleAsn1TspCryptoInfos *cryptoInfos, LibOrgBouncycastleAsn1TspEncryptionInfo *encryptionInfo, LibOrgBouncycastleAsn1TspArchiveTimeStampSequence *archiveTimeStampSequence);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1TspEvidenceRecord)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // EvidenceRecord_H
