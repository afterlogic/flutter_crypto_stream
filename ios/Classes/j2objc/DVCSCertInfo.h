//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/dvcs/DVCSCertInfo.java
//

#ifndef DVCSCertInfo_H
#define DVCSCertInfo_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class IOSObjectArray;
@class LibOrgBouncycastleAsn1ASN1Integer;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1ASN1Set;
@class LibOrgBouncycastleAsn1ASN1TaggedObject;
@class LibOrgBouncycastleAsn1CmpPKIStatusInfo;
@class LibOrgBouncycastleAsn1DvcsDVCSRequestInformation;
@class LibOrgBouncycastleAsn1DvcsDVCSTime;
@class LibOrgBouncycastleAsn1X509DigestInfo;
@class LibOrgBouncycastleAsn1X509Extensions;
@class LibOrgBouncycastleAsn1X509PolicyInformation;

@interface LibOrgBouncycastleAsn1DvcsDVCSCertInfo : LibOrgBouncycastleAsn1ASN1Object

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1DvcsDVCSRequestInformation:(LibOrgBouncycastleAsn1DvcsDVCSRequestInformation *)dvReqInfo
                                          withLibOrgBouncycastleAsn1X509DigestInfo:(LibOrgBouncycastleAsn1X509DigestInfo *)messageImprint
                                             withLibOrgBouncycastleAsn1ASN1Integer:(LibOrgBouncycastleAsn1ASN1Integer *)serialNumber
                                            withLibOrgBouncycastleAsn1DvcsDVCSTime:(LibOrgBouncycastleAsn1DvcsDVCSTime *)responseTime;

- (IOSObjectArray *)getCerts;

- (LibOrgBouncycastleAsn1DvcsDVCSRequestInformation *)getDvReqInfo;

- (LibOrgBouncycastleAsn1CmpPKIStatusInfo *)getDvStatus;

- (LibOrgBouncycastleAsn1X509Extensions *)getExtensions;

+ (LibOrgBouncycastleAsn1DvcsDVCSCertInfo *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                      withBoolean:(jboolean)explicit_;

+ (LibOrgBouncycastleAsn1DvcsDVCSCertInfo *)getInstanceWithId:(id)obj;

- (LibOrgBouncycastleAsn1X509DigestInfo *)getMessageImprint;

- (LibOrgBouncycastleAsn1X509PolicyInformation *)getPolicy;

- (LibOrgBouncycastleAsn1ASN1Set *)getReqSignature;

- (LibOrgBouncycastleAsn1DvcsDVCSTime *)getResponseTime;

- (LibOrgBouncycastleAsn1ASN1Integer *)getSerialNumber;

- (jint)getVersion;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

- (NSString *)description;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1DvcsDVCSCertInfo)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1DvcsDVCSCertInfo_initWithLibOrgBouncycastleAsn1DvcsDVCSRequestInformation_withLibOrgBouncycastleAsn1X509DigestInfo_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1DvcsDVCSTime_(LibOrgBouncycastleAsn1DvcsDVCSCertInfo *self, LibOrgBouncycastleAsn1DvcsDVCSRequestInformation *dvReqInfo, LibOrgBouncycastleAsn1X509DigestInfo *messageImprint, LibOrgBouncycastleAsn1ASN1Integer *serialNumber, LibOrgBouncycastleAsn1DvcsDVCSTime *responseTime);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DvcsDVCSCertInfo *new_LibOrgBouncycastleAsn1DvcsDVCSCertInfo_initWithLibOrgBouncycastleAsn1DvcsDVCSRequestInformation_withLibOrgBouncycastleAsn1X509DigestInfo_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1DvcsDVCSTime_(LibOrgBouncycastleAsn1DvcsDVCSRequestInformation *dvReqInfo, LibOrgBouncycastleAsn1X509DigestInfo *messageImprint, LibOrgBouncycastleAsn1ASN1Integer *serialNumber, LibOrgBouncycastleAsn1DvcsDVCSTime *responseTime) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DvcsDVCSCertInfo *create_LibOrgBouncycastleAsn1DvcsDVCSCertInfo_initWithLibOrgBouncycastleAsn1DvcsDVCSRequestInformation_withLibOrgBouncycastleAsn1X509DigestInfo_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1DvcsDVCSTime_(LibOrgBouncycastleAsn1DvcsDVCSRequestInformation *dvReqInfo, LibOrgBouncycastleAsn1X509DigestInfo *messageImprint, LibOrgBouncycastleAsn1ASN1Integer *serialNumber, LibOrgBouncycastleAsn1DvcsDVCSTime *responseTime);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DvcsDVCSCertInfo *LibOrgBouncycastleAsn1DvcsDVCSCertInfo_getInstanceWithId_(id obj);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DvcsDVCSCertInfo *LibOrgBouncycastleAsn1DvcsDVCSCertInfo_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1DvcsDVCSCertInfo)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // DVCSCertInfo_H
