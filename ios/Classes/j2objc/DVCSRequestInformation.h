//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/dvcs/DVCSRequestInformation.java
//

#ifndef DVCSRequestInformation_H
#define DVCSRequestInformation_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class JavaMathBigInteger;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1ASN1TaggedObject;
@class LibOrgBouncycastleAsn1DvcsDVCSTime;
@class LibOrgBouncycastleAsn1DvcsServiceType;
@class LibOrgBouncycastleAsn1X509Extensions;
@class LibOrgBouncycastleAsn1X509GeneralNames;
@class LibOrgBouncycastleAsn1X509PolicyInformation;

@interface LibOrgBouncycastleAsn1DvcsDVCSRequestInformation : LibOrgBouncycastleAsn1ASN1Object

#pragma mark Public

- (LibOrgBouncycastleAsn1X509GeneralNames *)getDataLocations;

- (LibOrgBouncycastleAsn1X509GeneralNames *)getDVCS;

- (LibOrgBouncycastleAsn1X509Extensions *)getExtensions;

+ (LibOrgBouncycastleAsn1DvcsDVCSRequestInformation *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                                withBoolean:(jboolean)explicit_;

+ (LibOrgBouncycastleAsn1DvcsDVCSRequestInformation *)getInstanceWithId:(id)obj;

- (JavaMathBigInteger *)getNonce;

- (LibOrgBouncycastleAsn1X509GeneralNames *)getRequester;

- (LibOrgBouncycastleAsn1X509PolicyInformation *)getRequestPolicy;

- (LibOrgBouncycastleAsn1DvcsDVCSTime *)getRequestTime;

- (LibOrgBouncycastleAsn1DvcsServiceType *)getService;

- (jint)getVersion;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

- (NSString *)description;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1DvcsDVCSRequestInformation)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DvcsDVCSRequestInformation *LibOrgBouncycastleAsn1DvcsDVCSRequestInformation_getInstanceWithId_(id obj);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DvcsDVCSRequestInformation *LibOrgBouncycastleAsn1DvcsDVCSRequestInformation_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1DvcsDVCSRequestInformation)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // DVCSRequestInformation_H
