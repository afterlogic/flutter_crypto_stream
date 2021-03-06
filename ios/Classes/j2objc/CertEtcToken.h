//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/dvcs/CertEtcToken.java
//

#ifndef CertEtcToken_H
#define CertEtcToken_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Choice.h"
#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class IOSObjectArray;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1ASN1Sequence;
@class LibOrgBouncycastleAsn1X509Extension;
@protocol LibOrgBouncycastleAsn1ASN1Encodable;

@interface LibOrgBouncycastleAsn1DvcsCertEtcToken : LibOrgBouncycastleAsn1ASN1Object < LibOrgBouncycastleAsn1ASN1Choice >
@property (readonly, class) jint TAG_CERTIFICATE NS_SWIFT_NAME(TAG_CERTIFICATE);
@property (readonly, class) jint TAG_ESSCERTID NS_SWIFT_NAME(TAG_ESSCERTID);
@property (readonly, class) jint TAG_PKISTATUS NS_SWIFT_NAME(TAG_PKISTATUS);
@property (readonly, class) jint TAG_ASSERTION NS_SWIFT_NAME(TAG_ASSERTION);
@property (readonly, class) jint TAG_CRL NS_SWIFT_NAME(TAG_CRL);
@property (readonly, class) jint TAG_OCSPCERTSTATUS NS_SWIFT_NAME(TAG_OCSPCERTSTATUS);
@property (readonly, class) jint TAG_OCSPCERTID NS_SWIFT_NAME(TAG_OCSPCERTID);
@property (readonly, class) jint TAG_OCSPRESPONSE NS_SWIFT_NAME(TAG_OCSPRESPONSE);
@property (readonly, class) jint TAG_CAPABILITIES NS_SWIFT_NAME(TAG_CAPABILITIES);

+ (jint)TAG_CERTIFICATE;

+ (jint)TAG_ESSCERTID;

+ (jint)TAG_PKISTATUS;

+ (jint)TAG_ASSERTION;

+ (jint)TAG_CRL;

+ (jint)TAG_OCSPCERTSTATUS;

+ (jint)TAG_OCSPCERTID;

+ (jint)TAG_OCSPRESPONSE;

+ (jint)TAG_CAPABILITIES;

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1X509Extension:(LibOrgBouncycastleAsn1X509Extension *)extension;

- (instancetype __nonnull)initWithInt:(jint)tagNo
withLibOrgBouncycastleAsn1ASN1Encodable:(id<LibOrgBouncycastleAsn1ASN1Encodable>)value;

+ (IOSObjectArray *)arrayFromSequenceWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

- (LibOrgBouncycastleAsn1X509Extension *)getExtension;

+ (LibOrgBouncycastleAsn1DvcsCertEtcToken *)getInstanceWithId:(id)obj;

- (jint)getTagNo;

- (id<LibOrgBouncycastleAsn1ASN1Encodable>)getValue;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

- (NSString *)description;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleAsn1DvcsCertEtcToken)

inline jint LibOrgBouncycastleAsn1DvcsCertEtcToken_get_TAG_CERTIFICATE(void);
#define LibOrgBouncycastleAsn1DvcsCertEtcToken_TAG_CERTIFICATE 0
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1DvcsCertEtcToken, TAG_CERTIFICATE, jint)

inline jint LibOrgBouncycastleAsn1DvcsCertEtcToken_get_TAG_ESSCERTID(void);
#define LibOrgBouncycastleAsn1DvcsCertEtcToken_TAG_ESSCERTID 1
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1DvcsCertEtcToken, TAG_ESSCERTID, jint)

inline jint LibOrgBouncycastleAsn1DvcsCertEtcToken_get_TAG_PKISTATUS(void);
#define LibOrgBouncycastleAsn1DvcsCertEtcToken_TAG_PKISTATUS 2
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1DvcsCertEtcToken, TAG_PKISTATUS, jint)

inline jint LibOrgBouncycastleAsn1DvcsCertEtcToken_get_TAG_ASSERTION(void);
#define LibOrgBouncycastleAsn1DvcsCertEtcToken_TAG_ASSERTION 3
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1DvcsCertEtcToken, TAG_ASSERTION, jint)

inline jint LibOrgBouncycastleAsn1DvcsCertEtcToken_get_TAG_CRL(void);
#define LibOrgBouncycastleAsn1DvcsCertEtcToken_TAG_CRL 4
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1DvcsCertEtcToken, TAG_CRL, jint)

inline jint LibOrgBouncycastleAsn1DvcsCertEtcToken_get_TAG_OCSPCERTSTATUS(void);
#define LibOrgBouncycastleAsn1DvcsCertEtcToken_TAG_OCSPCERTSTATUS 5
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1DvcsCertEtcToken, TAG_OCSPCERTSTATUS, jint)

inline jint LibOrgBouncycastleAsn1DvcsCertEtcToken_get_TAG_OCSPCERTID(void);
#define LibOrgBouncycastleAsn1DvcsCertEtcToken_TAG_OCSPCERTID 6
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1DvcsCertEtcToken, TAG_OCSPCERTID, jint)

inline jint LibOrgBouncycastleAsn1DvcsCertEtcToken_get_TAG_OCSPRESPONSE(void);
#define LibOrgBouncycastleAsn1DvcsCertEtcToken_TAG_OCSPRESPONSE 7
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1DvcsCertEtcToken, TAG_OCSPRESPONSE, jint)

inline jint LibOrgBouncycastleAsn1DvcsCertEtcToken_get_TAG_CAPABILITIES(void);
#define LibOrgBouncycastleAsn1DvcsCertEtcToken_TAG_CAPABILITIES 8
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1DvcsCertEtcToken, TAG_CAPABILITIES, jint)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1DvcsCertEtcToken_initWithInt_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1DvcsCertEtcToken *self, jint tagNo, id<LibOrgBouncycastleAsn1ASN1Encodable> value);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DvcsCertEtcToken *new_LibOrgBouncycastleAsn1DvcsCertEtcToken_initWithInt_withLibOrgBouncycastleAsn1ASN1Encodable_(jint tagNo, id<LibOrgBouncycastleAsn1ASN1Encodable> value) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DvcsCertEtcToken *create_LibOrgBouncycastleAsn1DvcsCertEtcToken_initWithInt_withLibOrgBouncycastleAsn1ASN1Encodable_(jint tagNo, id<LibOrgBouncycastleAsn1ASN1Encodable> value);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1DvcsCertEtcToken_initWithLibOrgBouncycastleAsn1X509Extension_(LibOrgBouncycastleAsn1DvcsCertEtcToken *self, LibOrgBouncycastleAsn1X509Extension *extension);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DvcsCertEtcToken *new_LibOrgBouncycastleAsn1DvcsCertEtcToken_initWithLibOrgBouncycastleAsn1X509Extension_(LibOrgBouncycastleAsn1X509Extension *extension) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DvcsCertEtcToken *create_LibOrgBouncycastleAsn1DvcsCertEtcToken_initWithLibOrgBouncycastleAsn1X509Extension_(LibOrgBouncycastleAsn1X509Extension *extension);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DvcsCertEtcToken *LibOrgBouncycastleAsn1DvcsCertEtcToken_getInstanceWithId_(id obj);

FOUNDATION_EXPORT IOSObjectArray *LibOrgBouncycastleAsn1DvcsCertEtcToken_arrayFromSequenceWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1DvcsCertEtcToken)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // CertEtcToken_H
