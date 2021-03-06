//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/ocsp/OCSPResponseStatus.java
//

#ifndef OCSPResponseStatus_H
#define OCSPResponseStatus_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class JavaMathBigInteger;
@class LibOrgBouncycastleAsn1ASN1Primitive;

@interface LibOrgBouncycastleAsn1OcspOCSPResponseStatus : LibOrgBouncycastleAsn1ASN1Object
@property (readonly, class) jint SUCCESSFUL NS_SWIFT_NAME(SUCCESSFUL);
@property (readonly, class) jint MALFORMED_REQUEST NS_SWIFT_NAME(MALFORMED_REQUEST);
@property (readonly, class) jint INTERNAL_ERROR NS_SWIFT_NAME(INTERNAL_ERROR);
@property (readonly, class) jint TRY_LATER NS_SWIFT_NAME(TRY_LATER);
@property (readonly, class) jint SIG_REQUIRED NS_SWIFT_NAME(SIG_REQUIRED);
@property (readonly, class) jint UNAUTHORIZED NS_SWIFT_NAME(UNAUTHORIZED);

+ (jint)SUCCESSFUL;

+ (jint)MALFORMED_REQUEST;

+ (jint)INTERNAL_ERROR;

+ (jint)TRY_LATER;

+ (jint)SIG_REQUIRED;

+ (jint)UNAUTHORIZED;

#pragma mark Public

- (instancetype __nonnull)initWithInt:(jint)value;

+ (LibOrgBouncycastleAsn1OcspOCSPResponseStatus *)getInstanceWithId:(id)obj;

- (JavaMathBigInteger *)getValue;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1OcspOCSPResponseStatus)

inline jint LibOrgBouncycastleAsn1OcspOCSPResponseStatus_get_SUCCESSFUL(void);
#define LibOrgBouncycastleAsn1OcspOCSPResponseStatus_SUCCESSFUL 0
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1OcspOCSPResponseStatus, SUCCESSFUL, jint)

inline jint LibOrgBouncycastleAsn1OcspOCSPResponseStatus_get_MALFORMED_REQUEST(void);
#define LibOrgBouncycastleAsn1OcspOCSPResponseStatus_MALFORMED_REQUEST 1
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1OcspOCSPResponseStatus, MALFORMED_REQUEST, jint)

inline jint LibOrgBouncycastleAsn1OcspOCSPResponseStatus_get_INTERNAL_ERROR(void);
#define LibOrgBouncycastleAsn1OcspOCSPResponseStatus_INTERNAL_ERROR 2
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1OcspOCSPResponseStatus, INTERNAL_ERROR, jint)

inline jint LibOrgBouncycastleAsn1OcspOCSPResponseStatus_get_TRY_LATER(void);
#define LibOrgBouncycastleAsn1OcspOCSPResponseStatus_TRY_LATER 3
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1OcspOCSPResponseStatus, TRY_LATER, jint)

inline jint LibOrgBouncycastleAsn1OcspOCSPResponseStatus_get_SIG_REQUIRED(void);
#define LibOrgBouncycastleAsn1OcspOCSPResponseStatus_SIG_REQUIRED 5
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1OcspOCSPResponseStatus, SIG_REQUIRED, jint)

inline jint LibOrgBouncycastleAsn1OcspOCSPResponseStatus_get_UNAUTHORIZED(void);
#define LibOrgBouncycastleAsn1OcspOCSPResponseStatus_UNAUTHORIZED 6
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1OcspOCSPResponseStatus, UNAUTHORIZED, jint)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1OcspOCSPResponseStatus_initWithInt_(LibOrgBouncycastleAsn1OcspOCSPResponseStatus *self, jint value);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1OcspOCSPResponseStatus *new_LibOrgBouncycastleAsn1OcspOCSPResponseStatus_initWithInt_(jint value) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1OcspOCSPResponseStatus *create_LibOrgBouncycastleAsn1OcspOCSPResponseStatus_initWithInt_(jint value);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1OcspOCSPResponseStatus *LibOrgBouncycastleAsn1OcspOCSPResponseStatus_getInstanceWithId_(id obj);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1OcspOCSPResponseStatus)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // OCSPResponseStatus_H
