//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/CertificateStatusRequest.java
//

#ifndef CertificateStatusRequest_H
#define CertificateStatusRequest_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class JavaIoInputStream;
@class JavaIoOutputStream;
@class LibOrgBouncycastleCryptoTlsOCSPStatusRequest;

@interface LibOrgBouncycastleCryptoTlsCertificateStatusRequest : NSObject {
 @public
  jshort statusType_;
  id request_;
}

#pragma mark Public

- (instancetype __nonnull)initWithShort:(jshort)statusType
                                 withId:(id)request;

- (void)encodeWithJavaIoOutputStream:(JavaIoOutputStream *)output;

- (LibOrgBouncycastleCryptoTlsOCSPStatusRequest *)getOCSPStatusRequest;

- (id)getRequest;

- (jshort)getStatusType;

+ (LibOrgBouncycastleCryptoTlsCertificateStatusRequest *)parseWithJavaIoInputStream:(JavaIoInputStream *)input;

#pragma mark Protected

+ (jboolean)isCorrectTypeWithShort:(jshort)statusType
                            withId:(id)request;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoTlsCertificateStatusRequest)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsCertificateStatusRequest, request_, id)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoTlsCertificateStatusRequest_initWithShort_withId_(LibOrgBouncycastleCryptoTlsCertificateStatusRequest *self, jshort statusType, id request);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsCertificateStatusRequest *new_LibOrgBouncycastleCryptoTlsCertificateStatusRequest_initWithShort_withId_(jshort statusType, id request) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsCertificateStatusRequest *create_LibOrgBouncycastleCryptoTlsCertificateStatusRequest_initWithShort_withId_(jshort statusType, id request);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsCertificateStatusRequest *LibOrgBouncycastleCryptoTlsCertificateStatusRequest_parseWithJavaIoInputStream_(JavaIoInputStream *input);

FOUNDATION_EXPORT jboolean LibOrgBouncycastleCryptoTlsCertificateStatusRequest_isCorrectTypeWithShort_withId_(jshort statusType, id request);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoTlsCertificateStatusRequest)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // CertificateStatusRequest_H
