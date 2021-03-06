//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jce/netscape/NetscapeCertRequest.java
//

#ifndef NetscapeCertRequest_H
#define NetscapeCertRequest_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@class JavaSecuritySecureRandom;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1ASN1Sequence;
@class LibOrgBouncycastleAsn1DERBitString;
@class LibOrgBouncycastleAsn1X509AlgorithmIdentifier;
@protocol JavaSecurityPrivateKey;
@protocol JavaSecurityPublicKey;

@interface LibOrgBouncycastleJceNetscapeNetscapeCertRequest : LibOrgBouncycastleAsn1ASN1Object {
 @public
  LibOrgBouncycastleAsn1X509AlgorithmIdentifier *sigAlg_;
  LibOrgBouncycastleAsn1X509AlgorithmIdentifier *keyAlg_;
  IOSByteArray *sigBits_;
  NSString *challenge_;
  LibOrgBouncycastleAsn1DERBitString *content_;
  id<JavaSecurityPublicKey> pubkey_;
}

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)spkac;

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)req;

- (instancetype __nonnull)initWithNSString:(NSString *)challenge
withLibOrgBouncycastleAsn1X509AlgorithmIdentifier:(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)signing_alg
                 withJavaSecurityPublicKey:(id<JavaSecurityPublicKey>)pub_key;

- (NSString *)getChallenge;

- (LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)getKeyAlgorithm;

- (id<JavaSecurityPublicKey>)getPublicKey;

- (LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)getSigningAlgorithm;

- (void)setChallengeWithNSString:(NSString *)value;

- (void)setKeyAlgorithmWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier:(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)value;

- (void)setPublicKeyWithJavaSecurityPublicKey:(id<JavaSecurityPublicKey>)value;

- (void)setSigningAlgorithmWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier:(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)value;

- (void)signWithJavaSecurityPrivateKey:(id<JavaSecurityPrivateKey>)priv_key;

- (void)signWithJavaSecurityPrivateKey:(id<JavaSecurityPrivateKey>)priv_key
          withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)rand;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

- (jboolean)verifyWithNSString:(NSString *)challenge;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJceNetscapeNetscapeCertRequest)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleJceNetscapeNetscapeCertRequest, sigAlg_, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJceNetscapeNetscapeCertRequest, keyAlg_, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJceNetscapeNetscapeCertRequest, sigBits_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJceNetscapeNetscapeCertRequest, challenge_, NSString *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJceNetscapeNetscapeCertRequest, content_, LibOrgBouncycastleAsn1DERBitString *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJceNetscapeNetscapeCertRequest, pubkey_, id<JavaSecurityPublicKey>)

FOUNDATION_EXPORT void LibOrgBouncycastleJceNetscapeNetscapeCertRequest_initWithByteArray_(LibOrgBouncycastleJceNetscapeNetscapeCertRequest *self, IOSByteArray *req);

FOUNDATION_EXPORT LibOrgBouncycastleJceNetscapeNetscapeCertRequest *new_LibOrgBouncycastleJceNetscapeNetscapeCertRequest_initWithByteArray_(IOSByteArray *req) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJceNetscapeNetscapeCertRequest *create_LibOrgBouncycastleJceNetscapeNetscapeCertRequest_initWithByteArray_(IOSByteArray *req);

FOUNDATION_EXPORT void LibOrgBouncycastleJceNetscapeNetscapeCertRequest_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleJceNetscapeNetscapeCertRequest *self, LibOrgBouncycastleAsn1ASN1Sequence *spkac);

FOUNDATION_EXPORT LibOrgBouncycastleJceNetscapeNetscapeCertRequest *new_LibOrgBouncycastleJceNetscapeNetscapeCertRequest_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *spkac) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJceNetscapeNetscapeCertRequest *create_LibOrgBouncycastleJceNetscapeNetscapeCertRequest_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *spkac);

FOUNDATION_EXPORT void LibOrgBouncycastleJceNetscapeNetscapeCertRequest_initWithNSString_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withJavaSecurityPublicKey_(LibOrgBouncycastleJceNetscapeNetscapeCertRequest *self, NSString *challenge, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *signing_alg, id<JavaSecurityPublicKey> pub_key);

FOUNDATION_EXPORT LibOrgBouncycastleJceNetscapeNetscapeCertRequest *new_LibOrgBouncycastleJceNetscapeNetscapeCertRequest_initWithNSString_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withJavaSecurityPublicKey_(NSString *challenge, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *signing_alg, id<JavaSecurityPublicKey> pub_key) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJceNetscapeNetscapeCertRequest *create_LibOrgBouncycastleJceNetscapeNetscapeCertRequest_initWithNSString_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withJavaSecurityPublicKey_(NSString *challenge, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *signing_alg, id<JavaSecurityPublicKey> pub_key);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJceNetscapeNetscapeCertRequest)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // NetscapeCertRequest_H
