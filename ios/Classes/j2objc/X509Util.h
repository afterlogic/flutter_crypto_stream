//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/x509/X509Util.java
//

#ifndef X509Util_H
#define X509Util_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;
@class JavaSecurityProvider;
@class JavaSecuritySecureRandom;
@class JavaSecuritySignature;
@class JavaxSecurityAuthX500X500Principal;
@class LibOrgBouncycastleAsn1ASN1ObjectIdentifier;
@class LibOrgBouncycastleAsn1X509AlgorithmIdentifier;
@class LibOrgBouncycastleJceX509Principal;
@class LibOrgBouncycastleX509X509Util_Implementation;
@protocol JavaSecurityPrivateKey;
@protocol JavaUtilIterator;
@protocol LibOrgBouncycastleAsn1ASN1Encodable;

@interface LibOrgBouncycastleX509X509Util : NSObject

#pragma mark Package-Private

- (instancetype __nonnull)init;

+ (IOSByteArray *)calculateSignatureWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)sigOid
                                                                      withNSString:(NSString *)sigName
                                                        withJavaSecurityPrivateKey:(id<JavaSecurityPrivateKey>)key
                                                      withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random
                                           withLibOrgBouncycastleAsn1ASN1Encodable:(id<LibOrgBouncycastleAsn1ASN1Encodable>)object;

+ (IOSByteArray *)calculateSignatureWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)sigOid
                                                                      withNSString:(NSString *)sigName
                                                                      withNSString:(NSString *)provider
                                                        withJavaSecurityPrivateKey:(id<JavaSecurityPrivateKey>)key
                                                      withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random
                                           withLibOrgBouncycastleAsn1ASN1Encodable:(id<LibOrgBouncycastleAsn1ASN1Encodable>)object;

+ (LibOrgBouncycastleJceX509Principal *)convertPrincipalWithJavaxSecurityAuthX500X500Principal:(JavaxSecurityAuthX500X500Principal *)principal;

+ (id<JavaUtilIterator>)getAlgNames;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)getAlgorithmOIDWithNSString:(NSString *)algorithmName;

+ (LibOrgBouncycastleX509X509Util_Implementation *)getImplementationWithNSString:(NSString *)baseName
                                                                    withNSString:(NSString *)algorithm;

+ (LibOrgBouncycastleX509X509Util_Implementation *)getImplementationWithNSString:(NSString *)baseName
                                                                    withNSString:(NSString *)algorithm
                                                        withJavaSecurityProvider:(JavaSecurityProvider *)prov;

+ (JavaSecurityProvider *)getProviderWithNSString:(NSString *)provider;

+ (LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)getSigAlgIDWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)sigOid
                                                                                                withNSString:(NSString *)algorithmName;

+ (JavaSecuritySignature *)getSignatureInstanceWithNSString:(NSString *)algorithm;

+ (JavaSecuritySignature *)getSignatureInstanceWithNSString:(NSString *)algorithm
                                               withNSString:(NSString *)provider;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleX509X509Util)

FOUNDATION_EXPORT void LibOrgBouncycastleX509X509Util_init(LibOrgBouncycastleX509X509Util *self);

FOUNDATION_EXPORT LibOrgBouncycastleX509X509Util *new_LibOrgBouncycastleX509X509Util_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleX509X509Util *create_LibOrgBouncycastleX509X509Util_init(void);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleX509X509Util_getAlgorithmOIDWithNSString_(NSString *algorithmName);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509AlgorithmIdentifier *LibOrgBouncycastleX509X509Util_getSigAlgIDWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withNSString_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *sigOid, NSString *algorithmName);

FOUNDATION_EXPORT id<JavaUtilIterator> LibOrgBouncycastleX509X509Util_getAlgNames(void);

FOUNDATION_EXPORT JavaSecuritySignature *LibOrgBouncycastleX509X509Util_getSignatureInstanceWithNSString_(NSString *algorithm);

FOUNDATION_EXPORT JavaSecuritySignature *LibOrgBouncycastleX509X509Util_getSignatureInstanceWithNSString_withNSString_(NSString *algorithm, NSString *provider);

FOUNDATION_EXPORT IOSByteArray *LibOrgBouncycastleX509X509Util_calculateSignatureWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withNSString_withJavaSecurityPrivateKey_withJavaSecuritySecureRandom_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *sigOid, NSString *sigName, id<JavaSecurityPrivateKey> key, JavaSecuritySecureRandom *random, id<LibOrgBouncycastleAsn1ASN1Encodable> object);

FOUNDATION_EXPORT IOSByteArray *LibOrgBouncycastleX509X509Util_calculateSignatureWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withNSString_withNSString_withJavaSecurityPrivateKey_withJavaSecuritySecureRandom_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *sigOid, NSString *sigName, NSString *provider, id<JavaSecurityPrivateKey> key, JavaSecuritySecureRandom *random, id<LibOrgBouncycastleAsn1ASN1Encodable> object);

FOUNDATION_EXPORT LibOrgBouncycastleJceX509Principal *LibOrgBouncycastleX509X509Util_convertPrincipalWithJavaxSecurityAuthX500X500Principal_(JavaxSecurityAuthX500X500Principal *principal);

FOUNDATION_EXPORT LibOrgBouncycastleX509X509Util_Implementation *LibOrgBouncycastleX509X509Util_getImplementationWithNSString_withNSString_withJavaSecurityProvider_(NSString *baseName, NSString *algorithm, JavaSecurityProvider *prov);

FOUNDATION_EXPORT LibOrgBouncycastleX509X509Util_Implementation *LibOrgBouncycastleX509X509Util_getImplementationWithNSString_withNSString_(NSString *baseName, NSString *algorithm);

FOUNDATION_EXPORT JavaSecurityProvider *LibOrgBouncycastleX509X509Util_getProviderWithNSString_(NSString *provider);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleX509X509Util)

@interface LibOrgBouncycastleX509X509Util_Implementation : NSObject {
 @public
  id engine_;
  JavaSecurityProvider *provider_;
}

#pragma mark Package-Private

- (instancetype __nonnull)initWithId:(id)engine
            withJavaSecurityProvider:(JavaSecurityProvider *)provider;

- (id)getEngine;

- (JavaSecurityProvider *)getProvider;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleX509X509Util_Implementation)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleX509X509Util_Implementation, engine_, id)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleX509X509Util_Implementation, provider_, JavaSecurityProvider *)

FOUNDATION_EXPORT void LibOrgBouncycastleX509X509Util_Implementation_initWithId_withJavaSecurityProvider_(LibOrgBouncycastleX509X509Util_Implementation *self, id engine, JavaSecurityProvider *provider);

FOUNDATION_EXPORT LibOrgBouncycastleX509X509Util_Implementation *new_LibOrgBouncycastleX509X509Util_Implementation_initWithId_withJavaSecurityProvider_(id engine, JavaSecurityProvider *provider) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleX509X509Util_Implementation *create_LibOrgBouncycastleX509X509Util_Implementation_initWithId_withJavaSecurityProvider_(id engine, JavaSecurityProvider *provider);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleX509X509Util_Implementation)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // X509Util_H