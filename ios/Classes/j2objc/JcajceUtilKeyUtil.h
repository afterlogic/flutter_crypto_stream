//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/asymmetric/util/JcajceUtilKeyUtil.java
//

#ifndef JcajceUtilKeyUtil_H
#define JcajceUtilKeyUtil_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;
@class LibOrgBouncycastleAsn1PkcsPrivateKeyInfo;
@class LibOrgBouncycastleAsn1X509AlgorithmIdentifier;
@class LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo;
@protocol LibOrgBouncycastleAsn1ASN1Encodable;

@interface LibOrgBouncycastleJcajceProviderAsymmetricUtilJcajceUtilKeyUtil : NSObject

#pragma mark Public

- (instancetype __nonnull)init;

+ (IOSByteArray *)getEncodedPrivateKeyInfoWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier:(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)algId
                                                    withLibOrgBouncycastleAsn1ASN1Encodable:(id<LibOrgBouncycastleAsn1ASN1Encodable>)privKey;

+ (IOSByteArray *)getEncodedPrivateKeyInfoWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo:(LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *)info;

+ (IOSByteArray *)getEncodedSubjectPublicKeyInfoWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier:(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)algId
                                                          withLibOrgBouncycastleAsn1ASN1Encodable:(id<LibOrgBouncycastleAsn1ASN1Encodable>)keyData;

+ (IOSByteArray *)getEncodedSubjectPublicKeyInfoWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier:(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)algId
                                                                                    withByteArray:(IOSByteArray *)keyData;

+ (IOSByteArray *)getEncodedSubjectPublicKeyInfoWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo:(LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *)info;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricUtilJcajceUtilKeyUtil)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricUtilJcajceUtilKeyUtil_init(LibOrgBouncycastleJcajceProviderAsymmetricUtilJcajceUtilKeyUtil *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricUtilJcajceUtilKeyUtil *new_LibOrgBouncycastleJcajceProviderAsymmetricUtilJcajceUtilKeyUtil_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricUtilJcajceUtilKeyUtil *create_LibOrgBouncycastleJcajceProviderAsymmetricUtilJcajceUtilKeyUtil_init(void);

FOUNDATION_EXPORT IOSByteArray *LibOrgBouncycastleJcajceProviderAsymmetricUtilJcajceUtilKeyUtil_getEncodedSubjectPublicKeyInfoWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *algId, id<LibOrgBouncycastleAsn1ASN1Encodable> keyData);

FOUNDATION_EXPORT IOSByteArray *LibOrgBouncycastleJcajceProviderAsymmetricUtilJcajceUtilKeyUtil_getEncodedSubjectPublicKeyInfoWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *algId, IOSByteArray *keyData);

FOUNDATION_EXPORT IOSByteArray *LibOrgBouncycastleJcajceProviderAsymmetricUtilJcajceUtilKeyUtil_getEncodedSubjectPublicKeyInfoWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_(LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *info);

FOUNDATION_EXPORT IOSByteArray *LibOrgBouncycastleJcajceProviderAsymmetricUtilJcajceUtilKeyUtil_getEncodedPrivateKeyInfoWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *algId, id<LibOrgBouncycastleAsn1ASN1Encodable> privKey);

FOUNDATION_EXPORT IOSByteArray *LibOrgBouncycastleJcajceProviderAsymmetricUtilJcajceUtilKeyUtil_getEncodedPrivateKeyInfoWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo_(LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *info);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricUtilJcajceUtilKeyUtil)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // JcajceUtilKeyUtil_H