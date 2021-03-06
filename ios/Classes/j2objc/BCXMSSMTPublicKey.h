//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/jcajce/provider/xmss/BCXMSSMTPublicKey.java
//

#ifndef BCXMSSMTPublicKey_H
#define BCXMSSMTPublicKey_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "XMSSMTKey.h"
#include "java/security/PublicKey.h"

@class IOSByteArray;
@class LibOrgBouncycastleAsn1ASN1ObjectIdentifier;
@class LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo;
@class LibOrgBouncycastlePqcCryptoXmssXMSSMTPublicKeyParameters;
@protocol LibOrgBouncycastleCryptoCipherParameters;

@interface LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSMTPublicKey : NSObject < JavaSecurityPublicKey, LibOrgBouncycastlePqcJcajceInterfacesXMSSMTKey >

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)treeDigest
                withLibOrgBouncycastlePqcCryptoXmssXMSSMTPublicKeyParameters:(LibOrgBouncycastlePqcCryptoXmssXMSSMTPublicKeyParameters *)keyParams;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo:(LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *)keyInfo;

- (jboolean)isEqual:(id)o;

- (NSString *)getAlgorithm;

- (IOSByteArray *)getEncoded;

- (NSString *)getFormat;

- (jint)getHeight;

- (jint)getLayers;

- (NSString *)getTreeDigest;

- (NSUInteger)hash;

#pragma mark Package-Private

- (id<LibOrgBouncycastleCryptoCipherParameters>)getKeyParams;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSMTPublicKey)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSMTPublicKey_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastlePqcCryptoXmssXMSSMTPublicKeyParameters_(LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSMTPublicKey *self, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *treeDigest, LibOrgBouncycastlePqcCryptoXmssXMSSMTPublicKeyParameters *keyParams);

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSMTPublicKey *new_LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSMTPublicKey_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastlePqcCryptoXmssXMSSMTPublicKeyParameters_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *treeDigest, LibOrgBouncycastlePqcCryptoXmssXMSSMTPublicKeyParameters *keyParams) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSMTPublicKey *create_LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSMTPublicKey_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastlePqcCryptoXmssXMSSMTPublicKeyParameters_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *treeDigest, LibOrgBouncycastlePqcCryptoXmssXMSSMTPublicKeyParameters *keyParams);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSMTPublicKey_initWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_(LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSMTPublicKey *self, LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *keyInfo);

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSMTPublicKey *new_LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSMTPublicKey_initWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_(LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *keyInfo) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSMTPublicKey *create_LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSMTPublicKey_initWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_(LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *keyInfo);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcJcajceProviderXmssBCXMSSMTPublicKey)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // BCXMSSMTPublicKey_H
