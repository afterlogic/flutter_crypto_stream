//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/jcajce/provider/mceliece/McElieceKeyFactorySpi.java
//

#ifndef McElieceKeyFactorySpi_H
#define McElieceKeyFactorySpi_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "AsymmetricKeyInfoConverter.h"
#include "J2ObjC_header.h"
#include "java/security/KeyFactorySpi.h"

@class IOSClass;
@class LibOrgBouncycastleAsn1PkcsPrivateKeyInfo;
@class LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo;
@protocol JavaSecurityKey;
@protocol JavaSecurityPrivateKey;
@protocol JavaSecurityPublicKey;
@protocol JavaSecuritySpecKeySpec;

@interface LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceKeyFactorySpi : JavaSecurityKeyFactorySpi < LibOrgBouncycastleJcajceProviderUtilAsymmetricKeyInfoConverter >
@property (readonly, copy, class) NSString *OID NS_SWIFT_NAME(OID);

+ (NSString *)OID;

#pragma mark Public

- (instancetype __nonnull)init;

- (id<JavaSecurityPrivateKey>)generatePrivateWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo:(LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *)pki;

- (id<JavaSecurityPublicKey>)generatePublicWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo:(LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *)pki;

- (id<JavaSecuritySpecKeySpec>)getKeySpecWithJavaSecurityKey:(id<JavaSecurityKey>)key
                                                withIOSClass:(IOSClass *)keySpec;

- (id<JavaSecurityKey>)translateKeyWithJavaSecurityKey:(id<JavaSecurityKey>)key;

#pragma mark Protected

- (id<JavaSecurityPrivateKey>)engineGeneratePrivateWithJavaSecuritySpecKeySpec:(id<JavaSecuritySpecKeySpec>)keySpec;

- (id<JavaSecurityPublicKey>)engineGeneratePublicWithJavaSecuritySpecKeySpec:(id<JavaSecuritySpecKeySpec>)keySpec;

- (id<JavaSecuritySpecKeySpec>)engineGetKeySpecWithJavaSecurityKey:(id<JavaSecurityKey>)key
                                                      withIOSClass:(IOSClass *)tClass;

- (id<JavaSecurityKey>)engineTranslateKeyWithJavaSecurityKey:(id<JavaSecurityKey>)key;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceKeyFactorySpi)

inline NSString *LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceKeyFactorySpi_get_OID(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT NSString *LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceKeyFactorySpi_OID;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceKeyFactorySpi, OID, NSString *)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceKeyFactorySpi_init(LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceKeyFactorySpi *self);

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceKeyFactorySpi *new_LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceKeyFactorySpi_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceKeyFactorySpi *create_LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceKeyFactorySpi_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceKeyFactorySpi)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // McElieceKeyFactorySpi_H
