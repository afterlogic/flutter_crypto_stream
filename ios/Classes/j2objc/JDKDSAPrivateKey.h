//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jce/provider/JDKDSAPrivateKey.java
//

#ifndef JDKDSAPrivateKey_H
#define JDKDSAPrivateKey_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "PKCS12BagAttributeCarrier.h"
#include "java/security/interfaces/DSAPrivateKey.h"

@class IOSByteArray;
@class JavaMathBigInteger;
@class JavaSecuritySpecDSAPrivateKeySpec;
@class LibOrgBouncycastleAsn1ASN1ObjectIdentifier;
@class LibOrgBouncycastleAsn1PkcsPrivateKeyInfo;
@class LibOrgBouncycastleCryptoParamsDSAPrivateKeyParameters;
@protocol JavaSecurityInterfacesDSAParams;
@protocol JavaUtilEnumeration;
@protocol LibOrgBouncycastleAsn1ASN1Encodable;

@interface LibOrgBouncycastleJceProviderJDKDSAPrivateKey : NSObject < JavaSecurityInterfacesDSAPrivateKey, LibOrgBouncycastleJceInterfacesPKCS12BagAttributeCarrier > {
 @public
  JavaMathBigInteger *x_;
  id<JavaSecurityInterfacesDSAParams> dsaSpec_;
}

#pragma mark Public

- (jboolean)isEqual:(id)o;

- (NSString *)getAlgorithm;

- (id<LibOrgBouncycastleAsn1ASN1Encodable>)getBagAttributeWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)oid;

- (id<JavaUtilEnumeration>)getBagAttributeKeys;

- (IOSByteArray *)getEncoded;

- (NSString *)getFormat;

- (id<JavaSecurityInterfacesDSAParams>)getParams;

- (JavaMathBigInteger *)getX;

- (NSUInteger)hash;

- (void)setBagAttributeWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)oid
                              withLibOrgBouncycastleAsn1ASN1Encodable:(id<LibOrgBouncycastleAsn1ASN1Encodable>)attribute;

#pragma mark Protected

- (instancetype __nonnull)init;

#pragma mark Package-Private

- (instancetype __nonnull)initWithJavaSecurityInterfacesDSAPrivateKey:(id<JavaSecurityInterfacesDSAPrivateKey>)key;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoParamsDSAPrivateKeyParameters:(LibOrgBouncycastleCryptoParamsDSAPrivateKeyParameters *)params;

- (instancetype __nonnull)initWithJavaSecuritySpecDSAPrivateKeySpec:(JavaSecuritySpecDSAPrivateKeySpec *)spec;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo:(LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *)info;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJceProviderJDKDSAPrivateKey)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleJceProviderJDKDSAPrivateKey, x_, JavaMathBigInteger *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJceProviderJDKDSAPrivateKey, dsaSpec_, id<JavaSecurityInterfacesDSAParams>)

FOUNDATION_EXPORT void LibOrgBouncycastleJceProviderJDKDSAPrivateKey_init(LibOrgBouncycastleJceProviderJDKDSAPrivateKey *self);

FOUNDATION_EXPORT LibOrgBouncycastleJceProviderJDKDSAPrivateKey *new_LibOrgBouncycastleJceProviderJDKDSAPrivateKey_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJceProviderJDKDSAPrivateKey *create_LibOrgBouncycastleJceProviderJDKDSAPrivateKey_init(void);

FOUNDATION_EXPORT void LibOrgBouncycastleJceProviderJDKDSAPrivateKey_initWithJavaSecurityInterfacesDSAPrivateKey_(LibOrgBouncycastleJceProviderJDKDSAPrivateKey *self, id<JavaSecurityInterfacesDSAPrivateKey> key);

FOUNDATION_EXPORT LibOrgBouncycastleJceProviderJDKDSAPrivateKey *new_LibOrgBouncycastleJceProviderJDKDSAPrivateKey_initWithJavaSecurityInterfacesDSAPrivateKey_(id<JavaSecurityInterfacesDSAPrivateKey> key) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJceProviderJDKDSAPrivateKey *create_LibOrgBouncycastleJceProviderJDKDSAPrivateKey_initWithJavaSecurityInterfacesDSAPrivateKey_(id<JavaSecurityInterfacesDSAPrivateKey> key);

FOUNDATION_EXPORT void LibOrgBouncycastleJceProviderJDKDSAPrivateKey_initWithJavaSecuritySpecDSAPrivateKeySpec_(LibOrgBouncycastleJceProviderJDKDSAPrivateKey *self, JavaSecuritySpecDSAPrivateKeySpec *spec);

FOUNDATION_EXPORT LibOrgBouncycastleJceProviderJDKDSAPrivateKey *new_LibOrgBouncycastleJceProviderJDKDSAPrivateKey_initWithJavaSecuritySpecDSAPrivateKeySpec_(JavaSecuritySpecDSAPrivateKeySpec *spec) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJceProviderJDKDSAPrivateKey *create_LibOrgBouncycastleJceProviderJDKDSAPrivateKey_initWithJavaSecuritySpecDSAPrivateKeySpec_(JavaSecuritySpecDSAPrivateKeySpec *spec);

FOUNDATION_EXPORT void LibOrgBouncycastleJceProviderJDKDSAPrivateKey_initWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo_(LibOrgBouncycastleJceProviderJDKDSAPrivateKey *self, LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *info);

FOUNDATION_EXPORT LibOrgBouncycastleJceProviderJDKDSAPrivateKey *new_LibOrgBouncycastleJceProviderJDKDSAPrivateKey_initWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo_(LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *info) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJceProviderJDKDSAPrivateKey *create_LibOrgBouncycastleJceProviderJDKDSAPrivateKey_initWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo_(LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *info);

FOUNDATION_EXPORT void LibOrgBouncycastleJceProviderJDKDSAPrivateKey_initWithLibOrgBouncycastleCryptoParamsDSAPrivateKeyParameters_(LibOrgBouncycastleJceProviderJDKDSAPrivateKey *self, LibOrgBouncycastleCryptoParamsDSAPrivateKeyParameters *params);

FOUNDATION_EXPORT LibOrgBouncycastleJceProviderJDKDSAPrivateKey *new_LibOrgBouncycastleJceProviderJDKDSAPrivateKey_initWithLibOrgBouncycastleCryptoParamsDSAPrivateKeyParameters_(LibOrgBouncycastleCryptoParamsDSAPrivateKeyParameters *params) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJceProviderJDKDSAPrivateKey *create_LibOrgBouncycastleJceProviderJDKDSAPrivateKey_initWithLibOrgBouncycastleCryptoParamsDSAPrivateKeyParameters_(LibOrgBouncycastleCryptoParamsDSAPrivateKeyParameters *params);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJceProviderJDKDSAPrivateKey)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // JDKDSAPrivateKey_H
