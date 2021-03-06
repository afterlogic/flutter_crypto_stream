//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jce/provider/JCERSAPrivateKey.java
//

#ifndef JCERSAPrivateKey_H
#define JCERSAPrivateKey_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "PKCS12BagAttributeCarrier.h"
#include "java/security/interfaces/RSAPrivateKey.h"

@class IOSByteArray;
@class JavaMathBigInteger;
@class JavaSecuritySpecRSAPrivateKeySpec;
@class LibOrgBouncycastleAsn1ASN1ObjectIdentifier;
@class LibOrgBouncycastleCryptoParamsRSAKeyParameters;
@protocol JavaUtilEnumeration;
@protocol LibOrgBouncycastleAsn1ASN1Encodable;

@interface LibOrgBouncycastleJceProviderJCERSAPrivateKey : NSObject < JavaSecurityInterfacesRSAPrivateKey, LibOrgBouncycastleJceInterfacesPKCS12BagAttributeCarrier > {
 @public
  JavaMathBigInteger *modulus_;
  JavaMathBigInteger *privateExponent_;
}
@property (readonly, class) jlong serialVersionUID NS_SWIFT_NAME(serialVersionUID);

+ (jlong)serialVersionUID;

#pragma mark Public

- (jboolean)isEqual:(id)o;

- (NSString *)getAlgorithm;

- (id<LibOrgBouncycastleAsn1ASN1Encodable>)getBagAttributeWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)oid;

- (id<JavaUtilEnumeration>)getBagAttributeKeys;

- (IOSByteArray *)getEncoded;

- (NSString *)getFormat;

- (JavaMathBigInteger *)getModulus;

- (JavaMathBigInteger *)getPrivateExponent;

- (NSUInteger)hash;

- (void)setBagAttributeWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)oid
                              withLibOrgBouncycastleAsn1ASN1Encodable:(id<LibOrgBouncycastleAsn1ASN1Encodable>)attribute;

#pragma mark Protected

- (instancetype __nonnull)init;

#pragma mark Package-Private

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoParamsRSAKeyParameters:(LibOrgBouncycastleCryptoParamsRSAKeyParameters *)key;

- (instancetype __nonnull)initWithJavaSecurityInterfacesRSAPrivateKey:(id<JavaSecurityInterfacesRSAPrivateKey>)key;

- (instancetype __nonnull)initWithJavaSecuritySpecRSAPrivateKeySpec:(JavaSecuritySpecRSAPrivateKeySpec *)spec;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleJceProviderJCERSAPrivateKey)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleJceProviderJCERSAPrivateKey, modulus_, JavaMathBigInteger *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJceProviderJCERSAPrivateKey, privateExponent_, JavaMathBigInteger *)

inline jlong LibOrgBouncycastleJceProviderJCERSAPrivateKey_get_serialVersionUID(void);
#define LibOrgBouncycastleJceProviderJCERSAPrivateKey_serialVersionUID 5110188922551353628LL
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleJceProviderJCERSAPrivateKey, serialVersionUID, jlong)

FOUNDATION_EXPORT void LibOrgBouncycastleJceProviderJCERSAPrivateKey_init(LibOrgBouncycastleJceProviderJCERSAPrivateKey *self);

FOUNDATION_EXPORT LibOrgBouncycastleJceProviderJCERSAPrivateKey *new_LibOrgBouncycastleJceProviderJCERSAPrivateKey_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJceProviderJCERSAPrivateKey *create_LibOrgBouncycastleJceProviderJCERSAPrivateKey_init(void);

FOUNDATION_EXPORT void LibOrgBouncycastleJceProviderJCERSAPrivateKey_initWithLibOrgBouncycastleCryptoParamsRSAKeyParameters_(LibOrgBouncycastleJceProviderJCERSAPrivateKey *self, LibOrgBouncycastleCryptoParamsRSAKeyParameters *key);

FOUNDATION_EXPORT LibOrgBouncycastleJceProviderJCERSAPrivateKey *new_LibOrgBouncycastleJceProviderJCERSAPrivateKey_initWithLibOrgBouncycastleCryptoParamsRSAKeyParameters_(LibOrgBouncycastleCryptoParamsRSAKeyParameters *key) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJceProviderJCERSAPrivateKey *create_LibOrgBouncycastleJceProviderJCERSAPrivateKey_initWithLibOrgBouncycastleCryptoParamsRSAKeyParameters_(LibOrgBouncycastleCryptoParamsRSAKeyParameters *key);

FOUNDATION_EXPORT void LibOrgBouncycastleJceProviderJCERSAPrivateKey_initWithJavaSecuritySpecRSAPrivateKeySpec_(LibOrgBouncycastleJceProviderJCERSAPrivateKey *self, JavaSecuritySpecRSAPrivateKeySpec *spec);

FOUNDATION_EXPORT LibOrgBouncycastleJceProviderJCERSAPrivateKey *new_LibOrgBouncycastleJceProviderJCERSAPrivateKey_initWithJavaSecuritySpecRSAPrivateKeySpec_(JavaSecuritySpecRSAPrivateKeySpec *spec) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJceProviderJCERSAPrivateKey *create_LibOrgBouncycastleJceProviderJCERSAPrivateKey_initWithJavaSecuritySpecRSAPrivateKeySpec_(JavaSecuritySpecRSAPrivateKeySpec *spec);

FOUNDATION_EXPORT void LibOrgBouncycastleJceProviderJCERSAPrivateKey_initWithJavaSecurityInterfacesRSAPrivateKey_(LibOrgBouncycastleJceProviderJCERSAPrivateKey *self, id<JavaSecurityInterfacesRSAPrivateKey> key);

FOUNDATION_EXPORT LibOrgBouncycastleJceProviderJCERSAPrivateKey *new_LibOrgBouncycastleJceProviderJCERSAPrivateKey_initWithJavaSecurityInterfacesRSAPrivateKey_(id<JavaSecurityInterfacesRSAPrivateKey> key) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJceProviderJCERSAPrivateKey *create_LibOrgBouncycastleJceProviderJCERSAPrivateKey_initWithJavaSecurityInterfacesRSAPrivateKey_(id<JavaSecurityInterfacesRSAPrivateKey> key);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJceProviderJCERSAPrivateKey)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // JCERSAPrivateKey_H
