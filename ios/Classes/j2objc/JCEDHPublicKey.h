//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jce/provider/JCEDHPublicKey.java
//

#ifndef JCEDHPublicKey_H
#define JCEDHPublicKey_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "javax/crypto/interfaces/DHPublicKey.h"

@class IOSByteArray;
@class JavaMathBigInteger;
@class JavaxCryptoSpecDHParameterSpec;
@class JavaxCryptoSpecDHPublicKeySpec;
@class LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo;
@class LibOrgBouncycastleCryptoParamsDHPublicKeyParameters;

@interface LibOrgBouncycastleJceProviderJCEDHPublicKey : NSObject < JavaxCryptoInterfacesDHPublicKey >
@property (readonly, class) jlong serialVersionUID NS_SWIFT_NAME(serialVersionUID);

+ (jlong)serialVersionUID;

#pragma mark Public

- (NSString *)getAlgorithm;

- (IOSByteArray *)getEncoded;

- (NSString *)getFormat;

- (JavaxCryptoSpecDHParameterSpec *)getParams;

- (JavaMathBigInteger *)getY;

#pragma mark Package-Private

- (instancetype __nonnull)initWithJavaMathBigInteger:(JavaMathBigInteger *)y
                  withJavaxCryptoSpecDHParameterSpec:(JavaxCryptoSpecDHParameterSpec *)dhSpec;

- (instancetype __nonnull)initWithJavaxCryptoInterfacesDHPublicKey:(id<JavaxCryptoInterfacesDHPublicKey>)key;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoParamsDHPublicKeyParameters:(LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *)params;

- (instancetype __nonnull)initWithJavaxCryptoSpecDHPublicKeySpec:(JavaxCryptoSpecDHPublicKeySpec *)spec;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo:(LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *)info;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJceProviderJCEDHPublicKey)

inline jlong LibOrgBouncycastleJceProviderJCEDHPublicKey_get_serialVersionUID(void);
#define LibOrgBouncycastleJceProviderJCEDHPublicKey_serialVersionUID -216691575254424324LL
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleJceProviderJCEDHPublicKey, serialVersionUID, jlong)

FOUNDATION_EXPORT void LibOrgBouncycastleJceProviderJCEDHPublicKey_initWithJavaxCryptoSpecDHPublicKeySpec_(LibOrgBouncycastleJceProviderJCEDHPublicKey *self, JavaxCryptoSpecDHPublicKeySpec *spec);

FOUNDATION_EXPORT LibOrgBouncycastleJceProviderJCEDHPublicKey *new_LibOrgBouncycastleJceProviderJCEDHPublicKey_initWithJavaxCryptoSpecDHPublicKeySpec_(JavaxCryptoSpecDHPublicKeySpec *spec) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJceProviderJCEDHPublicKey *create_LibOrgBouncycastleJceProviderJCEDHPublicKey_initWithJavaxCryptoSpecDHPublicKeySpec_(JavaxCryptoSpecDHPublicKeySpec *spec);

FOUNDATION_EXPORT void LibOrgBouncycastleJceProviderJCEDHPublicKey_initWithJavaxCryptoInterfacesDHPublicKey_(LibOrgBouncycastleJceProviderJCEDHPublicKey *self, id<JavaxCryptoInterfacesDHPublicKey> key);

FOUNDATION_EXPORT LibOrgBouncycastleJceProviderJCEDHPublicKey *new_LibOrgBouncycastleJceProviderJCEDHPublicKey_initWithJavaxCryptoInterfacesDHPublicKey_(id<JavaxCryptoInterfacesDHPublicKey> key) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJceProviderJCEDHPublicKey *create_LibOrgBouncycastleJceProviderJCEDHPublicKey_initWithJavaxCryptoInterfacesDHPublicKey_(id<JavaxCryptoInterfacesDHPublicKey> key);

FOUNDATION_EXPORT void LibOrgBouncycastleJceProviderJCEDHPublicKey_initWithLibOrgBouncycastleCryptoParamsDHPublicKeyParameters_(LibOrgBouncycastleJceProviderJCEDHPublicKey *self, LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *params);

FOUNDATION_EXPORT LibOrgBouncycastleJceProviderJCEDHPublicKey *new_LibOrgBouncycastleJceProviderJCEDHPublicKey_initWithLibOrgBouncycastleCryptoParamsDHPublicKeyParameters_(LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *params) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJceProviderJCEDHPublicKey *create_LibOrgBouncycastleJceProviderJCEDHPublicKey_initWithLibOrgBouncycastleCryptoParamsDHPublicKeyParameters_(LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *params);

FOUNDATION_EXPORT void LibOrgBouncycastleJceProviderJCEDHPublicKey_initWithJavaMathBigInteger_withJavaxCryptoSpecDHParameterSpec_(LibOrgBouncycastleJceProviderJCEDHPublicKey *self, JavaMathBigInteger *y, JavaxCryptoSpecDHParameterSpec *dhSpec);

FOUNDATION_EXPORT LibOrgBouncycastleJceProviderJCEDHPublicKey *new_LibOrgBouncycastleJceProviderJCEDHPublicKey_initWithJavaMathBigInteger_withJavaxCryptoSpecDHParameterSpec_(JavaMathBigInteger *y, JavaxCryptoSpecDHParameterSpec *dhSpec) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJceProviderJCEDHPublicKey *create_LibOrgBouncycastleJceProviderJCEDHPublicKey_initWithJavaMathBigInteger_withJavaxCryptoSpecDHParameterSpec_(JavaMathBigInteger *y, JavaxCryptoSpecDHParameterSpec *dhSpec);

FOUNDATION_EXPORT void LibOrgBouncycastleJceProviderJCEDHPublicKey_initWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_(LibOrgBouncycastleJceProviderJCEDHPublicKey *self, LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *info);

FOUNDATION_EXPORT LibOrgBouncycastleJceProviderJCEDHPublicKey *new_LibOrgBouncycastleJceProviderJCEDHPublicKey_initWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_(LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *info) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJceProviderJCEDHPublicKey *create_LibOrgBouncycastleJceProviderJCEDHPublicKey_initWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_(LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *info);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJceProviderJCEDHPublicKey)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // JCEDHPublicKey_H
