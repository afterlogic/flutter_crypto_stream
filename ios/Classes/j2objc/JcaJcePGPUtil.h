//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/openpgp/operator/jcajce/JcaJcePGPUtil.java
//

#ifndef JcaJcePGPUtil_H
#define JcaJcePGPUtil_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;
@class JavaMathBigInteger;
@class LibOrgBouncycastleAsn1ASN1ObjectIdentifier;
@class LibOrgBouncycastleAsn1X9X9ECParameters;
@class LibOrgBouncycastleMathEcECCurve;
@class LibOrgBouncycastleMathEcECPoint;
@protocol JavaxCryptoSecretKey;

@interface LibOrgBouncycastleOpenpgpOperatorJcajceJcaJcePGPUtil : NSObject

#pragma mark Public

+ (id<JavaxCryptoSecretKey>)makeSymmetricKeyWithInt:(jint)algorithm
                                      withByteArray:(IOSByteArray *)keyBytes;

#pragma mark Package-Private

- (instancetype __nonnull)init;

+ (LibOrgBouncycastleMathEcECPoint *)decodePointWithJavaMathBigInteger:(JavaMathBigInteger *)encodedPoint
                                   withLibOrgBouncycastleMathEcECCurve:(LibOrgBouncycastleMathEcECCurve *)curve;

+ (LibOrgBouncycastleAsn1X9X9ECParameters *)getX9ParametersWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)curveOID;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleOpenpgpOperatorJcajceJcaJcePGPUtil)

FOUNDATION_EXPORT void LibOrgBouncycastleOpenpgpOperatorJcajceJcaJcePGPUtil_init(LibOrgBouncycastleOpenpgpOperatorJcajceJcaJcePGPUtil *self);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpOperatorJcajceJcaJcePGPUtil *new_LibOrgBouncycastleOpenpgpOperatorJcajceJcaJcePGPUtil_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpOperatorJcajceJcaJcePGPUtil *create_LibOrgBouncycastleOpenpgpOperatorJcajceJcaJcePGPUtil_init(void);

FOUNDATION_EXPORT id<JavaxCryptoSecretKey> LibOrgBouncycastleOpenpgpOperatorJcajceJcaJcePGPUtil_makeSymmetricKeyWithInt_withByteArray_(jint algorithm, IOSByteArray *keyBytes);

FOUNDATION_EXPORT LibOrgBouncycastleMathEcECPoint *LibOrgBouncycastleOpenpgpOperatorJcajceJcaJcePGPUtil_decodePointWithJavaMathBigInteger_withLibOrgBouncycastleMathEcECCurve_(JavaMathBigInteger *encodedPoint, LibOrgBouncycastleMathEcECCurve *curve);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X9X9ECParameters *LibOrgBouncycastleOpenpgpOperatorJcajceJcaJcePGPUtil_getX9ParametersWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *curveOID);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleOpenpgpOperatorJcajceJcaJcePGPUtil)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // JcaJcePGPUtil_H
