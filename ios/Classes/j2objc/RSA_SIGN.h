//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/com/afterlogic/pgp/key/generation/type/RSA_SIGN.java
//

#ifndef RSA_SIGN_H
#define RSA_SIGN_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "RSA_GENERAL.h"

@class LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm;
@class LibComAfterlogicPgpKeyGenerationTypeLengthRsaLength;

@interface LibComAfterlogicPgpKeyGenerationTypeRSA_SIGN : LibComAfterlogicPgpKeyGenerationTypeRSA_GENERAL

#pragma mark Public

- (LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm *)getAlgorithm;

#pragma mark Package-Private

- (instancetype __nonnull)initWithLibComAfterlogicPgpKeyGenerationTypeLengthRsaLength:(LibComAfterlogicPgpKeyGenerationTypeLengthRsaLength *)length;

@end

J2OBJC_EMPTY_STATIC_INIT(LibComAfterlogicPgpKeyGenerationTypeRSA_SIGN)

FOUNDATION_EXPORT void LibComAfterlogicPgpKeyGenerationTypeRSA_SIGN_initWithLibComAfterlogicPgpKeyGenerationTypeLengthRsaLength_(LibComAfterlogicPgpKeyGenerationTypeRSA_SIGN *self, LibComAfterlogicPgpKeyGenerationTypeLengthRsaLength *length);

FOUNDATION_EXPORT LibComAfterlogicPgpKeyGenerationTypeRSA_SIGN *new_LibComAfterlogicPgpKeyGenerationTypeRSA_SIGN_initWithLibComAfterlogicPgpKeyGenerationTypeLengthRsaLength_(LibComAfterlogicPgpKeyGenerationTypeLengthRsaLength *length) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibComAfterlogicPgpKeyGenerationTypeRSA_SIGN *create_LibComAfterlogicPgpKeyGenerationTypeRSA_SIGN_initWithLibComAfterlogicPgpKeyGenerationTypeLengthRsaLength_(LibComAfterlogicPgpKeyGenerationTypeLengthRsaLength *length);

J2OBJC_TYPE_LITERAL_HEADER(LibComAfterlogicPgpKeyGenerationTypeRSA_SIGN)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // RSA_SIGN_H
