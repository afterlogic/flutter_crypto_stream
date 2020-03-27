//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/generators/PKCS5S2ParametersGenerator.java
//

#ifndef PKCS5S2ParametersGenerator_H
#define PKCS5S2ParametersGenerator_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "PBEParametersGenerator.h"

@protocol LibOrgBouncycastleCryptoCipherParameters;
@protocol LibOrgBouncycastleCryptoDigest;

@interface LibOrgBouncycastleCryptoGeneratorsPKCS5S2ParametersGenerator : LibOrgBouncycastleCryptoPBEParametersGenerator

#pragma mark Public

- (instancetype __nonnull)init;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)digest;

- (id<LibOrgBouncycastleCryptoCipherParameters>)generateDerivedMacParametersWithInt:(jint)keySize;

- (id<LibOrgBouncycastleCryptoCipherParameters>)generateDerivedParametersWithInt:(jint)keySize;

- (id<LibOrgBouncycastleCryptoCipherParameters>)generateDerivedParametersWithInt:(jint)keySize
                                                                         withInt:(jint)ivSize;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoGeneratorsPKCS5S2ParametersGenerator)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoGeneratorsPKCS5S2ParametersGenerator_init(LibOrgBouncycastleCryptoGeneratorsPKCS5S2ParametersGenerator *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoGeneratorsPKCS5S2ParametersGenerator *new_LibOrgBouncycastleCryptoGeneratorsPKCS5S2ParametersGenerator_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoGeneratorsPKCS5S2ParametersGenerator *create_LibOrgBouncycastleCryptoGeneratorsPKCS5S2ParametersGenerator_init(void);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoGeneratorsPKCS5S2ParametersGenerator_initWithLibOrgBouncycastleCryptoDigest_(LibOrgBouncycastleCryptoGeneratorsPKCS5S2ParametersGenerator *self, id<LibOrgBouncycastleCryptoDigest> digest);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoGeneratorsPKCS5S2ParametersGenerator *new_LibOrgBouncycastleCryptoGeneratorsPKCS5S2ParametersGenerator_initWithLibOrgBouncycastleCryptoDigest_(id<LibOrgBouncycastleCryptoDigest> digest) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoGeneratorsPKCS5S2ParametersGenerator *create_LibOrgBouncycastleCryptoGeneratorsPKCS5S2ParametersGenerator_initWithLibOrgBouncycastleCryptoDigest_(id<LibOrgBouncycastleCryptoDigest> digest);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoGeneratorsPKCS5S2ParametersGenerator)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // PKCS5S2ParametersGenerator_H