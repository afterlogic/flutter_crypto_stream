//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/params/MGFParameters.java
//

#ifndef MGFParameters_H
#define MGFParameters_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "DerivationParameters.h"
#include "J2ObjC_header.h"

@class IOSByteArray;

@interface LibOrgBouncycastleCryptoParamsMGFParameters : NSObject < LibOrgBouncycastleCryptoDerivationParameters > {
 @public
  IOSByteArray *seed_;
}

#pragma mark Public

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)seed;

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)seed
                                    withInt:(jint)off
                                    withInt:(jint)len;

- (IOSByteArray *)getSeed;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoParamsMGFParameters)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoParamsMGFParameters, seed_, IOSByteArray *)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoParamsMGFParameters_initWithByteArray_(LibOrgBouncycastleCryptoParamsMGFParameters *self, IOSByteArray *seed);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoParamsMGFParameters *new_LibOrgBouncycastleCryptoParamsMGFParameters_initWithByteArray_(IOSByteArray *seed) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoParamsMGFParameters *create_LibOrgBouncycastleCryptoParamsMGFParameters_initWithByteArray_(IOSByteArray *seed);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoParamsMGFParameters_initWithByteArray_withInt_withInt_(LibOrgBouncycastleCryptoParamsMGFParameters *self, IOSByteArray *seed, jint off, jint len);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoParamsMGFParameters *new_LibOrgBouncycastleCryptoParamsMGFParameters_initWithByteArray_withInt_withInt_(IOSByteArray *seed, jint off, jint len) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoParamsMGFParameters *create_LibOrgBouncycastleCryptoParamsMGFParameters_initWithByteArray_withInt_withInt_(IOSByteArray *seed, jint off, jint len);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoParamsMGFParameters)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // MGFParameters_H
