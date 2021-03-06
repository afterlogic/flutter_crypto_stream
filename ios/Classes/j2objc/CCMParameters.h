//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/params/CCMParameters.java
//

#ifndef CCMParameters_H
#define CCMParameters_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "AEADParameters.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@class LibOrgBouncycastleCryptoParamsKeyParameter;

@interface LibOrgBouncycastleCryptoParamsCCMParameters : LibOrgBouncycastleCryptoParamsAEADParameters

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoParamsKeyParameter:(LibOrgBouncycastleCryptoParamsKeyParameter *)key
                                                                     withInt:(jint)macSize
                                                               withByteArray:(IOSByteArray *)nonce
                                                               withByteArray:(IOSByteArray *)associatedText;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoParamsKeyParameter:(LibOrgBouncycastleCryptoParamsKeyParameter *)arg0
                                                                     withInt:(jint)arg1
                                                               withByteArray:(IOSByteArray *)arg2 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoParamsCCMParameters)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoParamsCCMParameters_initWithLibOrgBouncycastleCryptoParamsKeyParameter_withInt_withByteArray_withByteArray_(LibOrgBouncycastleCryptoParamsCCMParameters *self, LibOrgBouncycastleCryptoParamsKeyParameter *key, jint macSize, IOSByteArray *nonce, IOSByteArray *associatedText);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoParamsCCMParameters *new_LibOrgBouncycastleCryptoParamsCCMParameters_initWithLibOrgBouncycastleCryptoParamsKeyParameter_withInt_withByteArray_withByteArray_(LibOrgBouncycastleCryptoParamsKeyParameter *key, jint macSize, IOSByteArray *nonce, IOSByteArray *associatedText) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoParamsCCMParameters *create_LibOrgBouncycastleCryptoParamsCCMParameters_initWithLibOrgBouncycastleCryptoParamsKeyParameter_withInt_withByteArray_withByteArray_(LibOrgBouncycastleCryptoParamsKeyParameter *key, jint macSize, IOSByteArray *nonce, IOSByteArray *associatedText);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoParamsCCMParameters)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // CCMParameters_H
