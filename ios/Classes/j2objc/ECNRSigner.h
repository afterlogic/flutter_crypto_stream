//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/signers/ECNRSigner.java
//

#ifndef ECNRSigner_H
#define ECNRSigner_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "DSAExt.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@class IOSObjectArray;
@class JavaMathBigInteger;
@protocol LibOrgBouncycastleCryptoCipherParameters;

@interface LibOrgBouncycastleCryptoSignersECNRSigner : NSObject < LibOrgBouncycastleCryptoDSAExt >

#pragma mark Public

- (instancetype __nonnull)init;

- (IOSObjectArray *)generateSignatureWithByteArray:(IOSByteArray *)digest;

- (JavaMathBigInteger *)getOrder;

- (void)init__WithBoolean:(jboolean)forSigning
withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)param OBJC_METHOD_FAMILY_NONE;

- (jboolean)verifySignatureWithByteArray:(IOSByteArray *)digest
                  withJavaMathBigInteger:(JavaMathBigInteger *)r
                  withJavaMathBigInteger:(JavaMathBigInteger *)s;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoSignersECNRSigner)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoSignersECNRSigner_init(LibOrgBouncycastleCryptoSignersECNRSigner *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoSignersECNRSigner *new_LibOrgBouncycastleCryptoSignersECNRSigner_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoSignersECNRSigner *create_LibOrgBouncycastleCryptoSignersECNRSigner_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoSignersECNRSigner)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ECNRSigner_H
