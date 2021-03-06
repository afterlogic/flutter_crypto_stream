//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/signers/DSASigner.java
//

#ifndef DSASigner_H
#define DSASigner_H

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
@class JavaSecuritySecureRandom;
@protocol LibOrgBouncycastleCryptoCipherParameters;
@protocol LibOrgBouncycastleCryptoSignersDSAKCalculator;

@interface LibOrgBouncycastleCryptoSignersDSASigner : NSObject < LibOrgBouncycastleCryptoDSAExt >

#pragma mark Public

- (instancetype __nonnull)init;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoSignersDSAKCalculator:(id<LibOrgBouncycastleCryptoSignersDSAKCalculator>)kCalculator;

- (IOSObjectArray *)generateSignatureWithByteArray:(IOSByteArray *)message;

- (JavaMathBigInteger *)getOrder;

- (void)init__WithBoolean:(jboolean)forSigning
withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)param OBJC_METHOD_FAMILY_NONE;

- (jboolean)verifySignatureWithByteArray:(IOSByteArray *)message
                  withJavaMathBigInteger:(JavaMathBigInteger *)r
                  withJavaMathBigInteger:(JavaMathBigInteger *)s;

#pragma mark Protected

- (JavaSecuritySecureRandom *)initSecureRandomWithBoolean:(jboolean)needed
                             withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)provided OBJC_METHOD_FAMILY_NONE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoSignersDSASigner)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoSignersDSASigner_init(LibOrgBouncycastleCryptoSignersDSASigner *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoSignersDSASigner *new_LibOrgBouncycastleCryptoSignersDSASigner_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoSignersDSASigner *create_LibOrgBouncycastleCryptoSignersDSASigner_init(void);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoSignersDSASigner_initWithLibOrgBouncycastleCryptoSignersDSAKCalculator_(LibOrgBouncycastleCryptoSignersDSASigner *self, id<LibOrgBouncycastleCryptoSignersDSAKCalculator> kCalculator);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoSignersDSASigner *new_LibOrgBouncycastleCryptoSignersDSASigner_initWithLibOrgBouncycastleCryptoSignersDSAKCalculator_(id<LibOrgBouncycastleCryptoSignersDSAKCalculator> kCalculator) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoSignersDSASigner *create_LibOrgBouncycastleCryptoSignersDSASigner_initWithLibOrgBouncycastleCryptoSignersDSAKCalculator_(id<LibOrgBouncycastleCryptoSignersDSAKCalculator> kCalculator);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoSignersDSASigner)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // DSASigner_H
