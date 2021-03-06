//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/engines/CramerShoupCoreEngine.java
//

#ifndef CramerShoupCoreEngine_H
#define CramerShoupCoreEngine_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "java/lang/Exception.h"

@class IOSByteArray;
@class JavaLangThrowable;
@class JavaMathBigInteger;
@class JavaSecuritySecureRandom;
@class LibOrgBouncycastleCryptoEnginesCramerShoupCiphertext;
@protocol LibOrgBouncycastleCryptoCipherParameters;

@interface LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine : NSObject

#pragma mark Public

- (instancetype __nonnull)init;

- (JavaMathBigInteger *)convertInputWithByteArray:(IOSByteArray *)inArg
                                          withInt:(jint)inOff
                                          withInt:(jint)inLen;

- (IOSByteArray *)convertOutputWithJavaMathBigInteger:(JavaMathBigInteger *)result;

- (JavaMathBigInteger *)decryptBlockWithLibOrgBouncycastleCryptoEnginesCramerShoupCiphertext:(LibOrgBouncycastleCryptoEnginesCramerShoupCiphertext *)input;

- (LibOrgBouncycastleCryptoEnginesCramerShoupCiphertext *)encryptBlockWithJavaMathBigInteger:(JavaMathBigInteger *)input;

- (jint)getInputBlockSize;

- (jint)getOutputBlockSize;

- (void)init__WithBoolean:(jboolean)forEncryption
withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)param OBJC_METHOD_FAMILY_NONE;

- (void)init__WithBoolean:(jboolean)forEncryption
withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)param
             withNSString:(NSString *)label OBJC_METHOD_FAMILY_NONE;

#pragma mark Protected

- (JavaSecuritySecureRandom *)initSecureRandomWithBoolean:(jboolean)needed
                             withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)provided OBJC_METHOD_FAMILY_NONE;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine_init(LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine *new_LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine *create_LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine)

@interface LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine_CramerShoupCiphertextException : JavaLangException

#pragma mark Public

- (instancetype __nonnull)initWithNSString:(NSString *)msg;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

- (instancetype __nonnull)initWithJavaLangThrowable:(JavaLangThrowable *)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithNSString:(NSString *)arg0
                     withJavaLangThrowable:(JavaLangThrowable *)arg1 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithNSString:(NSString *)arg0
                     withJavaLangThrowable:(JavaLangThrowable *)arg1
                               withBoolean:(jboolean)arg2
                               withBoolean:(jboolean)arg3 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine_CramerShoupCiphertextException)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine_CramerShoupCiphertextException_initWithNSString_(LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine_CramerShoupCiphertextException *self, NSString *msg);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine_CramerShoupCiphertextException *new_LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine_CramerShoupCiphertextException_initWithNSString_(NSString *msg) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine_CramerShoupCiphertextException *create_LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine_CramerShoupCiphertextException_initWithNSString_(NSString *msg);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoEnginesCramerShoupCoreEngine_CramerShoupCiphertextException)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // CramerShoupCoreEngine_H
