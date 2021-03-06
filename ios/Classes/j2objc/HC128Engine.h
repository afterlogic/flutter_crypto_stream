//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/engines/HC128Engine.java
//

#ifndef HC128Engine_H
#define HC128Engine_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "StreamCipher.h"

@class IOSByteArray;
@protocol LibOrgBouncycastleCryptoCipherParameters;

@interface LibOrgBouncycastleCryptoEnginesHC128Engine : NSObject < LibOrgBouncycastleCryptoStreamCipher >

#pragma mark Public

- (instancetype __nonnull)init;

- (NSString *)getAlgorithmName;

- (void)init__WithBoolean:(jboolean)forEncryption
withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)params OBJC_METHOD_FAMILY_NONE;

- (jint)processBytesWithByteArray:(IOSByteArray *)inArg
                          withInt:(jint)inOff
                          withInt:(jint)len
                    withByteArray:(IOSByteArray *)outArg
                          withInt:(jint)outOff;

- (void)reset;

- (jbyte)returnByteWithByte:(jbyte)inArg;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoEnginesHC128Engine)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoEnginesHC128Engine_init(LibOrgBouncycastleCryptoEnginesHC128Engine *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoEnginesHC128Engine *new_LibOrgBouncycastleCryptoEnginesHC128Engine_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoEnginesHC128Engine *create_LibOrgBouncycastleCryptoEnginesHC128Engine_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoEnginesHC128Engine)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // HC128Engine_H
