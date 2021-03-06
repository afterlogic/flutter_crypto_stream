//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/engines/DESedeWrapEngine.java
//

#ifndef DESedeWrapEngine_H
#define DESedeWrapEngine_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "Wrapper.h"

@class IOSByteArray;
@protocol LibOrgBouncycastleCryptoCipherParameters;
@protocol LibOrgBouncycastleCryptoDigest;

@interface LibOrgBouncycastleCryptoEnginesDESedeWrapEngine : NSObject < LibOrgBouncycastleCryptoWrapper > {
 @public
  id<LibOrgBouncycastleCryptoDigest> sha1_;
  IOSByteArray *digest_;
}

#pragma mark Public

- (instancetype __nonnull)init;

- (NSString *)getAlgorithmName;

- (void)init__WithBoolean:(jboolean)forWrapping
withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)param OBJC_METHOD_FAMILY_NONE;

- (IOSByteArray *)unwrapWithByteArray:(IOSByteArray *)inArg
                              withInt:(jint)inOff
                              withInt:(jint)inLen;

- (IOSByteArray *)wrapWithByteArray:(IOSByteArray *)inArg
                            withInt:(jint)inOff
                            withInt:(jint)inLen;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleCryptoEnginesDESedeWrapEngine)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoEnginesDESedeWrapEngine, sha1_, id<LibOrgBouncycastleCryptoDigest>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoEnginesDESedeWrapEngine, digest_, IOSByteArray *)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoEnginesDESedeWrapEngine_init(LibOrgBouncycastleCryptoEnginesDESedeWrapEngine *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoEnginesDESedeWrapEngine *new_LibOrgBouncycastleCryptoEnginesDESedeWrapEngine_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoEnginesDESedeWrapEngine *create_LibOrgBouncycastleCryptoEnginesDESedeWrapEngine_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoEnginesDESedeWrapEngine)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // DESedeWrapEngine_H
