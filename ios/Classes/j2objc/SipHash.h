//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/macs/SipHash.java
//

#ifndef SipHash_H
#define SipHash_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "Mac.h"

@class IOSByteArray;
@protocol LibOrgBouncycastleCryptoCipherParameters;

@interface LibOrgBouncycastleCryptoMacsSipHash : NSObject < LibOrgBouncycastleCryptoMac > {
 @public
  jint c_;
  jint d_;
  jlong k0_;
  jlong k1_;
  jlong v0_;
  jlong v1_;
  jlong v2_;
  jlong v3_;
  jlong m_;
  jint wordPos_;
  jint wordCount_;
}

#pragma mark Public

- (instancetype __nonnull)init;

- (instancetype __nonnull)initWithInt:(jint)c
                              withInt:(jint)d;

- (jlong)doFinal;

- (jint)doFinalWithByteArray:(IOSByteArray *)outArg
                     withInt:(jint)outOff;

- (NSString *)getAlgorithmName;

- (jint)getMacSize;

- (void)init__WithLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)params OBJC_METHOD_FAMILY_NONE;

- (void)reset;

- (void)updateWithByte:(jbyte)input;

- (void)updateWithByteArray:(IOSByteArray *)input
                    withInt:(jint)offset
                    withInt:(jint)length;

#pragma mark Protected

- (void)applySipRoundsWithInt:(jint)n;

- (void)processMessageWord;

+ (jlong)rotateLeftWithLong:(jlong)x
                    withInt:(jint)n;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoMacsSipHash)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoMacsSipHash_init(LibOrgBouncycastleCryptoMacsSipHash *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoMacsSipHash *new_LibOrgBouncycastleCryptoMacsSipHash_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoMacsSipHash *create_LibOrgBouncycastleCryptoMacsSipHash_init(void);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoMacsSipHash_initWithInt_withInt_(LibOrgBouncycastleCryptoMacsSipHash *self, jint c, jint d);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoMacsSipHash *new_LibOrgBouncycastleCryptoMacsSipHash_initWithInt_withInt_(jint c, jint d) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoMacsSipHash *create_LibOrgBouncycastleCryptoMacsSipHash_initWithInt_withInt_(jint c, jint d);

FOUNDATION_EXPORT jlong LibOrgBouncycastleCryptoMacsSipHash_rotateLeftWithLong_withInt_(jlong x, jint n);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoMacsSipHash)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // SipHash_H
