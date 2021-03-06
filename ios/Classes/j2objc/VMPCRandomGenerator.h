//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/prng/VMPCRandomGenerator.java
//

#ifndef VMPCRandomGenerator_H
#define VMPCRandomGenerator_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "RandomGenerator.h"

@class IOSByteArray;

@interface LibOrgBouncycastleCryptoPrngVMPCRandomGenerator : NSObject < LibOrgBouncycastleCryptoPrngRandomGenerator >

#pragma mark Public

- (instancetype __nonnull)init;

- (void)addSeedMaterialWithByteArray:(IOSByteArray *)seed;

- (void)addSeedMaterialWithLong:(jlong)seed;

- (void)nextBytesWithByteArray:(IOSByteArray *)bytes;

- (void)nextBytesWithByteArray:(IOSByteArray *)bytes
                       withInt:(jint)start
                       withInt:(jint)len;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoPrngVMPCRandomGenerator)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoPrngVMPCRandomGenerator_init(LibOrgBouncycastleCryptoPrngVMPCRandomGenerator *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoPrngVMPCRandomGenerator *new_LibOrgBouncycastleCryptoPrngVMPCRandomGenerator_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoPrngVMPCRandomGenerator *create_LibOrgBouncycastleCryptoPrngVMPCRandomGenerator_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoPrngVMPCRandomGenerator)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // VMPCRandomGenerator_H
