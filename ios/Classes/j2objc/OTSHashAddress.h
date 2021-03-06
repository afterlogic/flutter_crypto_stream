//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/crypto/xmss/OTSHashAddress.java
//

#ifndef OTSHashAddress_H
#define OTSHashAddress_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "XMSSAddress.h"

@class IOSByteArray;

@interface LibOrgBouncycastlePqcCryptoXmssOTSHashAddress : LibOrgBouncycastlePqcCryptoXmssXMSSAddress

#pragma mark Protected

- (jint)getChainAddress;

- (jint)getHashAddress;

- (jint)getOTSAddress;

- (IOSByteArray *)toByteArray;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastlePqcCryptoXmssXMSSAddress_Builder:(LibOrgBouncycastlePqcCryptoXmssXMSSAddress_Builder *)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcCryptoXmssOTSHashAddress)

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcCryptoXmssOTSHashAddress)

@interface LibOrgBouncycastlePqcCryptoXmssOTSHashAddress_Builder : LibOrgBouncycastlePqcCryptoXmssXMSSAddress_Builder

#pragma mark Protected

- (instancetype __nonnull)init;

- (LibOrgBouncycastlePqcCryptoXmssXMSSAddress *)build;

- (LibOrgBouncycastlePqcCryptoXmssOTSHashAddress_Builder *)getThis;

- (LibOrgBouncycastlePqcCryptoXmssOTSHashAddress_Builder *)withChainAddressWithInt:(jint)val;

- (LibOrgBouncycastlePqcCryptoXmssOTSHashAddress_Builder *)withHashAddressWithInt:(jint)val;

- (LibOrgBouncycastlePqcCryptoXmssOTSHashAddress_Builder *)withKeyAndMaskWithInt:(jint)arg0;

- (LibOrgBouncycastlePqcCryptoXmssOTSHashAddress_Builder *)withLayerAddressWithInt:(jint)arg0;

- (LibOrgBouncycastlePqcCryptoXmssOTSHashAddress_Builder *)withOTSAddressWithInt:(jint)val;

- (LibOrgBouncycastlePqcCryptoXmssOTSHashAddress_Builder *)withTreeAddressWithLong:(jlong)arg0;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithInt:(jint)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcCryptoXmssOTSHashAddress_Builder)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoXmssOTSHashAddress_Builder_init(LibOrgBouncycastlePqcCryptoXmssOTSHashAddress_Builder *self);

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoXmssOTSHashAddress_Builder *new_LibOrgBouncycastlePqcCryptoXmssOTSHashAddress_Builder_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoXmssOTSHashAddress_Builder *create_LibOrgBouncycastlePqcCryptoXmssOTSHashAddress_Builder_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcCryptoXmssOTSHashAddress_Builder)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // OTSHashAddress_H
