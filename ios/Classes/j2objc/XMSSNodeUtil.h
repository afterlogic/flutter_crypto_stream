//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/crypto/xmss/XMSSNodeUtil.java
//

#ifndef XMSSNodeUtil_H
#define XMSSNodeUtil_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class LibOrgBouncycastlePqcCryptoXmssLTreeAddress;
@class LibOrgBouncycastlePqcCryptoXmssWOTSPlus;
@class LibOrgBouncycastlePqcCryptoXmssWOTSPlusPublicKeyParameters;
@class LibOrgBouncycastlePqcCryptoXmssXMSSAddress;
@class LibOrgBouncycastlePqcCryptoXmssXMSSNode;

@interface LibOrgBouncycastlePqcCryptoXmssXMSSNodeUtil : NSObject

#pragma mark Package-Private

- (instancetype __nonnull)init;

+ (LibOrgBouncycastlePqcCryptoXmssXMSSNode *)lTreeWithLibOrgBouncycastlePqcCryptoXmssWOTSPlus:(LibOrgBouncycastlePqcCryptoXmssWOTSPlus *)wotsPlus
                               withLibOrgBouncycastlePqcCryptoXmssWOTSPlusPublicKeyParameters:(LibOrgBouncycastlePqcCryptoXmssWOTSPlusPublicKeyParameters *)publicKey
                                              withLibOrgBouncycastlePqcCryptoXmssLTreeAddress:(LibOrgBouncycastlePqcCryptoXmssLTreeAddress *)address;

+ (LibOrgBouncycastlePqcCryptoXmssXMSSNode *)randomizeHashWithLibOrgBouncycastlePqcCryptoXmssWOTSPlus:(LibOrgBouncycastlePqcCryptoXmssWOTSPlus *)wotsPlus
                                                          withLibOrgBouncycastlePqcCryptoXmssXMSSNode:(LibOrgBouncycastlePqcCryptoXmssXMSSNode *)left
                                                          withLibOrgBouncycastlePqcCryptoXmssXMSSNode:(LibOrgBouncycastlePqcCryptoXmssXMSSNode *)right
                                                       withLibOrgBouncycastlePqcCryptoXmssXMSSAddress:(LibOrgBouncycastlePqcCryptoXmssXMSSAddress *)address;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcCryptoXmssXMSSNodeUtil)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoXmssXMSSNodeUtil_init(LibOrgBouncycastlePqcCryptoXmssXMSSNodeUtil *self);

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoXmssXMSSNodeUtil *new_LibOrgBouncycastlePqcCryptoXmssXMSSNodeUtil_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoXmssXMSSNodeUtil *create_LibOrgBouncycastlePqcCryptoXmssXMSSNodeUtil_init(void);

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoXmssXMSSNode *LibOrgBouncycastlePqcCryptoXmssXMSSNodeUtil_lTreeWithLibOrgBouncycastlePqcCryptoXmssWOTSPlus_withLibOrgBouncycastlePqcCryptoXmssWOTSPlusPublicKeyParameters_withLibOrgBouncycastlePqcCryptoXmssLTreeAddress_(LibOrgBouncycastlePqcCryptoXmssWOTSPlus *wotsPlus, LibOrgBouncycastlePqcCryptoXmssWOTSPlusPublicKeyParameters *publicKey, LibOrgBouncycastlePqcCryptoXmssLTreeAddress *address);

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoXmssXMSSNode *LibOrgBouncycastlePqcCryptoXmssXMSSNodeUtil_randomizeHashWithLibOrgBouncycastlePqcCryptoXmssWOTSPlus_withLibOrgBouncycastlePqcCryptoXmssXMSSNode_withLibOrgBouncycastlePqcCryptoXmssXMSSNode_withLibOrgBouncycastlePqcCryptoXmssXMSSAddress_(LibOrgBouncycastlePqcCryptoXmssWOTSPlus *wotsPlus, LibOrgBouncycastlePqcCryptoXmssXMSSNode *left, LibOrgBouncycastlePqcCryptoXmssXMSSNode *right, LibOrgBouncycastlePqcCryptoXmssXMSSAddress *address);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcCryptoXmssXMSSNodeUtil)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // XMSSNodeUtil_H
