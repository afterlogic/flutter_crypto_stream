//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/openpgp/operator/PublicKeyDataDecryptorFactory.java
//

#ifndef PublicKeyDataDecryptorFactory_H
#define PublicKeyDataDecryptorFactory_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "PGPDataDecryptorFactory.h"

@class IOSByteArray;
@class IOSObjectArray;

@protocol LibOrgBouncycastleOpenpgpOperatorPublicKeyDataDecryptorFactory < LibOrgBouncycastleOpenpgpOperatorPGPDataDecryptorFactory, JavaObject >

- (IOSByteArray *)recoverSessionDataWithInt:(jint)keyAlgorithm
                             withByteArray2:(IOSObjectArray *)secKeyData;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleOpenpgpOperatorPublicKeyDataDecryptorFactory)

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleOpenpgpOperatorPublicKeyDataDecryptorFactory)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // PublicKeyDataDecryptorFactory_H
