//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/jcajce/interfaces/NHPrivateKey.java
//

#ifndef NHPrivateKey_H
#define NHPrivateKey_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "NHKey.h"
#include "java/security/PrivateKey.h"

@class IOSShortArray;

@protocol LibOrgBouncycastlePqcJcajceInterfacesNHPrivateKey < LibOrgBouncycastlePqcJcajceInterfacesNHKey, JavaSecurityPrivateKey, JavaObject >

- (IOSShortArray *)getSecretData;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcJcajceInterfacesNHPrivateKey)

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcJcajceInterfacesNHPrivateKey)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // NHPrivateKey_H