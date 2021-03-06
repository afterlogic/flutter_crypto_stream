//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/PBEParametersGenerator.java
//

#ifndef PBEParametersGenerator_H
#define PBEParametersGenerator_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;
@class IOSCharArray;
@protocol LibOrgBouncycastleCryptoCipherParameters;

@interface LibOrgBouncycastleCryptoPBEParametersGenerator : NSObject {
 @public
  IOSByteArray *password_;
  IOSByteArray *salt_;
  jint iterationCount_;
}

#pragma mark Public

- (id<LibOrgBouncycastleCryptoCipherParameters>)generateDerivedMacParametersWithInt:(jint)keySize;

- (id<LibOrgBouncycastleCryptoCipherParameters>)generateDerivedParametersWithInt:(jint)keySize;

- (id<LibOrgBouncycastleCryptoCipherParameters>)generateDerivedParametersWithInt:(jint)keySize
                                                                         withInt:(jint)ivSize;

- (jint)getIterationCount;

- (IOSByteArray *)getPassword;

- (IOSByteArray *)getSalt;

- (void)init__WithByteArray:(IOSByteArray *)password
              withByteArray:(IOSByteArray *)salt
                    withInt:(jint)iterationCount OBJC_METHOD_FAMILY_NONE;

+ (IOSByteArray *)PKCS12PasswordToBytesWithCharArray:(IOSCharArray *)password;

+ (IOSByteArray *)PKCS5PasswordToBytesWithCharArray:(IOSCharArray *)password;

+ (IOSByteArray *)PKCS5PasswordToUTF8BytesWithCharArray:(IOSCharArray *)password;

#pragma mark Protected

- (instancetype __nonnull)init;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoPBEParametersGenerator)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoPBEParametersGenerator, password_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoPBEParametersGenerator, salt_, IOSByteArray *)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoPBEParametersGenerator_init(LibOrgBouncycastleCryptoPBEParametersGenerator *self);

FOUNDATION_EXPORT IOSByteArray *LibOrgBouncycastleCryptoPBEParametersGenerator_PKCS5PasswordToBytesWithCharArray_(IOSCharArray *password);

FOUNDATION_EXPORT IOSByteArray *LibOrgBouncycastleCryptoPBEParametersGenerator_PKCS5PasswordToUTF8BytesWithCharArray_(IOSCharArray *password);

FOUNDATION_EXPORT IOSByteArray *LibOrgBouncycastleCryptoPBEParametersGenerator_PKCS12PasswordToBytesWithCharArray_(IOSCharArray *password);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoPBEParametersGenerator)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // PBEParametersGenerator_H
