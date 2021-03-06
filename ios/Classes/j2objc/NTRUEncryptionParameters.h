//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/crypto/ntru/NTRUEncryptionParameters.java
//

#ifndef NTRUEncryptionParameters_H
#define NTRUEncryptionParameters_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;
@class JavaIoInputStream;
@class JavaIoOutputStream;
@protocol LibOrgBouncycastleCryptoDigest;

@interface LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters : NSObject < NSCopying > {
 @public
  jint N_;
  jint q_;
  jint df_;
  jint df1_;
  jint df2_;
  jint df3_;
  jint dr_;
  jint dr1_;
  jint dr2_;
  jint dr3_;
  jint dg_;
  jint llen_;
  jint maxMsgLenBytes_;
  jint db_;
  jint bufferLenBits_;
  jint bufferLenTrits_;
  jint dm0_;
  jint pkLen_;
  jint c_;
  jint minCallsR_;
  jint minCallsMask_;
  jboolean hashSeed_;
  IOSByteArray *oid_;
  jboolean sparse_;
  jboolean fastFp_;
  jint polyType_;
  id<LibOrgBouncycastleCryptoDigest> hashAlg_;
}

#pragma mark Public

- (instancetype __nonnull)initWithJavaIoInputStream:(JavaIoInputStream *)is;

- (instancetype __nonnull)initWithInt:(jint)N
                              withInt:(jint)q
                              withInt:(jint)df
                              withInt:(jint)dm0
                              withInt:(jint)db
                              withInt:(jint)c
                              withInt:(jint)minCallsR
                              withInt:(jint)minCallsMask
                          withBoolean:(jboolean)hashSeed
                        withByteArray:(IOSByteArray *)oid
                          withBoolean:(jboolean)sparse
                          withBoolean:(jboolean)fastFp
   withLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)hashAlg;

- (instancetype __nonnull)initWithInt:(jint)N
                              withInt:(jint)q
                              withInt:(jint)df1
                              withInt:(jint)df2
                              withInt:(jint)df3
                              withInt:(jint)dm0
                              withInt:(jint)db
                              withInt:(jint)c
                              withInt:(jint)minCallsR
                              withInt:(jint)minCallsMask
                          withBoolean:(jboolean)hashSeed
                        withByteArray:(IOSByteArray *)oid
                          withBoolean:(jboolean)sparse
                          withBoolean:(jboolean)fastFp
   withLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)hashAlg;

- (LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters *)java_clone;

- (jboolean)isEqual:(id)obj;

- (jint)getMaxMessageLength;

- (NSUInteger)hash;

- (NSString *)description;

- (void)writeToWithJavaIoOutputStream:(JavaIoOutputStream *)os;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters)

J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters, oid_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters, hashAlg_, id<LibOrgBouncycastleCryptoDigest>)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters_initWithInt_withInt_withInt_withInt_withInt_withInt_withInt_withInt_withBoolean_withByteArray_withBoolean_withBoolean_withLibOrgBouncycastleCryptoDigest_(LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters *self, jint N, jint q, jint df, jint dm0, jint db, jint c, jint minCallsR, jint minCallsMask, jboolean hashSeed, IOSByteArray *oid, jboolean sparse, jboolean fastFp, id<LibOrgBouncycastleCryptoDigest> hashAlg);

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters *new_LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters_initWithInt_withInt_withInt_withInt_withInt_withInt_withInt_withInt_withBoolean_withByteArray_withBoolean_withBoolean_withLibOrgBouncycastleCryptoDigest_(jint N, jint q, jint df, jint dm0, jint db, jint c, jint minCallsR, jint minCallsMask, jboolean hashSeed, IOSByteArray *oid, jboolean sparse, jboolean fastFp, id<LibOrgBouncycastleCryptoDigest> hashAlg) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters *create_LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters_initWithInt_withInt_withInt_withInt_withInt_withInt_withInt_withInt_withBoolean_withByteArray_withBoolean_withBoolean_withLibOrgBouncycastleCryptoDigest_(jint N, jint q, jint df, jint dm0, jint db, jint c, jint minCallsR, jint minCallsMask, jboolean hashSeed, IOSByteArray *oid, jboolean sparse, jboolean fastFp, id<LibOrgBouncycastleCryptoDigest> hashAlg);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters_initWithInt_withInt_withInt_withInt_withInt_withInt_withInt_withInt_withInt_withInt_withBoolean_withByteArray_withBoolean_withBoolean_withLibOrgBouncycastleCryptoDigest_(LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters *self, jint N, jint q, jint df1, jint df2, jint df3, jint dm0, jint db, jint c, jint minCallsR, jint minCallsMask, jboolean hashSeed, IOSByteArray *oid, jboolean sparse, jboolean fastFp, id<LibOrgBouncycastleCryptoDigest> hashAlg);

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters *new_LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters_initWithInt_withInt_withInt_withInt_withInt_withInt_withInt_withInt_withInt_withInt_withBoolean_withByteArray_withBoolean_withBoolean_withLibOrgBouncycastleCryptoDigest_(jint N, jint q, jint df1, jint df2, jint df3, jint dm0, jint db, jint c, jint minCallsR, jint minCallsMask, jboolean hashSeed, IOSByteArray *oid, jboolean sparse, jboolean fastFp, id<LibOrgBouncycastleCryptoDigest> hashAlg) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters *create_LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters_initWithInt_withInt_withInt_withInt_withInt_withInt_withInt_withInt_withInt_withInt_withBoolean_withByteArray_withBoolean_withBoolean_withLibOrgBouncycastleCryptoDigest_(jint N, jint q, jint df1, jint df2, jint df3, jint dm0, jint db, jint c, jint minCallsR, jint minCallsMask, jboolean hashSeed, IOSByteArray *oid, jboolean sparse, jboolean fastFp, id<LibOrgBouncycastleCryptoDigest> hashAlg);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters_initWithJavaIoInputStream_(LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters *self, JavaIoInputStream *is);

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters *new_LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters_initWithJavaIoInputStream_(JavaIoInputStream *is) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters *create_LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters_initWithJavaIoInputStream_(JavaIoInputStream *is);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // NTRUEncryptionParameters_H
