//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/crypto/newhope/ErrorCorrection.java
//

#ifndef ErrorCorrection_H
#define ErrorCorrection_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;
@class IOSIntArray;
@class IOSShortArray;

@interface LibOrgBouncycastlePqcCryptoNewhopeErrorCorrection : NSObject

#pragma mark Package-Private

- (instancetype __nonnull)init;

+ (jint)absWithInt:(jint)v;

+ (jint)fWithIntArray:(IOSIntArray *)v
              withInt:(jint)off0
              withInt:(jint)off1
              withInt:(jint)x;

+ (jint)gWithInt:(jint)x;

+ (void)helpRecWithShortArray:(IOSShortArray *)c
               withShortArray:(IOSShortArray *)v
                withByteArray:(IOSByteArray *)seed
                     withByte:(jbyte)nonce;

+ (jshort)LDDecodeWithInt:(jint)xi0
                  withInt:(jint)xi1
                  withInt:(jint)xi2
                  withInt:(jint)xi3;

+ (void)recWithByteArray:(IOSByteArray *)key
          withShortArray:(IOSShortArray *)v
          withShortArray:(IOSShortArray *)c;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcCryptoNewhopeErrorCorrection)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoNewhopeErrorCorrection_init(LibOrgBouncycastlePqcCryptoNewhopeErrorCorrection *self);

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoNewhopeErrorCorrection *new_LibOrgBouncycastlePqcCryptoNewhopeErrorCorrection_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoNewhopeErrorCorrection *create_LibOrgBouncycastlePqcCryptoNewhopeErrorCorrection_init(void);

FOUNDATION_EXPORT jint LibOrgBouncycastlePqcCryptoNewhopeErrorCorrection_absWithInt_(jint v);

FOUNDATION_EXPORT jint LibOrgBouncycastlePqcCryptoNewhopeErrorCorrection_fWithIntArray_withInt_withInt_withInt_(IOSIntArray *v, jint off0, jint off1, jint x);

FOUNDATION_EXPORT jint LibOrgBouncycastlePqcCryptoNewhopeErrorCorrection_gWithInt_(jint x);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoNewhopeErrorCorrection_helpRecWithShortArray_withShortArray_withByteArray_withByte_(IOSShortArray *c, IOSShortArray *v, IOSByteArray *seed, jbyte nonce);

FOUNDATION_EXPORT jshort LibOrgBouncycastlePqcCryptoNewhopeErrorCorrection_LDDecodeWithInt_withInt_withInt_withInt_(jint xi0, jint xi1, jint xi2, jint xi3);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoNewhopeErrorCorrection_recWithByteArray_withShortArray_withShortArray_(IOSByteArray *key, IOSShortArray *v, IOSShortArray *c);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcCryptoNewhopeErrorCorrection)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ErrorCorrection_H