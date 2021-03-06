//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/modes/NISTCTSBlockCipher.java
//

#ifndef NISTCTSBlockCipher_H
#define NISTCTSBlockCipher_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "BufferedBlockCipher.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@protocol LibOrgBouncycastleCryptoBlockCipher;

@interface LibOrgBouncycastleCryptoModesNISTCTSBlockCipher : LibOrgBouncycastleCryptoBufferedBlockCipher
@property (readonly, class) jint CS1 NS_SWIFT_NAME(CS1);
@property (readonly, class) jint CS2 NS_SWIFT_NAME(CS2);
@property (readonly, class) jint CS3 NS_SWIFT_NAME(CS3);

+ (jint)CS1;

+ (jint)CS2;

+ (jint)CS3;

#pragma mark Public

- (instancetype __nonnull)initWithInt:(jint)type
withLibOrgBouncycastleCryptoBlockCipher:(id<LibOrgBouncycastleCryptoBlockCipher>)cipher;

- (jint)doFinalWithByteArray:(IOSByteArray *)outArg
                     withInt:(jint)outOff;

- (jint)getOutputSizeWithInt:(jint)len;

- (jint)getUpdateOutputSizeWithInt:(jint)len;

- (jint)processByteWithByte:(jbyte)inArg
              withByteArray:(IOSByteArray *)outArg
                    withInt:(jint)outOff;

- (jint)processBytesWithByteArray:(IOSByteArray *)inArg
                          withInt:(jint)inOff
                          withInt:(jint)len
                    withByteArray:(IOSByteArray *)outArg
                          withInt:(jint)outOff;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoBlockCipher:(id<LibOrgBouncycastleCryptoBlockCipher>)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoModesNISTCTSBlockCipher)

inline jint LibOrgBouncycastleCryptoModesNISTCTSBlockCipher_get_CS1(void);
#define LibOrgBouncycastleCryptoModesNISTCTSBlockCipher_CS1 1
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoModesNISTCTSBlockCipher, CS1, jint)

inline jint LibOrgBouncycastleCryptoModesNISTCTSBlockCipher_get_CS2(void);
#define LibOrgBouncycastleCryptoModesNISTCTSBlockCipher_CS2 2
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoModesNISTCTSBlockCipher, CS2, jint)

inline jint LibOrgBouncycastleCryptoModesNISTCTSBlockCipher_get_CS3(void);
#define LibOrgBouncycastleCryptoModesNISTCTSBlockCipher_CS3 3
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoModesNISTCTSBlockCipher, CS3, jint)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoModesNISTCTSBlockCipher_initWithInt_withLibOrgBouncycastleCryptoBlockCipher_(LibOrgBouncycastleCryptoModesNISTCTSBlockCipher *self, jint type, id<LibOrgBouncycastleCryptoBlockCipher> cipher);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoModesNISTCTSBlockCipher *new_LibOrgBouncycastleCryptoModesNISTCTSBlockCipher_initWithInt_withLibOrgBouncycastleCryptoBlockCipher_(jint type, id<LibOrgBouncycastleCryptoBlockCipher> cipher) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoModesNISTCTSBlockCipher *create_LibOrgBouncycastleCryptoModesNISTCTSBlockCipher_initWithInt_withLibOrgBouncycastleCryptoBlockCipher_(jint type, id<LibOrgBouncycastleCryptoBlockCipher> cipher);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoModesNISTCTSBlockCipher)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // NISTCTSBlockCipher_H
