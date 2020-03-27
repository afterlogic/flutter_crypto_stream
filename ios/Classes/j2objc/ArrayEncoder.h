//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/math/ntru/util/ArrayEncoder.java
//

#ifndef ArrayEncoder_H
#define ArrayEncoder_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;
@class IOSIntArray;
@class JavaIoInputStream;

@interface LibOrgBouncycastlePqcMathNtruUtilArrayEncoder : NSObject

#pragma mark Public

- (instancetype __nonnull)init;

+ (IOSIntArray *)decodeMod3SvesWithByteArray:(IOSByteArray *)data
                                     withInt:(jint)N;

+ (IOSIntArray *)decodeMod3TightWithByteArray:(IOSByteArray *)b
                                      withInt:(jint)N;

+ (IOSIntArray *)decodeMod3TightWithJavaIoInputStream:(JavaIoInputStream *)is
                                              withInt:(jint)N;

+ (IOSIntArray *)decodeModQWithByteArray:(IOSByteArray *)data
                                 withInt:(jint)N
                                 withInt:(jint)q;

+ (IOSIntArray *)decodeModQWithJavaIoInputStream:(JavaIoInputStream *)is
                                         withInt:(jint)N
                                         withInt:(jint)q;

+ (IOSByteArray *)encodeMod3SvesWithIntArray:(IOSIntArray *)arr;

+ (IOSByteArray *)encodeMod3TightWithIntArray:(IOSIntArray *)intArray;

+ (IOSByteArray *)encodeModQWithIntArray:(IOSIntArray *)a
                                 withInt:(jint)q;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastlePqcMathNtruUtilArrayEncoder)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcMathNtruUtilArrayEncoder_init(LibOrgBouncycastlePqcMathNtruUtilArrayEncoder *self);

FOUNDATION_EXPORT LibOrgBouncycastlePqcMathNtruUtilArrayEncoder *new_LibOrgBouncycastlePqcMathNtruUtilArrayEncoder_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcMathNtruUtilArrayEncoder *create_LibOrgBouncycastlePqcMathNtruUtilArrayEncoder_init(void);

FOUNDATION_EXPORT IOSByteArray *LibOrgBouncycastlePqcMathNtruUtilArrayEncoder_encodeModQWithIntArray_withInt_(IOSIntArray *a, jint q);

FOUNDATION_EXPORT IOSIntArray *LibOrgBouncycastlePqcMathNtruUtilArrayEncoder_decodeModQWithByteArray_withInt_withInt_(IOSByteArray *data, jint N, jint q);

FOUNDATION_EXPORT IOSIntArray *LibOrgBouncycastlePqcMathNtruUtilArrayEncoder_decodeModQWithJavaIoInputStream_withInt_withInt_(JavaIoInputStream *is, jint N, jint q);

FOUNDATION_EXPORT IOSIntArray *LibOrgBouncycastlePqcMathNtruUtilArrayEncoder_decodeMod3SvesWithByteArray_withInt_(IOSByteArray *data, jint N);

FOUNDATION_EXPORT IOSByteArray *LibOrgBouncycastlePqcMathNtruUtilArrayEncoder_encodeMod3SvesWithIntArray_(IOSIntArray *arr);

FOUNDATION_EXPORT IOSByteArray *LibOrgBouncycastlePqcMathNtruUtilArrayEncoder_encodeMod3TightWithIntArray_(IOSIntArray *intArray);

FOUNDATION_EXPORT IOSIntArray *LibOrgBouncycastlePqcMathNtruUtilArrayEncoder_decodeMod3TightWithByteArray_withInt_(IOSByteArray *b, jint N);

FOUNDATION_EXPORT IOSIntArray *LibOrgBouncycastlePqcMathNtruUtilArrayEncoder_decodeMod3TightWithJavaIoInputStream_withInt_(JavaIoInputStream *is, jint N);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcMathNtruUtilArrayEncoder)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ArrayEncoder_H