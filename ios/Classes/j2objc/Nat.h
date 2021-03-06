//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/math/raw/Nat.java
//

#ifndef Nat_H
#define Nat_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSIntArray;
@class IOSLongArray;
@class JavaMathBigInteger;

@interface LibOrgBouncycastleMathRawNat : NSObject

#pragma mark Public

- (instancetype __nonnull)init;

+ (jint)addWithInt:(jint)len
      withIntArray:(IOSIntArray *)x
      withIntArray:(IOSIntArray *)y
      withIntArray:(IOSIntArray *)z;

+ (jint)add33AtWithInt:(jint)len
               withInt:(jint)x
          withIntArray:(IOSIntArray *)z
               withInt:(jint)zPos;

+ (jint)add33AtWithInt:(jint)len
               withInt:(jint)x
          withIntArray:(IOSIntArray *)z
               withInt:(jint)zOff
               withInt:(jint)zPos;

+ (jint)add33ToWithInt:(jint)len
               withInt:(jint)x
          withIntArray:(IOSIntArray *)z;

+ (jint)add33ToWithInt:(jint)len
               withInt:(jint)x
          withIntArray:(IOSIntArray *)z
               withInt:(jint)zOff;

+ (jint)addBothToWithInt:(jint)len
            withIntArray:(IOSIntArray *)x
                 withInt:(jint)xOff
            withIntArray:(IOSIntArray *)y
                 withInt:(jint)yOff
            withIntArray:(IOSIntArray *)z
                 withInt:(jint)zOff;

+ (jint)addBothToWithInt:(jint)len
            withIntArray:(IOSIntArray *)x
            withIntArray:(IOSIntArray *)y
            withIntArray:(IOSIntArray *)z;

+ (jint)addDWordAtWithInt:(jint)len
                 withLong:(jlong)x
             withIntArray:(IOSIntArray *)z
                  withInt:(jint)zPos;

+ (jint)addDWordAtWithInt:(jint)len
                 withLong:(jlong)x
             withIntArray:(IOSIntArray *)z
                  withInt:(jint)zOff
                  withInt:(jint)zPos;

+ (jint)addDWordToWithInt:(jint)len
                 withLong:(jlong)x
             withIntArray:(IOSIntArray *)z;

+ (jint)addDWordToWithInt:(jint)len
                 withLong:(jlong)x
             withIntArray:(IOSIntArray *)z
                  withInt:(jint)zOff;

+ (jint)addToWithInt:(jint)len
        withIntArray:(IOSIntArray *)x
             withInt:(jint)xOff
        withIntArray:(IOSIntArray *)z
             withInt:(jint)zOff;

+ (jint)addToWithInt:(jint)len
        withIntArray:(IOSIntArray *)x
        withIntArray:(IOSIntArray *)z;

+ (jint)addWordAtWithInt:(jint)len
                 withInt:(jint)x
            withIntArray:(IOSIntArray *)z
                 withInt:(jint)zPos;

+ (jint)addWordAtWithInt:(jint)len
                 withInt:(jint)x
            withIntArray:(IOSIntArray *)z
                 withInt:(jint)zOff
                 withInt:(jint)zPos;

+ (jint)addWordToWithInt:(jint)len
                 withInt:(jint)x
            withIntArray:(IOSIntArray *)z;

+ (jint)addWordToWithInt:(jint)len
                 withInt:(jint)x
            withIntArray:(IOSIntArray *)z
                 withInt:(jint)zOff;

+ (jint)caddWithInt:(jint)len
            withInt:(jint)mask
       withIntArray:(IOSIntArray *)x
       withIntArray:(IOSIntArray *)y
       withIntArray:(IOSIntArray *)z;

+ (void)cmovWithInt:(jint)len
            withInt:(jint)mask
       withIntArray:(IOSIntArray *)x
            withInt:(jint)xOff
       withIntArray:(IOSIntArray *)z
            withInt:(jint)zOff;

+ (IOSIntArray *)copy__WithInt:(jint)len
                  withIntArray:(IOSIntArray *)x OBJC_METHOD_FAMILY_NONE;

+ (void)copy__WithInt:(jint)len
         withIntArray:(IOSIntArray *)x
              withInt:(jint)xOff
         withIntArray:(IOSIntArray *)z
              withInt:(jint)zOff OBJC_METHOD_FAMILY_NONE;

+ (void)copy__WithInt:(jint)len
         withIntArray:(IOSIntArray *)x
         withIntArray:(IOSIntArray *)z OBJC_METHOD_FAMILY_NONE;

+ (IOSIntArray *)createWithInt:(jint)len;

+ (IOSLongArray *)create64WithInt:(jint)len;

+ (jint)csubWithInt:(jint)len
            withInt:(jint)mask
       withIntArray:(IOSIntArray *)x
       withIntArray:(IOSIntArray *)y
       withIntArray:(IOSIntArray *)z;

+ (jint)decWithInt:(jint)len
      withIntArray:(IOSIntArray *)z;

+ (jint)decWithInt:(jint)len
      withIntArray:(IOSIntArray *)x
      withIntArray:(IOSIntArray *)z;

+ (jint)decAtWithInt:(jint)len
        withIntArray:(IOSIntArray *)z
             withInt:(jint)zPos;

+ (jint)decAtWithInt:(jint)len
        withIntArray:(IOSIntArray *)z
             withInt:(jint)zOff
             withInt:(jint)zPos;

+ (jboolean)eqWithInt:(jint)len
         withIntArray:(IOSIntArray *)x
         withIntArray:(IOSIntArray *)y;

+ (IOSIntArray *)fromBigIntegerWithInt:(jint)bits
                withJavaMathBigInteger:(JavaMathBigInteger *)x;

+ (jint)getBitWithIntArray:(IOSIntArray *)x
                   withInt:(jint)bit;

+ (jboolean)gteWithInt:(jint)len
          withIntArray:(IOSIntArray *)x
          withIntArray:(IOSIntArray *)y;

+ (jint)incWithInt:(jint)len
      withIntArray:(IOSIntArray *)z;

+ (jint)incWithInt:(jint)len
      withIntArray:(IOSIntArray *)x
      withIntArray:(IOSIntArray *)z;

+ (jint)incAtWithInt:(jint)len
        withIntArray:(IOSIntArray *)z
             withInt:(jint)zPos;

+ (jint)incAtWithInt:(jint)len
        withIntArray:(IOSIntArray *)z
             withInt:(jint)zOff
             withInt:(jint)zPos;

+ (jboolean)isOneWithInt:(jint)len
            withIntArray:(IOSIntArray *)x;

+ (jboolean)isZeroWithInt:(jint)len
             withIntArray:(IOSIntArray *)x;

+ (void)mulWithInt:(jint)len
      withIntArray:(IOSIntArray *)x
           withInt:(jint)xOff
      withIntArray:(IOSIntArray *)y
           withInt:(jint)yOff
      withIntArray:(IOSIntArray *)zz
           withInt:(jint)zzOff;

+ (void)mulWithInt:(jint)len
      withIntArray:(IOSIntArray *)x
      withIntArray:(IOSIntArray *)y
      withIntArray:(IOSIntArray *)zz;

+ (void)mulWithIntArray:(IOSIntArray *)x
                withInt:(jint)xOff
                withInt:(jint)xLen
           withIntArray:(IOSIntArray *)y
                withInt:(jint)yOff
                withInt:(jint)yLen
           withIntArray:(IOSIntArray *)zz
                withInt:(jint)zzOff;

+ (jint)mul31BothAddWithInt:(jint)len
                    withInt:(jint)a
               withIntArray:(IOSIntArray *)x
                    withInt:(jint)b
               withIntArray:(IOSIntArray *)y
               withIntArray:(IOSIntArray *)z
                    withInt:(jint)zOff;

+ (jint)mulAddToWithInt:(jint)len
           withIntArray:(IOSIntArray *)x
                withInt:(jint)xOff
           withIntArray:(IOSIntArray *)y
                withInt:(jint)yOff
           withIntArray:(IOSIntArray *)zz
                withInt:(jint)zzOff;

+ (jint)mulAddToWithInt:(jint)len
           withIntArray:(IOSIntArray *)x
           withIntArray:(IOSIntArray *)y
           withIntArray:(IOSIntArray *)zz;

+ (jint)mulWordWithInt:(jint)len
               withInt:(jint)x
          withIntArray:(IOSIntArray *)y
               withInt:(jint)yOff
          withIntArray:(IOSIntArray *)z
               withInt:(jint)zOff;

+ (jint)mulWordWithInt:(jint)len
               withInt:(jint)x
          withIntArray:(IOSIntArray *)y
          withIntArray:(IOSIntArray *)z;

+ (jint)mulWordAddToWithInt:(jint)len
                    withInt:(jint)x
               withIntArray:(IOSIntArray *)y
                    withInt:(jint)yOff
               withIntArray:(IOSIntArray *)z
                    withInt:(jint)zOff;

+ (jint)mulWordDwordAddAtWithInt:(jint)len
                         withInt:(jint)x
                        withLong:(jlong)y
                    withIntArray:(IOSIntArray *)z
                         withInt:(jint)zPos;

+ (jint)shiftDownBitWithInt:(jint)len
               withIntArray:(IOSIntArray *)z
                    withInt:(jint)c;

+ (jint)shiftDownBitWithInt:(jint)len
               withIntArray:(IOSIntArray *)z
                    withInt:(jint)zOff
                    withInt:(jint)c;

+ (jint)shiftDownBitWithInt:(jint)len
               withIntArray:(IOSIntArray *)x
                    withInt:(jint)xOff
                    withInt:(jint)c
               withIntArray:(IOSIntArray *)z
                    withInt:(jint)zOff;

+ (jint)shiftDownBitWithInt:(jint)len
               withIntArray:(IOSIntArray *)x
                    withInt:(jint)c
               withIntArray:(IOSIntArray *)z;

+ (jint)shiftDownBitsWithInt:(jint)len
                withIntArray:(IOSIntArray *)z
                     withInt:(jint)bits
                     withInt:(jint)c;

+ (jint)shiftDownBitsWithInt:(jint)len
                withIntArray:(IOSIntArray *)z
                     withInt:(jint)zOff
                     withInt:(jint)bits
                     withInt:(jint)c;

+ (jint)shiftDownBitsWithInt:(jint)len
                withIntArray:(IOSIntArray *)x
                     withInt:(jint)xOff
                     withInt:(jint)bits
                     withInt:(jint)c
                withIntArray:(IOSIntArray *)z
                     withInt:(jint)zOff;

+ (jint)shiftDownBitsWithInt:(jint)len
                withIntArray:(IOSIntArray *)x
                     withInt:(jint)bits
                     withInt:(jint)c
                withIntArray:(IOSIntArray *)z;

+ (jint)shiftDownWordWithInt:(jint)len
                withIntArray:(IOSIntArray *)z
                     withInt:(jint)c;

+ (jint)shiftUpBitWithInt:(jint)len
             withIntArray:(IOSIntArray *)z
                  withInt:(jint)c;

+ (jint)shiftUpBitWithInt:(jint)len
             withIntArray:(IOSIntArray *)z
                  withInt:(jint)zOff
                  withInt:(jint)c;

+ (jint)shiftUpBitWithInt:(jint)len
             withIntArray:(IOSIntArray *)x
                  withInt:(jint)xOff
                  withInt:(jint)c
             withIntArray:(IOSIntArray *)z
                  withInt:(jint)zOff;

+ (jint)shiftUpBitWithInt:(jint)len
             withIntArray:(IOSIntArray *)x
                  withInt:(jint)c
             withIntArray:(IOSIntArray *)z;

+ (jlong)shiftUpBit64WithInt:(jint)len
               withLongArray:(IOSLongArray *)x
                     withInt:(jint)xOff
                    withLong:(jlong)c
               withLongArray:(IOSLongArray *)z
                     withInt:(jint)zOff;

+ (jint)shiftUpBitsWithInt:(jint)len
              withIntArray:(IOSIntArray *)z
                   withInt:(jint)bits
                   withInt:(jint)c;

+ (jint)shiftUpBitsWithInt:(jint)len
              withIntArray:(IOSIntArray *)z
                   withInt:(jint)zOff
                   withInt:(jint)bits
                   withInt:(jint)c;

+ (jint)shiftUpBitsWithInt:(jint)len
              withIntArray:(IOSIntArray *)x
                   withInt:(jint)xOff
                   withInt:(jint)bits
                   withInt:(jint)c
              withIntArray:(IOSIntArray *)z
                   withInt:(jint)zOff;

+ (jint)shiftUpBitsWithInt:(jint)len
              withIntArray:(IOSIntArray *)x
                   withInt:(jint)bits
                   withInt:(jint)c
              withIntArray:(IOSIntArray *)z;

+ (jlong)shiftUpBits64WithInt:(jint)len
                withLongArray:(IOSLongArray *)z
                      withInt:(jint)zOff
                      withInt:(jint)bits
                     withLong:(jlong)c;

+ (jlong)shiftUpBits64WithInt:(jint)len
                withLongArray:(IOSLongArray *)x
                      withInt:(jint)xOff
                      withInt:(jint)bits
                     withLong:(jlong)c
                withLongArray:(IOSLongArray *)z
                      withInt:(jint)zOff;

+ (void)squareWithInt:(jint)len
         withIntArray:(IOSIntArray *)x
              withInt:(jint)xOff
         withIntArray:(IOSIntArray *)zz
              withInt:(jint)zzOff;

+ (void)squareWithInt:(jint)len
         withIntArray:(IOSIntArray *)x
         withIntArray:(IOSIntArray *)zz;

+ (jint)squareWordAddWithIntArray:(IOSIntArray *)x
                          withInt:(jint)xOff
                          withInt:(jint)xPos
                     withIntArray:(IOSIntArray *)z
                          withInt:(jint)zOff;

+ (jint)squareWordAddWithIntArray:(IOSIntArray *)x
                          withInt:(jint)xPos
                     withIntArray:(IOSIntArray *)z;

+ (jint)subWithInt:(jint)len
      withIntArray:(IOSIntArray *)x
           withInt:(jint)xOff
      withIntArray:(IOSIntArray *)y
           withInt:(jint)yOff
      withIntArray:(IOSIntArray *)z
           withInt:(jint)zOff;

+ (jint)subWithInt:(jint)len
      withIntArray:(IOSIntArray *)x
      withIntArray:(IOSIntArray *)y
      withIntArray:(IOSIntArray *)z;

+ (jint)sub33AtWithInt:(jint)len
               withInt:(jint)x
          withIntArray:(IOSIntArray *)z
               withInt:(jint)zPos;

+ (jint)sub33AtWithInt:(jint)len
               withInt:(jint)x
          withIntArray:(IOSIntArray *)z
               withInt:(jint)zOff
               withInt:(jint)zPos;

+ (jint)sub33FromWithInt:(jint)len
                 withInt:(jint)x
            withIntArray:(IOSIntArray *)z;

+ (jint)sub33FromWithInt:(jint)len
                 withInt:(jint)x
            withIntArray:(IOSIntArray *)z
                 withInt:(jint)zOff;

+ (jint)subBothFromWithInt:(jint)len
              withIntArray:(IOSIntArray *)x
                   withInt:(jint)xOff
              withIntArray:(IOSIntArray *)y
                   withInt:(jint)yOff
              withIntArray:(IOSIntArray *)z
                   withInt:(jint)zOff;

+ (jint)subBothFromWithInt:(jint)len
              withIntArray:(IOSIntArray *)x
              withIntArray:(IOSIntArray *)y
              withIntArray:(IOSIntArray *)z;

+ (jint)subDWordAtWithInt:(jint)len
                 withLong:(jlong)x
             withIntArray:(IOSIntArray *)z
                  withInt:(jint)zPos;

+ (jint)subDWordAtWithInt:(jint)len
                 withLong:(jlong)x
             withIntArray:(IOSIntArray *)z
                  withInt:(jint)zOff
                  withInt:(jint)zPos;

+ (jint)subDWordFromWithInt:(jint)len
                   withLong:(jlong)x
               withIntArray:(IOSIntArray *)z;

+ (jint)subDWordFromWithInt:(jint)len
                   withLong:(jlong)x
               withIntArray:(IOSIntArray *)z
                    withInt:(jint)zOff;

+ (jint)subFromWithInt:(jint)len
          withIntArray:(IOSIntArray *)x
               withInt:(jint)xOff
          withIntArray:(IOSIntArray *)z
               withInt:(jint)zOff;

+ (jint)subFromWithInt:(jint)len
          withIntArray:(IOSIntArray *)x
          withIntArray:(IOSIntArray *)z;

+ (jint)subWordAtWithInt:(jint)len
                 withInt:(jint)x
            withIntArray:(IOSIntArray *)z
                 withInt:(jint)zPos;

+ (jint)subWordAtWithInt:(jint)len
                 withInt:(jint)x
            withIntArray:(IOSIntArray *)z
                 withInt:(jint)zOff
                 withInt:(jint)zPos;

+ (jint)subWordFromWithInt:(jint)len
                   withInt:(jint)x
              withIntArray:(IOSIntArray *)z;

+ (jint)subWordFromWithInt:(jint)len
                   withInt:(jint)x
              withIntArray:(IOSIntArray *)z
                   withInt:(jint)zOff;

+ (JavaMathBigInteger *)toBigIntegerWithInt:(jint)len
                               withIntArray:(IOSIntArray *)x;

+ (void)zeroWithInt:(jint)len
       withIntArray:(IOSIntArray *)z;

+ (void)zero64WithInt:(jint)len
        withLongArray:(IOSLongArray *)z;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleMathRawNat)

FOUNDATION_EXPORT void LibOrgBouncycastleMathRawNat_init(LibOrgBouncycastleMathRawNat *self);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_addWithInt_withIntArray_withIntArray_withIntArray_(jint len, IOSIntArray *x, IOSIntArray *y, IOSIntArray *z);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_add33AtWithInt_withInt_withIntArray_withInt_(jint len, jint x, IOSIntArray *z, jint zPos);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_add33AtWithInt_withInt_withIntArray_withInt_withInt_(jint len, jint x, IOSIntArray *z, jint zOff, jint zPos);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_add33ToWithInt_withInt_withIntArray_(jint len, jint x, IOSIntArray *z);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_add33ToWithInt_withInt_withIntArray_withInt_(jint len, jint x, IOSIntArray *z, jint zOff);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_addBothToWithInt_withIntArray_withIntArray_withIntArray_(jint len, IOSIntArray *x, IOSIntArray *y, IOSIntArray *z);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_addBothToWithInt_withIntArray_withInt_withIntArray_withInt_withIntArray_withInt_(jint len, IOSIntArray *x, jint xOff, IOSIntArray *y, jint yOff, IOSIntArray *z, jint zOff);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_addDWordAtWithInt_withLong_withIntArray_withInt_(jint len, jlong x, IOSIntArray *z, jint zPos);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_addDWordAtWithInt_withLong_withIntArray_withInt_withInt_(jint len, jlong x, IOSIntArray *z, jint zOff, jint zPos);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_addDWordToWithInt_withLong_withIntArray_(jint len, jlong x, IOSIntArray *z);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_addDWordToWithInt_withLong_withIntArray_withInt_(jint len, jlong x, IOSIntArray *z, jint zOff);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_addToWithInt_withIntArray_withIntArray_(jint len, IOSIntArray *x, IOSIntArray *z);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_addToWithInt_withIntArray_withInt_withIntArray_withInt_(jint len, IOSIntArray *x, jint xOff, IOSIntArray *z, jint zOff);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_addWordAtWithInt_withInt_withIntArray_withInt_(jint len, jint x, IOSIntArray *z, jint zPos);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_addWordAtWithInt_withInt_withIntArray_withInt_withInt_(jint len, jint x, IOSIntArray *z, jint zOff, jint zPos);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_addWordToWithInt_withInt_withIntArray_(jint len, jint x, IOSIntArray *z);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_addWordToWithInt_withInt_withIntArray_withInt_(jint len, jint x, IOSIntArray *z, jint zOff);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_caddWithInt_withInt_withIntArray_withIntArray_withIntArray_(jint len, jint mask, IOSIntArray *x, IOSIntArray *y, IOSIntArray *z);

FOUNDATION_EXPORT void LibOrgBouncycastleMathRawNat_cmovWithInt_withInt_withIntArray_withInt_withIntArray_withInt_(jint len, jint mask, IOSIntArray *x, jint xOff, IOSIntArray *z, jint zOff);

FOUNDATION_EXPORT IOSIntArray *LibOrgBouncycastleMathRawNat_copy__WithInt_withIntArray_(jint len, IOSIntArray *x);

FOUNDATION_EXPORT void LibOrgBouncycastleMathRawNat_copy__WithInt_withIntArray_withIntArray_(jint len, IOSIntArray *x, IOSIntArray *z);

FOUNDATION_EXPORT void LibOrgBouncycastleMathRawNat_copy__WithInt_withIntArray_withInt_withIntArray_withInt_(jint len, IOSIntArray *x, jint xOff, IOSIntArray *z, jint zOff);

FOUNDATION_EXPORT IOSIntArray *LibOrgBouncycastleMathRawNat_createWithInt_(jint len);

FOUNDATION_EXPORT IOSLongArray *LibOrgBouncycastleMathRawNat_create64WithInt_(jint len);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_csubWithInt_withInt_withIntArray_withIntArray_withIntArray_(jint len, jint mask, IOSIntArray *x, IOSIntArray *y, IOSIntArray *z);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_decWithInt_withIntArray_(jint len, IOSIntArray *z);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_decWithInt_withIntArray_withIntArray_(jint len, IOSIntArray *x, IOSIntArray *z);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_decAtWithInt_withIntArray_withInt_(jint len, IOSIntArray *z, jint zPos);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_decAtWithInt_withIntArray_withInt_withInt_(jint len, IOSIntArray *z, jint zOff, jint zPos);

FOUNDATION_EXPORT jboolean LibOrgBouncycastleMathRawNat_eqWithInt_withIntArray_withIntArray_(jint len, IOSIntArray *x, IOSIntArray *y);

FOUNDATION_EXPORT IOSIntArray *LibOrgBouncycastleMathRawNat_fromBigIntegerWithInt_withJavaMathBigInteger_(jint bits, JavaMathBigInteger *x);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_getBitWithIntArray_withInt_(IOSIntArray *x, jint bit);

FOUNDATION_EXPORT jboolean LibOrgBouncycastleMathRawNat_gteWithInt_withIntArray_withIntArray_(jint len, IOSIntArray *x, IOSIntArray *y);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_incWithInt_withIntArray_(jint len, IOSIntArray *z);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_incWithInt_withIntArray_withIntArray_(jint len, IOSIntArray *x, IOSIntArray *z);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_incAtWithInt_withIntArray_withInt_(jint len, IOSIntArray *z, jint zPos);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_incAtWithInt_withIntArray_withInt_withInt_(jint len, IOSIntArray *z, jint zOff, jint zPos);

FOUNDATION_EXPORT jboolean LibOrgBouncycastleMathRawNat_isOneWithInt_withIntArray_(jint len, IOSIntArray *x);

FOUNDATION_EXPORT jboolean LibOrgBouncycastleMathRawNat_isZeroWithInt_withIntArray_(jint len, IOSIntArray *x);

FOUNDATION_EXPORT void LibOrgBouncycastleMathRawNat_mulWithInt_withIntArray_withIntArray_withIntArray_(jint len, IOSIntArray *x, IOSIntArray *y, IOSIntArray *zz);

FOUNDATION_EXPORT void LibOrgBouncycastleMathRawNat_mulWithInt_withIntArray_withInt_withIntArray_withInt_withIntArray_withInt_(jint len, IOSIntArray *x, jint xOff, IOSIntArray *y, jint yOff, IOSIntArray *zz, jint zzOff);

FOUNDATION_EXPORT void LibOrgBouncycastleMathRawNat_mulWithIntArray_withInt_withInt_withIntArray_withInt_withInt_withIntArray_withInt_(IOSIntArray *x, jint xOff, jint xLen, IOSIntArray *y, jint yOff, jint yLen, IOSIntArray *zz, jint zzOff);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_mulAddToWithInt_withIntArray_withIntArray_withIntArray_(jint len, IOSIntArray *x, IOSIntArray *y, IOSIntArray *zz);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_mulAddToWithInt_withIntArray_withInt_withIntArray_withInt_withIntArray_withInt_(jint len, IOSIntArray *x, jint xOff, IOSIntArray *y, jint yOff, IOSIntArray *zz, jint zzOff);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_mul31BothAddWithInt_withInt_withIntArray_withInt_withIntArray_withIntArray_withInt_(jint len, jint a, IOSIntArray *x, jint b, IOSIntArray *y, IOSIntArray *z, jint zOff);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_mulWordWithInt_withInt_withIntArray_withIntArray_(jint len, jint x, IOSIntArray *y, IOSIntArray *z);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_mulWordWithInt_withInt_withIntArray_withInt_withIntArray_withInt_(jint len, jint x, IOSIntArray *y, jint yOff, IOSIntArray *z, jint zOff);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_mulWordAddToWithInt_withInt_withIntArray_withInt_withIntArray_withInt_(jint len, jint x, IOSIntArray *y, jint yOff, IOSIntArray *z, jint zOff);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_mulWordDwordAddAtWithInt_withInt_withLong_withIntArray_withInt_(jint len, jint x, jlong y, IOSIntArray *z, jint zPos);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_shiftDownBitWithInt_withIntArray_withInt_(jint len, IOSIntArray *z, jint c);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_shiftDownBitWithInt_withIntArray_withInt_withInt_(jint len, IOSIntArray *z, jint zOff, jint c);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_shiftDownBitWithInt_withIntArray_withInt_withIntArray_(jint len, IOSIntArray *x, jint c, IOSIntArray *z);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_shiftDownBitWithInt_withIntArray_withInt_withInt_withIntArray_withInt_(jint len, IOSIntArray *x, jint xOff, jint c, IOSIntArray *z, jint zOff);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_shiftDownBitsWithInt_withIntArray_withInt_withInt_(jint len, IOSIntArray *z, jint bits, jint c);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_shiftDownBitsWithInt_withIntArray_withInt_withInt_withInt_(jint len, IOSIntArray *z, jint zOff, jint bits, jint c);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_shiftDownBitsWithInt_withIntArray_withInt_withInt_withIntArray_(jint len, IOSIntArray *x, jint bits, jint c, IOSIntArray *z);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_shiftDownBitsWithInt_withIntArray_withInt_withInt_withInt_withIntArray_withInt_(jint len, IOSIntArray *x, jint xOff, jint bits, jint c, IOSIntArray *z, jint zOff);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_shiftDownWordWithInt_withIntArray_withInt_(jint len, IOSIntArray *z, jint c);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_shiftUpBitWithInt_withIntArray_withInt_(jint len, IOSIntArray *z, jint c);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_shiftUpBitWithInt_withIntArray_withInt_withInt_(jint len, IOSIntArray *z, jint zOff, jint c);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_shiftUpBitWithInt_withIntArray_withInt_withIntArray_(jint len, IOSIntArray *x, jint c, IOSIntArray *z);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_shiftUpBitWithInt_withIntArray_withInt_withInt_withIntArray_withInt_(jint len, IOSIntArray *x, jint xOff, jint c, IOSIntArray *z, jint zOff);

FOUNDATION_EXPORT jlong LibOrgBouncycastleMathRawNat_shiftUpBit64WithInt_withLongArray_withInt_withLong_withLongArray_withInt_(jint len, IOSLongArray *x, jint xOff, jlong c, IOSLongArray *z, jint zOff);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_shiftUpBitsWithInt_withIntArray_withInt_withInt_(jint len, IOSIntArray *z, jint bits, jint c);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_shiftUpBitsWithInt_withIntArray_withInt_withInt_withInt_(jint len, IOSIntArray *z, jint zOff, jint bits, jint c);

FOUNDATION_EXPORT jlong LibOrgBouncycastleMathRawNat_shiftUpBits64WithInt_withLongArray_withInt_withInt_withLong_(jint len, IOSLongArray *z, jint zOff, jint bits, jlong c);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_shiftUpBitsWithInt_withIntArray_withInt_withInt_withIntArray_(jint len, IOSIntArray *x, jint bits, jint c, IOSIntArray *z);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_shiftUpBitsWithInt_withIntArray_withInt_withInt_withInt_withIntArray_withInt_(jint len, IOSIntArray *x, jint xOff, jint bits, jint c, IOSIntArray *z, jint zOff);

FOUNDATION_EXPORT jlong LibOrgBouncycastleMathRawNat_shiftUpBits64WithInt_withLongArray_withInt_withInt_withLong_withLongArray_withInt_(jint len, IOSLongArray *x, jint xOff, jint bits, jlong c, IOSLongArray *z, jint zOff);

FOUNDATION_EXPORT void LibOrgBouncycastleMathRawNat_squareWithInt_withIntArray_withIntArray_(jint len, IOSIntArray *x, IOSIntArray *zz);

FOUNDATION_EXPORT void LibOrgBouncycastleMathRawNat_squareWithInt_withIntArray_withInt_withIntArray_withInt_(jint len, IOSIntArray *x, jint xOff, IOSIntArray *zz, jint zzOff);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_squareWordAddWithIntArray_withInt_withIntArray_(IOSIntArray *x, jint xPos, IOSIntArray *z);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_squareWordAddWithIntArray_withInt_withInt_withIntArray_withInt_(IOSIntArray *x, jint xOff, jint xPos, IOSIntArray *z, jint zOff);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_subWithInt_withIntArray_withIntArray_withIntArray_(jint len, IOSIntArray *x, IOSIntArray *y, IOSIntArray *z);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_subWithInt_withIntArray_withInt_withIntArray_withInt_withIntArray_withInt_(jint len, IOSIntArray *x, jint xOff, IOSIntArray *y, jint yOff, IOSIntArray *z, jint zOff);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_sub33AtWithInt_withInt_withIntArray_withInt_(jint len, jint x, IOSIntArray *z, jint zPos);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_sub33AtWithInt_withInt_withIntArray_withInt_withInt_(jint len, jint x, IOSIntArray *z, jint zOff, jint zPos);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_sub33FromWithInt_withInt_withIntArray_(jint len, jint x, IOSIntArray *z);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_sub33FromWithInt_withInt_withIntArray_withInt_(jint len, jint x, IOSIntArray *z, jint zOff);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_subBothFromWithInt_withIntArray_withIntArray_withIntArray_(jint len, IOSIntArray *x, IOSIntArray *y, IOSIntArray *z);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_subBothFromWithInt_withIntArray_withInt_withIntArray_withInt_withIntArray_withInt_(jint len, IOSIntArray *x, jint xOff, IOSIntArray *y, jint yOff, IOSIntArray *z, jint zOff);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_subDWordAtWithInt_withLong_withIntArray_withInt_(jint len, jlong x, IOSIntArray *z, jint zPos);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_subDWordAtWithInt_withLong_withIntArray_withInt_withInt_(jint len, jlong x, IOSIntArray *z, jint zOff, jint zPos);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_subDWordFromWithInt_withLong_withIntArray_(jint len, jlong x, IOSIntArray *z);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_subDWordFromWithInt_withLong_withIntArray_withInt_(jint len, jlong x, IOSIntArray *z, jint zOff);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_subFromWithInt_withIntArray_withIntArray_(jint len, IOSIntArray *x, IOSIntArray *z);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_subFromWithInt_withIntArray_withInt_withIntArray_withInt_(jint len, IOSIntArray *x, jint xOff, IOSIntArray *z, jint zOff);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_subWordAtWithInt_withInt_withIntArray_withInt_(jint len, jint x, IOSIntArray *z, jint zPos);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_subWordAtWithInt_withInt_withIntArray_withInt_withInt_(jint len, jint x, IOSIntArray *z, jint zOff, jint zPos);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_subWordFromWithInt_withInt_withIntArray_(jint len, jint x, IOSIntArray *z);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathRawNat_subWordFromWithInt_withInt_withIntArray_withInt_(jint len, jint x, IOSIntArray *z, jint zOff);

FOUNDATION_EXPORT JavaMathBigInteger *LibOrgBouncycastleMathRawNat_toBigIntegerWithInt_withIntArray_(jint len, IOSIntArray *x);

FOUNDATION_EXPORT void LibOrgBouncycastleMathRawNat_zeroWithInt_withIntArray_(jint len, IOSIntArray *z);

FOUNDATION_EXPORT void LibOrgBouncycastleMathRawNat_zero64WithInt_withLongArray_(jint len, IOSLongArray *z);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleMathRawNat)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // Nat_H
