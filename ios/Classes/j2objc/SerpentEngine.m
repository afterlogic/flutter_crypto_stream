//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/engines/SerpentEngine.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "Pack.h"
#include "SerpentEngine.h"
#include "SerpentEngineBase.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/System.h"

@implementation LibOrgBouncycastleCryptoEnginesSerpentEngine

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoEnginesSerpentEngine_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (IOSIntArray *)makeWorkingKeyWithByteArray:(IOSByteArray *)key {
  IOSIntArray *kPad = [IOSIntArray newArrayWithLength:16];
  jint off = 0;
  jint length = 0;
  for (off = 0; (off + 4) < ((IOSByteArray *) nil_chk(key))->size_; off += 4) {
    *IOSIntArray_GetRef(kPad, length++) = LibOrgBouncycastleUtilPack_littleEndianToIntWithByteArray_withInt_(key, off);
  }
  if (off % 4 == 0) {
    *IOSIntArray_GetRef(kPad, length++) = LibOrgBouncycastleUtilPack_littleEndianToIntWithByteArray_withInt_(key, off);
    if (length < 8) {
      *IOSIntArray_GetRef(kPad, length) = 1;
    }
  }
  else {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"key must be a multiple of 4 bytes");
  }
  jint amount = (LibOrgBouncycastleCryptoEnginesSerpentEngineBase_ROUNDS + 1) * 4;
  IOSIntArray *w = [IOSIntArray newArrayWithLength:amount];
  for (jint i = 8; i < 16; i++) {
    *IOSIntArray_GetRef(kPad, i) = LibOrgBouncycastleCryptoEnginesSerpentEngineBase_rotateLeftWithInt_withInt_(IOSIntArray_Get(kPad, i - 8) ^ IOSIntArray_Get(kPad, i - 5) ^ IOSIntArray_Get(kPad, i - 3) ^ IOSIntArray_Get(kPad, i - 1) ^ LibOrgBouncycastleCryptoEnginesSerpentEngineBase_PHI ^ (i - 8), 11);
  }
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(kPad, 8, w, 0, 8);
  for (jint i = 8; i < amount; i++) {
    *IOSIntArray_GetRef(w, i) = LibOrgBouncycastleCryptoEnginesSerpentEngineBase_rotateLeftWithInt_withInt_(IOSIntArray_Get(w, i - 8) ^ IOSIntArray_Get(w, i - 5) ^ IOSIntArray_Get(w, i - 3) ^ IOSIntArray_Get(w, i - 1) ^ LibOrgBouncycastleCryptoEnginesSerpentEngineBase_PHI ^ i, 11);
  }
  [self sb3WithInt:IOSIntArray_Get(w, 0) withInt:IOSIntArray_Get(w, 1) withInt:IOSIntArray_Get(w, 2) withInt:IOSIntArray_Get(w, 3)];
  *IOSIntArray_GetRef(w, 0) = X0_;
  *IOSIntArray_GetRef(w, 1) = X1_;
  *IOSIntArray_GetRef(w, 2) = X2_;
  *IOSIntArray_GetRef(w, 3) = X3_;
  [self sb2WithInt:IOSIntArray_Get(w, 4) withInt:IOSIntArray_Get(w, 5) withInt:IOSIntArray_Get(w, 6) withInt:IOSIntArray_Get(w, 7)];
  *IOSIntArray_GetRef(w, 4) = X0_;
  *IOSIntArray_GetRef(w, 5) = X1_;
  *IOSIntArray_GetRef(w, 6) = X2_;
  *IOSIntArray_GetRef(w, 7) = X3_;
  [self sb1WithInt:IOSIntArray_Get(w, 8) withInt:IOSIntArray_Get(w, 9) withInt:IOSIntArray_Get(w, 10) withInt:IOSIntArray_Get(w, 11)];
  *IOSIntArray_GetRef(w, 8) = X0_;
  *IOSIntArray_GetRef(w, 9) = X1_;
  *IOSIntArray_GetRef(w, 10) = X2_;
  *IOSIntArray_GetRef(w, 11) = X3_;
  [self sb0WithInt:IOSIntArray_Get(w, 12) withInt:IOSIntArray_Get(w, 13) withInt:IOSIntArray_Get(w, 14) withInt:IOSIntArray_Get(w, 15)];
  *IOSIntArray_GetRef(w, 12) = X0_;
  *IOSIntArray_GetRef(w, 13) = X1_;
  *IOSIntArray_GetRef(w, 14) = X2_;
  *IOSIntArray_GetRef(w, 15) = X3_;
  [self sb7WithInt:IOSIntArray_Get(w, 16) withInt:IOSIntArray_Get(w, 17) withInt:IOSIntArray_Get(w, 18) withInt:IOSIntArray_Get(w, 19)];
  *IOSIntArray_GetRef(w, 16) = X0_;
  *IOSIntArray_GetRef(w, 17) = X1_;
  *IOSIntArray_GetRef(w, 18) = X2_;
  *IOSIntArray_GetRef(w, 19) = X3_;
  [self sb6WithInt:IOSIntArray_Get(w, 20) withInt:IOSIntArray_Get(w, 21) withInt:IOSIntArray_Get(w, 22) withInt:IOSIntArray_Get(w, 23)];
  *IOSIntArray_GetRef(w, 20) = X0_;
  *IOSIntArray_GetRef(w, 21) = X1_;
  *IOSIntArray_GetRef(w, 22) = X2_;
  *IOSIntArray_GetRef(w, 23) = X3_;
  [self sb5WithInt:IOSIntArray_Get(w, 24) withInt:IOSIntArray_Get(w, 25) withInt:IOSIntArray_Get(w, 26) withInt:IOSIntArray_Get(w, 27)];
  *IOSIntArray_GetRef(w, 24) = X0_;
  *IOSIntArray_GetRef(w, 25) = X1_;
  *IOSIntArray_GetRef(w, 26) = X2_;
  *IOSIntArray_GetRef(w, 27) = X3_;
  [self sb4WithInt:IOSIntArray_Get(w, 28) withInt:IOSIntArray_Get(w, 29) withInt:IOSIntArray_Get(w, 30) withInt:IOSIntArray_Get(w, 31)];
  *IOSIntArray_GetRef(w, 28) = X0_;
  *IOSIntArray_GetRef(w, 29) = X1_;
  *IOSIntArray_GetRef(w, 30) = X2_;
  *IOSIntArray_GetRef(w, 31) = X3_;
  [self sb3WithInt:IOSIntArray_Get(w, 32) withInt:IOSIntArray_Get(w, 33) withInt:IOSIntArray_Get(w, 34) withInt:IOSIntArray_Get(w, 35)];
  *IOSIntArray_GetRef(w, 32) = X0_;
  *IOSIntArray_GetRef(w, 33) = X1_;
  *IOSIntArray_GetRef(w, 34) = X2_;
  *IOSIntArray_GetRef(w, 35) = X3_;
  [self sb2WithInt:IOSIntArray_Get(w, 36) withInt:IOSIntArray_Get(w, 37) withInt:IOSIntArray_Get(w, 38) withInt:IOSIntArray_Get(w, 39)];
  *IOSIntArray_GetRef(w, 36) = X0_;
  *IOSIntArray_GetRef(w, 37) = X1_;
  *IOSIntArray_GetRef(w, 38) = X2_;
  *IOSIntArray_GetRef(w, 39) = X3_;
  [self sb1WithInt:IOSIntArray_Get(w, 40) withInt:IOSIntArray_Get(w, 41) withInt:IOSIntArray_Get(w, 42) withInt:IOSIntArray_Get(w, 43)];
  *IOSIntArray_GetRef(w, 40) = X0_;
  *IOSIntArray_GetRef(w, 41) = X1_;
  *IOSIntArray_GetRef(w, 42) = X2_;
  *IOSIntArray_GetRef(w, 43) = X3_;
  [self sb0WithInt:IOSIntArray_Get(w, 44) withInt:IOSIntArray_Get(w, 45) withInt:IOSIntArray_Get(w, 46) withInt:IOSIntArray_Get(w, 47)];
  *IOSIntArray_GetRef(w, 44) = X0_;
  *IOSIntArray_GetRef(w, 45) = X1_;
  *IOSIntArray_GetRef(w, 46) = X2_;
  *IOSIntArray_GetRef(w, 47) = X3_;
  [self sb7WithInt:IOSIntArray_Get(w, 48) withInt:IOSIntArray_Get(w, 49) withInt:IOSIntArray_Get(w, 50) withInt:IOSIntArray_Get(w, 51)];
  *IOSIntArray_GetRef(w, 48) = X0_;
  *IOSIntArray_GetRef(w, 49) = X1_;
  *IOSIntArray_GetRef(w, 50) = X2_;
  *IOSIntArray_GetRef(w, 51) = X3_;
  [self sb6WithInt:IOSIntArray_Get(w, 52) withInt:IOSIntArray_Get(w, 53) withInt:IOSIntArray_Get(w, 54) withInt:IOSIntArray_Get(w, 55)];
  *IOSIntArray_GetRef(w, 52) = X0_;
  *IOSIntArray_GetRef(w, 53) = X1_;
  *IOSIntArray_GetRef(w, 54) = X2_;
  *IOSIntArray_GetRef(w, 55) = X3_;
  [self sb5WithInt:IOSIntArray_Get(w, 56) withInt:IOSIntArray_Get(w, 57) withInt:IOSIntArray_Get(w, 58) withInt:IOSIntArray_Get(w, 59)];
  *IOSIntArray_GetRef(w, 56) = X0_;
  *IOSIntArray_GetRef(w, 57) = X1_;
  *IOSIntArray_GetRef(w, 58) = X2_;
  *IOSIntArray_GetRef(w, 59) = X3_;
  [self sb4WithInt:IOSIntArray_Get(w, 60) withInt:IOSIntArray_Get(w, 61) withInt:IOSIntArray_Get(w, 62) withInt:IOSIntArray_Get(w, 63)];
  *IOSIntArray_GetRef(w, 60) = X0_;
  *IOSIntArray_GetRef(w, 61) = X1_;
  *IOSIntArray_GetRef(w, 62) = X2_;
  *IOSIntArray_GetRef(w, 63) = X3_;
  [self sb3WithInt:IOSIntArray_Get(w, 64) withInt:IOSIntArray_Get(w, 65) withInt:IOSIntArray_Get(w, 66) withInt:IOSIntArray_Get(w, 67)];
  *IOSIntArray_GetRef(w, 64) = X0_;
  *IOSIntArray_GetRef(w, 65) = X1_;
  *IOSIntArray_GetRef(w, 66) = X2_;
  *IOSIntArray_GetRef(w, 67) = X3_;
  [self sb2WithInt:IOSIntArray_Get(w, 68) withInt:IOSIntArray_Get(w, 69) withInt:IOSIntArray_Get(w, 70) withInt:IOSIntArray_Get(w, 71)];
  *IOSIntArray_GetRef(w, 68) = X0_;
  *IOSIntArray_GetRef(w, 69) = X1_;
  *IOSIntArray_GetRef(w, 70) = X2_;
  *IOSIntArray_GetRef(w, 71) = X3_;
  [self sb1WithInt:IOSIntArray_Get(w, 72) withInt:IOSIntArray_Get(w, 73) withInt:IOSIntArray_Get(w, 74) withInt:IOSIntArray_Get(w, 75)];
  *IOSIntArray_GetRef(w, 72) = X0_;
  *IOSIntArray_GetRef(w, 73) = X1_;
  *IOSIntArray_GetRef(w, 74) = X2_;
  *IOSIntArray_GetRef(w, 75) = X3_;
  [self sb0WithInt:IOSIntArray_Get(w, 76) withInt:IOSIntArray_Get(w, 77) withInt:IOSIntArray_Get(w, 78) withInt:IOSIntArray_Get(w, 79)];
  *IOSIntArray_GetRef(w, 76) = X0_;
  *IOSIntArray_GetRef(w, 77) = X1_;
  *IOSIntArray_GetRef(w, 78) = X2_;
  *IOSIntArray_GetRef(w, 79) = X3_;
  [self sb7WithInt:IOSIntArray_Get(w, 80) withInt:IOSIntArray_Get(w, 81) withInt:IOSIntArray_Get(w, 82) withInt:IOSIntArray_Get(w, 83)];
  *IOSIntArray_GetRef(w, 80) = X0_;
  *IOSIntArray_GetRef(w, 81) = X1_;
  *IOSIntArray_GetRef(w, 82) = X2_;
  *IOSIntArray_GetRef(w, 83) = X3_;
  [self sb6WithInt:IOSIntArray_Get(w, 84) withInt:IOSIntArray_Get(w, 85) withInt:IOSIntArray_Get(w, 86) withInt:IOSIntArray_Get(w, 87)];
  *IOSIntArray_GetRef(w, 84) = X0_;
  *IOSIntArray_GetRef(w, 85) = X1_;
  *IOSIntArray_GetRef(w, 86) = X2_;
  *IOSIntArray_GetRef(w, 87) = X3_;
  [self sb5WithInt:IOSIntArray_Get(w, 88) withInt:IOSIntArray_Get(w, 89) withInt:IOSIntArray_Get(w, 90) withInt:IOSIntArray_Get(w, 91)];
  *IOSIntArray_GetRef(w, 88) = X0_;
  *IOSIntArray_GetRef(w, 89) = X1_;
  *IOSIntArray_GetRef(w, 90) = X2_;
  *IOSIntArray_GetRef(w, 91) = X3_;
  [self sb4WithInt:IOSIntArray_Get(w, 92) withInt:IOSIntArray_Get(w, 93) withInt:IOSIntArray_Get(w, 94) withInt:IOSIntArray_Get(w, 95)];
  *IOSIntArray_GetRef(w, 92) = X0_;
  *IOSIntArray_GetRef(w, 93) = X1_;
  *IOSIntArray_GetRef(w, 94) = X2_;
  *IOSIntArray_GetRef(w, 95) = X3_;
  [self sb3WithInt:IOSIntArray_Get(w, 96) withInt:IOSIntArray_Get(w, 97) withInt:IOSIntArray_Get(w, 98) withInt:IOSIntArray_Get(w, 99)];
  *IOSIntArray_GetRef(w, 96) = X0_;
  *IOSIntArray_GetRef(w, 97) = X1_;
  *IOSIntArray_GetRef(w, 98) = X2_;
  *IOSIntArray_GetRef(w, 99) = X3_;
  [self sb2WithInt:IOSIntArray_Get(w, 100) withInt:IOSIntArray_Get(w, 101) withInt:IOSIntArray_Get(w, 102) withInt:IOSIntArray_Get(w, 103)];
  *IOSIntArray_GetRef(w, 100) = X0_;
  *IOSIntArray_GetRef(w, 101) = X1_;
  *IOSIntArray_GetRef(w, 102) = X2_;
  *IOSIntArray_GetRef(w, 103) = X3_;
  [self sb1WithInt:IOSIntArray_Get(w, 104) withInt:IOSIntArray_Get(w, 105) withInt:IOSIntArray_Get(w, 106) withInt:IOSIntArray_Get(w, 107)];
  *IOSIntArray_GetRef(w, 104) = X0_;
  *IOSIntArray_GetRef(w, 105) = X1_;
  *IOSIntArray_GetRef(w, 106) = X2_;
  *IOSIntArray_GetRef(w, 107) = X3_;
  [self sb0WithInt:IOSIntArray_Get(w, 108) withInt:IOSIntArray_Get(w, 109) withInt:IOSIntArray_Get(w, 110) withInt:IOSIntArray_Get(w, 111)];
  *IOSIntArray_GetRef(w, 108) = X0_;
  *IOSIntArray_GetRef(w, 109) = X1_;
  *IOSIntArray_GetRef(w, 110) = X2_;
  *IOSIntArray_GetRef(w, 111) = X3_;
  [self sb7WithInt:IOSIntArray_Get(w, 112) withInt:IOSIntArray_Get(w, 113) withInt:IOSIntArray_Get(w, 114) withInt:IOSIntArray_Get(w, 115)];
  *IOSIntArray_GetRef(w, 112) = X0_;
  *IOSIntArray_GetRef(w, 113) = X1_;
  *IOSIntArray_GetRef(w, 114) = X2_;
  *IOSIntArray_GetRef(w, 115) = X3_;
  [self sb6WithInt:IOSIntArray_Get(w, 116) withInt:IOSIntArray_Get(w, 117) withInt:IOSIntArray_Get(w, 118) withInt:IOSIntArray_Get(w, 119)];
  *IOSIntArray_GetRef(w, 116) = X0_;
  *IOSIntArray_GetRef(w, 117) = X1_;
  *IOSIntArray_GetRef(w, 118) = X2_;
  *IOSIntArray_GetRef(w, 119) = X3_;
  [self sb5WithInt:IOSIntArray_Get(w, 120) withInt:IOSIntArray_Get(w, 121) withInt:IOSIntArray_Get(w, 122) withInt:IOSIntArray_Get(w, 123)];
  *IOSIntArray_GetRef(w, 120) = X0_;
  *IOSIntArray_GetRef(w, 121) = X1_;
  *IOSIntArray_GetRef(w, 122) = X2_;
  *IOSIntArray_GetRef(w, 123) = X3_;
  [self sb4WithInt:IOSIntArray_Get(w, 124) withInt:IOSIntArray_Get(w, 125) withInt:IOSIntArray_Get(w, 126) withInt:IOSIntArray_Get(w, 127)];
  *IOSIntArray_GetRef(w, 124) = X0_;
  *IOSIntArray_GetRef(w, 125) = X1_;
  *IOSIntArray_GetRef(w, 126) = X2_;
  *IOSIntArray_GetRef(w, 127) = X3_;
  [self sb3WithInt:IOSIntArray_Get(w, 128) withInt:IOSIntArray_Get(w, 129) withInt:IOSIntArray_Get(w, 130) withInt:IOSIntArray_Get(w, 131)];
  *IOSIntArray_GetRef(w, 128) = X0_;
  *IOSIntArray_GetRef(w, 129) = X1_;
  *IOSIntArray_GetRef(w, 130) = X2_;
  *IOSIntArray_GetRef(w, 131) = X3_;
  return w;
}

- (void)encryptBlockWithByteArray:(IOSByteArray *)input
                          withInt:(jint)inOff
                    withByteArray:(IOSByteArray *)output
                          withInt:(jint)outOff {
  X0_ = LibOrgBouncycastleUtilPack_littleEndianToIntWithByteArray_withInt_(input, inOff);
  X1_ = LibOrgBouncycastleUtilPack_littleEndianToIntWithByteArray_withInt_(input, inOff + 4);
  X2_ = LibOrgBouncycastleUtilPack_littleEndianToIntWithByteArray_withInt_(input, inOff + 8);
  X3_ = LibOrgBouncycastleUtilPack_littleEndianToIntWithByteArray_withInt_(input, inOff + 12);
  [self sb0WithInt:IOSIntArray_Get(nil_chk(wKey_), 0) ^ X0_ withInt:IOSIntArray_Get(wKey_, 1) ^ X1_ withInt:IOSIntArray_Get(wKey_, 2) ^ X2_ withInt:IOSIntArray_Get(wKey_, 3) ^ X3_];
  [self LT];
  [self sb1WithInt:IOSIntArray_Get(nil_chk(wKey_), 4) ^ X0_ withInt:IOSIntArray_Get(wKey_, 5) ^ X1_ withInt:IOSIntArray_Get(wKey_, 6) ^ X2_ withInt:IOSIntArray_Get(wKey_, 7) ^ X3_];
  [self LT];
  [self sb2WithInt:IOSIntArray_Get(nil_chk(wKey_), 8) ^ X0_ withInt:IOSIntArray_Get(wKey_, 9) ^ X1_ withInt:IOSIntArray_Get(wKey_, 10) ^ X2_ withInt:IOSIntArray_Get(wKey_, 11) ^ X3_];
  [self LT];
  [self sb3WithInt:IOSIntArray_Get(nil_chk(wKey_), 12) ^ X0_ withInt:IOSIntArray_Get(wKey_, 13) ^ X1_ withInt:IOSIntArray_Get(wKey_, 14) ^ X2_ withInt:IOSIntArray_Get(wKey_, 15) ^ X3_];
  [self LT];
  [self sb4WithInt:IOSIntArray_Get(nil_chk(wKey_), 16) ^ X0_ withInt:IOSIntArray_Get(wKey_, 17) ^ X1_ withInt:IOSIntArray_Get(wKey_, 18) ^ X2_ withInt:IOSIntArray_Get(wKey_, 19) ^ X3_];
  [self LT];
  [self sb5WithInt:IOSIntArray_Get(nil_chk(wKey_), 20) ^ X0_ withInt:IOSIntArray_Get(wKey_, 21) ^ X1_ withInt:IOSIntArray_Get(wKey_, 22) ^ X2_ withInt:IOSIntArray_Get(wKey_, 23) ^ X3_];
  [self LT];
  [self sb6WithInt:IOSIntArray_Get(nil_chk(wKey_), 24) ^ X0_ withInt:IOSIntArray_Get(wKey_, 25) ^ X1_ withInt:IOSIntArray_Get(wKey_, 26) ^ X2_ withInt:IOSIntArray_Get(wKey_, 27) ^ X3_];
  [self LT];
  [self sb7WithInt:IOSIntArray_Get(nil_chk(wKey_), 28) ^ X0_ withInt:IOSIntArray_Get(wKey_, 29) ^ X1_ withInt:IOSIntArray_Get(wKey_, 30) ^ X2_ withInt:IOSIntArray_Get(wKey_, 31) ^ X3_];
  [self LT];
  [self sb0WithInt:IOSIntArray_Get(nil_chk(wKey_), 32) ^ X0_ withInt:IOSIntArray_Get(wKey_, 33) ^ X1_ withInt:IOSIntArray_Get(wKey_, 34) ^ X2_ withInt:IOSIntArray_Get(wKey_, 35) ^ X3_];
  [self LT];
  [self sb1WithInt:IOSIntArray_Get(nil_chk(wKey_), 36) ^ X0_ withInt:IOSIntArray_Get(wKey_, 37) ^ X1_ withInt:IOSIntArray_Get(wKey_, 38) ^ X2_ withInt:IOSIntArray_Get(wKey_, 39) ^ X3_];
  [self LT];
  [self sb2WithInt:IOSIntArray_Get(nil_chk(wKey_), 40) ^ X0_ withInt:IOSIntArray_Get(wKey_, 41) ^ X1_ withInt:IOSIntArray_Get(wKey_, 42) ^ X2_ withInt:IOSIntArray_Get(wKey_, 43) ^ X3_];
  [self LT];
  [self sb3WithInt:IOSIntArray_Get(nil_chk(wKey_), 44) ^ X0_ withInt:IOSIntArray_Get(wKey_, 45) ^ X1_ withInt:IOSIntArray_Get(wKey_, 46) ^ X2_ withInt:IOSIntArray_Get(wKey_, 47) ^ X3_];
  [self LT];
  [self sb4WithInt:IOSIntArray_Get(nil_chk(wKey_), 48) ^ X0_ withInt:IOSIntArray_Get(wKey_, 49) ^ X1_ withInt:IOSIntArray_Get(wKey_, 50) ^ X2_ withInt:IOSIntArray_Get(wKey_, 51) ^ X3_];
  [self LT];
  [self sb5WithInt:IOSIntArray_Get(nil_chk(wKey_), 52) ^ X0_ withInt:IOSIntArray_Get(wKey_, 53) ^ X1_ withInt:IOSIntArray_Get(wKey_, 54) ^ X2_ withInt:IOSIntArray_Get(wKey_, 55) ^ X3_];
  [self LT];
  [self sb6WithInt:IOSIntArray_Get(nil_chk(wKey_), 56) ^ X0_ withInt:IOSIntArray_Get(wKey_, 57) ^ X1_ withInt:IOSIntArray_Get(wKey_, 58) ^ X2_ withInt:IOSIntArray_Get(wKey_, 59) ^ X3_];
  [self LT];
  [self sb7WithInt:IOSIntArray_Get(nil_chk(wKey_), 60) ^ X0_ withInt:IOSIntArray_Get(wKey_, 61) ^ X1_ withInt:IOSIntArray_Get(wKey_, 62) ^ X2_ withInt:IOSIntArray_Get(wKey_, 63) ^ X3_];
  [self LT];
  [self sb0WithInt:IOSIntArray_Get(nil_chk(wKey_), 64) ^ X0_ withInt:IOSIntArray_Get(wKey_, 65) ^ X1_ withInt:IOSIntArray_Get(wKey_, 66) ^ X2_ withInt:IOSIntArray_Get(wKey_, 67) ^ X3_];
  [self LT];
  [self sb1WithInt:IOSIntArray_Get(nil_chk(wKey_), 68) ^ X0_ withInt:IOSIntArray_Get(wKey_, 69) ^ X1_ withInt:IOSIntArray_Get(wKey_, 70) ^ X2_ withInt:IOSIntArray_Get(wKey_, 71) ^ X3_];
  [self LT];
  [self sb2WithInt:IOSIntArray_Get(nil_chk(wKey_), 72) ^ X0_ withInt:IOSIntArray_Get(wKey_, 73) ^ X1_ withInt:IOSIntArray_Get(wKey_, 74) ^ X2_ withInt:IOSIntArray_Get(wKey_, 75) ^ X3_];
  [self LT];
  [self sb3WithInt:IOSIntArray_Get(nil_chk(wKey_), 76) ^ X0_ withInt:IOSIntArray_Get(wKey_, 77) ^ X1_ withInt:IOSIntArray_Get(wKey_, 78) ^ X2_ withInt:IOSIntArray_Get(wKey_, 79) ^ X3_];
  [self LT];
  [self sb4WithInt:IOSIntArray_Get(nil_chk(wKey_), 80) ^ X0_ withInt:IOSIntArray_Get(wKey_, 81) ^ X1_ withInt:IOSIntArray_Get(wKey_, 82) ^ X2_ withInt:IOSIntArray_Get(wKey_, 83) ^ X3_];
  [self LT];
  [self sb5WithInt:IOSIntArray_Get(nil_chk(wKey_), 84) ^ X0_ withInt:IOSIntArray_Get(wKey_, 85) ^ X1_ withInt:IOSIntArray_Get(wKey_, 86) ^ X2_ withInt:IOSIntArray_Get(wKey_, 87) ^ X3_];
  [self LT];
  [self sb6WithInt:IOSIntArray_Get(nil_chk(wKey_), 88) ^ X0_ withInt:IOSIntArray_Get(wKey_, 89) ^ X1_ withInt:IOSIntArray_Get(wKey_, 90) ^ X2_ withInt:IOSIntArray_Get(wKey_, 91) ^ X3_];
  [self LT];
  [self sb7WithInt:IOSIntArray_Get(nil_chk(wKey_), 92) ^ X0_ withInt:IOSIntArray_Get(wKey_, 93) ^ X1_ withInt:IOSIntArray_Get(wKey_, 94) ^ X2_ withInt:IOSIntArray_Get(wKey_, 95) ^ X3_];
  [self LT];
  [self sb0WithInt:IOSIntArray_Get(nil_chk(wKey_), 96) ^ X0_ withInt:IOSIntArray_Get(wKey_, 97) ^ X1_ withInt:IOSIntArray_Get(wKey_, 98) ^ X2_ withInt:IOSIntArray_Get(wKey_, 99) ^ X3_];
  [self LT];
  [self sb1WithInt:IOSIntArray_Get(nil_chk(wKey_), 100) ^ X0_ withInt:IOSIntArray_Get(wKey_, 101) ^ X1_ withInt:IOSIntArray_Get(wKey_, 102) ^ X2_ withInt:IOSIntArray_Get(wKey_, 103) ^ X3_];
  [self LT];
  [self sb2WithInt:IOSIntArray_Get(nil_chk(wKey_), 104) ^ X0_ withInt:IOSIntArray_Get(wKey_, 105) ^ X1_ withInt:IOSIntArray_Get(wKey_, 106) ^ X2_ withInt:IOSIntArray_Get(wKey_, 107) ^ X3_];
  [self LT];
  [self sb3WithInt:IOSIntArray_Get(nil_chk(wKey_), 108) ^ X0_ withInt:IOSIntArray_Get(wKey_, 109) ^ X1_ withInt:IOSIntArray_Get(wKey_, 110) ^ X2_ withInt:IOSIntArray_Get(wKey_, 111) ^ X3_];
  [self LT];
  [self sb4WithInt:IOSIntArray_Get(nil_chk(wKey_), 112) ^ X0_ withInt:IOSIntArray_Get(wKey_, 113) ^ X1_ withInt:IOSIntArray_Get(wKey_, 114) ^ X2_ withInt:IOSIntArray_Get(wKey_, 115) ^ X3_];
  [self LT];
  [self sb5WithInt:IOSIntArray_Get(nil_chk(wKey_), 116) ^ X0_ withInt:IOSIntArray_Get(wKey_, 117) ^ X1_ withInt:IOSIntArray_Get(wKey_, 118) ^ X2_ withInt:IOSIntArray_Get(wKey_, 119) ^ X3_];
  [self LT];
  [self sb6WithInt:IOSIntArray_Get(nil_chk(wKey_), 120) ^ X0_ withInt:IOSIntArray_Get(wKey_, 121) ^ X1_ withInt:IOSIntArray_Get(wKey_, 122) ^ X2_ withInt:IOSIntArray_Get(wKey_, 123) ^ X3_];
  [self LT];
  [self sb7WithInt:IOSIntArray_Get(nil_chk(wKey_), 124) ^ X0_ withInt:IOSIntArray_Get(wKey_, 125) ^ X1_ withInt:IOSIntArray_Get(wKey_, 126) ^ X2_ withInt:IOSIntArray_Get(wKey_, 127) ^ X3_];
  LibOrgBouncycastleUtilPack_intToLittleEndianWithInt_withByteArray_withInt_(IOSIntArray_Get(nil_chk(wKey_), 128) ^ X0_, output, outOff);
  LibOrgBouncycastleUtilPack_intToLittleEndianWithInt_withByteArray_withInt_(IOSIntArray_Get(nil_chk(wKey_), 129) ^ X1_, output, outOff + 4);
  LibOrgBouncycastleUtilPack_intToLittleEndianWithInt_withByteArray_withInt_(IOSIntArray_Get(nil_chk(wKey_), 130) ^ X2_, output, outOff + 8);
  LibOrgBouncycastleUtilPack_intToLittleEndianWithInt_withByteArray_withInt_(IOSIntArray_Get(nil_chk(wKey_), 131) ^ X3_, output, outOff + 12);
}

- (void)decryptBlockWithByteArray:(IOSByteArray *)input
                          withInt:(jint)inOff
                    withByteArray:(IOSByteArray *)output
                          withInt:(jint)outOff {
  X0_ = IOSIntArray_Get(nil_chk(wKey_), 128) ^ LibOrgBouncycastleUtilPack_littleEndianToIntWithByteArray_withInt_(input, inOff);
  X1_ = IOSIntArray_Get(nil_chk(wKey_), 129) ^ LibOrgBouncycastleUtilPack_littleEndianToIntWithByteArray_withInt_(input, inOff + 4);
  X2_ = IOSIntArray_Get(nil_chk(wKey_), 130) ^ LibOrgBouncycastleUtilPack_littleEndianToIntWithByteArray_withInt_(input, inOff + 8);
  X3_ = IOSIntArray_Get(nil_chk(wKey_), 131) ^ LibOrgBouncycastleUtilPack_littleEndianToIntWithByteArray_withInt_(input, inOff + 12);
  [self ib7WithInt:X0_ withInt:X1_ withInt:X2_ withInt:X3_];
  X0_ ^= IOSIntArray_Get(nil_chk(wKey_), 124);
  X1_ ^= IOSIntArray_Get(wKey_, 125);
  X2_ ^= IOSIntArray_Get(wKey_, 126);
  X3_ ^= IOSIntArray_Get(wKey_, 127);
  [self inverseLT];
  [self ib6WithInt:X0_ withInt:X1_ withInt:X2_ withInt:X3_];
  X0_ ^= IOSIntArray_Get(nil_chk(wKey_), 120);
  X1_ ^= IOSIntArray_Get(wKey_, 121);
  X2_ ^= IOSIntArray_Get(wKey_, 122);
  X3_ ^= IOSIntArray_Get(wKey_, 123);
  [self inverseLT];
  [self ib5WithInt:X0_ withInt:X1_ withInt:X2_ withInt:X3_];
  X0_ ^= IOSIntArray_Get(nil_chk(wKey_), 116);
  X1_ ^= IOSIntArray_Get(wKey_, 117);
  X2_ ^= IOSIntArray_Get(wKey_, 118);
  X3_ ^= IOSIntArray_Get(wKey_, 119);
  [self inverseLT];
  [self ib4WithInt:X0_ withInt:X1_ withInt:X2_ withInt:X3_];
  X0_ ^= IOSIntArray_Get(nil_chk(wKey_), 112);
  X1_ ^= IOSIntArray_Get(wKey_, 113);
  X2_ ^= IOSIntArray_Get(wKey_, 114);
  X3_ ^= IOSIntArray_Get(wKey_, 115);
  [self inverseLT];
  [self ib3WithInt:X0_ withInt:X1_ withInt:X2_ withInt:X3_];
  X0_ ^= IOSIntArray_Get(nil_chk(wKey_), 108);
  X1_ ^= IOSIntArray_Get(wKey_, 109);
  X2_ ^= IOSIntArray_Get(wKey_, 110);
  X3_ ^= IOSIntArray_Get(wKey_, 111);
  [self inverseLT];
  [self ib2WithInt:X0_ withInt:X1_ withInt:X2_ withInt:X3_];
  X0_ ^= IOSIntArray_Get(nil_chk(wKey_), 104);
  X1_ ^= IOSIntArray_Get(wKey_, 105);
  X2_ ^= IOSIntArray_Get(wKey_, 106);
  X3_ ^= IOSIntArray_Get(wKey_, 107);
  [self inverseLT];
  [self ib1WithInt:X0_ withInt:X1_ withInt:X2_ withInt:X3_];
  X0_ ^= IOSIntArray_Get(nil_chk(wKey_), 100);
  X1_ ^= IOSIntArray_Get(wKey_, 101);
  X2_ ^= IOSIntArray_Get(wKey_, 102);
  X3_ ^= IOSIntArray_Get(wKey_, 103);
  [self inverseLT];
  [self ib0WithInt:X0_ withInt:X1_ withInt:X2_ withInt:X3_];
  X0_ ^= IOSIntArray_Get(nil_chk(wKey_), 96);
  X1_ ^= IOSIntArray_Get(wKey_, 97);
  X2_ ^= IOSIntArray_Get(wKey_, 98);
  X3_ ^= IOSIntArray_Get(wKey_, 99);
  [self inverseLT];
  [self ib7WithInt:X0_ withInt:X1_ withInt:X2_ withInt:X3_];
  X0_ ^= IOSIntArray_Get(nil_chk(wKey_), 92);
  X1_ ^= IOSIntArray_Get(wKey_, 93);
  X2_ ^= IOSIntArray_Get(wKey_, 94);
  X3_ ^= IOSIntArray_Get(wKey_, 95);
  [self inverseLT];
  [self ib6WithInt:X0_ withInt:X1_ withInt:X2_ withInt:X3_];
  X0_ ^= IOSIntArray_Get(nil_chk(wKey_), 88);
  X1_ ^= IOSIntArray_Get(wKey_, 89);
  X2_ ^= IOSIntArray_Get(wKey_, 90);
  X3_ ^= IOSIntArray_Get(wKey_, 91);
  [self inverseLT];
  [self ib5WithInt:X0_ withInt:X1_ withInt:X2_ withInt:X3_];
  X0_ ^= IOSIntArray_Get(nil_chk(wKey_), 84);
  X1_ ^= IOSIntArray_Get(wKey_, 85);
  X2_ ^= IOSIntArray_Get(wKey_, 86);
  X3_ ^= IOSIntArray_Get(wKey_, 87);
  [self inverseLT];
  [self ib4WithInt:X0_ withInt:X1_ withInt:X2_ withInt:X3_];
  X0_ ^= IOSIntArray_Get(nil_chk(wKey_), 80);
  X1_ ^= IOSIntArray_Get(wKey_, 81);
  X2_ ^= IOSIntArray_Get(wKey_, 82);
  X3_ ^= IOSIntArray_Get(wKey_, 83);
  [self inverseLT];
  [self ib3WithInt:X0_ withInt:X1_ withInt:X2_ withInt:X3_];
  X0_ ^= IOSIntArray_Get(nil_chk(wKey_), 76);
  X1_ ^= IOSIntArray_Get(wKey_, 77);
  X2_ ^= IOSIntArray_Get(wKey_, 78);
  X3_ ^= IOSIntArray_Get(wKey_, 79);
  [self inverseLT];
  [self ib2WithInt:X0_ withInt:X1_ withInt:X2_ withInt:X3_];
  X0_ ^= IOSIntArray_Get(nil_chk(wKey_), 72);
  X1_ ^= IOSIntArray_Get(wKey_, 73);
  X2_ ^= IOSIntArray_Get(wKey_, 74);
  X3_ ^= IOSIntArray_Get(wKey_, 75);
  [self inverseLT];
  [self ib1WithInt:X0_ withInt:X1_ withInt:X2_ withInt:X3_];
  X0_ ^= IOSIntArray_Get(nil_chk(wKey_), 68);
  X1_ ^= IOSIntArray_Get(wKey_, 69);
  X2_ ^= IOSIntArray_Get(wKey_, 70);
  X3_ ^= IOSIntArray_Get(wKey_, 71);
  [self inverseLT];
  [self ib0WithInt:X0_ withInt:X1_ withInt:X2_ withInt:X3_];
  X0_ ^= IOSIntArray_Get(nil_chk(wKey_), 64);
  X1_ ^= IOSIntArray_Get(wKey_, 65);
  X2_ ^= IOSIntArray_Get(wKey_, 66);
  X3_ ^= IOSIntArray_Get(wKey_, 67);
  [self inverseLT];
  [self ib7WithInt:X0_ withInt:X1_ withInt:X2_ withInt:X3_];
  X0_ ^= IOSIntArray_Get(nil_chk(wKey_), 60);
  X1_ ^= IOSIntArray_Get(wKey_, 61);
  X2_ ^= IOSIntArray_Get(wKey_, 62);
  X3_ ^= IOSIntArray_Get(wKey_, 63);
  [self inverseLT];
  [self ib6WithInt:X0_ withInt:X1_ withInt:X2_ withInt:X3_];
  X0_ ^= IOSIntArray_Get(nil_chk(wKey_), 56);
  X1_ ^= IOSIntArray_Get(wKey_, 57);
  X2_ ^= IOSIntArray_Get(wKey_, 58);
  X3_ ^= IOSIntArray_Get(wKey_, 59);
  [self inverseLT];
  [self ib5WithInt:X0_ withInt:X1_ withInt:X2_ withInt:X3_];
  X0_ ^= IOSIntArray_Get(nil_chk(wKey_), 52);
  X1_ ^= IOSIntArray_Get(wKey_, 53);
  X2_ ^= IOSIntArray_Get(wKey_, 54);
  X3_ ^= IOSIntArray_Get(wKey_, 55);
  [self inverseLT];
  [self ib4WithInt:X0_ withInt:X1_ withInt:X2_ withInt:X3_];
  X0_ ^= IOSIntArray_Get(nil_chk(wKey_), 48);
  X1_ ^= IOSIntArray_Get(wKey_, 49);
  X2_ ^= IOSIntArray_Get(wKey_, 50);
  X3_ ^= IOSIntArray_Get(wKey_, 51);
  [self inverseLT];
  [self ib3WithInt:X0_ withInt:X1_ withInt:X2_ withInt:X3_];
  X0_ ^= IOSIntArray_Get(nil_chk(wKey_), 44);
  X1_ ^= IOSIntArray_Get(wKey_, 45);
  X2_ ^= IOSIntArray_Get(wKey_, 46);
  X3_ ^= IOSIntArray_Get(wKey_, 47);
  [self inverseLT];
  [self ib2WithInt:X0_ withInt:X1_ withInt:X2_ withInt:X3_];
  X0_ ^= IOSIntArray_Get(nil_chk(wKey_), 40);
  X1_ ^= IOSIntArray_Get(wKey_, 41);
  X2_ ^= IOSIntArray_Get(wKey_, 42);
  X3_ ^= IOSIntArray_Get(wKey_, 43);
  [self inverseLT];
  [self ib1WithInt:X0_ withInt:X1_ withInt:X2_ withInt:X3_];
  X0_ ^= IOSIntArray_Get(nil_chk(wKey_), 36);
  X1_ ^= IOSIntArray_Get(wKey_, 37);
  X2_ ^= IOSIntArray_Get(wKey_, 38);
  X3_ ^= IOSIntArray_Get(wKey_, 39);
  [self inverseLT];
  [self ib0WithInt:X0_ withInt:X1_ withInt:X2_ withInt:X3_];
  X0_ ^= IOSIntArray_Get(nil_chk(wKey_), 32);
  X1_ ^= IOSIntArray_Get(wKey_, 33);
  X2_ ^= IOSIntArray_Get(wKey_, 34);
  X3_ ^= IOSIntArray_Get(wKey_, 35);
  [self inverseLT];
  [self ib7WithInt:X0_ withInt:X1_ withInt:X2_ withInt:X3_];
  X0_ ^= IOSIntArray_Get(nil_chk(wKey_), 28);
  X1_ ^= IOSIntArray_Get(wKey_, 29);
  X2_ ^= IOSIntArray_Get(wKey_, 30);
  X3_ ^= IOSIntArray_Get(wKey_, 31);
  [self inverseLT];
  [self ib6WithInt:X0_ withInt:X1_ withInt:X2_ withInt:X3_];
  X0_ ^= IOSIntArray_Get(nil_chk(wKey_), 24);
  X1_ ^= IOSIntArray_Get(wKey_, 25);
  X2_ ^= IOSIntArray_Get(wKey_, 26);
  X3_ ^= IOSIntArray_Get(wKey_, 27);
  [self inverseLT];
  [self ib5WithInt:X0_ withInt:X1_ withInt:X2_ withInt:X3_];
  X0_ ^= IOSIntArray_Get(nil_chk(wKey_), 20);
  X1_ ^= IOSIntArray_Get(wKey_, 21);
  X2_ ^= IOSIntArray_Get(wKey_, 22);
  X3_ ^= IOSIntArray_Get(wKey_, 23);
  [self inverseLT];
  [self ib4WithInt:X0_ withInt:X1_ withInt:X2_ withInt:X3_];
  X0_ ^= IOSIntArray_Get(nil_chk(wKey_), 16);
  X1_ ^= IOSIntArray_Get(wKey_, 17);
  X2_ ^= IOSIntArray_Get(wKey_, 18);
  X3_ ^= IOSIntArray_Get(wKey_, 19);
  [self inverseLT];
  [self ib3WithInt:X0_ withInt:X1_ withInt:X2_ withInt:X3_];
  X0_ ^= IOSIntArray_Get(nil_chk(wKey_), 12);
  X1_ ^= IOSIntArray_Get(wKey_, 13);
  X2_ ^= IOSIntArray_Get(wKey_, 14);
  X3_ ^= IOSIntArray_Get(wKey_, 15);
  [self inverseLT];
  [self ib2WithInt:X0_ withInt:X1_ withInt:X2_ withInt:X3_];
  X0_ ^= IOSIntArray_Get(nil_chk(wKey_), 8);
  X1_ ^= IOSIntArray_Get(wKey_, 9);
  X2_ ^= IOSIntArray_Get(wKey_, 10);
  X3_ ^= IOSIntArray_Get(wKey_, 11);
  [self inverseLT];
  [self ib1WithInt:X0_ withInt:X1_ withInt:X2_ withInt:X3_];
  X0_ ^= IOSIntArray_Get(nil_chk(wKey_), 4);
  X1_ ^= IOSIntArray_Get(wKey_, 5);
  X2_ ^= IOSIntArray_Get(wKey_, 6);
  X3_ ^= IOSIntArray_Get(wKey_, 7);
  [self inverseLT];
  [self ib0WithInt:X0_ withInt:X1_ withInt:X2_ withInt:X3_];
  LibOrgBouncycastleUtilPack_intToLittleEndianWithInt_withByteArray_withInt_(X0_ ^ IOSIntArray_Get(nil_chk(wKey_), 0), output, outOff);
  LibOrgBouncycastleUtilPack_intToLittleEndianWithInt_withByteArray_withInt_(X1_ ^ IOSIntArray_Get(nil_chk(wKey_), 1), output, outOff + 4);
  LibOrgBouncycastleUtilPack_intToLittleEndianWithInt_withByteArray_withInt_(X2_ ^ IOSIntArray_Get(nil_chk(wKey_), 2), output, outOff + 8);
  LibOrgBouncycastleUtilPack_intToLittleEndianWithInt_withByteArray_withInt_(X3_ ^ IOSIntArray_Get(nil_chk(wKey_), 3), output, outOff + 12);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[I", 0x4, 0, 1, 2, -1, -1, -1 },
    { NULL, "V", 0x4, 3, 4, -1, -1, -1, -1 },
    { NULL, "V", 0x4, 5, 4, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(makeWorkingKeyWithByteArray:);
  methods[2].selector = @selector(encryptBlockWithByteArray:withInt:withByteArray:withInt:);
  methods[3].selector = @selector(decryptBlockWithByteArray:withInt:withByteArray:withInt:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "makeWorkingKey", "[B", "LJavaLangIllegalArgumentException;", "encryptBlock", "[BI[BI", "decryptBlock" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoEnginesSerpentEngine = { "SerpentEngine", "lib.org.bouncycastle.crypto.engines", ptrTable, methods, NULL, 7, 0x11, 4, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoEnginesSerpentEngine;
}

@end

void LibOrgBouncycastleCryptoEnginesSerpentEngine_init(LibOrgBouncycastleCryptoEnginesSerpentEngine *self) {
  LibOrgBouncycastleCryptoEnginesSerpentEngineBase_init(self);
}

LibOrgBouncycastleCryptoEnginesSerpentEngine *new_LibOrgBouncycastleCryptoEnginesSerpentEngine_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoEnginesSerpentEngine, init)
}

LibOrgBouncycastleCryptoEnginesSerpentEngine *create_LibOrgBouncycastleCryptoEnginesSerpentEngine_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoEnginesSerpentEngine, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoEnginesSerpentEngine)
