//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/engines/SM4Engine.java
//

#include "CipherParameters.h"
#include "DataLengthException.h"
#include "IOSClass.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "KeyParameter.h"
#include "OutputLengthException.h"
#include "Pack.h"
#include "SM4Engine.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/IllegalStateException.h"

@interface LibOrgBouncycastleCryptoEnginesSM4Engine () {
 @public
  IOSIntArray *X_;
  IOSIntArray *rk_;
}

- (jint)rotateLeftWithInt:(jint)x
                  withInt:(jint)bits;

- (jint)tauWithInt:(jint)A;

- (jint)L_apWithInt:(jint)B;

- (jint)T_apWithInt:(jint)Z;

- (IOSIntArray *)expandKeyWithBoolean:(jboolean)forEncryption
                        withByteArray:(IOSByteArray *)key;

- (jint)LWithInt:(jint)B;

- (jint)TWithInt:(jint)Z;

- (jint)F0WithIntArray:(IOSIntArray *)X
               withInt:(jint)rk;

- (jint)F1WithIntArray:(IOSIntArray *)X
               withInt:(jint)rk;

- (jint)F2WithIntArray:(IOSIntArray *)X
               withInt:(jint)rk;

- (jint)F3WithIntArray:(IOSIntArray *)X
               withInt:(jint)rk;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoEnginesSM4Engine, X_, IOSIntArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoEnginesSM4Engine, rk_, IOSIntArray *)

inline jint LibOrgBouncycastleCryptoEnginesSM4Engine_get_BLOCK_SIZE(void);
#define LibOrgBouncycastleCryptoEnginesSM4Engine_BLOCK_SIZE 16
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoEnginesSM4Engine, BLOCK_SIZE, jint)

inline IOSByteArray *LibOrgBouncycastleCryptoEnginesSM4Engine_get_Sbox(void);
static IOSByteArray *LibOrgBouncycastleCryptoEnginesSM4Engine_Sbox;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoEnginesSM4Engine, Sbox, IOSByteArray *)

inline IOSIntArray *LibOrgBouncycastleCryptoEnginesSM4Engine_get_CK(void);
static IOSIntArray *LibOrgBouncycastleCryptoEnginesSM4Engine_CK;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoEnginesSM4Engine, CK, IOSIntArray *)

inline IOSIntArray *LibOrgBouncycastleCryptoEnginesSM4Engine_get_FK(void);
static IOSIntArray *LibOrgBouncycastleCryptoEnginesSM4Engine_FK;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoEnginesSM4Engine, FK, IOSIntArray *)

__attribute__((unused)) static jint LibOrgBouncycastleCryptoEnginesSM4Engine_rotateLeftWithInt_withInt_(LibOrgBouncycastleCryptoEnginesSM4Engine *self, jint x, jint bits);

__attribute__((unused)) static jint LibOrgBouncycastleCryptoEnginesSM4Engine_tauWithInt_(LibOrgBouncycastleCryptoEnginesSM4Engine *self, jint A);

__attribute__((unused)) static jint LibOrgBouncycastleCryptoEnginesSM4Engine_L_apWithInt_(LibOrgBouncycastleCryptoEnginesSM4Engine *self, jint B);

__attribute__((unused)) static jint LibOrgBouncycastleCryptoEnginesSM4Engine_T_apWithInt_(LibOrgBouncycastleCryptoEnginesSM4Engine *self, jint Z);

__attribute__((unused)) static IOSIntArray *LibOrgBouncycastleCryptoEnginesSM4Engine_expandKeyWithBoolean_withByteArray_(LibOrgBouncycastleCryptoEnginesSM4Engine *self, jboolean forEncryption, IOSByteArray *key);

__attribute__((unused)) static jint LibOrgBouncycastleCryptoEnginesSM4Engine_LWithInt_(LibOrgBouncycastleCryptoEnginesSM4Engine *self, jint B);

__attribute__((unused)) static jint LibOrgBouncycastleCryptoEnginesSM4Engine_TWithInt_(LibOrgBouncycastleCryptoEnginesSM4Engine *self, jint Z);

__attribute__((unused)) static jint LibOrgBouncycastleCryptoEnginesSM4Engine_F0WithIntArray_withInt_(LibOrgBouncycastleCryptoEnginesSM4Engine *self, IOSIntArray *X, jint rk);

__attribute__((unused)) static jint LibOrgBouncycastleCryptoEnginesSM4Engine_F1WithIntArray_withInt_(LibOrgBouncycastleCryptoEnginesSM4Engine *self, IOSIntArray *X, jint rk);

__attribute__((unused)) static jint LibOrgBouncycastleCryptoEnginesSM4Engine_F2WithIntArray_withInt_(LibOrgBouncycastleCryptoEnginesSM4Engine *self, IOSIntArray *X, jint rk);

__attribute__((unused)) static jint LibOrgBouncycastleCryptoEnginesSM4Engine_F3WithIntArray_withInt_(LibOrgBouncycastleCryptoEnginesSM4Engine *self, IOSIntArray *X, jint rk);

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleCryptoEnginesSM4Engine)

@implementation LibOrgBouncycastleCryptoEnginesSM4Engine

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoEnginesSM4Engine_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (jint)rotateLeftWithInt:(jint)x
                  withInt:(jint)bits {
  return LibOrgBouncycastleCryptoEnginesSM4Engine_rotateLeftWithInt_withInt_(self, x, bits);
}

- (jint)tauWithInt:(jint)A {
  return LibOrgBouncycastleCryptoEnginesSM4Engine_tauWithInt_(self, A);
}

- (jint)L_apWithInt:(jint)B {
  return LibOrgBouncycastleCryptoEnginesSM4Engine_L_apWithInt_(self, B);
}

- (jint)T_apWithInt:(jint)Z {
  return LibOrgBouncycastleCryptoEnginesSM4Engine_T_apWithInt_(self, Z);
}

- (IOSIntArray *)expandKeyWithBoolean:(jboolean)forEncryption
                        withByteArray:(IOSByteArray *)key {
  return LibOrgBouncycastleCryptoEnginesSM4Engine_expandKeyWithBoolean_withByteArray_(self, forEncryption, key);
}

- (jint)LWithInt:(jint)B {
  return LibOrgBouncycastleCryptoEnginesSM4Engine_LWithInt_(self, B);
}

- (jint)TWithInt:(jint)Z {
  return LibOrgBouncycastleCryptoEnginesSM4Engine_TWithInt_(self, Z);
}

- (jint)F0WithIntArray:(IOSIntArray *)X
               withInt:(jint)rk {
  return LibOrgBouncycastleCryptoEnginesSM4Engine_F0WithIntArray_withInt_(self, X, rk);
}

- (jint)F1WithIntArray:(IOSIntArray *)X
               withInt:(jint)rk {
  return LibOrgBouncycastleCryptoEnginesSM4Engine_F1WithIntArray_withInt_(self, X, rk);
}

- (jint)F2WithIntArray:(IOSIntArray *)X
               withInt:(jint)rk {
  return LibOrgBouncycastleCryptoEnginesSM4Engine_F2WithIntArray_withInt_(self, X, rk);
}

- (jint)F3WithIntArray:(IOSIntArray *)X
               withInt:(jint)rk {
  return LibOrgBouncycastleCryptoEnginesSM4Engine_F3WithIntArray_withInt_(self, X, rk);
}

- (void)init__WithBoolean:(jboolean)forEncryption
withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)params {
  if ([params isKindOfClass:[LibOrgBouncycastleCryptoParamsKeyParameter class]]) {
    IOSByteArray *key = [((LibOrgBouncycastleCryptoParamsKeyParameter *) nil_chk(((LibOrgBouncycastleCryptoParamsKeyParameter *) params))) getKey];
    if (((IOSByteArray *) nil_chk(key))->size_ != 16) {
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"SM4 requires a 128 bit key");
    }
    rk_ = LibOrgBouncycastleCryptoEnginesSM4Engine_expandKeyWithBoolean_withByteArray_(self, forEncryption, key);
  }
  else {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$", @"invalid parameter passed to SM4 init - ", [[((id<LibOrgBouncycastleCryptoCipherParameters>) nil_chk(params)) java_getClass] getName]));
  }
}

- (NSString *)getAlgorithmName {
  return @"SM4";
}

- (jint)getBlockSize {
  return LibOrgBouncycastleCryptoEnginesSM4Engine_BLOCK_SIZE;
}

- (jint)processBlockWithByteArray:(IOSByteArray *)inArg
                          withInt:(jint)inOff
                    withByteArray:(IOSByteArray *)outArg
                          withInt:(jint)outOff {
  if (rk_ == nil) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"SM4 not initialised");
  }
  if ((inOff + LibOrgBouncycastleCryptoEnginesSM4Engine_BLOCK_SIZE) > ((IOSByteArray *) nil_chk(inArg))->size_) {
    @throw new_LibOrgBouncycastleCryptoDataLengthException_initWithNSString_(@"input buffer too short");
  }
  if ((outOff + LibOrgBouncycastleCryptoEnginesSM4Engine_BLOCK_SIZE) > ((IOSByteArray *) nil_chk(outArg))->size_) {
    @throw new_LibOrgBouncycastleCryptoOutputLengthException_initWithNSString_(@"output buffer too short");
  }
  *IOSIntArray_GetRef(nil_chk(X_), 0) = LibOrgBouncycastleUtilPack_bigEndianToIntWithByteArray_withInt_(inArg, inOff);
  *IOSIntArray_GetRef(X_, 1) = LibOrgBouncycastleUtilPack_bigEndianToIntWithByteArray_withInt_(inArg, inOff + 4);
  *IOSIntArray_GetRef(X_, 2) = LibOrgBouncycastleUtilPack_bigEndianToIntWithByteArray_withInt_(inArg, inOff + 8);
  *IOSIntArray_GetRef(X_, 3) = LibOrgBouncycastleUtilPack_bigEndianToIntWithByteArray_withInt_(inArg, inOff + 12);
  jint i;
  for (i = 0; i < 32; i += 4) {
    *IOSIntArray_GetRef(X_, 0) = LibOrgBouncycastleCryptoEnginesSM4Engine_F0WithIntArray_withInt_(self, X_, IOSIntArray_Get(nil_chk(rk_), i));
    *IOSIntArray_GetRef(X_, 1) = LibOrgBouncycastleCryptoEnginesSM4Engine_F1WithIntArray_withInt_(self, X_, IOSIntArray_Get(nil_chk(rk_), i + 1));
    *IOSIntArray_GetRef(X_, 2) = LibOrgBouncycastleCryptoEnginesSM4Engine_F2WithIntArray_withInt_(self, X_, IOSIntArray_Get(nil_chk(rk_), i + 2));
    *IOSIntArray_GetRef(X_, 3) = LibOrgBouncycastleCryptoEnginesSM4Engine_F3WithIntArray_withInt_(self, X_, IOSIntArray_Get(nil_chk(rk_), i + 3));
  }
  LibOrgBouncycastleUtilPack_intToBigEndianWithInt_withByteArray_withInt_(IOSIntArray_Get(X_, 3), outArg, outOff);
  LibOrgBouncycastleUtilPack_intToBigEndianWithInt_withByteArray_withInt_(IOSIntArray_Get(X_, 2), outArg, outOff + 4);
  LibOrgBouncycastleUtilPack_intToBigEndianWithInt_withByteArray_withInt_(IOSIntArray_Get(X_, 1), outArg, outOff + 8);
  LibOrgBouncycastleUtilPack_intToBigEndianWithInt_withByteArray_withInt_(IOSIntArray_Get(X_, 0), outArg, outOff + 12);
  return LibOrgBouncycastleCryptoEnginesSM4Engine_BLOCK_SIZE;
}

- (void)reset {
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x2, 0, 1, -1, -1, -1, -1 },
    { NULL, "I", 0x2, 2, 3, -1, -1, -1, -1 },
    { NULL, "I", 0x2, 4, 3, -1, -1, -1, -1 },
    { NULL, "I", 0x2, 5, 3, -1, -1, -1, -1 },
    { NULL, "[I", 0x2, 6, 7, -1, -1, -1, -1 },
    { NULL, "I", 0x2, 8, 3, -1, -1, -1, -1 },
    { NULL, "I", 0x2, 9, 3, -1, -1, -1, -1 },
    { NULL, "I", 0x2, 10, 11, -1, -1, -1, -1 },
    { NULL, "I", 0x2, 12, 11, -1, -1, -1, -1 },
    { NULL, "I", 0x2, 13, 11, -1, -1, -1, -1 },
    { NULL, "I", 0x2, 14, 11, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 15, 16, 17, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 18, 19, 20, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(rotateLeftWithInt:withInt:);
  methods[2].selector = @selector(tauWithInt:);
  methods[3].selector = @selector(L_apWithInt:);
  methods[4].selector = @selector(T_apWithInt:);
  methods[5].selector = @selector(expandKeyWithBoolean:withByteArray:);
  methods[6].selector = @selector(LWithInt:);
  methods[7].selector = @selector(TWithInt:);
  methods[8].selector = @selector(F0WithIntArray:withInt:);
  methods[9].selector = @selector(F1WithIntArray:withInt:);
  methods[10].selector = @selector(F2WithIntArray:withInt:);
  methods[11].selector = @selector(F3WithIntArray:withInt:);
  methods[12].selector = @selector(init__WithBoolean:withLibOrgBouncycastleCryptoCipherParameters:);
  methods[13].selector = @selector(getAlgorithmName);
  methods[14].selector = @selector(getBlockSize);
  methods[15].selector = @selector(processBlockWithByteArray:withInt:withByteArray:withInt:);
  methods[16].selector = @selector(reset);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "BLOCK_SIZE", "I", .constantValue.asInt = LibOrgBouncycastleCryptoEnginesSM4Engine_BLOCK_SIZE, 0x1a, -1, -1, -1, -1 },
    { "Sbox", "[B", .constantValue.asLong = 0, 0x1a, -1, 21, -1, -1 },
    { "CK", "[I", .constantValue.asLong = 0, 0x1a, -1, 22, -1, -1 },
    { "FK", "[I", .constantValue.asLong = 0, 0x1a, -1, 23, -1, -1 },
    { "X_", "[I", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "rk_", "[I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "rotateLeft", "II", "tau", "I", "L_ap", "T_ap", "expandKey", "Z[B", "L", "T", "F0", "[II", "F1", "F2", "F3", "init", "ZLLibOrgBouncycastleCryptoCipherParameters;", "LJavaLangIllegalArgumentException;", "processBlock", "[BI[BI", "LLibOrgBouncycastleCryptoDataLengthException;LJavaLangIllegalStateException;", &LibOrgBouncycastleCryptoEnginesSM4Engine_Sbox, &LibOrgBouncycastleCryptoEnginesSM4Engine_CK, &LibOrgBouncycastleCryptoEnginesSM4Engine_FK };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoEnginesSM4Engine = { "SM4Engine", "lib.org.bouncycastle.crypto.engines", ptrTable, methods, fields, 7, 0x1, 17, 6, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoEnginesSM4Engine;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleCryptoEnginesSM4Engine class]) {
    LibOrgBouncycastleCryptoEnginesSM4Engine_Sbox = [IOSByteArray newArrayWithBytes:(jbyte[]){ (jbyte) (jint) 0xd6, (jbyte) (jint) 0x90, (jbyte) (jint) 0xe9, (jbyte) (jint) 0xfe, (jbyte) (jint) 0xcc, (jbyte) (jint) 0xe1, (jbyte) (jint) 0x3d, (jbyte) (jint) 0xb7, (jbyte) (jint) 0x16, (jbyte) (jint) 0xb6, (jbyte) (jint) 0x14, (jbyte) (jint) 0xc2, (jbyte) (jint) 0x28, (jbyte) (jint) 0xfb, (jbyte) (jint) 0x2c, (jbyte) (jint) 0x05, (jbyte) (jint) 0x2b, (jbyte) (jint) 0x67, (jbyte) (jint) 0x9a, (jbyte) (jint) 0x76, (jbyte) (jint) 0x2a, (jbyte) (jint) 0xbe, (jbyte) (jint) 0x04, (jbyte) (jint) 0xc3, (jbyte) (jint) 0xaa, (jbyte) (jint) 0x44, (jbyte) (jint) 0x13, (jbyte) (jint) 0x26, (jbyte) (jint) 0x49, (jbyte) (jint) 0x86, (jbyte) (jint) 0x06, (jbyte) (jint) 0x99, (jbyte) (jint) 0x9c, (jbyte) (jint) 0x42, (jbyte) (jint) 0x50, (jbyte) (jint) 0xf4, (jbyte) (jint) 0x91, (jbyte) (jint) 0xef, (jbyte) (jint) 0x98, (jbyte) (jint) 0x7a, (jbyte) (jint) 0x33, (jbyte) (jint) 0x54, (jbyte) (jint) 0x0b, (jbyte) (jint) 0x43, (jbyte) (jint) 0xed, (jbyte) (jint) 0xcf, (jbyte) (jint) 0xac, (jbyte) (jint) 0x62, (jbyte) (jint) 0xe4, (jbyte) (jint) 0xb3, (jbyte) (jint) 0x1c, (jbyte) (jint) 0xa9, (jbyte) (jint) 0xc9, (jbyte) (jint) 0x08, (jbyte) (jint) 0xe8, (jbyte) (jint) 0x95, (jbyte) (jint) 0x80, (jbyte) (jint) 0xdf, (jbyte) (jint) 0x94, (jbyte) (jint) 0xfa, (jbyte) (jint) 0x75, (jbyte) (jint) 0x8f, (jbyte) (jint) 0x3f, (jbyte) (jint) 0xa6, (jbyte) (jint) 0x47, (jbyte) (jint) 0x07, (jbyte) (jint) 0xa7, (jbyte) (jint) 0xfc, (jbyte) (jint) 0xf3, (jbyte) (jint) 0x73, (jbyte) (jint) 0x17, (jbyte) (jint) 0xba, (jbyte) (jint) 0x83, (jbyte) (jint) 0x59, (jbyte) (jint) 0x3c, (jbyte) (jint) 0x19, (jbyte) (jint) 0xe6, (jbyte) (jint) 0x85, (jbyte) (jint) 0x4f, (jbyte) (jint) 0xa8, (jbyte) (jint) 0x68, (jbyte) (jint) 0x6b, (jbyte) (jint) 0x81, (jbyte) (jint) 0xb2, (jbyte) (jint) 0x71, (jbyte) (jint) 0x64, (jbyte) (jint) 0xda, (jbyte) (jint) 0x8b, (jbyte) (jint) 0xf8, (jbyte) (jint) 0xeb, (jbyte) (jint) 0x0f, (jbyte) (jint) 0x4b, (jbyte) (jint) 0x70, (jbyte) (jint) 0x56, (jbyte) (jint) 0x9d, (jbyte) (jint) 0x35, (jbyte) (jint) 0x1e, (jbyte) (jint) 0x24, (jbyte) (jint) 0x0e, (jbyte) (jint) 0x5e, (jbyte) (jint) 0x63, (jbyte) (jint) 0x58, (jbyte) (jint) 0xd1, (jbyte) (jint) 0xa2, (jbyte) (jint) 0x25, (jbyte) (jint) 0x22, (jbyte) (jint) 0x7c, (jbyte) (jint) 0x3b, (jbyte) (jint) 0x01, (jbyte) (jint) 0x21, (jbyte) (jint) 0x78, (jbyte) (jint) 0x87, (jbyte) (jint) 0xd4, (jbyte) (jint) 0x00, (jbyte) (jint) 0x46, (jbyte) (jint) 0x57, (jbyte) (jint) 0x9f, (jbyte) (jint) 0xd3, (jbyte) (jint) 0x27, (jbyte) (jint) 0x52, (jbyte) (jint) 0x4c, (jbyte) (jint) 0x36, (jbyte) (jint) 0x02, (jbyte) (jint) 0xe7, (jbyte) (jint) 0xa0, (jbyte) (jint) 0xc4, (jbyte) (jint) 0xc8, (jbyte) (jint) 0x9e, (jbyte) (jint) 0xea, (jbyte) (jint) 0xbf, (jbyte) (jint) 0x8a, (jbyte) (jint) 0xd2, (jbyte) (jint) 0x40, (jbyte) (jint) 0xc7, (jbyte) (jint) 0x38, (jbyte) (jint) 0xb5, (jbyte) (jint) 0xa3, (jbyte) (jint) 0xf7, (jbyte) (jint) 0xf2, (jbyte) (jint) 0xce, (jbyte) (jint) 0xf9, (jbyte) (jint) 0x61, (jbyte) (jint) 0x15, (jbyte) (jint) 0xa1, (jbyte) (jint) 0xe0, (jbyte) (jint) 0xae, (jbyte) (jint) 0x5d, (jbyte) (jint) 0xa4, (jbyte) (jint) 0x9b, (jbyte) (jint) 0x34, (jbyte) (jint) 0x1a, (jbyte) (jint) 0x55, (jbyte) (jint) 0xad, (jbyte) (jint) 0x93, (jbyte) (jint) 0x32, (jbyte) (jint) 0x30, (jbyte) (jint) 0xf5, (jbyte) (jint) 0x8c, (jbyte) (jint) 0xb1, (jbyte) (jint) 0xe3, (jbyte) (jint) 0x1d, (jbyte) (jint) 0xf6, (jbyte) (jint) 0xe2, (jbyte) (jint) 0x2e, (jbyte) (jint) 0x82, (jbyte) (jint) 0x66, (jbyte) (jint) 0xca, (jbyte) (jint) 0x60, (jbyte) (jint) 0xc0, (jbyte) (jint) 0x29, (jbyte) (jint) 0x23, (jbyte) (jint) 0xab, (jbyte) (jint) 0x0d, (jbyte) (jint) 0x53, (jbyte) (jint) 0x4e, (jbyte) (jint) 0x6f, (jbyte) (jint) 0xd5, (jbyte) (jint) 0xdb, (jbyte) (jint) 0x37, (jbyte) (jint) 0x45, (jbyte) (jint) 0xde, (jbyte) (jint) 0xfd, (jbyte) (jint) 0x8e, (jbyte) (jint) 0x2f, (jbyte) (jint) 0x03, (jbyte) (jint) 0xff, (jbyte) (jint) 0x6a, (jbyte) (jint) 0x72, (jbyte) (jint) 0x6d, (jbyte) (jint) 0x6c, (jbyte) (jint) 0x5b, (jbyte) (jint) 0x51, (jbyte) (jint) 0x8d, (jbyte) (jint) 0x1b, (jbyte) (jint) 0xaf, (jbyte) (jint) 0x92, (jbyte) (jint) 0xbb, (jbyte) (jint) 0xdd, (jbyte) (jint) 0xbc, (jbyte) (jint) 0x7f, (jbyte) (jint) 0x11, (jbyte) (jint) 0xd9, (jbyte) (jint) 0x5c, (jbyte) (jint) 0x41, (jbyte) (jint) 0x1f, (jbyte) (jint) 0x10, (jbyte) (jint) 0x5a, (jbyte) (jint) 0xd8, (jbyte) (jint) 0x0a, (jbyte) (jint) 0xc1, (jbyte) (jint) 0x31, (jbyte) (jint) 0x88, (jbyte) (jint) 0xa5, (jbyte) (jint) 0xcd, (jbyte) (jint) 0x7b, (jbyte) (jint) 0xbd, (jbyte) (jint) 0x2d, (jbyte) (jint) 0x74, (jbyte) (jint) 0xd0, (jbyte) (jint) 0x12, (jbyte) (jint) 0xb8, (jbyte) (jint) 0xe5, (jbyte) (jint) 0xb4, (jbyte) (jint) 0xb0, (jbyte) (jint) 0x89, (jbyte) (jint) 0x69, (jbyte) (jint) 0x97, (jbyte) (jint) 0x4a, (jbyte) (jint) 0x0c, (jbyte) (jint) 0x96, (jbyte) (jint) 0x77, (jbyte) (jint) 0x7e, (jbyte) (jint) 0x65, (jbyte) (jint) 0xb9, (jbyte) (jint) 0xf1, (jbyte) (jint) 0x09, (jbyte) (jint) 0xc5, (jbyte) (jint) 0x6e, (jbyte) (jint) 0xc6, (jbyte) (jint) 0x84, (jbyte) (jint) 0x18, (jbyte) (jint) 0xf0, (jbyte) (jint) 0x7d, (jbyte) (jint) 0xec, (jbyte) (jint) 0x3a, (jbyte) (jint) 0xdc, (jbyte) (jint) 0x4d, (jbyte) (jint) 0x20, (jbyte) (jint) 0x79, (jbyte) (jint) 0xee, (jbyte) (jint) 0x5f, (jbyte) (jint) 0x3e, (jbyte) (jint) 0xd7, (jbyte) (jint) 0xcb, (jbyte) (jint) 0x39, (jbyte) (jint) 0x48 } count:256];
    LibOrgBouncycastleCryptoEnginesSM4Engine_CK = [IOSIntArray newArrayWithInts:(jint[]){ (jint) 0x00070e15, (jint) 0x1c232a31, (jint) 0x383f464d, (jint) 0x545b6269, (jint) 0x70777e85, (jint) 0x8c939aa1, (jint) 0xa8afb6bd, (jint) 0xc4cbd2d9, (jint) 0xe0e7eef5, (jint) 0xfc030a11, (jint) 0x181f262d, (jint) 0x343b4249, (jint) 0x50575e65, (jint) 0x6c737a81, (jint) 0x888f969d, (jint) 0xa4abb2b9, (jint) 0xc0c7ced5, (jint) 0xdce3eaf1, (jint) 0xf8ff060d, (jint) 0x141b2229, (jint) 0x30373e45, (jint) 0x4c535a61, (jint) 0x686f767d, (jint) 0x848b9299, (jint) 0xa0a7aeb5, (jint) 0xbcc3cad1, (jint) 0xd8dfe6ed, (jint) 0xf4fb0209, (jint) 0x10171e25, (jint) 0x2c333a41, (jint) 0x484f565d, (jint) 0x646b7279 } count:32];
    LibOrgBouncycastleCryptoEnginesSM4Engine_FK = [IOSIntArray newArrayWithInts:(jint[]){ (jint) 0xa3b1bac6, (jint) 0x56aa3350, (jint) 0x677d9197, (jint) 0xb27022dc } count:4];
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleCryptoEnginesSM4Engine)
  }
}

@end

void LibOrgBouncycastleCryptoEnginesSM4Engine_init(LibOrgBouncycastleCryptoEnginesSM4Engine *self) {
  NSObject_init(self);
  self->X_ = [IOSIntArray newArrayWithLength:4];
}

LibOrgBouncycastleCryptoEnginesSM4Engine *new_LibOrgBouncycastleCryptoEnginesSM4Engine_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoEnginesSM4Engine, init)
}

LibOrgBouncycastleCryptoEnginesSM4Engine *create_LibOrgBouncycastleCryptoEnginesSM4Engine_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoEnginesSM4Engine, init)
}

jint LibOrgBouncycastleCryptoEnginesSM4Engine_rotateLeftWithInt_withInt_(LibOrgBouncycastleCryptoEnginesSM4Engine *self, jint x, jint bits) {
  return (JreLShift32(x, bits)) | (JreURShift32(x, -bits));
}

jint LibOrgBouncycastleCryptoEnginesSM4Engine_tauWithInt_(LibOrgBouncycastleCryptoEnginesSM4Engine *self, jint A) {
  jint b0 = IOSByteArray_Get(nil_chk(LibOrgBouncycastleCryptoEnginesSM4Engine_Sbox), (JreRShift32(A, 24)) & (jint) 0xff) & (jint) 0xff;
  jint b1 = IOSByteArray_Get(LibOrgBouncycastleCryptoEnginesSM4Engine_Sbox, (JreRShift32(A, 16)) & (jint) 0xff) & (jint) 0xff;
  jint b2 = IOSByteArray_Get(LibOrgBouncycastleCryptoEnginesSM4Engine_Sbox, (JreRShift32(A, 8)) & (jint) 0xff) & (jint) 0xff;
  jint b3 = IOSByteArray_Get(LibOrgBouncycastleCryptoEnginesSM4Engine_Sbox, A & (jint) 0xff) & (jint) 0xff;
  return (JreLShift32(b0, 24)) | (JreLShift32(b1, 16)) | (JreLShift32(b2, 8)) | b3;
}

jint LibOrgBouncycastleCryptoEnginesSM4Engine_L_apWithInt_(LibOrgBouncycastleCryptoEnginesSM4Engine *self, jint B) {
  return (B ^ (LibOrgBouncycastleCryptoEnginesSM4Engine_rotateLeftWithInt_withInt_(self, B, 13)) ^ (LibOrgBouncycastleCryptoEnginesSM4Engine_rotateLeftWithInt_withInt_(self, B, 23)));
}

jint LibOrgBouncycastleCryptoEnginesSM4Engine_T_apWithInt_(LibOrgBouncycastleCryptoEnginesSM4Engine *self, jint Z) {
  return LibOrgBouncycastleCryptoEnginesSM4Engine_L_apWithInt_(self, LibOrgBouncycastleCryptoEnginesSM4Engine_tauWithInt_(self, Z));
}

IOSIntArray *LibOrgBouncycastleCryptoEnginesSM4Engine_expandKeyWithBoolean_withByteArray_(LibOrgBouncycastleCryptoEnginesSM4Engine *self, jboolean forEncryption, IOSByteArray *key) {
  IOSIntArray *rk = [IOSIntArray newArrayWithLength:32];
  IOSIntArray *MK = [IOSIntArray newArrayWithLength:4];
  *IOSIntArray_GetRef(MK, 0) = LibOrgBouncycastleUtilPack_bigEndianToIntWithByteArray_withInt_(key, 0);
  *IOSIntArray_GetRef(MK, 1) = LibOrgBouncycastleUtilPack_bigEndianToIntWithByteArray_withInt_(key, 4);
  *IOSIntArray_GetRef(MK, 2) = LibOrgBouncycastleUtilPack_bigEndianToIntWithByteArray_withInt_(key, 8);
  *IOSIntArray_GetRef(MK, 3) = LibOrgBouncycastleUtilPack_bigEndianToIntWithByteArray_withInt_(key, 12);
  jint i;
  IOSIntArray *K = [IOSIntArray newArrayWithLength:4];
  *IOSIntArray_GetRef(K, 0) = IOSIntArray_Get(MK, 0) ^ IOSIntArray_Get(nil_chk(LibOrgBouncycastleCryptoEnginesSM4Engine_FK), 0);
  *IOSIntArray_GetRef(K, 1) = IOSIntArray_Get(MK, 1) ^ IOSIntArray_Get(LibOrgBouncycastleCryptoEnginesSM4Engine_FK, 1);
  *IOSIntArray_GetRef(K, 2) = IOSIntArray_Get(MK, 2) ^ IOSIntArray_Get(LibOrgBouncycastleCryptoEnginesSM4Engine_FK, 2);
  *IOSIntArray_GetRef(K, 3) = IOSIntArray_Get(MK, 3) ^ IOSIntArray_Get(LibOrgBouncycastleCryptoEnginesSM4Engine_FK, 3);
  if (forEncryption) {
    *IOSIntArray_GetRef(rk, 0) = IOSIntArray_Get(K, 0) ^ LibOrgBouncycastleCryptoEnginesSM4Engine_T_apWithInt_(self, IOSIntArray_Get(K, 1) ^ IOSIntArray_Get(K, 2) ^ IOSIntArray_Get(K, 3) ^ IOSIntArray_Get(nil_chk(LibOrgBouncycastleCryptoEnginesSM4Engine_CK), 0));
    *IOSIntArray_GetRef(rk, 1) = IOSIntArray_Get(K, 1) ^ LibOrgBouncycastleCryptoEnginesSM4Engine_T_apWithInt_(self, IOSIntArray_Get(K, 2) ^ IOSIntArray_Get(K, 3) ^ IOSIntArray_Get(rk, 0) ^ IOSIntArray_Get(LibOrgBouncycastleCryptoEnginesSM4Engine_CK, 1));
    *IOSIntArray_GetRef(rk, 2) = IOSIntArray_Get(K, 2) ^ LibOrgBouncycastleCryptoEnginesSM4Engine_T_apWithInt_(self, IOSIntArray_Get(K, 3) ^ IOSIntArray_Get(rk, 0) ^ IOSIntArray_Get(rk, 1) ^ IOSIntArray_Get(LibOrgBouncycastleCryptoEnginesSM4Engine_CK, 2));
    *IOSIntArray_GetRef(rk, 3) = IOSIntArray_Get(K, 3) ^ LibOrgBouncycastleCryptoEnginesSM4Engine_T_apWithInt_(self, IOSIntArray_Get(rk, 0) ^ IOSIntArray_Get(rk, 1) ^ IOSIntArray_Get(rk, 2) ^ IOSIntArray_Get(LibOrgBouncycastleCryptoEnginesSM4Engine_CK, 3));
    for (i = 4; i < 32; i++) {
      *IOSIntArray_GetRef(rk, i) = IOSIntArray_Get(rk, i - 4) ^ LibOrgBouncycastleCryptoEnginesSM4Engine_T_apWithInt_(self, IOSIntArray_Get(rk, i - 3) ^ IOSIntArray_Get(rk, i - 2) ^ IOSIntArray_Get(rk, i - 1) ^ IOSIntArray_Get(LibOrgBouncycastleCryptoEnginesSM4Engine_CK, i));
    }
  }
  else {
    *IOSIntArray_GetRef(rk, 31) = IOSIntArray_Get(K, 0) ^ LibOrgBouncycastleCryptoEnginesSM4Engine_T_apWithInt_(self, IOSIntArray_Get(K, 1) ^ IOSIntArray_Get(K, 2) ^ IOSIntArray_Get(K, 3) ^ IOSIntArray_Get(nil_chk(LibOrgBouncycastleCryptoEnginesSM4Engine_CK), 0));
    *IOSIntArray_GetRef(rk, 30) = IOSIntArray_Get(K, 1) ^ LibOrgBouncycastleCryptoEnginesSM4Engine_T_apWithInt_(self, IOSIntArray_Get(K, 2) ^ IOSIntArray_Get(K, 3) ^ IOSIntArray_Get(rk, 31) ^ IOSIntArray_Get(LibOrgBouncycastleCryptoEnginesSM4Engine_CK, 1));
    *IOSIntArray_GetRef(rk, 29) = IOSIntArray_Get(K, 2) ^ LibOrgBouncycastleCryptoEnginesSM4Engine_T_apWithInt_(self, IOSIntArray_Get(K, 3) ^ IOSIntArray_Get(rk, 31) ^ IOSIntArray_Get(rk, 30) ^ IOSIntArray_Get(LibOrgBouncycastleCryptoEnginesSM4Engine_CK, 2));
    *IOSIntArray_GetRef(rk, 28) = IOSIntArray_Get(K, 3) ^ LibOrgBouncycastleCryptoEnginesSM4Engine_T_apWithInt_(self, IOSIntArray_Get(rk, 31) ^ IOSIntArray_Get(rk, 30) ^ IOSIntArray_Get(rk, 29) ^ IOSIntArray_Get(LibOrgBouncycastleCryptoEnginesSM4Engine_CK, 3));
    for (i = 27; i >= 0; i--) {
      *IOSIntArray_GetRef(rk, i) = IOSIntArray_Get(rk, i + 4) ^ LibOrgBouncycastleCryptoEnginesSM4Engine_T_apWithInt_(self, IOSIntArray_Get(rk, i + 3) ^ IOSIntArray_Get(rk, i + 2) ^ IOSIntArray_Get(rk, i + 1) ^ IOSIntArray_Get(LibOrgBouncycastleCryptoEnginesSM4Engine_CK, 31 - i));
    }
  }
  return rk;
}

jint LibOrgBouncycastleCryptoEnginesSM4Engine_LWithInt_(LibOrgBouncycastleCryptoEnginesSM4Engine *self, jint B) {
  jint C;
  C = (B ^ (LibOrgBouncycastleCryptoEnginesSM4Engine_rotateLeftWithInt_withInt_(self, B, 2)) ^ (LibOrgBouncycastleCryptoEnginesSM4Engine_rotateLeftWithInt_withInt_(self, B, 10)) ^ (LibOrgBouncycastleCryptoEnginesSM4Engine_rotateLeftWithInt_withInt_(self, B, 18)) ^ (LibOrgBouncycastleCryptoEnginesSM4Engine_rotateLeftWithInt_withInt_(self, B, 24)));
  return C;
}

jint LibOrgBouncycastleCryptoEnginesSM4Engine_TWithInt_(LibOrgBouncycastleCryptoEnginesSM4Engine *self, jint Z) {
  return LibOrgBouncycastleCryptoEnginesSM4Engine_LWithInt_(self, LibOrgBouncycastleCryptoEnginesSM4Engine_tauWithInt_(self, Z));
}

jint LibOrgBouncycastleCryptoEnginesSM4Engine_F0WithIntArray_withInt_(LibOrgBouncycastleCryptoEnginesSM4Engine *self, IOSIntArray *X, jint rk) {
  return (IOSIntArray_Get(nil_chk(X), 0) ^ LibOrgBouncycastleCryptoEnginesSM4Engine_TWithInt_(self, IOSIntArray_Get(X, 1) ^ IOSIntArray_Get(X, 2) ^ IOSIntArray_Get(X, 3) ^ rk));
}

jint LibOrgBouncycastleCryptoEnginesSM4Engine_F1WithIntArray_withInt_(LibOrgBouncycastleCryptoEnginesSM4Engine *self, IOSIntArray *X, jint rk) {
  return (IOSIntArray_Get(nil_chk(X), 1) ^ LibOrgBouncycastleCryptoEnginesSM4Engine_TWithInt_(self, IOSIntArray_Get(X, 2) ^ IOSIntArray_Get(X, 3) ^ IOSIntArray_Get(X, 0) ^ rk));
}

jint LibOrgBouncycastleCryptoEnginesSM4Engine_F2WithIntArray_withInt_(LibOrgBouncycastleCryptoEnginesSM4Engine *self, IOSIntArray *X, jint rk) {
  return (IOSIntArray_Get(nil_chk(X), 2) ^ LibOrgBouncycastleCryptoEnginesSM4Engine_TWithInt_(self, IOSIntArray_Get(X, 3) ^ IOSIntArray_Get(X, 0) ^ IOSIntArray_Get(X, 1) ^ rk));
}

jint LibOrgBouncycastleCryptoEnginesSM4Engine_F3WithIntArray_withInt_(LibOrgBouncycastleCryptoEnginesSM4Engine *self, IOSIntArray *X, jint rk) {
  return (IOSIntArray_Get(nil_chk(X), 3) ^ LibOrgBouncycastleCryptoEnginesSM4Engine_TWithInt_(self, IOSIntArray_Get(X, 0) ^ IOSIntArray_Get(X, 1) ^ IOSIntArray_Get(X, 2) ^ rk));
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoEnginesSM4Engine)
