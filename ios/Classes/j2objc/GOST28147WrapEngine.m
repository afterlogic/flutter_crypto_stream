//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/engines/GOST28147WrapEngine.java
//

#include "Arrays.h"
#include "CipherParameters.h"
#include "GOST28147Engine.h"
#include "GOST28147Mac.h"
#include "GOST28147WrapEngine.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "KeyParameter.h"
#include "ParametersWithIV.h"
#include "ParametersWithRandom.h"
#include "ParametersWithSBox.h"
#include "ParametersWithUKM.h"
#include "java/lang/IllegalStateException.h"
#include "java/lang/System.h"

@interface LibOrgBouncycastleCryptoEnginesGOST28147WrapEngine () {
 @public
  LibOrgBouncycastleCryptoEnginesGOST28147Engine *cipher_;
  LibOrgBouncycastleCryptoMacsGOST28147Mac *mac_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoEnginesGOST28147WrapEngine, cipher_, LibOrgBouncycastleCryptoEnginesGOST28147Engine *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoEnginesGOST28147WrapEngine, mac_, LibOrgBouncycastleCryptoMacsGOST28147Mac *)

@implementation LibOrgBouncycastleCryptoEnginesGOST28147WrapEngine

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoEnginesGOST28147WrapEngine_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)init__WithBoolean:(jboolean)forWrapping
withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)param {
  if ([param isKindOfClass:[LibOrgBouncycastleCryptoParamsParametersWithRandom class]]) {
    LibOrgBouncycastleCryptoParamsParametersWithRandom *pr = (LibOrgBouncycastleCryptoParamsParametersWithRandom *) param;
    param = [((LibOrgBouncycastleCryptoParamsParametersWithRandom *) nil_chk(pr)) getParameters];
  }
  LibOrgBouncycastleCryptoParamsParametersWithUKM *pU = (LibOrgBouncycastleCryptoParamsParametersWithUKM *) cast_chk(param, [LibOrgBouncycastleCryptoParamsParametersWithUKM class]);
  [((LibOrgBouncycastleCryptoEnginesGOST28147Engine *) nil_chk(cipher_)) init__WithBoolean:forWrapping withLibOrgBouncycastleCryptoCipherParameters:[((LibOrgBouncycastleCryptoParamsParametersWithUKM *) nil_chk(pU)) getParameters]];
  LibOrgBouncycastleCryptoParamsKeyParameter *kParam;
  if ([[pU getParameters] isKindOfClass:[LibOrgBouncycastleCryptoParamsParametersWithSBox class]]) {
    kParam = (LibOrgBouncycastleCryptoParamsKeyParameter *) cast_chk([((LibOrgBouncycastleCryptoParamsParametersWithSBox *) nil_chk(((LibOrgBouncycastleCryptoParamsParametersWithSBox *) cast_chk([pU getParameters], [LibOrgBouncycastleCryptoParamsParametersWithSBox class])))) getParameters], [LibOrgBouncycastleCryptoParamsKeyParameter class]);
  }
  else {
    kParam = (LibOrgBouncycastleCryptoParamsKeyParameter *) cast_chk([pU getParameters], [LibOrgBouncycastleCryptoParamsKeyParameter class]);
  }
  [((LibOrgBouncycastleCryptoMacsGOST28147Mac *) nil_chk(mac_)) init__WithLibOrgBouncycastleCryptoCipherParameters:new_LibOrgBouncycastleCryptoParamsParametersWithIV_initWithLibOrgBouncycastleCryptoCipherParameters_withByteArray_(kParam, [pU getUKM])];
}

- (NSString *)getAlgorithmName {
  return @"GOST28147Wrap";
}

- (IOSByteArray *)wrapWithByteArray:(IOSByteArray *)input
                            withInt:(jint)inOff
                            withInt:(jint)inLen {
  [((LibOrgBouncycastleCryptoMacsGOST28147Mac *) nil_chk(mac_)) updateWithByteArray:input withInt:inOff withInt:inLen];
  IOSByteArray *wrappedKey = [IOSByteArray newArrayWithLength:inLen + [((LibOrgBouncycastleCryptoMacsGOST28147Mac *) nil_chk(mac_)) getMacSize]];
  [((LibOrgBouncycastleCryptoEnginesGOST28147Engine *) nil_chk(cipher_)) processBlockWithByteArray:input withInt:inOff withByteArray:wrappedKey withInt:0];
  [((LibOrgBouncycastleCryptoEnginesGOST28147Engine *) nil_chk(cipher_)) processBlockWithByteArray:input withInt:inOff + 8 withByteArray:wrappedKey withInt:8];
  [((LibOrgBouncycastleCryptoEnginesGOST28147Engine *) nil_chk(cipher_)) processBlockWithByteArray:input withInt:inOff + 16 withByteArray:wrappedKey withInt:16];
  [((LibOrgBouncycastleCryptoEnginesGOST28147Engine *) nil_chk(cipher_)) processBlockWithByteArray:input withInt:inOff + 24 withByteArray:wrappedKey withInt:24];
  [((LibOrgBouncycastleCryptoMacsGOST28147Mac *) nil_chk(mac_)) doFinalWithByteArray:wrappedKey withInt:inLen];
  return wrappedKey;
}

- (IOSByteArray *)unwrapWithByteArray:(IOSByteArray *)input
                              withInt:(jint)inOff
                              withInt:(jint)inLen {
  IOSByteArray *decKey = [IOSByteArray newArrayWithLength:inLen - [((LibOrgBouncycastleCryptoMacsGOST28147Mac *) nil_chk(mac_)) getMacSize]];
  [((LibOrgBouncycastleCryptoEnginesGOST28147Engine *) nil_chk(cipher_)) processBlockWithByteArray:input withInt:inOff withByteArray:decKey withInt:0];
  [((LibOrgBouncycastleCryptoEnginesGOST28147Engine *) nil_chk(cipher_)) processBlockWithByteArray:input withInt:inOff + 8 withByteArray:decKey withInt:8];
  [((LibOrgBouncycastleCryptoEnginesGOST28147Engine *) nil_chk(cipher_)) processBlockWithByteArray:input withInt:inOff + 16 withByteArray:decKey withInt:16];
  [((LibOrgBouncycastleCryptoEnginesGOST28147Engine *) nil_chk(cipher_)) processBlockWithByteArray:input withInt:inOff + 24 withByteArray:decKey withInt:24];
  IOSByteArray *macResult = [IOSByteArray newArrayWithLength:[((LibOrgBouncycastleCryptoMacsGOST28147Mac *) nil_chk(mac_)) getMacSize]];
  [((LibOrgBouncycastleCryptoMacsGOST28147Mac *) nil_chk(mac_)) updateWithByteArray:decKey withInt:0 withInt:decKey->size_];
  [((LibOrgBouncycastleCryptoMacsGOST28147Mac *) nil_chk(mac_)) doFinalWithByteArray:macResult withInt:0];
  IOSByteArray *macExpected = [IOSByteArray newArrayWithLength:[((LibOrgBouncycastleCryptoMacsGOST28147Mac *) nil_chk(mac_)) getMacSize]];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(input, inOff + inLen - 4, macExpected, 0, [((LibOrgBouncycastleCryptoMacsGOST28147Mac *) nil_chk(mac_)) getMacSize]);
  if (!LibOrgBouncycastleUtilArrays_constantTimeAreEqualWithByteArray_withByteArray_(macResult, macExpected)) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"mac mismatch");
  }
  return decKey;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, 2, 3, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, 4, 3, 5, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(init__WithBoolean:withLibOrgBouncycastleCryptoCipherParameters:);
  methods[2].selector = @selector(getAlgorithmName);
  methods[3].selector = @selector(wrapWithByteArray:withInt:withInt:);
  methods[4].selector = @selector(unwrapWithByteArray:withInt:withInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "cipher_", "LLibOrgBouncycastleCryptoEnginesGOST28147Engine;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "mac_", "LLibOrgBouncycastleCryptoMacsGOST28147Mac;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "init", "ZLLibOrgBouncycastleCryptoCipherParameters;", "wrap", "[BII", "unwrap", "LLibOrgBouncycastleCryptoInvalidCipherTextException;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoEnginesGOST28147WrapEngine = { "GOST28147WrapEngine", "lib.org.bouncycastle.crypto.engines", ptrTable, methods, fields, 7, 0x1, 5, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoEnginesGOST28147WrapEngine;
}

@end

void LibOrgBouncycastleCryptoEnginesGOST28147WrapEngine_init(LibOrgBouncycastleCryptoEnginesGOST28147WrapEngine *self) {
  NSObject_init(self);
  self->cipher_ = new_LibOrgBouncycastleCryptoEnginesGOST28147Engine_init();
  self->mac_ = new_LibOrgBouncycastleCryptoMacsGOST28147Mac_init();
}

LibOrgBouncycastleCryptoEnginesGOST28147WrapEngine *new_LibOrgBouncycastleCryptoEnginesGOST28147WrapEngine_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoEnginesGOST28147WrapEngine, init)
}

LibOrgBouncycastleCryptoEnginesGOST28147WrapEngine *create_LibOrgBouncycastleCryptoEnginesGOST28147WrapEngine_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoEnginesGOST28147WrapEngine, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoEnginesGOST28147WrapEngine)
