//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/macs/SkeinMac.java
//

#include "CipherParameters.h"
#include "IOSClass.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "KeyParameter.h"
#include "SkeinEngine.h"
#include "SkeinMac.h"
#include "SkeinParameters.h"
#include "java/lang/IllegalArgumentException.h"

@interface LibOrgBouncycastleCryptoMacsSkeinMac () {
 @public
  LibOrgBouncycastleCryptoDigestsSkeinEngine *engine_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoMacsSkeinMac, engine_, LibOrgBouncycastleCryptoDigestsSkeinEngine *)

@implementation LibOrgBouncycastleCryptoMacsSkeinMac

+ (jint)SKEIN_256 {
  return LibOrgBouncycastleCryptoMacsSkeinMac_SKEIN_256;
}

+ (jint)SKEIN_512 {
  return LibOrgBouncycastleCryptoMacsSkeinMac_SKEIN_512;
}

+ (jint)SKEIN_1024 {
  return LibOrgBouncycastleCryptoMacsSkeinMac_SKEIN_1024;
}

- (instancetype)initWithInt:(jint)stateSizeBits
                    withInt:(jint)digestSizeBits {
  LibOrgBouncycastleCryptoMacsSkeinMac_initWithInt_withInt_(self, stateSizeBits, digestSizeBits);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleCryptoMacsSkeinMac:(LibOrgBouncycastleCryptoMacsSkeinMac *)mac {
  LibOrgBouncycastleCryptoMacsSkeinMac_initWithLibOrgBouncycastleCryptoMacsSkeinMac_(self, mac);
  return self;
}

- (NSString *)getAlgorithmName {
  return JreStrcat("$ICI", @"Skein-MAC-", ([((LibOrgBouncycastleCryptoDigestsSkeinEngine *) nil_chk(engine_)) getBlockSize] * 8), '-', ([((LibOrgBouncycastleCryptoDigestsSkeinEngine *) nil_chk(engine_)) getOutputSize] * 8));
}

- (void)init__WithLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)params {
  LibOrgBouncycastleCryptoParamsSkeinParameters *skeinParameters;
  if ([params isKindOfClass:[LibOrgBouncycastleCryptoParamsSkeinParameters class]]) {
    skeinParameters = (LibOrgBouncycastleCryptoParamsSkeinParameters *) params;
  }
  else if ([params isKindOfClass:[LibOrgBouncycastleCryptoParamsKeyParameter class]]) {
    skeinParameters = [((LibOrgBouncycastleCryptoParamsSkeinParameters_Builder *) nil_chk([new_LibOrgBouncycastleCryptoParamsSkeinParameters_Builder_init() setKeyWithByteArray:[((LibOrgBouncycastleCryptoParamsKeyParameter *) nil_chk(((LibOrgBouncycastleCryptoParamsKeyParameter *) params))) getKey]])) build];
  }
  else {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$", @"Invalid parameter passed to Skein MAC init - ", [[((id<LibOrgBouncycastleCryptoCipherParameters>) nil_chk(params)) java_getClass] getName]));
  }
  if ([((LibOrgBouncycastleCryptoParamsSkeinParameters *) nil_chk(skeinParameters)) getKey] == nil) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Skein MAC requires a key parameter.");
  }
  [((LibOrgBouncycastleCryptoDigestsSkeinEngine *) nil_chk(engine_)) init__WithLibOrgBouncycastleCryptoParamsSkeinParameters:skeinParameters];
}

- (jint)getMacSize {
  return [((LibOrgBouncycastleCryptoDigestsSkeinEngine *) nil_chk(engine_)) getOutputSize];
}

- (void)reset {
  [((LibOrgBouncycastleCryptoDigestsSkeinEngine *) nil_chk(engine_)) reset];
}

- (void)updateWithByte:(jbyte)inArg {
  [((LibOrgBouncycastleCryptoDigestsSkeinEngine *) nil_chk(engine_)) updateWithByte:inArg];
}

- (void)updateWithByteArray:(IOSByteArray *)inArg
                    withInt:(jint)inOff
                    withInt:(jint)len {
  [((LibOrgBouncycastleCryptoDigestsSkeinEngine *) nil_chk(engine_)) updateWithByteArray:inArg withInt:inOff withInt:len];
}

- (jint)doFinalWithByteArray:(IOSByteArray *)outArg
                     withInt:(jint)outOff {
  return [((LibOrgBouncycastleCryptoDigestsSkeinEngine *) nil_chk(engine_)) doFinalWithByteArray:outArg withInt:outOff];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 2, 3, 4, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 5, 6, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 5, 7, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 8, 9, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithInt:withInt:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleCryptoMacsSkeinMac:);
  methods[2].selector = @selector(getAlgorithmName);
  methods[3].selector = @selector(init__WithLibOrgBouncycastleCryptoCipherParameters:);
  methods[4].selector = @selector(getMacSize);
  methods[5].selector = @selector(reset);
  methods[6].selector = @selector(updateWithByte:);
  methods[7].selector = @selector(updateWithByteArray:withInt:withInt:);
  methods[8].selector = @selector(doFinalWithByteArray:withInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "SKEIN_256", "I", .constantValue.asInt = LibOrgBouncycastleCryptoMacsSkeinMac_SKEIN_256, 0x19, -1, -1, -1, -1 },
    { "SKEIN_512", "I", .constantValue.asInt = LibOrgBouncycastleCryptoMacsSkeinMac_SKEIN_512, 0x19, -1, -1, -1, -1 },
    { "SKEIN_1024", "I", .constantValue.asInt = LibOrgBouncycastleCryptoMacsSkeinMac_SKEIN_1024, 0x19, -1, -1, -1, -1 },
    { "engine_", "LLibOrgBouncycastleCryptoDigestsSkeinEngine;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "II", "LLibOrgBouncycastleCryptoMacsSkeinMac;", "init", "LLibOrgBouncycastleCryptoCipherParameters;", "LJavaLangIllegalArgumentException;", "update", "B", "[BII", "doFinal", "[BI" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoMacsSkeinMac = { "SkeinMac", "lib.org.bouncycastle.crypto.macs", ptrTable, methods, fields, 7, 0x1, 9, 4, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoMacsSkeinMac;
}

@end

void LibOrgBouncycastleCryptoMacsSkeinMac_initWithInt_withInt_(LibOrgBouncycastleCryptoMacsSkeinMac *self, jint stateSizeBits, jint digestSizeBits) {
  NSObject_init(self);
  self->engine_ = new_LibOrgBouncycastleCryptoDigestsSkeinEngine_initWithInt_withInt_(stateSizeBits, digestSizeBits);
}

LibOrgBouncycastleCryptoMacsSkeinMac *new_LibOrgBouncycastleCryptoMacsSkeinMac_initWithInt_withInt_(jint stateSizeBits, jint digestSizeBits) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoMacsSkeinMac, initWithInt_withInt_, stateSizeBits, digestSizeBits)
}

LibOrgBouncycastleCryptoMacsSkeinMac *create_LibOrgBouncycastleCryptoMacsSkeinMac_initWithInt_withInt_(jint stateSizeBits, jint digestSizeBits) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoMacsSkeinMac, initWithInt_withInt_, stateSizeBits, digestSizeBits)
}

void LibOrgBouncycastleCryptoMacsSkeinMac_initWithLibOrgBouncycastleCryptoMacsSkeinMac_(LibOrgBouncycastleCryptoMacsSkeinMac *self, LibOrgBouncycastleCryptoMacsSkeinMac *mac) {
  NSObject_init(self);
  self->engine_ = new_LibOrgBouncycastleCryptoDigestsSkeinEngine_initWithLibOrgBouncycastleCryptoDigestsSkeinEngine_(((LibOrgBouncycastleCryptoMacsSkeinMac *) nil_chk(mac))->engine_);
}

LibOrgBouncycastleCryptoMacsSkeinMac *new_LibOrgBouncycastleCryptoMacsSkeinMac_initWithLibOrgBouncycastleCryptoMacsSkeinMac_(LibOrgBouncycastleCryptoMacsSkeinMac *mac) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoMacsSkeinMac, initWithLibOrgBouncycastleCryptoMacsSkeinMac_, mac)
}

LibOrgBouncycastleCryptoMacsSkeinMac *create_LibOrgBouncycastleCryptoMacsSkeinMac_initWithLibOrgBouncycastleCryptoMacsSkeinMac_(LibOrgBouncycastleCryptoMacsSkeinMac *mac) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoMacsSkeinMac, initWithLibOrgBouncycastleCryptoMacsSkeinMac_, mac)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoMacsSkeinMac)
