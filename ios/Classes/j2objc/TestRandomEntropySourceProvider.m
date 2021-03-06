//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/util/test/TestRandomEntropySourceProvider.java
//

#include "EntropySource.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "TestRandomEntropySourceProvider.h"
#include "java/security/SecureRandom.h"

@interface LibOrgBouncycastleUtilTestTestRandomEntropySourceProvider () {
 @public
  JavaSecuritySecureRandom *_sr_;
  jboolean _predictionResistant_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleUtilTestTestRandomEntropySourceProvider, _sr_, JavaSecuritySecureRandom *)

@interface LibOrgBouncycastleUtilTestTestRandomEntropySourceProvider_1 : NSObject < LibOrgBouncycastleCryptoPrngEntropySource > {
 @public
  LibOrgBouncycastleUtilTestTestRandomEntropySourceProvider *this$0_;
  jint val$bitsRequired_;
}

- (instancetype)initWithLibOrgBouncycastleUtilTestTestRandomEntropySourceProvider:(LibOrgBouncycastleUtilTestTestRandomEntropySourceProvider *)outer$
                                                                          withInt:(jint)capture$0;

- (jboolean)isPredictionResistant;

- (IOSByteArray *)getEntropy;

- (jint)entropySize;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleUtilTestTestRandomEntropySourceProvider_1)

__attribute__((unused)) static void LibOrgBouncycastleUtilTestTestRandomEntropySourceProvider_1_initWithLibOrgBouncycastleUtilTestTestRandomEntropySourceProvider_withInt_(LibOrgBouncycastleUtilTestTestRandomEntropySourceProvider_1 *self, LibOrgBouncycastleUtilTestTestRandomEntropySourceProvider *outer$, jint capture$0);

__attribute__((unused)) static LibOrgBouncycastleUtilTestTestRandomEntropySourceProvider_1 *new_LibOrgBouncycastleUtilTestTestRandomEntropySourceProvider_1_initWithLibOrgBouncycastleUtilTestTestRandomEntropySourceProvider_withInt_(LibOrgBouncycastleUtilTestTestRandomEntropySourceProvider *outer$, jint capture$0) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleUtilTestTestRandomEntropySourceProvider_1 *create_LibOrgBouncycastleUtilTestTestRandomEntropySourceProvider_1_initWithLibOrgBouncycastleUtilTestTestRandomEntropySourceProvider_withInt_(LibOrgBouncycastleUtilTestTestRandomEntropySourceProvider *outer$, jint capture$0);

@implementation LibOrgBouncycastleUtilTestTestRandomEntropySourceProvider

- (instancetype)initWithBoolean:(jboolean)isPredictionResistant {
  LibOrgBouncycastleUtilTestTestRandomEntropySourceProvider_initWithBoolean_(self, isPredictionResistant);
  return self;
}

- (id<LibOrgBouncycastleCryptoPrngEntropySource>)getWithInt:(jint)bitsRequired {
  return new_LibOrgBouncycastleUtilTestTestRandomEntropySourceProvider_1_initWithLibOrgBouncycastleUtilTestTestRandomEntropySourceProvider_withInt_(self, bitsRequired);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoPrngEntropySource;", 0x1, 1, 2, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithBoolean:);
  methods[1].selector = @selector(getWithInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "_sr_", "LJavaSecuritySecureRandom;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "_predictionResistant_", "Z", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "Z", "get", "I" };
  static const J2ObjcClassInfo _LibOrgBouncycastleUtilTestTestRandomEntropySourceProvider = { "TestRandomEntropySourceProvider", "lib.org.bouncycastle.util.test", ptrTable, methods, fields, 7, 0x1, 2, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleUtilTestTestRandomEntropySourceProvider;
}

@end

void LibOrgBouncycastleUtilTestTestRandomEntropySourceProvider_initWithBoolean_(LibOrgBouncycastleUtilTestTestRandomEntropySourceProvider *self, jboolean isPredictionResistant) {
  NSObject_init(self);
  self->_sr_ = new_JavaSecuritySecureRandom_init();
  self->_predictionResistant_ = isPredictionResistant;
}

LibOrgBouncycastleUtilTestTestRandomEntropySourceProvider *new_LibOrgBouncycastleUtilTestTestRandomEntropySourceProvider_initWithBoolean_(jboolean isPredictionResistant) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleUtilTestTestRandomEntropySourceProvider, initWithBoolean_, isPredictionResistant)
}

LibOrgBouncycastleUtilTestTestRandomEntropySourceProvider *create_LibOrgBouncycastleUtilTestTestRandomEntropySourceProvider_initWithBoolean_(jboolean isPredictionResistant) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleUtilTestTestRandomEntropySourceProvider, initWithBoolean_, isPredictionResistant)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleUtilTestTestRandomEntropySourceProvider)

@implementation LibOrgBouncycastleUtilTestTestRandomEntropySourceProvider_1

- (instancetype)initWithLibOrgBouncycastleUtilTestTestRandomEntropySourceProvider:(LibOrgBouncycastleUtilTestTestRandomEntropySourceProvider *)outer$
                                                                          withInt:(jint)capture$0 {
  LibOrgBouncycastleUtilTestTestRandomEntropySourceProvider_1_initWithLibOrgBouncycastleUtilTestTestRandomEntropySourceProvider_withInt_(self, outer$, capture$0);
  return self;
}

- (jboolean)isPredictionResistant {
  return this$0_->_predictionResistant_;
}

- (IOSByteArray *)getEntropy {
  IOSByteArray *rv = [IOSByteArray newArrayWithLength:(val$bitsRequired_ + 7) / 8];
  [((JavaSecuritySecureRandom *) nil_chk(this$0_->_sr_)) nextBytesWithByteArray:rv];
  return rv;
}

- (jint)entropySize {
  return val$bitsRequired_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleUtilTestTestRandomEntropySourceProvider:withInt:);
  methods[1].selector = @selector(isPredictionResistant);
  methods[2].selector = @selector(getEntropy);
  methods[3].selector = @selector(entropySize);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "this$0_", "LLibOrgBouncycastleUtilTestTestRandomEntropySourceProvider;", .constantValue.asLong = 0, 0x1012, -1, -1, -1, -1 },
    { "val$bitsRequired_", "I", .constantValue.asLong = 0, 0x1012, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleUtilTestTestRandomEntropySourceProvider;", "getWithInt:" };
  static const J2ObjcClassInfo _LibOrgBouncycastleUtilTestTestRandomEntropySourceProvider_1 = { "", "lib.org.bouncycastle.util.test", ptrTable, methods, fields, 7, 0x8010, 4, 2, 0, -1, 1, -1, -1 };
  return &_LibOrgBouncycastleUtilTestTestRandomEntropySourceProvider_1;
}

@end

void LibOrgBouncycastleUtilTestTestRandomEntropySourceProvider_1_initWithLibOrgBouncycastleUtilTestTestRandomEntropySourceProvider_withInt_(LibOrgBouncycastleUtilTestTestRandomEntropySourceProvider_1 *self, LibOrgBouncycastleUtilTestTestRandomEntropySourceProvider *outer$, jint capture$0) {
  self->this$0_ = outer$;
  self->val$bitsRequired_ = capture$0;
  NSObject_init(self);
}

LibOrgBouncycastleUtilTestTestRandomEntropySourceProvider_1 *new_LibOrgBouncycastleUtilTestTestRandomEntropySourceProvider_1_initWithLibOrgBouncycastleUtilTestTestRandomEntropySourceProvider_withInt_(LibOrgBouncycastleUtilTestTestRandomEntropySourceProvider *outer$, jint capture$0) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleUtilTestTestRandomEntropySourceProvider_1, initWithLibOrgBouncycastleUtilTestTestRandomEntropySourceProvider_withInt_, outer$, capture$0)
}

LibOrgBouncycastleUtilTestTestRandomEntropySourceProvider_1 *create_LibOrgBouncycastleUtilTestTestRandomEntropySourceProvider_1_initWithLibOrgBouncycastleUtilTestTestRandomEntropySourceProvider_withInt_(LibOrgBouncycastleUtilTestTestRandomEntropySourceProvider *outer$, jint capture$0) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleUtilTestTestRandomEntropySourceProvider_1, initWithLibOrgBouncycastleUtilTestTestRandomEntropySourceProvider_withInt_, outer$, capture$0)
}
