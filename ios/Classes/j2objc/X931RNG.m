//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/prng/X931RNG.java
//

#include "BlockCipher.h"
#include "EntropySource.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "X931RNG.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/IllegalStateException.h"
#include "java/lang/System.h"

@interface LibOrgBouncycastleCryptoPrngX931RNG () {
 @public
  id<LibOrgBouncycastleCryptoBlockCipher> engine_;
  id<LibOrgBouncycastleCryptoPrngEntropySource> entropySource_;
  IOSByteArray *DT_;
  IOSByteArray *I_;
  IOSByteArray *R_;
  IOSByteArray *V_;
  jlong reseedCounter_;
}

- (void)processWithByteArray:(IOSByteArray *)res
               withByteArray:(IOSByteArray *)a
               withByteArray:(IOSByteArray *)b;

- (void)incrementWithByteArray:(IOSByteArray *)val;

+ (jboolean)isTooLargeWithByteArray:(IOSByteArray *)bytes
                            withInt:(jint)maxBytes;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoPrngX931RNG, engine_, id<LibOrgBouncycastleCryptoBlockCipher>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoPrngX931RNG, entropySource_, id<LibOrgBouncycastleCryptoPrngEntropySource>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoPrngX931RNG, DT_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoPrngX931RNG, I_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoPrngX931RNG, R_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoPrngX931RNG, V_, IOSByteArray *)

inline jlong LibOrgBouncycastleCryptoPrngX931RNG_get_BLOCK64_RESEED_MAX(void);
#define LibOrgBouncycastleCryptoPrngX931RNG_BLOCK64_RESEED_MAX 32768LL
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoPrngX931RNG, BLOCK64_RESEED_MAX, jlong)

inline jlong LibOrgBouncycastleCryptoPrngX931RNG_get_BLOCK128_RESEED_MAX(void);
#define LibOrgBouncycastleCryptoPrngX931RNG_BLOCK128_RESEED_MAX 8388608LL
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoPrngX931RNG, BLOCK128_RESEED_MAX, jlong)

inline jint LibOrgBouncycastleCryptoPrngX931RNG_get_BLOCK64_MAX_BITS_REQUEST(void);
#define LibOrgBouncycastleCryptoPrngX931RNG_BLOCK64_MAX_BITS_REQUEST 4096
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoPrngX931RNG, BLOCK64_MAX_BITS_REQUEST, jint)

inline jint LibOrgBouncycastleCryptoPrngX931RNG_get_BLOCK128_MAX_BITS_REQUEST(void);
#define LibOrgBouncycastleCryptoPrngX931RNG_BLOCK128_MAX_BITS_REQUEST 262144
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoPrngX931RNG, BLOCK128_MAX_BITS_REQUEST, jint)

__attribute__((unused)) static void LibOrgBouncycastleCryptoPrngX931RNG_processWithByteArray_withByteArray_withByteArray_(LibOrgBouncycastleCryptoPrngX931RNG *self, IOSByteArray *res, IOSByteArray *a, IOSByteArray *b);

__attribute__((unused)) static void LibOrgBouncycastleCryptoPrngX931RNG_incrementWithByteArray_(LibOrgBouncycastleCryptoPrngX931RNG *self, IOSByteArray *val);

__attribute__((unused)) static jboolean LibOrgBouncycastleCryptoPrngX931RNG_isTooLargeWithByteArray_withInt_(IOSByteArray *bytes, jint maxBytes);

@implementation LibOrgBouncycastleCryptoPrngX931RNG

- (instancetype)initWithLibOrgBouncycastleCryptoBlockCipher:(id<LibOrgBouncycastleCryptoBlockCipher>)engine
                                              withByteArray:(IOSByteArray *)dateTimeVector
              withLibOrgBouncycastleCryptoPrngEntropySource:(id<LibOrgBouncycastleCryptoPrngEntropySource>)entropySource {
  LibOrgBouncycastleCryptoPrngX931RNG_initWithLibOrgBouncycastleCryptoBlockCipher_withByteArray_withLibOrgBouncycastleCryptoPrngEntropySource_(self, engine, dateTimeVector, entropySource);
  return self;
}

- (jint)generateWithByteArray:(IOSByteArray *)output
                  withBoolean:(jboolean)predictionResistant {
  if (((IOSByteArray *) nil_chk(R_))->size_ == 8) {
    if (reseedCounter_ > LibOrgBouncycastleCryptoPrngX931RNG_BLOCK64_RESEED_MAX) {
      return -1;
    }
    if (LibOrgBouncycastleCryptoPrngX931RNG_isTooLargeWithByteArray_withInt_(output, LibOrgBouncycastleCryptoPrngX931RNG_BLOCK64_MAX_BITS_REQUEST / 8)) {
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$I", @"Number of bits per request limited to ", LibOrgBouncycastleCryptoPrngX931RNG_BLOCK64_MAX_BITS_REQUEST));
    }
  }
  else {
    if (reseedCounter_ > LibOrgBouncycastleCryptoPrngX931RNG_BLOCK128_RESEED_MAX) {
      return -1;
    }
    if (LibOrgBouncycastleCryptoPrngX931RNG_isTooLargeWithByteArray_withInt_(output, LibOrgBouncycastleCryptoPrngX931RNG_BLOCK128_MAX_BITS_REQUEST / 8)) {
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$I", @"Number of bits per request limited to ", LibOrgBouncycastleCryptoPrngX931RNG_BLOCK128_MAX_BITS_REQUEST));
    }
  }
  if (predictionResistant || V_ == nil) {
    V_ = [((id<LibOrgBouncycastleCryptoPrngEntropySource>) nil_chk(entropySource_)) getEntropy];
    if (((IOSByteArray *) nil_chk(V_))->size_ != [((id<LibOrgBouncycastleCryptoBlockCipher>) nil_chk(engine_)) getBlockSize]) {
      @throw new_JavaLangIllegalStateException_initWithNSString_(@"Insufficient entropy returned");
    }
  }
  jint m = ((IOSByteArray *) nil_chk(output))->size_ / R_->size_;
  for (jint i = 0; i < m; i++) {
    [((id<LibOrgBouncycastleCryptoBlockCipher>) nil_chk(engine_)) processBlockWithByteArray:DT_ withInt:0 withByteArray:I_ withInt:0];
    LibOrgBouncycastleCryptoPrngX931RNG_processWithByteArray_withByteArray_withByteArray_(self, R_, I_, V_);
    LibOrgBouncycastleCryptoPrngX931RNG_processWithByteArray_withByteArray_withByteArray_(self, V_, R_, I_);
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(R_, 0, output, i * R_->size_, R_->size_);
    LibOrgBouncycastleCryptoPrngX931RNG_incrementWithByteArray_(self, DT_);
  }
  jint bytesToCopy = (output->size_ - m * R_->size_);
  if (bytesToCopy > 0) {
    [((id<LibOrgBouncycastleCryptoBlockCipher>) nil_chk(engine_)) processBlockWithByteArray:DT_ withInt:0 withByteArray:I_ withInt:0];
    LibOrgBouncycastleCryptoPrngX931RNG_processWithByteArray_withByteArray_withByteArray_(self, R_, I_, V_);
    LibOrgBouncycastleCryptoPrngX931RNG_processWithByteArray_withByteArray_withByteArray_(self, V_, R_, I_);
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(R_, 0, output, m * R_->size_, bytesToCopy);
    LibOrgBouncycastleCryptoPrngX931RNG_incrementWithByteArray_(self, DT_);
  }
  reseedCounter_++;
  return output->size_;
}

- (void)reseed {
  V_ = [((id<LibOrgBouncycastleCryptoPrngEntropySource>) nil_chk(entropySource_)) getEntropy];
  if (((IOSByteArray *) nil_chk(V_))->size_ != [((id<LibOrgBouncycastleCryptoBlockCipher>) nil_chk(engine_)) getBlockSize]) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"Insufficient entropy returned");
  }
  reseedCounter_ = 1;
}

- (id<LibOrgBouncycastleCryptoPrngEntropySource>)getEntropySource {
  return entropySource_;
}

- (void)processWithByteArray:(IOSByteArray *)res
               withByteArray:(IOSByteArray *)a
               withByteArray:(IOSByteArray *)b {
  LibOrgBouncycastleCryptoPrngX931RNG_processWithByteArray_withByteArray_withByteArray_(self, res, a, b);
}

- (void)incrementWithByteArray:(IOSByteArray *)val {
  LibOrgBouncycastleCryptoPrngX931RNG_incrementWithByteArray_(self, val);
}

+ (jboolean)isTooLargeWithByteArray:(IOSByteArray *)bytes
                            withInt:(jint)maxBytes {
  return LibOrgBouncycastleCryptoPrngX931RNG_isTooLargeWithByteArray_withInt_(bytes, maxBytes);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "I", 0x0, 1, 2, -1, -1, -1, -1 },
    { NULL, "V", 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoPrngEntropySource;", 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 3, 4, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 5, 6, -1, -1, -1, -1 },
    { NULL, "Z", 0xa, 7, 8, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleCryptoBlockCipher:withByteArray:withLibOrgBouncycastleCryptoPrngEntropySource:);
  methods[1].selector = @selector(generateWithByteArray:withBoolean:);
  methods[2].selector = @selector(reseed);
  methods[3].selector = @selector(getEntropySource);
  methods[4].selector = @selector(processWithByteArray:withByteArray:withByteArray:);
  methods[5].selector = @selector(incrementWithByteArray:);
  methods[6].selector = @selector(isTooLargeWithByteArray:withInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "BLOCK64_RESEED_MAX", "J", .constantValue.asLong = LibOrgBouncycastleCryptoPrngX931RNG_BLOCK64_RESEED_MAX, 0x1a, -1, -1, -1, -1 },
    { "BLOCK128_RESEED_MAX", "J", .constantValue.asLong = LibOrgBouncycastleCryptoPrngX931RNG_BLOCK128_RESEED_MAX, 0x1a, -1, -1, -1, -1 },
    { "BLOCK64_MAX_BITS_REQUEST", "I", .constantValue.asInt = LibOrgBouncycastleCryptoPrngX931RNG_BLOCK64_MAX_BITS_REQUEST, 0x1a, -1, -1, -1, -1 },
    { "BLOCK128_MAX_BITS_REQUEST", "I", .constantValue.asInt = LibOrgBouncycastleCryptoPrngX931RNG_BLOCK128_MAX_BITS_REQUEST, 0x1a, -1, -1, -1, -1 },
    { "engine_", "LLibOrgBouncycastleCryptoBlockCipher;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "entropySource_", "LLibOrgBouncycastleCryptoPrngEntropySource;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "DT_", "[B", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "I_", "[B", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "R_", "[B", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "V_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "reseedCounter_", "J", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleCryptoBlockCipher;[BLLibOrgBouncycastleCryptoPrngEntropySource;", "generate", "[BZ", "process", "[B[B[B", "increment", "[B", "isTooLarge", "[BI" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoPrngX931RNG = { "X931RNG", "lib.org.bouncycastle.crypto.prng", ptrTable, methods, fields, 7, 0x1, 7, 11, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoPrngX931RNG;
}

@end

void LibOrgBouncycastleCryptoPrngX931RNG_initWithLibOrgBouncycastleCryptoBlockCipher_withByteArray_withLibOrgBouncycastleCryptoPrngEntropySource_(LibOrgBouncycastleCryptoPrngX931RNG *self, id<LibOrgBouncycastleCryptoBlockCipher> engine, IOSByteArray *dateTimeVector, id<LibOrgBouncycastleCryptoPrngEntropySource> entropySource) {
  NSObject_init(self);
  self->reseedCounter_ = 1;
  self->engine_ = engine;
  self->entropySource_ = entropySource;
  self->DT_ = [IOSByteArray newArrayWithLength:[((id<LibOrgBouncycastleCryptoBlockCipher>) nil_chk(engine)) getBlockSize]];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(dateTimeVector, 0, self->DT_, 0, self->DT_->size_);
  self->I_ = [IOSByteArray newArrayWithLength:[engine getBlockSize]];
  self->R_ = [IOSByteArray newArrayWithLength:[engine getBlockSize]];
}

LibOrgBouncycastleCryptoPrngX931RNG *new_LibOrgBouncycastleCryptoPrngX931RNG_initWithLibOrgBouncycastleCryptoBlockCipher_withByteArray_withLibOrgBouncycastleCryptoPrngEntropySource_(id<LibOrgBouncycastleCryptoBlockCipher> engine, IOSByteArray *dateTimeVector, id<LibOrgBouncycastleCryptoPrngEntropySource> entropySource) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoPrngX931RNG, initWithLibOrgBouncycastleCryptoBlockCipher_withByteArray_withLibOrgBouncycastleCryptoPrngEntropySource_, engine, dateTimeVector, entropySource)
}

LibOrgBouncycastleCryptoPrngX931RNG *create_LibOrgBouncycastleCryptoPrngX931RNG_initWithLibOrgBouncycastleCryptoBlockCipher_withByteArray_withLibOrgBouncycastleCryptoPrngEntropySource_(id<LibOrgBouncycastleCryptoBlockCipher> engine, IOSByteArray *dateTimeVector, id<LibOrgBouncycastleCryptoPrngEntropySource> entropySource) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoPrngX931RNG, initWithLibOrgBouncycastleCryptoBlockCipher_withByteArray_withLibOrgBouncycastleCryptoPrngEntropySource_, engine, dateTimeVector, entropySource)
}

void LibOrgBouncycastleCryptoPrngX931RNG_processWithByteArray_withByteArray_withByteArray_(LibOrgBouncycastleCryptoPrngX931RNG *self, IOSByteArray *res, IOSByteArray *a, IOSByteArray *b) {
  for (jint i = 0; i != ((IOSByteArray *) nil_chk(res))->size_; i++) {
    *IOSByteArray_GetRef(res, i) = (jbyte) (IOSByteArray_Get(nil_chk(a), i) ^ IOSByteArray_Get(nil_chk(b), i));
  }
  [((id<LibOrgBouncycastleCryptoBlockCipher>) nil_chk(self->engine_)) processBlockWithByteArray:res withInt:0 withByteArray:res withInt:0];
}

void LibOrgBouncycastleCryptoPrngX931RNG_incrementWithByteArray_(LibOrgBouncycastleCryptoPrngX931RNG *self, IOSByteArray *val) {
  for (jint i = ((IOSByteArray *) nil_chk(val))->size_ - 1; i >= 0; i--) {
    if (++(*IOSByteArray_GetRef(val, i)) != 0) {
      break;
    }
  }
}

jboolean LibOrgBouncycastleCryptoPrngX931RNG_isTooLargeWithByteArray_withInt_(IOSByteArray *bytes, jint maxBytes) {
  LibOrgBouncycastleCryptoPrngX931RNG_initialize();
  return bytes != nil && bytes->size_ > maxBytes;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoPrngX931RNG)
