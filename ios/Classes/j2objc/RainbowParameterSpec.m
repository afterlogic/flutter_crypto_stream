//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/jcajce/spec/RainbowParameterSpec.java
//

#include "Arrays.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "RainbowParameterSpec.h"
#include "java/lang/IllegalArgumentException.h"

@interface LibOrgBouncycastlePqcJcajceSpecRainbowParameterSpec () {
 @public
  IOSIntArray *vi_;
}

- (void)checkParams;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcJcajceSpecRainbowParameterSpec, vi_, IOSIntArray *)

inline IOSIntArray *LibOrgBouncycastlePqcJcajceSpecRainbowParameterSpec_get_DEFAULT_VI(void);
static IOSIntArray *LibOrgBouncycastlePqcJcajceSpecRainbowParameterSpec_DEFAULT_VI;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastlePqcJcajceSpecRainbowParameterSpec, DEFAULT_VI, IOSIntArray *)

__attribute__((unused)) static void LibOrgBouncycastlePqcJcajceSpecRainbowParameterSpec_checkParams(LibOrgBouncycastlePqcJcajceSpecRainbowParameterSpec *self);

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastlePqcJcajceSpecRainbowParameterSpec)

@implementation LibOrgBouncycastlePqcJcajceSpecRainbowParameterSpec

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastlePqcJcajceSpecRainbowParameterSpec_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (instancetype)initWithIntArray:(IOSIntArray *)vi {
  LibOrgBouncycastlePqcJcajceSpecRainbowParameterSpec_initWithIntArray_(self, vi);
  return self;
}

- (void)checkParams {
  LibOrgBouncycastlePqcJcajceSpecRainbowParameterSpec_checkParams(self);
}

- (jint)getNumOfLayers {
  return ((IOSIntArray *) nil_chk(self->vi_))->size_ - 1;
}

- (jint)getDocumentLength {
  return IOSIntArray_Get(vi_, ((IOSIntArray *) nil_chk(vi_))->size_ - 1) - IOSIntArray_Get(vi_, 0);
}

- (IOSIntArray *)getVi {
  return LibOrgBouncycastleUtilArrays_cloneWithIntArray_(self->vi_);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "V", 0x2, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[I", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(initWithIntArray:);
  methods[2].selector = @selector(checkParams);
  methods[3].selector = @selector(getNumOfLayers);
  methods[4].selector = @selector(getDocumentLength);
  methods[5].selector = @selector(getVi);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "DEFAULT_VI", "[I", .constantValue.asLong = 0, 0x1a, -1, 1, -1, -1 },
    { "vi_", "[I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "[I", &LibOrgBouncycastlePqcJcajceSpecRainbowParameterSpec_DEFAULT_VI };
  static const J2ObjcClassInfo _LibOrgBouncycastlePqcJcajceSpecRainbowParameterSpec = { "RainbowParameterSpec", "lib.org.bouncycastle.pqc.jcajce.spec", ptrTable, methods, fields, 7, 0x1, 6, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastlePqcJcajceSpecRainbowParameterSpec;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastlePqcJcajceSpecRainbowParameterSpec class]) {
    LibOrgBouncycastlePqcJcajceSpecRainbowParameterSpec_DEFAULT_VI = [IOSIntArray newArrayWithInts:(jint[]){ 6, 12, 17, 22, 33 } count:5];
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastlePqcJcajceSpecRainbowParameterSpec)
  }
}

@end

void LibOrgBouncycastlePqcJcajceSpecRainbowParameterSpec_init(LibOrgBouncycastlePqcJcajceSpecRainbowParameterSpec *self) {
  NSObject_init(self);
  self->vi_ = LibOrgBouncycastlePqcJcajceSpecRainbowParameterSpec_DEFAULT_VI;
}

LibOrgBouncycastlePqcJcajceSpecRainbowParameterSpec *new_LibOrgBouncycastlePqcJcajceSpecRainbowParameterSpec_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcJcajceSpecRainbowParameterSpec, init)
}

LibOrgBouncycastlePqcJcajceSpecRainbowParameterSpec *create_LibOrgBouncycastlePqcJcajceSpecRainbowParameterSpec_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcJcajceSpecRainbowParameterSpec, init)
}

void LibOrgBouncycastlePqcJcajceSpecRainbowParameterSpec_initWithIntArray_(LibOrgBouncycastlePqcJcajceSpecRainbowParameterSpec *self, IOSIntArray *vi) {
  NSObject_init(self);
  self->vi_ = vi;
  LibOrgBouncycastlePqcJcajceSpecRainbowParameterSpec_checkParams(self);
}

LibOrgBouncycastlePqcJcajceSpecRainbowParameterSpec *new_LibOrgBouncycastlePqcJcajceSpecRainbowParameterSpec_initWithIntArray_(IOSIntArray *vi) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcJcajceSpecRainbowParameterSpec, initWithIntArray_, vi)
}

LibOrgBouncycastlePqcJcajceSpecRainbowParameterSpec *create_LibOrgBouncycastlePqcJcajceSpecRainbowParameterSpec_initWithIntArray_(IOSIntArray *vi) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcJcajceSpecRainbowParameterSpec, initWithIntArray_, vi)
}

void LibOrgBouncycastlePqcJcajceSpecRainbowParameterSpec_checkParams(LibOrgBouncycastlePqcJcajceSpecRainbowParameterSpec *self) {
  if (self->vi_ == nil) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"no layers defined.");
  }
  if (self->vi_->size_ > 1) {
    for (jint i = 0; i < self->vi_->size_ - 1; i++) {
      if (IOSIntArray_Get(self->vi_, i) >= IOSIntArray_Get(self->vi_, i + 1)) {
        @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"v[i] has to be smaller than v[i+1]");
      }
    }
  }
  else {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Rainbow needs at least 1 layer, such that v1 < v2.");
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastlePqcJcajceSpecRainbowParameterSpec)
