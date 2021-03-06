//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/jcajce/spec/XMSSMTParameterSpec.java
//

#include "J2ObjC_source.h"
#include "XMSSMTParameterSpec.h"

@interface LibOrgBouncycastlePqcJcajceSpecXMSSMTParameterSpec () {
 @public
  jint height_;
  jint layers_;
  NSString *treeDigest_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcJcajceSpecXMSSMTParameterSpec, treeDigest_, NSString *)

NSString *LibOrgBouncycastlePqcJcajceSpecXMSSMTParameterSpec_SHA256 = @"SHA256";
NSString *LibOrgBouncycastlePqcJcajceSpecXMSSMTParameterSpec_SHA512 = @"SHA512";
NSString *LibOrgBouncycastlePqcJcajceSpecXMSSMTParameterSpec_SHAKE128 = @"SHAKE128";
NSString *LibOrgBouncycastlePqcJcajceSpecXMSSMTParameterSpec_SHAKE256 = @"SHAKE256";

@implementation LibOrgBouncycastlePqcJcajceSpecXMSSMTParameterSpec

+ (NSString *)SHA256 {
  return LibOrgBouncycastlePqcJcajceSpecXMSSMTParameterSpec_SHA256;
}

+ (NSString *)SHA512 {
  return LibOrgBouncycastlePqcJcajceSpecXMSSMTParameterSpec_SHA512;
}

+ (NSString *)SHAKE128 {
  return LibOrgBouncycastlePqcJcajceSpecXMSSMTParameterSpec_SHAKE128;
}

+ (NSString *)SHAKE256 {
  return LibOrgBouncycastlePqcJcajceSpecXMSSMTParameterSpec_SHAKE256;
}

- (instancetype)initWithInt:(jint)height
                    withInt:(jint)layers
               withNSString:(NSString *)treeDigest {
  LibOrgBouncycastlePqcJcajceSpecXMSSMTParameterSpec_initWithInt_withInt_withNSString_(self, height, layers, treeDigest);
  return self;
}

- (NSString *)getTreeDigest {
  return treeDigest_;
}

- (jint)getHeight {
  return height_;
}

- (jint)getLayers {
  return layers_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithInt:withInt:withNSString:);
  methods[1].selector = @selector(getTreeDigest);
  methods[2].selector = @selector(getHeight);
  methods[3].selector = @selector(getLayers);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "SHA256", "LNSString;", .constantValue.asLong = 0, 0x19, -1, 1, -1, -1 },
    { "SHA512", "LNSString;", .constantValue.asLong = 0, 0x19, -1, 2, -1, -1 },
    { "SHAKE128", "LNSString;", .constantValue.asLong = 0, 0x19, -1, 3, -1, -1 },
    { "SHAKE256", "LNSString;", .constantValue.asLong = 0, 0x19, -1, 4, -1, -1 },
    { "height_", "I", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "layers_", "I", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "treeDigest_", "LNSString;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "IILNSString;", &LibOrgBouncycastlePqcJcajceSpecXMSSMTParameterSpec_SHA256, &LibOrgBouncycastlePqcJcajceSpecXMSSMTParameterSpec_SHA512, &LibOrgBouncycastlePqcJcajceSpecXMSSMTParameterSpec_SHAKE128, &LibOrgBouncycastlePqcJcajceSpecXMSSMTParameterSpec_SHAKE256 };
  static const J2ObjcClassInfo _LibOrgBouncycastlePqcJcajceSpecXMSSMTParameterSpec = { "XMSSMTParameterSpec", "lib.org.bouncycastle.pqc.jcajce.spec", ptrTable, methods, fields, 7, 0x1, 4, 7, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastlePqcJcajceSpecXMSSMTParameterSpec;
}

@end

void LibOrgBouncycastlePqcJcajceSpecXMSSMTParameterSpec_initWithInt_withInt_withNSString_(LibOrgBouncycastlePqcJcajceSpecXMSSMTParameterSpec *self, jint height, jint layers, NSString *treeDigest) {
  NSObject_init(self);
  self->height_ = height;
  self->layers_ = layers;
  self->treeDigest_ = treeDigest;
}

LibOrgBouncycastlePqcJcajceSpecXMSSMTParameterSpec *new_LibOrgBouncycastlePqcJcajceSpecXMSSMTParameterSpec_initWithInt_withInt_withNSString_(jint height, jint layers, NSString *treeDigest) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcJcajceSpecXMSSMTParameterSpec, initWithInt_withInt_withNSString_, height, layers, treeDigest)
}

LibOrgBouncycastlePqcJcajceSpecXMSSMTParameterSpec *create_LibOrgBouncycastlePqcJcajceSpecXMSSMTParameterSpec_initWithInt_withInt_withNSString_(jint height, jint layers, NSString *treeDigest) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcJcajceSpecXMSSMTParameterSpec, initWithInt_withInt_withNSString_, height, layers, treeDigest)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastlePqcJcajceSpecXMSSMTParameterSpec)
