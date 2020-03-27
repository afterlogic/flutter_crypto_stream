//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/symmetric/util/BaseAlgorithmParameters.java
//

#include "BaseAlgorithmParameters.h"
#include "IOSClass.h"
#include "J2ObjC_source.h"
#include "java/lang/NullPointerException.h"
#include "java/security/AlgorithmParametersSpi.h"
#include "java/security/spec/AlgorithmParameterSpec.h"

@implementation LibOrgBouncycastleJcajceProviderSymmetricUtilBaseAlgorithmParameters

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderSymmetricUtilBaseAlgorithmParameters_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (jboolean)isASN1FormatStringWithNSString:(NSString *)format {
  return format == nil || [format isEqual:@"ASN.1"];
}

- (id<JavaSecuritySpecAlgorithmParameterSpec>)engineGetParameterSpecWithIOSClass:(IOSClass *)paramSpec {
  if (paramSpec == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"argument to getParameterSpec must not be null");
  }
  return [self localEngineGetParameterSpecWithIOSClass:paramSpec];
}

- (id<JavaSecuritySpecAlgorithmParameterSpec>)localEngineGetParameterSpecWithIOSClass:(IOSClass *)paramSpec {
  // can't call an abstract method
  [self doesNotRecognizeSelector:_cmd];
  return 0;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x4, 0, 1, -1, -1, -1, -1 },
    { NULL, "LJavaSecuritySpecAlgorithmParameterSpec;", 0x4, 2, 3, 4, -1, -1, -1 },
    { NULL, "LJavaSecuritySpecAlgorithmParameterSpec;", 0x404, 5, 3, 4, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(isASN1FormatStringWithNSString:);
  methods[2].selector = @selector(engineGetParameterSpecWithIOSClass:);
  methods[3].selector = @selector(localEngineGetParameterSpecWithIOSClass:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "isASN1FormatString", "LNSString;", "engineGetParameterSpec", "LIOSClass;", "LJavaSecuritySpecInvalidParameterSpecException;", "localEngineGetParameterSpec" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricUtilBaseAlgorithmParameters = { "BaseAlgorithmParameters", "lib.org.bouncycastle.jcajce.provider.symmetric.util", ptrTable, methods, NULL, 7, 0x401, 4, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricUtilBaseAlgorithmParameters;
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricUtilBaseAlgorithmParameters_init(LibOrgBouncycastleJcajceProviderSymmetricUtilBaseAlgorithmParameters *self) {
  JavaSecurityAlgorithmParametersSpi_init(self);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricUtilBaseAlgorithmParameters)