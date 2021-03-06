//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/gpg/keybox/jcajce/JcaKeyBoxBuilder.java
//

#include "DefaultJcaJceHelper.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "JcaBlobVerifier.h"
#include "JcaJceHelper.h"
#include "JcaKeyBox.h"
#include "JcaKeyBoxBuilder.h"
#include "JcaKeyFingerprintCalculator.h"
#include "NamedJcaJceHelper.h"
#include "ProviderJcaJceHelper.h"
#include "java/io/InputStream.h"
#include "java/security/Provider.h"

@interface LibOrgBouncycastleGpgKeyboxJcajceJcaKeyBoxBuilder () {
 @public
  id<LibOrgBouncycastleJcajceUtilJcaJceHelper> helper_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleGpgKeyboxJcajceJcaKeyBoxBuilder, helper_, id<LibOrgBouncycastleJcajceUtilJcaJceHelper>)

@implementation LibOrgBouncycastleGpgKeyboxJcajceJcaKeyBoxBuilder

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleGpgKeyboxJcajceJcaKeyBoxBuilder_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (LibOrgBouncycastleGpgKeyboxJcajceJcaKeyBoxBuilder *)setProviderWithJavaSecurityProvider:(JavaSecurityProvider *)provider {
  self->helper_ = new_LibOrgBouncycastleJcajceUtilProviderJcaJceHelper_initWithJavaSecurityProvider_(provider);
  return self;
}

- (LibOrgBouncycastleGpgKeyboxJcajceJcaKeyBoxBuilder *)setProviderWithNSString:(NSString *)providerName {
  self->helper_ = new_LibOrgBouncycastleJcajceUtilNamedJcaJceHelper_initWithNSString_(providerName);
  return self;
}

- (LibOrgBouncycastleGpgKeyboxJcajceJcaKeyBox *)buildWithJavaIoInputStream:(JavaIoInputStream *)input {
  return new_LibOrgBouncycastleGpgKeyboxJcajceJcaKeyBox_initWithJavaIoInputStream_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_withLibOrgBouncycastleGpgKeyboxBlobVerifier_(input, new_LibOrgBouncycastleOpenpgpOperatorJcajceJcaKeyFingerprintCalculator_init(), new_LibOrgBouncycastleGpgKeyboxJcajceJcaBlobVerifier_initWithLibOrgBouncycastleJcajceUtilJcaJceHelper_(helper_));
}

- (LibOrgBouncycastleGpgKeyboxJcajceJcaKeyBox *)buildWithByteArray:(IOSByteArray *)encoding {
  return new_LibOrgBouncycastleGpgKeyboxJcajceJcaKeyBox_initWithByteArray_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_withLibOrgBouncycastleGpgKeyboxBlobVerifier_(encoding, new_LibOrgBouncycastleOpenpgpOperatorJcajceJcaKeyFingerprintCalculator_init(), new_LibOrgBouncycastleGpgKeyboxJcajceJcaBlobVerifier_initWithLibOrgBouncycastleJcajceUtilJcaJceHelper_(helper_));
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleGpgKeyboxJcajceJcaKeyBoxBuilder;", 0x1, 0, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleGpgKeyboxJcajceJcaKeyBoxBuilder;", 0x1, 0, 2, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleGpgKeyboxJcajceJcaKeyBox;", 0x1, 3, 4, 5, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleGpgKeyboxJcajceJcaKeyBox;", 0x1, 3, 6, 5, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(setProviderWithJavaSecurityProvider:);
  methods[2].selector = @selector(setProviderWithNSString:);
  methods[3].selector = @selector(buildWithJavaIoInputStream:);
  methods[4].selector = @selector(buildWithByteArray:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "helper_", "LLibOrgBouncycastleJcajceUtilJcaJceHelper;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "setProvider", "LJavaSecurityProvider;", "LNSString;", "build", "LJavaIoInputStream;", "LJavaSecurityNoSuchProviderException;LJavaSecurityNoSuchAlgorithmException;LJavaIoIOException;", "[B" };
  static const J2ObjcClassInfo _LibOrgBouncycastleGpgKeyboxJcajceJcaKeyBoxBuilder = { "JcaKeyBoxBuilder", "lib.org.bouncycastle.gpg.keybox.jcajce", ptrTable, methods, fields, 7, 0x1, 5, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleGpgKeyboxJcajceJcaKeyBoxBuilder;
}

@end

void LibOrgBouncycastleGpgKeyboxJcajceJcaKeyBoxBuilder_init(LibOrgBouncycastleGpgKeyboxJcajceJcaKeyBoxBuilder *self) {
  NSObject_init(self);
  self->helper_ = new_LibOrgBouncycastleJcajceUtilDefaultJcaJceHelper_init();
}

LibOrgBouncycastleGpgKeyboxJcajceJcaKeyBoxBuilder *new_LibOrgBouncycastleGpgKeyboxJcajceJcaKeyBoxBuilder_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleGpgKeyboxJcajceJcaKeyBoxBuilder, init)
}

LibOrgBouncycastleGpgKeyboxJcajceJcaKeyBoxBuilder *create_LibOrgBouncycastleGpgKeyboxJcajceJcaKeyBoxBuilder_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleGpgKeyboxJcajceJcaKeyBoxBuilder, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleGpgKeyboxJcajceJcaKeyBoxBuilder)
