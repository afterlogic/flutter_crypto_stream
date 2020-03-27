//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/openpgp/bc/BcPGPPublicKeyRing.java
//

#include "BcKeyFingerprintCalculator.h"
#include "BcPGPPublicKeyRing.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "KeyFingerPrintCalculator.h"
#include "PGPPublicKeyRing.h"
#include "java/io/InputStream.h"

inline id<LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator> LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRing_get_fingerPrintCalculator(void);
inline id<LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator> LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRing_set_fingerPrintCalculator(id<LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator> value);
static id<LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator> LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRing_fingerPrintCalculator;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRing, fingerPrintCalculator, id<LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator>)

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRing)

@implementation LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRing

- (instancetype)initWithByteArray:(IOSByteArray *)encoding {
  LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRing_initWithByteArray_(self, encoding);
  return self;
}

- (instancetype)initWithJavaIoInputStream:(JavaIoInputStream *)inArg {
  LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRing_initWithJavaIoInputStream_(self, inArg);
  return self;
}

- (NSUInteger)countByEnumeratingWithState:(NSFastEnumerationState *)state objects:(__unsafe_unretained id *)stackbuf count:(NSUInteger)len {
  return JreDefaultFastEnumeration(self, state, stackbuf);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, 1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, 1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithByteArray:);
  methods[1].selector = @selector(initWithJavaIoInputStream:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "fingerPrintCalculator", "LLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator;", .constantValue.asLong = 0, 0xa, -1, 3, -1, -1 },
  };
  static const void *ptrTable[] = { "[B", "LJavaIoIOException;", "LJavaIoInputStream;", &LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRing_fingerPrintCalculator };
  static const J2ObjcClassInfo _LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRing = { "BcPGPPublicKeyRing", "lib.org.bouncycastle.openpgp.bc", ptrTable, methods, fields, 7, 0x1, 2, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRing;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRing class]) {
    LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRing_fingerPrintCalculator = new_LibOrgBouncycastleOpenpgpOperatorBcBcKeyFingerprintCalculator_init();
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRing)
  }
}

@end

void LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRing_initWithByteArray_(LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRing *self, IOSByteArray *encoding) {
  LibOrgBouncycastleOpenpgpPGPPublicKeyRing_initWithByteArray_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_(self, encoding, LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRing_fingerPrintCalculator);
}

LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRing *new_LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRing_initWithByteArray_(IOSByteArray *encoding) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRing, initWithByteArray_, encoding)
}

LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRing *create_LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRing_initWithByteArray_(IOSByteArray *encoding) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRing, initWithByteArray_, encoding)
}

void LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRing_initWithJavaIoInputStream_(LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRing *self, JavaIoInputStream *inArg) {
  LibOrgBouncycastleOpenpgpPGPPublicKeyRing_initWithJavaIoInputStream_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_(self, inArg, LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRing_fingerPrintCalculator);
}

LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRing *new_LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRing_initWithJavaIoInputStream_(JavaIoInputStream *inArg) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRing, initWithJavaIoInputStream_, inArg)
}

LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRing *create_LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRing_initWithJavaIoInputStream_(JavaIoInputStream *inArg) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRing, initWithJavaIoInputStream_, inArg)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleOpenpgpBcBcPGPPublicKeyRing)