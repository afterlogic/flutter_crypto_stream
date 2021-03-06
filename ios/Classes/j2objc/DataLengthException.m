//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/DataLengthException.java
//

#include "DataLengthException.h"
#include "J2ObjC_source.h"
#include "RuntimeCryptoException.h"

@implementation LibOrgBouncycastleCryptoDataLengthException

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoDataLengthException_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (instancetype)initWithNSString:(NSString *)message {
  LibOrgBouncycastleCryptoDataLengthException_initWithNSString_(self, message);
  return self;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(initWithNSString:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "LNSString;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoDataLengthException = { "DataLengthException", "lib.org.bouncycastle.crypto", ptrTable, methods, NULL, 7, 0x1, 2, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoDataLengthException;
}

@end

void LibOrgBouncycastleCryptoDataLengthException_init(LibOrgBouncycastleCryptoDataLengthException *self) {
  LibOrgBouncycastleCryptoRuntimeCryptoException_init(self);
}

LibOrgBouncycastleCryptoDataLengthException *new_LibOrgBouncycastleCryptoDataLengthException_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoDataLengthException, init)
}

LibOrgBouncycastleCryptoDataLengthException *create_LibOrgBouncycastleCryptoDataLengthException_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoDataLengthException, init)
}

void LibOrgBouncycastleCryptoDataLengthException_initWithNSString_(LibOrgBouncycastleCryptoDataLengthException *self, NSString *message) {
  LibOrgBouncycastleCryptoRuntimeCryptoException_initWithNSString_(self, message);
}

LibOrgBouncycastleCryptoDataLengthException *new_LibOrgBouncycastleCryptoDataLengthException_initWithNSString_(NSString *message) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoDataLengthException, initWithNSString_, message)
}

LibOrgBouncycastleCryptoDataLengthException *create_LibOrgBouncycastleCryptoDataLengthException_initWithNSString_(NSString *message) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoDataLengthException, initWithNSString_, message)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoDataLengthException)
