//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/com/afterlogic/pgp/PgpError.java
//

#include "J2ObjC_source.h"
#include "PgpError.h"
#include "PgpErrorCase.h"
#include "java/lang/Throwable.h"

@interface LibComAfterlogicPgpPgpError () {
 @public
  LibComAfterlogicPgpPgpErrorCase *errorCase_;
}

@end

J2OBJC_FIELD_SETTER(LibComAfterlogicPgpPgpError, errorCase_, LibComAfterlogicPgpPgpErrorCase *)

@implementation LibComAfterlogicPgpPgpError

- (instancetype)initWithLibComAfterlogicPgpPgpErrorCase:(LibComAfterlogicPgpPgpErrorCase *)errorCase {
  LibComAfterlogicPgpPgpError_initWithLibComAfterlogicPgpPgpErrorCase_(self, errorCase);
  return self;
}

- (LibComAfterlogicPgpPgpErrorCase *)getErrorCase {
  return errorCase_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, 0, -1, -1, -1, -1 },
    { NULL, "LLibComAfterlogicPgpPgpErrorCase;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibComAfterlogicPgpPgpErrorCase:);
  methods[1].selector = @selector(getErrorCase);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "errorCase_", "LLibComAfterlogicPgpPgpErrorCase;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibComAfterlogicPgpPgpErrorCase;" };
  static const J2ObjcClassInfo _LibComAfterlogicPgpPgpError = { "PgpError", "lib.com.afterlogic.pgp", ptrTable, methods, fields, 7, 0x1, 2, 1, -1, -1, -1, -1, -1 };
  return &_LibComAfterlogicPgpPgpError;
}

@end

void LibComAfterlogicPgpPgpError_initWithLibComAfterlogicPgpPgpErrorCase_(LibComAfterlogicPgpPgpError *self, LibComAfterlogicPgpPgpErrorCase *errorCase) {
  JavaLangThrowable_init(self);
  self->errorCase_ = errorCase;
}

LibComAfterlogicPgpPgpError *new_LibComAfterlogicPgpPgpError_initWithLibComAfterlogicPgpPgpErrorCase_(LibComAfterlogicPgpPgpErrorCase *errorCase) {
  J2OBJC_NEW_IMPL(LibComAfterlogicPgpPgpError, initWithLibComAfterlogicPgpPgpErrorCase_, errorCase)
}

LibComAfterlogicPgpPgpError *create_LibComAfterlogicPgpPgpError_initWithLibComAfterlogicPgpPgpErrorCase_(LibComAfterlogicPgpPgpErrorCase *errorCase) {
  J2OBJC_CREATE_IMPL(LibComAfterlogicPgpPgpError, initWithLibComAfterlogicPgpPgpErrorCase_, errorCase)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibComAfterlogicPgpPgpError)
