//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/PBKDF2Key.java
//

#include "Arrays.h"
#include "CharToByteConverter.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "PBKDF2Key.h"
#include "javax/security/auth/Destroyable.h"

@interface LibOrgBouncycastleJcajcePBKDF2Key () {
 @public
  IOSCharArray *password_;
  id<LibOrgBouncycastleCryptoCharToByteConverter> converter_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajcePBKDF2Key, password_, IOSCharArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajcePBKDF2Key, converter_, id<LibOrgBouncycastleCryptoCharToByteConverter>)

@implementation LibOrgBouncycastleJcajcePBKDF2Key

- (instancetype)initWithCharArray:(IOSCharArray *)password
withLibOrgBouncycastleCryptoCharToByteConverter:(id<LibOrgBouncycastleCryptoCharToByteConverter>)converter {
  LibOrgBouncycastleJcajcePBKDF2Key_initWithCharArray_withLibOrgBouncycastleCryptoCharToByteConverter_(self, password, converter);
  return self;
}

- (IOSCharArray *)getPassword {
  return password_;
}

- (NSString *)getAlgorithm {
  return @"PBKDF2";
}

- (NSString *)getFormat {
  return [((id<LibOrgBouncycastleCryptoCharToByteConverter>) nil_chk(converter_)) getType];
}

- (IOSByteArray *)getEncoded {
  return [((id<LibOrgBouncycastleCryptoCharToByteConverter>) nil_chk(converter_)) convertWithCharArray:password_];
}

- (void)destroy {
  JavaxSecurityAuthDestroyable_destroy(self);
}

- (jboolean)isDestroyed {
  return JavaxSecurityAuthDestroyable_isDestroyed(self);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "[C", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithCharArray:withLibOrgBouncycastleCryptoCharToByteConverter:);
  methods[1].selector = @selector(getPassword);
  methods[2].selector = @selector(getAlgorithm);
  methods[3].selector = @selector(getFormat);
  methods[4].selector = @selector(getEncoded);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "password_", "[C", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "converter_", "LLibOrgBouncycastleCryptoCharToByteConverter;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "[CLLibOrgBouncycastleCryptoCharToByteConverter;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajcePBKDF2Key = { "PBKDF2Key", "lib.org.bouncycastle.jcajce", ptrTable, methods, fields, 7, 0x1, 5, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajcePBKDF2Key;
}

@end

void LibOrgBouncycastleJcajcePBKDF2Key_initWithCharArray_withLibOrgBouncycastleCryptoCharToByteConverter_(LibOrgBouncycastleJcajcePBKDF2Key *self, IOSCharArray *password, id<LibOrgBouncycastleCryptoCharToByteConverter> converter) {
  NSObject_init(self);
  self->password_ = LibOrgBouncycastleUtilArrays_cloneWithCharArray_(password);
  self->converter_ = converter;
}

LibOrgBouncycastleJcajcePBKDF2Key *new_LibOrgBouncycastleJcajcePBKDF2Key_initWithCharArray_withLibOrgBouncycastleCryptoCharToByteConverter_(IOSCharArray *password, id<LibOrgBouncycastleCryptoCharToByteConverter> converter) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajcePBKDF2Key, initWithCharArray_withLibOrgBouncycastleCryptoCharToByteConverter_, password, converter)
}

LibOrgBouncycastleJcajcePBKDF2Key *create_LibOrgBouncycastleJcajcePBKDF2Key_initWithCharArray_withLibOrgBouncycastleCryptoCharToByteConverter_(IOSCharArray *password, id<LibOrgBouncycastleCryptoCharToByteConverter> converter) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajcePBKDF2Key, initWithCharArray_withLibOrgBouncycastleCryptoCharToByteConverter_, password, converter)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajcePBKDF2Key)
