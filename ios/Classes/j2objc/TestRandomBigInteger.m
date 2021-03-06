//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/util/test/TestRandomBigInteger.java
//

#include "BigIntegers.h"
#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "TestRandomBigInteger.h"
#include "UtilTestFixedSecureRandom.h"
#include "java/math/BigInteger.h"

@implementation LibOrgBouncycastleUtilTestTestRandomBigInteger

- (instancetype)initWithNSString:(NSString *)encoding {
  LibOrgBouncycastleUtilTestTestRandomBigInteger_initWithNSString_(self, encoding);
  return self;
}

- (instancetype)initWithNSString:(NSString *)encoding
                         withInt:(jint)radix {
  LibOrgBouncycastleUtilTestTestRandomBigInteger_initWithNSString_withInt_(self, encoding, radix);
  return self;
}

- (instancetype)initWithByteArray:(IOSByteArray *)encoding {
  LibOrgBouncycastleUtilTestTestRandomBigInteger_initWithByteArray_(self, encoding);
  return self;
}

- (instancetype)initWithInt:(jint)bitLength
              withByteArray:(IOSByteArray *)encoding {
  LibOrgBouncycastleUtilTestTestRandomBigInteger_initWithInt_withByteArray_(self, bitLength, encoding);
  return self;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithNSString:);
  methods[1].selector = @selector(initWithNSString:withInt:);
  methods[2].selector = @selector(initWithByteArray:);
  methods[3].selector = @selector(initWithInt:withByteArray:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "LNSString;", "LNSString;I", "[B", "I[B" };
  static const J2ObjcClassInfo _LibOrgBouncycastleUtilTestTestRandomBigInteger = { "TestRandomBigInteger", "lib.org.bouncycastle.util.test", ptrTable, methods, NULL, 7, 0x1, 4, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleUtilTestTestRandomBigInteger;
}

@end

void LibOrgBouncycastleUtilTestTestRandomBigInteger_initWithNSString_(LibOrgBouncycastleUtilTestTestRandomBigInteger *self, NSString *encoding) {
  LibOrgBouncycastleUtilTestTestRandomBigInteger_initWithNSString_withInt_(self, encoding, 10);
}

LibOrgBouncycastleUtilTestTestRandomBigInteger *new_LibOrgBouncycastleUtilTestTestRandomBigInteger_initWithNSString_(NSString *encoding) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleUtilTestTestRandomBigInteger, initWithNSString_, encoding)
}

LibOrgBouncycastleUtilTestTestRandomBigInteger *create_LibOrgBouncycastleUtilTestTestRandomBigInteger_initWithNSString_(NSString *encoding) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleUtilTestTestRandomBigInteger, initWithNSString_, encoding)
}

void LibOrgBouncycastleUtilTestTestRandomBigInteger_initWithNSString_withInt_(LibOrgBouncycastleUtilTestTestRandomBigInteger *self, NSString *encoding, jint radix) {
  LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_initWithLibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_SourceArray_(self, [IOSObjectArray newArrayWithObjects:(id[]){ create_LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_BigInteger_initWithByteArray_(LibOrgBouncycastleUtilBigIntegers_asUnsignedByteArrayWithJavaMathBigInteger_(create_JavaMathBigInteger_initWithNSString_withInt_(encoding, radix))) } count:1 type:LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_Source_class_()]);
}

LibOrgBouncycastleUtilTestTestRandomBigInteger *new_LibOrgBouncycastleUtilTestTestRandomBigInteger_initWithNSString_withInt_(NSString *encoding, jint radix) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleUtilTestTestRandomBigInteger, initWithNSString_withInt_, encoding, radix)
}

LibOrgBouncycastleUtilTestTestRandomBigInteger *create_LibOrgBouncycastleUtilTestTestRandomBigInteger_initWithNSString_withInt_(NSString *encoding, jint radix) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleUtilTestTestRandomBigInteger, initWithNSString_withInt_, encoding, radix)
}

void LibOrgBouncycastleUtilTestTestRandomBigInteger_initWithByteArray_(LibOrgBouncycastleUtilTestTestRandomBigInteger *self, IOSByteArray *encoding) {
  LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_initWithLibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_SourceArray_(self, [IOSObjectArray newArrayWithObjects:(id[]){ create_LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_BigInteger_initWithByteArray_(encoding) } count:1 type:LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_Source_class_()]);
}

LibOrgBouncycastleUtilTestTestRandomBigInteger *new_LibOrgBouncycastleUtilTestTestRandomBigInteger_initWithByteArray_(IOSByteArray *encoding) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleUtilTestTestRandomBigInteger, initWithByteArray_, encoding)
}

LibOrgBouncycastleUtilTestTestRandomBigInteger *create_LibOrgBouncycastleUtilTestTestRandomBigInteger_initWithByteArray_(IOSByteArray *encoding) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleUtilTestTestRandomBigInteger, initWithByteArray_, encoding)
}

void LibOrgBouncycastleUtilTestTestRandomBigInteger_initWithInt_withByteArray_(LibOrgBouncycastleUtilTestTestRandomBigInteger *self, jint bitLength, IOSByteArray *encoding) {
  LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_initWithLibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_SourceArray_(self, [IOSObjectArray newArrayWithObjects:(id[]){ create_LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_BigInteger_initWithInt_withByteArray_(bitLength, encoding) } count:1 type:LibOrgBouncycastleUtilTestUtilTestFixedSecureRandom_Source_class_()]);
}

LibOrgBouncycastleUtilTestTestRandomBigInteger *new_LibOrgBouncycastleUtilTestTestRandomBigInteger_initWithInt_withByteArray_(jint bitLength, IOSByteArray *encoding) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleUtilTestTestRandomBigInteger, initWithInt_withByteArray_, bitLength, encoding)
}

LibOrgBouncycastleUtilTestTestRandomBigInteger *create_LibOrgBouncycastleUtilTestTestRandomBigInteger_initWithInt_withByteArray_(jint bitLength, IOSByteArray *encoding) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleUtilTestTestRandomBigInteger, initWithInt_withByteArray_, bitLength, encoding)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleUtilTestTestRandomBigInteger)
