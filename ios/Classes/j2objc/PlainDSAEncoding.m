//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/signers/PlainDSAEncoding.java
//

#include "Arrays.h"
#include "BigIntegers.h"
#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "PlainDSAEncoding.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/Math.h"
#include "java/lang/System.h"
#include "java/math/BigInteger.h"

@interface LibOrgBouncycastleCryptoSignersPlainDSAEncoding ()

- (void)encodeValueWithJavaMathBigInteger:(JavaMathBigInteger *)n
                   withJavaMathBigInteger:(JavaMathBigInteger *)x
                            withByteArray:(IOSByteArray *)buf
                                  withInt:(jint)off
                                  withInt:(jint)len;

@end

__attribute__((unused)) static void LibOrgBouncycastleCryptoSignersPlainDSAEncoding_encodeValueWithJavaMathBigInteger_withJavaMathBigInteger_withByteArray_withInt_withInt_(LibOrgBouncycastleCryptoSignersPlainDSAEncoding *self, JavaMathBigInteger *n, JavaMathBigInteger *x, IOSByteArray *buf, jint off, jint len);

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleCryptoSignersPlainDSAEncoding)

LibOrgBouncycastleCryptoSignersPlainDSAEncoding *LibOrgBouncycastleCryptoSignersPlainDSAEncoding_INSTANCE;

@implementation LibOrgBouncycastleCryptoSignersPlainDSAEncoding

+ (LibOrgBouncycastleCryptoSignersPlainDSAEncoding *)INSTANCE {
  return LibOrgBouncycastleCryptoSignersPlainDSAEncoding_INSTANCE;
}

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoSignersPlainDSAEncoding_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (IOSByteArray *)encodeWithJavaMathBigInteger:(JavaMathBigInteger *)n
                        withJavaMathBigInteger:(JavaMathBigInteger *)r
                        withJavaMathBigInteger:(JavaMathBigInteger *)s {
  jint valueLength = LibOrgBouncycastleUtilBigIntegers_getUnsignedByteLengthWithJavaMathBigInteger_(n);
  IOSByteArray *result = [IOSByteArray newArrayWithLength:valueLength * 2];
  LibOrgBouncycastleCryptoSignersPlainDSAEncoding_encodeValueWithJavaMathBigInteger_withJavaMathBigInteger_withByteArray_withInt_withInt_(self, n, r, result, 0, valueLength);
  LibOrgBouncycastleCryptoSignersPlainDSAEncoding_encodeValueWithJavaMathBigInteger_withJavaMathBigInteger_withByteArray_withInt_withInt_(self, n, s, result, valueLength, valueLength);
  return result;
}

- (IOSObjectArray *)decodeWithJavaMathBigInteger:(JavaMathBigInteger *)n
                                   withByteArray:(IOSByteArray *)encoding {
  jint valueLength = LibOrgBouncycastleUtilBigIntegers_getUnsignedByteLengthWithJavaMathBigInteger_(n);
  if (((IOSByteArray *) nil_chk(encoding))->size_ != valueLength * 2) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Encoding has incorrect length");
  }
  return [IOSObjectArray newArrayWithObjects:(id[]){ [self decodeValueWithJavaMathBigInteger:n withByteArray:encoding withInt:0 withInt:valueLength], [self decodeValueWithJavaMathBigInteger:n withByteArray:encoding withInt:valueLength withInt:valueLength] } count:2 type:JavaMathBigInteger_class_()];
}

- (JavaMathBigInteger *)checkValueWithJavaMathBigInteger:(JavaMathBigInteger *)n
                                  withJavaMathBigInteger:(JavaMathBigInteger *)x {
  if ([((JavaMathBigInteger *) nil_chk(x)) signum] < 0 || [x compareToWithId:n] >= 0) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Value out of range");
  }
  return x;
}

- (JavaMathBigInteger *)decodeValueWithJavaMathBigInteger:(JavaMathBigInteger *)n
                                            withByteArray:(IOSByteArray *)buf
                                                  withInt:(jint)off
                                                  withInt:(jint)len {
  IOSByteArray *bs = LibOrgBouncycastleUtilArrays_copyOfRangeWithByteArray_withInt_withInt_(buf, off, off + len);
  return [self checkValueWithJavaMathBigInteger:n withJavaMathBigInteger:new_JavaMathBigInteger_initWithInt_withByteArray_(1, bs)];
}

- (void)encodeValueWithJavaMathBigInteger:(JavaMathBigInteger *)n
                   withJavaMathBigInteger:(JavaMathBigInteger *)x
                            withByteArray:(IOSByteArray *)buf
                                  withInt:(jint)off
                                  withInt:(jint)len {
  LibOrgBouncycastleCryptoSignersPlainDSAEncoding_encodeValueWithJavaMathBigInteger_withJavaMathBigInteger_withByteArray_withInt_withInt_(self, n, x, buf, off, len);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, 0, 1, -1, -1, -1, -1 },
    { NULL, "[LJavaMathBigInteger;", 0x1, 2, 3, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x4, 4, 5, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x4, 6, 7, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 8, 9, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(encodeWithJavaMathBigInteger:withJavaMathBigInteger:withJavaMathBigInteger:);
  methods[2].selector = @selector(decodeWithJavaMathBigInteger:withByteArray:);
  methods[3].selector = @selector(checkValueWithJavaMathBigInteger:withJavaMathBigInteger:);
  methods[4].selector = @selector(decodeValueWithJavaMathBigInteger:withByteArray:withInt:withInt:);
  methods[5].selector = @selector(encodeValueWithJavaMathBigInteger:withJavaMathBigInteger:withByteArray:withInt:withInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "INSTANCE", "LLibOrgBouncycastleCryptoSignersPlainDSAEncoding;", .constantValue.asLong = 0, 0x19, -1, 10, -1, -1 },
  };
  static const void *ptrTable[] = { "encode", "LJavaMathBigInteger;LJavaMathBigInteger;LJavaMathBigInteger;", "decode", "LJavaMathBigInteger;[B", "checkValue", "LJavaMathBigInteger;LJavaMathBigInteger;", "decodeValue", "LJavaMathBigInteger;[BII", "encodeValue", "LJavaMathBigInteger;LJavaMathBigInteger;[BII", &LibOrgBouncycastleCryptoSignersPlainDSAEncoding_INSTANCE };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoSignersPlainDSAEncoding = { "PlainDSAEncoding", "lib.org.bouncycastle.crypto.signers", ptrTable, methods, fields, 7, 0x1, 6, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoSignersPlainDSAEncoding;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleCryptoSignersPlainDSAEncoding class]) {
    LibOrgBouncycastleCryptoSignersPlainDSAEncoding_INSTANCE = new_LibOrgBouncycastleCryptoSignersPlainDSAEncoding_init();
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleCryptoSignersPlainDSAEncoding)
  }
}

@end

void LibOrgBouncycastleCryptoSignersPlainDSAEncoding_init(LibOrgBouncycastleCryptoSignersPlainDSAEncoding *self) {
  NSObject_init(self);
}

LibOrgBouncycastleCryptoSignersPlainDSAEncoding *new_LibOrgBouncycastleCryptoSignersPlainDSAEncoding_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoSignersPlainDSAEncoding, init)
}

LibOrgBouncycastleCryptoSignersPlainDSAEncoding *create_LibOrgBouncycastleCryptoSignersPlainDSAEncoding_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoSignersPlainDSAEncoding, init)
}

void LibOrgBouncycastleCryptoSignersPlainDSAEncoding_encodeValueWithJavaMathBigInteger_withJavaMathBigInteger_withByteArray_withInt_withInt_(LibOrgBouncycastleCryptoSignersPlainDSAEncoding *self, JavaMathBigInteger *n, JavaMathBigInteger *x, IOSByteArray *buf, jint off, jint len) {
  IOSByteArray *bs = [((JavaMathBigInteger *) nil_chk([self checkValueWithJavaMathBigInteger:n withJavaMathBigInteger:x])) toByteArray];
  jint bsOff = JavaLangMath_maxWithInt_withInt_(0, ((IOSByteArray *) nil_chk(bs))->size_ - len);
  jint bsLen = bs->size_ - bsOff;
  jint pos = len - bsLen;
  LibOrgBouncycastleUtilArrays_fillWithByteArray_withInt_withInt_withByte_(buf, off, off + pos, (jbyte) 0);
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(bs, bsOff, buf, off + pos, bsLen);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoSignersPlainDSAEncoding)
