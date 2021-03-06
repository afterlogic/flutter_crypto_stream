//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/signers/StandardDSAEncoding.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1Encoding.h"
#include "ASN1Integer.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "Arrays.h"
#include "DERSequence.h"
#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "StandardDSAEncoding.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/math/BigInteger.h"

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleCryptoSignersStandardDSAEncoding)

LibOrgBouncycastleCryptoSignersStandardDSAEncoding *LibOrgBouncycastleCryptoSignersStandardDSAEncoding_INSTANCE;

@implementation LibOrgBouncycastleCryptoSignersStandardDSAEncoding

+ (LibOrgBouncycastleCryptoSignersStandardDSAEncoding *)INSTANCE {
  return LibOrgBouncycastleCryptoSignersStandardDSAEncoding_INSTANCE;
}

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoSignersStandardDSAEncoding_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (IOSByteArray *)encodeWithJavaMathBigInteger:(JavaMathBigInteger *)n
                        withJavaMathBigInteger:(JavaMathBigInteger *)r
                        withJavaMathBigInteger:(JavaMathBigInteger *)s {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [self encodeValueWithJavaMathBigInteger:n withLibOrgBouncycastleAsn1ASN1EncodableVector:v withJavaMathBigInteger:r];
  [self encodeValueWithJavaMathBigInteger:n withLibOrgBouncycastleAsn1ASN1EncodableVector:v withJavaMathBigInteger:s];
  return [new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v) getEncodedWithNSString:LibOrgBouncycastleAsn1ASN1Encoding_DER];
}

- (IOSObjectArray *)decodeWithJavaMathBigInteger:(JavaMathBigInteger *)n
                                   withByteArray:(IOSByteArray *)encoding {
  LibOrgBouncycastleAsn1ASN1Sequence *seq = (LibOrgBouncycastleAsn1ASN1Sequence *) cast_chk(LibOrgBouncycastleAsn1ASN1Primitive_fromByteArrayWithByteArray_(encoding), [LibOrgBouncycastleAsn1ASN1Sequence class]);
  if ([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) size] == 2) {
    JavaMathBigInteger *r = [self decodeValueWithJavaMathBigInteger:n withLibOrgBouncycastleAsn1ASN1Sequence:seq withInt:0];
    JavaMathBigInteger *s = [self decodeValueWithJavaMathBigInteger:n withLibOrgBouncycastleAsn1ASN1Sequence:seq withInt:1];
    IOSByteArray *expectedEncoding = [self encodeWithJavaMathBigInteger:n withJavaMathBigInteger:r withJavaMathBigInteger:s];
    if (LibOrgBouncycastleUtilArrays_areEqualWithByteArray_withByteArray_(expectedEncoding, encoding)) {
      return [IOSObjectArray newArrayWithObjects:(id[]){ r, s } count:2 type:JavaMathBigInteger_class_()];
    }
  }
  @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Malformed signature");
}

- (JavaMathBigInteger *)checkValueWithJavaMathBigInteger:(JavaMathBigInteger *)n
                                  withJavaMathBigInteger:(JavaMathBigInteger *)x {
  if ([((JavaMathBigInteger *) nil_chk(x)) signum] < 0 || (nil != n && [x compareToWithId:n] >= 0)) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Value out of range");
  }
  return x;
}

- (JavaMathBigInteger *)decodeValueWithJavaMathBigInteger:(JavaMathBigInteger *)n
                   withLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)s
                                                  withInt:(jint)pos {
  return [self checkValueWithJavaMathBigInteger:n withJavaMathBigInteger:[((LibOrgBouncycastleAsn1ASN1Integer *) nil_chk(((LibOrgBouncycastleAsn1ASN1Integer *) cast_chk([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(s)) getObjectAtWithInt:pos], [LibOrgBouncycastleAsn1ASN1Integer class])))) getValue]];
}

- (void)encodeValueWithJavaMathBigInteger:(JavaMathBigInteger *)n
withLibOrgBouncycastleAsn1ASN1EncodableVector:(LibOrgBouncycastleAsn1ASN1EncodableVector *)v
                   withJavaMathBigInteger:(JavaMathBigInteger *)x {
  [((LibOrgBouncycastleAsn1ASN1EncodableVector *) nil_chk(v)) addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1ASN1Integer_initWithJavaMathBigInteger_([self checkValueWithJavaMathBigInteger:n withJavaMathBigInteger:x])];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, 0, 1, 2, -1, -1, -1 },
    { NULL, "[LJavaMathBigInteger;", 0x1, 3, 4, 2, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x4, 5, 6, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x4, 7, 8, -1, -1, -1, -1 },
    { NULL, "V", 0x4, 9, 10, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(encodeWithJavaMathBigInteger:withJavaMathBigInteger:withJavaMathBigInteger:);
  methods[2].selector = @selector(decodeWithJavaMathBigInteger:withByteArray:);
  methods[3].selector = @selector(checkValueWithJavaMathBigInteger:withJavaMathBigInteger:);
  methods[4].selector = @selector(decodeValueWithJavaMathBigInteger:withLibOrgBouncycastleAsn1ASN1Sequence:withInt:);
  methods[5].selector = @selector(encodeValueWithJavaMathBigInteger:withLibOrgBouncycastleAsn1ASN1EncodableVector:withJavaMathBigInteger:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "INSTANCE", "LLibOrgBouncycastleCryptoSignersStandardDSAEncoding;", .constantValue.asLong = 0, 0x19, -1, 11, -1, -1 },
  };
  static const void *ptrTable[] = { "encode", "LJavaMathBigInteger;LJavaMathBigInteger;LJavaMathBigInteger;", "LJavaIoIOException;", "decode", "LJavaMathBigInteger;[B", "checkValue", "LJavaMathBigInteger;LJavaMathBigInteger;", "decodeValue", "LJavaMathBigInteger;LLibOrgBouncycastleAsn1ASN1Sequence;I", "encodeValue", "LJavaMathBigInteger;LLibOrgBouncycastleAsn1ASN1EncodableVector;LJavaMathBigInteger;", &LibOrgBouncycastleCryptoSignersStandardDSAEncoding_INSTANCE };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoSignersStandardDSAEncoding = { "StandardDSAEncoding", "lib.org.bouncycastle.crypto.signers", ptrTable, methods, fields, 7, 0x1, 6, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoSignersStandardDSAEncoding;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleCryptoSignersStandardDSAEncoding class]) {
    LibOrgBouncycastleCryptoSignersStandardDSAEncoding_INSTANCE = new_LibOrgBouncycastleCryptoSignersStandardDSAEncoding_init();
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleCryptoSignersStandardDSAEncoding)
  }
}

@end

void LibOrgBouncycastleCryptoSignersStandardDSAEncoding_init(LibOrgBouncycastleCryptoSignersStandardDSAEncoding *self) {
  NSObject_init(self);
}

LibOrgBouncycastleCryptoSignersStandardDSAEncoding *new_LibOrgBouncycastleCryptoSignersStandardDSAEncoding_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoSignersStandardDSAEncoding, init)
}

LibOrgBouncycastleCryptoSignersStandardDSAEncoding *create_LibOrgBouncycastleCryptoSignersStandardDSAEncoding_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoSignersStandardDSAEncoding, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoSignersStandardDSAEncoding)
