//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/parsers/DHIESPublicKeyParser.java
//

#include "AsymmetricKeyParameter.h"
#include "DHIESPublicKeyParser.h"
#include "DHParameters.h"
#include "DHPublicKeyParameters.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "Streams.h"
#include "java/io/InputStream.h"
#include "java/math/BigInteger.h"

@interface LibOrgBouncycastleCryptoParsersDHIESPublicKeyParser () {
 @public
  LibOrgBouncycastleCryptoParamsDHParameters *dhParams_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoParsersDHIESPublicKeyParser, dhParams_, LibOrgBouncycastleCryptoParamsDHParameters *)

@implementation LibOrgBouncycastleCryptoParsersDHIESPublicKeyParser

- (instancetype)initWithLibOrgBouncycastleCryptoParamsDHParameters:(LibOrgBouncycastleCryptoParamsDHParameters *)dhParams {
  LibOrgBouncycastleCryptoParsersDHIESPublicKeyParser_initWithLibOrgBouncycastleCryptoParamsDHParameters_(self, dhParams);
  return self;
}

- (LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)readKeyWithJavaIoInputStream:(JavaIoInputStream *)stream {
  IOSByteArray *V = [IOSByteArray newArrayWithLength:([((JavaMathBigInteger *) nil_chk([((LibOrgBouncycastleCryptoParamsDHParameters *) nil_chk(dhParams_)) getP])) bitLength] + 7) / 8];
  LibOrgBouncycastleUtilIoStreams_readFullyWithJavaIoInputStream_withByteArray_withInt_withInt_(stream, V, 0, V->size_);
  return new_LibOrgBouncycastleCryptoParamsDHPublicKeyParameters_initWithJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsDHParameters_(new_JavaMathBigInteger_initWithInt_withByteArray_(1, V), dhParams_);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter;", 0x1, 1, 2, 3, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleCryptoParamsDHParameters:);
  methods[1].selector = @selector(readKeyWithJavaIoInputStream:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "dhParams_", "LLibOrgBouncycastleCryptoParamsDHParameters;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleCryptoParamsDHParameters;", "readKey", "LJavaIoInputStream;", "LJavaIoIOException;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoParsersDHIESPublicKeyParser = { "DHIESPublicKeyParser", "lib.org.bouncycastle.crypto.parsers", ptrTable, methods, fields, 7, 0x1, 2, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoParsersDHIESPublicKeyParser;
}

@end

void LibOrgBouncycastleCryptoParsersDHIESPublicKeyParser_initWithLibOrgBouncycastleCryptoParamsDHParameters_(LibOrgBouncycastleCryptoParsersDHIESPublicKeyParser *self, LibOrgBouncycastleCryptoParamsDHParameters *dhParams) {
  NSObject_init(self);
  self->dhParams_ = dhParams;
}

LibOrgBouncycastleCryptoParsersDHIESPublicKeyParser *new_LibOrgBouncycastleCryptoParsersDHIESPublicKeyParser_initWithLibOrgBouncycastleCryptoParamsDHParameters_(LibOrgBouncycastleCryptoParamsDHParameters *dhParams) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoParsersDHIESPublicKeyParser, initWithLibOrgBouncycastleCryptoParamsDHParameters_, dhParams)
}

LibOrgBouncycastleCryptoParsersDHIESPublicKeyParser *create_LibOrgBouncycastleCryptoParsersDHIESPublicKeyParser_initWithLibOrgBouncycastleCryptoParamsDHParameters_(LibOrgBouncycastleCryptoParamsDHParameters *dhParams) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoParsersDHIESPublicKeyParser, initWithLibOrgBouncycastleCryptoParamsDHParameters_, dhParams)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoParsersDHIESPublicKeyParser)