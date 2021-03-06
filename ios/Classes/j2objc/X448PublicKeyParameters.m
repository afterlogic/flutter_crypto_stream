//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/params/X448PublicKeyParameters.java
//

#include "Arrays.h"
#include "AsymmetricKeyParameter.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "Streams.h"
#include "X448PublicKeyParameters.h"
#include "java/io/EOFException.h"
#include "java/io/InputStream.h"
#include "java/lang/System.h"

@interface LibOrgBouncycastleCryptoParamsX448PublicKeyParameters () {
 @public
  IOSByteArray *data_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoParamsX448PublicKeyParameters, data_, IOSByteArray *)

@implementation LibOrgBouncycastleCryptoParamsX448PublicKeyParameters

+ (jint)KEY_SIZE {
  return LibOrgBouncycastleCryptoParamsX448PublicKeyParameters_KEY_SIZE;
}

- (instancetype)initWithByteArray:(IOSByteArray *)buf
                          withInt:(jint)off {
  LibOrgBouncycastleCryptoParamsX448PublicKeyParameters_initWithByteArray_withInt_(self, buf, off);
  return self;
}

- (instancetype)initWithJavaIoInputStream:(JavaIoInputStream *)input {
  LibOrgBouncycastleCryptoParamsX448PublicKeyParameters_initWithJavaIoInputStream_(self, input);
  return self;
}

- (void)encodeWithByteArray:(IOSByteArray *)buf
                    withInt:(jint)off {
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(data_, 0, buf, off, LibOrgBouncycastleCryptoParamsX448PublicKeyParameters_KEY_SIZE);
}

- (IOSByteArray *)getEncoded {
  return LibOrgBouncycastleUtilArrays_cloneWithByteArray_(data_);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, 2, -1, -1, -1 },
    { NULL, "V", 0x1, 3, 0, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithByteArray:withInt:);
  methods[1].selector = @selector(initWithJavaIoInputStream:);
  methods[2].selector = @selector(encodeWithByteArray:withInt:);
  methods[3].selector = @selector(getEncoded);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "KEY_SIZE", "I", .constantValue.asInt = LibOrgBouncycastleCryptoParamsX448PublicKeyParameters_KEY_SIZE, 0x19, -1, -1, -1, -1 },
    { "data_", "[B", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "[BI", "LJavaIoInputStream;", "LJavaIoIOException;", "encode" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoParamsX448PublicKeyParameters = { "X448PublicKeyParameters", "lib.org.bouncycastle.crypto.params", ptrTable, methods, fields, 7, 0x11, 4, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoParamsX448PublicKeyParameters;
}

@end

void LibOrgBouncycastleCryptoParamsX448PublicKeyParameters_initWithByteArray_withInt_(LibOrgBouncycastleCryptoParamsX448PublicKeyParameters *self, IOSByteArray *buf, jint off) {
  LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_initWithBoolean_(self, false);
  self->data_ = [IOSByteArray newArrayWithLength:LibOrgBouncycastleCryptoParamsX448PublicKeyParameters_KEY_SIZE];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(buf, off, self->data_, 0, LibOrgBouncycastleCryptoParamsX448PublicKeyParameters_KEY_SIZE);
}

LibOrgBouncycastleCryptoParamsX448PublicKeyParameters *new_LibOrgBouncycastleCryptoParamsX448PublicKeyParameters_initWithByteArray_withInt_(IOSByteArray *buf, jint off) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoParamsX448PublicKeyParameters, initWithByteArray_withInt_, buf, off)
}

LibOrgBouncycastleCryptoParamsX448PublicKeyParameters *create_LibOrgBouncycastleCryptoParamsX448PublicKeyParameters_initWithByteArray_withInt_(IOSByteArray *buf, jint off) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoParamsX448PublicKeyParameters, initWithByteArray_withInt_, buf, off)
}

void LibOrgBouncycastleCryptoParamsX448PublicKeyParameters_initWithJavaIoInputStream_(LibOrgBouncycastleCryptoParamsX448PublicKeyParameters *self, JavaIoInputStream *input) {
  LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_initWithBoolean_(self, false);
  self->data_ = [IOSByteArray newArrayWithLength:LibOrgBouncycastleCryptoParamsX448PublicKeyParameters_KEY_SIZE];
  if (LibOrgBouncycastleCryptoParamsX448PublicKeyParameters_KEY_SIZE != LibOrgBouncycastleUtilIoStreams_readFullyWithJavaIoInputStream_withByteArray_(input, self->data_)) {
    @throw new_JavaIoEOFException_initWithNSString_(@"EOF encountered in middle of X448 public key");
  }
}

LibOrgBouncycastleCryptoParamsX448PublicKeyParameters *new_LibOrgBouncycastleCryptoParamsX448PublicKeyParameters_initWithJavaIoInputStream_(JavaIoInputStream *input) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoParamsX448PublicKeyParameters, initWithJavaIoInputStream_, input)
}

LibOrgBouncycastleCryptoParamsX448PublicKeyParameters *create_LibOrgBouncycastleCryptoParamsX448PublicKeyParameters_initWithJavaIoInputStream_(JavaIoInputStream *input) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoParamsX448PublicKeyParameters, initWithJavaIoInputStream_, input)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoParamsX448PublicKeyParameters)
