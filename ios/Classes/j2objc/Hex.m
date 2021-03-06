//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/util/encoders/Hex.java
//

#include "DecoderException.h"
#include "Encoder.h"
#include "EncoderException.h"
#include "Hex.h"
#include "HexEncoder.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "Strings.h"
#include "java/io/ByteArrayOutputStream.h"
#include "java/io/OutputStream.h"
#include "java/lang/Exception.h"

inline id<LibOrgBouncycastleUtilEncodersEncoder> LibOrgBouncycastleUtilEncodersHex_get_encoder(void);
static id<LibOrgBouncycastleUtilEncodersEncoder> LibOrgBouncycastleUtilEncodersHex_encoder;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleUtilEncodersHex, encoder, id<LibOrgBouncycastleUtilEncodersEncoder>)

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleUtilEncodersHex)

@implementation LibOrgBouncycastleUtilEncodersHex

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleUtilEncodersHex_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (NSString *)toHexStringWithByteArray:(IOSByteArray *)data {
  return LibOrgBouncycastleUtilEncodersHex_toHexStringWithByteArray_(data);
}

+ (NSString *)toHexStringWithByteArray:(IOSByteArray *)data
                               withInt:(jint)off
                               withInt:(jint)length {
  return LibOrgBouncycastleUtilEncodersHex_toHexStringWithByteArray_withInt_withInt_(data, off, length);
}

+ (IOSByteArray *)encodeWithByteArray:(IOSByteArray *)data {
  return LibOrgBouncycastleUtilEncodersHex_encodeWithByteArray_(data);
}

+ (IOSByteArray *)encodeWithByteArray:(IOSByteArray *)data
                              withInt:(jint)off
                              withInt:(jint)length {
  return LibOrgBouncycastleUtilEncodersHex_encodeWithByteArray_withInt_withInt_(data, off, length);
}

+ (jint)encodeWithByteArray:(IOSByteArray *)data
     withJavaIoOutputStream:(JavaIoOutputStream *)outArg {
  return LibOrgBouncycastleUtilEncodersHex_encodeWithByteArray_withJavaIoOutputStream_(data, outArg);
}

+ (jint)encodeWithByteArray:(IOSByteArray *)data
                    withInt:(jint)off
                    withInt:(jint)length
     withJavaIoOutputStream:(JavaIoOutputStream *)outArg {
  return LibOrgBouncycastleUtilEncodersHex_encodeWithByteArray_withInt_withInt_withJavaIoOutputStream_(data, off, length, outArg);
}

+ (IOSByteArray *)decodeWithByteArray:(IOSByteArray *)data {
  return LibOrgBouncycastleUtilEncodersHex_decodeWithByteArray_(data);
}

+ (IOSByteArray *)decodeWithNSString:(NSString *)data {
  return LibOrgBouncycastleUtilEncodersHex_decodeWithNSString_(data);
}

+ (jint)decodeWithNSString:(NSString *)data
    withJavaIoOutputStream:(JavaIoOutputStream *)outArg {
  return LibOrgBouncycastleUtilEncodersHex_decodeWithNSString_withJavaIoOutputStream_(data, outArg);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x9, 0, 2, -1, -1, -1, -1 },
    { NULL, "[B", 0x9, 3, 1, -1, -1, -1, -1 },
    { NULL, "[B", 0x9, 3, 2, -1, -1, -1, -1 },
    { NULL, "I", 0x9, 3, 4, 5, -1, -1, -1 },
    { NULL, "I", 0x9, 3, 6, 5, -1, -1, -1 },
    { NULL, "[B", 0x9, 7, 1, -1, -1, -1, -1 },
    { NULL, "[B", 0x9, 7, 8, -1, -1, -1, -1 },
    { NULL, "I", 0x9, 7, 9, 5, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(toHexStringWithByteArray:);
  methods[2].selector = @selector(toHexStringWithByteArray:withInt:withInt:);
  methods[3].selector = @selector(encodeWithByteArray:);
  methods[4].selector = @selector(encodeWithByteArray:withInt:withInt:);
  methods[5].selector = @selector(encodeWithByteArray:withJavaIoOutputStream:);
  methods[6].selector = @selector(encodeWithByteArray:withInt:withInt:withJavaIoOutputStream:);
  methods[7].selector = @selector(decodeWithByteArray:);
  methods[8].selector = @selector(decodeWithNSString:);
  methods[9].selector = @selector(decodeWithNSString:withJavaIoOutputStream:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "encoder", "LLibOrgBouncycastleUtilEncodersEncoder;", .constantValue.asLong = 0, 0x1a, -1, 10, -1, -1 },
  };
  static const void *ptrTable[] = { "toHexString", "[B", "[BII", "encode", "[BLJavaIoOutputStream;", "LJavaIoIOException;", "[BIILJavaIoOutputStream;", "decode", "LNSString;", "LNSString;LJavaIoOutputStream;", &LibOrgBouncycastleUtilEncodersHex_encoder };
  static const J2ObjcClassInfo _LibOrgBouncycastleUtilEncodersHex = { "Hex", "lib.org.bouncycastle.util.encoders", ptrTable, methods, fields, 7, 0x1, 10, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleUtilEncodersHex;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleUtilEncodersHex class]) {
    LibOrgBouncycastleUtilEncodersHex_encoder = new_LibOrgBouncycastleUtilEncodersHexEncoder_init();
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleUtilEncodersHex)
  }
}

@end

void LibOrgBouncycastleUtilEncodersHex_init(LibOrgBouncycastleUtilEncodersHex *self) {
  NSObject_init(self);
}

LibOrgBouncycastleUtilEncodersHex *new_LibOrgBouncycastleUtilEncodersHex_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleUtilEncodersHex, init)
}

LibOrgBouncycastleUtilEncodersHex *create_LibOrgBouncycastleUtilEncodersHex_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleUtilEncodersHex, init)
}

NSString *LibOrgBouncycastleUtilEncodersHex_toHexStringWithByteArray_(IOSByteArray *data) {
  LibOrgBouncycastleUtilEncodersHex_initialize();
  return LibOrgBouncycastleUtilEncodersHex_toHexStringWithByteArray_withInt_withInt_(data, 0, ((IOSByteArray *) nil_chk(data))->size_);
}

NSString *LibOrgBouncycastleUtilEncodersHex_toHexStringWithByteArray_withInt_withInt_(IOSByteArray *data, jint off, jint length) {
  LibOrgBouncycastleUtilEncodersHex_initialize();
  IOSByteArray *encoded = LibOrgBouncycastleUtilEncodersHex_encodeWithByteArray_withInt_withInt_(data, off, length);
  return LibOrgBouncycastleUtilStrings_fromByteArrayWithByteArray_(encoded);
}

IOSByteArray *LibOrgBouncycastleUtilEncodersHex_encodeWithByteArray_(IOSByteArray *data) {
  LibOrgBouncycastleUtilEncodersHex_initialize();
  return LibOrgBouncycastleUtilEncodersHex_encodeWithByteArray_withInt_withInt_(data, 0, ((IOSByteArray *) nil_chk(data))->size_);
}

IOSByteArray *LibOrgBouncycastleUtilEncodersHex_encodeWithByteArray_withInt_withInt_(IOSByteArray *data, jint off, jint length) {
  LibOrgBouncycastleUtilEncodersHex_initialize();
  JavaIoByteArrayOutputStream *bOut = new_JavaIoByteArrayOutputStream_init();
  @try {
    [((id<LibOrgBouncycastleUtilEncodersEncoder>) nil_chk(LibOrgBouncycastleUtilEncodersHex_encoder)) encodeWithByteArray:data withInt:off withInt:length withJavaIoOutputStream:bOut];
  }
  @catch (JavaLangException *e) {
    @throw new_LibOrgBouncycastleUtilEncodersEncoderException_initWithNSString_withJavaLangThrowable_(JreStrcat("$$", @"exception encoding Hex string: ", [e getMessage]), e);
  }
  return [bOut toByteArray];
}

jint LibOrgBouncycastleUtilEncodersHex_encodeWithByteArray_withJavaIoOutputStream_(IOSByteArray *data, JavaIoOutputStream *outArg) {
  LibOrgBouncycastleUtilEncodersHex_initialize();
  return [((id<LibOrgBouncycastleUtilEncodersEncoder>) nil_chk(LibOrgBouncycastleUtilEncodersHex_encoder)) encodeWithByteArray:data withInt:0 withInt:((IOSByteArray *) nil_chk(data))->size_ withJavaIoOutputStream:outArg];
}

jint LibOrgBouncycastleUtilEncodersHex_encodeWithByteArray_withInt_withInt_withJavaIoOutputStream_(IOSByteArray *data, jint off, jint length, JavaIoOutputStream *outArg) {
  LibOrgBouncycastleUtilEncodersHex_initialize();
  return [((id<LibOrgBouncycastleUtilEncodersEncoder>) nil_chk(LibOrgBouncycastleUtilEncodersHex_encoder)) encodeWithByteArray:data withInt:off withInt:length withJavaIoOutputStream:outArg];
}

IOSByteArray *LibOrgBouncycastleUtilEncodersHex_decodeWithByteArray_(IOSByteArray *data) {
  LibOrgBouncycastleUtilEncodersHex_initialize();
  JavaIoByteArrayOutputStream *bOut = new_JavaIoByteArrayOutputStream_init();
  @try {
    [((id<LibOrgBouncycastleUtilEncodersEncoder>) nil_chk(LibOrgBouncycastleUtilEncodersHex_encoder)) decodeWithByteArray:data withInt:0 withInt:((IOSByteArray *) nil_chk(data))->size_ withJavaIoOutputStream:bOut];
  }
  @catch (JavaLangException *e) {
    @throw new_LibOrgBouncycastleUtilEncodersDecoderException_initWithNSString_withJavaLangThrowable_(JreStrcat("$$", @"exception decoding Hex data: ", [e getMessage]), e);
  }
  return [bOut toByteArray];
}

IOSByteArray *LibOrgBouncycastleUtilEncodersHex_decodeWithNSString_(NSString *data) {
  LibOrgBouncycastleUtilEncodersHex_initialize();
  JavaIoByteArrayOutputStream *bOut = new_JavaIoByteArrayOutputStream_init();
  @try {
    [((id<LibOrgBouncycastleUtilEncodersEncoder>) nil_chk(LibOrgBouncycastleUtilEncodersHex_encoder)) decodeWithNSString:data withJavaIoOutputStream:bOut];
  }
  @catch (JavaLangException *e) {
    @throw new_LibOrgBouncycastleUtilEncodersDecoderException_initWithNSString_withJavaLangThrowable_(JreStrcat("$$", @"exception decoding Hex string: ", [e getMessage]), e);
  }
  return [bOut toByteArray];
}

jint LibOrgBouncycastleUtilEncodersHex_decodeWithNSString_withJavaIoOutputStream_(NSString *data, JavaIoOutputStream *outArg) {
  LibOrgBouncycastleUtilEncodersHex_initialize();
  return [((id<LibOrgBouncycastleUtilEncodersEncoder>) nil_chk(LibOrgBouncycastleUtilEncodersHex_encoder)) decodeWithNSString:data withJavaIoOutputStream:outArg];
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleUtilEncodersHex)
