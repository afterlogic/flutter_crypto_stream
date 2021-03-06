//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/DefiniteLengthInputStream.java
//

#include "DefiniteLengthInputStream.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "LimitedInputStream.h"
#include "Streams.h"
#include "java/io/EOFException.h"
#include "java/io/InputStream.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/Math.h"

@interface LibOrgBouncycastleAsn1DefiniteLengthInputStream () {
 @public
  jint _originalLength_;
  jint _remaining_;
}

@end

inline IOSByteArray *LibOrgBouncycastleAsn1DefiniteLengthInputStream_get_EMPTY_BYTES(void);
static IOSByteArray *LibOrgBouncycastleAsn1DefiniteLengthInputStream_EMPTY_BYTES;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1DefiniteLengthInputStream, EMPTY_BYTES, IOSByteArray *)

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleAsn1DefiniteLengthInputStream)

@implementation LibOrgBouncycastleAsn1DefiniteLengthInputStream

- (instancetype)initWithJavaIoInputStream:(JavaIoInputStream *)inArg
                                  withInt:(jint)length {
  LibOrgBouncycastleAsn1DefiniteLengthInputStream_initWithJavaIoInputStream_withInt_(self, inArg, length);
  return self;
}

- (jint)getRemaining {
  return _remaining_;
}

- (jint)read {
  if (_remaining_ == 0) {
    return -1;
  }
  jint b = [((JavaIoInputStream *) nil_chk(_in_)) read];
  if (b < 0) {
    @throw new_JavaIoEOFException_initWithNSString_(JreStrcat("$I$I", @"DEF length ", _originalLength_, @" object truncated by ", _remaining_));
  }
  if (--_remaining_ == 0) {
    [self setParentEofDetectWithBoolean:true];
  }
  return b;
}

- (jint)readWithByteArray:(IOSByteArray *)buf
                  withInt:(jint)off
                  withInt:(jint)len {
  if (_remaining_ == 0) {
    return -1;
  }
  jint toRead = JavaLangMath_minWithInt_withInt_(len, _remaining_);
  jint numRead = [((JavaIoInputStream *) nil_chk(_in_)) readWithByteArray:buf withInt:off withInt:toRead];
  if (numRead < 0) {
    @throw new_JavaIoEOFException_initWithNSString_(JreStrcat("$I$I", @"DEF length ", _originalLength_, @" object truncated by ", _remaining_));
  }
  if ((_remaining_ -= numRead) == 0) {
    [self setParentEofDetectWithBoolean:true];
  }
  return numRead;
}

- (IOSByteArray *)toByteArray {
  if (_remaining_ == 0) {
    return LibOrgBouncycastleAsn1DefiniteLengthInputStream_EMPTY_BYTES;
  }
  IOSByteArray *bytes = [IOSByteArray newArrayWithLength:_remaining_];
  if ((_remaining_ -= LibOrgBouncycastleUtilIoStreams_readFullyWithJavaIoInputStream_withByteArray_(_in_, bytes)) != 0) {
    @throw new_JavaIoEOFException_initWithNSString_(JreStrcat("$I$I", @"DEF length ", _originalLength_, @" object truncated by ", _remaining_));
  }
  [self setParentEofDetectWithBoolean:true];
  return bytes;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, 0, -1, -1, -1, -1 },
    { NULL, "I", 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, 1, -1, -1, -1 },
    { NULL, "I", 0x1, 2, 3, 1, -1, -1, -1 },
    { NULL, "[B", 0x0, -1, -1, 1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithJavaIoInputStream:withInt:);
  methods[1].selector = @selector(getRemaining);
  methods[2].selector = @selector(read);
  methods[3].selector = @selector(readWithByteArray:withInt:withInt:);
  methods[4].selector = @selector(toByteArray);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "EMPTY_BYTES", "[B", .constantValue.asLong = 0, 0x1a, -1, 4, -1, -1 },
    { "_originalLength_", "I", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "_remaining_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaIoInputStream;I", "LJavaIoIOException;", "read", "[BII", &LibOrgBouncycastleAsn1DefiniteLengthInputStream_EMPTY_BYTES };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1DefiniteLengthInputStream = { "DefiniteLengthInputStream", "lib.org.bouncycastle.asn1", ptrTable, methods, fields, 7, 0x0, 5, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1DefiniteLengthInputStream;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleAsn1DefiniteLengthInputStream class]) {
    LibOrgBouncycastleAsn1DefiniteLengthInputStream_EMPTY_BYTES = [IOSByteArray newArrayWithLength:0];
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleAsn1DefiniteLengthInputStream)
  }
}

@end

void LibOrgBouncycastleAsn1DefiniteLengthInputStream_initWithJavaIoInputStream_withInt_(LibOrgBouncycastleAsn1DefiniteLengthInputStream *self, JavaIoInputStream *inArg, jint length) {
  LibOrgBouncycastleAsn1LimitedInputStream_initWithJavaIoInputStream_withInt_(self, inArg, length);
  if (length < 0) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"negative lengths not allowed");
  }
  self->_originalLength_ = length;
  self->_remaining_ = length;
  if (length == 0) {
    [self setParentEofDetectWithBoolean:true];
  }
}

LibOrgBouncycastleAsn1DefiniteLengthInputStream *new_LibOrgBouncycastleAsn1DefiniteLengthInputStream_initWithJavaIoInputStream_withInt_(JavaIoInputStream *inArg, jint length) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1DefiniteLengthInputStream, initWithJavaIoInputStream_withInt_, inArg, length)
}

LibOrgBouncycastleAsn1DefiniteLengthInputStream *create_LibOrgBouncycastleAsn1DefiniteLengthInputStream_initWithJavaIoInputStream_withInt_(JavaIoInputStream *inArg, jint length) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1DefiniteLengthInputStream, initWithJavaIoInputStream_withInt_, inArg, length)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1DefiniteLengthInputStream)
