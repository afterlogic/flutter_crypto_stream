//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/ConstructedOctetStream.java
//

#include "ASN1Encodable.h"
#include "ASN1OctetStringParser.h"
#include "ASN1StreamParser.h"
#include "ConstructedOctetStream.h"
#include "IOSClass.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/io/InputStream.h"

@interface LibOrgBouncycastleAsn1ConstructedOctetStream () {
 @public
  LibOrgBouncycastleAsn1ASN1StreamParser *_parser_;
  jboolean _first_;
  JavaIoInputStream *_currentStream_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1ConstructedOctetStream, _parser_, LibOrgBouncycastleAsn1ASN1StreamParser *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1ConstructedOctetStream, _currentStream_, JavaIoInputStream *)

@implementation LibOrgBouncycastleAsn1ConstructedOctetStream

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1StreamParser:(LibOrgBouncycastleAsn1ASN1StreamParser *)parser {
  LibOrgBouncycastleAsn1ConstructedOctetStream_initWithLibOrgBouncycastleAsn1ASN1StreamParser_(self, parser);
  return self;
}

- (jint)readWithByteArray:(IOSByteArray *)b
                  withInt:(jint)off
                  withInt:(jint)len {
  if (_currentStream_ == nil) {
    if (!_first_) {
      return -1;
    }
    id<LibOrgBouncycastleAsn1ASN1OctetStringParser> s = (id<LibOrgBouncycastleAsn1ASN1OctetStringParser>) cast_check([((LibOrgBouncycastleAsn1ASN1StreamParser *) nil_chk(_parser_)) readObject], LibOrgBouncycastleAsn1ASN1OctetStringParser_class_());
    if (s == nil) {
      return -1;
    }
    _first_ = false;
    _currentStream_ = [s getOctetStream];
  }
  jint totalRead = 0;
  for (; ; ) {
    jint numRead = [((JavaIoInputStream *) nil_chk(_currentStream_)) readWithByteArray:b withInt:off + totalRead withInt:len - totalRead];
    if (numRead >= 0) {
      totalRead += numRead;
      if (totalRead == len) {
        return totalRead;
      }
    }
    else {
      id<LibOrgBouncycastleAsn1ASN1OctetStringParser> aos = (id<LibOrgBouncycastleAsn1ASN1OctetStringParser>) cast_check([((LibOrgBouncycastleAsn1ASN1StreamParser *) nil_chk(_parser_)) readObject], LibOrgBouncycastleAsn1ASN1OctetStringParser_class_());
      if (aos == nil) {
        _currentStream_ = nil;
        return totalRead < 1 ? -1 : totalRead;
      }
      _currentStream_ = [aos getOctetStream];
    }
  }
}

- (jint)read {
  if (_currentStream_ == nil) {
    if (!_first_) {
      return -1;
    }
    id<LibOrgBouncycastleAsn1ASN1OctetStringParser> s = (id<LibOrgBouncycastleAsn1ASN1OctetStringParser>) cast_check([((LibOrgBouncycastleAsn1ASN1StreamParser *) nil_chk(_parser_)) readObject], LibOrgBouncycastleAsn1ASN1OctetStringParser_class_());
    if (s == nil) {
      return -1;
    }
    _first_ = false;
    _currentStream_ = [s getOctetStream];
  }
  for (; ; ) {
    jint b = [((JavaIoInputStream *) nil_chk(_currentStream_)) read];
    if (b >= 0) {
      return b;
    }
    id<LibOrgBouncycastleAsn1ASN1OctetStringParser> s = (id<LibOrgBouncycastleAsn1ASN1OctetStringParser>) cast_check([((LibOrgBouncycastleAsn1ASN1StreamParser *) nil_chk(_parser_)) readObject], LibOrgBouncycastleAsn1ASN1OctetStringParser_class_());
    if (s == nil) {
      _currentStream_ = nil;
      return -1;
    }
    _currentStream_ = [s getOctetStream];
  }
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, 0, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 1, 2, 3, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, 3, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1StreamParser:);
  methods[1].selector = @selector(readWithByteArray:withInt:withInt:);
  methods[2].selector = @selector(read);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "_parser_", "LLibOrgBouncycastleAsn1ASN1StreamParser;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "_first_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "_currentStream_", "LJavaIoInputStream;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1ASN1StreamParser;", "read", "[BII", "LJavaIoIOException;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1ConstructedOctetStream = { "ConstructedOctetStream", "lib.org.bouncycastle.asn1", ptrTable, methods, fields, 7, 0x0, 3, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1ConstructedOctetStream;
}

@end

void LibOrgBouncycastleAsn1ConstructedOctetStream_initWithLibOrgBouncycastleAsn1ASN1StreamParser_(LibOrgBouncycastleAsn1ConstructedOctetStream *self, LibOrgBouncycastleAsn1ASN1StreamParser *parser) {
  JavaIoInputStream_init(self);
  self->_first_ = true;
  self->_parser_ = parser;
}

LibOrgBouncycastleAsn1ConstructedOctetStream *new_LibOrgBouncycastleAsn1ConstructedOctetStream_initWithLibOrgBouncycastleAsn1ASN1StreamParser_(LibOrgBouncycastleAsn1ASN1StreamParser *parser) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1ConstructedOctetStream, initWithLibOrgBouncycastleAsn1ASN1StreamParser_, parser)
}

LibOrgBouncycastleAsn1ConstructedOctetStream *create_LibOrgBouncycastleAsn1ConstructedOctetStream_initWithLibOrgBouncycastleAsn1ASN1StreamParser_(LibOrgBouncycastleAsn1ASN1StreamParser *parser) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1ConstructedOctetStream, initWithLibOrgBouncycastleAsn1ASN1StreamParser_, parser)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1ConstructedOctetStream)