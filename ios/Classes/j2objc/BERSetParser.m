//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/BERSetParser.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1ParsingException.h"
#include "ASN1Primitive.h"
#include "ASN1StreamParser.h"
#include "BERSet.h"
#include "BERSetParser.h"
#include "J2ObjC_source.h"
#include "java/io/IOException.h"

@interface LibOrgBouncycastleAsn1BERSetParser () {
 @public
  LibOrgBouncycastleAsn1ASN1StreamParser *_parser_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1BERSetParser, _parser_, LibOrgBouncycastleAsn1ASN1StreamParser *)

@implementation LibOrgBouncycastleAsn1BERSetParser

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1StreamParser:(LibOrgBouncycastleAsn1ASN1StreamParser *)parser {
  LibOrgBouncycastleAsn1BERSetParser_initWithLibOrgBouncycastleAsn1ASN1StreamParser_(self, parser);
  return self;
}

- (id<LibOrgBouncycastleAsn1ASN1Encodable>)readObject {
  return [((LibOrgBouncycastleAsn1ASN1StreamParser *) nil_chk(_parser_)) readObject];
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)getLoadedObject {
  return new_LibOrgBouncycastleAsn1BERSet_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_([((LibOrgBouncycastleAsn1ASN1StreamParser *) nil_chk(_parser_)) readVector]);
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  @try {
    return [self getLoadedObject];
  }
  @catch (JavaIoIOException *e) {
    @throw new_LibOrgBouncycastleAsn1ASN1ParsingException_initWithNSString_withJavaLangThrowable_([e getMessage], e);
  }
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, 0, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Encodable;", 0x1, -1, -1, 1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, 1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1StreamParser:);
  methods[1].selector = @selector(readObject);
  methods[2].selector = @selector(getLoadedObject);
  methods[3].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "_parser_", "LLibOrgBouncycastleAsn1ASN1StreamParser;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1ASN1StreamParser;", "LJavaIoIOException;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1BERSetParser = { "BERSetParser", "lib.org.bouncycastle.asn1", ptrTable, methods, fields, 7, 0x1, 4, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1BERSetParser;
}

@end

void LibOrgBouncycastleAsn1BERSetParser_initWithLibOrgBouncycastleAsn1ASN1StreamParser_(LibOrgBouncycastleAsn1BERSetParser *self, LibOrgBouncycastleAsn1ASN1StreamParser *parser) {
  NSObject_init(self);
  self->_parser_ = parser;
}

LibOrgBouncycastleAsn1BERSetParser *new_LibOrgBouncycastleAsn1BERSetParser_initWithLibOrgBouncycastleAsn1ASN1StreamParser_(LibOrgBouncycastleAsn1ASN1StreamParser *parser) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1BERSetParser, initWithLibOrgBouncycastleAsn1ASN1StreamParser_, parser)
}

LibOrgBouncycastleAsn1BERSetParser *create_LibOrgBouncycastleAsn1BERSetParser_initWithLibOrgBouncycastleAsn1ASN1StreamParser_(LibOrgBouncycastleAsn1ASN1StreamParser *parser) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1BERSetParser, initWithLibOrgBouncycastleAsn1ASN1StreamParser_, parser)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1BERSetParser)
