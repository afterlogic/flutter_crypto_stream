//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cms/EncryptedContentInfoParser.java
//

#include "ASN1Encodable.h"
#include "ASN1ObjectIdentifier.h"
#include "ASN1Primitive.h"
#include "ASN1SequenceParser.h"
#include "ASN1TaggedObjectParser.h"
#include "AlgorithmIdentifier.h"
#include "EncryptedContentInfoParser.h"
#include "IOSClass.h"
#include "J2ObjC_source.h"

@interface LibOrgBouncycastleAsn1CmsEncryptedContentInfoParser () {
 @public
  LibOrgBouncycastleAsn1ASN1ObjectIdentifier *_contentType_;
  LibOrgBouncycastleAsn1X509AlgorithmIdentifier *_contentEncryptionAlgorithm_;
  id<LibOrgBouncycastleAsn1ASN1TaggedObjectParser> _encryptedContent_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmsEncryptedContentInfoParser, _contentType_, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmsEncryptedContentInfoParser, _contentEncryptionAlgorithm_, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmsEncryptedContentInfoParser, _encryptedContent_, id<LibOrgBouncycastleAsn1ASN1TaggedObjectParser>)

@implementation LibOrgBouncycastleAsn1CmsEncryptedContentInfoParser

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1SequenceParser:(id<LibOrgBouncycastleAsn1ASN1SequenceParser>)seq {
  LibOrgBouncycastleAsn1CmsEncryptedContentInfoParser_initWithLibOrgBouncycastleAsn1ASN1SequenceParser_(self, seq);
  return self;
}

- (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)getContentType {
  return _contentType_;
}

- (LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)getContentEncryptionAlgorithm {
  return _contentEncryptionAlgorithm_;
}

- (id<LibOrgBouncycastleAsn1ASN1Encodable>)getEncryptedContentWithInt:(jint)tag {
  return [((id<LibOrgBouncycastleAsn1ASN1TaggedObjectParser>) nil_chk(_encryptedContent_)) getObjectParserWithInt:tag withBoolean:false];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, 1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509AlgorithmIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Encodable;", 0x1, 2, 3, 1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1SequenceParser:);
  methods[1].selector = @selector(getContentType);
  methods[2].selector = @selector(getContentEncryptionAlgorithm);
  methods[3].selector = @selector(getEncryptedContentWithInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "_contentType_", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "_contentEncryptionAlgorithm_", "LLibOrgBouncycastleAsn1X509AlgorithmIdentifier;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "_encryptedContent_", "LLibOrgBouncycastleAsn1ASN1TaggedObjectParser;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1ASN1SequenceParser;", "LJavaIoIOException;", "getEncryptedContent", "I" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1CmsEncryptedContentInfoParser = { "EncryptedContentInfoParser", "lib.org.bouncycastle.asn1.cms", ptrTable, methods, fields, 7, 0x1, 4, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1CmsEncryptedContentInfoParser;
}

@end

void LibOrgBouncycastleAsn1CmsEncryptedContentInfoParser_initWithLibOrgBouncycastleAsn1ASN1SequenceParser_(LibOrgBouncycastleAsn1CmsEncryptedContentInfoParser *self, id<LibOrgBouncycastleAsn1ASN1SequenceParser> seq) {
  NSObject_init(self);
  self->_contentType_ = (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) cast_chk([((id<LibOrgBouncycastleAsn1ASN1SequenceParser>) nil_chk(seq)) readObject], [LibOrgBouncycastleAsn1ASN1ObjectIdentifier class]);
  self->_contentEncryptionAlgorithm_ = LibOrgBouncycastleAsn1X509AlgorithmIdentifier_getInstanceWithId_([((id<LibOrgBouncycastleAsn1ASN1Encodable>) nil_chk([seq readObject])) toASN1Primitive]);
  self->_encryptedContent_ = (id<LibOrgBouncycastleAsn1ASN1TaggedObjectParser>) cast_check([seq readObject], LibOrgBouncycastleAsn1ASN1TaggedObjectParser_class_());
}

LibOrgBouncycastleAsn1CmsEncryptedContentInfoParser *new_LibOrgBouncycastleAsn1CmsEncryptedContentInfoParser_initWithLibOrgBouncycastleAsn1ASN1SequenceParser_(id<LibOrgBouncycastleAsn1ASN1SequenceParser> seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmsEncryptedContentInfoParser, initWithLibOrgBouncycastleAsn1ASN1SequenceParser_, seq)
}

LibOrgBouncycastleAsn1CmsEncryptedContentInfoParser *create_LibOrgBouncycastleAsn1CmsEncryptedContentInfoParser_initWithLibOrgBouncycastleAsn1ASN1SequenceParser_(id<LibOrgBouncycastleAsn1ASN1SequenceParser> seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmsEncryptedContentInfoParser, initWithLibOrgBouncycastleAsn1ASN1SequenceParser_, seq)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1CmsEncryptedContentInfoParser)
