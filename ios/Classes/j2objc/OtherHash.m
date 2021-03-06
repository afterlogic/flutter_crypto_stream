//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/esf/OtherHash.java
//

#include "ASN1Object.h"
#include "ASN1ObjectIdentifier.h"
#include "ASN1OctetString.h"
#include "ASN1Primitive.h"
#include "AlgorithmIdentifier.h"
#include "DEROctetString.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "OIWObjectIdentifiers.h"
#include "OtherHash.h"
#include "OtherHashAlgAndValue.h"

@interface LibOrgBouncycastleAsn1EsfOtherHash () {
 @public
  LibOrgBouncycastleAsn1ASN1OctetString *sha1Hash_;
  LibOrgBouncycastleAsn1EsfOtherHashAlgAndValue *otherHash_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1OctetString:(LibOrgBouncycastleAsn1ASN1OctetString *)sha1Hash;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1EsfOtherHash, sha1Hash_, LibOrgBouncycastleAsn1ASN1OctetString *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1EsfOtherHash, otherHash_, LibOrgBouncycastleAsn1EsfOtherHashAlgAndValue *)

__attribute__((unused)) static void LibOrgBouncycastleAsn1EsfOtherHash_initWithLibOrgBouncycastleAsn1ASN1OctetString_(LibOrgBouncycastleAsn1EsfOtherHash *self, LibOrgBouncycastleAsn1ASN1OctetString *sha1Hash);

__attribute__((unused)) static LibOrgBouncycastleAsn1EsfOtherHash *new_LibOrgBouncycastleAsn1EsfOtherHash_initWithLibOrgBouncycastleAsn1ASN1OctetString_(LibOrgBouncycastleAsn1ASN1OctetString *sha1Hash) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1EsfOtherHash *create_LibOrgBouncycastleAsn1EsfOtherHash_initWithLibOrgBouncycastleAsn1ASN1OctetString_(LibOrgBouncycastleAsn1ASN1OctetString *sha1Hash);

@implementation LibOrgBouncycastleAsn1EsfOtherHash

+ (LibOrgBouncycastleAsn1EsfOtherHash *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1EsfOtherHash_getInstanceWithId_(obj);
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1OctetString:(LibOrgBouncycastleAsn1ASN1OctetString *)sha1Hash {
  LibOrgBouncycastleAsn1EsfOtherHash_initWithLibOrgBouncycastleAsn1ASN1OctetString_(self, sha1Hash);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1EsfOtherHashAlgAndValue:(LibOrgBouncycastleAsn1EsfOtherHashAlgAndValue *)otherHash {
  LibOrgBouncycastleAsn1EsfOtherHash_initWithLibOrgBouncycastleAsn1EsfOtherHashAlgAndValue_(self, otherHash);
  return self;
}

- (instancetype)initWithByteArray:(IOSByteArray *)sha1Hash {
  LibOrgBouncycastleAsn1EsfOtherHash_initWithByteArray_(self, sha1Hash);
  return self;
}

- (LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)getHashAlgorithm {
  if (nil == self->otherHash_) {
    return new_LibOrgBouncycastleAsn1X509AlgorithmIdentifier_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(JreLoadStatic(LibOrgBouncycastleAsn1OiwOIWObjectIdentifiers, idSHA1));
  }
  return [self->otherHash_ getHashAlgorithm];
}

- (IOSByteArray *)getHashValue {
  if (nil == self->otherHash_) {
    return [((LibOrgBouncycastleAsn1ASN1OctetString *) nil_chk(self->sha1Hash_)) getOctets];
  }
  return [((LibOrgBouncycastleAsn1ASN1OctetString *) nil_chk([self->otherHash_ getHashValue])) getOctets];
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  if (nil == self->otherHash_) {
    return self->sha1Hash_;
  }
  return [self->otherHash_ toASN1Primitive];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LLibOrgBouncycastleAsn1EsfOtherHash;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509AlgorithmIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithId:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1OctetString:);
  methods[2].selector = @selector(initWithLibOrgBouncycastleAsn1EsfOtherHashAlgAndValue:);
  methods[3].selector = @selector(initWithByteArray:);
  methods[4].selector = @selector(getHashAlgorithm);
  methods[5].selector = @selector(getHashValue);
  methods[6].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "sha1Hash_", "LLibOrgBouncycastleAsn1ASN1OctetString;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "otherHash_", "LLibOrgBouncycastleAsn1EsfOtherHashAlgAndValue;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LNSObject;", "LLibOrgBouncycastleAsn1ASN1OctetString;", "LLibOrgBouncycastleAsn1EsfOtherHashAlgAndValue;", "[B" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1EsfOtherHash = { "OtherHash", "lib.org.bouncycastle.asn1.esf", ptrTable, methods, fields, 7, 0x1, 7, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1EsfOtherHash;
}

@end

LibOrgBouncycastleAsn1EsfOtherHash *LibOrgBouncycastleAsn1EsfOtherHash_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1EsfOtherHash_initialize();
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1EsfOtherHash class]]) {
    return (LibOrgBouncycastleAsn1EsfOtherHash *) obj;
  }
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1ASN1OctetString class]]) {
    return new_LibOrgBouncycastleAsn1EsfOtherHash_initWithLibOrgBouncycastleAsn1ASN1OctetString_((LibOrgBouncycastleAsn1ASN1OctetString *) obj);
  }
  return new_LibOrgBouncycastleAsn1EsfOtherHash_initWithLibOrgBouncycastleAsn1EsfOtherHashAlgAndValue_(LibOrgBouncycastleAsn1EsfOtherHashAlgAndValue_getInstanceWithId_(obj));
}

void LibOrgBouncycastleAsn1EsfOtherHash_initWithLibOrgBouncycastleAsn1ASN1OctetString_(LibOrgBouncycastleAsn1EsfOtherHash *self, LibOrgBouncycastleAsn1ASN1OctetString *sha1Hash) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->sha1Hash_ = sha1Hash;
}

LibOrgBouncycastleAsn1EsfOtherHash *new_LibOrgBouncycastleAsn1EsfOtherHash_initWithLibOrgBouncycastleAsn1ASN1OctetString_(LibOrgBouncycastleAsn1ASN1OctetString *sha1Hash) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1EsfOtherHash, initWithLibOrgBouncycastleAsn1ASN1OctetString_, sha1Hash)
}

LibOrgBouncycastleAsn1EsfOtherHash *create_LibOrgBouncycastleAsn1EsfOtherHash_initWithLibOrgBouncycastleAsn1ASN1OctetString_(LibOrgBouncycastleAsn1ASN1OctetString *sha1Hash) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1EsfOtherHash, initWithLibOrgBouncycastleAsn1ASN1OctetString_, sha1Hash)
}

void LibOrgBouncycastleAsn1EsfOtherHash_initWithLibOrgBouncycastleAsn1EsfOtherHashAlgAndValue_(LibOrgBouncycastleAsn1EsfOtherHash *self, LibOrgBouncycastleAsn1EsfOtherHashAlgAndValue *otherHash) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->otherHash_ = otherHash;
}

LibOrgBouncycastleAsn1EsfOtherHash *new_LibOrgBouncycastleAsn1EsfOtherHash_initWithLibOrgBouncycastleAsn1EsfOtherHashAlgAndValue_(LibOrgBouncycastleAsn1EsfOtherHashAlgAndValue *otherHash) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1EsfOtherHash, initWithLibOrgBouncycastleAsn1EsfOtherHashAlgAndValue_, otherHash)
}

LibOrgBouncycastleAsn1EsfOtherHash *create_LibOrgBouncycastleAsn1EsfOtherHash_initWithLibOrgBouncycastleAsn1EsfOtherHashAlgAndValue_(LibOrgBouncycastleAsn1EsfOtherHashAlgAndValue *otherHash) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1EsfOtherHash, initWithLibOrgBouncycastleAsn1EsfOtherHashAlgAndValue_, otherHash)
}

void LibOrgBouncycastleAsn1EsfOtherHash_initWithByteArray_(LibOrgBouncycastleAsn1EsfOtherHash *self, IOSByteArray *sha1Hash) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->sha1Hash_ = new_LibOrgBouncycastleAsn1DEROctetString_initWithByteArray_(sha1Hash);
}

LibOrgBouncycastleAsn1EsfOtherHash *new_LibOrgBouncycastleAsn1EsfOtherHash_initWithByteArray_(IOSByteArray *sha1Hash) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1EsfOtherHash, initWithByteArray_, sha1Hash)
}

LibOrgBouncycastleAsn1EsfOtherHash *create_LibOrgBouncycastleAsn1EsfOtherHash_initWithByteArray_(IOSByteArray *sha1Hash) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1EsfOtherHash, initWithByteArray_, sha1Hash)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1EsfOtherHash)
