//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cryptlib/CryptlibObjectIdentifiers.java
//

#include "ASN1ObjectIdentifier.h"
#include "CryptlibObjectIdentifiers.h"
#include "J2ObjC_source.h"

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleAsn1CryptlibCryptlibObjectIdentifiers)

LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1CryptlibCryptlibObjectIdentifiers_cryptlib;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1CryptlibCryptlibObjectIdentifiers_ecc;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1CryptlibCryptlibObjectIdentifiers_curvey25519;

@implementation LibOrgBouncycastleAsn1CryptlibCryptlibObjectIdentifiers

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)cryptlib {
  return LibOrgBouncycastleAsn1CryptlibCryptlibObjectIdentifiers_cryptlib;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)ecc {
  return LibOrgBouncycastleAsn1CryptlibCryptlibObjectIdentifiers_ecc;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)curvey25519 {
  return LibOrgBouncycastleAsn1CryptlibCryptlibObjectIdentifiers_curvey25519;
}

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleAsn1CryptlibCryptlibObjectIdentifiers_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "cryptlib", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 0, -1, -1 },
    { "ecc", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 1, -1, -1 },
    { "curvey25519", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 2, -1, -1 },
  };
  static const void *ptrTable[] = { &LibOrgBouncycastleAsn1CryptlibCryptlibObjectIdentifiers_cryptlib, &LibOrgBouncycastleAsn1CryptlibCryptlibObjectIdentifiers_ecc, &LibOrgBouncycastleAsn1CryptlibCryptlibObjectIdentifiers_curvey25519 };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1CryptlibCryptlibObjectIdentifiers = { "CryptlibObjectIdentifiers", "lib.org.bouncycastle.asn1.cryptlib", ptrTable, methods, fields, 7, 0x1, 1, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1CryptlibCryptlibObjectIdentifiers;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleAsn1CryptlibCryptlibObjectIdentifiers class]) {
    LibOrgBouncycastleAsn1CryptlibCryptlibObjectIdentifiers_cryptlib = new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"1.3.6.1.4.1.3029");
    LibOrgBouncycastleAsn1CryptlibCryptlibObjectIdentifiers_ecc = [((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk([LibOrgBouncycastleAsn1CryptlibCryptlibObjectIdentifiers_cryptlib branchWithNSString:@"1"])) branchWithNSString:@"5"];
    LibOrgBouncycastleAsn1CryptlibCryptlibObjectIdentifiers_curvey25519 = [((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(LibOrgBouncycastleAsn1CryptlibCryptlibObjectIdentifiers_ecc)) branchWithNSString:@"1"];
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleAsn1CryptlibCryptlibObjectIdentifiers)
  }
}

@end

void LibOrgBouncycastleAsn1CryptlibCryptlibObjectIdentifiers_init(LibOrgBouncycastleAsn1CryptlibCryptlibObjectIdentifiers *self) {
  NSObject_init(self);
}

LibOrgBouncycastleAsn1CryptlibCryptlibObjectIdentifiers *new_LibOrgBouncycastleAsn1CryptlibCryptlibObjectIdentifiers_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CryptlibCryptlibObjectIdentifiers, init)
}

LibOrgBouncycastleAsn1CryptlibCryptlibObjectIdentifiers *create_LibOrgBouncycastleAsn1CryptlibCryptlibObjectIdentifiers_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CryptlibCryptlibObjectIdentifiers, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1CryptlibCryptlibObjectIdentifiers)