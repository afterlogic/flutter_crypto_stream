//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/util/AlgorithmIdentifierFactory.java
//

#include "ASN1ObjectIdentifier.h"
#include "AlgorithmIdentifier.h"
#include "AlgorithmIdentifierFactory.h"
#include "CAST5CBCParameters.h"
#include "DERNull.h"
#include "DEROctetString.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "KISAObjectIdentifiers.h"
#include "NISTObjectIdentifiers.h"
#include "NTTObjectIdentifiers.h"
#include "OIWObjectIdentifiers.h"
#include "PKCSObjectIdentifiers.h"
#include "RC2CBCParameter.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/security/SecureRandom.h"

@interface LibOrgBouncycastleCryptoUtilAlgorithmIdentifierFactory ()

- (instancetype)init;

@end

inline IOSShortArray *LibOrgBouncycastleCryptoUtilAlgorithmIdentifierFactory_get_rc2Table(void);
static IOSShortArray *LibOrgBouncycastleCryptoUtilAlgorithmIdentifierFactory_rc2Table;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoUtilAlgorithmIdentifierFactory, rc2Table, IOSShortArray *)

__attribute__((unused)) static void LibOrgBouncycastleCryptoUtilAlgorithmIdentifierFactory_init(LibOrgBouncycastleCryptoUtilAlgorithmIdentifierFactory *self);

__attribute__((unused)) static LibOrgBouncycastleCryptoUtilAlgorithmIdentifierFactory *new_LibOrgBouncycastleCryptoUtilAlgorithmIdentifierFactory_init(void) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleCryptoUtilAlgorithmIdentifierFactory *create_LibOrgBouncycastleCryptoUtilAlgorithmIdentifierFactory_init(void);

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleCryptoUtilAlgorithmIdentifierFactory)

LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleCryptoUtilAlgorithmIdentifierFactory_IDEA_CBC;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleCryptoUtilAlgorithmIdentifierFactory_CAST5_CBC;

@implementation LibOrgBouncycastleCryptoUtilAlgorithmIdentifierFactory

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)IDEA_CBC {
  return LibOrgBouncycastleCryptoUtilAlgorithmIdentifierFactory_IDEA_CBC;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)CAST5_CBC {
  return LibOrgBouncycastleCryptoUtilAlgorithmIdentifierFactory_CAST5_CBC;
}

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoUtilAlgorithmIdentifierFactory_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)generateEncryptionAlgIDWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)encryptionOID
                                                                                                                 withInt:(jint)keySize
                                                                                            withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random {
  return LibOrgBouncycastleCryptoUtilAlgorithmIdentifierFactory_generateEncryptionAlgIDWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withInt_withJavaSecuritySecureRandom_(encryptionOID, keySize, random);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509AlgorithmIdentifier;", 0x9, 0, 1, 2, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(generateEncryptionAlgIDWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:withInt:withJavaSecuritySecureRandom:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "IDEA_CBC", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x18, -1, 3, -1, -1 },
    { "CAST5_CBC", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x18, -1, 4, -1, -1 },
    { "rc2Table", "[S", .constantValue.asLong = 0, 0x1a, -1, 5, -1, -1 },
  };
  static const void *ptrTable[] = { "generateEncryptionAlgID", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;ILJavaSecuritySecureRandom;", "LJavaLangIllegalArgumentException;", &LibOrgBouncycastleCryptoUtilAlgorithmIdentifierFactory_IDEA_CBC, &LibOrgBouncycastleCryptoUtilAlgorithmIdentifierFactory_CAST5_CBC, &LibOrgBouncycastleCryptoUtilAlgorithmIdentifierFactory_rc2Table };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoUtilAlgorithmIdentifierFactory = { "AlgorithmIdentifierFactory", "lib.org.bouncycastle.crypto.util", ptrTable, methods, fields, 7, 0x1, 2, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoUtilAlgorithmIdentifierFactory;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleCryptoUtilAlgorithmIdentifierFactory class]) {
    LibOrgBouncycastleCryptoUtilAlgorithmIdentifierFactory_IDEA_CBC = [new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"1.3.6.1.4.1.188.7.1.1.2") intern];
    LibOrgBouncycastleCryptoUtilAlgorithmIdentifierFactory_CAST5_CBC = [new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(@"1.2.840.113533.7.66.10") intern];
    LibOrgBouncycastleCryptoUtilAlgorithmIdentifierFactory_rc2Table = [IOSShortArray newArrayWithShorts:(jshort[]){ (jint) 0xbd, (jint) 0x56, (jint) 0xea, (jint) 0xf2, (jint) 0xa2, (jint) 0xf1, (jint) 0xac, (jint) 0x2a, (jint) 0xb0, (jint) 0x93, (jint) 0xd1, (jint) 0x9c, (jint) 0x1b, (jint) 0x33, (jint) 0xfd, (jint) 0xd0, (jint) 0x30, (jint) 0x04, (jint) 0xb6, (jint) 0xdc, (jint) 0x7d, (jint) 0xdf, (jint) 0x32, (jint) 0x4b, (jint) 0xf7, (jint) 0xcb, (jint) 0x45, (jint) 0x9b, (jint) 0x31, (jint) 0xbb, (jint) 0x21, (jint) 0x5a, (jint) 0x41, (jint) 0x9f, (jint) 0xe1, (jint) 0xd9, (jint) 0x4a, (jint) 0x4d, (jint) 0x9e, (jint) 0xda, (jint) 0xa0, (jint) 0x68, (jint) 0x2c, (jint) 0xc3, (jint) 0x27, (jint) 0x5f, (jint) 0x80, (jint) 0x36, (jint) 0x3e, (jint) 0xee, (jint) 0xfb, (jint) 0x95, (jint) 0x1a, (jint) 0xfe, (jint) 0xce, (jint) 0xa8, (jint) 0x34, (jint) 0xa9, (jint) 0x13, (jint) 0xf0, (jint) 0xa6, (jint) 0x3f, (jint) 0xd8, (jint) 0x0c, (jint) 0x78, (jint) 0x24, (jint) 0xaf, (jint) 0x23, (jint) 0x52, (jint) 0xc1, (jint) 0x67, (jint) 0x17, (jint) 0xf5, (jint) 0x66, (jint) 0x90, (jint) 0xe7, (jint) 0xe8, (jint) 0x07, (jint) 0xb8, (jint) 0x60, (jint) 0x48, (jint) 0xe6, (jint) 0x1e, (jint) 0x53, (jint) 0xf3, (jint) 0x92, (jint) 0xa4, (jint) 0x72, (jint) 0x8c, (jint) 0x08, (jint) 0x15, (jint) 0x6e, (jint) 0x86, (jint) 0x00, (jint) 0x84, (jint) 0xfa, (jint) 0xf4, (jint) 0x7f, (jint) 0x8a, (jint) 0x42, (jint) 0x19, (jint) 0xf6, (jint) 0xdb, (jint) 0xcd, (jint) 0x14, (jint) 0x8d, (jint) 0x50, (jint) 0x12, (jint) 0xba, (jint) 0x3c, (jint) 0x06, (jint) 0x4e, (jint) 0xec, (jint) 0xb3, (jint) 0x35, (jint) 0x11, (jint) 0xa1, (jint) 0x88, (jint) 0x8e, (jint) 0x2b, (jint) 0x94, (jint) 0x99, (jint) 0xb7, (jint) 0x71, (jint) 0x74, (jint) 0xd3, (jint) 0xe4, (jint) 0xbf, (jint) 0x3a, (jint) 0xde, (jint) 0x96, (jint) 0x0e, (jint) 0xbc, (jint) 0x0a, (jint) 0xed, (jint) 0x77, (jint) 0xfc, (jint) 0x37, (jint) 0x6b, (jint) 0x03, (jint) 0x79, (jint) 0x89, (jint) 0x62, (jint) 0xc6, (jint) 0xd7, (jint) 0xc0, (jint) 0xd2, (jint) 0x7c, (jint) 0x6a, (jint) 0x8b, (jint) 0x22, (jint) 0xa3, (jint) 0x5b, (jint) 0x05, (jint) 0x5d, (jint) 0x02, (jint) 0x75, (jint) 0xd5, (jint) 0x61, (jint) 0xe3, (jint) 0x18, (jint) 0x8f, (jint) 0x55, (jint) 0x51, (jint) 0xad, (jint) 0x1f, (jint) 0x0b, (jint) 0x5e, (jint) 0x85, (jint) 0xe5, (jint) 0xc2, (jint) 0x57, (jint) 0x63, (jint) 0xca, (jint) 0x3d, (jint) 0x6c, (jint) 0xb4, (jint) 0xc5, (jint) 0xcc, (jint) 0x70, (jint) 0xb2, (jint) 0x91, (jint) 0x59, (jint) 0x0d, (jint) 0x47, (jint) 0x20, (jint) 0xc8, (jint) 0x4f, (jint) 0x58, (jint) 0xe0, (jint) 0x01, (jint) 0xe2, (jint) 0x16, (jint) 0x38, (jint) 0xc4, (jint) 0x6f, (jint) 0x3b, (jint) 0x0f, (jint) 0x65, (jint) 0x46, (jint) 0xbe, (jint) 0x7e, (jint) 0x2d, (jint) 0x7b, (jint) 0x82, (jint) 0xf9, (jint) 0x40, (jint) 0xb5, (jint) 0x1d, (jint) 0x73, (jint) 0xf8, (jint) 0xeb, (jint) 0x26, (jint) 0xc7, (jint) 0x87, (jint) 0x97, (jint) 0x25, (jint) 0x54, (jint) 0xb1, (jint) 0x28, (jint) 0xaa, (jint) 0x98, (jint) 0x9d, (jint) 0xa5, (jint) 0x64, (jint) 0x6d, (jint) 0x7a, (jint) 0xd4, (jint) 0x10, (jint) 0x81, (jint) 0x44, (jint) 0xef, (jint) 0x49, (jint) 0xd6, (jint) 0xae, (jint) 0x2e, (jint) 0xdd, (jint) 0x76, (jint) 0x5c, (jint) 0x2f, (jint) 0xa7, (jint) 0x1c, (jint) 0xc9, (jint) 0x09, (jint) 0x69, (jint) 0x9a, (jint) 0x83, (jint) 0xcf, (jint) 0x29, (jint) 0x39, (jint) 0xb9, (jint) 0xe9, (jint) 0x4c, (jint) 0xff, (jint) 0x43, (jint) 0xab } count:256];
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleCryptoUtilAlgorithmIdentifierFactory)
  }
}

@end

void LibOrgBouncycastleCryptoUtilAlgorithmIdentifierFactory_init(LibOrgBouncycastleCryptoUtilAlgorithmIdentifierFactory *self) {
  NSObject_init(self);
}

LibOrgBouncycastleCryptoUtilAlgorithmIdentifierFactory *new_LibOrgBouncycastleCryptoUtilAlgorithmIdentifierFactory_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoUtilAlgorithmIdentifierFactory, init)
}

LibOrgBouncycastleCryptoUtilAlgorithmIdentifierFactory *create_LibOrgBouncycastleCryptoUtilAlgorithmIdentifierFactory_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoUtilAlgorithmIdentifierFactory, init)
}

LibOrgBouncycastleAsn1X509AlgorithmIdentifier *LibOrgBouncycastleCryptoUtilAlgorithmIdentifierFactory_generateEncryptionAlgIDWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withInt_withJavaSecuritySecureRandom_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *encryptionOID, jint keySize, JavaSecuritySecureRandom *random) {
  LibOrgBouncycastleCryptoUtilAlgorithmIdentifierFactory_initialize();
  if ([((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(encryptionOID)) isEqual:JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_aes128_CBC)] || [encryptionOID isEqual:JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_aes192_CBC)] || [encryptionOID isEqual:JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_aes256_CBC)] || [encryptionOID isEqual:JreLoadStatic(LibOrgBouncycastleAsn1NttNTTObjectIdentifiers, id_camellia128_cbc)] || [encryptionOID isEqual:JreLoadStatic(LibOrgBouncycastleAsn1NttNTTObjectIdentifiers, id_camellia192_cbc)] || [encryptionOID isEqual:JreLoadStatic(LibOrgBouncycastleAsn1NttNTTObjectIdentifiers, id_camellia256_cbc)] || [encryptionOID isEqual:JreLoadStatic(LibOrgBouncycastleAsn1KisaKISAObjectIdentifiers, id_seedCBC)]) {
    IOSByteArray *iv = [IOSByteArray newArrayWithLength:16];
    [((JavaSecuritySecureRandom *) nil_chk(random)) nextBytesWithByteArray:iv];
    return new_LibOrgBouncycastleAsn1X509AlgorithmIdentifier_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(encryptionOID, new_LibOrgBouncycastleAsn1DEROctetString_initWithByteArray_(iv));
  }
  else if ([encryptionOID isEqual:JreLoadStatic(LibOrgBouncycastleAsn1PkcsPKCSObjectIdentifiers, des_EDE3_CBC)] || [encryptionOID isEqual:LibOrgBouncycastleCryptoUtilAlgorithmIdentifierFactory_IDEA_CBC] || [encryptionOID isEqual:JreLoadStatic(LibOrgBouncycastleAsn1OiwOIWObjectIdentifiers, desCBC)]) {
    IOSByteArray *iv = [IOSByteArray newArrayWithLength:8];
    [((JavaSecuritySecureRandom *) nil_chk(random)) nextBytesWithByteArray:iv];
    return new_LibOrgBouncycastleAsn1X509AlgorithmIdentifier_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(encryptionOID, new_LibOrgBouncycastleAsn1DEROctetString_initWithByteArray_(iv));
  }
  else if ([encryptionOID isEqual:LibOrgBouncycastleCryptoUtilAlgorithmIdentifierFactory_CAST5_CBC]) {
    IOSByteArray *iv = [IOSByteArray newArrayWithLength:8];
    [((JavaSecuritySecureRandom *) nil_chk(random)) nextBytesWithByteArray:iv];
    LibOrgBouncycastleAsn1MiscCAST5CBCParameters *cbcParams = new_LibOrgBouncycastleAsn1MiscCAST5CBCParameters_initWithByteArray_withInt_(iv, keySize);
    return new_LibOrgBouncycastleAsn1X509AlgorithmIdentifier_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(encryptionOID, cbcParams);
  }
  else if ([encryptionOID isEqual:JreLoadStatic(LibOrgBouncycastleAsn1PkcsPKCSObjectIdentifiers, rc4)]) {
    return new_LibOrgBouncycastleAsn1X509AlgorithmIdentifier_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(encryptionOID, JreLoadStatic(LibOrgBouncycastleAsn1DERNull, INSTANCE));
  }
  else if ([encryptionOID isEqual:JreLoadStatic(LibOrgBouncycastleAsn1PkcsPKCSObjectIdentifiers, RC2_CBC)]) {
    IOSByteArray *iv = [IOSByteArray newArrayWithLength:8];
    [((JavaSecuritySecureRandom *) nil_chk(random)) nextBytesWithByteArray:iv];
    LibOrgBouncycastleAsn1PkcsRC2CBCParameter *cbcParams = new_LibOrgBouncycastleAsn1PkcsRC2CBCParameter_initWithInt_withByteArray_(IOSShortArray_Get(nil_chk(LibOrgBouncycastleCryptoUtilAlgorithmIdentifierFactory_rc2Table), 128), iv);
    return new_LibOrgBouncycastleAsn1X509AlgorithmIdentifier_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(encryptionOID, cbcParams);
  }
  else {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"unable to match algorithm");
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoUtilAlgorithmIdentifierFactory)
