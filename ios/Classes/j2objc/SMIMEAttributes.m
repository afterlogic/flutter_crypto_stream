//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/smime/SMIMEAttributes.java
//

#include "ASN1ObjectIdentifier.h"
#include "J2ObjC_source.h"
#include "PKCSObjectIdentifiers.h"
#include "SMIMEAttributes.h"

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleAsn1SmimeSMIMEAttributes)

LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1SmimeSMIMEAttributes_smimeCapabilities;
LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1SmimeSMIMEAttributes_encrypKeyPref;

@implementation LibOrgBouncycastleAsn1SmimeSMIMEAttributes

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)smimeCapabilities {
  return LibOrgBouncycastleAsn1SmimeSMIMEAttributes_smimeCapabilities;
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)encrypKeyPref {
  return LibOrgBouncycastleAsn1SmimeSMIMEAttributes_encrypKeyPref;
}

+ (const J2ObjcClassInfo *)__metadata {
  static const J2ObjcFieldInfo fields[] = {
    { "smimeCapabilities", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 0, -1, -1 },
    { "encrypKeyPref", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x19, -1, 1, -1, -1 },
  };
  static const void *ptrTable[] = { &LibOrgBouncycastleAsn1SmimeSMIMEAttributes_smimeCapabilities, &LibOrgBouncycastleAsn1SmimeSMIMEAttributes_encrypKeyPref };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1SmimeSMIMEAttributes = { "SMIMEAttributes", "lib.org.bouncycastle.asn1.smime", ptrTable, NULL, fields, 7, 0x609, 0, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1SmimeSMIMEAttributes;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleAsn1SmimeSMIMEAttributes class]) {
    LibOrgBouncycastleAsn1SmimeSMIMEAttributes_smimeCapabilities = JreLoadStatic(LibOrgBouncycastleAsn1PkcsPKCSObjectIdentifiers, pkcs_9_at_smimeCapabilities);
    LibOrgBouncycastleAsn1SmimeSMIMEAttributes_encrypKeyPref = JreLoadStatic(LibOrgBouncycastleAsn1PkcsPKCSObjectIdentifiers, id_aa_encrypKeyPref);
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleAsn1SmimeSMIMEAttributes)
  }
}

@end

J2OBJC_INTERFACE_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1SmimeSMIMEAttributes)
