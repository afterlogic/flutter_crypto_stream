//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/crmf/POPOSigningKeyInput.java
//

#ifndef POPOSigningKeyInput_H
#define POPOSigningKeyInput_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1CrmfPKMACValue;
@class LibOrgBouncycastleAsn1X509GeneralName;
@class LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo;

@interface LibOrgBouncycastleAsn1CrmfPOPOSigningKeyInput : LibOrgBouncycastleAsn1ASN1Object

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1X509GeneralName:(LibOrgBouncycastleAsn1X509GeneralName *)sender
                     withLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo:(LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *)spki;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1CrmfPKMACValue:(LibOrgBouncycastleAsn1CrmfPKMACValue *)pkmac
                    withLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo:(LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *)spki;

+ (LibOrgBouncycastleAsn1CrmfPOPOSigningKeyInput *)getInstanceWithId:(id)o;

- (LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *)getPublicKey;

- (LibOrgBouncycastleAsn1CrmfPKMACValue *)getPublicKeyMAC;

- (LibOrgBouncycastleAsn1X509GeneralName *)getSender;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1CrmfPOPOSigningKeyInput)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CrmfPOPOSigningKeyInput *LibOrgBouncycastleAsn1CrmfPOPOSigningKeyInput_getInstanceWithId_(id o);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1CrmfPOPOSigningKeyInput_initWithLibOrgBouncycastleAsn1X509GeneralName_withLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_(LibOrgBouncycastleAsn1CrmfPOPOSigningKeyInput *self, LibOrgBouncycastleAsn1X509GeneralName *sender, LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *spki);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CrmfPOPOSigningKeyInput *new_LibOrgBouncycastleAsn1CrmfPOPOSigningKeyInput_initWithLibOrgBouncycastleAsn1X509GeneralName_withLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_(LibOrgBouncycastleAsn1X509GeneralName *sender, LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *spki) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CrmfPOPOSigningKeyInput *create_LibOrgBouncycastleAsn1CrmfPOPOSigningKeyInput_initWithLibOrgBouncycastleAsn1X509GeneralName_withLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_(LibOrgBouncycastleAsn1X509GeneralName *sender, LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *spki);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1CrmfPOPOSigningKeyInput_initWithLibOrgBouncycastleAsn1CrmfPKMACValue_withLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_(LibOrgBouncycastleAsn1CrmfPOPOSigningKeyInput *self, LibOrgBouncycastleAsn1CrmfPKMACValue *pkmac, LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *spki);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CrmfPOPOSigningKeyInput *new_LibOrgBouncycastleAsn1CrmfPOPOSigningKeyInput_initWithLibOrgBouncycastleAsn1CrmfPKMACValue_withLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_(LibOrgBouncycastleAsn1CrmfPKMACValue *pkmac, LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *spki) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CrmfPOPOSigningKeyInput *create_LibOrgBouncycastleAsn1CrmfPOPOSigningKeyInput_initWithLibOrgBouncycastleAsn1CrmfPKMACValue_withLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_(LibOrgBouncycastleAsn1CrmfPKMACValue *pkmac, LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *spki);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1CrmfPOPOSigningKeyInput)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // POPOSigningKeyInput_H
