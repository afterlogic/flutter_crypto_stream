//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jce/provider/PrincipalUtils.java
//

#include "AttributeCertificateIssuer.h"
#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "PrincipalUtils.h"
#include "X500Name.h"
#include "X509AttributeCertificate.h"
#include "java/security/Principal.h"
#include "java/security/cert/TrustAnchor.h"
#include "java/security/cert/X509CRL.h"
#include "java/security/cert/X509Certificate.h"
#include "javax/security/auth/x500/X500Principal.h"

@implementation LibOrgBouncycastleJceProviderPrincipalUtils

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJceProviderPrincipalUtils_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (LibOrgBouncycastleAsn1X500X500Name *)getSubjectPrincipalWithJavaSecurityCertX509Certificate:(JavaSecurityCertX509Certificate *)cert {
  return LibOrgBouncycastleJceProviderPrincipalUtils_getSubjectPrincipalWithJavaSecurityCertX509Certificate_(cert);
}

+ (LibOrgBouncycastleAsn1X500X500Name *)getIssuerPrincipalWithJavaSecurityCertX509CRL:(JavaSecurityCertX509CRL *)crl {
  return LibOrgBouncycastleJceProviderPrincipalUtils_getIssuerPrincipalWithJavaSecurityCertX509CRL_(crl);
}

+ (LibOrgBouncycastleAsn1X500X500Name *)getIssuerPrincipalWithJavaSecurityCertX509Certificate:(JavaSecurityCertX509Certificate *)cert {
  return LibOrgBouncycastleJceProviderPrincipalUtils_getIssuerPrincipalWithJavaSecurityCertX509Certificate_(cert);
}

+ (LibOrgBouncycastleAsn1X500X500Name *)getCAWithJavaSecurityCertTrustAnchor:(JavaSecurityCertTrustAnchor *)trustAnchor {
  return LibOrgBouncycastleJceProviderPrincipalUtils_getCAWithJavaSecurityCertTrustAnchor_(trustAnchor);
}

+ (LibOrgBouncycastleAsn1X500X500Name *)getEncodedIssuerPrincipalWithId:(id)cert {
  return LibOrgBouncycastleJceProviderPrincipalUtils_getEncodedIssuerPrincipalWithId_(cert);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X500X500Name;", 0x8, 0, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X500X500Name;", 0x8, 2, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X500X500Name;", 0x8, 2, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X500X500Name;", 0x8, 4, 5, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X500X500Name;", 0x8, 6, 7, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(getSubjectPrincipalWithJavaSecurityCertX509Certificate:);
  methods[2].selector = @selector(getIssuerPrincipalWithJavaSecurityCertX509CRL:);
  methods[3].selector = @selector(getIssuerPrincipalWithJavaSecurityCertX509Certificate:);
  methods[4].selector = @selector(getCAWithJavaSecurityCertTrustAnchor:);
  methods[5].selector = @selector(getEncodedIssuerPrincipalWithId:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "getSubjectPrincipal", "LJavaSecurityCertX509Certificate;", "getIssuerPrincipal", "LJavaSecurityCertX509CRL;", "getCA", "LJavaSecurityCertTrustAnchor;", "getEncodedIssuerPrincipal", "LNSObject;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJceProviderPrincipalUtils = { "PrincipalUtils", "lib.org.bouncycastle.jce.provider", ptrTable, methods, NULL, 7, 0x0, 6, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJceProviderPrincipalUtils;
}

@end

void LibOrgBouncycastleJceProviderPrincipalUtils_init(LibOrgBouncycastleJceProviderPrincipalUtils *self) {
  NSObject_init(self);
}

LibOrgBouncycastleJceProviderPrincipalUtils *new_LibOrgBouncycastleJceProviderPrincipalUtils_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJceProviderPrincipalUtils, init)
}

LibOrgBouncycastleJceProviderPrincipalUtils *create_LibOrgBouncycastleJceProviderPrincipalUtils_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJceProviderPrincipalUtils, init)
}

LibOrgBouncycastleAsn1X500X500Name *LibOrgBouncycastleJceProviderPrincipalUtils_getSubjectPrincipalWithJavaSecurityCertX509Certificate_(JavaSecurityCertX509Certificate *cert) {
  LibOrgBouncycastleJceProviderPrincipalUtils_initialize();
  return LibOrgBouncycastleAsn1X500X500Name_getInstanceWithId_([((JavaxSecurityAuthX500X500Principal *) nil_chk([((JavaSecurityCertX509Certificate *) nil_chk(cert)) getSubjectX500Principal])) getEncoded]);
}

LibOrgBouncycastleAsn1X500X500Name *LibOrgBouncycastleJceProviderPrincipalUtils_getIssuerPrincipalWithJavaSecurityCertX509CRL_(JavaSecurityCertX509CRL *crl) {
  LibOrgBouncycastleJceProviderPrincipalUtils_initialize();
  return LibOrgBouncycastleAsn1X500X500Name_getInstanceWithId_([((JavaxSecurityAuthX500X500Principal *) nil_chk([((JavaSecurityCertX509CRL *) nil_chk(crl)) getIssuerX500Principal])) getEncoded]);
}

LibOrgBouncycastleAsn1X500X500Name *LibOrgBouncycastleJceProviderPrincipalUtils_getIssuerPrincipalWithJavaSecurityCertX509Certificate_(JavaSecurityCertX509Certificate *cert) {
  LibOrgBouncycastleJceProviderPrincipalUtils_initialize();
  return LibOrgBouncycastleAsn1X500X500Name_getInstanceWithId_([((JavaxSecurityAuthX500X500Principal *) nil_chk([((JavaSecurityCertX509Certificate *) nil_chk(cert)) getIssuerX500Principal])) getEncoded]);
}

LibOrgBouncycastleAsn1X500X500Name *LibOrgBouncycastleJceProviderPrincipalUtils_getCAWithJavaSecurityCertTrustAnchor_(JavaSecurityCertTrustAnchor *trustAnchor) {
  LibOrgBouncycastleJceProviderPrincipalUtils_initialize();
  return LibOrgBouncycastleAsn1X500X500Name_getInstanceWithId_([((JavaxSecurityAuthX500X500Principal *) nil_chk([((JavaSecurityCertTrustAnchor *) nil_chk(trustAnchor)) getCA])) getEncoded]);
}

LibOrgBouncycastleAsn1X500X500Name *LibOrgBouncycastleJceProviderPrincipalUtils_getEncodedIssuerPrincipalWithId_(id cert) {
  LibOrgBouncycastleJceProviderPrincipalUtils_initialize();
  if ([cert isKindOfClass:[JavaSecurityCertX509Certificate class]]) {
    return LibOrgBouncycastleJceProviderPrincipalUtils_getIssuerPrincipalWithJavaSecurityCertX509Certificate_((JavaSecurityCertX509Certificate *) cert);
  }
  else {
    return LibOrgBouncycastleAsn1X500X500Name_getInstanceWithId_([((JavaxSecurityAuthX500X500Principal *) nil_chk(((JavaxSecurityAuthX500X500Principal *) cast_chk(IOSObjectArray_Get(nil_chk([((LibOrgBouncycastleX509AttributeCertificateIssuer *) nil_chk([((id<LibOrgBouncycastleX509X509AttributeCertificate>) nil_chk(((id<LibOrgBouncycastleX509X509AttributeCertificate>) cast_check(cert, LibOrgBouncycastleX509X509AttributeCertificate_class_())))) getIssuer])) getPrincipals]), 0), [JavaxSecurityAuthX500X500Principal class])))) getEncoded]);
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJceProviderPrincipalUtils)
