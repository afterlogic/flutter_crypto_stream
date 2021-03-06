//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/PKIXCertStoreSelector.java
//

#include "IOSClass.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "PKIXCertStoreSelector.h"
#include "java/io/IOException.h"
#include "java/lang/IllegalStateException.h"
#include "java/math/BigInteger.h"
#include "java/security/PublicKey.h"
#include "java/security/cert/CertSelector.h"
#include "java/security/cert/CertStore.h"
#include "java/security/cert/Certificate.h"
#include "java/security/cert/X509CertSelector.h"
#include "java/security/cert/X509Certificate.h"
#include "java/util/Collection.h"
#include "java/util/Date.h"
#include "java/util/Set.h"

@interface LibOrgBouncycastleJcajcePKIXCertStoreSelector () {
 @public
  id<JavaSecurityCertCertSelector> baseSelector_;
}

- (instancetype)initWithJavaSecurityCertCertSelector:(id<JavaSecurityCertCertSelector>)baseSelector;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajcePKIXCertStoreSelector, baseSelector_, id<JavaSecurityCertCertSelector>)

__attribute__((unused)) static void LibOrgBouncycastleJcajcePKIXCertStoreSelector_initWithJavaSecurityCertCertSelector_(LibOrgBouncycastleJcajcePKIXCertStoreSelector *self, id<JavaSecurityCertCertSelector> baseSelector);

__attribute__((unused)) static LibOrgBouncycastleJcajcePKIXCertStoreSelector *new_LibOrgBouncycastleJcajcePKIXCertStoreSelector_initWithJavaSecurityCertCertSelector_(id<JavaSecurityCertCertSelector> baseSelector) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleJcajcePKIXCertStoreSelector *create_LibOrgBouncycastleJcajcePKIXCertStoreSelector_initWithJavaSecurityCertCertSelector_(id<JavaSecurityCertCertSelector> baseSelector);

@interface LibOrgBouncycastleJcajcePKIXCertStoreSelector_Builder () {
 @public
  id<JavaSecurityCertCertSelector> baseSelector_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajcePKIXCertStoreSelector_Builder, baseSelector_, id<JavaSecurityCertCertSelector>)

@interface LibOrgBouncycastleJcajcePKIXCertStoreSelector_SelectorClone : JavaSecurityCertX509CertSelector {
 @public
  LibOrgBouncycastleJcajcePKIXCertStoreSelector *selector_;
}

- (instancetype)initWithLibOrgBouncycastleJcajcePKIXCertStoreSelector:(LibOrgBouncycastleJcajcePKIXCertStoreSelector *)selector;

- (jboolean)matchWithJavaSecurityCertCertificate:(JavaSecurityCertCertificate *)certificate;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajcePKIXCertStoreSelector_SelectorClone)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajcePKIXCertStoreSelector_SelectorClone, selector_, LibOrgBouncycastleJcajcePKIXCertStoreSelector *)

__attribute__((unused)) static void LibOrgBouncycastleJcajcePKIXCertStoreSelector_SelectorClone_initWithLibOrgBouncycastleJcajcePKIXCertStoreSelector_(LibOrgBouncycastleJcajcePKIXCertStoreSelector_SelectorClone *self, LibOrgBouncycastleJcajcePKIXCertStoreSelector *selector);

__attribute__((unused)) static LibOrgBouncycastleJcajcePKIXCertStoreSelector_SelectorClone *new_LibOrgBouncycastleJcajcePKIXCertStoreSelector_SelectorClone_initWithLibOrgBouncycastleJcajcePKIXCertStoreSelector_(LibOrgBouncycastleJcajcePKIXCertStoreSelector *selector) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleJcajcePKIXCertStoreSelector_SelectorClone *create_LibOrgBouncycastleJcajcePKIXCertStoreSelector_SelectorClone_initWithLibOrgBouncycastleJcajcePKIXCertStoreSelector_(LibOrgBouncycastleJcajcePKIXCertStoreSelector *selector);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajcePKIXCertStoreSelector_SelectorClone)

@implementation LibOrgBouncycastleJcajcePKIXCertStoreSelector

- (instancetype)initWithJavaSecurityCertCertSelector:(id<JavaSecurityCertCertSelector>)baseSelector {
  LibOrgBouncycastleJcajcePKIXCertStoreSelector_initWithJavaSecurityCertCertSelector_(self, baseSelector);
  return self;
}

- (jboolean)matchWithId:(JavaSecurityCertCertificate *)cert {
  return [((id<JavaSecurityCertCertSelector>) nil_chk(baseSelector_)) matchWithJavaSecurityCertCertificate:cert];
}

- (id)java_clone {
  return new_LibOrgBouncycastleJcajcePKIXCertStoreSelector_initWithJavaSecurityCertCertSelector_(baseSelector_);
}

+ (id<JavaUtilCollection>)getCertificatesWithLibOrgBouncycastleJcajcePKIXCertStoreSelector:(LibOrgBouncycastleJcajcePKIXCertStoreSelector *)selector
                                                             withJavaSecurityCertCertStore:(JavaSecurityCertCertStore *)certStore {
  return LibOrgBouncycastleJcajcePKIXCertStoreSelector_getCertificatesWithLibOrgBouncycastleJcajcePKIXCertStoreSelector_withJavaSecurityCertCertStore_(selector, certStore);
}

- (id)clone {
  return [self java_clone];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, 0, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 1, 2, -1, -1, -1, -1 },
    { NULL, "LNSObject;", 0x1, 3, -1, -1, -1, -1, -1 },
    { NULL, "LJavaUtilCollection;", 0x9, 4, 5, 6, 7, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithJavaSecurityCertCertSelector:);
  methods[1].selector = @selector(matchWithId:);
  methods[2].selector = @selector(java_clone);
  methods[3].selector = @selector(getCertificatesWithLibOrgBouncycastleJcajcePKIXCertStoreSelector:withJavaSecurityCertCertStore:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "baseSelector_", "LJavaSecurityCertCertSelector;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaSecurityCertCertSelector;", "match", "LJavaSecurityCertCertificate;", "clone", "getCertificates", "LLibOrgBouncycastleJcajcePKIXCertStoreSelector;LJavaSecurityCertCertStore;", "LJavaSecurityCertCertStoreException;", "(Llib/org/bouncycastle/jcajce/PKIXCertStoreSelector;Ljava/security/cert/CertStore;)Ljava/util/Collection<+Ljava/security/cert/Certificate;>;", "LLibOrgBouncycastleJcajcePKIXCertStoreSelector_Builder;LLibOrgBouncycastleJcajcePKIXCertStoreSelector_SelectorClone;", "<T:Ljava/security/cert/Certificate;>Ljava/lang/Object;Llib/org/bouncycastle/util/Selector<TT;>;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajcePKIXCertStoreSelector = { "PKIXCertStoreSelector", "lib.org.bouncycastle.jcajce", ptrTable, methods, fields, 7, 0x1, 4, 1, -1, 8, -1, 9, -1 };
  return &_LibOrgBouncycastleJcajcePKIXCertStoreSelector;
}

- (id)copyWithZone:(NSZone *)zone {
  return [self java_clone];
}

@end

void LibOrgBouncycastleJcajcePKIXCertStoreSelector_initWithJavaSecurityCertCertSelector_(LibOrgBouncycastleJcajcePKIXCertStoreSelector *self, id<JavaSecurityCertCertSelector> baseSelector) {
  NSObject_init(self);
  self->baseSelector_ = baseSelector;
}

LibOrgBouncycastleJcajcePKIXCertStoreSelector *new_LibOrgBouncycastleJcajcePKIXCertStoreSelector_initWithJavaSecurityCertCertSelector_(id<JavaSecurityCertCertSelector> baseSelector) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajcePKIXCertStoreSelector, initWithJavaSecurityCertCertSelector_, baseSelector)
}

LibOrgBouncycastleJcajcePKIXCertStoreSelector *create_LibOrgBouncycastleJcajcePKIXCertStoreSelector_initWithJavaSecurityCertCertSelector_(id<JavaSecurityCertCertSelector> baseSelector) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajcePKIXCertStoreSelector, initWithJavaSecurityCertCertSelector_, baseSelector)
}

id<JavaUtilCollection> LibOrgBouncycastleJcajcePKIXCertStoreSelector_getCertificatesWithLibOrgBouncycastleJcajcePKIXCertStoreSelector_withJavaSecurityCertCertStore_(LibOrgBouncycastleJcajcePKIXCertStoreSelector *selector, JavaSecurityCertCertStore *certStore) {
  LibOrgBouncycastleJcajcePKIXCertStoreSelector_initialize();
  return [((JavaSecurityCertCertStore *) nil_chk(certStore)) getCertificatesWithJavaSecurityCertCertSelector:new_LibOrgBouncycastleJcajcePKIXCertStoreSelector_SelectorClone_initWithLibOrgBouncycastleJcajcePKIXCertStoreSelector_(selector)];
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajcePKIXCertStoreSelector)

@implementation LibOrgBouncycastleJcajcePKIXCertStoreSelector_Builder

- (instancetype)initWithJavaSecurityCertCertSelector:(id<JavaSecurityCertCertSelector>)certSelector {
  LibOrgBouncycastleJcajcePKIXCertStoreSelector_Builder_initWithJavaSecurityCertCertSelector_(self, certSelector);
  return self;
}

- (LibOrgBouncycastleJcajcePKIXCertStoreSelector *)build {
  return new_LibOrgBouncycastleJcajcePKIXCertStoreSelector_initWithJavaSecurityCertCertSelector_(baseSelector_);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleJcajcePKIXCertStoreSelector;", 0x1, -1, -1, -1, 1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithJavaSecurityCertCertSelector:);
  methods[1].selector = @selector(build);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "baseSelector_", "LJavaSecurityCertCertSelector;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaSecurityCertCertSelector;", "()Llib/org/bouncycastle/jcajce/PKIXCertStoreSelector<+Ljava/security/cert/Certificate;>;", "LLibOrgBouncycastleJcajcePKIXCertStoreSelector;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajcePKIXCertStoreSelector_Builder = { "Builder", "lib.org.bouncycastle.jcajce", ptrTable, methods, fields, 7, 0x9, 2, 1, 2, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajcePKIXCertStoreSelector_Builder;
}

@end

void LibOrgBouncycastleJcajcePKIXCertStoreSelector_Builder_initWithJavaSecurityCertCertSelector_(LibOrgBouncycastleJcajcePKIXCertStoreSelector_Builder *self, id<JavaSecurityCertCertSelector> certSelector) {
  NSObject_init(self);
  self->baseSelector_ = (id<JavaSecurityCertCertSelector>) cast_check([((id<JavaSecurityCertCertSelector>) nil_chk(certSelector)) clone], JavaSecurityCertCertSelector_class_());
}

LibOrgBouncycastleJcajcePKIXCertStoreSelector_Builder *new_LibOrgBouncycastleJcajcePKIXCertStoreSelector_Builder_initWithJavaSecurityCertCertSelector_(id<JavaSecurityCertCertSelector> certSelector) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajcePKIXCertStoreSelector_Builder, initWithJavaSecurityCertCertSelector_, certSelector)
}

LibOrgBouncycastleJcajcePKIXCertStoreSelector_Builder *create_LibOrgBouncycastleJcajcePKIXCertStoreSelector_Builder_initWithJavaSecurityCertCertSelector_(id<JavaSecurityCertCertSelector> certSelector) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajcePKIXCertStoreSelector_Builder, initWithJavaSecurityCertCertSelector_, certSelector)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajcePKIXCertStoreSelector_Builder)

@implementation LibOrgBouncycastleJcajcePKIXCertStoreSelector_SelectorClone

- (instancetype)initWithLibOrgBouncycastleJcajcePKIXCertStoreSelector:(LibOrgBouncycastleJcajcePKIXCertStoreSelector *)selector {
  LibOrgBouncycastleJcajcePKIXCertStoreSelector_SelectorClone_initWithLibOrgBouncycastleJcajcePKIXCertStoreSelector_(self, selector);
  return self;
}

- (jboolean)matchWithJavaSecurityCertCertificate:(JavaSecurityCertCertificate *)certificate {
  return (selector_ == nil) ? (certificate != nil) : [((LibOrgBouncycastleJcajcePKIXCertStoreSelector *) nil_chk(selector_)) matchWithId:certificate];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, 0, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 1, 2, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleJcajcePKIXCertStoreSelector:);
  methods[1].selector = @selector(matchWithJavaSecurityCertCertificate:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "selector_", "LLibOrgBouncycastleJcajcePKIXCertStoreSelector;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajcePKIXCertStoreSelector;", "match", "LJavaSecurityCertCertificate;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajcePKIXCertStoreSelector_SelectorClone = { "SelectorClone", "lib.org.bouncycastle.jcajce", ptrTable, methods, fields, 7, 0xa, 2, 1, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajcePKIXCertStoreSelector_SelectorClone;
}

@end

void LibOrgBouncycastleJcajcePKIXCertStoreSelector_SelectorClone_initWithLibOrgBouncycastleJcajcePKIXCertStoreSelector_(LibOrgBouncycastleJcajcePKIXCertStoreSelector_SelectorClone *self, LibOrgBouncycastleJcajcePKIXCertStoreSelector *selector) {
  JavaSecurityCertX509CertSelector_init(self);
  self->selector_ = selector;
  if ([((LibOrgBouncycastleJcajcePKIXCertStoreSelector *) nil_chk(selector))->baseSelector_ isKindOfClass:[JavaSecurityCertX509CertSelector class]]) {
    JavaSecurityCertX509CertSelector *baseSelector = (JavaSecurityCertX509CertSelector *) selector->baseSelector_;
    [self setAuthorityKeyIdentifierWithByteArray:[((JavaSecurityCertX509CertSelector *) nil_chk(baseSelector)) getAuthorityKeyIdentifier]];
    [self setBasicConstraintsWithInt:[baseSelector getBasicConstraints]];
    [self setCertificateWithJavaSecurityCertX509Certificate:[baseSelector getCertificate]];
    [self setCertificateValidWithJavaUtilDate:[baseSelector getCertificateValid]];
    [self setKeyUsageWithBooleanArray:[baseSelector getKeyUsage]];
    [self setMatchAllSubjectAltNamesWithBoolean:[baseSelector getMatchAllSubjectAltNames]];
    [self setPrivateKeyValidWithJavaUtilDate:[baseSelector getPrivateKeyValid]];
    [self setSerialNumberWithJavaMathBigInteger:[baseSelector getSerialNumber]];
    [self setSubjectKeyIdentifierWithByteArray:[baseSelector getSubjectKeyIdentifier]];
    [self setSubjectPublicKeyWithJavaSecurityPublicKey:[baseSelector getSubjectPublicKey]];
    @try {
      [self setExtendedKeyUsageWithJavaUtilSet:[baseSelector getExtendedKeyUsage]];
      [self setIssuerWithByteArray:[baseSelector getIssuerAsBytes]];
      [self setNameConstraintsWithByteArray:[baseSelector getNameConstraints]];
      [self setPathToNamesWithJavaUtilCollection:[baseSelector getPathToNames]];
      [self setPolicyWithJavaUtilSet:[baseSelector getPolicy]];
      [self setSubjectWithByteArray:[baseSelector getSubjectAsBytes]];
      [self setSubjectAlternativeNamesWithJavaUtilCollection:[baseSelector getSubjectAlternativeNames]];
      [self setSubjectPublicKeyAlgIDWithNSString:[baseSelector getSubjectPublicKeyAlgID]];
    }
    @catch (JavaIoIOException *e) {
      @throw new_JavaLangIllegalStateException_initWithNSString_withJavaLangThrowable_(JreStrcat("$$", @"base selector invalid: ", [e getMessage]), e);
    }
  }
}

LibOrgBouncycastleJcajcePKIXCertStoreSelector_SelectorClone *new_LibOrgBouncycastleJcajcePKIXCertStoreSelector_SelectorClone_initWithLibOrgBouncycastleJcajcePKIXCertStoreSelector_(LibOrgBouncycastleJcajcePKIXCertStoreSelector *selector) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajcePKIXCertStoreSelector_SelectorClone, initWithLibOrgBouncycastleJcajcePKIXCertStoreSelector_, selector)
}

LibOrgBouncycastleJcajcePKIXCertStoreSelector_SelectorClone *create_LibOrgBouncycastleJcajcePKIXCertStoreSelector_SelectorClone_initWithLibOrgBouncycastleJcajcePKIXCertStoreSelector_(LibOrgBouncycastleJcajcePKIXCertStoreSelector *selector) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajcePKIXCertStoreSelector_SelectorClone, initWithLibOrgBouncycastleJcajcePKIXCertStoreSelector_, selector)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajcePKIXCertStoreSelector_SelectorClone)
