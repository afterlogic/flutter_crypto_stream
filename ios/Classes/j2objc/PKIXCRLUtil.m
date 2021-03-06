//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/x509/PKIXCRLUtil.java
//

#include "AnnotatedException.h"
#include "ExtendedPKIXParameters.h"
#include "J2ObjC_source.h"
#include "PKIXCRLUtil.h"
#include "StoreException.h"
#include "X509CRLStoreSelector.h"
#include "X509Store.h"
#include "java/security/cert/CertStore.h"
#include "java/security/cert/CertStoreException.h"
#include "java/security/cert/PKIXParameters.h"
#include "java/security/cert/X509CRL.h"
#include "java/security/cert/X509Certificate.h"
#include "java/util/Collection.h"
#include "java/util/Date.h"
#include "java/util/HashSet.h"
#include "java/util/Iterator.h"
#include "java/util/List.h"
#include "java/util/Set.h"

@interface LibOrgBouncycastleX509PKIXCRLUtil ()

- (id<JavaUtilCollection>)findCRLsWithLibOrgBouncycastleX509X509CRLStoreSelector:(LibOrgBouncycastleX509X509CRLStoreSelector *)crlSelect
                                                                withJavaUtilList:(id<JavaUtilList>)crlStores;

@end

__attribute__((unused)) static id<JavaUtilCollection> LibOrgBouncycastleX509PKIXCRLUtil_findCRLsWithLibOrgBouncycastleX509X509CRLStoreSelector_withJavaUtilList_(LibOrgBouncycastleX509PKIXCRLUtil *self, LibOrgBouncycastleX509X509CRLStoreSelector *crlSelect, id<JavaUtilList> crlStores);

@implementation LibOrgBouncycastleX509PKIXCRLUtil

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleX509PKIXCRLUtil_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (id<JavaUtilSet>)findCRLsWithLibOrgBouncycastleX509X509CRLStoreSelector:(LibOrgBouncycastleX509X509CRLStoreSelector *)crlselect
                         withLibOrgBouncycastleX509ExtendedPKIXParameters:(LibOrgBouncycastleX509ExtendedPKIXParameters *)paramsPKIX
                                                         withJavaUtilDate:(JavaUtilDate *)currentDate {
  id<JavaUtilSet> initialSet = new_JavaUtilHashSet_init();
  @try {
    [initialSet addAllWithJavaUtilCollection:LibOrgBouncycastleX509PKIXCRLUtil_findCRLsWithLibOrgBouncycastleX509X509CRLStoreSelector_withJavaUtilList_(self, crlselect, [((LibOrgBouncycastleX509ExtendedPKIXParameters *) nil_chk(paramsPKIX)) getAdditionalStores])];
    [initialSet addAllWithJavaUtilCollection:LibOrgBouncycastleX509PKIXCRLUtil_findCRLsWithLibOrgBouncycastleX509X509CRLStoreSelector_withJavaUtilList_(self, crlselect, [paramsPKIX getStores])];
    [initialSet addAllWithJavaUtilCollection:LibOrgBouncycastleX509PKIXCRLUtil_findCRLsWithLibOrgBouncycastleX509X509CRLStoreSelector_withJavaUtilList_(self, crlselect, [paramsPKIX getCertStores])];
  }
  @catch (LibOrgBouncycastleJceProviderAnnotatedException *e) {
    @throw new_LibOrgBouncycastleJceProviderAnnotatedException_initWithNSString_withJavaLangThrowable_(@"Exception obtaining complete CRLs.", e);
  }
  id<JavaUtilSet> finalSet = new_JavaUtilHashSet_init();
  JavaUtilDate *validityDate = currentDate;
  if ([paramsPKIX getDate] != nil) {
    validityDate = [paramsPKIX getDate];
  }
  for (id<JavaUtilIterator> it = [initialSet iterator]; [((id<JavaUtilIterator>) nil_chk(it)) hasNext]; ) {
    JavaSecurityCertX509CRL *crl = (JavaSecurityCertX509CRL *) cast_chk([it next], [JavaSecurityCertX509CRL class]);
    if ([((JavaUtilDate *) nil_chk([((JavaSecurityCertX509CRL *) nil_chk(crl)) getNextUpdate])) afterWithJavaUtilDate:validityDate]) {
      JavaSecurityCertX509Certificate *cert = [((LibOrgBouncycastleX509X509CRLStoreSelector *) nil_chk(crlselect)) getCertificateChecking];
      if (cert != nil) {
        if ([((JavaUtilDate *) nil_chk([crl getThisUpdate])) beforeWithJavaUtilDate:[cert getNotAfter]]) {
          [finalSet addWithId:crl];
        }
      }
      else {
        [finalSet addWithId:crl];
      }
    }
  }
  return finalSet;
}

- (id<JavaUtilSet>)findCRLsWithLibOrgBouncycastleX509X509CRLStoreSelector:(LibOrgBouncycastleX509X509CRLStoreSelector *)crlselect
                                       withJavaSecurityCertPKIXParameters:(JavaSecurityCertPKIXParameters *)paramsPKIX {
  id<JavaUtilSet> completeSet = new_JavaUtilHashSet_init();
  @try {
    [completeSet addAllWithJavaUtilCollection:LibOrgBouncycastleX509PKIXCRLUtil_findCRLsWithLibOrgBouncycastleX509X509CRLStoreSelector_withJavaUtilList_(self, crlselect, [((JavaSecurityCertPKIXParameters *) nil_chk(paramsPKIX)) getCertStores])];
  }
  @catch (LibOrgBouncycastleJceProviderAnnotatedException *e) {
    @throw new_LibOrgBouncycastleJceProviderAnnotatedException_initWithNSString_withJavaLangThrowable_(@"Exception obtaining complete CRLs.", e);
  }
  return completeSet;
}

- (id<JavaUtilCollection>)findCRLsWithLibOrgBouncycastleX509X509CRLStoreSelector:(LibOrgBouncycastleX509X509CRLStoreSelector *)crlSelect
                                                                withJavaUtilList:(id<JavaUtilList>)crlStores {
  return LibOrgBouncycastleX509PKIXCRLUtil_findCRLsWithLibOrgBouncycastleX509X509CRLStoreSelector_withJavaUtilList_(self, crlSelect, crlStores);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaUtilSet;", 0x1, 0, 1, 2, -1, -1, -1 },
    { NULL, "LJavaUtilSet;", 0x1, 0, 3, 2, -1, -1, -1 },
    { NULL, "LJavaUtilCollection;", 0x12, 0, 4, 2, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(findCRLsWithLibOrgBouncycastleX509X509CRLStoreSelector:withLibOrgBouncycastleX509ExtendedPKIXParameters:withJavaUtilDate:);
  methods[2].selector = @selector(findCRLsWithLibOrgBouncycastleX509X509CRLStoreSelector:withJavaSecurityCertPKIXParameters:);
  methods[3].selector = @selector(findCRLsWithLibOrgBouncycastleX509X509CRLStoreSelector:withJavaUtilList:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "findCRLs", "LLibOrgBouncycastleX509X509CRLStoreSelector;LLibOrgBouncycastleX509ExtendedPKIXParameters;LJavaUtilDate;", "LLibOrgBouncycastleJceProviderAnnotatedException;", "LLibOrgBouncycastleX509X509CRLStoreSelector;LJavaSecurityCertPKIXParameters;", "LLibOrgBouncycastleX509X509CRLStoreSelector;LJavaUtilList;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleX509PKIXCRLUtil = { "PKIXCRLUtil", "lib.org.bouncycastle.x509", ptrTable, methods, NULL, 7, 0x0, 4, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleX509PKIXCRLUtil;
}

@end

void LibOrgBouncycastleX509PKIXCRLUtil_init(LibOrgBouncycastleX509PKIXCRLUtil *self) {
  NSObject_init(self);
}

LibOrgBouncycastleX509PKIXCRLUtil *new_LibOrgBouncycastleX509PKIXCRLUtil_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleX509PKIXCRLUtil, init)
}

LibOrgBouncycastleX509PKIXCRLUtil *create_LibOrgBouncycastleX509PKIXCRLUtil_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleX509PKIXCRLUtil, init)
}

id<JavaUtilCollection> LibOrgBouncycastleX509PKIXCRLUtil_findCRLsWithLibOrgBouncycastleX509X509CRLStoreSelector_withJavaUtilList_(LibOrgBouncycastleX509PKIXCRLUtil *self, LibOrgBouncycastleX509X509CRLStoreSelector *crlSelect, id<JavaUtilList> crlStores) {
  id<JavaUtilSet> crls = new_JavaUtilHashSet_init();
  id<JavaUtilIterator> iter = [((id<JavaUtilList>) nil_chk(crlStores)) iterator];
  LibOrgBouncycastleJceProviderAnnotatedException *lastException = nil;
  jboolean foundValidStore = false;
  while ([((id<JavaUtilIterator>) nil_chk(iter)) hasNext]) {
    id obj = [iter next];
    if ([obj isKindOfClass:[LibOrgBouncycastleX509X509Store class]]) {
      LibOrgBouncycastleX509X509Store *store = (LibOrgBouncycastleX509X509Store *) obj;
      @try {
        [crls addAllWithJavaUtilCollection:[((LibOrgBouncycastleX509X509Store *) nil_chk(store)) getMatchesWithLibOrgBouncycastleUtilSelector:crlSelect]];
        foundValidStore = true;
      }
      @catch (LibOrgBouncycastleUtilStoreException *e) {
        lastException = new_LibOrgBouncycastleJceProviderAnnotatedException_initWithNSString_withJavaLangThrowable_(@"Exception searching in X.509 CRL store.", e);
      }
    }
    else {
      JavaSecurityCertCertStore *store = (JavaSecurityCertCertStore *) cast_chk(obj, [JavaSecurityCertCertStore class]);
      @try {
        [crls addAllWithJavaUtilCollection:[((JavaSecurityCertCertStore *) nil_chk(store)) getCRLsWithJavaSecurityCertCRLSelector:crlSelect]];
        foundValidStore = true;
      }
      @catch (JavaSecurityCertCertStoreException *e) {
        lastException = new_LibOrgBouncycastleJceProviderAnnotatedException_initWithNSString_withJavaLangThrowable_(@"Exception searching in X.509 CRL store.", e);
      }
    }
  }
  if (!foundValidStore && lastException != nil) {
    @throw lastException;
  }
  return crls;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleX509PKIXCRLUtil)
