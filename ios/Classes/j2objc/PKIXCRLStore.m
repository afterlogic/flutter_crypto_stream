//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/PKIXCRLStore.java
//

#include "J2ObjC_source.h"
#include "PKIXCRLStore.h"

@interface LibOrgBouncycastleJcajcePKIXCRLStore : NSObject

@end

@implementation LibOrgBouncycastleJcajcePKIXCRLStore

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LJavaUtilCollection;", 0x401, 0, 1, 2, 3, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getMatchesWithLibOrgBouncycastleUtilSelector:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "getMatches", "LLibOrgBouncycastleUtilSelector;", "LLibOrgBouncycastleUtilStoreException;", "(Llib/org/bouncycastle/util/Selector<TT;>;)Ljava/util/Collection<TT;>;", "<T:Ljava/security/cert/CRL;>Ljava/lang/Object;Llib/org/bouncycastle/util/Store<TT;>;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajcePKIXCRLStore = { "PKIXCRLStore", "lib.org.bouncycastle.jcajce", ptrTable, methods, NULL, 7, 0x609, 1, 0, -1, -1, -1, 4, -1 };
  return &_LibOrgBouncycastleJcajcePKIXCRLStore;
}

@end

J2OBJC_INTERFACE_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajcePKIXCRLStore)
