//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/com/afterlogic/pgp/key/selection/key/KeySelectionStrategy.java
//

#include "J2ObjC_source.h"
#include "KeySelectionStrategy.h"

@interface LibComAfterlogicPgpKeySelectionKeyKeySelectionStrategy : NSObject

@end

@implementation LibComAfterlogicPgpKeySelectionKeyKeySelectionStrategy

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "Z", 0x401, 0, 1, -1, 2, -1, -1 },
    { NULL, "LJavaUtilSet;", 0x401, 3, 1, -1, 4, -1, -1 },
    { NULL, "LLibComAfterlogicPgpUtilMultiMap;", 0x401, 5, 6, -1, 7, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(acceptWithId:withId:);
  methods[1].selector = @selector(selectKeysFromKeyRingWithId:withId:);
  methods[2].selector = @selector(selectKeysFromKeyRingsWithLibComAfterlogicPgpUtilMultiMap:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "accept", "LNSObject;LNSObject;", "(TO;TK;)Z", "selectKeysFromKeyRing", "(TO;TR;)Ljava/util/Set<TK;>;", "selectKeysFromKeyRings", "LLibComAfterlogicPgpUtilMultiMap;", "(Llib/com/afterlogic/pgp/util/MultiMap<TO;TR;>;)Llib/com/afterlogic/pgp/util/MultiMap<TO;TK;>;", "<K:Ljava/lang/Object;R:Ljava/lang/Object;O:Ljava/lang/Object;>Ljava/lang/Object;" };
  static const J2ObjcClassInfo _LibComAfterlogicPgpKeySelectionKeyKeySelectionStrategy = { "KeySelectionStrategy", "lib.com.afterlogic.pgp.key.selection.key", ptrTable, methods, NULL, 7, 0x609, 3, 0, -1, -1, -1, 8, -1 };
  return &_LibComAfterlogicPgpKeySelectionKeyKeySelectionStrategy;
}

@end

J2OBJC_INTERFACE_TYPE_LITERAL_SOURCE(LibComAfterlogicPgpKeySelectionKeyKeySelectionStrategy)
