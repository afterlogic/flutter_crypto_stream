//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/com/afterlogic/pgp/key/selection/key/impl/EncryptionKeySelectionStrategy.java
//

#include "EncryptionKeySelectionStrategy.h"
#include "J2ObjC_source.h"
#include "PGPPublicKey.h"
#include "PublicKeySelectionStrategy.h"

@implementation LibComAfterlogicPgpKeySelectionKeyImplEncryptionKeySelectionStrategy

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibComAfterlogicPgpKeySelectionKeyImplEncryptionKeySelectionStrategy_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (jboolean)acceptWithId:(id)identifier
                  withId:(LibOrgBouncycastleOpenpgpPGPPublicKey *)key {
  return [((LibOrgBouncycastleOpenpgpPGPPublicKey *) nil_chk(key)) isEncryptionKey];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 0, 1, -1, 2, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(acceptWithId:withId:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "accept", "LNSObject;LLibOrgBouncycastleOpenpgpPGPPublicKey;", "(TO;Llib/org/bouncycastle/openpgp/PGPPublicKey;)Z", "<O:Ljava/lang/Object;>Llib/com/afterlogic/pgp/key/selection/key/PublicKeySelectionStrategy<TO;>;" };
  static const J2ObjcClassInfo _LibComAfterlogicPgpKeySelectionKeyImplEncryptionKeySelectionStrategy = { "EncryptionKeySelectionStrategy", "lib.com.afterlogic.pgp.key.selection.key.impl", ptrTable, methods, NULL, 7, 0x1, 2, 0, -1, -1, -1, 3, -1 };
  return &_LibComAfterlogicPgpKeySelectionKeyImplEncryptionKeySelectionStrategy;
}

@end

void LibComAfterlogicPgpKeySelectionKeyImplEncryptionKeySelectionStrategy_init(LibComAfterlogicPgpKeySelectionKeyImplEncryptionKeySelectionStrategy *self) {
  LibComAfterlogicPgpKeySelectionKeyPublicKeySelectionStrategy_init(self);
}

LibComAfterlogicPgpKeySelectionKeyImplEncryptionKeySelectionStrategy *new_LibComAfterlogicPgpKeySelectionKeyImplEncryptionKeySelectionStrategy_init() {
  J2OBJC_NEW_IMPL(LibComAfterlogicPgpKeySelectionKeyImplEncryptionKeySelectionStrategy, init)
}

LibComAfterlogicPgpKeySelectionKeyImplEncryptionKeySelectionStrategy *create_LibComAfterlogicPgpKeySelectionKeyImplEncryptionKeySelectionStrategy_init() {
  J2OBJC_CREATE_IMPL(LibComAfterlogicPgpKeySelectionKeyImplEncryptionKeySelectionStrategy, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibComAfterlogicPgpKeySelectionKeyImplEncryptionKeySelectionStrategy)