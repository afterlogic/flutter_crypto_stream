//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/com/afterlogic/pgp/key/selection/keyring/impl/XMPP.java
//

#include "ExactUserId.h"
#include "J2ObjC_source.h"
#include "PGPPublicKeyRing.h"
#include "PGPSecretKeyRing.h"
#include "XMPP.h"

@implementation LibComAfterlogicPgpKeySelectionKeyringImplXMPP

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibComAfterlogicPgpKeySelectionKeyringImplXMPP_init(self);
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
  static const void *ptrTable[] = { "LLibComAfterlogicPgpKeySelectionKeyringImplXMPP_PubRingSelectionStrategy;LLibComAfterlogicPgpKeySelectionKeyringImplXMPP_SecRingSelectionStrategy;" };
  static const J2ObjcClassInfo _LibComAfterlogicPgpKeySelectionKeyringImplXMPP = { "XMPP", "lib.com.afterlogic.pgp.key.selection.keyring.impl", ptrTable, methods, NULL, 7, 0x1, 1, 0, -1, 0, -1, -1, -1 };
  return &_LibComAfterlogicPgpKeySelectionKeyringImplXMPP;
}

@end

void LibComAfterlogicPgpKeySelectionKeyringImplXMPP_init(LibComAfterlogicPgpKeySelectionKeyringImplXMPP *self) {
  NSObject_init(self);
}

LibComAfterlogicPgpKeySelectionKeyringImplXMPP *new_LibComAfterlogicPgpKeySelectionKeyringImplXMPP_init() {
  J2OBJC_NEW_IMPL(LibComAfterlogicPgpKeySelectionKeyringImplXMPP, init)
}

LibComAfterlogicPgpKeySelectionKeyringImplXMPP *create_LibComAfterlogicPgpKeySelectionKeyringImplXMPP_init() {
  J2OBJC_CREATE_IMPL(LibComAfterlogicPgpKeySelectionKeyringImplXMPP, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibComAfterlogicPgpKeySelectionKeyringImplXMPP)

@implementation LibComAfterlogicPgpKeySelectionKeyringImplXMPP_PubRingSelectionStrategy

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibComAfterlogicPgpKeySelectionKeyringImplXMPP_PubRingSelectionStrategy_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (jboolean)acceptWithId:(NSString *)jid
                  withId:(LibOrgBouncycastleOpenpgpPGPPublicKeyRing *)keyRing {
  return [super acceptWithId:JreStrcat("$$", @"xmpp:", jid) withId:keyRing];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 0, 1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(acceptWithId:withId:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "accept", "LNSString;LLibOrgBouncycastleOpenpgpPGPPublicKeyRing;", "LLibComAfterlogicPgpKeySelectionKeyringImplXMPP;" };
  static const J2ObjcClassInfo _LibComAfterlogicPgpKeySelectionKeyringImplXMPP_PubRingSelectionStrategy = { "PubRingSelectionStrategy", "lib.com.afterlogic.pgp.key.selection.keyring.impl", ptrTable, methods, NULL, 7, 0x9, 2, 0, 2, -1, -1, -1, -1 };
  return &_LibComAfterlogicPgpKeySelectionKeyringImplXMPP_PubRingSelectionStrategy;
}

@end

void LibComAfterlogicPgpKeySelectionKeyringImplXMPP_PubRingSelectionStrategy_init(LibComAfterlogicPgpKeySelectionKeyringImplXMPP_PubRingSelectionStrategy *self) {
  LibComAfterlogicPgpKeySelectionKeyringImplExactUserId_PubRingSelectionStrategy_init(self);
}

LibComAfterlogicPgpKeySelectionKeyringImplXMPP_PubRingSelectionStrategy *new_LibComAfterlogicPgpKeySelectionKeyringImplXMPP_PubRingSelectionStrategy_init() {
  J2OBJC_NEW_IMPL(LibComAfterlogicPgpKeySelectionKeyringImplXMPP_PubRingSelectionStrategy, init)
}

LibComAfterlogicPgpKeySelectionKeyringImplXMPP_PubRingSelectionStrategy *create_LibComAfterlogicPgpKeySelectionKeyringImplXMPP_PubRingSelectionStrategy_init() {
  J2OBJC_CREATE_IMPL(LibComAfterlogicPgpKeySelectionKeyringImplXMPP_PubRingSelectionStrategy, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibComAfterlogicPgpKeySelectionKeyringImplXMPP_PubRingSelectionStrategy)

@implementation LibComAfterlogicPgpKeySelectionKeyringImplXMPP_SecRingSelectionStrategy

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibComAfterlogicPgpKeySelectionKeyringImplXMPP_SecRingSelectionStrategy_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (jboolean)acceptWithId:(NSString *)jid
                  withId:(LibOrgBouncycastleOpenpgpPGPSecretKeyRing *)keyRing {
  return [super acceptWithId:JreStrcat("$$", @"xmpp:", jid) withId:keyRing];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 0, 1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(acceptWithId:withId:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "accept", "LNSString;LLibOrgBouncycastleOpenpgpPGPSecretKeyRing;", "LLibComAfterlogicPgpKeySelectionKeyringImplXMPP;" };
  static const J2ObjcClassInfo _LibComAfterlogicPgpKeySelectionKeyringImplXMPP_SecRingSelectionStrategy = { "SecRingSelectionStrategy", "lib.com.afterlogic.pgp.key.selection.keyring.impl", ptrTable, methods, NULL, 7, 0x9, 2, 0, 2, -1, -1, -1, -1 };
  return &_LibComAfterlogicPgpKeySelectionKeyringImplXMPP_SecRingSelectionStrategy;
}

@end

void LibComAfterlogicPgpKeySelectionKeyringImplXMPP_SecRingSelectionStrategy_init(LibComAfterlogicPgpKeySelectionKeyringImplXMPP_SecRingSelectionStrategy *self) {
  LibComAfterlogicPgpKeySelectionKeyringImplExactUserId_SecRingSelectionStrategy_init(self);
}

LibComAfterlogicPgpKeySelectionKeyringImplXMPP_SecRingSelectionStrategy *new_LibComAfterlogicPgpKeySelectionKeyringImplXMPP_SecRingSelectionStrategy_init() {
  J2OBJC_NEW_IMPL(LibComAfterlogicPgpKeySelectionKeyringImplXMPP_SecRingSelectionStrategy, init)
}

LibComAfterlogicPgpKeySelectionKeyringImplXMPP_SecRingSelectionStrategy *create_LibComAfterlogicPgpKeySelectionKeyringImplXMPP_SecRingSelectionStrategy_init() {
  J2OBJC_CREATE_IMPL(LibComAfterlogicPgpKeySelectionKeyringImplXMPP_SecRingSelectionStrategy, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibComAfterlogicPgpKeySelectionKeyringImplXMPP_SecRingSelectionStrategy)
