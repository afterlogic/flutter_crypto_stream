//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/com/afterlogic/pgp/key/protection/PassphraseMapKeyRingProtector.java
//

#include "J2ObjC_source.h"
#include "KeyRingProtectionSettings.h"
#include "PBESecretKeyDecryptor.h"
#include "PBESecretKeyEncryptor.h"
#include "Passphrase.h"
#include "PassphraseMapKeyRingProtector.h"
#include "PasswordBasedSecretKeyRingProtector.h"
#include "SecretKeyPassphraseProvider.h"
#include "SecretKeyRingProtector.h"
#include "java/lang/Long.h"
#include "java/util/HashMap.h"
#include "java/util/Map.h"

@interface LibComAfterlogicPgpKeyProtectionPassphraseMapKeyRingProtector () {
 @public
  id<JavaUtilMap> cache_;
  id<LibComAfterlogicPgpKeyProtectionSecretKeyRingProtector> protector_;
  id<LibComAfterlogicPgpKeyProtectionSecretKeyPassphraseProvider> provider_;
}

@end

J2OBJC_FIELD_SETTER(LibComAfterlogicPgpKeyProtectionPassphraseMapKeyRingProtector, cache_, id<JavaUtilMap>)
J2OBJC_FIELD_SETTER(LibComAfterlogicPgpKeyProtectionPassphraseMapKeyRingProtector, protector_, id<LibComAfterlogicPgpKeyProtectionSecretKeyRingProtector>)
J2OBJC_FIELD_SETTER(LibComAfterlogicPgpKeyProtectionPassphraseMapKeyRingProtector, provider_, id<LibComAfterlogicPgpKeyProtectionSecretKeyPassphraseProvider>)

@implementation LibComAfterlogicPgpKeyProtectionPassphraseMapKeyRingProtector

- (instancetype)initWithJavaUtilMap:(id<JavaUtilMap>)passphrases
withLibComAfterlogicPgpKeyProtectionKeyRingProtectionSettings:(LibComAfterlogicPgpKeyProtectionKeyRingProtectionSettings *)protectionSettings
withLibComAfterlogicPgpKeyProtectionSecretKeyPassphraseProvider:(id<LibComAfterlogicPgpKeyProtectionSecretKeyPassphraseProvider>)missingPassphraseCallback {
  LibComAfterlogicPgpKeyProtectionPassphraseMapKeyRingProtector_initWithJavaUtilMap_withLibComAfterlogicPgpKeyProtectionKeyRingProtectionSettings_withLibComAfterlogicPgpKeyProtectionSecretKeyPassphraseProvider_(self, passphrases, protectionSettings, missingPassphraseCallback);
  return self;
}

- (void)addPassphraseWithJavaLangLong:(JavaLangLong *)keyId
withLibComAfterlogicPgpUtilPassphrase:(LibComAfterlogicPgpUtilPassphrase *)passphrase {
  (void) [((id<JavaUtilMap>) nil_chk(self->cache_)) putWithId:keyId withId:passphrase];
}

- (void)forgetPassphraseWithJavaLangLong:(JavaLangLong *)keyId {
  LibComAfterlogicPgpUtilPassphrase *passphrase = [((id<JavaUtilMap>) nil_chk(cache_)) getWithId:keyId];
  [((LibComAfterlogicPgpUtilPassphrase *) nil_chk(passphrase)) clear];
  (void) [cache_ removeWithId:keyId];
}

- (LibComAfterlogicPgpUtilPassphrase *)getPassphraseForWithJavaLangLong:(JavaLangLong *)keyId {
  LibComAfterlogicPgpUtilPassphrase *passphrase = [((id<JavaUtilMap>) nil_chk(cache_)) getWithId:keyId];
  if (passphrase == nil || ![passphrase isValid]) {
    passphrase = [((id<LibComAfterlogicPgpKeyProtectionSecretKeyPassphraseProvider>) nil_chk(provider_)) getPassphraseForWithJavaLangLong:keyId];
    if (passphrase != nil) {
      (void) [cache_ putWithId:keyId withId:passphrase];
    }
  }
  return passphrase;
}

- (LibOrgBouncycastleOpenpgpOperatorPBESecretKeyDecryptor *)getDecryptorWithJavaLangLong:(JavaLangLong *)keyId {
  return [((id<LibComAfterlogicPgpKeyProtectionSecretKeyRingProtector>) nil_chk(protector_)) getDecryptorWithJavaLangLong:keyId];
}

- (LibOrgBouncycastleOpenpgpOperatorPBESecretKeyEncryptor *)getEncryptorWithJavaLangLong:(JavaLangLong *)keyId {
  return [((id<LibComAfterlogicPgpKeyProtectionSecretKeyRingProtector>) nil_chk(protector_)) getEncryptorWithJavaLangLong:keyId];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, 1, -1, -1 },
    { NULL, "V", 0x1, 2, 3, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 4, 5, -1, -1, -1, -1 },
    { NULL, "LLibComAfterlogicPgpUtilPassphrase;", 0x1, 6, 5, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpOperatorPBESecretKeyDecryptor;", 0x1, 7, 5, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpOperatorPBESecretKeyEncryptor;", 0x1, 8, 5, 9, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithJavaUtilMap:withLibComAfterlogicPgpKeyProtectionKeyRingProtectionSettings:withLibComAfterlogicPgpKeyProtectionSecretKeyPassphraseProvider:);
  methods[1].selector = @selector(addPassphraseWithJavaLangLong:withLibComAfterlogicPgpUtilPassphrase:);
  methods[2].selector = @selector(forgetPassphraseWithJavaLangLong:);
  methods[3].selector = @selector(getPassphraseForWithJavaLangLong:);
  methods[4].selector = @selector(getDecryptorWithJavaLangLong:);
  methods[5].selector = @selector(getEncryptorWithJavaLangLong:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "cache_", "LJavaUtilMap;", .constantValue.asLong = 0, 0x12, -1, -1, 10, -1 },
    { "protector_", "LLibComAfterlogicPgpKeyProtectionSecretKeyRingProtector;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "provider_", "LLibComAfterlogicPgpKeyProtectionSecretKeyPassphraseProvider;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaUtilMap;LLibComAfterlogicPgpKeyProtectionKeyRingProtectionSettings;LLibComAfterlogicPgpKeyProtectionSecretKeyPassphraseProvider;", "(Ljava/util/Map<Ljava/lang/Long;Llib/com/afterlogic/pgp/util/Passphrase;>;Llib/com/afterlogic/pgp/key/protection/KeyRingProtectionSettings;Llib/com/afterlogic/pgp/key/protection/SecretKeyPassphraseProvider;)V", "addPassphrase", "LJavaLangLong;LLibComAfterlogicPgpUtilPassphrase;", "forgetPassphrase", "LJavaLangLong;", "getPassphraseFor", "getDecryptor", "getEncryptor", "LLibOrgBouncycastleOpenpgpPGPException;", "Ljava/util/Map<Ljava/lang/Long;Llib/com/afterlogic/pgp/util/Passphrase;>;" };
  static const J2ObjcClassInfo _LibComAfterlogicPgpKeyProtectionPassphraseMapKeyRingProtector = { "PassphraseMapKeyRingProtector", "lib.com.afterlogic.pgp.key.protection", ptrTable, methods, fields, 7, 0x1, 6, 3, -1, -1, -1, -1, -1 };
  return &_LibComAfterlogicPgpKeyProtectionPassphraseMapKeyRingProtector;
}

@end

void LibComAfterlogicPgpKeyProtectionPassphraseMapKeyRingProtector_initWithJavaUtilMap_withLibComAfterlogicPgpKeyProtectionKeyRingProtectionSettings_withLibComAfterlogicPgpKeyProtectionSecretKeyPassphraseProvider_(LibComAfterlogicPgpKeyProtectionPassphraseMapKeyRingProtector *self, id<JavaUtilMap> passphrases, LibComAfterlogicPgpKeyProtectionKeyRingProtectionSettings *protectionSettings, id<LibComAfterlogicPgpKeyProtectionSecretKeyPassphraseProvider> missingPassphraseCallback) {
  NSObject_init(self);
  self->cache_ = new_JavaUtilHashMap_init();
  [self->cache_ putAllWithJavaUtilMap:passphrases];
  self->protector_ = new_LibComAfterlogicPgpKeyProtectionPasswordBasedSecretKeyRingProtector_initWithLibComAfterlogicPgpKeyProtectionKeyRingProtectionSettings_withLibComAfterlogicPgpKeyProtectionSecretKeyPassphraseProvider_(protectionSettings, self);
  self->provider_ = missingPassphraseCallback;
}

LibComAfterlogicPgpKeyProtectionPassphraseMapKeyRingProtector *new_LibComAfterlogicPgpKeyProtectionPassphraseMapKeyRingProtector_initWithJavaUtilMap_withLibComAfterlogicPgpKeyProtectionKeyRingProtectionSettings_withLibComAfterlogicPgpKeyProtectionSecretKeyPassphraseProvider_(id<JavaUtilMap> passphrases, LibComAfterlogicPgpKeyProtectionKeyRingProtectionSettings *protectionSettings, id<LibComAfterlogicPgpKeyProtectionSecretKeyPassphraseProvider> missingPassphraseCallback) {
  J2OBJC_NEW_IMPL(LibComAfterlogicPgpKeyProtectionPassphraseMapKeyRingProtector, initWithJavaUtilMap_withLibComAfterlogicPgpKeyProtectionKeyRingProtectionSettings_withLibComAfterlogicPgpKeyProtectionSecretKeyPassphraseProvider_, passphrases, protectionSettings, missingPassphraseCallback)
}

LibComAfterlogicPgpKeyProtectionPassphraseMapKeyRingProtector *create_LibComAfterlogicPgpKeyProtectionPassphraseMapKeyRingProtector_initWithJavaUtilMap_withLibComAfterlogicPgpKeyProtectionKeyRingProtectionSettings_withLibComAfterlogicPgpKeyProtectionSecretKeyPassphraseProvider_(id<JavaUtilMap> passphrases, LibComAfterlogicPgpKeyProtectionKeyRingProtectionSettings *protectionSettings, id<LibComAfterlogicPgpKeyProtectionSecretKeyPassphraseProvider> missingPassphraseCallback) {
  J2OBJC_CREATE_IMPL(LibComAfterlogicPgpKeyProtectionPassphraseMapKeyRingProtector, initWithJavaUtilMap_withLibComAfterlogicPgpKeyProtectionKeyRingProtectionSettings_withLibComAfterlogicPgpKeyProtectionSecretKeyPassphraseProvider_, passphrases, protectionSettings, missingPassphraseCallback)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibComAfterlogicPgpKeyProtectionPassphraseMapKeyRingProtector)
