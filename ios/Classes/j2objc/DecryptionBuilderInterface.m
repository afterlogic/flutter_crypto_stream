//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/com/afterlogic/pgp/decryption_verification/DecryptionBuilderInterface.java
//

#include "DecryptionBuilderInterface.h"
#include "J2ObjC_source.h"

@interface LibComAfterlogicPgpDecryption_verificationDecryptionBuilderInterface : NSObject

@end

@interface LibComAfterlogicPgpDecryption_verificationDecryptionBuilderInterface_DecryptWith : NSObject

@end

@interface LibComAfterlogicPgpDecryption_verificationDecryptionBuilderInterface_VerifyWith : NSObject

@end

@interface LibComAfterlogicPgpDecryption_verificationDecryptionBuilderInterface_HandleMissingPublicKeys : NSObject

@end

@interface LibComAfterlogicPgpDecryption_verificationDecryptionBuilderInterface_Build : NSObject

@end

@implementation LibComAfterlogicPgpDecryption_verificationDecryptionBuilderInterface

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LLibComAfterlogicPgpDecryption_verificationDecryptionBuilderInterface_DecryptWith;", 0x401, 0, 1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(onInputStreamWithJavaIoInputStream:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "onInputStream", "LJavaIoInputStream;", "LLibComAfterlogicPgpDecryption_verificationDecryptionBuilderInterface_DecryptWith;LLibComAfterlogicPgpDecryption_verificationDecryptionBuilderInterface_VerifyWith;LLibComAfterlogicPgpDecryption_verificationDecryptionBuilderInterface_HandleMissingPublicKeys;LLibComAfterlogicPgpDecryption_verificationDecryptionBuilderInterface_Build;" };
  static const J2ObjcClassInfo _LibComAfterlogicPgpDecryption_verificationDecryptionBuilderInterface = { "DecryptionBuilderInterface", "lib.com.afterlogic.pgp.decryption_verification", ptrTable, methods, NULL, 7, 0x609, 1, 0, -1, 2, -1, -1, -1 };
  return &_LibComAfterlogicPgpDecryption_verificationDecryptionBuilderInterface;
}

@end

J2OBJC_INTERFACE_TYPE_LITERAL_SOURCE(LibComAfterlogicPgpDecryption_verificationDecryptionBuilderInterface)

@implementation LibComAfterlogicPgpDecryption_verificationDecryptionBuilderInterface_DecryptWith

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LLibComAfterlogicPgpDecryption_verificationDecryptionBuilderInterface_VerifyWith;", 0x401, 0, 1, -1, -1, -1, -1 },
    { NULL, "LLibComAfterlogicPgpDecryption_verificationDecryptionBuilderInterface_VerifyWith;", 0x401, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(decryptWithWithLibComAfterlogicPgpKeyProtectionSecretKeyRingProtector:withLibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection:);
  methods[1].selector = @selector(doNotDecrypt);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "decryptWith", "LLibComAfterlogicPgpKeyProtectionSecretKeyRingProtector;LLibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection;", "LLibComAfterlogicPgpDecryption_verificationDecryptionBuilderInterface;" };
  static const J2ObjcClassInfo _LibComAfterlogicPgpDecryption_verificationDecryptionBuilderInterface_DecryptWith = { "DecryptWith", "lib.com.afterlogic.pgp.decryption_verification", ptrTable, methods, NULL, 7, 0x609, 2, 0, 2, -1, -1, -1, -1 };
  return &_LibComAfterlogicPgpDecryption_verificationDecryptionBuilderInterface_DecryptWith;
}

@end

J2OBJC_INTERFACE_TYPE_LITERAL_SOURCE(LibComAfterlogicPgpDecryption_verificationDecryptionBuilderInterface_DecryptWith)

@implementation LibComAfterlogicPgpDecryption_verificationDecryptionBuilderInterface_VerifyWith

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LLibComAfterlogicPgpDecryption_verificationDecryptionBuilderInterface_HandleMissingPublicKeys;", 0x401, 0, 1, -1, -1, -1, -1 },
    { NULL, "LLibComAfterlogicPgpDecryption_verificationDecryptionBuilderInterface_HandleMissingPublicKeys;", 0x401, 0, 2, -1, 3, -1, -1 },
    { NULL, "LLibComAfterlogicPgpDecryption_verificationDecryptionBuilderInterface_HandleMissingPublicKeys;", 0x401, 0, 4, -1, 5, -1, -1 },
    { NULL, "LLibComAfterlogicPgpDecryption_verificationDecryptionBuilderInterface_Build;", 0x401, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(verifyWithWithLibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection:);
  methods[1].selector = @selector(verifyWithWithJavaUtilSet:withLibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection:);
  methods[2].selector = @selector(verifyWithWithJavaUtilSet:);
  methods[3].selector = @selector(doNotVerify);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "verifyWith", "LLibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection;", "LJavaUtilSet;LLibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection;", "(Ljava/util/Set<Llib/com/afterlogic/pgp/key/OpenPgpV4Fingerprint;>;Llib/org/bouncycastle/openpgp/PGPPublicKeyRingCollection;)Llib/com/afterlogic/pgp/decryption_verification/DecryptionBuilderInterface$HandleMissingPublicKeys;", "LJavaUtilSet;", "(Ljava/util/Set<Llib/org/bouncycastle/openpgp/PGPPublicKeyRing;>;)Llib/com/afterlogic/pgp/decryption_verification/DecryptionBuilderInterface$HandleMissingPublicKeys;", "LLibComAfterlogicPgpDecryption_verificationDecryptionBuilderInterface;" };
  static const J2ObjcClassInfo _LibComAfterlogicPgpDecryption_verificationDecryptionBuilderInterface_VerifyWith = { "VerifyWith", "lib.com.afterlogic.pgp.decryption_verification", ptrTable, methods, NULL, 7, 0x609, 4, 0, 6, -1, -1, -1, -1 };
  return &_LibComAfterlogicPgpDecryption_verificationDecryptionBuilderInterface_VerifyWith;
}

@end

J2OBJC_INTERFACE_TYPE_LITERAL_SOURCE(LibComAfterlogicPgpDecryption_verificationDecryptionBuilderInterface_VerifyWith)

@implementation LibComAfterlogicPgpDecryption_verificationDecryptionBuilderInterface_HandleMissingPublicKeys

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LLibComAfterlogicPgpDecryption_verificationDecryptionBuilderInterface_Build;", 0x401, 0, 1, -1, -1, -1, -1 },
    { NULL, "LLibComAfterlogicPgpDecryption_verificationDecryptionBuilderInterface_Build;", 0x401, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(handleMissingPublicKeysWithWithLibComAfterlogicPgpDecryption_verificationMissingPublicKeyCallback:);
  methods[1].selector = @selector(ignoreMissingPublicKeys);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "handleMissingPublicKeysWith", "LLibComAfterlogicPgpDecryption_verificationMissingPublicKeyCallback;", "LLibComAfterlogicPgpDecryption_verificationDecryptionBuilderInterface;" };
  static const J2ObjcClassInfo _LibComAfterlogicPgpDecryption_verificationDecryptionBuilderInterface_HandleMissingPublicKeys = { "HandleMissingPublicKeys", "lib.com.afterlogic.pgp.decryption_verification", ptrTable, methods, NULL, 7, 0x609, 2, 0, 2, -1, -1, -1, -1 };
  return &_LibComAfterlogicPgpDecryption_verificationDecryptionBuilderInterface_HandleMissingPublicKeys;
}

@end

J2OBJC_INTERFACE_TYPE_LITERAL_SOURCE(LibComAfterlogicPgpDecryption_verificationDecryptionBuilderInterface_HandleMissingPublicKeys)

@implementation LibComAfterlogicPgpDecryption_verificationDecryptionBuilderInterface_Build

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LLibComAfterlogicPgpDecryption_verificationDecryptionStream;", 0x401, -1, -1, 0, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(build);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "LJavaIoIOException;LLibOrgBouncycastleOpenpgpPGPException;", "LLibComAfterlogicPgpDecryption_verificationDecryptionBuilderInterface;" };
  static const J2ObjcClassInfo _LibComAfterlogicPgpDecryption_verificationDecryptionBuilderInterface_Build = { "Build", "lib.com.afterlogic.pgp.decryption_verification", ptrTable, methods, NULL, 7, 0x609, 1, 0, 1, -1, -1, -1, -1 };
  return &_LibComAfterlogicPgpDecryption_verificationDecryptionBuilderInterface_Build;
}

@end

J2OBJC_INTERFACE_TYPE_LITERAL_SOURCE(LibComAfterlogicPgpDecryption_verificationDecryptionBuilderInterface_Build)
