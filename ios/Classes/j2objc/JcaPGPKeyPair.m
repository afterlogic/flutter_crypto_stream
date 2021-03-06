//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/openpgp/operator/jcajce/JcaPGPKeyPair.java
//

#include "J2ObjC_source.h"
#include "JcaPGPKeyConverter.h"
#include "JcaPGPKeyPair.h"
#include "PGPAlgorithmParameters.h"
#include "PGPKeyPair.h"
#include "PGPPrivateKey.h"
#include "PGPPublicKey.h"
#include "java/security/KeyPair.h"
#include "java/security/PrivateKey.h"
#include "java/security/PublicKey.h"
#include "java/util/Date.h"

@interface LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyPair ()

+ (LibOrgBouncycastleOpenpgpPGPPublicKey *)getPublicKeyWithInt:(jint)algorithm
                                     withJavaSecurityPublicKey:(id<JavaSecurityPublicKey>)pubKey
                                              withJavaUtilDate:(JavaUtilDate *)date;

+ (LibOrgBouncycastleOpenpgpPGPPublicKey *)getPublicKeyWithInt:(jint)algorithm
           withLibOrgBouncycastleOpenpgpPGPAlgorithmParameters:(id<LibOrgBouncycastleOpenpgpPGPAlgorithmParameters>)algorithmParameters
                                     withJavaSecurityPublicKey:(id<JavaSecurityPublicKey>)pubKey
                                              withJavaUtilDate:(JavaUtilDate *)date;

+ (LibOrgBouncycastleOpenpgpPGPPrivateKey *)getPrivateKeyWithLibOrgBouncycastleOpenpgpPGPPublicKey:(LibOrgBouncycastleOpenpgpPGPPublicKey *)pub
                                                                        withJavaSecurityPrivateKey:(id<JavaSecurityPrivateKey>)privKey;

@end

__attribute__((unused)) static LibOrgBouncycastleOpenpgpPGPPublicKey *LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyPair_getPublicKeyWithInt_withJavaSecurityPublicKey_withJavaUtilDate_(jint algorithm, id<JavaSecurityPublicKey> pubKey, JavaUtilDate *date);

__attribute__((unused)) static LibOrgBouncycastleOpenpgpPGPPublicKey *LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyPair_getPublicKeyWithInt_withLibOrgBouncycastleOpenpgpPGPAlgorithmParameters_withJavaSecurityPublicKey_withJavaUtilDate_(jint algorithm, id<LibOrgBouncycastleOpenpgpPGPAlgorithmParameters> algorithmParameters, id<JavaSecurityPublicKey> pubKey, JavaUtilDate *date);

__attribute__((unused)) static LibOrgBouncycastleOpenpgpPGPPrivateKey *LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyPair_getPrivateKeyWithLibOrgBouncycastleOpenpgpPGPPublicKey_withJavaSecurityPrivateKey_(LibOrgBouncycastleOpenpgpPGPPublicKey *pub, id<JavaSecurityPrivateKey> privKey);

@implementation LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyPair

+ (LibOrgBouncycastleOpenpgpPGPPublicKey *)getPublicKeyWithInt:(jint)algorithm
                                     withJavaSecurityPublicKey:(id<JavaSecurityPublicKey>)pubKey
                                              withJavaUtilDate:(JavaUtilDate *)date {
  return LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyPair_getPublicKeyWithInt_withJavaSecurityPublicKey_withJavaUtilDate_(algorithm, pubKey, date);
}

+ (LibOrgBouncycastleOpenpgpPGPPublicKey *)getPublicKeyWithInt:(jint)algorithm
           withLibOrgBouncycastleOpenpgpPGPAlgorithmParameters:(id<LibOrgBouncycastleOpenpgpPGPAlgorithmParameters>)algorithmParameters
                                     withJavaSecurityPublicKey:(id<JavaSecurityPublicKey>)pubKey
                                              withJavaUtilDate:(JavaUtilDate *)date {
  return LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyPair_getPublicKeyWithInt_withLibOrgBouncycastleOpenpgpPGPAlgorithmParameters_withJavaSecurityPublicKey_withJavaUtilDate_(algorithm, algorithmParameters, pubKey, date);
}

+ (LibOrgBouncycastleOpenpgpPGPPrivateKey *)getPrivateKeyWithLibOrgBouncycastleOpenpgpPGPPublicKey:(LibOrgBouncycastleOpenpgpPGPPublicKey *)pub
                                                                        withJavaSecurityPrivateKey:(id<JavaSecurityPrivateKey>)privKey {
  return LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyPair_getPrivateKeyWithLibOrgBouncycastleOpenpgpPGPPublicKey_withJavaSecurityPrivateKey_(pub, privKey);
}

- (instancetype)initWithInt:(jint)algorithm
    withJavaSecurityKeyPair:(JavaSecurityKeyPair *)keyPair
           withJavaUtilDate:(JavaUtilDate *)date {
  LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyPair_initWithInt_withJavaSecurityKeyPair_withJavaUtilDate_(self, algorithm, keyPair, date);
  return self;
}

- (instancetype)initWithInt:(jint)algorithm
withLibOrgBouncycastleOpenpgpPGPAlgorithmParameters:(id<LibOrgBouncycastleOpenpgpPGPAlgorithmParameters>)parameters
    withJavaSecurityKeyPair:(JavaSecurityKeyPair *)keyPair
           withJavaUtilDate:(JavaUtilDate *)date {
  LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyPair_initWithInt_withLibOrgBouncycastleOpenpgpPGPAlgorithmParameters_withJavaSecurityKeyPair_withJavaUtilDate_(self, algorithm, parameters, keyPair, date);
  return self;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LLibOrgBouncycastleOpenpgpPGPPublicKey;", 0xa, 0, 1, 2, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpPGPPublicKey;", 0xa, 0, 3, 2, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpPGPPrivateKey;", 0xa, 4, 5, 2, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 6, 2, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 7, 2, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getPublicKeyWithInt:withJavaSecurityPublicKey:withJavaUtilDate:);
  methods[1].selector = @selector(getPublicKeyWithInt:withLibOrgBouncycastleOpenpgpPGPAlgorithmParameters:withJavaSecurityPublicKey:withJavaUtilDate:);
  methods[2].selector = @selector(getPrivateKeyWithLibOrgBouncycastleOpenpgpPGPPublicKey:withJavaSecurityPrivateKey:);
  methods[3].selector = @selector(initWithInt:withJavaSecurityKeyPair:withJavaUtilDate:);
  methods[4].selector = @selector(initWithInt:withLibOrgBouncycastleOpenpgpPGPAlgorithmParameters:withJavaSecurityKeyPair:withJavaUtilDate:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "getPublicKey", "ILJavaSecurityPublicKey;LJavaUtilDate;", "LLibOrgBouncycastleOpenpgpPGPException;", "ILLibOrgBouncycastleOpenpgpPGPAlgorithmParameters;LJavaSecurityPublicKey;LJavaUtilDate;", "getPrivateKey", "LLibOrgBouncycastleOpenpgpPGPPublicKey;LJavaSecurityPrivateKey;", "ILJavaSecurityKeyPair;LJavaUtilDate;", "ILLibOrgBouncycastleOpenpgpPGPAlgorithmParameters;LJavaSecurityKeyPair;LJavaUtilDate;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyPair = { "JcaPGPKeyPair", "lib.org.bouncycastle.openpgp.operator.jcajce", ptrTable, methods, NULL, 7, 0x1, 5, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyPair;
}

@end

LibOrgBouncycastleOpenpgpPGPPublicKey *LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyPair_getPublicKeyWithInt_withJavaSecurityPublicKey_withJavaUtilDate_(jint algorithm, id<JavaSecurityPublicKey> pubKey, JavaUtilDate *date) {
  LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyPair_initialize();
  return [new_LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyConverter_init() getPGPPublicKeyWithInt:algorithm withJavaSecurityPublicKey:pubKey withJavaUtilDate:date];
}

LibOrgBouncycastleOpenpgpPGPPublicKey *LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyPair_getPublicKeyWithInt_withLibOrgBouncycastleOpenpgpPGPAlgorithmParameters_withJavaSecurityPublicKey_withJavaUtilDate_(jint algorithm, id<LibOrgBouncycastleOpenpgpPGPAlgorithmParameters> algorithmParameters, id<JavaSecurityPublicKey> pubKey, JavaUtilDate *date) {
  LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyPair_initialize();
  return [new_LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyConverter_init() getPGPPublicKeyWithInt:algorithm withLibOrgBouncycastleOpenpgpPGPAlgorithmParameters:algorithmParameters withJavaSecurityPublicKey:pubKey withJavaUtilDate:date];
}

LibOrgBouncycastleOpenpgpPGPPrivateKey *LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyPair_getPrivateKeyWithLibOrgBouncycastleOpenpgpPGPPublicKey_withJavaSecurityPrivateKey_(LibOrgBouncycastleOpenpgpPGPPublicKey *pub, id<JavaSecurityPrivateKey> privKey) {
  LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyPair_initialize();
  return [new_LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyConverter_init() getPGPPrivateKeyWithLibOrgBouncycastleOpenpgpPGPPublicKey:pub withJavaSecurityPrivateKey:privKey];
}

void LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyPair_initWithInt_withJavaSecurityKeyPair_withJavaUtilDate_(LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyPair *self, jint algorithm, JavaSecurityKeyPair *keyPair, JavaUtilDate *date) {
  LibOrgBouncycastleOpenpgpPGPKeyPair_init(self);
  self->pub_ = LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyPair_getPublicKeyWithInt_withJavaSecurityPublicKey_withJavaUtilDate_(algorithm, [((JavaSecurityKeyPair *) nil_chk(keyPair)) getPublic], date);
  self->priv_ = LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyPair_getPrivateKeyWithLibOrgBouncycastleOpenpgpPGPPublicKey_withJavaSecurityPrivateKey_(self->pub_, [keyPair getPrivate]);
}

LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyPair *new_LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyPair_initWithInt_withJavaSecurityKeyPair_withJavaUtilDate_(jint algorithm, JavaSecurityKeyPair *keyPair, JavaUtilDate *date) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyPair, initWithInt_withJavaSecurityKeyPair_withJavaUtilDate_, algorithm, keyPair, date)
}

LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyPair *create_LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyPair_initWithInt_withJavaSecurityKeyPair_withJavaUtilDate_(jint algorithm, JavaSecurityKeyPair *keyPair, JavaUtilDate *date) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyPair, initWithInt_withJavaSecurityKeyPair_withJavaUtilDate_, algorithm, keyPair, date)
}

void LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyPair_initWithInt_withLibOrgBouncycastleOpenpgpPGPAlgorithmParameters_withJavaSecurityKeyPair_withJavaUtilDate_(LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyPair *self, jint algorithm, id<LibOrgBouncycastleOpenpgpPGPAlgorithmParameters> parameters, JavaSecurityKeyPair *keyPair, JavaUtilDate *date) {
  LibOrgBouncycastleOpenpgpPGPKeyPair_init(self);
  self->pub_ = LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyPair_getPublicKeyWithInt_withLibOrgBouncycastleOpenpgpPGPAlgorithmParameters_withJavaSecurityPublicKey_withJavaUtilDate_(algorithm, parameters, [((JavaSecurityKeyPair *) nil_chk(keyPair)) getPublic], date);
  self->priv_ = LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyPair_getPrivateKeyWithLibOrgBouncycastleOpenpgpPGPPublicKey_withJavaSecurityPrivateKey_(self->pub_, [keyPair getPrivate]);
}

LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyPair *new_LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyPair_initWithInt_withLibOrgBouncycastleOpenpgpPGPAlgorithmParameters_withJavaSecurityKeyPair_withJavaUtilDate_(jint algorithm, id<LibOrgBouncycastleOpenpgpPGPAlgorithmParameters> parameters, JavaSecurityKeyPair *keyPair, JavaUtilDate *date) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyPair, initWithInt_withLibOrgBouncycastleOpenpgpPGPAlgorithmParameters_withJavaSecurityKeyPair_withJavaUtilDate_, algorithm, parameters, keyPair, date)
}

LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyPair *create_LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyPair_initWithInt_withLibOrgBouncycastleOpenpgpPGPAlgorithmParameters_withJavaSecurityKeyPair_withJavaUtilDate_(jint algorithm, id<LibOrgBouncycastleOpenpgpPGPAlgorithmParameters> parameters, JavaSecurityKeyPair *keyPair, JavaUtilDate *date) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyPair, initWithInt_withLibOrgBouncycastleOpenpgpPGPAlgorithmParameters_withJavaSecurityKeyPair_withJavaUtilDate_, algorithm, parameters, keyPair, date)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyPair)
