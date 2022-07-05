//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/com/afterlogic/pgp/PgpUtilApi.java
//

#include "ArmoredOutputStream.h"
#include "HashAlgorithmUtil.h"
#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "KeyDescription.h"
#include "KeyRingBuilder.h"
#include "KeyRingBuilderInterface.h"
#include "KeyRingProtectionSettings.h"
#include "KeyRingReader.h"
#include "KeySpec.h"
#include "KeySpecBuilder.h"
#include "KeySpecBuilderInterface.h"
#include "PBESecretKeyDecryptor.h"
#include "PGPKeyRingUtil.h"
#include "PGPPrivateKey.h"
#include "PGPPublicKey.h"
#include "PGPPublicKeyRing.h"
#include "PGPPublicKeyRingCollection.h"
#include "PGPSecretKey.h"
#include "PGPSecretKeyRing.h"
#include "PGPUtil.h"
#include "Passphrase.h"
#include "PasswordBasedSecretKeyRingProtector.h"
#include "PgpError.h"
#include "PgpErrorCase.h"
#include "PgpUtilApi.h"
#include "RSA_GENERAL.h"
#include "RsaLength.h"
#include "SecretKeyPassphraseProvider.h"
#include "SymmetricKeyAlgorithm.h"
#include "java/io/ByteArrayInputStream.h"
#include "java/io/ByteArrayOutputStream.h"
#include "java/io/InputStream.h"
#include "java/io/PrintStream.h"
#include "java/lang/Long.h"
#include "java/lang/System.h"
#include "java/lang/Throwable.h"
#include "java/util/ArrayList.h"
#include "java/util/Arrays.h"
#include "java/util/Iterator.h"
#include "java/util/List.h"

@interface LibComAfterlogicPgpPgpUtilApi_1 : NSObject < LibComAfterlogicPgpKeyProtectionSecretKeyPassphraseProvider > {
 @public
  NSString *val$password_;
}

- (instancetype)initWithNSString:(NSString *)capture$0;

- (LibComAfterlogicPgpUtilPassphrase *)getPassphraseForWithJavaLangLong:(JavaLangLong *)keyId;

@end

J2OBJC_EMPTY_STATIC_INIT(LibComAfterlogicPgpPgpUtilApi_1)

__attribute__((unused)) static void LibComAfterlogicPgpPgpUtilApi_1_initWithNSString_(LibComAfterlogicPgpPgpUtilApi_1 *self, NSString *capture$0);

__attribute__((unused)) static LibComAfterlogicPgpPgpUtilApi_1 *new_LibComAfterlogicPgpPgpUtilApi_1_initWithNSString_(NSString *capture$0) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibComAfterlogicPgpPgpUtilApi_1 *create_LibComAfterlogicPgpPgpUtilApi_1_initWithNSString_(NSString *capture$0);

@implementation LibComAfterlogicPgpPgpUtilApi

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibComAfterlogicPgpPgpUtilApi_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (LibComAfterlogicPgpKeyDescription *)getKeyDescriptionWithNSString:(NSString *)text {
  @try {
    JavaIoInputStream *inputStream = (new_JavaIoByteArrayInputStream_initWithByteArray_([((NSString *) nil_chk(text)) java_getBytes]));
    jboolean isPrivate;
    LibOrgBouncycastleOpenpgpPGPPublicKey *key;
    NSString *armoredKey;
    @try {
      key = [((LibOrgBouncycastleOpenpgpPGPPublicKeyRing *) nil_chk(LibComAfterlogicPgpKeyParsingKeyRingReader_readPublicKeyRingWithJavaIoInputStream_(LibOrgBouncycastleOpenpgpPGPUtil_getDecoderStreamWithJavaIoInputStream_(inputStream)))) getPublicKey];
      isPrivate = false;
      JavaIoByteArrayOutputStream *publicOut = new_JavaIoByteArrayOutputStream_init();
      LibOrgBouncycastleBcpgArmoredOutputStream *armoredPublicOut = new_LibOrgBouncycastleBcpgArmoredOutputStream_initWithJavaIoOutputStream_(publicOut);
      [armoredPublicOut writeWithByteArray:[((LibOrgBouncycastleOpenpgpPGPPublicKey *) nil_chk(key)) getEncoded]];
      [armoredPublicOut close];
      armoredKey = [NSString java_stringWithBytes:[publicOut toByteArray]];
    }
    @catch (JavaLangThrowable *e) {
      [inputStream reset];
      LibOrgBouncycastleOpenpgpPGPSecretKeyRing *secretKeys = LibComAfterlogicPgpKeyParsingKeyRingReader_readSecretKeyRingWithJavaIoInputStream_(LibOrgBouncycastleOpenpgpPGPUtil_getDecoderStreamWithJavaIoInputStream_(inputStream));
      key = [((LibOrgBouncycastleOpenpgpPGPSecretKeyRing *) nil_chk(secretKeys)) getPublicKey];
      isPrivate = true;
      JavaIoByteArrayOutputStream *secretOut = new_JavaIoByteArrayOutputStream_init();
      LibOrgBouncycastleBcpgArmoredOutputStream *armoredPublicOut = new_LibOrgBouncycastleBcpgArmoredOutputStream_initWithJavaIoOutputStream_(secretOut);
      [armoredPublicOut writeWithByteArray:[secretKeys getEncoded]];
      [armoredPublicOut close];
      armoredKey = [NSString java_stringWithBytes:[secretOut toByteArray]];
    }
    JavaUtilArrayList *users = new_JavaUtilArrayList_init();
    id<JavaUtilIterator> iterator = [((LibOrgBouncycastleOpenpgpPGPPublicKey *) nil_chk(key)) getUserIDs];
    while ([((id<JavaUtilIterator>) nil_chk(iterator)) hasNext]) [users addWithId:[iterator next]];
    return new_LibComAfterlogicPgpKeyDescription_initWithBoolean_withJavaUtilArrayList_withInt_withNSString_(isPrivate, users, [key getBitStrength], armoredKey);
  }
  @catch (JavaLangThrowable *e) {
    if ([e isKindOfClass:[LibComAfterlogicPgpPgpError class]]) {
      @throw (LibComAfterlogicPgpPgpError *) e;
    }
    else {
      @throw new_LibComAfterlogicPgpPgpError_initWithLibComAfterlogicPgpPgpErrorCase_(JreLoadEnum(LibComAfterlogicPgpPgpErrorCase, Undefined));
    }
  }
}

- (IOSObjectArray *)createKeysWithInt:(jint)length
                         withNSString:(NSString *)email
                         withNSString:(NSString *)password {
  LibComAfterlogicPgpKeyGenerationTypeLengthRsaLength *rsaLength = JreLoadEnum(LibComAfterlogicPgpKeyGenerationTypeLengthRsaLength, _8192);
  if (length <= 1024) rsaLength = JreLoadEnum(LibComAfterlogicPgpKeyGenerationTypeLengthRsaLength, _1024);
  else if (length <= 2048) rsaLength = JreLoadEnum(LibComAfterlogicPgpKeyGenerationTypeLengthRsaLength, _2048);
  else if (length <= 3072) rsaLength = JreLoadEnum(LibComAfterlogicPgpKeyGenerationTypeLengthRsaLength, _3072);
  else if (length <= 4096) rsaLength = JreLoadEnum(LibComAfterlogicPgpKeyGenerationTypeLengthRsaLength, _4096);
  LibComAfterlogicPgpKeyCollectionPGPKeyRingUtil *keyRing = [((id<LibComAfterlogicPgpKeyGenerationKeyRingBuilderInterface_Build>) nil_chk([((id<LibComAfterlogicPgpKeyGenerationKeyRingBuilderInterface_WithPassphrase>) nil_chk([((id<LibComAfterlogicPgpKeyGenerationKeyRingBuilderInterface_WithPrimaryUserId>) nil_chk([new_LibComAfterlogicPgpKeyGenerationKeyRingBuilder_init() withMasterKeyWithLibComAfterlogicPgpKeyGenerationKeySpec:[((id<LibComAfterlogicPgpKeyGenerationKeySpecBuilderInterface_WithDetailedConfiguration>) nil_chk([((LibComAfterlogicPgpKeyGenerationKeySpecBuilder *) nil_chk(LibComAfterlogicPgpKeyGenerationKeySpec_getBuilderWithLibComAfterlogicPgpKeyGenerationTypeKeyType_(LibComAfterlogicPgpKeyGenerationTypeRSA_GENERAL_withLengthWithLibComAfterlogicPgpKeyGenerationTypeLengthRsaLength_(rsaLength)))) withDefaultKeyFlags])) withDefaultAlgorithms]])) withPrimaryUserIdWithNSString:email])) withPassphraseWithLibComAfterlogicPgpUtilPassphrase:new_LibComAfterlogicPgpUtilPassphrase_initWithCharArray_([((NSString *) nil_chk(password)) java_toCharArray])])) build];
  JavaIoByteArrayOutputStream *secretOut = new_JavaIoByteArrayOutputStream_init();
  JavaIoByteArrayOutputStream *publicOut = new_JavaIoByteArrayOutputStream_init();
  LibOrgBouncycastleBcpgArmoredOutputStream *armoredSecretOut = new_LibOrgBouncycastleBcpgArmoredOutputStream_initWithJavaIoOutputStream_(secretOut);
  LibOrgBouncycastleBcpgArmoredOutputStream *armoredPublicOut = new_LibOrgBouncycastleBcpgArmoredOutputStream_initWithJavaIoOutputStream_(publicOut);
  [armoredSecretOut writeWithByteArray:[((LibOrgBouncycastleOpenpgpPGPSecretKeyRing *) nil_chk([((LibComAfterlogicPgpKeyCollectionPGPKeyRingUtil *) nil_chk(keyRing)) getSecretKeys])) getEncoded]];
  [armoredPublicOut writeWithByteArray:[((LibOrgBouncycastleOpenpgpPGPPublicKeyRing *) nil_chk([keyRing getPublicKeys])) getEncoded]];
  [armoredSecretOut close];
  [armoredPublicOut close];
  return [IOSObjectArray newArrayWithObjects:(id[]){ [NSString java_stringWithBytes:[publicOut toByteArray]], [NSString java_stringWithBytes:[secretOut toByteArray]] } count:2 type:NSString_class_()];
}

- (jboolean)checkKeyPasswordWithNSString:(NSString *)privateKey
                            withNSString:(NSString *)password {
  @try {
    LibOrgBouncycastleOpenpgpPGPPrivateKey *key = LibComAfterlogicPgpPgpUtilApi_getPrivateKeyWithNSString_withNSString_(privateKey, password);
    return key != nil;
  }
  @catch (JavaLangThrowable *e) {
    return false;
  }
}

+ (LibOrgBouncycastleOpenpgpPGPPrivateKey *)getPrivateKeyWithNSString:(NSString *)privateKey
                                                         withNSString:(NSString *)password {
  return LibComAfterlogicPgpPgpUtilApi_getPrivateKeyWithNSString_withNSString_(privateKey, password);
}

+ (LibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection *)getPublicKeyRingWithNSStringArray:(IOSObjectArray *)publicKeys {
  return LibComAfterlogicPgpPgpUtilApi_getPublicKeyRingWithNSStringArray_(publicKeys);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibComAfterlogicPgpKeyDescription;", 0x1, 0, 1, 2, -1, -1, -1 },
    { NULL, "[LNSString;", 0x1, 3, 4, 5, -1, -1, -1 },
    { NULL, "Z", 0x1, 6, 7, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpPGPPrivateKey;", 0x8, 8, 7, 9, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection;", 0x8, 10, 11, 9, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(getKeyDescriptionWithNSString:);
  methods[2].selector = @selector(createKeysWithInt:withNSString:withNSString:);
  methods[3].selector = @selector(checkKeyPasswordWithNSString:withNSString:);
  methods[4].selector = @selector(getPrivateKeyWithNSString:withNSString:);
  methods[5].selector = @selector(getPublicKeyRingWithNSStringArray:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "getKeyDescription", "LNSString;", "LJavaIoIOException;LLibOrgBouncycastleOpenpgpPGPException;LLibComAfterlogicPgpPgpError;", "createKeys", "ILNSString;LNSString;", "LJavaSecurityInvalidAlgorithmParameterException;LJavaSecurityNoSuchAlgorithmException;LLibOrgBouncycastleOpenpgpPGPException;LJavaIoIOException;", "checkKeyPassword", "LNSString;LNSString;", "getPrivateKey", "LLibComAfterlogicPgpPgpError;", "getPublicKeyRing", "[LNSString;" };
  static const J2ObjcClassInfo _LibComAfterlogicPgpPgpUtilApi = { "PgpUtilApi", "lib.com.afterlogic.pgp", ptrTable, methods, NULL, 7, 0x1, 6, 0, -1, -1, -1, -1, -1 };
  return &_LibComAfterlogicPgpPgpUtilApi;
}

@end

void LibComAfterlogicPgpPgpUtilApi_init(LibComAfterlogicPgpPgpUtilApi *self) {
  NSObject_init(self);
}

LibComAfterlogicPgpPgpUtilApi *new_LibComAfterlogicPgpPgpUtilApi_init() {
  J2OBJC_NEW_IMPL(LibComAfterlogicPgpPgpUtilApi, init)
}

LibComAfterlogicPgpPgpUtilApi *create_LibComAfterlogicPgpPgpUtilApi_init() {
  J2OBJC_CREATE_IMPL(LibComAfterlogicPgpPgpUtilApi, init)
}

LibOrgBouncycastleOpenpgpPGPPrivateKey *LibComAfterlogicPgpPgpUtilApi_getPrivateKeyWithNSString_withNSString_(NSString *privateKey, NSString *password) {
  LibComAfterlogicPgpPgpUtilApi_initialize();
  @try {
    LibComAfterlogicPgpKeyProtectionKeyRingProtectionSettings *setting = new_LibComAfterlogicPgpKeyProtectionKeyRingProtectionSettings_initWithLibComAfterlogicPgpAlgorithmSymmetricKeyAlgorithm_withLibComAfterlogicPgpAlgorithmHashAlgorithmUtil_withInt_(JreLoadEnum(LibComAfterlogicPgpAlgorithmSymmetricKeyAlgorithm, AES_256), JreLoadEnum(LibComAfterlogicPgpAlgorithmHashAlgorithmUtil, MD5), 0);
    LibOrgBouncycastleOpenpgpPGPSecretKeyRing *secretKeys = [new_LibComAfterlogicPgpKeyParsingKeyRingReader_init() secretKeyRingWithNSString:privateKey];
    LibComAfterlogicPgpKeyProtectionPasswordBasedSecretKeyRingProtector *secretKeyRingProtector = new_LibComAfterlogicPgpKeyProtectionPasswordBasedSecretKeyRingProtector_initWithLibComAfterlogicPgpKeyProtectionKeyRingProtectionSettings_withLibComAfterlogicPgpKeyProtectionSecretKeyPassphraseProvider_(setting, new_LibComAfterlogicPgpPgpUtilApi_1_initWithNSString_(password));
    for (LibOrgBouncycastleOpenpgpPGPSecretKey * __strong key in nil_chk(secretKeys)) {
      @try {
        return [((LibOrgBouncycastleOpenpgpPGPSecretKey *) nil_chk(key)) extractPrivateKeyWithLibOrgBouncycastleOpenpgpOperatorPBESecretKeyDecryptor:[secretKeyRingProtector getDecryptorWithJavaLangLong:JavaLangLong_valueOfWithLong_([key getKeyID])]];
      }
      @catch (JavaLangThrowable *e) {
      }
    }
  }
  @catch (JavaLangThrowable *e) {
    [e printStackTrace];
  }
  @throw new_LibComAfterlogicPgpPgpError_initWithLibComAfterlogicPgpPgpErrorCase_(JreLoadEnum(LibComAfterlogicPgpPgpErrorCase, InvalidPassword));
}

LibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection *LibComAfterlogicPgpPgpUtilApi_getPublicKeyRingWithNSStringArray_(IOSObjectArray *publicKeys) {
  LibComAfterlogicPgpPgpUtilApi_initialize();
  @try {
    jint length = publicKeys == nil ? 0 : publicKeys->size_;
    IOSObjectArray *publicKeyRings = [IOSObjectArray newArrayWithLength:length type:LibOrgBouncycastleOpenpgpPGPPublicKeyRing_class_()];
    if (length > 0) {
      jint i = 0;
      {
        IOSObjectArray *a__ = publicKeys;
        NSString * const *b__ = ((IOSObjectArray *) nil_chk(a__))->buffer_;
        NSString * const *e__ = b__ + a__->size_;
        while (b__ < e__) {
          NSString *publicKey = *b__++;
          (void) IOSObjectArray_Set(publicKeyRings, i, LibComAfterlogicPgpKeyParsingKeyRingReader_readPublicKeyRingWithJavaIoInputStream_(new_JavaIoByteArrayInputStream_initWithByteArray_([((NSString *) nil_chk(publicKey)) java_getBytes])));
          i++;
        }
      }
    }
    return new_LibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection_initWithJavaUtilCollection_(JavaUtilArrays_asListWithNSObjectArray_(publicKeyRings));
  }
  @catch (JavaLangThrowable *e) {
    [((JavaIoPrintStream *) nil_chk(JreLoadStatic(JavaLangSystem, out))) printlnWithNSString:JreStrcat("$@", @"PgpUtilApi.getPublicKeyRing error:", e)];
    @throw new_LibComAfterlogicPgpPgpError_initWithLibComAfterlogicPgpPgpErrorCase_(JreLoadEnum(LibComAfterlogicPgpPgpErrorCase, InvalidMessage));
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibComAfterlogicPgpPgpUtilApi)

@implementation LibComAfterlogicPgpPgpUtilApi_1

- (instancetype)initWithNSString:(NSString *)capture$0 {
  LibComAfterlogicPgpPgpUtilApi_1_initWithNSString_(self, capture$0);
  return self;
}

- (LibComAfterlogicPgpUtilPassphrase *)getPassphraseForWithJavaLangLong:(JavaLangLong *)keyId {
  return new_LibComAfterlogicPgpUtilPassphrase_initWithCharArray_([((NSString *) nil_chk(val$password_)) java_toCharArray]);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibComAfterlogicPgpUtilPassphrase;", 0x1, 0, 1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithNSString:);
  methods[1].selector = @selector(getPassphraseForWithJavaLangLong:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "val$password_", "LNSString;", .constantValue.asLong = 0, 0x1012, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getPassphraseFor", "LJavaLangLong;", "LLibComAfterlogicPgpPgpUtilApi;", "getPrivateKeyWithNSString:withNSString:" };
  static const J2ObjcClassInfo _LibComAfterlogicPgpPgpUtilApi_1 = { "", "lib.com.afterlogic.pgp", ptrTable, methods, fields, 7, 0x8018, 2, 1, 2, -1, 3, -1, -1 };
  return &_LibComAfterlogicPgpPgpUtilApi_1;
}

@end

void LibComAfterlogicPgpPgpUtilApi_1_initWithNSString_(LibComAfterlogicPgpPgpUtilApi_1 *self, NSString *capture$0) {
  self->val$password_ = capture$0;
  NSObject_init(self);
}

LibComAfterlogicPgpPgpUtilApi_1 *new_LibComAfterlogicPgpPgpUtilApi_1_initWithNSString_(NSString *capture$0) {
  J2OBJC_NEW_IMPL(LibComAfterlogicPgpPgpUtilApi_1, initWithNSString_, capture$0)
}

LibComAfterlogicPgpPgpUtilApi_1 *create_LibComAfterlogicPgpPgpUtilApi_1_initWithNSString_(NSString *capture$0) {
  J2OBJC_CREATE_IMPL(LibComAfterlogicPgpPgpUtilApi_1, initWithNSString_, capture$0)
}
