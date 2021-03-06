//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/openpgp/operator/bc/BcKeyFingerprintCalculator.java
//

#include "BCPGKey.h"
#include "BcKeyFingerprintCalculator.h"
#include "Digest.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "MD5Digest.h"
#include "MPInteger.h"
#include "PGPException.h"
#include "PublicKeyPacket.h"
#include "RSAPublicBCPGKey.h"
#include "SHA1Digest.h"
#include "java/io/IOException.h"
#include "java/math/BigInteger.h"

@implementation LibOrgBouncycastleOpenpgpOperatorBcBcKeyFingerprintCalculator

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleOpenpgpOperatorBcBcKeyFingerprintCalculator_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (IOSByteArray *)calculateFingerprintWithLibOrgBouncycastleBcpgPublicKeyPacket:(LibOrgBouncycastleBcpgPublicKeyPacket *)publicPk {
  id<LibOrgBouncycastleBcpgBCPGKey> key = [((LibOrgBouncycastleBcpgPublicKeyPacket *) nil_chk(publicPk)) getKey];
  id<LibOrgBouncycastleCryptoDigest> digest;
  if ([publicPk getVersion] <= 3) {
    LibOrgBouncycastleBcpgRSAPublicBCPGKey *rK = (LibOrgBouncycastleBcpgRSAPublicBCPGKey *) cast_chk(key, [LibOrgBouncycastleBcpgRSAPublicBCPGKey class]);
    @try {
      digest = new_LibOrgBouncycastleCryptoDigestsMD5Digest_init();
      IOSByteArray *bytes = [new_LibOrgBouncycastleBcpgMPInteger_initWithJavaMathBigInteger_([((LibOrgBouncycastleBcpgRSAPublicBCPGKey *) nil_chk(rK)) getModulus]) getEncoded];
      [digest updateWithByteArray:bytes withInt:2 withInt:((IOSByteArray *) nil_chk(bytes))->size_ - 2];
      bytes = [new_LibOrgBouncycastleBcpgMPInteger_initWithJavaMathBigInteger_([rK getPublicExponent]) getEncoded];
      [digest updateWithByteArray:bytes withInt:2 withInt:((IOSByteArray *) nil_chk(bytes))->size_ - 2];
    }
    @catch (JavaIoIOException *e) {
      @throw new_LibOrgBouncycastleOpenpgpPGPException_initWithNSString_withJavaLangException_(JreStrcat("$$", @"can't encode key components: ", [e getMessage]), e);
    }
  }
  else {
    @try {
      IOSByteArray *kBytes = [publicPk getEncodedContents];
      digest = new_LibOrgBouncycastleCryptoDigestsSHA1Digest_init();
      [digest updateWithByte:(jbyte) (jint) 0x99];
      [digest updateWithByte:(jbyte) (JreRShift32(((IOSByteArray *) nil_chk(kBytes))->size_, 8))];
      [digest updateWithByte:(jbyte) kBytes->size_];
      [digest updateWithByteArray:kBytes withInt:0 withInt:kBytes->size_];
    }
    @catch (JavaIoIOException *e) {
      @throw new_LibOrgBouncycastleOpenpgpPGPException_initWithNSString_withJavaLangException_(JreStrcat("$$", @"can't encode key components: ", [e getMessage]), e);
    }
  }
  IOSByteArray *digBuf = [IOSByteArray newArrayWithLength:[((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest)) getDigestSize]];
  [digest doFinalWithByteArray:digBuf withInt:0];
  return digBuf;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, 0, 1, 2, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(calculateFingerprintWithLibOrgBouncycastleBcpgPublicKeyPacket:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "calculateFingerprint", "LLibOrgBouncycastleBcpgPublicKeyPacket;", "LLibOrgBouncycastleOpenpgpPGPException;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleOpenpgpOperatorBcBcKeyFingerprintCalculator = { "BcKeyFingerprintCalculator", "lib.org.bouncycastle.openpgp.operator.bc", ptrTable, methods, NULL, 7, 0x1, 2, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleOpenpgpOperatorBcBcKeyFingerprintCalculator;
}

@end

void LibOrgBouncycastleOpenpgpOperatorBcBcKeyFingerprintCalculator_init(LibOrgBouncycastleOpenpgpOperatorBcBcKeyFingerprintCalculator *self) {
  NSObject_init(self);
}

LibOrgBouncycastleOpenpgpOperatorBcBcKeyFingerprintCalculator *new_LibOrgBouncycastleOpenpgpOperatorBcBcKeyFingerprintCalculator_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleOpenpgpOperatorBcBcKeyFingerprintCalculator, init)
}

LibOrgBouncycastleOpenpgpOperatorBcBcKeyFingerprintCalculator *create_LibOrgBouncycastleOpenpgpOperatorBcBcKeyFingerprintCalculator_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleOpenpgpOperatorBcBcKeyFingerprintCalculator, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleOpenpgpOperatorBcBcKeyFingerprintCalculator)
