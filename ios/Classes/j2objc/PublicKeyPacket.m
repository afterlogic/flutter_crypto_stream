//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/bcpg/PublicKeyPacket.java
//

#include "BCPGInputStream.h"
#include "BCPGKey.h"
#include "BCPGObject.h"
#include "BCPGOutputStream.h"
#include "ContainedPacket.h"
#include "DSAPublicBCPGKey.h"
#include "ECDHPublicBCPGKey.h"
#include "ECDSAPublicBCPGKey.h"
#include "EdDSAPublicBCPGKey.h"
#include "ElGamalPublicBCPGKey.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "PacketTags.h"
#include "PublicKeyAlgorithmTags.h"
#include "PublicKeyPacket.h"
#include "RSAPublicBCPGKey.h"
#include "java/io/ByteArrayOutputStream.h"
#include "java/io/IOException.h"
#include "java/util/Date.h"

@interface LibOrgBouncycastleBcpgPublicKeyPacket () {
 @public
  jint version__;
  jlong time_;
  jint validDays_;
  jint algorithm_;
  id<LibOrgBouncycastleBcpgBCPGKey> key_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleBcpgPublicKeyPacket, key_, id<LibOrgBouncycastleBcpgBCPGKey>)

@implementation LibOrgBouncycastleBcpgPublicKeyPacket

- (instancetype)initWithLibOrgBouncycastleBcpgBCPGInputStream:(LibOrgBouncycastleBcpgBCPGInputStream *)inArg {
  LibOrgBouncycastleBcpgPublicKeyPacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(self, inArg);
  return self;
}

- (instancetype)initWithInt:(jint)algorithm
           withJavaUtilDate:(JavaUtilDate *)time
withLibOrgBouncycastleBcpgBCPGKey:(id<LibOrgBouncycastleBcpgBCPGKey>)key {
  LibOrgBouncycastleBcpgPublicKeyPacket_initWithInt_withJavaUtilDate_withLibOrgBouncycastleBcpgBCPGKey_(self, algorithm, time, key);
  return self;
}

- (jint)getVersion {
  return version__;
}

- (jint)getAlgorithm {
  return algorithm_;
}

- (jint)getValidDays {
  return validDays_;
}

- (JavaUtilDate *)getTime {
  return new_JavaUtilDate_initWithLong_(time_ * 1000);
}

- (id<LibOrgBouncycastleBcpgBCPGKey>)getKey {
  return key_;
}

- (IOSByteArray *)getEncodedContents {
  JavaIoByteArrayOutputStream *bOut = new_JavaIoByteArrayOutputStream_init();
  LibOrgBouncycastleBcpgBCPGOutputStream *pOut = new_LibOrgBouncycastleBcpgBCPGOutputStream_initWithJavaIoOutputStream_(bOut);
  [pOut writeWithInt:version__];
  [pOut writeWithInt:(jbyte) (JreRShift64(time_, 24))];
  [pOut writeWithInt:(jbyte) (JreRShift64(time_, 16))];
  [pOut writeWithInt:(jbyte) (JreRShift64(time_, 8))];
  [pOut writeWithInt:(jbyte) time_];
  if (version__ <= 3) {
    [pOut writeWithInt:(jbyte) (JreRShift32(validDays_, 8))];
    [pOut writeWithInt:(jbyte) validDays_];
  }
  [pOut writeWithInt:algorithm_];
  [pOut writeObjectWithLibOrgBouncycastleBcpgBCPGObject:(LibOrgBouncycastleBcpgBCPGObject *) cast_chk(key_, [LibOrgBouncycastleBcpgBCPGObject class])];
  [pOut close];
  return [bOut toByteArray];
}

- (void)encodeWithLibOrgBouncycastleBcpgBCPGOutputStream:(LibOrgBouncycastleBcpgBCPGOutputStream *)outArg {
  [((LibOrgBouncycastleBcpgBCPGOutputStream *) nil_chk(outArg)) writePacketWithInt:LibOrgBouncycastleBcpgPacketTags_PUBLIC_KEY withByteArray:[self getEncodedContents] withBoolean:true];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, 0, 1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaUtilDate;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleBcpgBCPGKey;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, 1, -1, -1, -1 },
    { NULL, "V", 0x1, 3, 4, 1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleBcpgBCPGInputStream:);
  methods[1].selector = @selector(initWithInt:withJavaUtilDate:withLibOrgBouncycastleBcpgBCPGKey:);
  methods[2].selector = @selector(getVersion);
  methods[3].selector = @selector(getAlgorithm);
  methods[4].selector = @selector(getValidDays);
  methods[5].selector = @selector(getTime);
  methods[6].selector = @selector(getKey);
  methods[7].selector = @selector(getEncodedContents);
  methods[8].selector = @selector(encodeWithLibOrgBouncycastleBcpgBCPGOutputStream:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "version__", "I", .constantValue.asLong = 0, 0x2, 5, -1, -1, -1 },
    { "time_", "J", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "validDays_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "algorithm_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "key_", "LLibOrgBouncycastleBcpgBCPGKey;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleBcpgBCPGInputStream;", "LJavaIoIOException;", "ILJavaUtilDate;LLibOrgBouncycastleBcpgBCPGKey;", "encode", "LLibOrgBouncycastleBcpgBCPGOutputStream;", "version" };
  static const J2ObjcClassInfo _LibOrgBouncycastleBcpgPublicKeyPacket = { "PublicKeyPacket", "lib.org.bouncycastle.bcpg", ptrTable, methods, fields, 7, 0x1, 9, 5, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleBcpgPublicKeyPacket;
}

@end

void LibOrgBouncycastleBcpgPublicKeyPacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgPublicKeyPacket *self, LibOrgBouncycastleBcpgBCPGInputStream *inArg) {
  LibOrgBouncycastleBcpgContainedPacket_init(self);
  self->version__ = [((LibOrgBouncycastleBcpgBCPGInputStream *) nil_chk(inArg)) read];
  self->time_ = (JreLShift64((jlong) [inArg read], 24)) | (JreLShift32([inArg read], 16)) | (JreLShift32([inArg read], 8)) | [inArg read];
  if (self->version__ <= 3) {
    self->validDays_ = (JreLShift32([inArg read], 8)) | [inArg read];
  }
  self->algorithm_ = (jbyte) [inArg read];
  switch (self->algorithm_) {
    case LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_RSA_ENCRYPT:
    case LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_RSA_GENERAL:
    case LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_RSA_SIGN:
    self->key_ = new_LibOrgBouncycastleBcpgRSAPublicBCPGKey_initWithLibOrgBouncycastleBcpgBCPGInputStream_(inArg);
    break;
    case LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_DSA:
    self->key_ = new_LibOrgBouncycastleBcpgDSAPublicBCPGKey_initWithLibOrgBouncycastleBcpgBCPGInputStream_(inArg);
    break;
    case LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_ELGAMAL_ENCRYPT:
    case LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_ELGAMAL_GENERAL:
    self->key_ = new_LibOrgBouncycastleBcpgElGamalPublicBCPGKey_initWithLibOrgBouncycastleBcpgBCPGInputStream_(inArg);
    break;
    case LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_ECDH:
    self->key_ = new_LibOrgBouncycastleBcpgECDHPublicBCPGKey_initWithLibOrgBouncycastleBcpgBCPGInputStream_(inArg);
    break;
    case LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_ECDSA:
    self->key_ = new_LibOrgBouncycastleBcpgECDSAPublicBCPGKey_initWithLibOrgBouncycastleBcpgBCPGInputStream_(inArg);
    break;
    case LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_EDDSA:
    self->key_ = new_LibOrgBouncycastleBcpgEdDSAPublicBCPGKey_initWithLibOrgBouncycastleBcpgBCPGInputStream_(inArg);
    break;
    default:
    @throw new_JavaIoIOException_initWithNSString_(JreStrcat("$I", @"unknown PGP public key algorithm encountered: ", self->algorithm_));
  }
}

LibOrgBouncycastleBcpgPublicKeyPacket *new_LibOrgBouncycastleBcpgPublicKeyPacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgBCPGInputStream *inArg) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleBcpgPublicKeyPacket, initWithLibOrgBouncycastleBcpgBCPGInputStream_, inArg)
}

LibOrgBouncycastleBcpgPublicKeyPacket *create_LibOrgBouncycastleBcpgPublicKeyPacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgBCPGInputStream *inArg) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleBcpgPublicKeyPacket, initWithLibOrgBouncycastleBcpgBCPGInputStream_, inArg)
}

void LibOrgBouncycastleBcpgPublicKeyPacket_initWithInt_withJavaUtilDate_withLibOrgBouncycastleBcpgBCPGKey_(LibOrgBouncycastleBcpgPublicKeyPacket *self, jint algorithm, JavaUtilDate *time, id<LibOrgBouncycastleBcpgBCPGKey> key) {
  LibOrgBouncycastleBcpgContainedPacket_init(self);
  self->version__ = 4;
  self->time_ = [((JavaUtilDate *) nil_chk(time)) getTime] / 1000;
  self->algorithm_ = algorithm;
  self->key_ = key;
}

LibOrgBouncycastleBcpgPublicKeyPacket *new_LibOrgBouncycastleBcpgPublicKeyPacket_initWithInt_withJavaUtilDate_withLibOrgBouncycastleBcpgBCPGKey_(jint algorithm, JavaUtilDate *time, id<LibOrgBouncycastleBcpgBCPGKey> key) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleBcpgPublicKeyPacket, initWithInt_withJavaUtilDate_withLibOrgBouncycastleBcpgBCPGKey_, algorithm, time, key)
}

LibOrgBouncycastleBcpgPublicKeyPacket *create_LibOrgBouncycastleBcpgPublicKeyPacket_initWithInt_withJavaUtilDate_withLibOrgBouncycastleBcpgBCPGKey_(jint algorithm, JavaUtilDate *time, id<LibOrgBouncycastleBcpgBCPGKey> key) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleBcpgPublicKeyPacket, initWithInt_withJavaUtilDate_withLibOrgBouncycastleBcpgBCPGKey_, algorithm, time, key)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleBcpgPublicKeyPacket)
