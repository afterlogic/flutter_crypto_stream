//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/bcpg/SecretKeyPacket.java
//

#include "BCPGInputStream.h"
#include "BCPGOutputStream.h"
#include "ContainedPacket.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "PacketTags.h"
#include "PublicKeyPacket.h"
#include "PublicSubkeyPacket.h"
#include "S2K.h"
#include "SecretKeyPacket.h"
#include "SecretSubkeyPacket.h"
#include "SymmetricKeyAlgorithmTags.h"
#include "java/io/ByteArrayOutputStream.h"

@interface LibOrgBouncycastleBcpgSecretKeyPacket () {
 @public
  LibOrgBouncycastleBcpgPublicKeyPacket *pubKeyPacket_;
  IOSByteArray *secKeyData_;
  jint s2kUsage_;
  jint encAlgorithm_;
  LibOrgBouncycastleBcpgS2K *s2k_;
  IOSByteArray *iv_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleBcpgSecretKeyPacket, pubKeyPacket_, LibOrgBouncycastleBcpgPublicKeyPacket *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleBcpgSecretKeyPacket, secKeyData_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleBcpgSecretKeyPacket, s2k_, LibOrgBouncycastleBcpgS2K *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleBcpgSecretKeyPacket, iv_, IOSByteArray *)

@implementation LibOrgBouncycastleBcpgSecretKeyPacket

+ (jint)USAGE_NONE {
  return LibOrgBouncycastleBcpgSecretKeyPacket_USAGE_NONE;
}

+ (jint)USAGE_CHECKSUM {
  return LibOrgBouncycastleBcpgSecretKeyPacket_USAGE_CHECKSUM;
}

+ (jint)USAGE_SHA1 {
  return LibOrgBouncycastleBcpgSecretKeyPacket_USAGE_SHA1;
}

- (instancetype)initWithLibOrgBouncycastleBcpgBCPGInputStream:(LibOrgBouncycastleBcpgBCPGInputStream *)inArg {
  LibOrgBouncycastleBcpgSecretKeyPacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(self, inArg);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleBcpgPublicKeyPacket:(LibOrgBouncycastleBcpgPublicKeyPacket *)pubKeyPacket
                                                      withInt:(jint)encAlgorithm
                                withLibOrgBouncycastleBcpgS2K:(LibOrgBouncycastleBcpgS2K *)s2k
                                                withByteArray:(IOSByteArray *)iv
                                                withByteArray:(IOSByteArray *)secKeyData {
  LibOrgBouncycastleBcpgSecretKeyPacket_initWithLibOrgBouncycastleBcpgPublicKeyPacket_withInt_withLibOrgBouncycastleBcpgS2K_withByteArray_withByteArray_(self, pubKeyPacket, encAlgorithm, s2k, iv, secKeyData);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleBcpgPublicKeyPacket:(LibOrgBouncycastleBcpgPublicKeyPacket *)pubKeyPacket
                                                      withInt:(jint)encAlgorithm
                                                      withInt:(jint)s2kUsage
                                withLibOrgBouncycastleBcpgS2K:(LibOrgBouncycastleBcpgS2K *)s2k
                                                withByteArray:(IOSByteArray *)iv
                                                withByteArray:(IOSByteArray *)secKeyData {
  LibOrgBouncycastleBcpgSecretKeyPacket_initWithLibOrgBouncycastleBcpgPublicKeyPacket_withInt_withInt_withLibOrgBouncycastleBcpgS2K_withByteArray_withByteArray_(self, pubKeyPacket, encAlgorithm, s2kUsage, s2k, iv, secKeyData);
  return self;
}

- (jint)getEncAlgorithm {
  return encAlgorithm_;
}

- (jint)getS2KUsage {
  return s2kUsage_;
}

- (IOSByteArray *)getIV {
  return iv_;
}

- (LibOrgBouncycastleBcpgS2K *)getS2K {
  return s2k_;
}

- (LibOrgBouncycastleBcpgPublicKeyPacket *)getPublicKeyPacket {
  return pubKeyPacket_;
}

- (IOSByteArray *)getSecretKeyData {
  return secKeyData_;
}

- (IOSByteArray *)getEncodedContents {
  JavaIoByteArrayOutputStream *bOut = new_JavaIoByteArrayOutputStream_init();
  LibOrgBouncycastleBcpgBCPGOutputStream *pOut = new_LibOrgBouncycastleBcpgBCPGOutputStream_initWithJavaIoOutputStream_(bOut);
  [pOut writeWithByteArray:[((LibOrgBouncycastleBcpgPublicKeyPacket *) nil_chk(pubKeyPacket_)) getEncodedContents]];
  [pOut writeWithInt:s2kUsage_];
  if (s2kUsage_ == LibOrgBouncycastleBcpgSecretKeyPacket_USAGE_CHECKSUM || s2kUsage_ == LibOrgBouncycastleBcpgSecretKeyPacket_USAGE_SHA1) {
    [pOut writeWithInt:encAlgorithm_];
    [pOut writeObjectWithLibOrgBouncycastleBcpgBCPGObject:s2k_];
  }
  if (iv_ != nil) {
    [pOut writeWithByteArray:iv_];
  }
  if (secKeyData_ != nil && secKeyData_->size_ > 0) {
    [pOut writeWithByteArray:secKeyData_];
  }
  [pOut close];
  return [bOut toByteArray];
}

- (void)encodeWithLibOrgBouncycastleBcpgBCPGOutputStream:(LibOrgBouncycastleBcpgBCPGOutputStream *)outArg {
  [((LibOrgBouncycastleBcpgBCPGOutputStream *) nil_chk(outArg)) writePacketWithInt:LibOrgBouncycastleBcpgPacketTags_SECRET_KEY withByteArray:[self getEncodedContents] withBoolean:true];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, 0, 1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleBcpgS2K;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleBcpgPublicKeyPacket;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, 1, -1, -1, -1 },
    { NULL, "V", 0x1, 4, 5, 1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleBcpgBCPGInputStream:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleBcpgPublicKeyPacket:withInt:withLibOrgBouncycastleBcpgS2K:withByteArray:withByteArray:);
  methods[2].selector = @selector(initWithLibOrgBouncycastleBcpgPublicKeyPacket:withInt:withInt:withLibOrgBouncycastleBcpgS2K:withByteArray:withByteArray:);
  methods[3].selector = @selector(getEncAlgorithm);
  methods[4].selector = @selector(getS2KUsage);
  methods[5].selector = @selector(getIV);
  methods[6].selector = @selector(getS2K);
  methods[7].selector = @selector(getPublicKeyPacket);
  methods[8].selector = @selector(getSecretKeyData);
  methods[9].selector = @selector(getEncodedContents);
  methods[10].selector = @selector(encodeWithLibOrgBouncycastleBcpgBCPGOutputStream:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "USAGE_NONE", "I", .constantValue.asInt = LibOrgBouncycastleBcpgSecretKeyPacket_USAGE_NONE, 0x19, -1, -1, -1, -1 },
    { "USAGE_CHECKSUM", "I", .constantValue.asInt = LibOrgBouncycastleBcpgSecretKeyPacket_USAGE_CHECKSUM, 0x19, -1, -1, -1, -1 },
    { "USAGE_SHA1", "I", .constantValue.asInt = LibOrgBouncycastleBcpgSecretKeyPacket_USAGE_SHA1, 0x19, -1, -1, -1, -1 },
    { "pubKeyPacket_", "LLibOrgBouncycastleBcpgPublicKeyPacket;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "secKeyData_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "s2kUsage_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "encAlgorithm_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "s2k_", "LLibOrgBouncycastleBcpgS2K;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "iv_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleBcpgBCPGInputStream;", "LJavaIoIOException;", "LLibOrgBouncycastleBcpgPublicKeyPacket;ILLibOrgBouncycastleBcpgS2K;[B[B", "LLibOrgBouncycastleBcpgPublicKeyPacket;IILLibOrgBouncycastleBcpgS2K;[B[B", "encode", "LLibOrgBouncycastleBcpgBCPGOutputStream;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleBcpgSecretKeyPacket = { "SecretKeyPacket", "lib.org.bouncycastle.bcpg", ptrTable, methods, fields, 7, 0x1, 11, 9, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleBcpgSecretKeyPacket;
}

@end

void LibOrgBouncycastleBcpgSecretKeyPacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgSecretKeyPacket *self, LibOrgBouncycastleBcpgBCPGInputStream *inArg) {
  LibOrgBouncycastleBcpgContainedPacket_init(self);
  if ([self isKindOfClass:[LibOrgBouncycastleBcpgSecretSubkeyPacket class]]) {
    self->pubKeyPacket_ = new_LibOrgBouncycastleBcpgPublicSubkeyPacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(inArg);
  }
  else {
    self->pubKeyPacket_ = new_LibOrgBouncycastleBcpgPublicKeyPacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(inArg);
  }
  self->s2kUsage_ = [((LibOrgBouncycastleBcpgBCPGInputStream *) nil_chk(inArg)) read];
  if (self->s2kUsage_ == LibOrgBouncycastleBcpgSecretKeyPacket_USAGE_CHECKSUM || self->s2kUsage_ == LibOrgBouncycastleBcpgSecretKeyPacket_USAGE_SHA1) {
    self->encAlgorithm_ = [inArg read];
    self->s2k_ = new_LibOrgBouncycastleBcpgS2K_initWithJavaIoInputStream_(inArg);
  }
  else {
    self->encAlgorithm_ = self->s2kUsage_;
  }
  if (!(self->s2k_ != nil && [self->s2k_ getType] == LibOrgBouncycastleBcpgS2K_GNU_DUMMY_S2K && [((LibOrgBouncycastleBcpgS2K *) nil_chk(self->s2k_)) getProtectionMode] == (jint) 0x01)) {
    if (self->s2kUsage_ != 0) {
      if (self->encAlgorithm_ < 7) {
        self->iv_ = [IOSByteArray newArrayWithLength:8];
      }
      else {
        self->iv_ = [IOSByteArray newArrayWithLength:16];
      }
      [inArg readFullyWithByteArray:self->iv_ withInt:0 withInt:self->iv_->size_];
    }
  }
  self->secKeyData_ = [inArg readAll];
}

LibOrgBouncycastleBcpgSecretKeyPacket *new_LibOrgBouncycastleBcpgSecretKeyPacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgBCPGInputStream *inArg) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleBcpgSecretKeyPacket, initWithLibOrgBouncycastleBcpgBCPGInputStream_, inArg)
}

LibOrgBouncycastleBcpgSecretKeyPacket *create_LibOrgBouncycastleBcpgSecretKeyPacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgBCPGInputStream *inArg) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleBcpgSecretKeyPacket, initWithLibOrgBouncycastleBcpgBCPGInputStream_, inArg)
}

void LibOrgBouncycastleBcpgSecretKeyPacket_initWithLibOrgBouncycastleBcpgPublicKeyPacket_withInt_withLibOrgBouncycastleBcpgS2K_withByteArray_withByteArray_(LibOrgBouncycastleBcpgSecretKeyPacket *self, LibOrgBouncycastleBcpgPublicKeyPacket *pubKeyPacket, jint encAlgorithm, LibOrgBouncycastleBcpgS2K *s2k, IOSByteArray *iv, IOSByteArray *secKeyData) {
  LibOrgBouncycastleBcpgContainedPacket_init(self);
  self->pubKeyPacket_ = pubKeyPacket;
  self->encAlgorithm_ = encAlgorithm;
  if (encAlgorithm != LibOrgBouncycastleBcpgSymmetricKeyAlgorithmTags_NULL) {
    self->s2kUsage_ = LibOrgBouncycastleBcpgSecretKeyPacket_USAGE_CHECKSUM;
  }
  else {
    self->s2kUsage_ = LibOrgBouncycastleBcpgSecretKeyPacket_USAGE_NONE;
  }
  self->s2k_ = s2k;
  self->iv_ = iv;
  self->secKeyData_ = secKeyData;
}

LibOrgBouncycastleBcpgSecretKeyPacket *new_LibOrgBouncycastleBcpgSecretKeyPacket_initWithLibOrgBouncycastleBcpgPublicKeyPacket_withInt_withLibOrgBouncycastleBcpgS2K_withByteArray_withByteArray_(LibOrgBouncycastleBcpgPublicKeyPacket *pubKeyPacket, jint encAlgorithm, LibOrgBouncycastleBcpgS2K *s2k, IOSByteArray *iv, IOSByteArray *secKeyData) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleBcpgSecretKeyPacket, initWithLibOrgBouncycastleBcpgPublicKeyPacket_withInt_withLibOrgBouncycastleBcpgS2K_withByteArray_withByteArray_, pubKeyPacket, encAlgorithm, s2k, iv, secKeyData)
}

LibOrgBouncycastleBcpgSecretKeyPacket *create_LibOrgBouncycastleBcpgSecretKeyPacket_initWithLibOrgBouncycastleBcpgPublicKeyPacket_withInt_withLibOrgBouncycastleBcpgS2K_withByteArray_withByteArray_(LibOrgBouncycastleBcpgPublicKeyPacket *pubKeyPacket, jint encAlgorithm, LibOrgBouncycastleBcpgS2K *s2k, IOSByteArray *iv, IOSByteArray *secKeyData) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleBcpgSecretKeyPacket, initWithLibOrgBouncycastleBcpgPublicKeyPacket_withInt_withLibOrgBouncycastleBcpgS2K_withByteArray_withByteArray_, pubKeyPacket, encAlgorithm, s2k, iv, secKeyData)
}

void LibOrgBouncycastleBcpgSecretKeyPacket_initWithLibOrgBouncycastleBcpgPublicKeyPacket_withInt_withInt_withLibOrgBouncycastleBcpgS2K_withByteArray_withByteArray_(LibOrgBouncycastleBcpgSecretKeyPacket *self, LibOrgBouncycastleBcpgPublicKeyPacket *pubKeyPacket, jint encAlgorithm, jint s2kUsage, LibOrgBouncycastleBcpgS2K *s2k, IOSByteArray *iv, IOSByteArray *secKeyData) {
  LibOrgBouncycastleBcpgContainedPacket_init(self);
  self->pubKeyPacket_ = pubKeyPacket;
  self->encAlgorithm_ = encAlgorithm;
  self->s2kUsage_ = s2kUsage;
  self->s2k_ = s2k;
  self->iv_ = iv;
  self->secKeyData_ = secKeyData;
}

LibOrgBouncycastleBcpgSecretKeyPacket *new_LibOrgBouncycastleBcpgSecretKeyPacket_initWithLibOrgBouncycastleBcpgPublicKeyPacket_withInt_withInt_withLibOrgBouncycastleBcpgS2K_withByteArray_withByteArray_(LibOrgBouncycastleBcpgPublicKeyPacket *pubKeyPacket, jint encAlgorithm, jint s2kUsage, LibOrgBouncycastleBcpgS2K *s2k, IOSByteArray *iv, IOSByteArray *secKeyData) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleBcpgSecretKeyPacket, initWithLibOrgBouncycastleBcpgPublicKeyPacket_withInt_withInt_withLibOrgBouncycastleBcpgS2K_withByteArray_withByteArray_, pubKeyPacket, encAlgorithm, s2kUsage, s2k, iv, secKeyData)
}

LibOrgBouncycastleBcpgSecretKeyPacket *create_LibOrgBouncycastleBcpgSecretKeyPacket_initWithLibOrgBouncycastleBcpgPublicKeyPacket_withInt_withInt_withLibOrgBouncycastleBcpgS2K_withByteArray_withByteArray_(LibOrgBouncycastleBcpgPublicKeyPacket *pubKeyPacket, jint encAlgorithm, jint s2kUsage, LibOrgBouncycastleBcpgS2K *s2k, IOSByteArray *iv, IOSByteArray *secKeyData) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleBcpgSecretKeyPacket, initWithLibOrgBouncycastleBcpgPublicKeyPacket_withInt_withInt_withLibOrgBouncycastleBcpgS2K_withByteArray_withByteArray_, pubKeyPacket, encAlgorithm, s2kUsage, s2k, iv, secKeyData)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleBcpgSecretKeyPacket)