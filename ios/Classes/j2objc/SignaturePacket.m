//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/bcpg/SignaturePacket.java
//

#include "Arrays.h"
#include "BCPGInputStream.h"
#include "BCPGOutputStream.h"
#include "ContainedPacket.h"
#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "IOSPrimitiveArray.h"
#include "IssuerKeyID.h"
#include "J2ObjC_source.h"
#include "MPInteger.h"
#include "PacketTags.h"
#include "PublicKeyAlgorithmTags.h"
#include "SignatureCreationTime.h"
#include "SignaturePacket.h"
#include "SignatureSubpacket.h"
#include "SignatureSubpacketInputStream.h"
#include "java/io/ByteArrayInputStream.h"
#include "java/io/ByteArrayOutputStream.h"
#include "java/io/IOException.h"
#include "java/lang/RuntimeException.h"
#include "java/util/Date.h"
#include "java/util/Vector.h"

@interface LibOrgBouncycastleBcpgSignaturePacket () {
 @public
  jint version__;
  jint signatureType_;
  jlong creationTime_;
  jlong keyID_;
  jint keyAlgorithm_;
  jint hashAlgorithm_;
  IOSObjectArray *signature_;
  IOSByteArray *fingerPrint_;
  IOSObjectArray *hashedData_;
  IOSObjectArray *unhashedData_;
  IOSByteArray *signatureEncoding_;
}

- (void)setCreationTime;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleBcpgSignaturePacket, signature_, IOSObjectArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleBcpgSignaturePacket, fingerPrint_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleBcpgSignaturePacket, hashedData_, IOSObjectArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleBcpgSignaturePacket, unhashedData_, IOSObjectArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleBcpgSignaturePacket, signatureEncoding_, IOSByteArray *)

__attribute__((unused)) static void LibOrgBouncycastleBcpgSignaturePacket_setCreationTime(LibOrgBouncycastleBcpgSignaturePacket *self);

@implementation LibOrgBouncycastleBcpgSignaturePacket

- (instancetype)initWithLibOrgBouncycastleBcpgBCPGInputStream:(LibOrgBouncycastleBcpgBCPGInputStream *)inArg {
  LibOrgBouncycastleBcpgSignaturePacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(self, inArg);
  return self;
}

- (instancetype)initWithInt:(jint)signatureType
                   withLong:(jlong)keyID
                    withInt:(jint)keyAlgorithm
                    withInt:(jint)hashAlgorithm
withLibOrgBouncycastleBcpgSignatureSubpacketArray:(IOSObjectArray *)hashedData
withLibOrgBouncycastleBcpgSignatureSubpacketArray:(IOSObjectArray *)unhashedData
              withByteArray:(IOSByteArray *)fingerPrint
withLibOrgBouncycastleBcpgMPIntegerArray:(IOSObjectArray *)signature {
  LibOrgBouncycastleBcpgSignaturePacket_initWithInt_withLong_withInt_withInt_withLibOrgBouncycastleBcpgSignatureSubpacketArray_withLibOrgBouncycastleBcpgSignatureSubpacketArray_withByteArray_withLibOrgBouncycastleBcpgMPIntegerArray_(self, signatureType, keyID, keyAlgorithm, hashAlgorithm, hashedData, unhashedData, fingerPrint, signature);
  return self;
}

- (instancetype)initWithInt:(jint)version_
                    withInt:(jint)signatureType
                   withLong:(jlong)keyID
                    withInt:(jint)keyAlgorithm
                    withInt:(jint)hashAlgorithm
                   withLong:(jlong)creationTime
              withByteArray:(IOSByteArray *)fingerPrint
withLibOrgBouncycastleBcpgMPIntegerArray:(IOSObjectArray *)signature {
  LibOrgBouncycastleBcpgSignaturePacket_initWithInt_withInt_withLong_withInt_withInt_withLong_withByteArray_withLibOrgBouncycastleBcpgMPIntegerArray_(self, version_, signatureType, keyID, keyAlgorithm, hashAlgorithm, creationTime, fingerPrint, signature);
  return self;
}

- (instancetype)initWithInt:(jint)version_
                    withInt:(jint)signatureType
                   withLong:(jlong)keyID
                    withInt:(jint)keyAlgorithm
                    withInt:(jint)hashAlgorithm
withLibOrgBouncycastleBcpgSignatureSubpacketArray:(IOSObjectArray *)hashedData
withLibOrgBouncycastleBcpgSignatureSubpacketArray:(IOSObjectArray *)unhashedData
              withByteArray:(IOSByteArray *)fingerPrint
withLibOrgBouncycastleBcpgMPIntegerArray:(IOSObjectArray *)signature {
  LibOrgBouncycastleBcpgSignaturePacket_initWithInt_withInt_withLong_withInt_withInt_withLibOrgBouncycastleBcpgSignatureSubpacketArray_withLibOrgBouncycastleBcpgSignatureSubpacketArray_withByteArray_withLibOrgBouncycastleBcpgMPIntegerArray_(self, version_, signatureType, keyID, keyAlgorithm, hashAlgorithm, hashedData, unhashedData, fingerPrint, signature);
  return self;
}

- (jint)getVersion {
  return version__;
}

- (jint)getSignatureType {
  return signatureType_;
}

- (jlong)getKeyID {
  return keyID_;
}

- (IOSByteArray *)getSignatureTrailer {
  IOSByteArray *trailer = nil;
  if (version__ == 3 || version__ == 2) {
    trailer = [IOSByteArray newArrayWithLength:5];
    jlong time = creationTime_ / 1000;
    *IOSByteArray_GetRef(trailer, 0) = (jbyte) signatureType_;
    *IOSByteArray_GetRef(trailer, 1) = (jbyte) (JreRShift64(time, 24));
    *IOSByteArray_GetRef(trailer, 2) = (jbyte) (JreRShift64(time, 16));
    *IOSByteArray_GetRef(trailer, 3) = (jbyte) (JreRShift64(time, 8));
    *IOSByteArray_GetRef(trailer, 4) = (jbyte) (time);
  }
  else {
    JavaIoByteArrayOutputStream *sOut = new_JavaIoByteArrayOutputStream_init();
    @try {
      [sOut writeWithInt:(jbyte) [self getVersion]];
      [sOut writeWithInt:(jbyte) [self getSignatureType]];
      [sOut writeWithInt:(jbyte) [self getKeyAlgorithm]];
      [sOut writeWithInt:(jbyte) [self getHashAlgorithm]];
      JavaIoByteArrayOutputStream *hOut = new_JavaIoByteArrayOutputStream_init();
      IOSObjectArray *hashed = [self getHashedSubPackets];
      for (jint i = 0; i != ((IOSObjectArray *) nil_chk(hashed))->size_; i++) {
        [((LibOrgBouncycastleBcpgSignatureSubpacket *) nil_chk(IOSObjectArray_Get(hashed, i))) encodeWithJavaIoOutputStream:hOut];
      }
      IOSByteArray *data = [hOut toByteArray];
      [sOut writeWithInt:(jbyte) (JreRShift32(((IOSByteArray *) nil_chk(data))->size_, 8))];
      [sOut writeWithInt:(jbyte) data->size_];
      [sOut writeWithByteArray:data];
      IOSByteArray *hData = [sOut toByteArray];
      [sOut writeWithInt:(jbyte) [self getVersion]];
      [sOut writeWithInt:(jbyte) (jint) 0xff];
      [sOut writeWithInt:(jbyte) (JreRShift32(((IOSByteArray *) nil_chk(hData))->size_, 24))];
      [sOut writeWithInt:(jbyte) (JreRShift32(hData->size_, 16))];
      [sOut writeWithInt:(jbyte) (JreRShift32(hData->size_, 8))];
      [sOut writeWithInt:(jbyte) (hData->size_)];
    }
    @catch (JavaIoIOException *e) {
      @throw new_JavaLangRuntimeException_initWithNSString_(JreStrcat("$@", @"exception generating trailer: ", e));
    }
    trailer = [sOut toByteArray];
  }
  return trailer;
}

- (jint)getKeyAlgorithm {
  return keyAlgorithm_;
}

- (jint)getHashAlgorithm {
  return hashAlgorithm_;
}

- (IOSObjectArray *)getSignature {
  return signature_;
}

- (IOSByteArray *)getSignatureBytes {
  if (signatureEncoding_ == nil) {
    JavaIoByteArrayOutputStream *bOut = new_JavaIoByteArrayOutputStream_init();
    LibOrgBouncycastleBcpgBCPGOutputStream *bcOut = new_LibOrgBouncycastleBcpgBCPGOutputStream_initWithJavaIoOutputStream_(bOut);
    for (jint i = 0; i != ((IOSObjectArray *) nil_chk(signature_))->size_; i++) {
      @try {
        [bcOut writeObjectWithLibOrgBouncycastleBcpgBCPGObject:IOSObjectArray_Get(signature_, i)];
      }
      @catch (JavaIoIOException *e) {
        @throw new_JavaLangRuntimeException_initWithNSString_(JreStrcat("$@", @"internal error: ", e));
      }
    }
    return [bOut toByteArray];
  }
  else {
    return LibOrgBouncycastleUtilArrays_cloneWithByteArray_(signatureEncoding_);
  }
}

- (IOSObjectArray *)getHashedSubPackets {
  return hashedData_;
}

- (IOSObjectArray *)getUnhashedSubPackets {
  return unhashedData_;
}

- (jlong)getCreationTime {
  return creationTime_;
}

- (void)encodeWithLibOrgBouncycastleBcpgBCPGOutputStream:(LibOrgBouncycastleBcpgBCPGOutputStream *)outArg {
  JavaIoByteArrayOutputStream *bOut = new_JavaIoByteArrayOutputStream_init();
  LibOrgBouncycastleBcpgBCPGOutputStream *pOut = new_LibOrgBouncycastleBcpgBCPGOutputStream_initWithJavaIoOutputStream_(bOut);
  [pOut writeWithInt:version__];
  if (version__ == 3 || version__ == 2) {
    [pOut writeWithInt:5];
    jlong time = creationTime_ / 1000;
    [pOut writeWithInt:signatureType_];
    [pOut writeWithInt:(jbyte) (JreRShift64(time, 24))];
    [pOut writeWithInt:(jbyte) (JreRShift64(time, 16))];
    [pOut writeWithInt:(jbyte) (JreRShift64(time, 8))];
    [pOut writeWithInt:(jbyte) time];
    [pOut writeWithInt:(jbyte) (JreRShift64(keyID_, 56))];
    [pOut writeWithInt:(jbyte) (JreRShift64(keyID_, 48))];
    [pOut writeWithInt:(jbyte) (JreRShift64(keyID_, 40))];
    [pOut writeWithInt:(jbyte) (JreRShift64(keyID_, 32))];
    [pOut writeWithInt:(jbyte) (JreRShift64(keyID_, 24))];
    [pOut writeWithInt:(jbyte) (JreRShift64(keyID_, 16))];
    [pOut writeWithInt:(jbyte) (JreRShift64(keyID_, 8))];
    [pOut writeWithInt:(jbyte) (keyID_)];
    [pOut writeWithInt:keyAlgorithm_];
    [pOut writeWithInt:hashAlgorithm_];
  }
  else if (version__ == 4) {
    [pOut writeWithInt:signatureType_];
    [pOut writeWithInt:keyAlgorithm_];
    [pOut writeWithInt:hashAlgorithm_];
    JavaIoByteArrayOutputStream *sOut = new_JavaIoByteArrayOutputStream_init();
    for (jint i = 0; i != ((IOSObjectArray *) nil_chk(hashedData_))->size_; i++) {
      [((LibOrgBouncycastleBcpgSignatureSubpacket *) nil_chk(IOSObjectArray_Get(hashedData_, i))) encodeWithJavaIoOutputStream:sOut];
    }
    IOSByteArray *data = [sOut toByteArray];
    [pOut writeWithInt:JreRShift32(((IOSByteArray *) nil_chk(data))->size_, 8)];
    [pOut writeWithInt:data->size_];
    [pOut writeWithByteArray:data];
    [sOut reset];
    for (jint i = 0; i != ((IOSObjectArray *) nil_chk(unhashedData_))->size_; i++) {
      [((LibOrgBouncycastleBcpgSignatureSubpacket *) nil_chk(IOSObjectArray_Get(unhashedData_, i))) encodeWithJavaIoOutputStream:sOut];
    }
    data = [sOut toByteArray];
    [pOut writeWithInt:JreRShift32(((IOSByteArray *) nil_chk(data))->size_, 8)];
    [pOut writeWithInt:data->size_];
    [pOut writeWithByteArray:data];
  }
  else {
    @throw new_JavaIoIOException_initWithNSString_(JreStrcat("$I", @"unknown version: ", version__));
  }
  [pOut writeWithByteArray:fingerPrint_];
  if (signature_ != nil) {
    for (jint i = 0; i != ((IOSObjectArray *) nil_chk(signature_))->size_; i++) {
      [pOut writeObjectWithLibOrgBouncycastleBcpgBCPGObject:IOSObjectArray_Get(signature_, i)];
    }
  }
  else {
    [pOut writeWithByteArray:signatureEncoding_];
  }
  [pOut close];
  [((LibOrgBouncycastleBcpgBCPGOutputStream *) nil_chk(outArg)) writePacketWithInt:LibOrgBouncycastleBcpgPacketTags_SIGNATURE withByteArray:[bOut toByteArray] withBoolean:true];
}

- (void)setCreationTime {
  LibOrgBouncycastleBcpgSignaturePacket_setCreationTime(self);
}

+ (LibOrgBouncycastleBcpgSignaturePacket *)fromByteArrayWithByteArray:(IOSByteArray *)data {
  return LibOrgBouncycastleBcpgSignaturePacket_fromByteArrayWithByteArray_(data);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, 0, 1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "J", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[LLibOrgBouncycastleBcpgMPInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[LLibOrgBouncycastleBcpgSignatureSubpacket;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[LLibOrgBouncycastleBcpgSignatureSubpacket;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "J", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 5, 6, 1, -1, -1, -1 },
    { NULL, "V", 0x2, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleBcpgSignaturePacket;", 0x9, 7, 8, 1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleBcpgBCPGInputStream:);
  methods[1].selector = @selector(initWithInt:withLong:withInt:withInt:withLibOrgBouncycastleBcpgSignatureSubpacketArray:withLibOrgBouncycastleBcpgSignatureSubpacketArray:withByteArray:withLibOrgBouncycastleBcpgMPIntegerArray:);
  methods[2].selector = @selector(initWithInt:withInt:withLong:withInt:withInt:withLong:withByteArray:withLibOrgBouncycastleBcpgMPIntegerArray:);
  methods[3].selector = @selector(initWithInt:withInt:withLong:withInt:withInt:withLibOrgBouncycastleBcpgSignatureSubpacketArray:withLibOrgBouncycastleBcpgSignatureSubpacketArray:withByteArray:withLibOrgBouncycastleBcpgMPIntegerArray:);
  methods[4].selector = @selector(getVersion);
  methods[5].selector = @selector(getSignatureType);
  methods[6].selector = @selector(getKeyID);
  methods[7].selector = @selector(getSignatureTrailer);
  methods[8].selector = @selector(getKeyAlgorithm);
  methods[9].selector = @selector(getHashAlgorithm);
  methods[10].selector = @selector(getSignature);
  methods[11].selector = @selector(getSignatureBytes);
  methods[12].selector = @selector(getHashedSubPackets);
  methods[13].selector = @selector(getUnhashedSubPackets);
  methods[14].selector = @selector(getCreationTime);
  methods[15].selector = @selector(encodeWithLibOrgBouncycastleBcpgBCPGOutputStream:);
  methods[16].selector = @selector(setCreationTime);
  methods[17].selector = @selector(fromByteArrayWithByteArray:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "version__", "I", .constantValue.asLong = 0, 0x2, 9, -1, -1, -1 },
    { "signatureType_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "creationTime_", "J", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "keyID_", "J", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "keyAlgorithm_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "hashAlgorithm_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "signature_", "[LLibOrgBouncycastleBcpgMPInteger;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "fingerPrint_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "hashedData_", "[LLibOrgBouncycastleBcpgSignatureSubpacket;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "unhashedData_", "[LLibOrgBouncycastleBcpgSignatureSubpacket;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "signatureEncoding_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleBcpgBCPGInputStream;", "LJavaIoIOException;", "IJII[LLibOrgBouncycastleBcpgSignatureSubpacket;[LLibOrgBouncycastleBcpgSignatureSubpacket;[B[LLibOrgBouncycastleBcpgMPInteger;", "IIJIIJ[B[LLibOrgBouncycastleBcpgMPInteger;", "IIJII[LLibOrgBouncycastleBcpgSignatureSubpacket;[LLibOrgBouncycastleBcpgSignatureSubpacket;[B[LLibOrgBouncycastleBcpgMPInteger;", "encode", "LLibOrgBouncycastleBcpgBCPGOutputStream;", "fromByteArray", "[B", "version" };
  static const J2ObjcClassInfo _LibOrgBouncycastleBcpgSignaturePacket = { "SignaturePacket", "lib.org.bouncycastle.bcpg", ptrTable, methods, fields, 7, 0x1, 18, 11, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleBcpgSignaturePacket;
}

@end

void LibOrgBouncycastleBcpgSignaturePacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgSignaturePacket *self, LibOrgBouncycastleBcpgBCPGInputStream *inArg) {
  LibOrgBouncycastleBcpgContainedPacket_init(self);
  self->version__ = [((LibOrgBouncycastleBcpgBCPGInputStream *) nil_chk(inArg)) read];
  if (self->version__ == 3 || self->version__ == 2) {
    jint l = [inArg read];
    self->signatureType_ = [inArg read];
    self->creationTime_ = ((JreLShift64((jlong) [inArg read], 24)) | (JreLShift32([inArg read], 16)) | (JreLShift32([inArg read], 8)) | [inArg read]) * 1000;
    self->keyID_ |= JreLShift64((jlong) [inArg read], 56);
    self->keyID_ |= JreLShift64((jlong) [inArg read], 48);
    self->keyID_ |= JreLShift64((jlong) [inArg read], 40);
    self->keyID_ |= JreLShift64((jlong) [inArg read], 32);
    self->keyID_ |= JreLShift64((jlong) [inArg read], 24);
    self->keyID_ |= JreLShift64((jlong) [inArg read], 16);
    self->keyID_ |= JreLShift64((jlong) [inArg read], 8);
    self->keyID_ |= [inArg read];
    self->keyAlgorithm_ = [inArg read];
    self->hashAlgorithm_ = [inArg read];
  }
  else if (self->version__ == 4) {
    self->signatureType_ = [inArg read];
    self->keyAlgorithm_ = [inArg read];
    self->hashAlgorithm_ = [inArg read];
    jint hashedLength = (JreLShift32([inArg read], 8)) | [inArg read];
    IOSByteArray *hashed = [IOSByteArray newArrayWithLength:hashedLength];
    [inArg readFullyWithByteArray:hashed];
    LibOrgBouncycastleBcpgSignatureSubpacket *sub;
    LibOrgBouncycastleBcpgSignatureSubpacketInputStream *sIn = new_LibOrgBouncycastleBcpgSignatureSubpacketInputStream_initWithJavaIoInputStream_(new_JavaIoByteArrayInputStream_initWithByteArray_(hashed));
    JavaUtilVector *v = new_JavaUtilVector_init();
    while ((sub = [sIn readPacket]) != nil) {
      [v addElementWithId:sub];
    }
    self->hashedData_ = [IOSObjectArray newArrayWithLength:[v size] type:LibOrgBouncycastleBcpgSignatureSubpacket_class_()];
    for (jint i = 0; i != self->hashedData_->size_; i++) {
      LibOrgBouncycastleBcpgSignatureSubpacket *p = (LibOrgBouncycastleBcpgSignatureSubpacket *) cast_chk([v elementAtWithInt:i], [LibOrgBouncycastleBcpgSignatureSubpacket class]);
      if ([p isKindOfClass:[LibOrgBouncycastleBcpgSigIssuerKeyID class]]) {
        self->keyID_ = [((LibOrgBouncycastleBcpgSigIssuerKeyID *) nil_chk(((LibOrgBouncycastleBcpgSigIssuerKeyID *) p))) getKeyID];
      }
      else if ([p isKindOfClass:[LibOrgBouncycastleBcpgSigSignatureCreationTime class]]) {
        self->creationTime_ = [((JavaUtilDate *) nil_chk([((LibOrgBouncycastleBcpgSigSignatureCreationTime *) nil_chk(((LibOrgBouncycastleBcpgSigSignatureCreationTime *) p))) getTime])) getTime];
      }
      (void) IOSObjectArray_Set(nil_chk(self->hashedData_), i, p);
    }
    jint unhashedLength = (JreLShift32([inArg read], 8)) | [inArg read];
    IOSByteArray *unhashed = [IOSByteArray newArrayWithLength:unhashedLength];
    [inArg readFullyWithByteArray:unhashed];
    sIn = new_LibOrgBouncycastleBcpgSignatureSubpacketInputStream_initWithJavaIoInputStream_(new_JavaIoByteArrayInputStream_initWithByteArray_(unhashed));
    [v removeAllElements];
    while ((sub = [sIn readPacket]) != nil) {
      [v addElementWithId:sub];
    }
    self->unhashedData_ = [IOSObjectArray newArrayWithLength:[v size] type:LibOrgBouncycastleBcpgSignatureSubpacket_class_()];
    for (jint i = 0; i != self->unhashedData_->size_; i++) {
      LibOrgBouncycastleBcpgSignatureSubpacket *p = (LibOrgBouncycastleBcpgSignatureSubpacket *) cast_chk([v elementAtWithInt:i], [LibOrgBouncycastleBcpgSignatureSubpacket class]);
      if ([p isKindOfClass:[LibOrgBouncycastleBcpgSigIssuerKeyID class]]) {
        self->keyID_ = [((LibOrgBouncycastleBcpgSigIssuerKeyID *) nil_chk(((LibOrgBouncycastleBcpgSigIssuerKeyID *) p))) getKeyID];
      }
      (void) IOSObjectArray_Set(nil_chk(self->unhashedData_), i, p);
    }
  }
  else {
    @throw new_JavaLangRuntimeException_initWithNSString_(JreStrcat("$I", @"unsupported version: ", self->version__));
  }
  self->fingerPrint_ = [IOSByteArray newArrayWithLength:2];
  [inArg readFullyWithByteArray:self->fingerPrint_];
  {
    LibOrgBouncycastleBcpgMPInteger *v;
    LibOrgBouncycastleBcpgMPInteger *r;
    LibOrgBouncycastleBcpgMPInteger *s;
    LibOrgBouncycastleBcpgMPInteger *p;
    LibOrgBouncycastleBcpgMPInteger *g;
    LibOrgBouncycastleBcpgMPInteger *y;
    LibOrgBouncycastleBcpgMPInteger *ecR;
    LibOrgBouncycastleBcpgMPInteger *ecS;
    LibOrgBouncycastleBcpgMPInteger *edR;
    LibOrgBouncycastleBcpgMPInteger *edS;
    switch (self->keyAlgorithm_) {
      case LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_RSA_GENERAL:
      case LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_RSA_SIGN:
      v = new_LibOrgBouncycastleBcpgMPInteger_initWithLibOrgBouncycastleBcpgBCPGInputStream_(inArg);
      self->signature_ = [IOSObjectArray newArrayWithLength:1 type:LibOrgBouncycastleBcpgMPInteger_class_()];
      (void) IOSObjectArray_Set(self->signature_, 0, v);
      break;
      case LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_DSA:
      r = new_LibOrgBouncycastleBcpgMPInteger_initWithLibOrgBouncycastleBcpgBCPGInputStream_(inArg);
      s = new_LibOrgBouncycastleBcpgMPInteger_initWithLibOrgBouncycastleBcpgBCPGInputStream_(inArg);
      self->signature_ = [IOSObjectArray newArrayWithLength:2 type:LibOrgBouncycastleBcpgMPInteger_class_()];
      (void) IOSObjectArray_Set(self->signature_, 0, r);
      (void) IOSObjectArray_Set(self->signature_, 1, s);
      break;
      case LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_ELGAMAL_ENCRYPT:
      case LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_ELGAMAL_GENERAL:
      p = new_LibOrgBouncycastleBcpgMPInteger_initWithLibOrgBouncycastleBcpgBCPGInputStream_(inArg);
      g = new_LibOrgBouncycastleBcpgMPInteger_initWithLibOrgBouncycastleBcpgBCPGInputStream_(inArg);
      y = new_LibOrgBouncycastleBcpgMPInteger_initWithLibOrgBouncycastleBcpgBCPGInputStream_(inArg);
      self->signature_ = [IOSObjectArray newArrayWithLength:3 type:LibOrgBouncycastleBcpgMPInteger_class_()];
      (void) IOSObjectArray_Set(self->signature_, 0, p);
      (void) IOSObjectArray_Set(self->signature_, 1, g);
      (void) IOSObjectArray_Set(self->signature_, 2, y);
      break;
      case LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_ECDSA:
      ecR = new_LibOrgBouncycastleBcpgMPInteger_initWithLibOrgBouncycastleBcpgBCPGInputStream_(inArg);
      ecS = new_LibOrgBouncycastleBcpgMPInteger_initWithLibOrgBouncycastleBcpgBCPGInputStream_(inArg);
      self->signature_ = [IOSObjectArray newArrayWithLength:2 type:LibOrgBouncycastleBcpgMPInteger_class_()];
      (void) IOSObjectArray_Set(self->signature_, 0, ecR);
      (void) IOSObjectArray_Set(self->signature_, 1, ecS);
      break;
      case LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_EDDSA:
      edR = new_LibOrgBouncycastleBcpgMPInteger_initWithLibOrgBouncycastleBcpgBCPGInputStream_(inArg);
      edS = new_LibOrgBouncycastleBcpgMPInteger_initWithLibOrgBouncycastleBcpgBCPGInputStream_(inArg);
      self->signature_ = [IOSObjectArray newArrayWithLength:2 type:LibOrgBouncycastleBcpgMPInteger_class_()];
      (void) IOSObjectArray_Set(self->signature_, 0, edR);
      (void) IOSObjectArray_Set(self->signature_, 1, edS);
      break;
      default:
      if (self->keyAlgorithm_ >= LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_EXPERIMENTAL_1 && self->keyAlgorithm_ <= LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_EXPERIMENTAL_11) {
        self->signature_ = nil;
        JavaIoByteArrayOutputStream *bOut = new_JavaIoByteArrayOutputStream_init();
        jint ch;
        while ((ch = [inArg read]) >= 0) {
          [bOut writeWithInt:ch];
        }
        self->signatureEncoding_ = [bOut toByteArray];
      }
      else {
        @throw new_JavaIoIOException_initWithNSString_(JreStrcat("$I", @"unknown signature key algorithm: ", self->keyAlgorithm_));
      }
    }
  }
}

LibOrgBouncycastleBcpgSignaturePacket *new_LibOrgBouncycastleBcpgSignaturePacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgBCPGInputStream *inArg) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleBcpgSignaturePacket, initWithLibOrgBouncycastleBcpgBCPGInputStream_, inArg)
}

LibOrgBouncycastleBcpgSignaturePacket *create_LibOrgBouncycastleBcpgSignaturePacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgBCPGInputStream *inArg) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleBcpgSignaturePacket, initWithLibOrgBouncycastleBcpgBCPGInputStream_, inArg)
}

void LibOrgBouncycastleBcpgSignaturePacket_initWithInt_withLong_withInt_withInt_withLibOrgBouncycastleBcpgSignatureSubpacketArray_withLibOrgBouncycastleBcpgSignatureSubpacketArray_withByteArray_withLibOrgBouncycastleBcpgMPIntegerArray_(LibOrgBouncycastleBcpgSignaturePacket *self, jint signatureType, jlong keyID, jint keyAlgorithm, jint hashAlgorithm, IOSObjectArray *hashedData, IOSObjectArray *unhashedData, IOSByteArray *fingerPrint, IOSObjectArray *signature) {
  LibOrgBouncycastleBcpgSignaturePacket_initWithInt_withInt_withLong_withInt_withInt_withLibOrgBouncycastleBcpgSignatureSubpacketArray_withLibOrgBouncycastleBcpgSignatureSubpacketArray_withByteArray_withLibOrgBouncycastleBcpgMPIntegerArray_(self, 4, signatureType, keyID, keyAlgorithm, hashAlgorithm, hashedData, unhashedData, fingerPrint, signature);
}

LibOrgBouncycastleBcpgSignaturePacket *new_LibOrgBouncycastleBcpgSignaturePacket_initWithInt_withLong_withInt_withInt_withLibOrgBouncycastleBcpgSignatureSubpacketArray_withLibOrgBouncycastleBcpgSignatureSubpacketArray_withByteArray_withLibOrgBouncycastleBcpgMPIntegerArray_(jint signatureType, jlong keyID, jint keyAlgorithm, jint hashAlgorithm, IOSObjectArray *hashedData, IOSObjectArray *unhashedData, IOSByteArray *fingerPrint, IOSObjectArray *signature) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleBcpgSignaturePacket, initWithInt_withLong_withInt_withInt_withLibOrgBouncycastleBcpgSignatureSubpacketArray_withLibOrgBouncycastleBcpgSignatureSubpacketArray_withByteArray_withLibOrgBouncycastleBcpgMPIntegerArray_, signatureType, keyID, keyAlgorithm, hashAlgorithm, hashedData, unhashedData, fingerPrint, signature)
}

LibOrgBouncycastleBcpgSignaturePacket *create_LibOrgBouncycastleBcpgSignaturePacket_initWithInt_withLong_withInt_withInt_withLibOrgBouncycastleBcpgSignatureSubpacketArray_withLibOrgBouncycastleBcpgSignatureSubpacketArray_withByteArray_withLibOrgBouncycastleBcpgMPIntegerArray_(jint signatureType, jlong keyID, jint keyAlgorithm, jint hashAlgorithm, IOSObjectArray *hashedData, IOSObjectArray *unhashedData, IOSByteArray *fingerPrint, IOSObjectArray *signature) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleBcpgSignaturePacket, initWithInt_withLong_withInt_withInt_withLibOrgBouncycastleBcpgSignatureSubpacketArray_withLibOrgBouncycastleBcpgSignatureSubpacketArray_withByteArray_withLibOrgBouncycastleBcpgMPIntegerArray_, signatureType, keyID, keyAlgorithm, hashAlgorithm, hashedData, unhashedData, fingerPrint, signature)
}

void LibOrgBouncycastleBcpgSignaturePacket_initWithInt_withInt_withLong_withInt_withInt_withLong_withByteArray_withLibOrgBouncycastleBcpgMPIntegerArray_(LibOrgBouncycastleBcpgSignaturePacket *self, jint version_, jint signatureType, jlong keyID, jint keyAlgorithm, jint hashAlgorithm, jlong creationTime, IOSByteArray *fingerPrint, IOSObjectArray *signature) {
  LibOrgBouncycastleBcpgSignaturePacket_initWithInt_withInt_withLong_withInt_withInt_withLibOrgBouncycastleBcpgSignatureSubpacketArray_withLibOrgBouncycastleBcpgSignatureSubpacketArray_withByteArray_withLibOrgBouncycastleBcpgMPIntegerArray_(self, version_, signatureType, keyID, keyAlgorithm, hashAlgorithm, nil, nil, fingerPrint, signature);
  self->creationTime_ = creationTime;
}

LibOrgBouncycastleBcpgSignaturePacket *new_LibOrgBouncycastleBcpgSignaturePacket_initWithInt_withInt_withLong_withInt_withInt_withLong_withByteArray_withLibOrgBouncycastleBcpgMPIntegerArray_(jint version_, jint signatureType, jlong keyID, jint keyAlgorithm, jint hashAlgorithm, jlong creationTime, IOSByteArray *fingerPrint, IOSObjectArray *signature) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleBcpgSignaturePacket, initWithInt_withInt_withLong_withInt_withInt_withLong_withByteArray_withLibOrgBouncycastleBcpgMPIntegerArray_, version_, signatureType, keyID, keyAlgorithm, hashAlgorithm, creationTime, fingerPrint, signature)
}

LibOrgBouncycastleBcpgSignaturePacket *create_LibOrgBouncycastleBcpgSignaturePacket_initWithInt_withInt_withLong_withInt_withInt_withLong_withByteArray_withLibOrgBouncycastleBcpgMPIntegerArray_(jint version_, jint signatureType, jlong keyID, jint keyAlgorithm, jint hashAlgorithm, jlong creationTime, IOSByteArray *fingerPrint, IOSObjectArray *signature) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleBcpgSignaturePacket, initWithInt_withInt_withLong_withInt_withInt_withLong_withByteArray_withLibOrgBouncycastleBcpgMPIntegerArray_, version_, signatureType, keyID, keyAlgorithm, hashAlgorithm, creationTime, fingerPrint, signature)
}

void LibOrgBouncycastleBcpgSignaturePacket_initWithInt_withInt_withLong_withInt_withInt_withLibOrgBouncycastleBcpgSignatureSubpacketArray_withLibOrgBouncycastleBcpgSignatureSubpacketArray_withByteArray_withLibOrgBouncycastleBcpgMPIntegerArray_(LibOrgBouncycastleBcpgSignaturePacket *self, jint version_, jint signatureType, jlong keyID, jint keyAlgorithm, jint hashAlgorithm, IOSObjectArray *hashedData, IOSObjectArray *unhashedData, IOSByteArray *fingerPrint, IOSObjectArray *signature) {
  LibOrgBouncycastleBcpgContainedPacket_init(self);
  self->version__ = version_;
  self->signatureType_ = signatureType;
  self->keyID_ = keyID;
  self->keyAlgorithm_ = keyAlgorithm;
  self->hashAlgorithm_ = hashAlgorithm;
  self->hashedData_ = hashedData;
  self->unhashedData_ = unhashedData;
  self->fingerPrint_ = fingerPrint;
  self->signature_ = signature;
  if (hashedData != nil) {
    LibOrgBouncycastleBcpgSignaturePacket_setCreationTime(self);
  }
}

LibOrgBouncycastleBcpgSignaturePacket *new_LibOrgBouncycastleBcpgSignaturePacket_initWithInt_withInt_withLong_withInt_withInt_withLibOrgBouncycastleBcpgSignatureSubpacketArray_withLibOrgBouncycastleBcpgSignatureSubpacketArray_withByteArray_withLibOrgBouncycastleBcpgMPIntegerArray_(jint version_, jint signatureType, jlong keyID, jint keyAlgorithm, jint hashAlgorithm, IOSObjectArray *hashedData, IOSObjectArray *unhashedData, IOSByteArray *fingerPrint, IOSObjectArray *signature) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleBcpgSignaturePacket, initWithInt_withInt_withLong_withInt_withInt_withLibOrgBouncycastleBcpgSignatureSubpacketArray_withLibOrgBouncycastleBcpgSignatureSubpacketArray_withByteArray_withLibOrgBouncycastleBcpgMPIntegerArray_, version_, signatureType, keyID, keyAlgorithm, hashAlgorithm, hashedData, unhashedData, fingerPrint, signature)
}

LibOrgBouncycastleBcpgSignaturePacket *create_LibOrgBouncycastleBcpgSignaturePacket_initWithInt_withInt_withLong_withInt_withInt_withLibOrgBouncycastleBcpgSignatureSubpacketArray_withLibOrgBouncycastleBcpgSignatureSubpacketArray_withByteArray_withLibOrgBouncycastleBcpgMPIntegerArray_(jint version_, jint signatureType, jlong keyID, jint keyAlgorithm, jint hashAlgorithm, IOSObjectArray *hashedData, IOSObjectArray *unhashedData, IOSByteArray *fingerPrint, IOSObjectArray *signature) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleBcpgSignaturePacket, initWithInt_withInt_withLong_withInt_withInt_withLibOrgBouncycastleBcpgSignatureSubpacketArray_withLibOrgBouncycastleBcpgSignatureSubpacketArray_withByteArray_withLibOrgBouncycastleBcpgMPIntegerArray_, version_, signatureType, keyID, keyAlgorithm, hashAlgorithm, hashedData, unhashedData, fingerPrint, signature)
}

void LibOrgBouncycastleBcpgSignaturePacket_setCreationTime(LibOrgBouncycastleBcpgSignaturePacket *self) {
  for (jint i = 0; i != ((IOSObjectArray *) nil_chk(self->hashedData_))->size_; i++) {
    if ([IOSObjectArray_Get(self->hashedData_, i) isKindOfClass:[LibOrgBouncycastleBcpgSigSignatureCreationTime class]]) {
      self->creationTime_ = [((JavaUtilDate *) nil_chk([((LibOrgBouncycastleBcpgSigSignatureCreationTime *) nil_chk(((LibOrgBouncycastleBcpgSigSignatureCreationTime *) cast_chk(IOSObjectArray_Get(self->hashedData_, i), [LibOrgBouncycastleBcpgSigSignatureCreationTime class])))) getTime])) getTime];
      break;
    }
  }
}

LibOrgBouncycastleBcpgSignaturePacket *LibOrgBouncycastleBcpgSignaturePacket_fromByteArrayWithByteArray_(IOSByteArray *data) {
  LibOrgBouncycastleBcpgSignaturePacket_initialize();
  LibOrgBouncycastleBcpgBCPGInputStream *in = new_LibOrgBouncycastleBcpgBCPGInputStream_initWithJavaIoInputStream_(new_JavaIoByteArrayInputStream_initWithByteArray_(data));
  return new_LibOrgBouncycastleBcpgSignaturePacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(in);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleBcpgSignaturePacket)
