//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/bcpg/BCPGInputStream.java
//

#include "BCPGInputStream.h"
#include "CompressedDataPacket.h"
#include "ExperimentalPacket.h"
#include "IOSPrimitiveArray.h"
#include "InputStreamPacket.h"
#include "J2ObjC_source.h"
#include "LiteralDataPacket.h"
#include "MarkerPacket.h"
#include "ModDetectionCodePacket.h"
#include "OnePassSignaturePacket.h"
#include "Packet.h"
#include "PacketTags.h"
#include "PublicKeyEncSessionPacket.h"
#include "PublicKeyPacket.h"
#include "PublicSubkeyPacket.h"
#include "SecretKeyPacket.h"
#include "SecretSubkeyPacket.h"
#include "SignaturePacket.h"
#include "Streams.h"
#include "SymmetricEncDataPacket.h"
#include "SymmetricEncIntegrityPacket.h"
#include "SymmetricKeyEncSessionPacket.h"
#include "TrustPacket.h"
#include "UserAttributePacket.h"
#include "UserIDPacket.h"
#include "java/io/EOFException.h"
#include "java/io/IOException.h"
#include "java/io/InputStream.h"

@interface LibOrgBouncycastleBcpgBCPGInputStream_PartialInputStream : JavaIoInputStream {
 @public
  LibOrgBouncycastleBcpgBCPGInputStream *in_;
  jboolean partial_;
  jint dataLength_;
}

- (instancetype)initWithLibOrgBouncycastleBcpgBCPGInputStream:(LibOrgBouncycastleBcpgBCPGInputStream *)inArg
                                                  withBoolean:(jboolean)partial
                                                      withInt:(jint)dataLength;

- (jint)available;

- (jint)loadDataLength;

- (jint)readWithByteArray:(IOSByteArray *)buf
                  withInt:(jint)offset
                  withInt:(jint)len;

- (jint)read;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleBcpgBCPGInputStream_PartialInputStream)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleBcpgBCPGInputStream_PartialInputStream, in_, LibOrgBouncycastleBcpgBCPGInputStream *)

__attribute__((unused)) static void LibOrgBouncycastleBcpgBCPGInputStream_PartialInputStream_initWithLibOrgBouncycastleBcpgBCPGInputStream_withBoolean_withInt_(LibOrgBouncycastleBcpgBCPGInputStream_PartialInputStream *self, LibOrgBouncycastleBcpgBCPGInputStream *inArg, jboolean partial, jint dataLength);

__attribute__((unused)) static LibOrgBouncycastleBcpgBCPGInputStream_PartialInputStream *new_LibOrgBouncycastleBcpgBCPGInputStream_PartialInputStream_initWithLibOrgBouncycastleBcpgBCPGInputStream_withBoolean_withInt_(LibOrgBouncycastleBcpgBCPGInputStream *inArg, jboolean partial, jint dataLength) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleBcpgBCPGInputStream_PartialInputStream *create_LibOrgBouncycastleBcpgBCPGInputStream_PartialInputStream_initWithLibOrgBouncycastleBcpgBCPGInputStream_withBoolean_withInt_(LibOrgBouncycastleBcpgBCPGInputStream *inArg, jboolean partial, jint dataLength);

__attribute__((unused)) static jint LibOrgBouncycastleBcpgBCPGInputStream_PartialInputStream_loadDataLength(LibOrgBouncycastleBcpgBCPGInputStream_PartialInputStream *self);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleBcpgBCPGInputStream_PartialInputStream)

@implementation LibOrgBouncycastleBcpgBCPGInputStream

- (instancetype)initWithJavaIoInputStream:(JavaIoInputStream *)inArg {
  LibOrgBouncycastleBcpgBCPGInputStream_initWithJavaIoInputStream_(self, inArg);
  return self;
}

- (jint)available {
  return [((JavaIoInputStream *) nil_chk(in_)) available];
}

- (jint)read {
  if (next_) {
    next_ = false;
    return nextB_;
  }
  else {
    return [((JavaIoInputStream *) nil_chk(in_)) read];
  }
}

- (jint)readWithByteArray:(IOSByteArray *)buf
                  withInt:(jint)off
                  withInt:(jint)len {
  if (len == 0) {
    return 0;
  }
  if (!next_) {
    return [((JavaIoInputStream *) nil_chk(in_)) readWithByteArray:buf withInt:off withInt:len];
  }
  if (nextB_ < 0) {
    return -1;
  }
  *IOSByteArray_GetRef(nil_chk(buf), off) = (jbyte) nextB_;
  next_ = false;
  return 1;
}

- (void)readFullyWithByteArray:(IOSByteArray *)buf
                       withInt:(jint)off
                       withInt:(jint)len {
  if (LibOrgBouncycastleUtilIoStreams_readFullyWithJavaIoInputStream_withByteArray_withInt_withInt_(self, buf, off, len) < len) {
    @throw new_JavaIoEOFException_init();
  }
}

- (IOSByteArray *)readAll {
  return LibOrgBouncycastleUtilIoStreams_readAllWithJavaIoInputStream_(self);
}

- (void)readFullyWithByteArray:(IOSByteArray *)buf {
  [self readFullyWithByteArray:buf withInt:0 withInt:((IOSByteArray *) nil_chk(buf))->size_];
}

- (jint)nextPacketTag {
  if (!next_) {
    @try {
      nextB_ = [((JavaIoInputStream *) nil_chk(in_)) read];
    }
    @catch (JavaIoEOFException *e) {
      nextB_ = -1;
    }
    next_ = true;
  }
  if (nextB_ < 0) {
    return nextB_;
  }
  jint maskB = nextB_ & (jint) 0x3f;
  if ((nextB_ & (jint) 0x40) == 0) {
    JreRShiftAssignInt(&maskB, 2);
  }
  return maskB;
}

- (LibOrgBouncycastleBcpgPacket *)readPacket {
  jint hdr = [self read];
  if (hdr < 0) {
    return nil;
  }
  if ((hdr & (jint) 0x80) == 0) {
    @throw new_JavaIoIOException_initWithNSString_(@"invalid header encountered");
  }
  jboolean newPacket = (hdr & (jint) 0x40) != 0;
  jint tag = 0;
  jint bodyLen = 0;
  jboolean partial = false;
  if (newPacket) {
    tag = hdr & (jint) 0x3f;
    jint l = [self read];
    if (l < 192) {
      bodyLen = l;
    }
    else if (l <= 223) {
      jint b = [((JavaIoInputStream *) nil_chk(in_)) read];
      bodyLen = (JreLShift32((l - 192), 8)) + (b) + 192;
    }
    else if (l == 255) {
      bodyLen = (JreLShift32([((JavaIoInputStream *) nil_chk(in_)) read], 24)) | (JreLShift32([((JavaIoInputStream *) nil_chk(in_)) read], 16)) | (JreLShift32([((JavaIoInputStream *) nil_chk(in_)) read], 8)) | [((JavaIoInputStream *) nil_chk(in_)) read];
    }
    else {
      partial = true;
      bodyLen = JreLShift32(1, (l & (jint) 0x1f));
    }
  }
  else {
    jint lengthType = hdr & (jint) 0x3;
    tag = JreRShift32((hdr & (jint) 0x3f), 2);
    switch (lengthType) {
      case 0:
      bodyLen = [self read];
      break;
      case 1:
      bodyLen = (JreLShift32([self read], 8)) | [self read];
      break;
      case 2:
      bodyLen = (JreLShift32([self read], 24)) | (JreLShift32([self read], 16)) | (JreLShift32([self read], 8)) | [self read];
      break;
      case 3:
      partial = true;
      break;
      default:
      @throw new_JavaIoIOException_initWithNSString_(@"unknown length type encountered");
    }
  }
  LibOrgBouncycastleBcpgBCPGInputStream *objStream;
  if (bodyLen == 0 && partial) {
    objStream = self;
  }
  else {
    objStream = new_LibOrgBouncycastleBcpgBCPGInputStream_initWithJavaIoInputStream_(new_LibOrgBouncycastleBcpgBCPGInputStream_PartialInputStream_initWithLibOrgBouncycastleBcpgBCPGInputStream_withBoolean_withInt_(self, partial, bodyLen));
  }
  switch (tag) {
    case LibOrgBouncycastleBcpgPacketTags_RESERVED:
    return new_LibOrgBouncycastleBcpgInputStreamPacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(objStream);
    case LibOrgBouncycastleBcpgPacketTags_PUBLIC_KEY_ENC_SESSION:
    return new_LibOrgBouncycastleBcpgPublicKeyEncSessionPacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(objStream);
    case LibOrgBouncycastleBcpgPacketTags_SIGNATURE:
    return new_LibOrgBouncycastleBcpgSignaturePacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(objStream);
    case LibOrgBouncycastleBcpgPacketTags_SYMMETRIC_KEY_ENC_SESSION:
    return new_LibOrgBouncycastleBcpgSymmetricKeyEncSessionPacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(objStream);
    case LibOrgBouncycastleBcpgPacketTags_ONE_PASS_SIGNATURE:
    return new_LibOrgBouncycastleBcpgOnePassSignaturePacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(objStream);
    case LibOrgBouncycastleBcpgPacketTags_SECRET_KEY:
    return new_LibOrgBouncycastleBcpgSecretKeyPacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(objStream);
    case LibOrgBouncycastleBcpgPacketTags_PUBLIC_KEY:
    return new_LibOrgBouncycastleBcpgPublicKeyPacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(objStream);
    case LibOrgBouncycastleBcpgPacketTags_SECRET_SUBKEY:
    return new_LibOrgBouncycastleBcpgSecretSubkeyPacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(objStream);
    case LibOrgBouncycastleBcpgPacketTags_COMPRESSED_DATA:
    return new_LibOrgBouncycastleBcpgCompressedDataPacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(objStream);
    case LibOrgBouncycastleBcpgPacketTags_SYMMETRIC_KEY_ENC:
    return new_LibOrgBouncycastleBcpgSymmetricEncDataPacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(objStream);
    case LibOrgBouncycastleBcpgPacketTags_MARKER:
    return new_LibOrgBouncycastleBcpgMarkerPacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(objStream);
    case LibOrgBouncycastleBcpgPacketTags_LITERAL_DATA:
    return new_LibOrgBouncycastleBcpgLiteralDataPacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(objStream);
    case LibOrgBouncycastleBcpgPacketTags_TRUST:
    return new_LibOrgBouncycastleBcpgTrustPacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(objStream);
    case LibOrgBouncycastleBcpgPacketTags_USER_ID:
    return new_LibOrgBouncycastleBcpgUserIDPacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(objStream);
    case LibOrgBouncycastleBcpgPacketTags_USER_ATTRIBUTE:
    return new_LibOrgBouncycastleBcpgUserAttributePacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(objStream);
    case LibOrgBouncycastleBcpgPacketTags_PUBLIC_SUBKEY:
    return new_LibOrgBouncycastleBcpgPublicSubkeyPacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(objStream);
    case LibOrgBouncycastleBcpgPacketTags_SYM_ENC_INTEGRITY_PRO:
    return new_LibOrgBouncycastleBcpgSymmetricEncIntegrityPacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(objStream);
    case LibOrgBouncycastleBcpgPacketTags_MOD_DETECTION_CODE:
    return new_LibOrgBouncycastleBcpgModDetectionCodePacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(objStream);
    case LibOrgBouncycastleBcpgPacketTags_EXPERIMENTAL_1:
    case LibOrgBouncycastleBcpgPacketTags_EXPERIMENTAL_2:
    case LibOrgBouncycastleBcpgPacketTags_EXPERIMENTAL_3:
    case LibOrgBouncycastleBcpgPacketTags_EXPERIMENTAL_4:
    return new_LibOrgBouncycastleBcpgExperimentalPacket_initWithInt_withLibOrgBouncycastleBcpgBCPGInputStream_(tag, objStream);
    default:
    @throw new_JavaIoIOException_initWithNSString_(JreStrcat("$I", @"unknown packet type encountered: ", tag));
  }
}

- (void)close {
  [((JavaIoInputStream *) nil_chk(in_)) close];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, 1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, 1, -1, -1, -1 },
    { NULL, "I", 0x1, 2, 3, 1, -1, -1, -1 },
    { NULL, "V", 0x1, 4, 3, 1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, 1, -1, -1, -1 },
    { NULL, "V", 0x1, 4, 5, 1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, 1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleBcpgPacket;", 0x1, -1, -1, 1, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, 1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithJavaIoInputStream:);
  methods[1].selector = @selector(available);
  methods[2].selector = @selector(read);
  methods[3].selector = @selector(readWithByteArray:withInt:withInt:);
  methods[4].selector = @selector(readFullyWithByteArray:withInt:withInt:);
  methods[5].selector = @selector(readAll);
  methods[6].selector = @selector(readFullyWithByteArray:);
  methods[7].selector = @selector(nextPacketTag);
  methods[8].selector = @selector(readPacket);
  methods[9].selector = @selector(close);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "in_", "LJavaIoInputStream;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "next_", "Z", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "nextB_", "I", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaIoInputStream;", "LJavaIoIOException;", "read", "[BII", "readFully", "[B", "LLibOrgBouncycastleBcpgBCPGInputStream_PartialInputStream;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleBcpgBCPGInputStream = { "BCPGInputStream", "lib.org.bouncycastle.bcpg", ptrTable, methods, fields, 7, 0x1, 10, 3, -1, 6, -1, -1, -1 };
  return &_LibOrgBouncycastleBcpgBCPGInputStream;
}

@end

void LibOrgBouncycastleBcpgBCPGInputStream_initWithJavaIoInputStream_(LibOrgBouncycastleBcpgBCPGInputStream *self, JavaIoInputStream *inArg) {
  JavaIoInputStream_init(self);
  self->next_ = false;
  self->in_ = inArg;
}

LibOrgBouncycastleBcpgBCPGInputStream *new_LibOrgBouncycastleBcpgBCPGInputStream_initWithJavaIoInputStream_(JavaIoInputStream *inArg) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleBcpgBCPGInputStream, initWithJavaIoInputStream_, inArg)
}

LibOrgBouncycastleBcpgBCPGInputStream *create_LibOrgBouncycastleBcpgBCPGInputStream_initWithJavaIoInputStream_(JavaIoInputStream *inArg) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleBcpgBCPGInputStream, initWithJavaIoInputStream_, inArg)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleBcpgBCPGInputStream)

@implementation LibOrgBouncycastleBcpgBCPGInputStream_PartialInputStream

- (instancetype)initWithLibOrgBouncycastleBcpgBCPGInputStream:(LibOrgBouncycastleBcpgBCPGInputStream *)inArg
                                                  withBoolean:(jboolean)partial
                                                      withInt:(jint)dataLength {
  LibOrgBouncycastleBcpgBCPGInputStream_PartialInputStream_initWithLibOrgBouncycastleBcpgBCPGInputStream_withBoolean_withInt_(self, inArg, partial, dataLength);
  return self;
}

- (jint)available {
  jint avail = [((LibOrgBouncycastleBcpgBCPGInputStream *) nil_chk(in_)) available];
  if (avail <= dataLength_ || dataLength_ < 0) {
    return avail;
  }
  else {
    if (partial_ && dataLength_ == 0) {
      return 1;
    }
    return dataLength_;
  }
}

- (jint)loadDataLength {
  return LibOrgBouncycastleBcpgBCPGInputStream_PartialInputStream_loadDataLength(self);
}

- (jint)readWithByteArray:(IOSByteArray *)buf
                  withInt:(jint)offset
                  withInt:(jint)len {
  do {
    if (dataLength_ != 0) {
      jint readLen = (dataLength_ > len || dataLength_ < 0) ? len : dataLength_;
      readLen = [((LibOrgBouncycastleBcpgBCPGInputStream *) nil_chk(in_)) readWithByteArray:buf withInt:offset withInt:readLen];
      if (readLen < 0) {
        @throw new_JavaIoEOFException_initWithNSString_(@"premature end of stream in PartialInputStream");
      }
      dataLength_ -= readLen;
      return readLen;
    }
  }
  while (partial_ && LibOrgBouncycastleBcpgBCPGInputStream_PartialInputStream_loadDataLength(self) >= 0);
  return -1;
}

- (jint)read {
  do {
    if (dataLength_ != 0) {
      jint ch = [((LibOrgBouncycastleBcpgBCPGInputStream *) nil_chk(in_)) read];
      if (ch < 0) {
        @throw new_JavaIoEOFException_initWithNSString_(@"premature end of stream in PartialInputStream");
      }
      dataLength_--;
      return ch;
    }
  }
  while (partial_ && LibOrgBouncycastleBcpgBCPGInputStream_PartialInputStream_loadDataLength(self) >= 0);
  return -1;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, 0, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, 1, -1, -1, -1 },
    { NULL, "I", 0x2, -1, -1, 1, -1, -1, -1 },
    { NULL, "I", 0x1, 2, 3, 1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, 1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleBcpgBCPGInputStream:withBoolean:withInt:);
  methods[1].selector = @selector(available);
  methods[2].selector = @selector(loadDataLength);
  methods[3].selector = @selector(readWithByteArray:withInt:withInt:);
  methods[4].selector = @selector(read);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "in_", "LLibOrgBouncycastleBcpgBCPGInputStream;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "partial_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "dataLength_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleBcpgBCPGInputStream;ZI", "LJavaIoIOException;", "read", "[BII", "LLibOrgBouncycastleBcpgBCPGInputStream;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleBcpgBCPGInputStream_PartialInputStream = { "PartialInputStream", "lib.org.bouncycastle.bcpg", ptrTable, methods, fields, 7, 0xa, 5, 3, 4, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleBcpgBCPGInputStream_PartialInputStream;
}

@end

void LibOrgBouncycastleBcpgBCPGInputStream_PartialInputStream_initWithLibOrgBouncycastleBcpgBCPGInputStream_withBoolean_withInt_(LibOrgBouncycastleBcpgBCPGInputStream_PartialInputStream *self, LibOrgBouncycastleBcpgBCPGInputStream *inArg, jboolean partial, jint dataLength) {
  JavaIoInputStream_init(self);
  self->in_ = inArg;
  self->partial_ = partial;
  self->dataLength_ = dataLength;
}

LibOrgBouncycastleBcpgBCPGInputStream_PartialInputStream *new_LibOrgBouncycastleBcpgBCPGInputStream_PartialInputStream_initWithLibOrgBouncycastleBcpgBCPGInputStream_withBoolean_withInt_(LibOrgBouncycastleBcpgBCPGInputStream *inArg, jboolean partial, jint dataLength) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleBcpgBCPGInputStream_PartialInputStream, initWithLibOrgBouncycastleBcpgBCPGInputStream_withBoolean_withInt_, inArg, partial, dataLength)
}

LibOrgBouncycastleBcpgBCPGInputStream_PartialInputStream *create_LibOrgBouncycastleBcpgBCPGInputStream_PartialInputStream_initWithLibOrgBouncycastleBcpgBCPGInputStream_withBoolean_withInt_(LibOrgBouncycastleBcpgBCPGInputStream *inArg, jboolean partial, jint dataLength) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleBcpgBCPGInputStream_PartialInputStream, initWithLibOrgBouncycastleBcpgBCPGInputStream_withBoolean_withInt_, inArg, partial, dataLength)
}

jint LibOrgBouncycastleBcpgBCPGInputStream_PartialInputStream_loadDataLength(LibOrgBouncycastleBcpgBCPGInputStream_PartialInputStream *self) {
  jint l = [((LibOrgBouncycastleBcpgBCPGInputStream *) nil_chk(self->in_)) read];
  if (l < 0) {
    return -1;
  }
  self->partial_ = false;
  if (l < 192) {
    self->dataLength_ = l;
  }
  else if (l <= 223) {
    self->dataLength_ = (JreLShift32((l - 192), 8)) + ([((LibOrgBouncycastleBcpgBCPGInputStream *) nil_chk(self->in_)) read]) + 192;
  }
  else if (l == 255) {
    self->dataLength_ = (JreLShift32([((LibOrgBouncycastleBcpgBCPGInputStream *) nil_chk(self->in_)) read], 24)) | (JreLShift32([((LibOrgBouncycastleBcpgBCPGInputStream *) nil_chk(self->in_)) read], 16)) | (JreLShift32([((LibOrgBouncycastleBcpgBCPGInputStream *) nil_chk(self->in_)) read], 8)) | [((LibOrgBouncycastleBcpgBCPGInputStream *) nil_chk(self->in_)) read];
  }
  else {
    self->partial_ = true;
    self->dataLength_ = JreLShift32(1, (l & (jint) 0x1f));
  }
  return self->dataLength_;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleBcpgBCPGInputStream_PartialInputStream)