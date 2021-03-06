//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/bcpg/ExperimentalPacket.java
//

#include "Arrays.h"
#include "BCPGInputStream.h"
#include "BCPGOutputStream.h"
#include "ContainedPacket.h"
#include "ExperimentalPacket.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"

@interface LibOrgBouncycastleBcpgExperimentalPacket () {
 @public
  jint tag_;
  IOSByteArray *contents_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleBcpgExperimentalPacket, contents_, IOSByteArray *)

@implementation LibOrgBouncycastleBcpgExperimentalPacket

- (instancetype)initWithInt:(jint)tag
withLibOrgBouncycastleBcpgBCPGInputStream:(LibOrgBouncycastleBcpgBCPGInputStream *)inArg {
  LibOrgBouncycastleBcpgExperimentalPacket_initWithInt_withLibOrgBouncycastleBcpgBCPGInputStream_(self, tag, inArg);
  return self;
}

- (jint)getTag {
  return tag_;
}

- (IOSByteArray *)getContents {
  return LibOrgBouncycastleUtilArrays_cloneWithByteArray_(contents_);
}

- (void)encodeWithLibOrgBouncycastleBcpgBCPGOutputStream:(LibOrgBouncycastleBcpgBCPGOutputStream *)outArg {
  [((LibOrgBouncycastleBcpgBCPGOutputStream *) nil_chk(outArg)) writePacketWithInt:tag_ withByteArray:contents_ withBoolean:true];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, 0, 1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 2, 3, 1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithInt:withLibOrgBouncycastleBcpgBCPGInputStream:);
  methods[1].selector = @selector(getTag);
  methods[2].selector = @selector(getContents);
  methods[3].selector = @selector(encodeWithLibOrgBouncycastleBcpgBCPGOutputStream:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "tag_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "contents_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "ILLibOrgBouncycastleBcpgBCPGInputStream;", "LJavaIoIOException;", "encode", "LLibOrgBouncycastleBcpgBCPGOutputStream;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleBcpgExperimentalPacket = { "ExperimentalPacket", "lib.org.bouncycastle.bcpg", ptrTable, methods, fields, 7, 0x1, 4, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleBcpgExperimentalPacket;
}

@end

void LibOrgBouncycastleBcpgExperimentalPacket_initWithInt_withLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgExperimentalPacket *self, jint tag, LibOrgBouncycastleBcpgBCPGInputStream *inArg) {
  LibOrgBouncycastleBcpgContainedPacket_init(self);
  self->tag_ = tag;
  self->contents_ = [((LibOrgBouncycastleBcpgBCPGInputStream *) nil_chk(inArg)) readAll];
}

LibOrgBouncycastleBcpgExperimentalPacket *new_LibOrgBouncycastleBcpgExperimentalPacket_initWithInt_withLibOrgBouncycastleBcpgBCPGInputStream_(jint tag, LibOrgBouncycastleBcpgBCPGInputStream *inArg) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleBcpgExperimentalPacket, initWithInt_withLibOrgBouncycastleBcpgBCPGInputStream_, tag, inArg)
}

LibOrgBouncycastleBcpgExperimentalPacket *create_LibOrgBouncycastleBcpgExperimentalPacket_initWithInt_withLibOrgBouncycastleBcpgBCPGInputStream_(jint tag, LibOrgBouncycastleBcpgBCPGInputStream *inArg) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleBcpgExperimentalPacket, initWithInt_withLibOrgBouncycastleBcpgBCPGInputStream_, tag, inArg)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleBcpgExperimentalPacket)
