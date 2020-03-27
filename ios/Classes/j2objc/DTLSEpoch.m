//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/DTLSEpoch.java
//

#include "DTLSEpoch.h"
#include "DTLSReplayWindow.h"
#include "J2ObjC_source.h"
#include "TlsCipher.h"
#include "java/lang/IllegalArgumentException.h"

@interface LibOrgBouncycastleCryptoTlsDTLSEpoch () {
 @public
  LibOrgBouncycastleCryptoTlsDTLSReplayWindow *replayWindow_;
  jint epoch_;
  id<LibOrgBouncycastleCryptoTlsTlsCipher> cipher_;
  jlong sequenceNumber_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsDTLSEpoch, replayWindow_, LibOrgBouncycastleCryptoTlsDTLSReplayWindow *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsDTLSEpoch, cipher_, id<LibOrgBouncycastleCryptoTlsTlsCipher>)

@implementation LibOrgBouncycastleCryptoTlsDTLSEpoch

- (instancetype)initWithInt:(jint)epoch
withLibOrgBouncycastleCryptoTlsTlsCipher:(id<LibOrgBouncycastleCryptoTlsTlsCipher>)cipher {
  LibOrgBouncycastleCryptoTlsDTLSEpoch_initWithInt_withLibOrgBouncycastleCryptoTlsTlsCipher_(self, epoch, cipher);
  return self;
}

- (jlong)allocateSequenceNumber {
  return sequenceNumber_++;
}

- (id<LibOrgBouncycastleCryptoTlsTlsCipher>)getCipher {
  return cipher_;
}

- (jint)getEpoch {
  return epoch_;
}

- (LibOrgBouncycastleCryptoTlsDTLSReplayWindow *)getReplayWindow {
  return replayWindow_;
}

- (jlong)getSequenceNumber {
  return sequenceNumber_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, 0, -1, -1, -1, -1 },
    { NULL, "J", 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoTlsTlsCipher;", 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoTlsDTLSReplayWindow;", 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "J", 0x0, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithInt:withLibOrgBouncycastleCryptoTlsTlsCipher:);
  methods[1].selector = @selector(allocateSequenceNumber);
  methods[2].selector = @selector(getCipher);
  methods[3].selector = @selector(getEpoch);
  methods[4].selector = @selector(getReplayWindow);
  methods[5].selector = @selector(getSequenceNumber);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "replayWindow_", "LLibOrgBouncycastleCryptoTlsDTLSReplayWindow;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "epoch_", "I", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "cipher_", "LLibOrgBouncycastleCryptoTlsTlsCipher;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "sequenceNumber_", "J", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "ILLibOrgBouncycastleCryptoTlsTlsCipher;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoTlsDTLSEpoch = { "DTLSEpoch", "lib.org.bouncycastle.crypto.tls", ptrTable, methods, fields, 7, 0x0, 6, 4, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoTlsDTLSEpoch;
}

@end

void LibOrgBouncycastleCryptoTlsDTLSEpoch_initWithInt_withLibOrgBouncycastleCryptoTlsTlsCipher_(LibOrgBouncycastleCryptoTlsDTLSEpoch *self, jint epoch, id<LibOrgBouncycastleCryptoTlsTlsCipher> cipher) {
  NSObject_init(self);
  self->replayWindow_ = new_LibOrgBouncycastleCryptoTlsDTLSReplayWindow_init();
  self->sequenceNumber_ = 0;
  if (epoch < 0) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"'epoch' must be >= 0");
  }
  if (cipher == nil) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"'cipher' cannot be null");
  }
  self->epoch_ = epoch;
  self->cipher_ = cipher;
}

LibOrgBouncycastleCryptoTlsDTLSEpoch *new_LibOrgBouncycastleCryptoTlsDTLSEpoch_initWithInt_withLibOrgBouncycastleCryptoTlsTlsCipher_(jint epoch, id<LibOrgBouncycastleCryptoTlsTlsCipher> cipher) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoTlsDTLSEpoch, initWithInt_withLibOrgBouncycastleCryptoTlsTlsCipher_, epoch, cipher)
}

LibOrgBouncycastleCryptoTlsDTLSEpoch *create_LibOrgBouncycastleCryptoTlsDTLSEpoch_initWithInt_withLibOrgBouncycastleCryptoTlsTlsCipher_(jint epoch, id<LibOrgBouncycastleCryptoTlsTlsCipher> cipher) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoTlsDTLSEpoch, initWithInt_withLibOrgBouncycastleCryptoTlsTlsCipher_, epoch, cipher)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoTlsDTLSEpoch)