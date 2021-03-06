//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/UDPTransport.java
//

#include "AlertDescription.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "TlsFatalAlert.h"
#include "UDPTransport.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/net/DatagramPacket.h"
#include "java/net/DatagramSocket.h"

@implementation LibOrgBouncycastleCryptoTlsUDPTransport

+ (jint)MIN_IP_OVERHEAD {
  return LibOrgBouncycastleCryptoTlsUDPTransport_MIN_IP_OVERHEAD;
}

+ (jint)MAX_IP_OVERHEAD {
  return LibOrgBouncycastleCryptoTlsUDPTransport_MAX_IP_OVERHEAD;
}

+ (jint)UDP_OVERHEAD {
  return LibOrgBouncycastleCryptoTlsUDPTransport_UDP_OVERHEAD;
}

- (instancetype)initWithJavaNetDatagramSocket:(JavaNetDatagramSocket *)socket
                                      withInt:(jint)mtu {
  LibOrgBouncycastleCryptoTlsUDPTransport_initWithJavaNetDatagramSocket_withInt_(self, socket, mtu);
  return self;
}

- (jint)getReceiveLimit {
  return receiveLimit_;
}

- (jint)getSendLimit {
  return sendLimit_;
}

- (jint)receiveWithByteArray:(IOSByteArray *)buf
                     withInt:(jint)off
                     withInt:(jint)len
                     withInt:(jint)waitMillis {
  [((JavaNetDatagramSocket *) nil_chk(socket_)) setSoTimeoutWithInt:waitMillis];
  JavaNetDatagramPacket *packet = new_JavaNetDatagramPacket_initWithByteArray_withInt_withInt_(buf, off, len);
  [socket_ receiveWithJavaNetDatagramPacket:packet];
  return [packet getLength];
}

- (void)sendWithByteArray:(IOSByteArray *)buf
                  withInt:(jint)off
                  withInt:(jint)len {
  if (len > [self getSendLimit]) {
    @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_(LibOrgBouncycastleCryptoTlsAlertDescription_internal_error);
  }
  JavaNetDatagramPacket *packet = new_JavaNetDatagramPacket_initWithByteArray_withInt_withInt_(buf, off, len);
  [((JavaNetDatagramSocket *) nil_chk(socket_)) sendWithJavaNetDatagramPacket:packet];
}

- (void)close {
  [((JavaNetDatagramSocket *) nil_chk(socket_)) close];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, 1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 2, 3, 1, -1, -1, -1 },
    { NULL, "V", 0x1, 4, 5, 1, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, 1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithJavaNetDatagramSocket:withInt:);
  methods[1].selector = @selector(getReceiveLimit);
  methods[2].selector = @selector(getSendLimit);
  methods[3].selector = @selector(receiveWithByteArray:withInt:withInt:withInt:);
  methods[4].selector = @selector(sendWithByteArray:withInt:withInt:);
  methods[5].selector = @selector(close);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "MIN_IP_OVERHEAD", "I", .constantValue.asInt = LibOrgBouncycastleCryptoTlsUDPTransport_MIN_IP_OVERHEAD, 0x1c, -1, -1, -1, -1 },
    { "MAX_IP_OVERHEAD", "I", .constantValue.asInt = LibOrgBouncycastleCryptoTlsUDPTransport_MAX_IP_OVERHEAD, 0x1c, -1, -1, -1, -1 },
    { "UDP_OVERHEAD", "I", .constantValue.asInt = LibOrgBouncycastleCryptoTlsUDPTransport_UDP_OVERHEAD, 0x1c, -1, -1, -1, -1 },
    { "socket_", "LJavaNetDatagramSocket;", .constantValue.asLong = 0, 0x14, -1, -1, -1, -1 },
    { "receiveLimit_", "I", .constantValue.asLong = 0, 0x14, -1, -1, -1, -1 },
    { "sendLimit_", "I", .constantValue.asLong = 0, 0x14, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaNetDatagramSocket;I", "LJavaIoIOException;", "receive", "[BIII", "send", "[BII" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoTlsUDPTransport = { "UDPTransport", "lib.org.bouncycastle.crypto.tls", ptrTable, methods, fields, 7, 0x1, 6, 6, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoTlsUDPTransport;
}

@end

void LibOrgBouncycastleCryptoTlsUDPTransport_initWithJavaNetDatagramSocket_withInt_(LibOrgBouncycastleCryptoTlsUDPTransport *self, JavaNetDatagramSocket *socket, jint mtu) {
  NSObject_init(self);
  if (![((JavaNetDatagramSocket *) nil_chk(socket)) isBound] || ![socket isConnected]) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"'socket' must be bound and connected");
  }
  self->socket_ = socket;
  self->receiveLimit_ = mtu - LibOrgBouncycastleCryptoTlsUDPTransport_MIN_IP_OVERHEAD - LibOrgBouncycastleCryptoTlsUDPTransport_UDP_OVERHEAD;
  self->sendLimit_ = mtu - LibOrgBouncycastleCryptoTlsUDPTransport_MAX_IP_OVERHEAD - LibOrgBouncycastleCryptoTlsUDPTransport_UDP_OVERHEAD;
}

LibOrgBouncycastleCryptoTlsUDPTransport *new_LibOrgBouncycastleCryptoTlsUDPTransport_initWithJavaNetDatagramSocket_withInt_(JavaNetDatagramSocket *socket, jint mtu) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoTlsUDPTransport, initWithJavaNetDatagramSocket_withInt_, socket, mtu)
}

LibOrgBouncycastleCryptoTlsUDPTransport *create_LibOrgBouncycastleCryptoTlsUDPTransport_initWithJavaNetDatagramSocket_withInt_(JavaNetDatagramSocket *socket, jint mtu) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoTlsUDPTransport, initWithJavaNetDatagramSocket_withInt_, socket, mtu)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoTlsUDPTransport)
