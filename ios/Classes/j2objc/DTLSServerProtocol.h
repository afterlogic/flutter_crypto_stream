//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/DTLSServerProtocol.java
//

#ifndef DTLSServerProtocol_H
#define DTLSServerProtocol_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "DTLSProtocol.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@class IOSIntArray;
@class IOSShortArray;
@class JavaSecuritySecureRandom;
@class JavaUtilHashtable;
@class LibOrgBouncycastleCryptoTlsCertificate;
@class LibOrgBouncycastleCryptoTlsCertificateRequest;
@class LibOrgBouncycastleCryptoTlsCertificateStatus;
@class LibOrgBouncycastleCryptoTlsDTLSRecordLayer;
@class LibOrgBouncycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState;
@class LibOrgBouncycastleCryptoTlsDTLSTransport;
@class LibOrgBouncycastleCryptoTlsNewSessionTicket;
@class LibOrgBouncycastleCryptoTlsSessionParameters;
@class LibOrgBouncycastleCryptoTlsSessionParameters_Builder;
@class LibOrgBouncycastleCryptoTlsTlsServerContextImpl;
@protocol LibOrgBouncycastleCryptoTlsDatagramTransport;
@protocol LibOrgBouncycastleCryptoTlsTlsCredentials;
@protocol LibOrgBouncycastleCryptoTlsTlsHandshakeHash;
@protocol LibOrgBouncycastleCryptoTlsTlsKeyExchange;
@protocol LibOrgBouncycastleCryptoTlsTlsServer;
@protocol LibOrgBouncycastleCryptoTlsTlsSession;

@interface LibOrgBouncycastleCryptoTlsDTLSServerProtocol : LibOrgBouncycastleCryptoTlsDTLSProtocol {
 @public
  jboolean verifyRequests_;
}

#pragma mark Public

- (instancetype __nonnull)initWithJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)secureRandom;

- (LibOrgBouncycastleCryptoTlsDTLSTransport *)acceptWithLibOrgBouncycastleCryptoTlsTlsServer:(id<LibOrgBouncycastleCryptoTlsTlsServer>)server
                                            withLibOrgBouncycastleCryptoTlsDatagramTransport:(id<LibOrgBouncycastleCryptoTlsDatagramTransport>)transport;

- (jboolean)getVerifyRequests;

- (void)setVerifyRequestsWithBoolean:(jboolean)verifyRequests;

#pragma mark Protected

- (void)abortServerHandshakeWithLibOrgBouncycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState:(LibOrgBouncycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState *)state
                                                    withLibOrgBouncycastleCryptoTlsDTLSRecordLayer:(LibOrgBouncycastleCryptoTlsDTLSRecordLayer *)recordLayer
                                                                                         withShort:(jshort)alertDescription;

- (jboolean)expectCertificateVerifyMessageWithLibOrgBouncycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState:(LibOrgBouncycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState *)state;

- (IOSByteArray *)generateCertificateRequestWithLibOrgBouncycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState:(LibOrgBouncycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState *)state
                                                                 withLibOrgBouncycastleCryptoTlsCertificateRequest:(LibOrgBouncycastleCryptoTlsCertificateRequest *)certificateRequest;

- (IOSByteArray *)generateCertificateStatusWithLibOrgBouncycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState:(LibOrgBouncycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState *)state
                                                                 withLibOrgBouncycastleCryptoTlsCertificateStatus:(LibOrgBouncycastleCryptoTlsCertificateStatus *)certificateStatus;

- (IOSByteArray *)generateNewSessionTicketWithLibOrgBouncycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState:(LibOrgBouncycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState *)state
                                                                 withLibOrgBouncycastleCryptoTlsNewSessionTicket:(LibOrgBouncycastleCryptoTlsNewSessionTicket *)newSessionTicket;

- (IOSByteArray *)generateServerHelloWithLibOrgBouncycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState:(LibOrgBouncycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState *)state;

- (void)invalidateSessionWithLibOrgBouncycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState:(LibOrgBouncycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState *)state;

- (void)notifyClientCertificateWithLibOrgBouncycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState:(LibOrgBouncycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState *)state
                                                           withLibOrgBouncycastleCryptoTlsCertificate:(LibOrgBouncycastleCryptoTlsCertificate *)clientCertificate;

- (void)processCertificateVerifyWithLibOrgBouncycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState:(LibOrgBouncycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState *)state
                                                                                         withByteArray:(IOSByteArray *)body
                                                       withLibOrgBouncycastleCryptoTlsTlsHandshakeHash:(id<LibOrgBouncycastleCryptoTlsTlsHandshakeHash>)prepareFinishHash;

- (void)processClientCertificateWithLibOrgBouncycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState:(LibOrgBouncycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState *)state
                                                                                         withByteArray:(IOSByteArray *)body;

- (void)processClientHelloWithLibOrgBouncycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState:(LibOrgBouncycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState *)state
                                                                                   withByteArray:(IOSByteArray *)body;

- (void)processClientKeyExchangeWithLibOrgBouncycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState:(LibOrgBouncycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState *)state
                                                                                         withByteArray:(IOSByteArray *)body;

- (void)processClientSupplementalDataWithLibOrgBouncycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState:(LibOrgBouncycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState *)state
                                                                                              withByteArray:(IOSByteArray *)body;

- (LibOrgBouncycastleCryptoTlsDTLSTransport *)serverHandshakeWithLibOrgBouncycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState:(LibOrgBouncycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState *)state
                                                                                     withLibOrgBouncycastleCryptoTlsDTLSRecordLayer:(LibOrgBouncycastleCryptoTlsDTLSRecordLayer *)recordLayer;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoTlsDTLSServerProtocol)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoTlsDTLSServerProtocol_initWithJavaSecuritySecureRandom_(LibOrgBouncycastleCryptoTlsDTLSServerProtocol *self, JavaSecuritySecureRandom *secureRandom);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsDTLSServerProtocol *new_LibOrgBouncycastleCryptoTlsDTLSServerProtocol_initWithJavaSecuritySecureRandom_(JavaSecuritySecureRandom *secureRandom) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsDTLSServerProtocol *create_LibOrgBouncycastleCryptoTlsDTLSServerProtocol_initWithJavaSecuritySecureRandom_(JavaSecuritySecureRandom *secureRandom);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoTlsDTLSServerProtocol)

@interface LibOrgBouncycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState : NSObject {
 @public
  id<LibOrgBouncycastleCryptoTlsTlsServer> server_;
  LibOrgBouncycastleCryptoTlsTlsServerContextImpl *serverContext_;
  id<LibOrgBouncycastleCryptoTlsTlsSession> tlsSession_;
  LibOrgBouncycastleCryptoTlsSessionParameters *sessionParameters_;
  LibOrgBouncycastleCryptoTlsSessionParameters_Builder *sessionParametersBuilder_;
  IOSIntArray *offeredCipherSuites_;
  IOSShortArray *offeredCompressionMethods_;
  JavaUtilHashtable *clientExtensions_;
  JavaUtilHashtable *serverExtensions_;
  jboolean resumedSession_;
  jboolean secure_renegotiation_;
  jboolean allowCertificateStatus_;
  jboolean expectSessionTicket_;
  id<LibOrgBouncycastleCryptoTlsTlsKeyExchange> keyExchange_;
  id<LibOrgBouncycastleCryptoTlsTlsCredentials> serverCredentials_;
  LibOrgBouncycastleCryptoTlsCertificateRequest *certificateRequest_;
  jshort clientCertificateType_;
  LibOrgBouncycastleCryptoTlsCertificate *clientCertificate_;
}

#pragma mark Protected

- (instancetype __nonnull)init;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState, server_, id<LibOrgBouncycastleCryptoTlsTlsServer>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState, serverContext_, LibOrgBouncycastleCryptoTlsTlsServerContextImpl *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState, tlsSession_, id<LibOrgBouncycastleCryptoTlsTlsSession>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState, sessionParameters_, LibOrgBouncycastleCryptoTlsSessionParameters *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState, sessionParametersBuilder_, LibOrgBouncycastleCryptoTlsSessionParameters_Builder *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState, offeredCipherSuites_, IOSIntArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState, offeredCompressionMethods_, IOSShortArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState, clientExtensions_, JavaUtilHashtable *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState, serverExtensions_, JavaUtilHashtable *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState, keyExchange_, id<LibOrgBouncycastleCryptoTlsTlsKeyExchange>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState, serverCredentials_, id<LibOrgBouncycastleCryptoTlsTlsCredentials>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState, certificateRequest_, LibOrgBouncycastleCryptoTlsCertificateRequest *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState, clientCertificate_, LibOrgBouncycastleCryptoTlsCertificate *)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState_init(LibOrgBouncycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState *new_LibOrgBouncycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState *create_LibOrgBouncycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoTlsDTLSServerProtocol_ServerHandshakeState)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // DTLSServerProtocol_H
