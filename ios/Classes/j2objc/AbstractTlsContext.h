//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/AbstractTlsContext.java
//

#ifndef AbstractTlsContext_H
#define AbstractTlsContext_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "TlsContext.h"

@class IOSByteArray;
@class JavaSecuritySecureRandom;
@class LibOrgBouncycastleCryptoTlsProtocolVersion;
@class LibOrgBouncycastleCryptoTlsSecurityParameters;
@protocol LibOrgBouncycastleCryptoPrngRandomGenerator;
@protocol LibOrgBouncycastleCryptoTlsTlsSession;

@interface LibOrgBouncycastleCryptoTlsAbstractTlsContext : NSObject < LibOrgBouncycastleCryptoTlsTlsContext >

#pragma mark Public

- (IOSByteArray *)exportKeyingMaterialWithNSString:(NSString *)asciiLabel
                                     withByteArray:(IOSByteArray *)context_value
                                           withInt:(jint)length;

- (LibOrgBouncycastleCryptoTlsProtocolVersion *)getClientVersion;

- (id<LibOrgBouncycastleCryptoPrngRandomGenerator>)getNonceRandomGenerator;

- (id<LibOrgBouncycastleCryptoTlsTlsSession>)getResumableSession;

- (JavaSecuritySecureRandom *)getSecureRandom;

- (LibOrgBouncycastleCryptoTlsSecurityParameters *)getSecurityParameters;

- (LibOrgBouncycastleCryptoTlsProtocolVersion *)getServerVersion;

- (id)getUserObject;

- (void)setUserObjectWithId:(id)userObject;

#pragma mark Package-Private

- (instancetype __nonnull)initWithJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)secureRandom
         withLibOrgBouncycastleCryptoTlsSecurityParameters:(LibOrgBouncycastleCryptoTlsSecurityParameters *)securityParameters;

- (void)setClientVersionWithLibOrgBouncycastleCryptoTlsProtocolVersion:(LibOrgBouncycastleCryptoTlsProtocolVersion *)clientVersion;

- (void)setResumableSessionWithLibOrgBouncycastleCryptoTlsTlsSession:(id<LibOrgBouncycastleCryptoTlsTlsSession>)session;

- (void)setServerVersionWithLibOrgBouncycastleCryptoTlsProtocolVersion:(LibOrgBouncycastleCryptoTlsProtocolVersion *)serverVersion;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleCryptoTlsAbstractTlsContext)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoTlsAbstractTlsContext_initWithJavaSecuritySecureRandom_withLibOrgBouncycastleCryptoTlsSecurityParameters_(LibOrgBouncycastleCryptoTlsAbstractTlsContext *self, JavaSecuritySecureRandom *secureRandom, LibOrgBouncycastleCryptoTlsSecurityParameters *securityParameters);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoTlsAbstractTlsContext)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // AbstractTlsContext_H