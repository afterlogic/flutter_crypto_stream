//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/agreement/ECMQVBasicAgreement.java
//

#ifndef ECMQVBasicAgreement_H
#define ECMQVBasicAgreement_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "BasicAgreement.h"
#include "J2ObjC_header.h"

@class JavaMathBigInteger;
@class LibOrgBouncycastleCryptoParamsMQVPrivateParameters;
@protocol LibOrgBouncycastleCryptoCipherParameters;

@interface LibOrgBouncycastleCryptoAgreementECMQVBasicAgreement : NSObject < LibOrgBouncycastleCryptoBasicAgreement > {
 @public
  LibOrgBouncycastleCryptoParamsMQVPrivateParameters *privParams_;
}

#pragma mark Public

- (instancetype __nonnull)init;

- (JavaMathBigInteger *)calculateAgreementWithLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)pubKey;

- (jint)getFieldSize;

- (void)init__WithLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)key OBJC_METHOD_FAMILY_NONE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoAgreementECMQVBasicAgreement)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoAgreementECMQVBasicAgreement, privParams_, LibOrgBouncycastleCryptoParamsMQVPrivateParameters *)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoAgreementECMQVBasicAgreement_init(LibOrgBouncycastleCryptoAgreementECMQVBasicAgreement *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoAgreementECMQVBasicAgreement *new_LibOrgBouncycastleCryptoAgreementECMQVBasicAgreement_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoAgreementECMQVBasicAgreement *create_LibOrgBouncycastleCryptoAgreementECMQVBasicAgreement_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoAgreementECMQVBasicAgreement)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ECMQVBasicAgreement_H
