//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/com/afterlogic/pgp/key/protection/KeyRingProtectionSettings.java
//

#ifndef KeyRingProtectionSettings_H
#define KeyRingProtectionSettings_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class LibComAfterlogicPgpAlgorithmHashAlgorithmUtil;
@class LibComAfterlogicPgpAlgorithmSymmetricKeyAlgorithm;

@interface LibComAfterlogicPgpKeyProtectionKeyRingProtectionSettings : NSObject

#pragma mark Public

- (instancetype __nonnull)initWithLibComAfterlogicPgpAlgorithmSymmetricKeyAlgorithm:(LibComAfterlogicPgpAlgorithmSymmetricKeyAlgorithm *)encryptionAlgorithm
                                  withLibComAfterlogicPgpAlgorithmHashAlgorithmUtil:(LibComAfterlogicPgpAlgorithmHashAlgorithmUtil *)hashAlgorithmUtil
                                                                            withInt:(jint)s2kCount;

- (LibComAfterlogicPgpAlgorithmSymmetricKeyAlgorithm *)getEncryptionAlgorithm;

- (LibComAfterlogicPgpAlgorithmHashAlgorithmUtil *)getHashAlgorithmUtil;

- (jint)getS2kCount;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibComAfterlogicPgpKeyProtectionKeyRingProtectionSettings)

FOUNDATION_EXPORT void LibComAfterlogicPgpKeyProtectionKeyRingProtectionSettings_initWithLibComAfterlogicPgpAlgorithmSymmetricKeyAlgorithm_withLibComAfterlogicPgpAlgorithmHashAlgorithmUtil_withInt_(LibComAfterlogicPgpKeyProtectionKeyRingProtectionSettings *self, LibComAfterlogicPgpAlgorithmSymmetricKeyAlgorithm *encryptionAlgorithm, LibComAfterlogicPgpAlgorithmHashAlgorithmUtil *hashAlgorithmUtil, jint s2kCount);

FOUNDATION_EXPORT LibComAfterlogicPgpKeyProtectionKeyRingProtectionSettings *new_LibComAfterlogicPgpKeyProtectionKeyRingProtectionSettings_initWithLibComAfterlogicPgpAlgorithmSymmetricKeyAlgorithm_withLibComAfterlogicPgpAlgorithmHashAlgorithmUtil_withInt_(LibComAfterlogicPgpAlgorithmSymmetricKeyAlgorithm *encryptionAlgorithm, LibComAfterlogicPgpAlgorithmHashAlgorithmUtil *hashAlgorithmUtil, jint s2kCount) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibComAfterlogicPgpKeyProtectionKeyRingProtectionSettings *create_LibComAfterlogicPgpKeyProtectionKeyRingProtectionSettings_initWithLibComAfterlogicPgpAlgorithmSymmetricKeyAlgorithm_withLibComAfterlogicPgpAlgorithmHashAlgorithmUtil_withInt_(LibComAfterlogicPgpAlgorithmSymmetricKeyAlgorithm *encryptionAlgorithm, LibComAfterlogicPgpAlgorithmHashAlgorithmUtil *hashAlgorithmUtil, jint s2kCount);

J2OBJC_TYPE_LITERAL_HEADER(LibComAfterlogicPgpKeyProtectionKeyRingProtectionSettings)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // KeyRingProtectionSettings_H
