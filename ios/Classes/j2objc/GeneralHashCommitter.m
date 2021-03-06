//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/commitments/GeneralHashCommitter.java
//

#include "Arrays.h"
#include "Commitment.h"
#include "DataLengthException.h"
#include "Digest.h"
#include "ExtendedDigest.h"
#include "GeneralHashCommitter.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/security/SecureRandom.h"

@interface LibOrgBouncycastleCryptoCommitmentsGeneralHashCommitter () {
 @public
  id<LibOrgBouncycastleCryptoDigest> digest_;
  jint byteLength_;
  JavaSecuritySecureRandom *random_;
}

- (IOSByteArray *)calculateCommitmentWithByteArray:(IOSByteArray *)w
                                     withByteArray:(IOSByteArray *)message;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoCommitmentsGeneralHashCommitter, digest_, id<LibOrgBouncycastleCryptoDigest>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoCommitmentsGeneralHashCommitter, random_, JavaSecuritySecureRandom *)

__attribute__((unused)) static IOSByteArray *LibOrgBouncycastleCryptoCommitmentsGeneralHashCommitter_calculateCommitmentWithByteArray_withByteArray_(LibOrgBouncycastleCryptoCommitmentsGeneralHashCommitter *self, IOSByteArray *w, IOSByteArray *message);

@implementation LibOrgBouncycastleCryptoCommitmentsGeneralHashCommitter

- (instancetype)initWithLibOrgBouncycastleCryptoExtendedDigest:(id<LibOrgBouncycastleCryptoExtendedDigest>)digest
                                  withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random {
  LibOrgBouncycastleCryptoCommitmentsGeneralHashCommitter_initWithLibOrgBouncycastleCryptoExtendedDigest_withJavaSecuritySecureRandom_(self, digest, random);
  return self;
}

- (LibOrgBouncycastleCryptoCommitment *)commitWithByteArray:(IOSByteArray *)message {
  if (((IOSByteArray *) nil_chk(message))->size_ > byteLength_ / 2) {
    @throw new_LibOrgBouncycastleCryptoDataLengthException_initWithNSString_(@"Message to be committed to too large for digest.");
  }
  IOSByteArray *w = [IOSByteArray newArrayWithLength:byteLength_ - message->size_];
  [((JavaSecuritySecureRandom *) nil_chk(random_)) nextBytesWithByteArray:w];
  return new_LibOrgBouncycastleCryptoCommitment_initWithByteArray_withByteArray_(w, LibOrgBouncycastleCryptoCommitmentsGeneralHashCommitter_calculateCommitmentWithByteArray_withByteArray_(self, w, message));
}

- (jboolean)isRevealedWithLibOrgBouncycastleCryptoCommitment:(LibOrgBouncycastleCryptoCommitment *)commitment
                                               withByteArray:(IOSByteArray *)message {
  if (((IOSByteArray *) nil_chk(message))->size_ + ((IOSByteArray *) nil_chk([((LibOrgBouncycastleCryptoCommitment *) nil_chk(commitment)) getSecret]))->size_ != byteLength_) {
    @throw new_LibOrgBouncycastleCryptoDataLengthException_initWithNSString_(@"Message and witness secret lengths do not match.");
  }
  IOSByteArray *calcCommitment = LibOrgBouncycastleCryptoCommitmentsGeneralHashCommitter_calculateCommitmentWithByteArray_withByteArray_(self, [commitment getSecret], message);
  return LibOrgBouncycastleUtilArrays_constantTimeAreEqualWithByteArray_withByteArray_([commitment getCommitment], calcCommitment);
}

- (IOSByteArray *)calculateCommitmentWithByteArray:(IOSByteArray *)w
                                     withByteArray:(IOSByteArray *)message {
  return LibOrgBouncycastleCryptoCommitmentsGeneralHashCommitter_calculateCommitmentWithByteArray_withByteArray_(self, w, message);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoCommitment;", 0x1, 1, 2, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 3, 4, -1, -1, -1, -1 },
    { NULL, "[B", 0x2, 5, 6, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleCryptoExtendedDigest:withJavaSecuritySecureRandom:);
  methods[1].selector = @selector(commitWithByteArray:);
  methods[2].selector = @selector(isRevealedWithLibOrgBouncycastleCryptoCommitment:withByteArray:);
  methods[3].selector = @selector(calculateCommitmentWithByteArray:withByteArray:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "digest_", "LLibOrgBouncycastleCryptoDigest;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "byteLength_", "I", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "random_", "LJavaSecuritySecureRandom;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleCryptoExtendedDigest;LJavaSecuritySecureRandom;", "commit", "[B", "isRevealed", "LLibOrgBouncycastleCryptoCommitment;[B", "calculateCommitment", "[B[B" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoCommitmentsGeneralHashCommitter = { "GeneralHashCommitter", "lib.org.bouncycastle.crypto.commitments", ptrTable, methods, fields, 7, 0x1, 4, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoCommitmentsGeneralHashCommitter;
}

@end

void LibOrgBouncycastleCryptoCommitmentsGeneralHashCommitter_initWithLibOrgBouncycastleCryptoExtendedDigest_withJavaSecuritySecureRandom_(LibOrgBouncycastleCryptoCommitmentsGeneralHashCommitter *self, id<LibOrgBouncycastleCryptoExtendedDigest> digest, JavaSecuritySecureRandom *random) {
  NSObject_init(self);
  self->digest_ = digest;
  self->byteLength_ = [((id<LibOrgBouncycastleCryptoExtendedDigest>) nil_chk(digest)) getByteLength];
  self->random_ = random;
}

LibOrgBouncycastleCryptoCommitmentsGeneralHashCommitter *new_LibOrgBouncycastleCryptoCommitmentsGeneralHashCommitter_initWithLibOrgBouncycastleCryptoExtendedDigest_withJavaSecuritySecureRandom_(id<LibOrgBouncycastleCryptoExtendedDigest> digest, JavaSecuritySecureRandom *random) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoCommitmentsGeneralHashCommitter, initWithLibOrgBouncycastleCryptoExtendedDigest_withJavaSecuritySecureRandom_, digest, random)
}

LibOrgBouncycastleCryptoCommitmentsGeneralHashCommitter *create_LibOrgBouncycastleCryptoCommitmentsGeneralHashCommitter_initWithLibOrgBouncycastleCryptoExtendedDigest_withJavaSecuritySecureRandom_(id<LibOrgBouncycastleCryptoExtendedDigest> digest, JavaSecuritySecureRandom *random) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoCommitmentsGeneralHashCommitter, initWithLibOrgBouncycastleCryptoExtendedDigest_withJavaSecuritySecureRandom_, digest, random)
}

IOSByteArray *LibOrgBouncycastleCryptoCommitmentsGeneralHashCommitter_calculateCommitmentWithByteArray_withByteArray_(LibOrgBouncycastleCryptoCommitmentsGeneralHashCommitter *self, IOSByteArray *w, IOSByteArray *message) {
  IOSByteArray *commitment = [IOSByteArray newArrayWithLength:[((id<LibOrgBouncycastleCryptoDigest>) nil_chk(self->digest_)) getDigestSize]];
  [self->digest_ updateWithByteArray:w withInt:0 withInt:((IOSByteArray *) nil_chk(w))->size_];
  [self->digest_ updateWithByteArray:message withInt:0 withInt:((IOSByteArray *) nil_chk(message))->size_];
  [self->digest_ updateWithByte:(jbyte) ((JreURShift32(message->size_, 8)))];
  [self->digest_ updateWithByte:(jbyte) (message->size_)];
  [self->digest_ doFinalWithByteArray:commitment withInt:0];
  return commitment;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoCommitmentsGeneralHashCommitter)
