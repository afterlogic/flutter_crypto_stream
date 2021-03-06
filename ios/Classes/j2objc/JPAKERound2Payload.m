//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/agreement/jpake/JPAKERound2Payload.java
//

#include "Arrays.h"
#include "IOSObjectArray.h"
#include "J2ObjC_source.h"
#include "JPAKERound2Payload.h"
#include "JPAKEUtil.h"
#include "java/math/BigInteger.h"

@interface LibOrgBouncycastleCryptoAgreementJpakeJPAKERound2Payload () {
 @public
  NSString *participantId_;
  JavaMathBigInteger *a_;
  IOSObjectArray *knowledgeProofForX2s_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoAgreementJpakeJPAKERound2Payload, participantId_, NSString *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoAgreementJpakeJPAKERound2Payload, a_, JavaMathBigInteger *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoAgreementJpakeJPAKERound2Payload, knowledgeProofForX2s_, IOSObjectArray *)

@implementation LibOrgBouncycastleCryptoAgreementJpakeJPAKERound2Payload

- (instancetype)initWithNSString:(NSString *)participantId
          withJavaMathBigInteger:(JavaMathBigInteger *)a
     withJavaMathBigIntegerArray:(IOSObjectArray *)knowledgeProofForX2s {
  LibOrgBouncycastleCryptoAgreementJpakeJPAKERound2Payload_initWithNSString_withJavaMathBigInteger_withJavaMathBigIntegerArray_(self, participantId, a, knowledgeProofForX2s);
  return self;
}

- (NSString *)getParticipantId {
  return participantId_;
}

- (JavaMathBigInteger *)getA {
  return a_;
}

- (IOSObjectArray *)getKnowledgeProofForX2s {
  return LibOrgBouncycastleUtilArrays_copyOfWithJavaMathBigIntegerArray_withInt_(knowledgeProofForX2s_, ((IOSObjectArray *) nil_chk(knowledgeProofForX2s_))->size_);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithNSString:withJavaMathBigInteger:withJavaMathBigIntegerArray:);
  methods[1].selector = @selector(getParticipantId);
  methods[2].selector = @selector(getA);
  methods[3].selector = @selector(getKnowledgeProofForX2s);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "participantId_", "LNSString;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "a_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "knowledgeProofForX2s_", "[LJavaMathBigInteger;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LNSString;LJavaMathBigInteger;[LJavaMathBigInteger;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoAgreementJpakeJPAKERound2Payload = { "JPAKERound2Payload", "lib.org.bouncycastle.crypto.agreement.jpake", ptrTable, methods, fields, 7, 0x1, 4, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoAgreementJpakeJPAKERound2Payload;
}

@end

void LibOrgBouncycastleCryptoAgreementJpakeJPAKERound2Payload_initWithNSString_withJavaMathBigInteger_withJavaMathBigIntegerArray_(LibOrgBouncycastleCryptoAgreementJpakeJPAKERound2Payload *self, NSString *participantId, JavaMathBigInteger *a, IOSObjectArray *knowledgeProofForX2s) {
  NSObject_init(self);
  LibOrgBouncycastleCryptoAgreementJpakeJPAKEUtil_validateNotNullWithId_withNSString_(participantId, @"participantId");
  LibOrgBouncycastleCryptoAgreementJpakeJPAKEUtil_validateNotNullWithId_withNSString_(a, @"a");
  LibOrgBouncycastleCryptoAgreementJpakeJPAKEUtil_validateNotNullWithId_withNSString_(knowledgeProofForX2s, @"knowledgeProofForX2s");
  self->participantId_ = participantId;
  self->a_ = a;
  self->knowledgeProofForX2s_ = LibOrgBouncycastleUtilArrays_copyOfWithJavaMathBigIntegerArray_withInt_(knowledgeProofForX2s, ((IOSObjectArray *) nil_chk(knowledgeProofForX2s))->size_);
}

LibOrgBouncycastleCryptoAgreementJpakeJPAKERound2Payload *new_LibOrgBouncycastleCryptoAgreementJpakeJPAKERound2Payload_initWithNSString_withJavaMathBigInteger_withJavaMathBigIntegerArray_(NSString *participantId, JavaMathBigInteger *a, IOSObjectArray *knowledgeProofForX2s) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoAgreementJpakeJPAKERound2Payload, initWithNSString_withJavaMathBigInteger_withJavaMathBigIntegerArray_, participantId, a, knowledgeProofForX2s)
}

LibOrgBouncycastleCryptoAgreementJpakeJPAKERound2Payload *create_LibOrgBouncycastleCryptoAgreementJpakeJPAKERound2Payload_initWithNSString_withJavaMathBigInteger_withJavaMathBigIntegerArray_(NSString *participantId, JavaMathBigInteger *a, IOSObjectArray *knowledgeProofForX2s) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoAgreementJpakeJPAKERound2Payload, initWithNSString_withJavaMathBigInteger_withJavaMathBigIntegerArray_, participantId, a, knowledgeProofForX2s)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoAgreementJpakeJPAKERound2Payload)
