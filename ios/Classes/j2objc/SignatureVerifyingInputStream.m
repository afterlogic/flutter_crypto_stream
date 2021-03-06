//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/com/afterlogic/pgp/decryption_verification/SignatureVerifyingInputStream.java
//

#include "IOSClass.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "OpenPgpMetadata.h"
#include "OpenPgpV4Fingerprint.h"
#include "PGPException.h"
#include "PGPObjectFactory.h"
#include "PGPOnePassSignature.h"
#include "PGPSignature.h"
#include "PGPSignatureList.h"
#include "SignatureVerifyingInputStream.h"
#include "java/io/FilterInputStream.h"
#include "java/io/IOException.h"
#include "java/io/InputStream.h"
#include "java/lang/Long.h"
#include "java/lang/UnsupportedOperationException.h"
#include "java/security/SignatureException.h"
#include "java/util/Collection.h"
#include "java/util/Map.h"
#include "java/util/Set.h"
#include "java/util/logging/Level.h"
#include "java/util/logging/Logger.h"

@interface LibComAfterlogicPgpDecryption_verificationSignatureVerifyingInputStream () {
 @public
  LibOrgBouncycastleOpenpgpPGPObjectFactory *objectFactory_;
  id<JavaUtilMap> onePassSignatures_;
  LibComAfterlogicPgpDecryption_verificationOpenPgpMetadata_Builder *resultBuilder_;
  jboolean validated_;
}

- (void)updateOnePassSignaturesWithByte:(jbyte)data;

- (void)updateOnePassSignaturesWithByteArray:(IOSByteArray *)b
                                     withInt:(jint)off
                                     withInt:(jint)len;

- (void)validateOnePassSignatures;

@end

J2OBJC_FIELD_SETTER(LibComAfterlogicPgpDecryption_verificationSignatureVerifyingInputStream, objectFactory_, LibOrgBouncycastleOpenpgpPGPObjectFactory *)
J2OBJC_FIELD_SETTER(LibComAfterlogicPgpDecryption_verificationSignatureVerifyingInputStream, onePassSignatures_, id<JavaUtilMap>)
J2OBJC_FIELD_SETTER(LibComAfterlogicPgpDecryption_verificationSignatureVerifyingInputStream, resultBuilder_, LibComAfterlogicPgpDecryption_verificationOpenPgpMetadata_Builder *)

inline JavaUtilLoggingLogger *LibComAfterlogicPgpDecryption_verificationSignatureVerifyingInputStream_get_LOGGER(void);
static JavaUtilLoggingLogger *LibComAfterlogicPgpDecryption_verificationSignatureVerifyingInputStream_LOGGER;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibComAfterlogicPgpDecryption_verificationSignatureVerifyingInputStream, LOGGER, JavaUtilLoggingLogger *)

inline JavaUtilLoggingLevel *LibComAfterlogicPgpDecryption_verificationSignatureVerifyingInputStream_get_LEVEL(void);
static JavaUtilLoggingLevel *LibComAfterlogicPgpDecryption_verificationSignatureVerifyingInputStream_LEVEL;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibComAfterlogicPgpDecryption_verificationSignatureVerifyingInputStream, LEVEL, JavaUtilLoggingLevel *)

__attribute__((unused)) static void LibComAfterlogicPgpDecryption_verificationSignatureVerifyingInputStream_updateOnePassSignaturesWithByte_(LibComAfterlogicPgpDecryption_verificationSignatureVerifyingInputStream *self, jbyte data);

__attribute__((unused)) static void LibComAfterlogicPgpDecryption_verificationSignatureVerifyingInputStream_updateOnePassSignaturesWithByteArray_withInt_withInt_(LibComAfterlogicPgpDecryption_verificationSignatureVerifyingInputStream *self, IOSByteArray *b, jint off, jint len);

__attribute__((unused)) static void LibComAfterlogicPgpDecryption_verificationSignatureVerifyingInputStream_validateOnePassSignatures(LibComAfterlogicPgpDecryption_verificationSignatureVerifyingInputStream *self);

J2OBJC_INITIALIZED_DEFN(LibComAfterlogicPgpDecryption_verificationSignatureVerifyingInputStream)

@implementation LibComAfterlogicPgpDecryption_verificationSignatureVerifyingInputStream

- (instancetype)initWithJavaIoInputStream:(JavaIoInputStream *)inputStream
withLibOrgBouncycastleOpenpgpPGPObjectFactory:(LibOrgBouncycastleOpenpgpPGPObjectFactory *)objectFactory
                          withJavaUtilMap:(id<JavaUtilMap>)onePassSignatures
withLibComAfterlogicPgpDecryption_verificationOpenPgpMetadata_Builder:(LibComAfterlogicPgpDecryption_verificationOpenPgpMetadata_Builder *)resultBuilder {
  LibComAfterlogicPgpDecryption_verificationSignatureVerifyingInputStream_initWithJavaIoInputStream_withLibOrgBouncycastleOpenpgpPGPObjectFactory_withJavaUtilMap_withLibComAfterlogicPgpDecryption_verificationOpenPgpMetadata_Builder_(self, inputStream, objectFactory, onePassSignatures, resultBuilder);
  return self;
}

- (void)updateOnePassSignaturesWithByte:(jbyte)data {
  LibComAfterlogicPgpDecryption_verificationSignatureVerifyingInputStream_updateOnePassSignaturesWithByte_(self, data);
}

- (void)updateOnePassSignaturesWithByteArray:(IOSByteArray *)b
                                     withInt:(jint)off
                                     withInt:(jint)len {
  LibComAfterlogicPgpDecryption_verificationSignatureVerifyingInputStream_updateOnePassSignaturesWithByteArray_withInt_withInt_(self, b, off, len);
}

- (void)validateOnePassSignatures {
  LibComAfterlogicPgpDecryption_verificationSignatureVerifyingInputStream_validateOnePassSignatures(self);
}

- (jint)read {
  jint data = [super read];
  jboolean endOfStream = data == -1;
  if (endOfStream) {
    LibComAfterlogicPgpDecryption_verificationSignatureVerifyingInputStream_validateOnePassSignatures(self);
  }
  else {
    LibComAfterlogicPgpDecryption_verificationSignatureVerifyingInputStream_updateOnePassSignaturesWithByte_(self, (jbyte) data);
  }
  return data;
}

- (jint)readWithByteArray:(IOSByteArray *)b {
  return [self readWithByteArray:b withInt:0 withInt:((IOSByteArray *) nil_chk(b))->size_];
}

- (jint)readWithByteArray:(IOSByteArray *)b
                  withInt:(jint)off
                  withInt:(jint)len {
  jint read = [super readWithByteArray:b withInt:off withInt:len];
  jboolean endOfStream = read == -1;
  if (endOfStream) {
    LibComAfterlogicPgpDecryption_verificationSignatureVerifyingInputStream_validateOnePassSignatures(self);
  }
  else {
    LibComAfterlogicPgpDecryption_verificationSignatureVerifyingInputStream_updateOnePassSignaturesWithByteArray_withInt_withInt_(self, b, off, read);
  }
  return read;
}

- (jlong)skipWithLong:(jlong)n {
  @throw new_JavaLangUnsupportedOperationException_initWithNSString_(@"skip() is not supported");
}

- (void)markWithInt:(jint)readlimit {
  @synchronized(self) {
    @throw new_JavaLangUnsupportedOperationException_initWithNSString_(@"mark() not supported");
  }
}

- (void)reset {
  @synchronized(self) {
    @throw new_JavaLangUnsupportedOperationException_initWithNSString_(@"reset() is not supported");
  }
}

- (jboolean)markSupported {
  return false;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x4, -1, 0, -1, 1, -1, -1 },
    { NULL, "V", 0x2, 2, 3, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 2, 4, -1, -1, -1, -1 },
    { NULL, "V", 0x2, -1, -1, 5, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, 5, -1, -1, -1 },
    { NULL, "I", 0x1, 6, 7, 5, -1, -1, -1 },
    { NULL, "I", 0x1, 6, 4, 5, -1, -1, -1 },
    { NULL, "J", 0x1, 8, 9, -1, -1, -1, -1 },
    { NULL, "V", 0x21, 10, 11, -1, -1, -1, -1 },
    { NULL, "V", 0x21, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithJavaIoInputStream:withLibOrgBouncycastleOpenpgpPGPObjectFactory:withJavaUtilMap:withLibComAfterlogicPgpDecryption_verificationOpenPgpMetadata_Builder:);
  methods[1].selector = @selector(updateOnePassSignaturesWithByte:);
  methods[2].selector = @selector(updateOnePassSignaturesWithByteArray:withInt:withInt:);
  methods[3].selector = @selector(validateOnePassSignatures);
  methods[4].selector = @selector(read);
  methods[5].selector = @selector(readWithByteArray:);
  methods[6].selector = @selector(readWithByteArray:withInt:withInt:);
  methods[7].selector = @selector(skipWithLong:);
  methods[8].selector = @selector(markWithInt:);
  methods[9].selector = @selector(reset);
  methods[10].selector = @selector(markSupported);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "LOGGER", "LJavaUtilLoggingLogger;", .constantValue.asLong = 0, 0x1a, -1, 12, -1, -1 },
    { "LEVEL", "LJavaUtilLoggingLevel;", .constantValue.asLong = 0, 0x1a, -1, 13, -1, -1 },
    { "objectFactory_", "LLibOrgBouncycastleOpenpgpPGPObjectFactory;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "onePassSignatures_", "LJavaUtilMap;", .constantValue.asLong = 0, 0x12, -1, -1, 14, -1 },
    { "resultBuilder_", "LLibComAfterlogicPgpDecryption_verificationOpenPgpMetadata_Builder;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "validated_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaIoInputStream;LLibOrgBouncycastleOpenpgpPGPObjectFactory;LJavaUtilMap;LLibComAfterlogicPgpDecryption_verificationOpenPgpMetadata_Builder;", "(Ljava/io/InputStream;Llib/org/bouncycastle/openpgp/PGPObjectFactory;Ljava/util/Map<Llib/com/afterlogic/pgp/key/OpenPgpV4Fingerprint;Llib/org/bouncycastle/openpgp/PGPOnePassSignature;>;Llib/com/afterlogic/pgp/decryption_verification/OpenPgpMetadata$Builder;)V", "updateOnePassSignatures", "B", "[BII", "LJavaIoIOException;", "read", "[B", "skip", "J", "mark", "I", &LibComAfterlogicPgpDecryption_verificationSignatureVerifyingInputStream_LOGGER, &LibComAfterlogicPgpDecryption_verificationSignatureVerifyingInputStream_LEVEL, "Ljava/util/Map<Llib/com/afterlogic/pgp/key/OpenPgpV4Fingerprint;Llib/org/bouncycastle/openpgp/PGPOnePassSignature;>;" };
  static const J2ObjcClassInfo _LibComAfterlogicPgpDecryption_verificationSignatureVerifyingInputStream = { "SignatureVerifyingInputStream", "lib.com.afterlogic.pgp.decryption_verification", ptrTable, methods, fields, 7, 0x1, 11, 6, -1, -1, -1, -1, -1 };
  return &_LibComAfterlogicPgpDecryption_verificationSignatureVerifyingInputStream;
}

+ (void)initialize {
  if (self == [LibComAfterlogicPgpDecryption_verificationSignatureVerifyingInputStream class]) {
    LibComAfterlogicPgpDecryption_verificationSignatureVerifyingInputStream_LOGGER = JavaUtilLoggingLogger_getLoggerWithNSString_([LibComAfterlogicPgpDecryption_verificationSignatureVerifyingInputStream_class_() getName]);
    LibComAfterlogicPgpDecryption_verificationSignatureVerifyingInputStream_LEVEL = JreLoadStatic(JavaUtilLoggingLevel, FINE);
    J2OBJC_SET_INITIALIZED(LibComAfterlogicPgpDecryption_verificationSignatureVerifyingInputStream)
  }
}

@end

void LibComAfterlogicPgpDecryption_verificationSignatureVerifyingInputStream_initWithJavaIoInputStream_withLibOrgBouncycastleOpenpgpPGPObjectFactory_withJavaUtilMap_withLibComAfterlogicPgpDecryption_verificationOpenPgpMetadata_Builder_(LibComAfterlogicPgpDecryption_verificationSignatureVerifyingInputStream *self, JavaIoInputStream *inputStream, LibOrgBouncycastleOpenpgpPGPObjectFactory *objectFactory, id<JavaUtilMap> onePassSignatures, LibComAfterlogicPgpDecryption_verificationOpenPgpMetadata_Builder *resultBuilder) {
  JavaIoFilterInputStream_initWithJavaIoInputStream_(self, inputStream);
  self->validated_ = false;
  self->objectFactory_ = objectFactory;
  self->resultBuilder_ = resultBuilder;
  self->onePassSignatures_ = onePassSignatures;
  [((JavaUtilLoggingLogger *) nil_chk(LibComAfterlogicPgpDecryption_verificationSignatureVerifyingInputStream_LOGGER)) logWithJavaUtilLoggingLevel:LibComAfterlogicPgpDecryption_verificationSignatureVerifyingInputStream_LEVEL withNSString:@"Begin verifying OnePassSignatures"];
}

LibComAfterlogicPgpDecryption_verificationSignatureVerifyingInputStream *new_LibComAfterlogicPgpDecryption_verificationSignatureVerifyingInputStream_initWithJavaIoInputStream_withLibOrgBouncycastleOpenpgpPGPObjectFactory_withJavaUtilMap_withLibComAfterlogicPgpDecryption_verificationOpenPgpMetadata_Builder_(JavaIoInputStream *inputStream, LibOrgBouncycastleOpenpgpPGPObjectFactory *objectFactory, id<JavaUtilMap> onePassSignatures, LibComAfterlogicPgpDecryption_verificationOpenPgpMetadata_Builder *resultBuilder) {
  J2OBJC_NEW_IMPL(LibComAfterlogicPgpDecryption_verificationSignatureVerifyingInputStream, initWithJavaIoInputStream_withLibOrgBouncycastleOpenpgpPGPObjectFactory_withJavaUtilMap_withLibComAfterlogicPgpDecryption_verificationOpenPgpMetadata_Builder_, inputStream, objectFactory, onePassSignatures, resultBuilder)
}

LibComAfterlogicPgpDecryption_verificationSignatureVerifyingInputStream *create_LibComAfterlogicPgpDecryption_verificationSignatureVerifyingInputStream_initWithJavaIoInputStream_withLibOrgBouncycastleOpenpgpPGPObjectFactory_withJavaUtilMap_withLibComAfterlogicPgpDecryption_verificationOpenPgpMetadata_Builder_(JavaIoInputStream *inputStream, LibOrgBouncycastleOpenpgpPGPObjectFactory *objectFactory, id<JavaUtilMap> onePassSignatures, LibComAfterlogicPgpDecryption_verificationOpenPgpMetadata_Builder *resultBuilder) {
  J2OBJC_CREATE_IMPL(LibComAfterlogicPgpDecryption_verificationSignatureVerifyingInputStream, initWithJavaIoInputStream_withLibOrgBouncycastleOpenpgpPGPObjectFactory_withJavaUtilMap_withLibComAfterlogicPgpDecryption_verificationOpenPgpMetadata_Builder_, inputStream, objectFactory, onePassSignatures, resultBuilder)
}

void LibComAfterlogicPgpDecryption_verificationSignatureVerifyingInputStream_updateOnePassSignaturesWithByte_(LibComAfterlogicPgpDecryption_verificationSignatureVerifyingInputStream *self, jbyte data) {
  for (LibOrgBouncycastleOpenpgpPGPOnePassSignature * __strong signature in nil_chk([((id<JavaUtilMap>) nil_chk(self->onePassSignatures_)) values])) {
    [((LibOrgBouncycastleOpenpgpPGPOnePassSignature *) nil_chk(signature)) updateWithByte:data];
  }
}

void LibComAfterlogicPgpDecryption_verificationSignatureVerifyingInputStream_updateOnePassSignaturesWithByteArray_withInt_withInt_(LibComAfterlogicPgpDecryption_verificationSignatureVerifyingInputStream *self, IOSByteArray *b, jint off, jint len) {
  for (LibOrgBouncycastleOpenpgpPGPOnePassSignature * __strong signature in nil_chk([((id<JavaUtilMap>) nil_chk(self->onePassSignatures_)) values])) {
    [((LibOrgBouncycastleOpenpgpPGPOnePassSignature *) nil_chk(signature)) updateWithByteArray:b withInt:off withInt:len];
  }
}

void LibComAfterlogicPgpDecryption_verificationSignatureVerifyingInputStream_validateOnePassSignatures(LibComAfterlogicPgpDecryption_verificationSignatureVerifyingInputStream *self) {
  if (self->validated_) {
    [((JavaUtilLoggingLogger *) nil_chk(LibComAfterlogicPgpDecryption_verificationSignatureVerifyingInputStream_LOGGER)) logWithJavaUtilLoggingLevel:LibComAfterlogicPgpDecryption_verificationSignatureVerifyingInputStream_LEVEL withNSString:@"Validated signatures already. Skip"];
    return;
  }
  self->validated_ = true;
  if ([((id<JavaUtilMap>) nil_chk(self->onePassSignatures_)) isEmpty]) {
    [((JavaUtilLoggingLogger *) nil_chk(LibComAfterlogicPgpDecryption_verificationSignatureVerifyingInputStream_LOGGER)) logWithJavaUtilLoggingLevel:LibComAfterlogicPgpDecryption_verificationSignatureVerifyingInputStream_LEVEL withNSString:@"No One-Pass-Signatures found -> No validation"];
    return;
  }
  @try {
    LibOrgBouncycastleOpenpgpPGPSignatureList *signatureList = nil;
    id obj = [((LibOrgBouncycastleOpenpgpPGPObjectFactory *) nil_chk(self->objectFactory_)) nextObject];
    while (obj != nil && signatureList == nil) {
      if ([obj isKindOfClass:[LibOrgBouncycastleOpenpgpPGPSignatureList class]]) {
        signatureList = (LibOrgBouncycastleOpenpgpPGPSignatureList *) obj;
      }
      else {
        obj = [self->objectFactory_ nextObject];
      }
    }
    if (signatureList == nil || [signatureList isEmpty]) {
      @throw new_JavaIoIOException_initWithNSString_(@"Verification failed - No Signatures found");
    }
    for (LibOrgBouncycastleOpenpgpPGPSignature * __strong signature in signatureList) {
      LibComAfterlogicPgpKeyOpenPgpV4Fingerprint *fingerprint = nil;
      for (LibComAfterlogicPgpKeyOpenPgpV4Fingerprint * __strong f in nil_chk([self->onePassSignatures_ keySet])) {
        if ([((LibComAfterlogicPgpKeyOpenPgpV4Fingerprint *) nil_chk(f)) getKeyId] == [((LibOrgBouncycastleOpenpgpPGPSignature *) nil_chk(signature)) getKeyID]) {
          fingerprint = f;
          break;
        }
      }
      LibOrgBouncycastleOpenpgpPGPOnePassSignature *onePassSignature;
      if (fingerprint == nil || (onePassSignature = [self->onePassSignatures_ getWithId:fingerprint]) == nil) {
        [((JavaUtilLoggingLogger *) nil_chk(LibComAfterlogicPgpDecryption_verificationSignatureVerifyingInputStream_LOGGER)) logWithJavaUtilLoggingLevel:LibComAfterlogicPgpDecryption_verificationSignatureVerifyingInputStream_LEVEL withNSString:@"Found Signature without respective OnePassSignature packet -> skip"];
        continue;
      }
      if (![((LibOrgBouncycastleOpenpgpPGPOnePassSignature *) nil_chk(onePassSignature)) verifyWithLibOrgBouncycastleOpenpgpPGPSignature:signature]) {
        @throw new_JavaSecuritySignatureException_initWithNSString_(JreStrcat("$J", @"Bad Signature of key ", [((LibOrgBouncycastleOpenpgpPGPSignature *) nil_chk(signature)) getKeyID]));
      }
      else {
        [((JavaUtilLoggingLogger *) nil_chk(LibComAfterlogicPgpDecryption_verificationSignatureVerifyingInputStream_LOGGER)) logWithJavaUtilLoggingLevel:LibComAfterlogicPgpDecryption_verificationSignatureVerifyingInputStream_LEVEL withNSString:JreStrcat("$$", @"Verified signature of key ", JavaLangLong_toHexStringWithLong_([((LibOrgBouncycastleOpenpgpPGPSignature *) nil_chk(signature)) getKeyID]))];
        (void) [((LibComAfterlogicPgpDecryption_verificationOpenPgpMetadata_Builder *) nil_chk(self->resultBuilder_)) addVerifiedSignatureFingerprintWithLibComAfterlogicPgpKeyOpenPgpV4Fingerprint:fingerprint];
      }
    }
  }
  @catch (LibOrgBouncycastleOpenpgpPGPException *e) {
    @throw new_JavaIoIOException_initWithNSString_withJavaLangThrowable_([e getMessage], e);
  }
  @catch (JavaSecuritySignatureException *e) {
    @throw new_JavaIoIOException_initWithNSString_withJavaLangThrowable_([e getMessage], e);
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibComAfterlogicPgpDecryption_verificationSignatureVerifyingInputStream)
