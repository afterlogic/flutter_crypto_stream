//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/openpgp/examples/ClearSignedFileProcessor.java
//

#include "ArmoredInputStream.h"
#include "ArmoredOutputStream.h"
#include "BCPGOutputStream.h"
#include "BouncyCastleProvider.h"
#include "ClearSignedFileProcessor.h"
#include "HashAlgorithmTags.h"
#include "IOSObjectArray.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "JcaKeyFingerprintCalculator.h"
#include "JcaPGPContentSignerBuilder.h"
#include "JcaPGPContentVerifierBuilderProvider.h"
#include "JcaPGPObjectFactory.h"
#include "JcePBESecretKeyDecryptorBuilder.h"
#include "PBESecretKeyDecryptor.h"
#include "PGPExampleUtil.h"
#include "PGPPrivateKey.h"
#include "PGPPublicKey.h"
#include "PGPPublicKeyRingCollection.h"
#include "PGPSecretKey.h"
#include "PGPSignature.h"
#include "PGPSignatureGenerator.h"
#include "PGPSignatureList.h"
#include "PGPSignatureSubpacketGenerator.h"
#include "PGPSignatureSubpacketVector.h"
#include "PGPUtil.h"
#include "Strings.h"
#include "java/io/BufferedInputStream.h"
#include "java/io/BufferedOutputStream.h"
#include "java/io/ByteArrayOutputStream.h"
#include "java/io/FileInputStream.h"
#include "java/io/FileOutputStream.h"
#include "java/io/InputStream.h"
#include "java/io/OutputStream.h"
#include "java/io/PrintStream.h"
#include "java/lang/System.h"
#include "java/security/Security.h"
#include "java/util/Iterator.h"

@interface LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor ()

+ (jint)readInputLineWithJavaIoByteArrayOutputStream:(JavaIoByteArrayOutputStream *)bOut
                               withJavaIoInputStream:(JavaIoInputStream *)fIn;

+ (jint)readInputLineWithJavaIoByteArrayOutputStream:(JavaIoByteArrayOutputStream *)bOut
                                             withInt:(jint)lookAhead
                               withJavaIoInputStream:(JavaIoInputStream *)fIn;

+ (jint)readPassedEOLWithJavaIoByteArrayOutputStream:(JavaIoByteArrayOutputStream *)bOut
                                             withInt:(jint)lastCh
                               withJavaIoInputStream:(JavaIoInputStream *)fIn;

+ (void)verifyFileWithJavaIoInputStream:(JavaIoInputStream *)inArg
                  withJavaIoInputStream:(JavaIoInputStream *)keyIn
                           withNSString:(NSString *)resultName;

+ (IOSByteArray *)getLineSeparator;

+ (void)signFileWithNSString:(NSString *)fileName
       withJavaIoInputStream:(JavaIoInputStream *)keyIn
      withJavaIoOutputStream:(JavaIoOutputStream *)outArg
               withCharArray:(IOSCharArray *)pass
                withNSString:(NSString *)digestName;

+ (void)processLineWithLibOrgBouncycastleOpenpgpPGPSignature:(LibOrgBouncycastleOpenpgpPGPSignature *)sig
                                               withByteArray:(IOSByteArray *)line;

+ (void)processLineWithJavaIoOutputStream:(JavaIoOutputStream *)aOut
withLibOrgBouncycastleOpenpgpPGPSignatureGenerator:(LibOrgBouncycastleOpenpgpPGPSignatureGenerator *)sGen
                            withByteArray:(IOSByteArray *)line;

+ (jint)getLengthWithoutSeparatorOrTrailingWhitespaceWithByteArray:(IOSByteArray *)line;

+ (jboolean)isLineEndingWithByte:(jbyte)b;

+ (jint)getLengthWithoutWhiteSpaceWithByteArray:(IOSByteArray *)line;

+ (jboolean)isWhiteSpaceWithByte:(jbyte)b;

@end

__attribute__((unused)) static jint LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_readInputLineWithJavaIoByteArrayOutputStream_withJavaIoInputStream_(JavaIoByteArrayOutputStream *bOut, JavaIoInputStream *fIn);

__attribute__((unused)) static jint LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_readInputLineWithJavaIoByteArrayOutputStream_withInt_withJavaIoInputStream_(JavaIoByteArrayOutputStream *bOut, jint lookAhead, JavaIoInputStream *fIn);

__attribute__((unused)) static jint LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_readPassedEOLWithJavaIoByteArrayOutputStream_withInt_withJavaIoInputStream_(JavaIoByteArrayOutputStream *bOut, jint lastCh, JavaIoInputStream *fIn);

__attribute__((unused)) static void LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_verifyFileWithJavaIoInputStream_withJavaIoInputStream_withNSString_(JavaIoInputStream *inArg, JavaIoInputStream *keyIn, NSString *resultName);

__attribute__((unused)) static IOSByteArray *LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_getLineSeparator(void);

__attribute__((unused)) static void LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_signFileWithNSString_withJavaIoInputStream_withJavaIoOutputStream_withCharArray_withNSString_(NSString *fileName, JavaIoInputStream *keyIn, JavaIoOutputStream *outArg, IOSCharArray *pass, NSString *digestName);

__attribute__((unused)) static void LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_processLineWithLibOrgBouncycastleOpenpgpPGPSignature_withByteArray_(LibOrgBouncycastleOpenpgpPGPSignature *sig, IOSByteArray *line);

__attribute__((unused)) static void LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_processLineWithJavaIoOutputStream_withLibOrgBouncycastleOpenpgpPGPSignatureGenerator_withByteArray_(JavaIoOutputStream *aOut, LibOrgBouncycastleOpenpgpPGPSignatureGenerator *sGen, IOSByteArray *line);

__attribute__((unused)) static jint LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_getLengthWithoutSeparatorOrTrailingWhitespaceWithByteArray_(IOSByteArray *line);

__attribute__((unused)) static jboolean LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_isLineEndingWithByte_(jbyte b);

__attribute__((unused)) static jint LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_getLengthWithoutWhiteSpaceWithByteArray_(IOSByteArray *line);

__attribute__((unused)) static jboolean LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_isWhiteSpaceWithByte_(jbyte b);

@implementation LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (jint)readInputLineWithJavaIoByteArrayOutputStream:(JavaIoByteArrayOutputStream *)bOut
                               withJavaIoInputStream:(JavaIoInputStream *)fIn {
  return LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_readInputLineWithJavaIoByteArrayOutputStream_withJavaIoInputStream_(bOut, fIn);
}

+ (jint)readInputLineWithJavaIoByteArrayOutputStream:(JavaIoByteArrayOutputStream *)bOut
                                             withInt:(jint)lookAhead
                               withJavaIoInputStream:(JavaIoInputStream *)fIn {
  return LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_readInputLineWithJavaIoByteArrayOutputStream_withInt_withJavaIoInputStream_(bOut, lookAhead, fIn);
}

+ (jint)readPassedEOLWithJavaIoByteArrayOutputStream:(JavaIoByteArrayOutputStream *)bOut
                                             withInt:(jint)lastCh
                               withJavaIoInputStream:(JavaIoInputStream *)fIn {
  return LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_readPassedEOLWithJavaIoByteArrayOutputStream_withInt_withJavaIoInputStream_(bOut, lastCh, fIn);
}

+ (void)verifyFileWithJavaIoInputStream:(JavaIoInputStream *)inArg
                  withJavaIoInputStream:(JavaIoInputStream *)keyIn
                           withNSString:(NSString *)resultName {
  LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_verifyFileWithJavaIoInputStream_withJavaIoInputStream_withNSString_(inArg, keyIn, resultName);
}

+ (IOSByteArray *)getLineSeparator {
  return LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_getLineSeparator();
}

+ (void)signFileWithNSString:(NSString *)fileName
       withJavaIoInputStream:(JavaIoInputStream *)keyIn
      withJavaIoOutputStream:(JavaIoOutputStream *)outArg
               withCharArray:(IOSCharArray *)pass
                withNSString:(NSString *)digestName {
  LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_signFileWithNSString_withJavaIoInputStream_withJavaIoOutputStream_withCharArray_withNSString_(fileName, keyIn, outArg, pass, digestName);
}

+ (void)processLineWithLibOrgBouncycastleOpenpgpPGPSignature:(LibOrgBouncycastleOpenpgpPGPSignature *)sig
                                               withByteArray:(IOSByteArray *)line {
  LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_processLineWithLibOrgBouncycastleOpenpgpPGPSignature_withByteArray_(sig, line);
}

+ (void)processLineWithJavaIoOutputStream:(JavaIoOutputStream *)aOut
withLibOrgBouncycastleOpenpgpPGPSignatureGenerator:(LibOrgBouncycastleOpenpgpPGPSignatureGenerator *)sGen
                            withByteArray:(IOSByteArray *)line {
  LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_processLineWithJavaIoOutputStream_withLibOrgBouncycastleOpenpgpPGPSignatureGenerator_withByteArray_(aOut, sGen, line);
}

+ (jint)getLengthWithoutSeparatorOrTrailingWhitespaceWithByteArray:(IOSByteArray *)line {
  return LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_getLengthWithoutSeparatorOrTrailingWhitespaceWithByteArray_(line);
}

+ (jboolean)isLineEndingWithByte:(jbyte)b {
  return LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_isLineEndingWithByte_(b);
}

+ (jint)getLengthWithoutWhiteSpaceWithByteArray:(IOSByteArray *)line {
  return LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_getLengthWithoutWhiteSpaceWithByteArray_(line);
}

+ (jboolean)isWhiteSpaceWithByte:(jbyte)b {
  return LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_isWhiteSpaceWithByte_(b);
}

+ (void)mainWithNSStringArray:(IOSObjectArray *)args {
  LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_mainWithNSStringArray_(args);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0xa, 0, 1, 2, -1, -1, -1 },
    { NULL, "I", 0xa, 0, 3, 2, -1, -1, -1 },
    { NULL, "I", 0xa, 4, 3, 2, -1, -1, -1 },
    { NULL, "V", 0xa, 5, 6, 7, -1, -1, -1 },
    { NULL, "[B", 0xa, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0xa, 8, 9, 10, -1, -1, -1 },
    { NULL, "V", 0xa, 11, 12, 13, -1, -1, -1 },
    { NULL, "V", 0xa, 11, 14, 13, -1, -1, -1 },
    { NULL, "I", 0xa, 15, 16, -1, -1, -1, -1 },
    { NULL, "Z", 0xa, 17, 18, -1, -1, -1, -1 },
    { NULL, "I", 0xa, 19, 16, -1, -1, -1, -1 },
    { NULL, "Z", 0xa, 20, 18, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 21, 22, 7, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(readInputLineWithJavaIoByteArrayOutputStream:withJavaIoInputStream:);
  methods[2].selector = @selector(readInputLineWithJavaIoByteArrayOutputStream:withInt:withJavaIoInputStream:);
  methods[3].selector = @selector(readPassedEOLWithJavaIoByteArrayOutputStream:withInt:withJavaIoInputStream:);
  methods[4].selector = @selector(verifyFileWithJavaIoInputStream:withJavaIoInputStream:withNSString:);
  methods[5].selector = @selector(getLineSeparator);
  methods[6].selector = @selector(signFileWithNSString:withJavaIoInputStream:withJavaIoOutputStream:withCharArray:withNSString:);
  methods[7].selector = @selector(processLineWithLibOrgBouncycastleOpenpgpPGPSignature:withByteArray:);
  methods[8].selector = @selector(processLineWithJavaIoOutputStream:withLibOrgBouncycastleOpenpgpPGPSignatureGenerator:withByteArray:);
  methods[9].selector = @selector(getLengthWithoutSeparatorOrTrailingWhitespaceWithByteArray:);
  methods[10].selector = @selector(isLineEndingWithByte:);
  methods[11].selector = @selector(getLengthWithoutWhiteSpaceWithByteArray:);
  methods[12].selector = @selector(isWhiteSpaceWithByte:);
  methods[13].selector = @selector(mainWithNSStringArray:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "readInputLine", "LJavaIoByteArrayOutputStream;LJavaIoInputStream;", "LJavaIoIOException;", "LJavaIoByteArrayOutputStream;ILJavaIoInputStream;", "readPassedEOL", "verifyFile", "LJavaIoInputStream;LJavaIoInputStream;LNSString;", "LJavaLangException;", "signFile", "LNSString;LJavaIoInputStream;LJavaIoOutputStream;[CLNSString;", "LJavaIoIOException;LJavaSecurityNoSuchAlgorithmException;LJavaSecurityNoSuchProviderException;LLibOrgBouncycastleOpenpgpPGPException;LJavaSecuritySignatureException;", "processLine", "LLibOrgBouncycastleOpenpgpPGPSignature;[B", "LJavaSecuritySignatureException;LJavaIoIOException;", "LJavaIoOutputStream;LLibOrgBouncycastleOpenpgpPGPSignatureGenerator;[B", "getLengthWithoutSeparatorOrTrailingWhitespace", "[B", "isLineEnding", "B", "getLengthWithoutWhiteSpace", "isWhiteSpace", "main", "[LNSString;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor = { "ClearSignedFileProcessor", "lib.org.bouncycastle.openpgp.examples", ptrTable, methods, NULL, 7, 0x1, 14, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor;
}

@end

void LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_init(LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor *self) {
  NSObject_init(self);
}

LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor *new_LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor, init)
}

LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor *create_LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor, init)
}

jint LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_readInputLineWithJavaIoByteArrayOutputStream_withJavaIoInputStream_(JavaIoByteArrayOutputStream *bOut, JavaIoInputStream *fIn) {
  LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_initialize();
  [((JavaIoByteArrayOutputStream *) nil_chk(bOut)) reset];
  jint lookAhead = -1;
  jint ch;
  while ((ch = [((JavaIoInputStream *) nil_chk(fIn)) read]) >= 0) {
    [bOut writeWithInt:ch];
    if (ch == 0x000d || ch == 0x000a) {
      lookAhead = LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_readPassedEOLWithJavaIoByteArrayOutputStream_withInt_withJavaIoInputStream_(bOut, ch, fIn);
      break;
    }
  }
  return lookAhead;
}

jint LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_readInputLineWithJavaIoByteArrayOutputStream_withInt_withJavaIoInputStream_(JavaIoByteArrayOutputStream *bOut, jint lookAhead, JavaIoInputStream *fIn) {
  LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_initialize();
  [((JavaIoByteArrayOutputStream *) nil_chk(bOut)) reset];
  jint ch = lookAhead;
  do {
    [bOut writeWithInt:ch];
    if (ch == 0x000d || ch == 0x000a) {
      lookAhead = LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_readPassedEOLWithJavaIoByteArrayOutputStream_withInt_withJavaIoInputStream_(bOut, ch, fIn);
      break;
    }
  }
  while ((ch = [((JavaIoInputStream *) nil_chk(fIn)) read]) >= 0);
  if (ch < 0) {
    lookAhead = -1;
  }
  return lookAhead;
}

jint LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_readPassedEOLWithJavaIoByteArrayOutputStream_withInt_withJavaIoInputStream_(JavaIoByteArrayOutputStream *bOut, jint lastCh, JavaIoInputStream *fIn) {
  LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_initialize();
  jint lookAhead = [((JavaIoInputStream *) nil_chk(fIn)) read];
  if (lastCh == 0x000d && lookAhead == 0x000a) {
    [((JavaIoByteArrayOutputStream *) nil_chk(bOut)) writeWithInt:lookAhead];
    lookAhead = [fIn read];
  }
  return lookAhead;
}

void LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_verifyFileWithJavaIoInputStream_withJavaIoInputStream_withNSString_(JavaIoInputStream *inArg, JavaIoInputStream *keyIn, NSString *resultName) {
  LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_initialize();
  LibOrgBouncycastleBcpgArmoredInputStream *aIn = new_LibOrgBouncycastleBcpgArmoredInputStream_initWithJavaIoInputStream_(inArg);
  JavaIoOutputStream *out = new_JavaIoBufferedOutputStream_initWithJavaIoOutputStream_(new_JavaIoFileOutputStream_initWithNSString_(resultName));
  JavaIoByteArrayOutputStream *lineOut = new_JavaIoByteArrayOutputStream_init();
  jint lookAhead = LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_readInputLineWithJavaIoByteArrayOutputStream_withJavaIoInputStream_(lineOut, aIn);
  IOSByteArray *lineSep = LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_getLineSeparator();
  if (lookAhead != -1 && [aIn isClearText]) {
    IOSByteArray *line = [lineOut toByteArray];
    [out writeWithByteArray:line withInt:0 withInt:LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_getLengthWithoutSeparatorOrTrailingWhitespaceWithByteArray_(line)];
    [out writeWithByteArray:lineSep];
    while (lookAhead != -1 && [aIn isClearText]) {
      lookAhead = LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_readInputLineWithJavaIoByteArrayOutputStream_withInt_withJavaIoInputStream_(lineOut, lookAhead, aIn);
      line = [lineOut toByteArray];
      [out writeWithByteArray:line withInt:0 withInt:LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_getLengthWithoutSeparatorOrTrailingWhitespaceWithByteArray_(line)];
      [out writeWithByteArray:lineSep];
    }
  }
  else {
    if (lookAhead != -1) {
      IOSByteArray *line = [lineOut toByteArray];
      [out writeWithByteArray:line withInt:0 withInt:LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_getLengthWithoutSeparatorOrTrailingWhitespaceWithByteArray_(line)];
      [out writeWithByteArray:lineSep];
    }
  }
  [out close];
  LibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection *pgpRings = new_LibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection_initWithJavaIoInputStream_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_(keyIn, new_LibOrgBouncycastleOpenpgpOperatorJcajceJcaKeyFingerprintCalculator_init());
  LibOrgBouncycastleOpenpgpJcajceJcaPGPObjectFactory *pgpFact = new_LibOrgBouncycastleOpenpgpJcajceJcaPGPObjectFactory_initWithJavaIoInputStream_(aIn);
  LibOrgBouncycastleOpenpgpPGPSignatureList *p3 = (LibOrgBouncycastleOpenpgpPGPSignatureList *) cast_chk([pgpFact nextObject], [LibOrgBouncycastleOpenpgpPGPSignatureList class]);
  LibOrgBouncycastleOpenpgpPGPSignature *sig = [((LibOrgBouncycastleOpenpgpPGPSignatureList *) nil_chk(p3)) getWithInt:0];
  LibOrgBouncycastleOpenpgpPGPPublicKey *publicKey = [pgpRings getPublicKeyWithLong:[((LibOrgBouncycastleOpenpgpPGPSignature *) nil_chk(sig)) getKeyID]];
  [sig init__WithLibOrgBouncycastleOpenpgpOperatorPGPContentVerifierBuilderProvider:[new_LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPContentVerifierBuilderProvider_init() setProviderWithNSString:@"BC"] withLibOrgBouncycastleOpenpgpPGPPublicKey:publicKey];
  JavaIoInputStream *sigIn = new_JavaIoBufferedInputStream_initWithJavaIoInputStream_(new_JavaIoFileInputStream_initWithNSString_(resultName));
  lookAhead = LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_readInputLineWithJavaIoByteArrayOutputStream_withJavaIoInputStream_(lineOut, sigIn);
  LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_processLineWithLibOrgBouncycastleOpenpgpPGPSignature_withByteArray_(sig, [lineOut toByteArray]);
  if (lookAhead != -1) {
    do {
      lookAhead = LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_readInputLineWithJavaIoByteArrayOutputStream_withInt_withJavaIoInputStream_(lineOut, lookAhead, sigIn);
      [sig updateWithByte:(jbyte) 0x000d];
      [sig updateWithByte:(jbyte) 0x000a];
      LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_processLineWithLibOrgBouncycastleOpenpgpPGPSignature_withByteArray_(sig, [lineOut toByteArray]);
    }
    while (lookAhead != -1);
  }
  [sigIn close];
  if ([sig verify]) {
    [((JavaIoPrintStream *) nil_chk(JreLoadStatic(JavaLangSystem, out))) printlnWithNSString:@"signature verified."];
  }
  else {
    [((JavaIoPrintStream *) nil_chk(JreLoadStatic(JavaLangSystem, out))) printlnWithNSString:@"signature verification failed."];
  }
}

IOSByteArray *LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_getLineSeparator() {
  LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_initialize();
  NSString *nl = LibOrgBouncycastleUtilStrings_lineSeparator();
  IOSByteArray *nlBytes = [IOSByteArray newArrayWithLength:[((NSString *) nil_chk(nl)) java_length]];
  for (jint i = 0; i != nlBytes->size_; i++) {
    *IOSByteArray_GetRef(nlBytes, i) = (jbyte) [nl charAtWithInt:i];
  }
  return nlBytes;
}

void LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_signFileWithNSString_withJavaIoInputStream_withJavaIoOutputStream_withCharArray_withNSString_(NSString *fileName, JavaIoInputStream *keyIn, JavaIoOutputStream *outArg, IOSCharArray *pass, NSString *digestName) {
  LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_initialize();
  jint digest;
  if ([((NSString *) nil_chk(digestName)) isEqual:@"SHA256"]) {
    digest = LibOrgBouncycastleBcpgHashAlgorithmTags_SHA256;
  }
  else if ([digestName isEqual:@"SHA384"]) {
    digest = LibOrgBouncycastleBcpgHashAlgorithmTags_SHA384;
  }
  else if ([digestName isEqual:@"SHA512"]) {
    digest = LibOrgBouncycastleBcpgHashAlgorithmTags_SHA512;
  }
  else if ([digestName isEqual:@"MD5"]) {
    digest = LibOrgBouncycastleBcpgHashAlgorithmTags_MD5;
  }
  else if ([digestName isEqual:@"RIPEMD160"]) {
    digest = LibOrgBouncycastleBcpgHashAlgorithmTags_RIPEMD160;
  }
  else {
    digest = LibOrgBouncycastleBcpgHashAlgorithmTags_SHA1;
  }
  LibOrgBouncycastleOpenpgpPGPSecretKey *pgpSecKey = LibOrgBouncycastleOpenpgpExamplesPGPExampleUtil_readSecretKeyWithJavaIoInputStream_(keyIn);
  LibOrgBouncycastleOpenpgpPGPPrivateKey *pgpPrivKey = [((LibOrgBouncycastleOpenpgpPGPSecretKey *) nil_chk(pgpSecKey)) extractPrivateKeyWithLibOrgBouncycastleOpenpgpOperatorPBESecretKeyDecryptor:[((LibOrgBouncycastleOpenpgpOperatorJcajceJcePBESecretKeyDecryptorBuilder *) nil_chk([new_LibOrgBouncycastleOpenpgpOperatorJcajceJcePBESecretKeyDecryptorBuilder_init() setProviderWithNSString:@"BC"])) buildWithCharArray:pass]];
  LibOrgBouncycastleOpenpgpPGPSignatureGenerator *sGen = new_LibOrgBouncycastleOpenpgpPGPSignatureGenerator_initWithLibOrgBouncycastleOpenpgpOperatorPGPContentSignerBuilder_([new_LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPContentSignerBuilder_initWithInt_withInt_([((LibOrgBouncycastleOpenpgpPGPPublicKey *) nil_chk([pgpSecKey getPublicKey])) getAlgorithm], digest) setProviderWithNSString:@"BC"]);
  LibOrgBouncycastleOpenpgpPGPSignatureSubpacketGenerator *spGen = new_LibOrgBouncycastleOpenpgpPGPSignatureSubpacketGenerator_init();
  [sGen init__WithInt:LibOrgBouncycastleOpenpgpPGPSignature_CANONICAL_TEXT_DOCUMENT withLibOrgBouncycastleOpenpgpPGPPrivateKey:pgpPrivKey];
  id<JavaUtilIterator> it = [((LibOrgBouncycastleOpenpgpPGPPublicKey *) nil_chk([pgpSecKey getPublicKey])) getUserIDs];
  if ([((id<JavaUtilIterator>) nil_chk(it)) hasNext]) {
    [spGen setSignerUserIDWithBoolean:false withNSString:(NSString *) cast_chk([it next], [NSString class])];
    [sGen setHashedSubpacketsWithLibOrgBouncycastleOpenpgpPGPSignatureSubpacketVector:[spGen generate]];
  }
  JavaIoInputStream *fIn = new_JavaIoBufferedInputStream_initWithJavaIoInputStream_(new_JavaIoFileInputStream_initWithNSString_(fileName));
  LibOrgBouncycastleBcpgArmoredOutputStream *aOut = new_LibOrgBouncycastleBcpgArmoredOutputStream_initWithJavaIoOutputStream_(outArg);
  [aOut beginClearTextWithInt:digest];
  JavaIoByteArrayOutputStream *lineOut = new_JavaIoByteArrayOutputStream_init();
  jint lookAhead = LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_readInputLineWithJavaIoByteArrayOutputStream_withJavaIoInputStream_(lineOut, fIn);
  LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_processLineWithJavaIoOutputStream_withLibOrgBouncycastleOpenpgpPGPSignatureGenerator_withByteArray_(aOut, sGen, [lineOut toByteArray]);
  if (lookAhead != -1) {
    do {
      lookAhead = LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_readInputLineWithJavaIoByteArrayOutputStream_withInt_withJavaIoInputStream_(lineOut, lookAhead, fIn);
      [sGen updateWithByte:(jbyte) 0x000d];
      [sGen updateWithByte:(jbyte) 0x000a];
      LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_processLineWithJavaIoOutputStream_withLibOrgBouncycastleOpenpgpPGPSignatureGenerator_withByteArray_(aOut, sGen, [lineOut toByteArray]);
    }
    while (lookAhead != -1);
  }
  [fIn close];
  [aOut endClearText];
  LibOrgBouncycastleBcpgBCPGOutputStream *bOut = new_LibOrgBouncycastleBcpgBCPGOutputStream_initWithJavaIoOutputStream_(aOut);
  [((LibOrgBouncycastleOpenpgpPGPSignature *) nil_chk([sGen generate])) encodeWithJavaIoOutputStream:bOut];
  [aOut close];
}

void LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_processLineWithLibOrgBouncycastleOpenpgpPGPSignature_withByteArray_(LibOrgBouncycastleOpenpgpPGPSignature *sig, IOSByteArray *line) {
  LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_initialize();
  jint length = LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_getLengthWithoutWhiteSpaceWithByteArray_(line);
  if (length > 0) {
    [((LibOrgBouncycastleOpenpgpPGPSignature *) nil_chk(sig)) updateWithByteArray:line withInt:0 withInt:length];
  }
}

void LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_processLineWithJavaIoOutputStream_withLibOrgBouncycastleOpenpgpPGPSignatureGenerator_withByteArray_(JavaIoOutputStream *aOut, LibOrgBouncycastleOpenpgpPGPSignatureGenerator *sGen, IOSByteArray *line) {
  LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_initialize();
  jint length = LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_getLengthWithoutWhiteSpaceWithByteArray_(line);
  if (length > 0) {
    [((LibOrgBouncycastleOpenpgpPGPSignatureGenerator *) nil_chk(sGen)) updateWithByteArray:line withInt:0 withInt:length];
  }
  [((JavaIoOutputStream *) nil_chk(aOut)) writeWithByteArray:line withInt:0 withInt:((IOSByteArray *) nil_chk(line))->size_];
}

jint LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_getLengthWithoutSeparatorOrTrailingWhitespaceWithByteArray_(IOSByteArray *line) {
  LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_initialize();
  jint end = ((IOSByteArray *) nil_chk(line))->size_ - 1;
  while (end >= 0 && LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_isWhiteSpaceWithByte_(IOSByteArray_Get(line, end))) {
    end--;
  }
  return end + 1;
}

jboolean LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_isLineEndingWithByte_(jbyte b) {
  LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_initialize();
  return b == 0x000d || b == 0x000a;
}

jint LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_getLengthWithoutWhiteSpaceWithByteArray_(IOSByteArray *line) {
  LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_initialize();
  jint end = ((IOSByteArray *) nil_chk(line))->size_ - 1;
  while (end >= 0 && LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_isWhiteSpaceWithByte_(IOSByteArray_Get(line, end))) {
    end--;
  }
  return end + 1;
}

jboolean LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_isWhiteSpaceWithByte_(jbyte b) {
  LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_initialize();
  return LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_isLineEndingWithByte_(b) || b == 0x0009 || b == ' ';
}

void LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_mainWithNSStringArray_(IOSObjectArray *args) {
  LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_initialize();
  JavaSecuritySecurity_addProviderWithJavaSecurityProvider_(new_LibOrgBouncycastleJceProviderBouncyCastleProvider_init());
  if ([((NSString *) nil_chk(IOSObjectArray_Get(nil_chk(args), 0))) isEqual:@"-s"]) {
    JavaIoInputStream *keyIn = LibOrgBouncycastleOpenpgpPGPUtil_getDecoderStreamWithJavaIoInputStream_(new_JavaIoFileInputStream_initWithNSString_(IOSObjectArray_Get(args, 2)));
    JavaIoFileOutputStream *out = new_JavaIoFileOutputStream_initWithNSString_(JreStrcat("$$", IOSObjectArray_Get(args, 1), @".asc"));
    if (args->size_ == 4) {
      LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_signFileWithNSString_withJavaIoInputStream_withJavaIoOutputStream_withCharArray_withNSString_(IOSObjectArray_Get(args, 1), keyIn, out, [((NSString *) nil_chk(IOSObjectArray_Get(args, 3))) java_toCharArray], @"SHA1");
    }
    else {
      LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_signFileWithNSString_withJavaIoInputStream_withJavaIoOutputStream_withCharArray_withNSString_(IOSObjectArray_Get(args, 1), keyIn, out, [((NSString *) nil_chk(IOSObjectArray_Get(args, 3))) java_toCharArray], IOSObjectArray_Get(args, 4));
    }
  }
  else if ([((NSString *) nil_chk(IOSObjectArray_Get(args, 0))) isEqual:@"-v"]) {
    if ([((NSString *) nil_chk(IOSObjectArray_Get(args, 1))) java_indexOfString:@".asc"] < 0) {
      [((JavaIoPrintStream *) nil_chk(JreLoadStatic(JavaLangSystem, err))) printlnWithNSString:@"file needs to end in \".asc\""];
      JavaLangSystem_exitWithInt_(1);
    }
    JavaIoFileInputStream *in = new_JavaIoFileInputStream_initWithNSString_(IOSObjectArray_Get(args, 1));
    JavaIoInputStream *keyIn = LibOrgBouncycastleOpenpgpPGPUtil_getDecoderStreamWithJavaIoInputStream_(new_JavaIoFileInputStream_initWithNSString_(IOSObjectArray_Get(args, 2)));
    LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor_verifyFileWithJavaIoInputStream_withJavaIoInputStream_withNSString_(in, keyIn, [((NSString *) nil_chk(IOSObjectArray_Get(args, 1))) java_substring:0 endIndex:[((NSString *) nil_chk(IOSObjectArray_Get(args, 1))) java_length] - 4]);
  }
  else {
    [((JavaIoPrintStream *) nil_chk(JreLoadStatic(JavaLangSystem, err))) printlnWithNSString:@"usage: ClearSignedFileProcessor [-s file keyfile passPhrase]|[-v sigFile keyFile]"];
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleOpenpgpExamplesClearSignedFileProcessor)
