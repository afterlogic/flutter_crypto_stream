//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/asymmetric/x509/CertificateFactory.java
//

#include "ASN1Encodable.h"
#include "ASN1InputStream.h"
#include "ASN1ObjectIdentifier.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "ASN1Set.h"
#include "ASN1TaggedObject.h"
#include "BCJcaJceHelper.h"
#include "CertificateFactory.h"
#include "CertificateList.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "JcaJceHelper.h"
#include "JcajceX509CRLObject.h"
#include "JcajceX509CertificateObject.h"
#include "JcajceX509PEMUtil.h"
#include "PKCSObjectIdentifiers.h"
#include "PKIXCertPath.h"
#include "SignedData.h"
#include "Streams.h"
#include "X509Certificate.h"
#include "java/io/BufferedInputStream.h"
#include "java/io/ByteArrayInputStream.h"
#include "java/io/InputStream.h"
#include "java/lang/Exception.h"
#include "java/lang/Throwable.h"
#include "java/security/cert/CRL.h"
#include "java/security/cert/CRLException.h"
#include "java/security/cert/CertPath.h"
#include "java/security/cert/Certificate.h"
#include "java/security/cert/CertificateException.h"
#include "java/security/cert/CertificateFactorySpi.h"
#include "java/security/cert/X509Certificate.h"
#include "java/util/ArrayList.h"
#include "java/util/Collection.h"
#include "java/util/Iterator.h"
#include "java/util/List.h"

@interface LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory () {
 @public
  id<LibOrgBouncycastleJcajceUtilJcaJceHelper> bcHelper_;
  LibOrgBouncycastleAsn1ASN1Set *sData_;
  jint sDataObjectCount_;
  JavaIoInputStream *currentStream_;
  LibOrgBouncycastleAsn1ASN1Set *sCrlData_;
  jint sCrlDataObjectCount_;
  JavaIoInputStream *currentCrlStream_;
}

- (JavaSecurityCertCertificate *)readDERCertificateWithLibOrgBouncycastleAsn1ASN1InputStream:(LibOrgBouncycastleAsn1ASN1InputStream *)dIn;

- (JavaSecurityCertCertificate *)readPEMCertificateWithJavaIoInputStream:(JavaIoInputStream *)inArg;

- (JavaSecurityCertCertificate *)getCertificateWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

- (JavaSecurityCertCertificate *)getCertificate;

- (JavaSecurityCertCRL *)readPEMCRLWithJavaIoInputStream:(JavaIoInputStream *)inArg;

- (JavaSecurityCertCRL *)readDERCRLWithLibOrgBouncycastleAsn1ASN1InputStream:(LibOrgBouncycastleAsn1ASN1InputStream *)aIn;

- (JavaSecurityCertCRL *)getCRLWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

- (JavaSecurityCertCRL *)getCRL;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory, bcHelper_, id<LibOrgBouncycastleJcajceUtilJcaJceHelper>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory, sData_, LibOrgBouncycastleAsn1ASN1Set *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory, currentStream_, JavaIoInputStream *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory, sCrlData_, LibOrgBouncycastleAsn1ASN1Set *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory, currentCrlStream_, JavaIoInputStream *)

inline LibOrgBouncycastleJcajceProviderAsymmetricX509JcajceX509PEMUtil *LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_get_PEM_CERT_PARSER(void);
static LibOrgBouncycastleJcajceProviderAsymmetricX509JcajceX509PEMUtil *LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_PEM_CERT_PARSER;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory, PEM_CERT_PARSER, LibOrgBouncycastleJcajceProviderAsymmetricX509JcajceX509PEMUtil *)

inline LibOrgBouncycastleJcajceProviderAsymmetricX509JcajceX509PEMUtil *LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_get_PEM_CRL_PARSER(void);
static LibOrgBouncycastleJcajceProviderAsymmetricX509JcajceX509PEMUtil *LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_PEM_CRL_PARSER;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory, PEM_CRL_PARSER, LibOrgBouncycastleJcajceProviderAsymmetricX509JcajceX509PEMUtil *)

inline LibOrgBouncycastleJcajceProviderAsymmetricX509JcajceX509PEMUtil *LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_get_PEM_PKCS7_PARSER(void);
static LibOrgBouncycastleJcajceProviderAsymmetricX509JcajceX509PEMUtil *LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_PEM_PKCS7_PARSER;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory, PEM_PKCS7_PARSER, LibOrgBouncycastleJcajceProviderAsymmetricX509JcajceX509PEMUtil *)

__attribute__((unused)) static JavaSecurityCertCertificate *LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_readDERCertificateWithLibOrgBouncycastleAsn1ASN1InputStream_(LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory *self, LibOrgBouncycastleAsn1ASN1InputStream *dIn);

__attribute__((unused)) static JavaSecurityCertCertificate *LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_readPEMCertificateWithJavaIoInputStream_(LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory *self, JavaIoInputStream *inArg);

__attribute__((unused)) static JavaSecurityCertCertificate *LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_getCertificateWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static JavaSecurityCertCertificate *LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_getCertificate(LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory *self);

__attribute__((unused)) static JavaSecurityCertCRL *LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_readPEMCRLWithJavaIoInputStream_(LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory *self, JavaIoInputStream *inArg);

__attribute__((unused)) static JavaSecurityCertCRL *LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_readDERCRLWithLibOrgBouncycastleAsn1ASN1InputStream_(LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory *self, LibOrgBouncycastleAsn1ASN1InputStream *aIn);

__attribute__((unused)) static JavaSecurityCertCRL *LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_getCRLWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static JavaSecurityCertCRL *LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_getCRL(LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory *self);

@interface LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_ExCertificateException : JavaSecurityCertCertificateException {
 @public
  JavaLangThrowable *cause_ExCertificateException_;
}

- (instancetype)initWithLibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory:(LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory *)outer$
                                                                   withJavaLangThrowable:(JavaLangThrowable *)cause;

- (instancetype)initWithLibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory:(LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory *)outer$
                                                                            withNSString:(NSString *)msg
                                                                   withJavaLangThrowable:(JavaLangThrowable *)cause;

- (JavaLangThrowable *)getCause;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_ExCertificateException)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_ExCertificateException, cause_ExCertificateException_, JavaLangThrowable *)

__attribute__((unused)) static void LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_ExCertificateException_initWithLibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_withJavaLangThrowable_(LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_ExCertificateException *self, LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory *outer$, JavaLangThrowable *cause);

__attribute__((unused)) static LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_ExCertificateException *new_LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_ExCertificateException_initWithLibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_withJavaLangThrowable_(LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory *outer$, JavaLangThrowable *cause) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_ExCertificateException *create_LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_ExCertificateException_initWithLibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_withJavaLangThrowable_(LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory *outer$, JavaLangThrowable *cause);

__attribute__((unused)) static void LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_ExCertificateException_initWithLibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_withNSString_withJavaLangThrowable_(LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_ExCertificateException *self, LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory *outer$, NSString *msg, JavaLangThrowable *cause);

__attribute__((unused)) static LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_ExCertificateException *new_LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_ExCertificateException_initWithLibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_withNSString_withJavaLangThrowable_(LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory *outer$, NSString *msg, JavaLangThrowable *cause) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_ExCertificateException *create_LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_ExCertificateException_initWithLibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_withNSString_withJavaLangThrowable_(LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory *outer$, NSString *msg, JavaLangThrowable *cause);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_ExCertificateException)

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory)

@implementation LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (JavaSecurityCertCertificate *)readDERCertificateWithLibOrgBouncycastleAsn1ASN1InputStream:(LibOrgBouncycastleAsn1ASN1InputStream *)dIn {
  return LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_readDERCertificateWithLibOrgBouncycastleAsn1ASN1InputStream_(self, dIn);
}

- (JavaSecurityCertCertificate *)readPEMCertificateWithJavaIoInputStream:(JavaIoInputStream *)inArg {
  return LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_readPEMCertificateWithJavaIoInputStream_(self, inArg);
}

- (JavaSecurityCertCertificate *)getCertificateWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  return LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_getCertificateWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
}

- (JavaSecurityCertCertificate *)getCertificate {
  return LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_getCertificate(self);
}

- (JavaSecurityCertCRL *)createCRLWithLibOrgBouncycastleAsn1X509CertificateList:(LibOrgBouncycastleAsn1X509CertificateList *)c {
  return new_LibOrgBouncycastleJcajceProviderAsymmetricX509JcajceX509CRLObject_initWithLibOrgBouncycastleJcajceUtilJcaJceHelper_withLibOrgBouncycastleAsn1X509CertificateList_(bcHelper_, c);
}

- (JavaSecurityCertCRL *)readPEMCRLWithJavaIoInputStream:(JavaIoInputStream *)inArg {
  return LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_readPEMCRLWithJavaIoInputStream_(self, inArg);
}

- (JavaSecurityCertCRL *)readDERCRLWithLibOrgBouncycastleAsn1ASN1InputStream:(LibOrgBouncycastleAsn1ASN1InputStream *)aIn {
  return LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_readDERCRLWithLibOrgBouncycastleAsn1ASN1InputStream_(self, aIn);
}

- (JavaSecurityCertCRL *)getCRLWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  return LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_getCRLWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
}

- (JavaSecurityCertCRL *)getCRL {
  return LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_getCRL(self);
}

- (JavaSecurityCertCertificate *)engineGenerateCertificateWithJavaIoInputStream:(JavaIoInputStream *)inArg {
  if (currentStream_ == nil) {
    currentStream_ = inArg;
    sData_ = nil;
    sDataObjectCount_ = 0;
  }
  else if (currentStream_ != inArg) {
    currentStream_ = inArg;
    sData_ = nil;
    sDataObjectCount_ = 0;
  }
  @try {
    if (sData_ != nil) {
      if (sDataObjectCount_ != [sData_ size]) {
        return LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_getCertificate(self);
      }
      else {
        sData_ = nil;
        sDataObjectCount_ = 0;
        return nil;
      }
    }
    JavaIoInputStream *pis;
    if ([((JavaIoInputStream *) nil_chk(inArg)) markSupported]) {
      pis = inArg;
    }
    else {
      pis = new_JavaIoByteArrayInputStream_initWithByteArray_(LibOrgBouncycastleUtilIoStreams_readAllWithJavaIoInputStream_(inArg));
    }
    [pis markWithInt:1];
    jint tag = [pis read];
    if (tag == -1) {
      return nil;
    }
    [pis reset];
    if (tag != (jint) 0x30) {
      return LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_readPEMCertificateWithJavaIoInputStream_(self, pis);
    }
    else {
      return LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_readDERCertificateWithLibOrgBouncycastleAsn1ASN1InputStream_(self, new_LibOrgBouncycastleAsn1ASN1InputStream_initWithJavaIoInputStream_(pis));
    }
  }
  @catch (JavaLangException *e) {
    @throw new_LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_ExCertificateException_initWithLibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_withNSString_withJavaLangThrowable_(self, JreStrcat("$$", @"parsing issue: ", [e getMessage]), e);
  }
}

- (id<JavaUtilCollection>)engineGenerateCertificatesWithJavaIoInputStream:(JavaIoInputStream *)inStream {
  JavaSecurityCertCertificate *cert;
  JavaIoBufferedInputStream *in = new_JavaIoBufferedInputStream_initWithJavaIoInputStream_(inStream);
  id<JavaUtilList> certs = new_JavaUtilArrayList_init();
  while ((cert = [self engineGenerateCertificateWithJavaIoInputStream:in]) != nil) {
    [certs addWithId:cert];
  }
  return certs;
}

- (JavaSecurityCertCRL *)engineGenerateCRLWithJavaIoInputStream:(JavaIoInputStream *)inArg {
  if (currentCrlStream_ == nil) {
    currentCrlStream_ = inArg;
    sCrlData_ = nil;
    sCrlDataObjectCount_ = 0;
  }
  else if (currentCrlStream_ != inArg) {
    currentCrlStream_ = inArg;
    sCrlData_ = nil;
    sCrlDataObjectCount_ = 0;
  }
  @try {
    if (sCrlData_ != nil) {
      if (sCrlDataObjectCount_ != [sCrlData_ size]) {
        return LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_getCRL(self);
      }
      else {
        sCrlData_ = nil;
        sCrlDataObjectCount_ = 0;
        return nil;
      }
    }
    JavaIoInputStream *pis;
    if ([((JavaIoInputStream *) nil_chk(inArg)) markSupported]) {
      pis = inArg;
    }
    else {
      pis = new_JavaIoByteArrayInputStream_initWithByteArray_(LibOrgBouncycastleUtilIoStreams_readAllWithJavaIoInputStream_(inArg));
    }
    [pis markWithInt:1];
    jint tag = [pis read];
    if (tag == -1) {
      return nil;
    }
    [pis reset];
    if (tag != (jint) 0x30) {
      return LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_readPEMCRLWithJavaIoInputStream_(self, pis);
    }
    else {
      return LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_readDERCRLWithLibOrgBouncycastleAsn1ASN1InputStream_(self, new_LibOrgBouncycastleAsn1ASN1InputStream_initWithJavaIoInputStream_withBoolean_(pis, true));
    }
  }
  @catch (JavaSecurityCertCRLException *e) {
    @throw e;
  }
  @catch (JavaLangException *e) {
    @throw new_JavaSecurityCertCRLException_initWithNSString_([e description]);
  }
}

- (id<JavaUtilCollection>)engineGenerateCRLsWithJavaIoInputStream:(JavaIoInputStream *)inStream {
  JavaSecurityCertCRL *crl;
  id<JavaUtilList> crls = new_JavaUtilArrayList_init();
  JavaIoBufferedInputStream *in = new_JavaIoBufferedInputStream_initWithJavaIoInputStream_(inStream);
  while ((crl = [self engineGenerateCRLWithJavaIoInputStream:in]) != nil) {
    [crls addWithId:crl];
  }
  return crls;
}

- (id<JavaUtilIterator>)engineGetCertPathEncodings {
  return [((id<JavaUtilList>) nil_chk(JreLoadStatic(LibOrgBouncycastleJcajceProviderAsymmetricX509PKIXCertPath, certPathEncodings))) iterator];
}

- (JavaSecurityCertCertPath *)engineGenerateCertPathWithJavaIoInputStream:(JavaIoInputStream *)inStream {
  return [self engineGenerateCertPathWithJavaIoInputStream:inStream withNSString:@"PkiPath"];
}

- (JavaSecurityCertCertPath *)engineGenerateCertPathWithJavaIoInputStream:(JavaIoInputStream *)inStream
                                                             withNSString:(NSString *)encoding {
  return new_LibOrgBouncycastleJcajceProviderAsymmetricX509PKIXCertPath_initWithJavaIoInputStream_withNSString_(inStream, encoding);
}

- (JavaSecurityCertCertPath *)engineGenerateCertPathWithJavaUtilList:(id<JavaUtilList>)certificates {
  id<JavaUtilIterator> iter = [((id<JavaUtilList>) nil_chk(certificates)) iterator];
  id obj;
  while ([((id<JavaUtilIterator>) nil_chk(iter)) hasNext]) {
    obj = [iter next];
    if (obj != nil) {
      if (!([obj isKindOfClass:[JavaSecurityCertX509Certificate class]])) {
        @throw new_JavaSecurityCertCertificateException_initWithNSString_(JreStrcat("$$", @"list contains non X509Certificate object while creating CertPath\n", [obj description]));
      }
    }
  }
  return new_LibOrgBouncycastleJcajceProviderAsymmetricX509PKIXCertPath_initWithJavaUtilList_(certificates);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaSecurityCertCertificate;", 0x2, 0, 1, 2, -1, -1, -1 },
    { NULL, "LJavaSecurityCertCertificate;", 0x2, 3, 4, 2, -1, -1, -1 },
    { NULL, "LJavaSecurityCertCertificate;", 0x2, 5, 6, 7, -1, -1, -1 },
    { NULL, "LJavaSecurityCertCertificate;", 0x2, -1, -1, 7, -1, -1, -1 },
    { NULL, "LJavaSecurityCertCRL;", 0x4, 8, 9, 10, -1, -1, -1 },
    { NULL, "LJavaSecurityCertCRL;", 0x2, 11, 4, 12, -1, -1, -1 },
    { NULL, "LJavaSecurityCertCRL;", 0x2, 13, 1, 12, -1, -1, -1 },
    { NULL, "LJavaSecurityCertCRL;", 0x2, 14, 6, 10, -1, -1, -1 },
    { NULL, "LJavaSecurityCertCRL;", 0x2, -1, -1, 10, -1, -1, -1 },
    { NULL, "LJavaSecurityCertCertificate;", 0x1, 15, 4, 16, -1, -1, -1 },
    { NULL, "LJavaUtilCollection;", 0x1, 17, 4, 16, -1, -1, -1 },
    { NULL, "LJavaSecurityCertCRL;", 0x1, 18, 4, 10, -1, -1, -1 },
    { NULL, "LJavaUtilCollection;", 0x1, 19, 4, 10, -1, -1, -1 },
    { NULL, "LJavaUtilIterator;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaSecurityCertCertPath;", 0x1, 20, 4, 16, -1, -1, -1 },
    { NULL, "LJavaSecurityCertCertPath;", 0x1, 20, 21, 16, -1, -1, -1 },
    { NULL, "LJavaSecurityCertCertPath;", 0x1, 20, 22, 16, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(readDERCertificateWithLibOrgBouncycastleAsn1ASN1InputStream:);
  methods[2].selector = @selector(readPEMCertificateWithJavaIoInputStream:);
  methods[3].selector = @selector(getCertificateWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[4].selector = @selector(getCertificate);
  methods[5].selector = @selector(createCRLWithLibOrgBouncycastleAsn1X509CertificateList:);
  methods[6].selector = @selector(readPEMCRLWithJavaIoInputStream:);
  methods[7].selector = @selector(readDERCRLWithLibOrgBouncycastleAsn1ASN1InputStream:);
  methods[8].selector = @selector(getCRLWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[9].selector = @selector(getCRL);
  methods[10].selector = @selector(engineGenerateCertificateWithJavaIoInputStream:);
  methods[11].selector = @selector(engineGenerateCertificatesWithJavaIoInputStream:);
  methods[12].selector = @selector(engineGenerateCRLWithJavaIoInputStream:);
  methods[13].selector = @selector(engineGenerateCRLsWithJavaIoInputStream:);
  methods[14].selector = @selector(engineGetCertPathEncodings);
  methods[15].selector = @selector(engineGenerateCertPathWithJavaIoInputStream:);
  methods[16].selector = @selector(engineGenerateCertPathWithJavaIoInputStream:withNSString:);
  methods[17].selector = @selector(engineGenerateCertPathWithJavaUtilList:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "bcHelper_", "LLibOrgBouncycastleJcajceUtilJcaJceHelper;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "PEM_CERT_PARSER", "LLibOrgBouncycastleJcajceProviderAsymmetricX509JcajceX509PEMUtil;", .constantValue.asLong = 0, 0x1a, -1, 23, -1, -1 },
    { "PEM_CRL_PARSER", "LLibOrgBouncycastleJcajceProviderAsymmetricX509JcajceX509PEMUtil;", .constantValue.asLong = 0, 0x1a, -1, 24, -1, -1 },
    { "PEM_PKCS7_PARSER", "LLibOrgBouncycastleJcajceProviderAsymmetricX509JcajceX509PEMUtil;", .constantValue.asLong = 0, 0x1a, -1, 25, -1, -1 },
    { "sData_", "LLibOrgBouncycastleAsn1ASN1Set;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "sDataObjectCount_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "currentStream_", "LJavaIoInputStream;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "sCrlData_", "LLibOrgBouncycastleAsn1ASN1Set;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "sCrlDataObjectCount_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "currentCrlStream_", "LJavaIoInputStream;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "readDERCertificate", "LLibOrgBouncycastleAsn1ASN1InputStream;", "LJavaIoIOException;LJavaSecurityCertCertificateParsingException;", "readPEMCertificate", "LJavaIoInputStream;", "getCertificate", "LLibOrgBouncycastleAsn1ASN1Sequence;", "LJavaSecurityCertCertificateParsingException;", "createCRL", "LLibOrgBouncycastleAsn1X509CertificateList;", "LJavaSecurityCertCRLException;", "readPEMCRL", "LJavaIoIOException;LJavaSecurityCertCRLException;", "readDERCRL", "getCRL", "engineGenerateCertificate", "LJavaSecurityCertCertificateException;", "engineGenerateCertificates", "engineGenerateCRL", "engineGenerateCRLs", "engineGenerateCertPath", "LJavaIoInputStream;LNSString;", "LJavaUtilList;", &LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_PEM_CERT_PARSER, &LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_PEM_CRL_PARSER, &LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_PEM_PKCS7_PARSER, "LLibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_ExCertificateException;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory = { "CertificateFactory", "lib.org.bouncycastle.jcajce.provider.asymmetric.x509", ptrTable, methods, fields, 7, 0x1, 18, 10, -1, 26, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory class]) {
    LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_PEM_CERT_PARSER = new_LibOrgBouncycastleJcajceProviderAsymmetricX509JcajceX509PEMUtil_initWithNSString_(@"CERTIFICATE");
    LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_PEM_CRL_PARSER = new_LibOrgBouncycastleJcajceProviderAsymmetricX509JcajceX509PEMUtil_initWithNSString_(@"CRL");
    LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_PEM_PKCS7_PARSER = new_LibOrgBouncycastleJcajceProviderAsymmetricX509JcajceX509PEMUtil_initWithNSString_(@"PKCS7");
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory)
  }
}

@end

void LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_init(LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory *self) {
  JavaSecurityCertCertificateFactorySpi_init(self);
  self->bcHelper_ = new_LibOrgBouncycastleJcajceUtilBCJcaJceHelper_init();
  self->sData_ = nil;
  self->sDataObjectCount_ = 0;
  self->currentStream_ = nil;
  self->sCrlData_ = nil;
  self->sCrlDataObjectCount_ = 0;
  self->currentCrlStream_ = nil;
}

LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory *new_LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory, init)
}

LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory *create_LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory, init)
}

JavaSecurityCertCertificate *LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_readDERCertificateWithLibOrgBouncycastleAsn1ASN1InputStream_(LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory *self, LibOrgBouncycastleAsn1ASN1InputStream *dIn) {
  return LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_getCertificateWithLibOrgBouncycastleAsn1ASN1Sequence_(self, LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_([((LibOrgBouncycastleAsn1ASN1InputStream *) nil_chk(dIn)) readObject]));
}

JavaSecurityCertCertificate *LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_readPEMCertificateWithJavaIoInputStream_(LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory *self, JavaIoInputStream *inArg) {
  return LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_getCertificateWithLibOrgBouncycastleAsn1ASN1Sequence_(self, [((LibOrgBouncycastleJcajceProviderAsymmetricX509JcajceX509PEMUtil *) nil_chk(LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_PEM_CERT_PARSER)) readPEMObjectWithJavaIoInputStream:inArg]);
}

JavaSecurityCertCertificate *LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_getCertificateWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  if (seq == nil) {
    return nil;
  }
  if ([seq size] > 1 && [[seq getObjectAtWithInt:0] isKindOfClass:[LibOrgBouncycastleAsn1ASN1ObjectIdentifier class]]) {
    if ([((id<LibOrgBouncycastleAsn1ASN1Encodable>) nil_chk([seq getObjectAtWithInt:0])) isEqual:JreLoadStatic(LibOrgBouncycastleAsn1PkcsPKCSObjectIdentifiers, signedData)]) {
      self->sData_ = [((LibOrgBouncycastleAsn1PkcsSignedData *) nil_chk(LibOrgBouncycastleAsn1PkcsSignedData_getInstanceWithId_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_((LibOrgBouncycastleAsn1ASN1TaggedObject *) cast_chk([seq getObjectAtWithInt:1], [LibOrgBouncycastleAsn1ASN1TaggedObject class]), true)))) getCertificates];
      return LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_getCertificate(self);
    }
  }
  return new_LibOrgBouncycastleJcajceProviderAsymmetricX509JcajceX509CertificateObject_initWithLibOrgBouncycastleJcajceUtilJcaJceHelper_withLibOrgBouncycastleAsn1X509X509Certificate_(self->bcHelper_, LibOrgBouncycastleAsn1X509X509Certificate_getInstanceWithId_(seq));
}

JavaSecurityCertCertificate *LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_getCertificate(LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory *self) {
  if (self->sData_ != nil) {
    while (self->sDataObjectCount_ < [((LibOrgBouncycastleAsn1ASN1Set *) nil_chk(self->sData_)) size]) {
      id obj = [((LibOrgBouncycastleAsn1ASN1Set *) nil_chk(self->sData_)) getObjectAtWithInt:self->sDataObjectCount_++];
      if ([obj isKindOfClass:[LibOrgBouncycastleAsn1ASN1Sequence class]]) {
        return new_LibOrgBouncycastleJcajceProviderAsymmetricX509JcajceX509CertificateObject_initWithLibOrgBouncycastleJcajceUtilJcaJceHelper_withLibOrgBouncycastleAsn1X509X509Certificate_(self->bcHelper_, LibOrgBouncycastleAsn1X509X509Certificate_getInstanceWithId_(obj));
      }
    }
  }
  return nil;
}

JavaSecurityCertCRL *LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_readPEMCRLWithJavaIoInputStream_(LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory *self, JavaIoInputStream *inArg) {
  return LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_getCRLWithLibOrgBouncycastleAsn1ASN1Sequence_(self, [((LibOrgBouncycastleJcajceProviderAsymmetricX509JcajceX509PEMUtil *) nil_chk(LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_PEM_CRL_PARSER)) readPEMObjectWithJavaIoInputStream:inArg]);
}

JavaSecurityCertCRL *LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_readDERCRLWithLibOrgBouncycastleAsn1ASN1InputStream_(LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory *self, LibOrgBouncycastleAsn1ASN1InputStream *aIn) {
  return LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_getCRLWithLibOrgBouncycastleAsn1ASN1Sequence_(self, LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_([((LibOrgBouncycastleAsn1ASN1InputStream *) nil_chk(aIn)) readObject]));
}

JavaSecurityCertCRL *LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_getCRLWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  if (seq == nil) {
    return nil;
  }
  if ([seq size] > 1 && [[seq getObjectAtWithInt:0] isKindOfClass:[LibOrgBouncycastleAsn1ASN1ObjectIdentifier class]]) {
    if ([((id<LibOrgBouncycastleAsn1ASN1Encodable>) nil_chk([seq getObjectAtWithInt:0])) isEqual:JreLoadStatic(LibOrgBouncycastleAsn1PkcsPKCSObjectIdentifiers, signedData)]) {
      self->sCrlData_ = [((LibOrgBouncycastleAsn1PkcsSignedData *) nil_chk(LibOrgBouncycastleAsn1PkcsSignedData_getInstanceWithId_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_((LibOrgBouncycastleAsn1ASN1TaggedObject *) cast_chk([seq getObjectAtWithInt:1], [LibOrgBouncycastleAsn1ASN1TaggedObject class]), true)))) getCRLs];
      return LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_getCRL(self);
    }
  }
  return [self createCRLWithLibOrgBouncycastleAsn1X509CertificateList:LibOrgBouncycastleAsn1X509CertificateList_getInstanceWithId_(seq)];
}

JavaSecurityCertCRL *LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_getCRL(LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory *self) {
  if (self->sCrlData_ == nil || self->sCrlDataObjectCount_ >= [self->sCrlData_ size]) {
    return nil;
  }
  return [self createCRLWithLibOrgBouncycastleAsn1X509CertificateList:LibOrgBouncycastleAsn1X509CertificateList_getInstanceWithId_([self->sCrlData_ getObjectAtWithInt:self->sCrlDataObjectCount_++])];
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory)

@implementation LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_ExCertificateException

- (instancetype)initWithLibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory:(LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory *)outer$
                                                                   withJavaLangThrowable:(JavaLangThrowable *)cause {
  LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_ExCertificateException_initWithLibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_withJavaLangThrowable_(self, outer$, cause);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory:(LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory *)outer$
                                                                            withNSString:(NSString *)msg
                                                                   withJavaLangThrowable:(JavaLangThrowable *)cause {
  LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_ExCertificateException_initWithLibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_withNSString_withJavaLangThrowable_(self, outer$, msg, cause);
  return self;
}

- (JavaLangThrowable *)getCause {
  return cause_ExCertificateException_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, "LJavaLangThrowable;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory:withJavaLangThrowable:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory:withNSString:withJavaLangThrowable:);
  methods[2].selector = @selector(getCause);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "cause_ExCertificateException_", "LJavaLangThrowable;", .constantValue.asLong = 0, 0x2, 2, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaLangThrowable;", "LNSString;LJavaLangThrowable;", "cause", "LLibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_ExCertificateException = { "ExCertificateException", "lib.org.bouncycastle.jcajce.provider.asymmetric.x509", ptrTable, methods, fields, 7, 0x2, 3, 1, 3, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_ExCertificateException;
}

@end

void LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_ExCertificateException_initWithLibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_withJavaLangThrowable_(LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_ExCertificateException *self, LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory *outer$, JavaLangThrowable *cause) {
  JavaSecurityCertCertificateException_init(self);
  self->cause_ExCertificateException_ = cause;
}

LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_ExCertificateException *new_LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_ExCertificateException_initWithLibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_withJavaLangThrowable_(LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory *outer$, JavaLangThrowable *cause) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_ExCertificateException, initWithLibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_withJavaLangThrowable_, outer$, cause)
}

LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_ExCertificateException *create_LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_ExCertificateException_initWithLibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_withJavaLangThrowable_(LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory *outer$, JavaLangThrowable *cause) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_ExCertificateException, initWithLibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_withJavaLangThrowable_, outer$, cause)
}

void LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_ExCertificateException_initWithLibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_withNSString_withJavaLangThrowable_(LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_ExCertificateException *self, LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory *outer$, NSString *msg, JavaLangThrowable *cause) {
  JavaSecurityCertCertificateException_initWithNSString_(self, msg);
  self->cause_ExCertificateException_ = cause;
}

LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_ExCertificateException *new_LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_ExCertificateException_initWithLibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_withNSString_withJavaLangThrowable_(LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory *outer$, NSString *msg, JavaLangThrowable *cause) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_ExCertificateException, initWithLibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_withNSString_withJavaLangThrowable_, outer$, msg, cause)
}

LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_ExCertificateException *create_LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_ExCertificateException_initWithLibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_withNSString_withJavaLangThrowable_(LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory *outer$, NSString *msg, JavaLangThrowable *cause) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_ExCertificateException, initWithLibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_withNSString_withJavaLangThrowable_, outer$, msg, cause)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_ExCertificateException)
