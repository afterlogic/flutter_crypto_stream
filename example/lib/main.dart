import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:crypto_stream/algorithm/pgp.dart';
import 'package:flutter/material.dart';
import 'package:path_provider/path_provider.dart';

void main() => runApp(MyApp());

class MyApp extends StatelessWidget {
  final Utf8Codec utf8 = Utf8Codec(allowMalformed: true);

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Flutter Demo',
      theme: ThemeData(
        // This is the theme of your application.
        //
        // Try running your application with "flutter run". You'll see the
        // application has a blue toolbar. Then, without quitting the app, try
        // changing the primarySwatch below to Colors.green and then invoke
        // "hot reload" (press "r" in the console where you ran "flutter run",
        // or simply save your changes to "hot reload" in a Flutter IDE).
        // Notice that the counter didn't reset back to zero; the application
        // is not restarted.
        primarySwatch: Colors.blue,
      ),
      home: DecryptTextPage(),
    );
  }
}

class DecryptTextPage extends StatefulWidget {
  @override
  _DecryptTextPageState createState() => _DecryptTextPageState();
}

class _DecryptTextPageState extends State<DecryptTextPage> {
  final pgp = Pgp();
  final outCtrl = TextEditingController();
  final textCtrl = TextEditingController();

  String get outText => outCtrl.text;

  set outText(String value) => outCtrl.text = value;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(),
      body: Center(
        child: ListView(
          children: <Widget>[
            TextFormField(
              controller: textCtrl,
            ),
            SingleChildScrollView(
              scrollDirection: Axis.horizontal,
              child: Row(
                children: <Widget>[
                  Column(
                    mainAxisSize: MainAxisSize.min,
                    children: <Widget>[
                      FlatButton(
                        child: Text("bufferEncrypt"),
                        onPressed: bufferEncrypt,
                      ),
                      FlatButton(
                        child: Text("bufferDecrypt"),
                        onPressed: bufferDecrypt,
                      ),
                    ],
                  ),
                  Column(
                    mainAxisSize: MainAxisSize.min,
                    children: <Widget>[
                      FlatButton(
                        child: Text("encrypt"),
                        onPressed: encrypt,
                      ),
                      FlatButton(
                        child: Text("decrypt"),
                        onPressed: decrypt,
                      ),
                    ],
                  ),
                  Column(
                    mainAxisSize: MainAxisSize.min,
                    children: <Widget>[
                      FlatButton(
                        child: Text("symmetricallyEncrypt"),
                        onPressed: symmetricallyEncrypt,
                      ),
                      FlatButton(
                        child: Text("symmetricallyDecrypt"),
                        onPressed: symmetricallyDecrypt,
                      ),
                    ],
                  ),
                  Column(
                    mainAxisSize: MainAxisSize.min,
                    children: <Widget>[
                      FlatButton(
                        child: Text("sign"),
                        onPressed: sign,
                      ),
                      FlatButton(
                        child: Text("verify"),
                        onPressed: verify,
                      ),
                    ],
                  ),
                  Center(
                    child: FlatButton(
                      child: Text("keyInfo"),
                      onPressed: keyInfo,
                    ),
                  ),
                  Center(
                    child: FlatButton(
                      child: Text("checkKey"),
                      onPressed: checkKey,
                    ),
                  ),
                ],
              ),
            ),
            TextField(
              controller: outCtrl,
              maxLines: null,
            ),
          ],
        ),
      ),
    );
  }

  bufferEncrypt() async {
    outText = await pgp.bufferPlatformSink(
      textCtrl.text,
      pgp.encrypt(null, [publicKey], null),
    );
    setState(() {});
  }

  bufferDecrypt() async {
    outText = await pgp.bufferPlatformSink(
      outText,
      pgp.decrypt(privateKey, null, password),
    );
    setState(() {});
  }

  encrypt() async {
    var currentBytes = utf8.encode(textCtrl.text);
    var outByte = List<int>();
    pgp.encrypt(null, [publicKey], password).listen((data) {
      outByte.addAll(data);
    }, onError: (e, s) {
      print(s);
      outText = "$e\n\n\n$s";
    }).onDone(() {
      outText = utf8.decode(outByte);
      setState(() {});
    });

    final platformSink = pgp.platformSink();
    final step = 100;
    var count = currentBytes.length / step;
    try {
      for (int i = 0; i < count; i++) {
        await platformSink.add(
            currentBytes.getRange(i * step, min((i + 1) * step, currentBytes.length)).toList());
      }
    } catch (e, s) {
      print(s);
    }
    await platformSink.close();
  }

  decrypt() async {
    var currentBytes = utf8.encode(outText);
    var outByte = List<int>();
    pgp.decrypt(privateKey, null, password).listen((data) {
      outByte.addAll(data);
    }, onError: (e, s) {
      print(s);
      outText = "$e\n\n\n$s";
    }).onDone(() {
      outText = utf8.decode(outByte);
      setState(() {});
    });

    final platformSink = pgp.platformSink();
    final step = 100;
    var count = currentBytes.length / step;
    try {
      for (int i = 0; i < count; i++) {
        await platformSink.add(
            currentBytes.getRange(i * step, min((i + 1) * step, currentBytes.length)).toList());
      }
    } catch (e, s) {
      print(s);
    }
    await platformSink.close();
  }

  symmetricallyEncrypt() async {
    Directory tempDir = await getTemporaryDirectory();
    File tempFile = File(tempDir.path + Platform.pathSeparator + "temp.temp");
    if (await tempFile.exists()) {
      await tempFile.delete();
    }

    var currentBytes = utf8.encode(textCtrl.text);
    var outByte = List<int>();
    pgp.symmetricallyEncrypt(tempFile, password, currentBytes.length).listen((data) {
      outByte.addAll(data);
    }, onError: (e, s) {
      print(s);
      outText = "$e\n\n\n$s";
    }).onDone(
      () {
        outText = utf8.decode(outByte);
        setState(() {});
      },
    );

    final platformSink = pgp.platformSink();
    final step = 100;
    var count = currentBytes.length / step;
    try {
      for (int i = 0; i < count; i++) {
        await platformSink.add(
            currentBytes.getRange(i * step, min((i + 1) * step, currentBytes.length)).toList());
      }
    } catch (e, s) {
      print(s);
    }
    await platformSink.close();
  }

  symmetricallyDecrypt() async {
    var currentBytes = utf8.encode(outText);
    var outByte = List<int>();
    pgp.symmetricallyDecrypt(password).listen((data) {
      outByte.addAll(data);
    }, onError: (e, s) {
      print(s);
      outText = "$e\n\n\n$s";
    }).onDone(
      () {
        outText = utf8.decode(outByte);
        setState(() {});
      },
    );

    final platformSink = pgp.platformSink();
    final step = 100;
    var count = currentBytes.length / step;
    try {
      for (int i = 0; i < count; i++) {
        await platformSink.add(
            currentBytes.getRange(i * step, min((i + 1) * step, currentBytes.length)).toList());
      }
    } catch (e, s) {
      print(s);
    }
    await platformSink.close();
  }

  sign() async {
    var text = textCtrl.text;
    outText = await pgp.sign(text, privateKey, password);
    setState(() {});
  }

  verify() async {
    var text = outText;
    outText = await pgp.verify(text, publicKey);
    setState(() {});
  }

  keyInfo() async {
    outText = "";
    final success = await pgp.checkKeyPassword(privateKey, password);
    outText += "checkKeyPassword = $success";
    setState(() {});
  }

  checkKey() async {
    outText = "";
    final pair = await pgp.createKeys(2000, email, password);

    final success = await pgp.checkKeyPassword(pair.privateKey, password);
    outText += "checkKeyPassword = $success";
    outText += "\n\n\n";
    final infoPrivate = await pgp.getKeyDescription(pair.privateKey);
    outText +=
        "privateKey : \n emails= ${infoPrivate.emails}\nlength= ${infoPrivate.length}\nisPrivate= ${infoPrivate.isPrivate}";
    outText += "\n\n\n";
    final infoPublic = await pgp.getKeyDescription(pair.publicKey);
    outText +=
        "publicKey : \n emails= ${infoPublic.emails}\nlength= ${infoPublic.length}\nisPrivate= ${infoPublic.isPrivate}";
    outText += "\n\n${pair.privateKey}\n\n${pair.publicKey}";
    setState(() {});
  }
}

final email = "test@test.com";
final password = "111";

final privateKey = """
-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: OpenPGP.js v4.5.5
Comment: https://openpgpjs.org

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
=RNRj
-----END PGP PRIVATE KEY BLOCK-----
""";
final publicKey = """
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: OpenPGP.js v4.5.5
Comment: https://openpgpjs.org

xsBNBF9SMKgBCADQJQ1KQOtREJm8r7arOGIzT5in5lgRtJJyQtNxNzqTVDYr
TIeylKpBB968v7Q4l07jPRmHzqlRzrpuv2SR465nLaGoY5lg9xlwnr0BnZsw
66APrNN2c98h6mxRC7s4oFF84Il/QFeE+9gtRJmndURuDqY+V3Kc4bSXGAbD
YXabDxQgyWI6PyCBGnvGh2kegKF3G8uGSn0U/3rfbMq+5tWJfklaOJBuHpz/
KhCTIqWYJWfk+46SpwKmJpZnBDk4GR2bZlT2hI/SZ6m7f75JiF3s/B7dsqBB
SFT+ueVwe/R73IUn5EhYJ6oDTH4002e030/fx3Me8/bGRHfjjgIZ8eVZABEB
AAHNFTx0ZXN0QGFmdGVybG9naWMuY29tPsLAdQQQAQgAHwUCX1IwqAYLCQcI
AwIEFQgKAgMWAgECGQECGwMCHgEACgkQ2BbWjGaAKfQDtAgAoNGab5eyeAa9
1r8Uj1s2844CgnURqQea9myzNW1CuDnzsZD2nG0XMAG8xCF6rV1xtgVB/Zfx
cpSSYKNBR0WqsOtw+CXTR8j/vwNBRvCBbWBqsUjF8PoWYfi0oNyUgbLKn6lD
n1iQpVraePh2tq8WjffFXDi3mgi6MT77VJHs3Ek1q727zP7Oy0IGre3d6CeR
SF0BoNvFziah1Wx8t0OPA10zIY4qHSJHRmfWUJe8k++yVHpoaXJIleu1Gj/Q
QKGNXclJT4hVWt3F7h5W7uzlMgpzd1b37O/bAfO0ry1IG2upuQFQJBZXIvsB
3vjKUcn3k2W4NZ95L4g2OFW699xm+87ATQRfUjCoAQgAqYa4bmguKUjbUJbB
p/4yTKGKSX3ivR6kqkTaNfuwlavQTgHPqwOfaE23gwp94veiwPCxkbVnfjn8
9pPrYJ2DRrMmGr5TnY/tbWfUn1Y/Vwt1ir05EgvsZBdQA3Y5Rnq71gW0f17F
EtidqMMJDzdRRhXEoI7lznkCh9Yp1nX6aXwqqXCwfX/L+IU6qJNAYExdwVuZ
Ya7ZwlJug+wUvEHlcyTU43yFZ+ZyknsmjKRzCh0C+/QkJGvhlnN5dM/i90vV
RIRB7PlU+jau7ptXGjYMvZovRy2Ez7iJygI+dPFsWu7QHkJ/jnTO8C+s4nbB
4vMLQPk2cZFF8O3RmxiBRpmtCwARAQABwsBfBBgBCAAJBQJfUjCoAhsMAAoJ
ENgW1oxmgCn0XOYH/2jdrVpH0MyQ7aae/iaN5AM8fZld0AnrwVy0E7X9J1hf
LzLgwWCIKBGxONR4FX67rAsdPOPadn4TBD9SUJUQtRIax3Bp7a0puqdIFc/J
8sU+oiJATP2fH5FVxYr3OF4D5+Qhlcu5szOLeRZApEYdmbUIXoBKfw8gOg1S
+V5y0lcxKFYALFG+TDnHG5qiQ7hpSQSTHS7412ssW2i/sviWnm/cfdOWvmy8
7+YgaTkKJ5g+jxntWaHmTeqhoFbyMJYoCgwh0vl1GTe/BPvta5iFt50bzSt/
7f80fydJjyRzw1ohxorVhEaeKQDnjRBEN6F//cN+Ef6EwAZ3f2EBQuWJQ+U=
=R/5j
-----END PGP PUBLIC KEY BLOCK-----
""";
