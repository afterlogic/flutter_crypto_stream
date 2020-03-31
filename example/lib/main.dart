import 'dart:io';
import 'dart:math';

import 'package:crypto_stream/algorithm/pgp.dart';
import 'package:flutter/material.dart';
import 'package:path_provider/path_provider.dart';

void main() => runApp(MyApp());

class MyApp extends StatelessWidget {
  // This widget is the root of your application.
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

  final textCtrl = TextEditingController();
  var outText = "";
  List<int> outByte = [];

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
                      child: Text("checkKey"),
                      onPressed: checkKey,
                    ),
                  ),
                ],
              ),
            ),
            Text(outText),
          ],
        ),
      ),
    );
  }

  encrypt() async {
    var currentBytes = textCtrl.text.codeUnits;
    outByte = List<int>();
    pgp.encrypt(null, [publicKey], password).listen((data) {
      outByte.addAll(data);
    }, onError: (e, s) {
      print(s);
      outText = "$e\n\n\n$s";
    }).onDone(() {
      outText = String.fromCharCodes(outByte);
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
    var currentBytes = outByte;
    outByte = List<int>();
    pgp.decrypt(privateKey, null, password).listen((data) {
      outByte.addAll(data);
    }, onError: (e, s) {
      print(s);
      outText = "$e\n\n\n$s";
    }).onDone(() {
      outText = String.fromCharCodes(outByte);
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

    var currentBytes = textCtrl.text.codeUnits;
    outByte = List<int>();
    pgp.symmetricallyEncrypt(tempFile, password, currentBytes.length).listen(
      (data) {
        outByte.addAll(data);
      }, onError: (e, s) {
      print(s);
      outText = "$e\n\n\n$s";
    }
    ).onDone(
      () {
        outText = String.fromCharCodes(outByte);
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
    var currentBytes = outByte;
    outByte = List<int>();
    pgp.symmetricallyDecrypt(password).listen(
      (data) {
        outByte.addAll(data);
      }, onError: (e, s) {
      print(s);
      outText = "$e\n\n\n$s";
    }
    ).onDone(
      () {
        outText = String.fromCharCodes(outByte);
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
Version: BCPG v1.61

lQPGBF5+IEMBCAC1Y2C2RugKIL+nY7UgqcPFNrI0R4PiJfyWdDb41lYQ6sFq7YNc
SY8+bFRKCjz18bVkL6krnR8HGLAjrIuEWrgFdyo/AFsdtOo2151SPqWVFgTOF87S
39CidBJHEe4/wurFmyAsNvP+C6Lva7wHkDcAJUP7SGT5rRgkBx/9rTXCy5lcb5s5
bKzQf8wX1RUFp78ZtDrr3hIJ+8P1I2iXm+1TPKir2YZ7OG4eUy7x3F3XkNeiHXDF
Vl/MZFYeiBV5FCMpakFXLjoY6m17aByX+dWPapJTxl52l5j/hVmcSRVCs5NR59ID
v79gd8jDMYCDk44jJ9yeJskY5lTdlKaL0k8bABEBAAH+CQMCA+9lk7A40w1g9I0T
Z+XpjbZqWNWq5YoWtU4BoORbicNLcnAXJJ1jzPuNUq9f/XpkR9hXECginqUTeuHA
LwNW+3LpHYyNF16wZGEsj/YsTkWBCO8sKJ1xf/Ux37Z/nieR4O2pYhwdK1/dJYbl
/Qxh6hGXGUF4omS+ZtX50rDpUcocCTSQAHS1LQ3ckGnuAud07CWAnMHRhlHApiPj
ZbyuRHSxtpmS0W1uBp99KlCHOXH0BfrGbGHc2DTZ5LIuSCCz+yq+oeoKC54652Gd
LBgu5jiQwtZCSK5mdzIWBdoIuUn5jsfa3dpQ2YR8gA0Eu3GVc0ce2srSBN6J88e+
B2xhhnLDE0n5tsktg2Ua9mmFuwVnVucxZN3d5Tk2k2sV9GhN8FEwEhxQYdnC8IQJ
2gPgcTTYi6SpFIf4BSTamYq0c6JbWcdP3IiJLsVJTOSJIxY+pqeRsxP4f+jdV96n
eqWnymPnlVJzHlKtJu81aVIESrjlO3uCABjjDYPcVbeAIdce94haUL+/ikyAqBcK
62lDnXYKgOx71z23NyOEj1shXT/jB21fbUHvrDDaB623UlMxuB+fiJHU01iyp6YB
kznp1ybmkw7OtIHqzW0hXRDKxiRTf+eq+me4OnBpunIXvGQO5KJZbVKbmzJZZXxD
43+njACFoDM41UMmsWCWJtxZYDCCvjDUFXzkBnzXedJPALExTKYvMbR2RfENO5NA
zlydK8yVjfojzz4Uh+91tmfrmogTIa6SWhCmyclpI6r/hd9WKsdUbafdg/Z9BXBj
giLQotj0VICXuL5+gZQFc9cKfycYmWP6teCC3Kj63pLP680e2yTi+1cjYD96SmcA
sSuYq9QZRlsrhFc1C3/Bj9nmKmclRBckkyBNDJJ2IYQcPMZwuJSAq9pF2h0V4SXU
T+05hIAREZb+tA10ZXN0QHRlc3QuY29tiQEzBBMBCgAdBQJefiBDAhsvBRYCAwEA
BAsJCAcFFQoJCAsCHgEACgkQC1kxFGk32IUVwAf+J1SxfhYIeK1QMA0f2B2wDJpB
nTp8+NEoUbn8IeQVwyRLNFPCvi8QD6TP8/kuDRUjSe/280O/Pr6MXnK3l0nojGdJ
9f4mOw5QcGAsAI0D7XQPZRQ/U/Gl40zCYputEB4tF9RjVu10f+sdYsQ/kgQQT3if
ILlfxlNPGVKdR6L2/Uvkyocx5NyXa/gKcQ7ozfeS2DD7guFWa22CBzNoR3w8jwrh
qsKMdKqIF53CixlldzXxFcA6KhPPa0GWL+oae7HVMj0cRiuWPvefhWTnq8GNN+WB
y+0Pem7KR2D0xXMrRpvgQLJRRVPqXD7jZw2KCai5pOtiU5Fb3ommkfVPIglHDg==
=gy3V
-----END PGP PRIVATE KEY BLOCK-----
""";
final publicKey = """
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: BCPG v1.61

mQENBF5+IEMBCAC1Y2C2RugKIL+nY7UgqcPFNrI0R4PiJfyWdDb41lYQ6sFq7YNc
SY8+bFRKCjz18bVkL6krnR8HGLAjrIuEWrgFdyo/AFsdtOo2151SPqWVFgTOF87S
39CidBJHEe4/wurFmyAsNvP+C6Lva7wHkDcAJUP7SGT5rRgkBx/9rTXCy5lcb5s5
bKzQf8wX1RUFp78ZtDrr3hIJ+8P1I2iXm+1TPKir2YZ7OG4eUy7x3F3XkNeiHXDF
Vl/MZFYeiBV5FCMpakFXLjoY6m17aByX+dWPapJTxl52l5j/hVmcSRVCs5NR59ID
v79gd8jDMYCDk44jJ9yeJskY5lTdlKaL0k8bABEBAAG0DXRlc3RAdGVzdC5jb22J
ATMEEwEKAB0FAl5+IEMCGy8FFgIDAQAECwkIBwUVCgkICwIeAQAKCRALWTEUaTfY
hRXAB/4nVLF+Fgh4rVAwDR/YHbAMmkGdOnz40ShRufwh5BXDJEs0U8K+LxAPpM/z
+S4NFSNJ7/bzQ78+voxecreXSeiMZ0n1/iY7DlBwYCwAjQPtdA9lFD9T8aXjTMJi
m60QHi0X1GNW7XR/6x1ixD+SBBBPeJ8guV/GU08ZUp1Hovb9S+TKhzHk3Jdr+Apx
DujN95LYMPuC4VZrbYIHM2hHfDyPCuGqwox0qogXncKLGWV3NfEVwDoqE89rQZYv
6hp7sdUyPRxGK5Y+95+FZOerwY035YHL7Q96bspHYPTFcytGm+BAslFFU+pcPuNn
DYoJqLmk62JTkVveiaaR9U8iCUcO
=tf8f
-----END PGP PUBLIC KEY BLOCK-----
""";
