import Flutter
import UIKit
import RxSwift

public class SwiftCryptoStreamPlugin: NSObject, FlutterPlugin,FlutterStreamHandler {
    var methodCallHandler : FlutterMethodCallHandler?
    let pgpApi = LibComAfterlogicPgpPgpApi()
    let pgpUtilApi = LibComAfterlogicPgpPgpUtilApi()
    var output : LibComAfterlogicPgpPlatform_streamPlatformOutputStream?
    var input : LibComAfterlogicPgpPlatform_streamPlatformInputStream?
    let flutterCallback : FlutterCallback
    let subject = BehaviorSubject<()->Void>(value: {})
    let disposable = CompositeDisposable()
    let executionScheduler = SerialDispatchQueueScheduler.init(qos: .background)
    
    override init() {
        flutterCallback = FlutterCallback(subject)
        
        super.init()
        JavaSecuritySecurity.addProvider(with: LibOrgBouncycastleJceProviderBouncyCastleProvider())
        disposable.insert(
            subject.observeOn(MainScheduler.instance)
                .subscribe({ it ->Void in
                    it.element?()
                })
        )
        methodCallHandler = ({  (call: FlutterMethodCall, result: @escaping FlutterResult) -> Void in
            let arguments = call.arguments as! [Any]
            let route = call.method.components(separatedBy: ".")
            let algorithm = route[0]
            let method = route[1]
            
            print("\(algorithm).\(method)")
            if(algorithm == "pgp" && method == "sendData"){
                self.flutterCallback.data((arguments[0] as! FlutterStandardTypedData).data)
                self.flutterCallback.result = result
                return
            }
            
            if(algorithm == "pgp" && method == "closeStream"){
                self.flutterCallback.close()
                self.flutterCallback.result = result
                return
            }
            
            self.disposable.insert(
                Single<Any>.create (subscribe: { observer -> Disposable in
                    do{
                        try ObjC.catchException {
                            do{
                                observer(.success( try self.methodExecute(algorithm, method, arguments)))
                            }catch{
                                observer(.error(error))
                            }
                        }
                    }catch{
                        observer(.error(error))
                    }
                    return Disposables.create {}
                })
                    .subscribeOn(self.executionScheduler)
                    .observeOn(MainScheduler.instance)
                    .subscribe(onSuccess: { (any) in
                        result(any)
                    }, onError: { (error) in
                        print(error)
                        if error is NotImplemented{
                            result(FlutterMethodNotImplemented)
                        } else if error is LibComAfterlogicPgpPgpError {
                            let pgpError = error as! LibComAfterlogicPgpPgpError
                            result(FlutterError(code: pgpError.getCase()!.name(), message: "", details: ""))
                        } else {
                            result(FlutterError(code: "", message: error.localizedDescription, details: ""))
                        }
                    })
            )
        })
    }
    
    public func onListen(withArguments arguments: Any?, eventSink events: @escaping FlutterEventSink) -> FlutterError? {
        var arg = (arguments as! [Any]).makeIterator()
        let route = (arg.next() as! String).components(separatedBy: ".")
        let algorithm = route[0]
        let method = route[1]
        
        output = LibComAfterlogicPgpPlatform_streamPlatformOutputStream.init(libComAfterlogicPgpPlatform_streamStreamSink: FlutterSink(subject, events))
        input = LibComAfterlogicPgpPlatform_streamPlatformInputStream.init(libComAfterlogicPgpPlatform_streamStreamCallback: flutterCallback)
        flutterCallback.inputStream = input
        switch algorithm {
        case "pgp":
            switch method {
            case "encrypt":
                let privateKey = arg.next() as? String
                let publicKeys = arg.next() as? [String]
                let password = arg.next() as? String
                let iosArray = publicKeys == nil ? nil :IOSObjectArray.init(nsArray: publicKeys!, type: NSString_class_())
                streamExecute(events){
                    self.pgpApi.encrypt(with: privateKey, withNSStringArray: iosArray, with:  password, with: self.input, with: self.output)
                }
                break
            case "decrypt":
                let privateKey = arg.next() as? String
                let publicKeys = arg.next() as? [String]
                let password = arg.next() as? String
                let iosArray = publicKeys == nil ? nil :IOSObjectArray.init(nsArray: publicKeys!, type: NSString_class_())
                streamExecute(events){
                    self.pgpApi.decrypt(with: privateKey, withNSStringArray: iosArray, with:  password, with: self.input, with: self.output)
                }
                break
            case "symmetricallyEncrypt":
                let tempFile = arg.next() as? String
                let password = arg.next() as? String
                let length = arg.next() as? NSNumber
                
                streamExecute(events){
                    self.pgpApi.symmetricallyEncrypt(with: self.input, with: self.output, with: JavaIoFile.init(nsString: tempFile), with:JavaLangLong.init(long: jlong.init(exactly: length!)!), with: password)
                }
                break
            case "symmetricallyDecrypt":
                let password = arg.next() as? String
                
                streamExecute(events){
                    self.pgpApi.symmetricallyDecrypt(with: self.input, with: self.output, with: password)
                }
                break
            default:
                return FlutterError.init(code: "NotImplemented", message: nil, details: nil)
            }
            break
        default:
            return FlutterError.init(code: "NotImplemented", message: nil, details: nil)
        }
        return nil
    }
    
    public func onCancel(withArguments arguments: Any?) -> FlutterError? {
        output?.close()
        input?.close()
        return nil
    }
    
    
    func streamExecute(_ events: @escaping FlutterEventSink, _ create: @escaping ()  -> Void) {
        disposable.insert(   Completable.create (subscribe: { observer in
            do{
                try ObjC.catchException {
                    create()
                }
                observer(.completed)
            }catch{
                observer(.error(error))
            }
            return Disposables.create {}
        })
            .subscribeOn(executionScheduler)
            .observeOn(MainScheduler.instance)
            .subscribe(onCompleted: {
                events(FlutterEndOfEventStream)
            }, onError: { (error) in
                print(error)
                if error is LibComAfterlogicPgpPgpError {
                    let pgpError = error as! LibComAfterlogicPgpPgpError
                    events(FlutterError(code: pgpError.getCase()!.name(), message: "", details: ""))
                } else {
                    events(FlutterError(code: "", message: error.localizedDescription, details: ""))
                }
                events(FlutterEndOfEventStream)
            }))
    }
    
    func methodExecute(_ algorithm: String,_ method: String,_ arguments: [Any]) throws -> Any{
        var arg = arguments.makeIterator()
        switch algorithm {
        case "aes":
            let fileData = (arg.next() as! FlutterStandardTypedData).data
            let rawData = (arg.next() as! String).data(using: .utf8)
            let iv = (arg.next() as! String).data(using: .utf8)
            let isLast = arg.next() as! Bool
            let isDecrypt = method == "decrypt"
            return  Aes.performCryption(fileData, rawData!, iv!, isLast, isDecrypt)
        case "pgp":
            switch method {
            case "getKeyDescription":
                let key = arg.next() as! String
                let result : LibComAfterlogicPgpKeyDescription =  pgpUtilApi.getKeyDescription(with: key)
                let length = result.getLength()
                let emailsIterator = result.getEmails()?.iterator()
                var emails:[String?]=[]
                while (emailsIterator?.hasNext()==jboolean.init(true)) {
                    emails.append(emailsIterator?.next() as? String)
                }
                let isPrivate = result.isPrivate()
                return [length,emails,isPrivate,result.getArmoredKey()]
                
            case "createKeys":
                let length = arg.next() as! NSNumber
                let email = arg.next() as! String
                let password = arg.next() as! String
                
                return try createKeys(length,email,password)
            case "checkKeyPassword":	
                let key = (arg.next() as! String)
                let password = arg.next() as! String
                return  pgpUtilApi.checkKeyPassword(with: key, with: password)
            case "lastVerifyResult":
                return pgpApi.getLastVerifyResult()
            case "sign":
                let text = arg.next() as! String
                let privateKey = arg.next() as! String
                let password = arg.next() as! String
                return  pgpApi.sign(with: text, with: privateKey, with: password)!
            case "verify":
                let text = arg.next() as! String
                let publicKey = arg.next() as! String
                
                return  pgpApi.verify(with: text, withNSStringArray: IOSObjectArray.init(nsArray: [publicKey], type: NSString_class_()))!
            default:
                throw NotImplemented()
            }
        default:
            throw NotImplemented()
        }
    }

    func createKeys(_ length:NSNumber,_ email:String,_ password:String)throws ->[String]{
         let generateData = GenerateKeyData(email: email, password: password, masterKey: KeyData(strength: Int(length)), subkey: KeyData(strength: Int(length)))
         let pair = try PGPKeyRingFactory(generateKeyData: generateData)
         
        return [pair.publicKeyRing.armored(),pair.secretKeyRing.armored()]
     }
    
    public static func register(with registrar: FlutterPluginRegistrar) {
        
        let messanger = registrar.messenger()
        let channel = FlutterMethodChannel(name: "crypto_method", binaryMessenger: messanger)
        let event = FlutterEventChannel(name: "crypto_event", binaryMessenger: messanger)
        let plugin = SwiftCryptoStreamPlugin()
        event.setStreamHandler(plugin)
        channel.setMethodCallHandler(plugin.methodCallHandler)
    }
}
class FlutterCallback: LibComAfterlogicPgpPlatform_streamStreamCallback    {
    let subject : BehaviorSubject<()->Void>
    var inputStream: LibComAfterlogicPgpPlatform_streamPlatformInputStream?
    var result:  FlutterResult?
    
    init(_ subject : BehaviorSubject<()->Void>) {
        self.subject = subject
    }
    
    func data(_ data:Data){
        inputStream?.addBuffer(with: IOSByteArray.init(nsData: data))
    }
    override func close(){
        inputStream?.onClose()
    }
    
    override func invoke() {
        subject.on(.next({
            self.result?(nil)
            self.result = nil
        }))
    }
}

class FlutterSink :LibComAfterlogicPgpPlatform_streamStreamSink{
    let subject : BehaviorSubject<()->Void>
    let eventSink : FlutterEventSink
    
    init(_ subject : BehaviorSubject<()->Void>,_ eventSink : @escaping FlutterEventSink) {
        self.subject = subject
        self.eventSink = eventSink
    }
    
    override func add(with bytes: IOSByteArray!) {
        subject.on(.next({
            self.eventSink(bytes.toNSData()!)
        }))
    }
}

class NotImplemented : Error{
    
}

extension LibOrgBouncycastleOpenpgpPGPKeyRing {

    public func armored() -> String {
        let output = JavaIoByteArrayOutputStream()
        let armoredOutput = LibOrgBouncycastleBcpgArmoredOutputStream(javaIoOutputStream: output)
        encode(with: armoredOutput)
        armoredOutput.close()
        output.close()

        return output.toString(with: "UTF-8")
    }

}
