import Flutter
import UIKit
import SCrypto
import Security

public class SwiftFlutterStringEncryptionPlugin: NSObject, FlutterPlugin {
  public static func register(with registrar: FlutterPluginRegistrar) {
    let channel = FlutterMethodChannel(name: "flutter_string_encryption", binaryMessenger: registrar.messenger())
    let instance = SwiftFlutterStringEncryptionPlugin()
    registrar.addMethodCallDelegate(instance, channel: channel)
  }

  public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    switch call.method {
    case "decrypt":
      guard let args = call.arguments as? [String: String] else {
        fatalError("args are formatted badly")
      }
      let data = args["data"]!
      let keyString = args["key"]!

      let civ = CipherIvMac(base64IvAndCiphertext: data)
      let keys = AESHMACKeys(base64AESAndHMAC: keyString)
      do {
        let decrypted = try keys.decryptToString(data: civ)

        result(decrypted)
      } catch (CryptoError.macMismatch) {
        result(FlutterError(code: "mac_mismatch", message: "mac don't match", details: nil))
      } catch {
        fatalError("\(error)")
      }

    case "encrypt":
      guard let args = call.arguments as? [String: String] else {
        fatalError("args are formatted badly")
      }
      let string = args["string"]!
      let keyString = args["key"]!

      let keys = AESHMACKeys(base64AESAndHMAC: keyString)
      let encrypted = keys.encrypt(string: string)

      result(encrypted.base64EncodedString)

    case "generate_random_key":
      let key = AESHMACKeys.random()
      let keyString = key.base64EncodedString

      result(keyString)

    case "generate_salt":
      let salt = AESHMACKeys.generateSalt()

      result(salt)

    case "generate_key_from_password":
      guard let args = call.arguments as? [String: String] else {
        fatalError("args are formatted badly")
      }
      let password = args["password"]!
      let salt = args["salt"]!

      let key = AESHMACKeys(password: password, salt: salt)

      result(key.base64EncodedString)
        
    case "generate_public_private_key_pair":
      guard let arg = call.arguments as? [String: String],
        let tag = arg["tag"] else {
        fatalError("args are formatted badly")
      }
      do {
        if let publicKey = try getPublicKeyFromTag(tag: tag),
          let b64pubKey = base64EncodeKey(key: publicKey) {
          result(b64pubKey)
        } else {
          let publicKey = try generateKeys(tag: tag)
          if let b64pubKey = base64EncodeKey(key: publicKey) {
              result(b64pubKey)
          } else {
              fatalError("Error generating keys.")
          }
        }
      } catch {
        fatalError("Error generating keys.")
      }
    case "get_public_key":
      guard let arg = call.arguments as? [String: String],
        let tag = arg["tag"] else {
        fatalError("args are formatted badly")
      }
      do {
        if let publicKey = try getPublicKeyFromTag(tag: tag) {
          result(base64EncodeKey(key: publicKey))
        }
      } catch {
        
      }
    case "delete_public_private_key_pair":
      guard let arg = call.arguments as? [String: String],
        let tag = arg["tag"] else {
        fatalError("args are formatted badly")
      }
      
      do {
        try deleteKeyWithTag(tag: tag)
      } catch {
        fatalError("Error generating keys.")
      }
    case "encrypt_message_with_public_key":
      guard let arg = call.arguments as? [String: String],
        let message = arg["message"],
        let public_key = arg ["public_key"] else {
          fatalError("args are formatted badly")
      }
      do {
        result(try encrypt(message: message, base64key: public_key))
      } catch {
        fatalError("Error encrypting message")
      }
    case "decrypt_message_with_key":
      guard let arg = call.arguments as? [String: String],
      let message = arg["message"],
        let tag = arg["tag"] else {
          fatalError("args are formatted badly")
      }
      do {
        result(try decrypt(message: message, tag: tag))
      } catch {
        fatalError("Error decrypting message")
      }
    default: result(FlutterMethodNotImplemented)
    }
  }
  
  func deleteKeyWithTag(tag: String) throws {
    let tag = tag.data(using: .utf8)!
    let getquery: [String: Any] = [kSecClass as String: kSecClassKey,
                                   kSecAttrApplicationTag as String: tag,
                                   kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                                   kSecReturnRef as String: true]
    
    let status = SecItemDelete(getquery as CFDictionary)
    guard status == errSecSuccess || status == errSecItemNotFound else {
      throw KeychainError.unhandledError(status: status)
    }
  }
    
  func base64EncodeKey(key: SecKey) -> String? {
    var error: Unmanaged<CFError>?
    guard let cfdata = SecKeyCopyExternalRepresentation(key, &error) else {
        return nil
    }
    let data:Data = cfdata as Data
    let b64Key = data.base64EncodedString()
    return b64Key
  }
    
  func getPublicKeyFromTag(tag: String) throws -> SecKey? {
    guard let privateKey = try self.getPrivateKeyFromTag(tag: tag),
      let publicKey = SecKeyCopyPublicKey(privateKey) else {
      throw NSError(domain: NSOSStatusErrorDomain, code: 0 , userInfo: nil)
    }
    return publicKey
  }
  
  func getPrivateKeyFromTag(tag: String) throws -> SecKey? {
    let tag = tag.data(using: .utf8)!
    let getquery: [String: Any] = [kSecClass as String: kSecClassKey,
                                   kSecAttrApplicationTag as String: tag,
                                   kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                                   kSecReturnRef as String: true]
    var item: CFTypeRef?
    let status = SecItemCopyMatching(getquery as CFDictionary, &item)
    guard status == errSecSuccess else { return nil }
    let privateKey = item as! SecKey
    return privateKey
  }
    
  func generateKeys(tag: String) throws -> SecKey {
    let tag = tag.data(using: .utf8)!
    let attributes: [String: Any] =
      [kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
       kSecAttrKeySizeInBits as String: 2048,
       kSecPrivateKeyAttrs as String:
        [
          kSecAttrIsPermanent as String: true,
          kSecAttrApplicationTag as String: tag
        ]
    ]
    
    var error: Unmanaged<CFError>?
    guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
        throw error!.takeRetainedValue() as Error
    }
    
    guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
      throw NSError(domain: NSOSStatusErrorDomain, code: 0 , userInfo: nil)
    }
    return publicKey
  }
  
  func encrypt(message: String, base64key: String) throws -> String {
    let key = Data.init(base64Encoded: base64key)
    if key == nil { // base64key was not valid base64 encoded
      throw NSError(domain: NSOSStatusErrorDomain, code: 0 , userInfo: nil)
    }
    let keyDict:[NSObject:NSObject] = [
      kSecAttrKeyType: kSecAttrKeyTypeRSA,
      kSecAttrKeyClass: kSecAttrKeyClassPublic,
      kSecAttrKeySizeInBits: NSNumber(value: 2048),
      kSecReturnPersistentRef: true as NSObject
    ]
    let publickeysi = SecKeyCreateWithData(key! as CFData, keyDict as CFDictionary, nil)
    let blockSize = SecKeyGetBlockSize(publickeysi!)
    var messageEncrypted = [UInt8](repeating: 0, count: blockSize)
    var messageEncryptedSize = blockSize
    
    var status: OSStatus!
    
    status = SecKeyEncrypt(publickeysi!, .PKCS1, message, message.count, &messageEncrypted, &messageEncryptedSize)
    
    if status != noErr {
      print("Encryption Error!")
      throw NSError(domain: NSOSStatusErrorDomain, code: 0 , userInfo: nil)
    }
    let encryptedData = Data(messageEncrypted)
    let b64encodedEncryptedData = encryptedData.base64EncodedString()
    return b64encodedEncryptedData
  }
  
  func decrypt(message: String, tag: String) throws -> String {
    guard let privateKey = try self.getPrivateKeyFromTag(tag: tag) else {
      throw NSError(domain: NSOSStatusErrorDomain, code: 0, userInfo: nil)
    }
    
    if let encryptedData = Data(base64Encoded: message) {
    let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: encryptedData.count)
    let stream = OutputStream(toBuffer: buffer, capacity: encryptedData.count)
    
    stream.open()
    encryptedData.withUnsafeBytes({ (p: UnsafePointer<UInt8>) -> Void in
      stream.write(p, maxLength: encryptedData.count)
    })
    
    stream.close()
    
    let encPointer = UnsafePointer<UInt8>(buffer)
      let blockSize = SecKeyGetBlockSize(privateKey)
      var decryptedData = [UInt8](repeating: 0, count: Int(blockSize))
      var decryptedDataLength = blockSize
      
      let result = SecKeyDecrypt(privateKey, SecPadding(arrayLiteral: SecPadding.PKCS1), encPointer, decryptedDataLength, &decryptedData, &decryptedDataLength)
      if let clearText = String(bytes: decryptedData, encoding: String.Encoding.utf8) {
        return clearText
      } else {
        throw NSError(domain: NSOSStatusErrorDomain, code: 0, userInfo: nil)
      }
    } else {
      throw NSError(domain: NSOSStatusErrorDomain, code: 0, userInfo: nil)
    }
  }
}

struct CipherIvMac {
  let iv: Data
  let mac: Data
  let cipher: Data

  var base64EncodedString: String {
    let ivString = self.iv.base64EncodedString()
    let cipherString = self.cipher.base64EncodedString()
    let macString = self.mac.base64EncodedString()
    return "\(ivString):\(macString):\(cipherString)"
  }

  init(iv: Data, mac: Data, cipher: Data) {
    self.iv = iv
    self.mac = mac
    self.cipher = cipher
  }

  init(base64IvAndCiphertext: String) {
    let civArray = base64IvAndCiphertext.split(separator: ":")
    guard civArray.count == 3 else {
      fatalError("Cannot parse iv:ciphertext:mac")
    }
    self.iv = Data(base64Encoded: String(civArray[0]))!
    self.mac = Data(base64Encoded: String(civArray[1]))!
    self.cipher = Data(base64Encoded: String(civArray[2]))!
  }

  static func ivCipherConcat(iv: Data, cipher: Data) -> Data {
    var copy = iv
    copy.append(cipher)

    return copy
  }

  var ivCipherConcat: Data {
    return CipherIvMac.ivCipherConcat(iv: self.iv, cipher: self.cipher)
  }
}

struct AESHMACKeys {
  static let aesKeyLengthBits = 128
  static let ivLengthBytes = 16
  static let hmacKeyLengthBits = 256
  static let pbeSaltLenghtBits = aesKeyLengthBits // same size as key output
  static let pbeIterationCount: UInt32 = 10000

  let aes: Data
  let hmac: Data

  init(base64AESAndHMAC: String) {
    let array = base64AESAndHMAC.split(separator: ":")
    self.aes = Data(base64Encoded: String(array[0]))!
    self.hmac = Data(base64Encoded: String(array[1]))!
  }

  init(password: String, salt: String) {
    let password = password.data(using: String.Encoding.utf8)!
    let salt = Data(base64Encoded: salt)!
    let keyLength = AESHMACKeys.aesKeyLengthBits / 8 + AESHMACKeys.hmacKeyLengthBits / 8
    let derivedKey = try! password.derivedKey(
      salt,
      pseudoRandomAlgorithm: .sha1,
      rounds: AESHMACKeys.pbeIterationCount,
      derivedKeyLength: keyLength
    )

    // Split the random bytes into two parts:
    self.aes = derivedKey.subdata(in: 0..<AESHMACKeys.aesKeyLengthBits / 8)
    self.hmac = derivedKey.subdata(in: AESHMACKeys.aesKeyLengthBits / 8..<keyLength)
  }

  init(aes: Data, hmac: Data) {
    self.aes = aes
    self.hmac = hmac
  }

  static func random() -> AESHMACKeys {
    let aes = try! Data.random(AESHMACKeys.aesKeyLengthBits / 8)
    let hmac = try! Data.random(AESHMACKeys.hmacKeyLengthBits / 8)

    return .init(aes: aes, hmac: hmac)
  }

  static func generateSalt() -> String {
    let salt = try! Data.random(pbeSaltLenghtBits / 8)
    return salt.base64EncodedString()
  }

  func encrypt(string: String) -> CipherIvMac {
    let data = string.data(using: .utf8)!

    return self.encrypt(data: data)
  }

  func encrypt(data: Data) -> CipherIvMac {
    let iv = try! Data.random(AESHMACKeys.ivLengthBytes)
    let cipher = try! data.encrypt(.aes, options: .PKCS7Padding, key: self.aes, iv: iv)
    let concat = CipherIvMac.ivCipherConcat(iv: iv, cipher: cipher)
    let integrity = concat.hmac(.sha256, key: self.hmac)

    return CipherIvMac(iv: iv, mac: integrity, cipher: cipher)
  }

  func decrypt(data: CipherIvMac) throws -> Data {
    let concat = data.ivCipherConcat
    let hmac = concat.hmac(.sha256, key: self.hmac)

    // TODO: undestand if this is a constant time equality check
    if hmac != data.mac {
      throw CryptoError.macMismatch
    }
    let decrypted = try data.cipher.decrypt(.aes, options: .PKCS7Padding, key: self.aes, iv: data.iv)

    return decrypted
  }

  func decryptToString(data: CipherIvMac, encoding: String.Encoding = .utf8) throws -> String {
    let data = try self.decrypt(data: data)
    return String(data: data, encoding: encoding)!
  }

  var base64EncodedString: String {
    let aesString = self.aes.base64EncodedString()
    let hmacString = self.hmac.base64EncodedString()
    return "\(aesString):\(hmacString)"
  }
}

enum CryptoError: Error {
  case macMismatch
}

enum KeychainError: Error {
  case noPassword
  case unexpectedPasswordData
  case unhandledError(status: OSStatus)
}
