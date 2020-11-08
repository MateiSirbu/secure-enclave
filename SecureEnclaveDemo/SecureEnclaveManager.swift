/*
 * Copyright (c) 2020 Matei Sîrbu
 */

import Foundation
import Security

final class SecureEnclaveManager {
    
    static let Shared = SecureEnclaveManager()
    
    let publicLabel: String =  "eu.msirbu.SecureEnclaveDemo.publicKey"
    let privateLabel: String = "eu.msirbu.SecureEnclaveDemo.privateKey"
    let operationPrompt: String = "Authenticate to continue"
    
    struct SecureEnclaveError: Error {
        let message: String
        let osStatus: OSStatus?
        
        init(message: String, osStatus: OSStatus?) {
            self.message = message
            self.osStatus = osStatus
        }
    }
    
    func getAccessControl(with protection: CFString = kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, flags: SecAccessControlCreateFlags = [.userPresence, .privateKeyUsage]) throws -> SecAccessControl {
        
        var accessControlError: Unmanaged<CFError>?
        let accessControl = SecAccessControlCreateWithFlags(kCFAllocatorDefault, protection, flags, &accessControlError)
        
        return accessControl!
    }
    
    func forceSavePublicKey(publicKey: SecKey) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeEC,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrApplicationTag as String: publicLabel,
            kSecValueRef as String: publicKey,
            kSecAttrIsPermanent as String: true,
            kSecReturnData as String: true,
        ]
        
        var raw: CFTypeRef?
        var status = SecItemAdd(query as CFDictionary, &raw)
        
        if status == errSecDuplicateItem {
            status = SecItemDelete(query as CFDictionary)
            status = SecItemAdd(query as CFDictionary, &raw)
        }
        
        guard status == errSecSuccess else {
            throw SecureEnclaveError(message: "Nu se poate salva perechea de chei.", osStatus: status)
        }
    }
    
    func generateKeyPair(accessControl: SecAccessControl) throws -> (`public`: SecKey, `private`: SecKey) {
        let privateKeyParams: [String: Any] = [
            kSecAttrLabel as String: privateLabel,
            kSecAttrIsPermanent as String: true,
            kSecAttrAccessControl as String: accessControl,
        ]
        let params: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeEC,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: privateKeyParams
        ]
        var publicKey, privateKey: SecKey?
        
        let status = SecKeyGeneratePair(params as CFDictionary, &publicKey, &privateKey)
        
        guard status == errSecSuccess else {
            throw SecureEnclaveError(message: "Nu se poate genera perechea de chei.", osStatus: status)
        }
        
        return (public: publicKey!, private: privateKey!)
    }
    
    private func getPublicKeyDictionary() throws -> [String: Any] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeEC,
            kSecAttrApplicationTag as String: publicLabel,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecReturnData as String: true,
            kSecReturnRef as String: true,
            kSecReturnPersistentRef as String: true,
        ]
        
        var result: CFTypeRef? = nil
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess else {
            throw SecureEnclaveError(message: "Nu se poate aduce cheia privată pentru interogarea: \(query)", osStatus: status)
        }
        
        return ((result! as! CFDictionary) as! [String: Any])
    }
    
    private func getPrivateKey() throws -> SecKey {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrLabel as String: privateLabel,
            kSecReturnRef as String: true,
            kSecUseOperationPrompt as String: self.operationPrompt,
        ]
        
        var result: AnyObject? = nil
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess else {
            throw SecureEnclaveError(message: "Nu se poate aduce cheia privată pentru interogarea: \(query)", osStatus: status)
        }
        
        return result as! SecKey
    }
    
    func getKeys() throws -> (public: SecKey, private: SecKey) {
        if let publicKey = try? getPublicKeyDictionary()[kSecValueRef as String] as! SecKey?, let privateKey = try? getPrivateKey() {
            return (public: publicKey, private: privateKey)
        }
        else {
            let accessControl = try getAccessControl(with: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)
            let keypairResult = try generateKeyPair(accessControl: accessControl)
            try forceSavePublicKey(publicKey: keypairResult.public)
            return (public: try getPublicKeyDictionary()[kSecValueRef as String] as! SecKey, private: try getPrivateKey())
        }
    }
    
    func deleteKeyPair() throws {
        let publicKeyQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeEC,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrApplicationTag as String: publicLabel
        ]
        
        let privateKeyQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrLabel as String: privateLabel,
            kSecReturnRef as String: true,
        ]
        
        let publicKeyStatus = SecItemDelete(publicKeyQuery as CFDictionary)
        
        let privateKeyStatus = SecItemDelete(privateKeyQuery as CFDictionary)
        
        guard publicKeyStatus == errSecSuccess else {
            throw SecureEnclaveError(message: "Nu se poate șterge cheia publică.", osStatus: publicKeyStatus)
        }
        guard privateKeyStatus == errSecSuccess else {
            throw SecureEnclaveError(message: "Nu se poate șterge cheia privată.", osStatus: privateKeyStatus)
        }
    }
    
    func encrypt(input: String) throws -> Data {
        let publicKey = try getKeys().public
        let data = input.data(using: String.Encoding.utf8)!
        let result = SecKeyCreateEncryptedData(publicKey, SecKeyAlgorithm.eciesEncryptionStandardX963SHA256AESGCM, data as CFData, nil)
        if (result == nil)
        {
            throw SecureEnclaveError(message: "Decriptare eșuată.", osStatus: nil)
        }
        return result! as Data
    }
    
    func decrypt(input: String) throws -> Data {
        let privateKey = try getKeys().private
        let data = try hexStringToData(hex: input)
        let result = SecKeyCreateDecryptedData(privateKey, SecKeyAlgorithm.eciesEncryptionStandardX963SHA256AESGCM, data as CFData, nil)
        if (result == nil)
        {
            throw SecureEnclaveError(message: "Decriptare eșuată.", osStatus: nil)
        }
        return result! as Data
    }
    
    func getPublicKeyHex() throws -> String {
        let data: Data = try getPublicKeyDictionary()[kSecValueData as String] as! Data
        return data.map { String(format: "%02hhx", $0) }.joined()
    }
    
    func hexStringToData(hex: String) throws -> Data {
        var hex = hex
        var data = Data()
        while (hex.count > 0) {
            if (hex.count == 1)
            {
                throw SecureEnclaveError(message: "Text invalid.", osStatus: nil)
            }
            let subIndex = hex.index(hex.startIndex, offsetBy: 2)
            let c = String(hex[..<subIndex])
            hex = String(hex[subIndex...])
            var ch: UInt64 = 0
            Scanner(string: c).scanHexInt64(&ch)
            var char = UInt8(ch)
            data.append(&char, count: 1)
        }
        return data
    }
}

