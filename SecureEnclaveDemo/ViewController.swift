/*
 * Copyright (c) 2020 Matei Sîrbu
 */

import UIKit

class ViewController: UIViewController, UITextFieldDelegate {

    @IBOutlet weak var publicKeyLabel: UILabel!
    @IBOutlet weak var inputTextField: UITextField!
    @IBOutlet weak var encryptedTextField: UITextField!
    
    @IBAction func regenerateKeypair(_ sender: Any) {
        do {
            try SecureEnclaveManager.Shared.deleteKeyPair()
            try SecureEnclaveManager.Shared.getKeys()
            let hexPublicKey = try SecureEnclaveManager.Shared.getPublicKeyHex();
            publicKeyLabel.text = hexPublicKey
            print("Cheie publică regenerată: \(hexPublicKey)")
        }
        catch let error {
            showError(err: error)
        }
    }
    
    @IBAction func showDecryptionView() {
        let controller = storyboard?.instantiateViewController(identifier: "secondaryController") as! SecondaryController
        present(controller, animated: true)
    }
    
    override func viewDidLoad() {
        super.viewDidLoad()
        self.inputTextField.delegate = self
        self.encryptedTextField.delegate = self
        do {
            try SecureEnclaveManager.Shared.getKeys()
            let hexPublicKey = try SecureEnclaveManager.Shared.getPublicKeyHex();
            publicKeyLabel.text = hexPublicKey
            print("Cheie publică: \(hexPublicKey)")
        }
        catch let error {
            showError(err: error)
        }
    }
    
    func showError(err: Error) {
        if let error = err as? SecureEnclaveManager.SecureEnclaveError {
            let alert = UIAlertController(title: "Eroare \(error.osStatus == nil ? "" : "(Security \(error.osStatus!))")", message: error.message, preferredStyle: UIAlertController.Style.alert)
            
            alert.addAction(UIAlertAction(title: "OK", style: UIAlertAction.Style.default, handler: nil))
            self.present(alert, animated: true, completion: nil)
        }
        else {
            print("Eroare: \(err.localizedDescription)");
            let alert = UIAlertController(title: "Eroare", message: err.localizedDescription, preferredStyle: UIAlertController.Style.alert)
            
            alert.addAction(UIAlertAction(title: "OK", style: UIAlertAction.Style.default, handler: nil))
            self.present(alert, animated: true, completion: nil)
        }
    }
    
    @IBAction func encrypt(_ sender: Any) {
        do {
            if (inputTextField.text != nil)
            {
                let encrypted = try SecureEnclaveManager.Shared.encrypt(input: inputTextField.text!)
                let encryptedAsHex = encrypted.map { String(format: "%02hhx", $0) }.joined()
                encryptedTextField.text = encryptedAsHex
                print("Text criptat: \(encryptedAsHex)")
            }
        }
        catch let error {
            showError(err: error)
        }
    }
    
    func textFieldShouldReturn(_ textField: UITextField) -> Bool {
        textField.resignFirstResponder()
        return true
    }
    
}

