/*
 * Copyright (c) 2020 Matei Sîrbu
 */

import UIKit

class SecondaryController: UIViewController, UITextFieldDelegate {

    @IBOutlet weak var publicKeyLabel: UILabel!
    @IBOutlet weak var encryptedTextField: UITextField!
    @IBOutlet weak var decryptedTextLabel: UILabel!
    
    override func viewDidLoad() {
        super.viewDidLoad()
        self.encryptedTextField.delegate = self
        do {
            publicKeyLabel.text = try SecureEnclaveManager.Shared.getPublicKeyHex();
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
    
    @IBAction func decrypt(_ sender: Any) {
        do {
            if (encryptedTextField.text != nil)
            {
                let decrypted = try SecureEnclaveManager.Shared.decrypt(input:  encryptedTextField.text!)
                decryptedTextLabel.text = String(data: decrypted, encoding: .utf8)
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
