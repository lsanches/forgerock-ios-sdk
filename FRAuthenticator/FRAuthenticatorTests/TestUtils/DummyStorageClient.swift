// 
//  DummyStorageClient.swift
//  FRAuthenticatorTests
//
//  Copyright (c) 2020 ForgeRock. All rights reserved.
//
//  This software may be modified and distributed under the terms
//  of the MIT license. See the LICENSE file for details.
//

import UIKit
@testable import FRCore
@testable import FRAuthenticator

class DummyStorageClient: StorageClient {
    var setAccountResult: Bool?
    var removeAccountResult: Bool?
    var shouldMockGetAccountResult: Bool = false
    var getAccountResult: Account?
    var getAllAccountsResult: [Account]?
    var setMechanismResult: Bool?
    var removeMechanismResult: Bool?
    var getMechanismsForAccountResult: [Mechanism]?
    var shouldMockGetMechanismsForUUIDResult: Bool = false
    var getMechanismForUUIDResult: Mechanism?
    var setNotificationResult: Bool?
    var removeNotificationResult: Bool?
    var getAllNotificationsForMechanismResult: [PushNotification]?
    var isEmptyResult: Bool?
    var defaultStorageClient: KeychainServiceClient
    
    init() {
        self.defaultStorageClient = KeychainServiceClient()
    }
    
    
    @discardableResult func setAccount(account: Account) -> Bool {
        if let mockResult = self.setAccountResult {
            return mockResult
        }

        return self.defaultStorageClient.setAccount(account: account)
    }
    
    
    @discardableResult func removeAccount(account: Account) -> Bool {
        if let mockResult = self.removeAccountResult {
            return mockResult
        }
        
        return self.defaultStorageClient.removeAccount(account: account)
    }
    
    
    func getAccount(accountIdentifier: String) -> Account? {
        if self.shouldMockGetAccountResult {
            return self.getAccountResult
        }
        return self.defaultStorageClient.getAccount(accountIdentifier: accountIdentifier)
    }
    
    
    func getAllAccounts() -> [Account] {
        if let mockResult = self.getAllAccountsResult {
            return mockResult
        }
        return self.defaultStorageClient.getAllAccounts()
    }
    
    
    @discardableResult func setMechanism(mechanism: Mechanism) -> Bool {
        if let mockResult = self.setMechanismResult {
            return mockResult
        }
        return self.defaultStorageClient.setMechanism(mechanism: mechanism)
    }
    
    
    @discardableResult func removeMechanism(mechanism: Mechanism) -> Bool {
        if let mockResult = self.removeMechanismResult {
            return mockResult
        }
        return self.defaultStorageClient.removeMechanism(mechanism: mechanism)
    }
    

    func getMechanismsForAccount(account: Account) -> [Mechanism] {
        if let mockResult = self.getMechanismsForAccountResult {
            return mockResult
        }
        return self.defaultStorageClient.getMechanismsForAccount(account: account)
    }
    
    
    func getMechanismForUUID(uuid: String) -> Mechanism? {
        if self.shouldMockGetMechanismsForUUIDResult {
            return self.getMechanismForUUIDResult
        }
        return self.defaultStorageClient.getMechanismForUUID(uuid: uuid)
    }
    
    
    @discardableResult func setNotification(notification: PushNotification) -> Bool {
        if let mockResult = self.setNotificationResult {
            return mockResult
        }
        return self.defaultStorageClient.setNotification(notification: notification)
    }
    
    
    @discardableResult func removeNotification(notification: PushNotification) -> Bool {
        if let mockResult = self.removeNotificationResult {
            return mockResult
        }
        return self.defaultStorageClient.removeNotification(notification: notification)
    }
    
    
    func getAllNotificationsForMechanism(mechanism: Mechanism) -> [PushNotification] {
        if let mockResult = self.getAllNotificationsForMechanismResult {
            return mockResult
        }
        return self.defaultStorageClient.getAllNotificationsForMechanism(mechanism: mechanism)
    }
    
    
    @discardableResult func isEmpty() -> Bool {
        if let mockResult = self.isEmptyResult {
            return mockResult
        }
        return self.defaultStorageClient.isEmpty()
    }
}
