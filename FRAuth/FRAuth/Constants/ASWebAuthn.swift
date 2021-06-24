// 
//  ASWebAuthn.swift
//  FRAuth
//
//  Copyright (c) 2021 ForgeRock. All rights reserved.
//
//  This software may be modified and distributed under the terms
//  of the MIT license. See the LICENSE file for details.
//


import Foundation
import AuthenticationServices

extension WAUserVerification {
    
    @available(iOS 15.0, *)
    func convertAS() -> ASAuthorizationPublicKeyCredentialUserVerificationPreference {
        switch self {
        case .preferred:
            return ASAuthorizationPublicKeyCredentialUserVerificationPreference.preferred
        case .required:
            return ASAuthorizationPublicKeyCredentialUserVerificationPreference.required
        case .discouraged:
            return ASAuthorizationPublicKeyCredentialUserVerificationPreference.discouraged
        }
    }
}


extension WAAttestationPreference {
    
    @available(iOS 15.0, *)
    func convertAS() -> ASAuthorizationPublicKeyCredentialAttestationKind {
        switch self {
        case .none:
            return ASAuthorizationPublicKeyCredentialAttestationKind.none
        case .direct:
            return ASAuthorizationPublicKeyCredentialAttestationKind.direct
        case .indirect:
            return ASAuthorizationPublicKeyCredentialAttestationKind.indirect
        }
    }
}

struct ASWebAuthn {
    
    static func extractAuthenticatorData(result: Data) -> AuthenticatorData? {
        //  Convert assertion or attestation into UInt8 array
        let resultUInt8Arr = [UInt8](result as Data)
        //  Using CBORReader, extract authData portion
        let cborReader = CBORReader(bytes: resultUInt8Arr)
        let resultMap = cborReader.readStringKeyMap()
        //  With authData, convert it into AuthenticatorData object
        if let authData = resultMap?["authData"] as? [UInt8], let authDataObj = AuthenticatorData.fromBytes(authData) {
            return authDataObj
        }
        FRLog.e("Failed to extract AuthenticatorData from given Attestation/Assertion")
        return nil
    }
    
    static func swapClientDataChallenge(clientData: Data, rawChallenge: String, type: String = "webauthn.create") throws -> String {
        do {
            if var clientDataJson = try JSONSerialization.jsonObject(with: clientData, options: []) as? [String: String] {
                let originalStr = String(data: clientData, encoding: .utf8)
                FRLog.w(originalStr ?? "")
                //  TODO: This maybe a bug from Apple that challenged included within clientDataJSON is base64 encoded; AM expects raw challenge with URL safe encoding only
                clientDataJson["challenge"] = rawChallenge.urlSafeEncoding()
                //  TODO: This is a bug from Apple that generated clientDataJSON for both registration and authentication is 'webauthn.create' which doesn't make sense
                clientDataJson["type"] = type
                let serializedData = try JSONSerialization.data(withJSONObject: clientDataJson, options: [])
                if let clientDataJsonStr = String(data: serializedData, encoding: .utf8) {
                    return clientDataJsonStr
                }
                else {
                    FRLog.e("Failed to convert updated ClientDataJSON into String")
                    throw WebAuthnError.badData
                }
            }
            else {
                FRLog.e("Failed to parse ClientDataJSON into JSON")
                throw WebAuthnError.badData
            }
        }
        catch {
            FRLog.e("Failed to convert ClientDataJSON")
            throw error
        }
    }
}
