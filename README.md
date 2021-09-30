[![Cocoapods](https://img.shields.io/cocoapods/v/FRAuth?color=%23f46200&label=Version&style=flat-square)](CHANGELOG.md)


<p align="center">
  <a href="https://github.com/ForgeRock">
    <img src="https://www.forgerock.com/themes/custom/forgerock/images/fr-logo-horz-color.svg" alt="Logo">
  </a>
  <h2 align="center">ForgeRock SDK for iOS</h2>
  <p align="center">
    <a href="./CHANGELOG.md">Change Log</a>
    ·
    <a href="#support">Support</a>
    ·
    <a href="#documentation" target="_blank">Docs</a>
  </p>
  <hr/>
</p>

 The ForgeRock iOS SDK enables you to quickly integrate the [ForgeRock Identity Platform](https://www.forgerock.com/digital-identity-and-access-management-platform) into your iOS apps.

Use the SDKs to leverage _[Intelligent Authentication](https://www.forgerock.com/platform/access-management/intelligent-authentication)_ in [ForgeRock's Access Management (AM)](https://www.forgerock.com/platform/access-management) product, to easily step through each stage of an authentication tree by using callbacks.

<!------------------------------------------------------------------------------------------------------------------------------------>
<!-- REQUIREMENTS - Supported AM versions, API versions, any other requirements. -->

## Requirements

* ForgeRock Identity Platform
    * Access Management (AM) 6.5.2+
* iOS 10 and above   
* Xcode
* Swift 5.x or Objective-C
* CocoaPods or Swift Package Manager (optional)

<!------------------------------------------------------------------------------------------------------------------------------------>
<!-- INSTALLATION -->

## Installation

### Cocoapods
Use the following pods in your `Podfile` to install FR iOS SDK module(s) if you want to install the latest version.

```
pod 'FRAuth' // Authentication module for Access Manager
pod 'FRUI' // UI SDK demonstrates FRAuth SDK functionalities
pod 'FRProximity' // Add-on for FRAuth's Device Profile feature related to location, and BLE
pod 'FRAutheneticator' // Authenticator module that generates HOTP, TOTP, and Push registration/authentication
pod 'FRGoogleSignIn' // Social Login module for Google Sign In
pod 'FRFacebookSignIn' // Social Login module for Facebook Login
```

### Swift Package Manager
> * The ForgeRock iOS SDK is available via Swift Package Manager from 3.0.0 and above. Any older versions (2.2.0 and below) are only available via Cocoapods.
> * `FRGoogleSignIn` module is currently not available in Swift Package Manager; use Cocoapods instead to integrate `FRGoogleSignIn` module.
 
1. In Xcode menus, `File` -> `Swift Packages` -> `Add Package Dependencies...`
2. Select the project to integrate the ForgeRock iOS SDK
3. Enter the url of the repo: `https://github.com/ForgeRock/forgerock-ios-sdk`
4. Select module(s) to integrate into the project

<!------------------------------------------------------------------------------------------------------------------------------------>
<!-- QUICK START - Get one of the included samples up and running in as few steps as possible. -->

## Getting Started

To try out the ForgeRock iOS SDK sample, perform these steps:

1. Setup an Access Management (AM) instance, as described in the [documentation](https://sdks.forgerock.com/ios/01_prepare-am/).
2. Clone this repo:
    ```
    git clone https://github.com/ForgeRock/forgerock-ios-sdk.git
    ```
3. Open the `/SampleApps/FRExample.xcworkspace` file in [Xcode](https://developer.apple.com/xcode/).
4. Open `/FRExample/FRExample/Configs/FRAuthConfig.plist` and edit the values to match your AM instance.
5. Ensure the active scheme is "_FRExample-Swift_", and then click the **Run** button.

<!------------------------------------------------------------------------------------------------------------------------------------>
<!-- SAMPLES - List the samples we include with the SDKs, where they are, briefly what they show. -->

## Samples

ForgeRock provides these samples to help demonstrate SDK functionality:

- **Swift Sample - `/FRExample/`**

    This sample Swift app demonstrates authenticating to an AM instance, both with and without the `FRUser` automatic user interface. 
    
    Other features include:

    - OAuth 2.0 access tokens
    - Logout
    - Collecting device information
    - Get the current user's details
    - Jailbreak detection

    Configure your AM instance settings in the `/FRexampleObjC/FRexampleObjC/Configs/FRAuthConfig.plist` file to use this sample application.

- **Objective-C Sample - `/FRexampleObjC/`**

    This sample Objective-C app demonstrates authenticating to an AM instance, both with and without the `FRUser` automatic user interface. 
    
    Other features include:

    - Logout
    - Collecting device information
    - Get the current user's details
    - Jailbreak detection

    Configure your AM instance settings in the `/FRExample/FRExample/Configs/FRAuthConfig.plist` file to use this sample application.
    
- **Authenticator App Sample - `/FRAuthenticatorExample/`**
	This Authenticator sample app demonstrates HMAC-based, and Time-based One-time Password, and Push Registration and Authentication with ForgeRock's Access Manager.


<!------------------------------------------------------------------------------------------------------------------------------------>
<!-- DOCS - Link off to the AM-centric documentation at sdks.forgerock.com. -->

## Documentation

Documentation for the SDKs is provided at **<https://sdks.forgerock.com>**, and includes topics such as:

* Introducting the SDK Features
* Preparing AM for use with the SDKS
* API Reference documentation

<!------------------------------------------------------------------------------------------------------------------------------------>
<!-- SUPPORT -->

## Support

If you encounter any issues, be sure to check our **[Troubleshooting](https://backstage.forgerock.com/knowledge/kb/article/a79362752)** pages.

Support tickets can be raised whenever you need our assistance; here are some examples of when it is appropriate to open a ticket (but not limited to):

* Suspected bugs or problems with ForgeRock software.
* Requests for assistance - please look at the **[Documentation](https://sdks.forgerock.com)** and **[Knowledge Base](https://backstage.forgerock.com/knowledge/kb/home/g32324668)** first.

You can raise a ticket using **[BackStage](https://backstage.forgerock.com/support/tickets)**, our customer support portal that provides one stop access to ForgeRock services. 

BackStage shows all currently open support tickets and allows you to raise a new one by clicking **New Ticket**.

<!------------------------------------------------------------------------------------------------------------------------------------>
<!-- COLLABORATION -->

## Contributing

If you would like to contribute to this project you can fork the repository, clone it to your machine and get started.

<!------------------------------------------------------------------------------------------------------------------------------------>
<!-- LEGAL -->

## Disclaimer

> This code is provided by ForgeRock on an “as is” basis, without warranty of any kind, to the fullest extent permitted by law. ForgeRock does not represent or warrant or make any guarantee regarding the use of this code or the accuracy, timeliness or completeness of any data or information relating to this code, and ForgeRock hereby disclaims all warranties whether express, or implied or statutory, including without limitation the implied warranties of merchantability, fitness for a particular purpose, and any warranty of non-infringement. ForgeRock shall not have any liability arising out of or related to any use, implementation or configuration of this code, including but not limited to use for any commercial purpose. Any action or suit relating to the use of the code may be brought only in the courts of a jurisdiction wherein ForgeRock resides or in which ForgeRock conducts its primary business, and under the laws of that jurisdiction excluding its conflict-of-law provisions.


<!------------------------------------------------------------------------------------------------------------------------------------>
<!-- LICENSE -->

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details

---

&copy; Copyright 2020 ForgeRock AS. All Rights Reserved

[forgerock-logo]: https://www.forgerock.com/themes/custom/forgerock/images/fr-logo-horz-color.svg "ForgeRock Logo"
