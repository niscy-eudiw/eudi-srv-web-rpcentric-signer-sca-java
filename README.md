# EUDI RP-centric SCA

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

:heavy_exclamation_mark: **Important!** Before you proceed, please read
the [EUDI Wallet Reference Implementation project description](https://github.com/eu-digital-identity-wallet/.github/blob/main/profile/reference-implementation.md)

## Table of contents

- [EUDI RP-centric SCA](#eudi-rp-centric-sca)
  - [Table of contents](#table-of-contents)
  - [Overview](#overview)
  - [Disclaimer](#disclaimer)
  - [Sequence Diagrams](#sequence-diagrams)
    - [Credential Authorization](#credential-authorization)
  - [Endpoints](#endpoints)
    - [Calculate Hash Endpoint](#calculate-hash-endpoint)
    - [Obtain Signed Document Endpoint](#obtain-signed-document-endpoint)
  - [Deployment](#deployment)
    - [Requirements](#requirements)
    - [Signature Creation Application](#signature-creation-application)
  - [How to contribute](#how-to-contribute)
  - [License](#license)
    - [Third-party component licenses](#third-party-component-licenses)
    - [License details](#license-details)


## Overview

This is a REST API server implementing the RP-centric SCA for the remote Qualified Electronic Signature (rQES) component of the EUDI Wallet.

This implementation of the SCA serves as a component of a Relying Party (RP) web page. It runs on the port 8088 and can be used to sign documents.
Currently, the server is running and being used by the RP web page at the url https://rpcentric.signer.eudiw.dev/tester. However, you can also [deploy](#deployment) it in your environment.

The RP web page utilizing this SCA, which is defined in the repository [eudi-srv-web-rpcentric-signer-relyingparty-py](https://github.com/eu-digital-identity-wallet/eudi-srv-web-rpcentric-signer-relyingparty-py).
It communicates with a QTSP server, which is defined in the repository [eudi-srv-web-walletdriven-rpcentric-signer-qtsp-java](https://github.com/eu-digital-identity-wallet/eudi-srv-web-walletdriven-rpcentric-signer-qtsp-java), to achieve the remote Qualified Electronic Signature (rQES) functionality, as described in the relevant specifications

## Disclaimer

The released software is an initial development release version:

-   The initial development release is an early endeavor reflecting the efforts of a short timeboxed
    period, and by no means can be considered as the final product.
-   The initial development release may be changed substantially over time, might introduce new
    features but also may change or remove existing ones, potentially breaking compatibility with your
    existing code.
-   The initial development release is limited in functional scope.
-   The initial development release may contain errors or design flaws and other problems that could
    cause system or other failures and data loss.
-   The initial development release has reduced security, privacy, availability, and reliability
    standards relative to future releases. This could make the software slower, less reliable, or more
    vulnerable to attacks than mature software.
-   The initial development release is not yet comprehensively documented.
-   Users of the software must perform sufficient engineering and additional testing in order to
    properly evaluate their application and determine whether any of the open-sourced components is
    suitable for use in that application.
-   We strongly recommend not putting this version of the software into production use.
-   Only the latest version of the software will be supported

## Sequence Diagrams

### Credential Authorization

```mermaid
sequenceDiagram
title Document Signing

    actor U as UserAgent
    participant EW as EUDI Wallet    
    participant BR as Browser
    participant RP as Web Page (RP)
    participant SCA as Signature Creation Application (RP)
    participant AS as Authorization Server (QTSP)
    participant RS as Resource Server (QTSP)
    participant OIDV as OID4VP Verifier

    U->>+RP: Choose credential to use
    RP->>+SCA: Request document signing
    SCA->>+RS: Get certificate of the chosen credential (credentials/info)
    SCA->>+SCA: Get document's hash

    SCA->>+AS: /oauth2/authorize
    AS->>+OIDV: Authorization Request (POST {verifier}/ui/presentations)
    OIDV-->>-AS: Authorization Request returns
    AS->>+AS: Generate link to Wallet
    AS-->>-BR: Render link as QrCode

    EW->>+BR: Scan QrCode 
    EW->>+OIDV: Share requested information

    AS->>+OIDV: Request VP Token
    OIDV-->>-AS: Get and validate VP Token

    AS-->>-BR: Redirects to /oauth2/authorize (with session token)
    BR->>+AS: /oauth2/authorize [Cookie JSession]
    AS-->>-BR: Redirect to {sca_redirect_uri}?code={code}

    BR->>+SCA: {sca_redirect_uri}?code={code}
    SCA->>+AS: /oauth2/token?code={code}
    AS-->>-SCA: access token authorizing credentials use (SAD/R)

    SCA->>+RS: Sign hash request (/signatures/signHash)
    RS-->>-SCA: signature

    SCA->>+SCA: generate signed document 
    SCA-->>-RP: returns signed document
```


## Endpoints

### Sign Document Endpoint

* Method: POST
* URL: http://localhost:8086/signatures/doc

This endpoint initiates the process to obtain a signed document. 

The request header must include:
* **Authorization**: a valid access token from the QTSP, with the scope 'service'

The payload of the request is a JSON object containing the following attributes:
* **credentialID**: the ID of the credential to be used to signing the document.
* **documents**: a JSON array of objects, where each object includes a base64-encoded document content to be signed and additional request parameters.
* **hashAlgorithmOID**: the OID of the hash algorithm used to generate the document's digest value.
* **authorizationServerUrl** (optional): The URL of a custom Authorization Server, if the user wishes to use one other than the default.
* **resourceServerUrl** (optional): The URL of a custom Resource Server, if the user wishes to use one other than the default.
* **redirectUri**: The URL to which the browser should be redirected after obtaining the signed document. The signed document will be sent to this URL.

If the request is successful, the browser will be redirected to the OAuth 2.0 Authentication Page.

### Signature Callback Endpoint

* Method: GET
* URL: http://localhost:8086/signatures/callback

This endpoint serves as the redirect endpoint, where the browser is redirected after the OAuth 2.0 Authorization process.

This endpoint must be called with the following query parameters, as defined in the OAuth 2.0 specification:
* **code**: The authorization code returned by the OAuth 2.0 Authorization Server.
* **state**: A value used to maintain state between the request and callback.

This endpoint displays an HTML page that allows the user to return to the RP page along with the signed document.

## Deployment

### Requirements
* Java version 17
* Apache Maven 3.6.3

### Signature Creation Application

1. **Create the application-oauth2.yml file**

    After creating the file **application-oauth2.yml** in the **src/main/resources** folder, add and complete the following data:

    ```
    oauth-client:
        client-id: "{client id}"
        client-secret: "{client secret}"
        redirect-uri: "http://localhost:8086/signatures/callback" # the endpoint of the SCA where to redirect after /oauth2/authorize
        scope: "credential" 
        client-authentication-methods: "client_secret_basic"
        authorization-grant-types: "authorization_code"
        authorization-server-url: "{authorization server}"
        resource-server-url: "{resource server}"
    ```

    The data added to the previous parameter should be retrieved from one QTSP with support for OAuth2, and that makes available the endpoints:
    * credentials/info
    * signatures/signHash
    * oauth2/authorize
    * oauth2/token
    As defined in the CSC API Specification v2.0.2.

2. **Add the Timestamp Authority Information**

    For certain conformance levels, access to a Timestamp Authority is required.
   The Timestamp Authority to be used can be specified in the **application.yml** file located in the folder **src/main/resources/application.yml**.
       
    ```
    timestamp-authority:
        filename: # the path to the certificate of the Timestamp Authority chosen
        server-url: # the url of the Timestamp Authority
        supported-digest-algorithm: # the list of the digest algorithms that are supported by the TSA.
        - Example: "2.16.840.1.101.3.4.2.1"
   ```

3. **Run the Resource Server**
   
    After configuring the previously mentioned settings, navigate to the **tools** directory and run the script:
   ```
   ./deploy_sca.sh
   ```

## How to contribute

We welcome contributions to this project. To ensure that the process is smooth for everyone
involved, follow the guidelines found in [CONTRIBUTING.md](CONTRIBUTING.md).

## License

### Third-party component licenses

See [licenses.md](licenses.md) for details.

### License details

Copyright (c) 2024 European Commission

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
