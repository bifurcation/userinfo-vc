%%%
title = "OpenID Connect Verifiable Credentials - Core"
abbrev = "OIDC VC Core"
ipr = "none"
workgroup = "OpenID Connect"
keyword = ["security", "openid", "ssi", "verifiable credential"]

[seriesInfo]
name = "Internet-Draft"
value = "openid-vc-profile-e2eid-1_0-00"
status = "standard"

[[author]]
initials="M."
surname="Ansari"
fullname="Morteza Ansari"
organization="Individual"
    [author.address]
    email = "mansari@robotsource.com"

[[author]]
initials="R."
surname="Barnes"
fullname="Richard Barnes"
organization="Cisco Systems"
    [author.address]
    email = "rlb@ipv.sx"

[[author]]
initials="K."
surname="Yasuda"
fullname="Kristina Yasuda"
organization="Microsoft"
    [author.address]
    email = "kristina.yasuda@microsoft.com"

%%%

.# Abstract

OpenID Connect Verifiable Credentials is an extension of OpenID Connect 1.0 to
add support for an OpenID Provider issuing Verifiable Credentials.  This
document defines a Verifiable Credential format that carries OpenID Conenct
claims, and profiles the general OpenID for Verifiable Credential Issuance
specficiation to provide a similar level of interoperability to OpenID Connect.
We also define a standard mechanism for an OpenID Provider to express credential
revocation information.

{mainmatter}

# Introduction

[[ RLB ]]
* Verifiable Credentials open up a new frontier in identity, enabling new use
  cases and more decentralization / privacy for existing use cases.
* VCs have struggled to achieve large-scale adoption because the VC framework is
  very high-level, not defined well enough to be interoperable.
* This document extends OIDC to support VCs, in a specific format that can be
  widely interoperable, as a baseline from which more advanced cases might
  follow.


Many applications today provide end-to-end encryption, which protects against inspection or tampering by the communications service provider.  Current applications, however, have only very manual techniques for verifying the identity of other users in a communication, for example, verifying key fingerprints in person.  E2E encryption without identity verification is like HTTPS with self-signed certificates – vulnerable to impersonation attacks.  There is a need for something to do what ACME and the Web PKI do for HTTPS, enabling users to prove their identities to one another with a high degree of automation.

E2E encryption protocols provide a starting point.  Users in these protocols are represented by cryptographic public keys.  One of the functions of the protocol is to prove that each user possesses the private key corresponding to their public key.  These protocols can also usually send “credentials” that bind identity information to a user’s public key.


# Terminology

[[ RLB ]]
* TODO Map OpenID Connect roles to VC roles, maybe with a picture?

Verifiable Credential (VC)

A verifiable Credential is a tamper-evident Credential that has authorship that can be cryptographically verified. Verifiable Credentials can be used to build verifiable presentations, which can also be cryptographically verified (see [@VC_DATA]).
Note that this specification uses a term "credential" as defined in Section 2 of [@VC_DATA], which is a different definition than in [@!OpenID.Core].

Credential

A set of one or more claims made by a Credential Issuer (see [@VC_DATA]). Note that this definition differs from that in [@OpenID.Core].

Presentation

Data derived from one or more verifiable Credentials, issued by one or more Credential Issuers, that is shared with a specific verifier (see [@VC_DATA]).

Verifiable Presentation (VP)

A verifiable presentation is a tamper-evident presentation encoded in such a way that authorship of the data can be trusted after a process of cryptographic verification. Certain types of verifiable presentations might contain data that is synthesized from, but do not contain, the original verifiable Credentials (for example, zero-knowledge proofs) (see [@VC_DATA]).

Wallet

Entity that receives, stores, presents, and manages Credentials and key material of the End-User. There is no single deployment model of a Wallet: Credentials and keys can both be stored/managed locally by the end-user, or by using a remote self-hosted service, or a remote third party service. In the context of this specification, the Wallet acts as an OAuth 2.0 Authorization Server (see [@!RFC6749]) towards the Credential Verifier which acts as the OAuth 2.0 Client.

Verifier

Entity that verifies the Credential to make a decision regarding providing a service to the End-User. Also called Relying Party (RP) or Client. During presentation of Credentials, Verifier acts as an OAuth 2.0 Client towards the Wallet acting as an OAuth 2.0 Authorization Server.

Credential Issuer

Entity that issues verifiable Credentials. Also called Issuer. In the context of this specification, the Credential Issuer acts as OAuth 2.0 Authorization Server (see [@!RFC6749]).

Base64url Encoding

Base64 encoding using the URL- and filename-safe character set defined in Section 5 of [@!RFC4648], with all trailing '=' characters omitted (as permitted by Section 3.2 of [@!RFC4648]) and without the inclusion of any line breaks, whitespace, or other additional characters. Note that the base64url encoding of the empty octet sequence is the empty string. (See Appendix C of [@!RFC7515] for notes on implementing base64url encoding without padding.)

# Use Cases

[[ RLB ]]
* Securing Identity in E2E-secure Applications
  * Holder = Verifier = E2E-secure app
  * Public key connects to E2E encryption layer
* VC-based Login
  * Holder = wallet (or something)
  * Verifier = app that wants to log user in

## Application obtaining credentials containing public key and identity

An application currently utilizing OpenID Connect for accessing various federated identity providers can use the same infrastructure to obtain credentials binding its public key to the identity of the user.

## Application validating authenticity of credentials recieved

An application recieving a credential can use OpenID Connect to verify validity of the public key and identity it is bound to.

# Overview

This specification defines a profile of OpenID for Verifiable Credential Issuance [@!OpenID4VCI] to ensure base level interoperability between applications needing to exchange public key bound to their identity with other clients and be able to verify authenticity of such credentials. This profile additionally defines a verifiable credential type that encodes the identity attributes provided by an OpenID Provider in OpenID Connect today.

## Issuance
The application initiates the process by performing standard OpenID Connect authorization and token requests to the OpenID Provider. The authorization request is done using appropriate scope allowing the application to issue a Verifiable Credential.

xxx Do we need example here? This part is already covered in core spec and then in OpenID4VCI, though example might be nice to show example of scope and also nounce in token response

The verifiable credential issuance is done using a request to the OpenID Provider’s credential endpoint as defined in Credential Endpoint section of [@!OpenID4VCI]. This request is authenticated with the application's key pair. The first request simply fetches a nonce to be used in the second request. The second request provides proof that the client possesses the private key of the key pair that will represent the credential subject. The OpenID Provider verifies that the private key that signed the JWT corresponds to one of the public keys referenced by the DID. The response provides the desired credential.

Below is a non-normative example of a `proof` parameter (line breaks for display purposes only):

```json
{
  "proof_type": "jwt",
  "jwt": "eyJraWQiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmNzEyZWJjNmYxYzI3NmUxMmVjMjEva2V5cy8
  xIiwiYWxnIjoiRVMyNTYiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJzNkJoZFJrcXQzIiwiYXVkIjoiaHR
  0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20iLCJpYXQiOiIyMDE4LTA5LTE0VDIxOjE5OjEwWiIsIm5vbm
  NlIjoidFppZ25zbkZicCJ9.ewdkIkPV50iOeBUqMXCC_aZKPxgihac0aW9EkL1nOzM"
  }
```

where the JWT looks like this:

```json
{
  "alg": "ES256",
  "kid":"did:example:ebfeb1f712ebc6f1c276e12ec21/keys/1"
}.
{
  "iss": "s6BhdRkqt3",
  "aud": "https://server.example.com",
  "iat": 1659145924,
  "nonce": "tZignsnFbp"
}
```

Below is a non-normative example of a Credential Request:

```
POST /credential HTTP/1.1
Host: server.example.com
Content-Type: application/json
Authorization: BEARER czZCaGRSa3F0MzpnWDFmQmF0M2JW

{
  "type": "https://did.example.org/KeyBinding"
  "format": "ldp_vc",
  "proof": {
    "proof_type": "jwt",
    "jwt": "eyJraWQiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmNzEyZWJjNmYxYzI3NmUxMmVjMjEva2V5cy8
    xIiwiYWxnIjoiRVMyNTYiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJzNkJoZFJrcXQzIiwiYXVkIjoiaHR
    0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20iLCJpYXQiOiIyMDE4LTA5LTE0VDIxOjE5OjEwWiIsIm5vbm
    NlIjoidFppZ25zbkZicCJ9.ewdkIkPV50iOeBUqMXCC_aZKPxgihac0aW9EkL1nOzM"
  }
}
```

xxx What format should the request be done in our case? jwt_vc might be a better option than ldp_vc?

Below is a non-normative example of a Credential Response in a synchronous flow:

```
HTTP/1.1 200 OK
  Content-Type: application/json
  Cache-Control: no-store

{
  "format": "ldp_vc"
  "credential" : "LUpixVCWJk0eOt4CXQe1NXK....WZwmhmn9OQp6YxX0a2L",
  "c_nonce": "fGFF7UkhLa",
  "c_nonce_expires_in": 86400  
}
```

# Design Principles

* Maximize ease of interop => No unnecessary flexibility
* Don't foreclose more flexibility in the future
* Maximize code reuse for OIDC clients and servers

# OpenID Connect Verifiable Credential Format

* credentialSubject.id = did:jwk or thumbprint URI -- latter consistent with "cnf.jkt"
* remainder of credentialSubject = same claims as UserInfo endpoint
* MUST be JWT, "instead of"; special "typ" value?
* Issuer keys looked up with ... OIDC Discovery?
* SHOULD have revocation info

* "alg" - supported algorithms advertised, configured for client
* "kid" MUST be present
* "sub" MUST be present = jkt URI   <------- POSSIBLE POINT OF CONFLICT!
* "iss" MUST
* "aud" MAY
* "jti" <- according to VCDM
* "nbf" <- according to VCDM
* "exp" <- according to VCDM
* vc["@context"] = [fixed]
* vc.type = [fixed]
* vc.credentialSubject = UserInfo
* vc.credentialStatus = StatusList2021 [OPTIONAL]


```
JWT header = {
  "alg": "ES256",
  "typ": "JWT"
}

JWT payload = {
  "vc": {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://openid.org/connect/vc/v1"
    ],
    "type": [
      "VerifiableCredential",
      "OpenIDCredential"
    ],
    "credentialSubject": {
      "id": "did:jwk:...",
      "given_name": "John",
      "family_name": "Public",
      "email": "jpublic@example.org",
      "email_verified": true,
      "phone_number": "+1 202 555 1212",
    },
    "credentialStatus": {
      "type": "StatusList2021",
      "id": "http://
    }
  },
  "iss": "https://server.example.com/",
  "nbf": 1262304000,
  "jti": "http://server.example.com/credentials/3732",
  "sub": "did:jwk:..."
}
```

# Verifiable Credential Issuance

* Scope value to authorize credential issuance
* MUST support VCI endpoint
* [[ required parameters ]]

```
[ example request ]
```


# Verifiable Credential Revocation

* Revocation endpoint advertised in VCs MUST be ...

```
[ vc integration in jwt above; status request here ]
```


# Asynchronous Issuer JWK Set Distribution

* JWKS URL SHOULD support Accept
* If you get Accept: application/jws+json, return a JWS:
  * alg = ?
  * x5c = WebPKI certificate chain that verifies issuer URL


# Verifiable Credential Validation

* [[ Is there a VC algorithm to profile? ]]
* Fetch JWKS from issuer, e.g., using discovery or bundle
* Verify signature 
* Check revocation

# Security Considerations {#security-considerations}

TBD

# Implementation Considerations

TBD

# Privacy Considerations

TBD

{backmatter}

<reference anchor="VC_DATA" target="https://www.w3.org/TR/vc-data-model">
  <front>
    <title>Verifiable Credentials Data Model 1.0</title>
    <author fullname="Manu Sporny">
      <organization>Digital Bazaar</organization>
    </author>
    <author fullname="Grant Noble">
      <organization>ConsenSys</organization>
    </author>
    <author fullname="Dave Longley">
      <organization>Digital Bazaar</organization>
    </author>
    <author fullname="Daniel C. Burnett">
      <organization>ConsenSys</organization>
    </author>
    <author fullname="Brent Zundel">
      <organization>Evernym</organization>
    </author>
    <author fullname="David Chadwick">
      <organization>University of Kent</organization>
    </author>
   <date day="19" month="Nov" year="2019"/>
  </front>
</reference>

<reference anchor="SIOPv2" target="https://openid.net/specs/openid-connect-self-issued-v2-1_0.html">
  <front>
    <title>Self-Issued OpenID Provider V2</title>
    <author ullname="Kristina Yasuda">
      <organization>Microsoft</organization>
    </author>
    <author fullname="Michael B. Jones">
      <organization>Microsoft</organization>
    </author>
   <date day="18" month="December" year="2021"/>
  </front>
</reference>

<reference anchor="OpenID.Core" target="http://openid.net/specs/openid-connect-core-1_0.html">
  <front>
    <title>OpenID Connect Core 1.0 incorporating errata set 1</title>
    <author initials="N." surname="Sakimura" fullname="Nat Sakimura">
      <organization>NRI</organization>
    </author>
    <author initials="J." surname="Bradley" fullname="John Bradley">
      <organization>Ping Identity</organization>
    </author>
    <author initials="M." surname="Jones" fullname="Michael B. Jones">
      <organization>Microsoft</organization>
    </author>
    <author initials="B." surname="de Medeiros" fullname="Breno de Medeiros">
      <organization>Google</organization>
    </author>
    <author initials="C." surname="Mortimore" fullname="Chuck Mortimore">
      <organization>Salesforce</organization>
    </author>
   <date day="8" month="Nov" year="2014"/>
  </front>
</reference>

<reference anchor="OpenID4VP" target="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">
      <front>
        <title>OpenID for Verifiable Presentations</title>
        <author initials="O." surname="Terbu" fullname="Oliver Terbu">
         <organization>ConsenSys Mesh</organization>
        </author>
        <author initials="T." surname="Lodderstedt" fullname="Torsten Lodderstedt">
          <organization>yes.com</organization>
        </author>
        <author initials="K." surname="Yasuda" fullname="Kristina Yasuda">
          <organization>Microsoft</organization>
        </author>
        <author initials="A." surname="Lemmon" fullname="Adam Lemmon">
          <organization>Convergence.tech</organization>
        </author>
        <author initials="T." surname="Looker" fullname="Tobias Looker">
          <organization>Mattr</organization>
        </author>
       <date day="20" month="June" year="2022"/>
      </front>
</reference>

<reference anchor="OpenID4VCI" target="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html">
      <front>
        <title>OpenID for Verifiable Credential Issuance</title>
        <author initials="T." surname="Lodderstedt" fullname="Torsten Lodderstedt">
          <organization>yes.com</organization>
        </author>
        <author initials="K." surname="Yasuda" fullname="Kristina Yasuda">
          <organization>Microsoft</organization>
        </author>
        <author initials="T." surname="Looker" fullname="Tobias Looker">
          <organization>Mattr</organization>
        </author>
       <date day="6" month="September" year="2022"/>
      </front>
</reference>

# IANA Considerations

TBD

# Acknowledgements {#Acknowledgements}

TBD

# Notices

Copyright (c) 2022 The OpenID Foundation.

The OpenID Foundation (OIDF) grants to any Contributor, developer, implementer, or other interested party a non-exclusive, royalty free, worldwide copyright license to reproduce, prepare derivative works from, distribute, perform and display, this Implementers Draft or Final Specification solely for the purposes of (i) developing specifications, and (ii) implementing Implementers Drafts and Final Specifications based on such documents, provided that attribution be made to the OIDF as the source of the material, but that such attribution does not indicate an endorsement by the OIDF.

The technology described in this specification was made available from contributions from various sources, including members of the OpenID Foundation and others. Although the OpenID Foundation has taken steps to help ensure that the technology is available for distribution, it takes no position regarding the validity or scope of any intellectual property or other rights that might be claimed to pertain to the implementation or use of the technology described in this specification or the extent to which any license under such rights might or might not be available; neither does it represent that it has made any independent effort to identify any such rights. The OpenID Foundation and the contributors to this specification make no (and hereby expressly disclaim any) warranties (express, implied, or otherwise), including implied warranties of merchantability, non-infringement, fitness for a particular purpose, or title, related to this specification, and the entire risk as to implementing this specification is assumed by the implementer. The OpenID Intellectual Property Rights policy requires contributors to offer a patent promise not to assert certain patent claims against other contributors and against implementers. The OpenID Foundation invites any interested party to bring to its attention any copyrights, patents, patent applications, or other proprietary rights that may cover technology that may be required to practice this specification.

# Appendix

# Document History

   [[ To be removed from the final specification ]]

   -00 

   *  initial revision
