%%%
title = "OpenID Connect Verifiable Credentials - Core"
abbrev = "OIDC VC Core"
ipr = "none"
workgroup = "OpenID Connect"
keyword = ["security", "openid", "verifiable credential"]

[seriesInfo]
name = "Internet-Draft"
value = "openid-vc-core-latest"
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

A verifiable Credential is a tamper-evident Credential that has authorship that can be cryptographically verified. Verifiable Credentials can be used to build verifiable presentations, which can also be cryptographically verified (see [@W3C.vc-data-model]).
Note that this specification uses a term "credential" as defined in Section 2 of [@W3C.vc-data-model], which is a different definition than in [@!OpenID.Core].

Credential

A set of one or more claims made by a Credential Issuer (see [@W3C.vc-data-model]). Note that this definition differs from that in [@OpenID.Core].

Presentation

Data derived from one or more verifiable Credentials, issued by one or more Credential Issuers, that is shared with a specific verifier (see [@W3C.vc-data-model]).

Verifiable Presentation (VP)

A verifiable presentation is a tamper-evident presentation encoded in such a way that authorship of the data can be trusted after a process of cryptographic verification. Certain types of verifiable presentations might contain data that is synthesized from, but do not contain, the original verifiable Credentials (for example, zero-knowledge proofs) (see [@W3C.vc-data-model]).

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

The OpenID Connect Verifiable Credential Format (OIDC VC) is a profile of the
JSON/JWT syntax for verifiable credentials.  The following restrictions apply:

* An OIDC VC MUST be represented as a JWT-formatted VC, as specified in Section
  6.3.1 of [@W3C.vc-data-model].  The `alg`, `kid`, and `typ` fields in the JWT
  header and the `exp`, `iss`, `nbf`, `jti`, and `sub` claims MUST be populated
  as specified in that section.  The corresponding subfields of the `vc` claim
  SHOULD be omitted.

* The `kid` field in the JWT header MUST be set.

* The `sub` claim MUST be a JWK Thumbprint URL [@RFC9278], reflecting the public
  key that the credential subject presented in their credential request (see
  [](#verifiable-credential-issuance)).

* The `iss` claim MUST be set to the Issuer Identifier for the OpenID Provider.

* The `aud` claime MUST be omitted.

* In the `vc` claim, the `@context` field MUST be a JSON array with the
  following two entries, in order:
  * `"https://www.w3.org/2018/credentials/v1"`
  * `"https://openid.org/connect/vc/v1"`

* In the `vc` claim, the `type` field MUST be a JSON array with the following
  two entries, in order:
  * `"VerifiableCredential"`
  * `"OpenIDCredential"`

* In the `vc` claim, the `credentialSubject` field MUST be a JSON object,
  populated with the same set of claims that a response from the OIDC
  UserInfo endpoint would provide.  In particular, the `sub` claim MUST be
  provided.

* In the `vc` claim, the `credentialStatus` field MAY be populated as
  specified in [@StatusList2021].

An OIDC VC is thus a JWT that can be verified in largely the same way as the
other JWTs produced by OpenID Connect (e.g., ID tokens and signed UserInfo
responses), but using the VC syntax to present a public key for the credential
subject in addition to the claims provided by the OP.

Note that there are two `sub` claims present in this object, one as a top-level
JWT claim, and one as a field within the `credentialSubject` object.  The `sub`
claim within the `credentialSubject` has the same semantic as the same claim in
an ID token or UserInfo response.  The top-level `iss` claim and the
`vc.credentialSubject.sub` field form a stable identifier for the end user, just
as in an ID token.  The top-level `sub` claim identifies the specific subject of
this credential, namely the holder of corresponding private key.  The verifiable
credential is an assertion by the OP that these two entities are the same, based
on the proof provided in the authorization request and the credential request.

The following OIDC VC would represent the same user as the UserInfo response
example in [@OpenID.Core]:

```
JWT header = {
  "alg": "ES256",
  "kid": "50615383-48AA-454D-B1E8-8721FBB7D7D1",
  "typ": "JWT"
}

JWT payload = {
  "iss": "https://server.example.com/",
  "nbf": 1262304000,
  "exp": 1262908800,
  "jti": "http://server.example.com/credentials/3732",
  "sub": "urn:ietf:params:oauth:jwk-thumbprint:sha-256:NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
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
      "sub": "248289761001",
      "name": "Jane Doe",
      "given_name": "Jane",
      "family_name": "Doe",
      "preferred_username": "j.doe",
      "email": "janedoe@example.com",
      "picture": "http://example.com/janedoe/me.jpg"
    },
    "credentialStatus": {
      "id": "https://server.example.com/credentials/status/3#94567"
      "type": "StatusList2021Entry",
      "statusPurpose": "revocation",
      "statusListIndex": "94567",
      "statusListCredential": "https://server.example.com/credentials/status/3"
    }
  },
}
```


# Verifiable Credential Validation

A Verifier processing an OIDC VC MUST validate it in the following manner:

1. The `alg` value MUST represent a digital signature algorithm supported by the
   Verifier.  The `alg` value MUST NOT represent a MAC based algorithm such as
   HS256, HS384, or HS512.

1. If the Verifier has not been provisioned with a public key with which to
   verify the VC, the Verifier MAY use the `iss` claim to locate the keys using
   OpenID Connect Discovery [@OpenID.Discovery].  To do this, the Verifier:

    * Sends a Discovery request for the specified Issuer Identifier
    * Fetches the JWK Set referenced by the `jwks_uri` field in the provider metadata
    * Identifies the key in the JWK Set corresponding to the `kid` field in the VC

1. The current time MUST be after the time represented in the `nbf` claim (if
   present) and before the time represented by the `exp` claim.

1. If the `vc` claim has a `credentialStatus` field, the Verifier SHOULD verify
   the revocation status as described in [](#verifiable-credential-revocation).
   If the credential is suspended or revoked, then it MUST be rejected.


# Verifiable Credential Revocation

As described in [](#openid-connect-verifiable-credential-format), an OIDC VC may
contain revocation information using the "StatusList2021" mechanism, which
provides a concise list of credentials revoked by an OP in a "status list
credential".  Status list credentials for OIDC VCs MUST meet the following
requirements, in addition to the requirements of [@StatusList2021]:

* An status list credential MUST be represented as a JWT-formatted VC, as
  specified in Section 6.3.1 of [@W3C.vc-data-model].  The `alg`, `kid`, and
  `typ` fields in the JWT header and the `exp`, `iss`, `nbf`, `jti`, and `sub`
  claims MUST be populated as specified in that section.  The corresponding
  subfields of the `vc` claim SHOULD be omitted.

* The `iss` claim MUST be equal to the `iss` claim of the credential being
  validated.

* The `jti` claim, if present, MUST be equal to the `statusListCredential` field
  of the credential being validated.

* The `vc` claim MUST NOT contain a `credentialStatus` field.

```
JWT header = {
  "alg": "ES256",
  "kid": "50615383-48AA-454D-B1E8-8721FBB7D7D1",
  "typ": "JWT"
}

JWT payload = {
  "iss": "https://server.example.com/",
  "iat": 1617632860,
  "exp": 1618237660,
  "jti": "https://server.example.com/credentials/status/3",
  "sub": "https://server.example.com/status/3#list"

  "vc": {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://w3id.org/vc/status-list/2021/v1"
    ],
    "type": [
      "VerifiableCredential",
      "StatusList2021Credential"
    ],
    "credentialSubject": {
      "type": "StatusList2021",
      "statusPurpose": "revocation",
      "encodedList": "H4sIAAAAAAAAA-3BMQEAAADCoPVPbQwfoAAAAAAAAAAAAAAAAAAAAIC3AYbSVKsAQAAA"
    },
  },
}
```

A Verifier processing the VC checks the revocation status of the credential
using the following steps:

1. Fetch the status list credential from URL in the `statusListCredential` field
   of the `credentialStatus` object.

1. Verify that the credential meets the criteria above.

1. Verify the signature and expiration status of the status list credential.

1. Perform the "Validate Algorithm" defined in [@StatusList2021].

If the final step returns `true`, then the Verifier MUST regard the certificate
as suspended or revoked (depending on the `statusPurpose`).  In either case, the
Verifier MUST reject the credential.  If any step fails, then the Verifier
SHOULD reject the credential.


# Verifiable Credential Issuance

The OP MUST support the OpenID for Verifiable Credential Issuance [@OpenID4VCI].
Overall, the OIDC VC issuance process unfolds in the following steps:

* The client sends an authorization request requesting the `openid_credential`
  scope and receives a successful authorization response.

* The client sends a normal OpenID Connect token request.

* The client sends a "priming" request to the OP's credential endpoint.  The
  response to this request provides a nonce that the client will include in its
  proof of possession in the subsequent request.

* The client computes a JWT proof of possession of a private key and sends this
  in a request to the credential endpoint.  The response to this request
  provides the client with OIDC VC covering its identity attributes and the
  client's public key.

To support this flow, the OP MUST meet the following requirements, which reflect
the OP's support for OIDC VCs and ensure interoperability:

* The OP's discovery metadata MUST include a `credential_endpoint` field.

* The OP's discovery metadata MUST include a `credentials_supported` field.
  This field MUST be a JSON object containing a `OpenIDCredential` key.  The
  value corresponding to this key MUST be a JSON object containing a `jwt_vc`
  key.  The value corresponding to the `jwt_vc` SHOULD be an empty JSON object.

```
{
  // ... other metadata fields
  "credential_endpoint": "https://server.example.com/credential",
  "credentials_supported": {
    "OpenIDCredential": {
      "jwt_vc": {}
    }
  }
}
```

* The OP's discovery metadata MUST include a
  `credential_request_alg_values_supported` field.

[[ TODO: File an issue on OpenID4VCI to add this metadata field ]]

* The OP MUST support a `scope` value `openid_credential`.  This scope requests
  authorization to issue OIDC VCs using the OP's credential endpoint.  In
  particular, if the `openid_credential` scope is granted for a particular
  access token, then the credential endpoint MUST allow requests authenticated
  with that access token if they have `type` set to OpenIDCredential.

* The OP's credential endpoint MUST support "priming" requests containing only a
  `type` parameter set to `"OpenIDCredential"`. The response to such a request
  MUST be a JSON object providing `c_nonce` and `c_nonce_expires_in` fields.

* The OP's credential endpoint MUST support requests using the following parameters:
  * `type`: `"OpenIDCredential"`
  * `format`: `"jwt_vc"`
  * `proof.proof_type`: `jwt`
  * `proof.jwt`: A proof JWT as described in [@OpenID4VCI].  This JWT MUST
    include a `jwk` header parameter.

* A successful credential response to a credential request with `type` set to
  `OpenIDCredential` and `format` set to `jwt_vc` MUST be synchronous, not
  deferred.  The response MUST contain the following values:
  * `format`: `"jwt_vc"`
  * `credential`: An OIDC VC as described in
    [](#openid-connect-verifiable-credential-format).  The `sub` value of this
    VC MUST be the JWK Thumbprint URI for the public key in the `jwk` header
    parameter of the proof JWT in the request.


[[ TODO: Example flow, possibly in an appendix ]]
* Discovery request / response
* Authz request / response
* Token request / response
* Credential priming request / response
* Credential request / response


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

<reference anchor="StatusList2021" target="https://www.w3.org/TR/vc-data-model">
  <front>
    <title>Status List 2021</title>
    <author fullname="Manu Sporny">
      <organization>Digital Bazaar</organization>
    </author>
    <author fullname="Dave Longley">
      <organization>Digital Bazaar</organization>
    </author>
    <author fullname="Orie Steele">
      <organization>Transmute</organization>
    </author>
    <author fullname="Mike Prorock">
      <organization>mesur.io</organization>
    </author>
    <author fullname="Mahmoud Alkhraishi">
      <organization>Mavennet</organization>
    </author>
   <date day="16" month="Jun" year="2022"/>
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

<reference anchor="OpenID.Discovery" target="https://openid.net/specs/openid-connect-discovery-1_0.html">
  <front>
    <title>OpenID Connect Discovery 1.0 incorporating errata set 1</title>
    <author initials="N." surname="Sakimura" fullname="Nat Sakimura">
      <organization>NRI</organization>
    </author>
    <author initials="J." surname="Bradley" fullname="John Bradley">
      <organization>Ping Identity</organization>
    </author>
    <author initials="M." surname="Jones" fullname="Michael B. Jones">
      <organization>Microsoft</organization>
    </author>
    <author initials="E." surname="Jay" fullname="Edmund Jay">
      <organization>Illumila</organization>
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
