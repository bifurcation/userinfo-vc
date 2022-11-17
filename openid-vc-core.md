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
initials="P."
surname="Kasselman"
fullname="Pieter Kasselman"
organization="Microsoft"
    [author.address]
    email = "pieter.kasselman@microsoft.com"

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
document defines a Verifiable Credential format that carries OpenID Connect
claims, and profiles the general OpenID for Verifiable Credential Issuance
specification to provide a similar level of interoperability to OpenID Connect.
We also define a standard mechanism for an OpenID Provider to express credential
revocation information.

{mainmatter}

# Introduction

Verifiable Credentials (VCs) promise to open up a new frontier in identity, enabling
new use cases as well as more decentralization and privacy for existing use
cases [@!W3C.vc-data-model].  OpenID Providers have a role to play in this
ecosystem: An OP is trusted by reling parties to verify and attest to users'
identities, and is thus in a natural position to act as an issuer of Verifiable
Credentials.

This document extends OpenID Connect with an interface by which a Client may
request a Verifiable Credential attesting to the user's identity attributes.
This interface is similar to the existing UserInfo interface; the main
difference is that a Verifiable Credential associates a user's identity
attributes with a cryptographic key pair, so that the credential can be
presented to third-party Verifiers.

The overall life-cycle of a Verifiable Credential involves three actors: A
Holder that is the subject of the VC, an Issuer that creates the VC, and a
Verifier that uses the VC to verify the Holder's identity attributes.  A
credential is created by means of an "issuance" interaction between the Holder
and the Issuer, and presented to a Verifier by means of a "presentation"
interaction between the Holder and the Verifier.  The only connection between
the Verifier and the Issuer is that the Verifier trusts the Issuer to issue VCs
containing correct information -- unlike the OP/RP relationship in OpenID
Connect, the OP acting as a VC Issuer need not know anything about the Verifier.

``` aasvg
+--------+               +--------+                   +----------+
| Issuer |--(issuance)-->| Holder |--(presentation)-->| Verifier |
+--------+               +--------+                   +----------+
    ^                                                      .
    .                                                      .
    .......................(trust)..........................
```

The interface defined here allows an OpenID Provider to act as an Issuer in the
Verifiable Credential model, with the OpenID Connect Relying Party acting as a
Holder.  This enables the Relying Party to prove its user's identity to other
Verifiers.

To create an interoperable interface, we define a specific Verifiable Credential
format that is tailored for carrying OpenID Connect identity claims.  We also
profile the general OpenID Connect for Verifiable Credential Issuance
specification [@!OpenID4VCI] to ensure support for a core set of features.

# Terminology

Verifiable Credential (VC):
: A verifiable Credential is a tamper-evident Credential that has authorship that
can be cryptographically verified. Verifiable Credentials can be used to build
verifiable presentations, which can also be cryptographically verified (see
[@!W3C.vc-data-model]).  Note that this specification uses a term "credential" as
defined in Section 2 of [@!W3C.vc-data-model], which is a different definition
than in [@!OpenID.Core].

Credential:
: A set of one or more claims made by a Credential Issuer (see
[@!W3C.vc-data-model]). Note that this definition differs from that in
[@!OpenID.Core].

Presentation:
: Data derived from one or more verifiable Credentials, issued by one or more
Credential Issuers, that is shared with a specific verifier (see
[@!W3C.vc-data-model]).

Verifiable Presentation (VP):
: A verifiable presentation is a tamper-evident presentation encoded in such a way
that authorship of the data can be trusted after a process of cryptographic
verification. Certain types of verifiable presentations might contain data that
is synthesized from, but do not contain, the original verifiable Credentials
(for example, zero-knowledge proofs) (see [@!W3C.vc-data-model]).

Wallet:
: Entity that receives, stores, presents, and manages Credentials and key material
of the End-User. There is no single deployment model of a Wallet: Credentials
and keys can both be stored/managed locally by the end-user, or by using a
remote self-hosted service, or a remote third party service. In the context of
this specification, the Wallet acts as an OAuth 2.0 Authorization Server (see
[@!RFC6749]) towards the Credential Verifier which acts as the OAuth 2.0 Client.

Verifier:
: Entity that verifies the Credential to make a decision regarding providing a
service to the End-User. Also called Relying Party (RP) or Client. During
presentation of Credentials, Verifier acts as an OAuth 2.0 Client towards the
Wallet acting as an OAuth 2.0 Authorization Server.

Credential Issuer:
: Entity that issues verifiable Credentials. Also called Issuer. In the context of
this specification, the Credential Issuer acts as OAuth 2.0 Authorization Server
(see [@!RFC6749]).

Base64url Encoding:
: Base64 encoding using the URL- and filename-safe character set defined in
Section 5 of [@!RFC4648], with all trailing '=' characters omitted (as permitted
by Section 3.2 of [@!RFC4648]) and without the inclusion of any line breaks,
whitespace, or other additional characters. Note that the base64url encoding of
the empty octet sequence is the empty string. (See Appendix C of [@!RFC7515] for
notes on implementing base64url encoding without padding.)

# Use Cases

## End-to-End Identity

Many applications today provide end-to-end encryption, which protects against
inspection or tampering by the communications service provider.  Current
applications, however, have only very manual techniques for verifying the
identity of other users in a communication, for example, verifying key
fingerprints in person.  E2E encryption without identity verification is like
HTTPS with self-signed certificates – vulnerable to impersonation attacks.

When appropriately integrated in an E2E encryption system, OpenID Verifiable
Credentials could eliminte the risk of impersonation attacks.  A participant in
an E2E-secure session would be able to present identity information that the
other participants could verified as coming from a trusted OP, and thus
protected from tampering by the application's servers.

In this regard, the OP would be the Issuer, and the Holder and Verifier roles
would be played by the user agent software in the E2E encrypted application.  A
user agent would act as Holder when proving its user's identity to others, and
as a Verifier when authenticating other participants in a session.


## Application obtaining credentials containing public key and identity

An application currently utilizing OpenID Connect for accessing various
federated identity providers can use the same infrastructure to obtain
credentials binding its public key to the identity of the user.

## Application validating authenticity of credentials recieved

An application recieving a credential can use OpenID Connect to verify validity
of the public key and identity it is bound to.

# Overview

This specification defines a profile of OpenID for Verifiable Credential
Issuance [@!OpenID4VCI] to ensure base level interoperability between
applications needing to exchange public key bound to their identity with other
clients and be able to verify authenticity of such credentials. This profile
additionally defines a verifiable credential type that encodes the identity
attributes provided by an OpenID Provider in OpenID Connect today.

The VC issuance interface defined in this document extends the basic OpenID
Connect flow:

1. The RP (Client) sends a request to the OpenID Provider (OP).
1. The OP authenticates the End-User and obtains authorization.
1. The OP responds with an ID Token and usually an Access Token.
1. The RP sends a "priming" request to the OP's credential endpoint.
1. The OP responds with a nonce to be used in a proof of possession.
1. The RP sends a JWT proving possession of a private key to the OP's credential
   endpoint.
1. The OP issues a VC containing information about the authenticated user and
   returns it to the RP.
1. The RP may then use the VC in a VC presentation protocol (outside the scope
   of this document) to demonstrate the End-User's identity to a Verifier.

These steps are illustrated in the following diagram:

```
+--------+                                           +--------+    +----------+
|        |                                           |        |    |          |
|        |---------(1) AuthN Request---------------->|        |    |          |
|        |                                           |        |    |          |
|        |  +--------+                               |        |    |          |
|        |  |        |                               |        |    |          |
|        |  |  End-  |<--(2) AuthN & AuthZ---------->|        |    |          |
|   RP   |  |  User  |                               |   OP   |    |          |
|   ==   |  |        |                               |   ==   |    | Verifier |
| Holder |  +--------+                               | Issuer |    |          |
|        |                                           |        |    |          |
|        |<--------(3) AuthN Response----------------|        |    |          |
|        |                                           |        |    |          |
|        |---------(4) Credential Request (Priming)->|        |    |          |
|        |                                           |        |    |          |
|        |<--------(5) Error Response----------------|        |    |          |
|        |                                           |        |    |          |
|        |---------(6) Credential Request----------->|        |    |          |
|        |                                           |        |    |          |
|        |<--------(7) Credential Response-----------|        |    |          |
|        |                                           |        |    |          |
|        |                                           +--------+    |          |
|        |                                                         |          |
|        |<~~~~~~~~(8) Presentation Protoco~~~~~~~~~~~~~~~~~~~~~~~>|          |
|        |                                                         |          |
+--------+                                                         +----------+
```

## Authentication and Authorization

The application initiates the process by performing standard OpenID
Connect authorization and token requests to the OpenID Provider. The
authorization request is done using the `openid_credential` scope allowing the
application to issue a Verifiable Credential.

## Issuance

The verifiable credential issuance is done using a request to the OpenID
Provider’s credential endpoint as defined in Credential Endpoint section of
[@!OpenID4VCI]. This request is authenticated with the application's key pair.
The first request simply fetches a nonce to be used in the second request. The
second request provides proof that the client possesses the private key of the
key pair that will represent the credential subject. The OpenID Provider
verifies that the private key that signed the JWT corresponds to one of the
public keys referenced by the DID. The response provides the desired credential.

```
POST /credential HTTP/1.1
Authorization: Bearer S_-WDgsXG8s3V7qrTbI3kZHf4mIcTByLPU2Rd5FoDib
Content-Type: application/json

{
  "type": "https://openid.net/vc/v1",
  "format": "jwt_vc"
}

HTTP/1.1 400 Bad Request
Content-Type: application/json; charset=utf-8

{
  "error_code": "missing_proof",
  "c_nonce": "qPDhlbqmqPt7wMCAS70dTlpE1O2np_d25MVBPYz9VwNLdL348bQ",
  "c_nonce_expires_in": 3600
}
```
Figure: A priming request and response.  Note that the `proof` field in the
request is not populated, but the response provides a `c_nonce` field.
{#fig-priming}

```
POST /credential HTTP/1.1
Authorization: Bearer S_-WDgsXG8s3V7qrTbI3kZHf4mIcTByLPU2Rd5FoDib
Content-Type: application/json

{
  "type": "https://openid.net/vc/v1",
  "format": "jwt_vc",
  "proof": {
    "proof_type": "jwt",
    "jwt": "eyJhbGciOiJFUzI1NiIsImp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2
            IiwieCI6InNzUzR0VDBFMEVrMC1jRktjS1RQeFMwMTZqTEZOdmM1a0tKLUll
            NUl5MlUiLCJ5IjoiOE1VZ242cGhCUUw2OGJTY0MtdFFXdDQ5ZlVBQTlBYnhx
            RkIyVjVYTEJaZyJ9fQ.eyJhdGgiOiJHVXF5LWpySFVRdll3QXkwQXZ4RGRtO
            TYweVYxdXJCZWExejl4UGo1UGZvIiwiaXNzIjoiYk94OFI0NFhoSUhpM0E5N
            jV6QkVuIiwiYXVkIjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20iLCJub
            25jZSI6InFQRGhsYnFtcVB0N3dNQ0FTNzBkVGxwRTFPMm5wX2QyNU1WQlBZe
            jlWd05MZEwzNDhiUSIsImlhdCI6MTY2NzU3NTksImp0aSI6IlhGbHpQWEFmS
            WxYR3ExMHFZRmVUejhZak5EbjhSUzNwRHMzZVJPVlJ4VkUifQ.abB_drdaUJ
            9F0KsixD6Q6TbTrOXYXsLTyqxaKWtvRT4-6tCP1womUlJvq8qDsAFjJ4gY3r
            Ksl6osAQ7FpX_-pg"
  }
}
```
Figure: A credential request.  Line breaks in the `proof` JWT are for
readability only. {#fig-credential-request}

```
Proof JWT header:

{
  "alg": "ES256",
  "jwk": {
    "kty": "EC",
    "crv": "P-256",
    "x": "ssS4tT0E0Ek0-cFKcKTPxS016jLFNvc5kKJ-Ie5Iy2U",
    "y": "8MUgn6phBQL68bScC-tQWt49fUAA9AbxqFB2V5XLBZg"
  }
}

Proof JWT payload:

{
  "ath": "GUqy-jrHUQvYwAy0AvxDdm960yV1urBea1z9xPj5Pfo",
  "iss": "bOx8R44XhIHi3A965zBEn",
  "aud": "https://server.example.com",
  "nonce": "qPDhlbqmqPt7wMCAS70dTlpE1O2np_d25MVBPYz9VwNLdL348bQ",
  "iat": 16675759,
  "jti": "XFlzPXAfIlXGq10qYFeTz8YjNDn8RS3pDs3eROVRxVE"
}
```
Figure: The contents of a proof-of-possession JWT in a credential request.
{#fig-proof-jwt}


```
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8

{
  "format": "jwt_vc",
  "credential": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IlhUU0dtaDczNF9K
                 NmZPV1ViSTdCTmltN3d5dmo1TFd4OEd6dUlIN1dIdzgifQ.eyJ2YyI6eyJAY
                 29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFsc
                 y92MSIsImh0dHBzOi8vb3BlbmlkLm9yZy92Yy91c2VyaW5mby92MSJdLCJ0e
                 XBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiT3BlbklEQ3JlZGVudGlhb
                 CJdLCJjcmVkZW50aWFsU3ViamVjdCI6eyJzdWIiOiIyNDgyODk3NjEwMDEiL
                 CJuYW1lIjoiSmFuZSBEb2UiLCJnaXZlbl9uYW1lIjoiSmFuZSIsImZhbWlse
                 V9uYW1lIjoiRG9lIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiai5kb2UiLCJlb
                 WFpbCI6ImphbmVkb2VAZXhhbXBsZS5jb20iLCJwaWN0dXJlIjoiaHR0cDovL
                 2V4YW1wbGUuY29tL2phbmVkb2UvbWUuanBnIn19LCJzdWIiOiJ1cm46aWV0Z
                 jpwYXJhbXM6b2F1dGg6andrLXRodW1icHJpbnQ6UUFiVk1tMzliYjNnWGtLN
                 Ud2MUhGdF9VS0E1NnNLV0cyaDk0Q0pNRDVPWSIsImF1ZCI6ImJPeDhSNDRYa
                 ElIaTNBOTY1ekJFbiIsImlhdCI6MTY2NzU3NTk4MiwiaXNzIjoiaHR0cHM6L
                 y9zZXJ2ZXIuZXhhbXBsZS5jb20ifQ.--x6mCdiNEe4dx5KN0skmD5tOvVcwn
                 1tj4-EVC7m6lyD5nop_gPgn6aa1PJYjiVV6XI-nd6__3TPTsYl8EJR3w"
}
```
Figure: A credential response.  Line breaks in the credential JWT are for
readability only. {#fig-credential-response}

## OpenID Verifiable Credentials

The credential returned by the credential endpoint is in a format optimized for
compatibility with existing OpenID Connect implementations.  The attributes
associated with the credential subject are the same claims returned by the
UserInfo endpoint.  The signing structure is the same as for an ID Token.

A Verifiable Credential needs to be bound to a public key whose private key is
held by the Holder.  This binding is provided by the `sub` claim of the JWT,
which contains a URL encoding the JWT Thumbprint of the Holder's public key.
The normal OpenID Connect `sub` attribute (a unique subject identifier within
the scope of the issuer) is provided along with other claims in the
`credentialSubject` object.

```
Credential JWT Header

{
  "alg": "ES256",
  "typ": "JWT",
  "kid": "XTSGmh734_J6fOWUbI7BNim7wyvj5LWx8GzuIH7WHw8"
}

Credential JWT payload:

{
  "vc": {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://openid.org/vc/userinfo/v1"
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
    }
  },
  "sub": "urn:ietf:params:oauth:jwk-thumbprint:QAbVMm39bb3gXkK5Gv1HFt_UKA56sKWG2h94CJMD5OY",
  "aud": "bOx8R44XhIHi3A965zBEn",
  "iat": 1667575982,
  "iss": "https://server.example.com"
}

```
Figure: The contents of an OpenID Verifiable Credential

## Verification

Verifier can verify credentials using one of the two mechanisms. If the verifier
has been provisioned with a public key, it can use the key to verify the
crednetials. Alternatively it can use OpenID Connect Discovery
[@!OpenID.Discovery] to fetch the OP's JWK Set and use the coresponding key to
verify the credentials as described in (#verifiable-credential-validation).

## Revocation

An OpenID Connect VC may contain revocation information using the
"StatusList2021" mechanism. This enables the OP to provide a concise list of
revoked credentials as described in (#verifiable-credential-revocation).

# OpenID Connect Verifiable Credential Format

The OpenID Connect Verifiable Credential Format (OIDC VC) is a profile of the
JSON/JWT syntax for verifiable credentials.  The following restrictions apply:

* An OIDC VC MUST be represented as a JWT-formatted VC, as specified in Section
  6.3.1 of [@!W3C.vc-data-model].  The `alg`, `kid`, and `typ` fields in the JWT
  header and the `exp`, `iss`, `nbf`, `jti`, and `sub` claims MUST be populated
  as specified in that section.  The corresponding subfields of the `vc` claim
  SHOULD be omitted.

* The `kid` field in the JWT header MUST be set.

* The `iss` claim MUST be set to the Issuer Identifier for the OpenID Provider.

* The `aud` claim MAY be omitted.  If present, it MUST contain the OAuth 2.0
  `client_id` of the Relying Party, just as in an OpenID Connect ID Token.  Note
  that this value represents the Holder of the VC, not the Verifier to whom it
  will be presented.

* In the `vc` claim, the `@context` field MUST be a JSON array with the
  following single entry:
  * `"https://www.w3.org/2018/credentials/v1"`

* In the `vc` claim, the `type` field MUST be a JSON array with the following
  two entries, in order:
  * `"VerifiableCredential"`
  * `"OpenIDCredential"`

* In the `vc` claim, the `credentialSubject` field MUST be a JSON object.
  * The `id` field of this object a MUST be a JWK Thumbprint URL [@!RFC9278],
    reflecting the public key that the credential subject presented in their
    credential request (see (#verifiable-credential-issuance)).
  * The other fields in this object MUST be the exact set of claims that would
    be returned an a successful UserInfo request authenticated with the access token
    that was used in the Credential Request.

  populated with the same set of claims that a response from the OIDC
  UserInfo endpoint would provide.  In particular, the `sub` claim MUST be
  provided.

* In the `vc` claim, the `credentialStatus` field MAY be populated as
  specified in [@!StatusList2021].

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
example in [@!OpenID.Core]:

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



# Verifiable Credential Issuance

The OP MUST support the OpenID for Verifiable Credential Issuance [@!OpenID4VCI].
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
  * `proof.jwt`: A proof JWT as described in [@!OpenID4VCI].  This JWT MUST
    include a `jwk` header parameter.

* A successful credential response to a credential request with `type` set to
  `OpenIDCredential` and `format` set to `jwt_vc` MUST be synchronous, not
  deferred.  The response MUST contain the following values:
  * `format`: `"jwt_vc"`
  * `credential`: An OIDC VC as described in
    (#openid-connect-verifiable-credential-format).  The `sub` value of this
    VC MUST be the JWK Thumbprint URI for the public key in the `jwk` header
    parameter of the proof JWT in the request.

A non-normative example of a credential issuance is shown in (#fig-priming), (#fig-credential-request),  (#fig-proof-jwt), and (#fig-credential-response).

# Verifiable Credential Validation

A Verifier processing an OIDC VC MUST validate it in the following manner:

1. The `alg` value MUST represent a digital signature algorithm supported by the
   Verifier.  The `alg` value MUST NOT represent a MAC based algorithm such as
   HS256, HS384, or HS512.

1. If the Verifier has not been provisioned with a public key with which to
   verify the VC, the Verifier MAY use the `iss` claim to locate the keys using
   OpenID Connect Discovery [@!OpenID.Discovery].  To do this, the Verifier:

    * Sends a Discovery request for the specified Issuer Identifier
    * Fetches the JWK Set referenced by the `jwks_uri` field in the provider metadata
    * Identifies the key in the JWK Set corresponding to the `kid` field in the VC

1. The current time MUST be after the time represented in the `nbf` claim (if
   present) and before the time represented by the `exp` claim.

1. If the `vc` claim has a `credentialStatus` field, the Verifier SHOULD verify
   the revocation status as described in (#verifiable-credential-revocation).
   If the credential is suspended or revoked, then it MUST be rejected.


# Verifiable Credential Revocation

As described in (#openid-connect-verifiable-credential-format), an OIDC VC may
contain revocation information using the "StatusList2021" mechanism, which
provides a concise list of credentials revoked by an OP in a "status list
credential".  Status list credentials for OIDC VCs MUST meet the following
requirements, in addition to the requirements of [@!StatusList2021]:

* An status list credential MUST be represented as a JWT-formatted VC, as
  specified in Section 6.3.1 of [@!W3C.vc-data-model].  The `alg`, `kid`, and
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
Figure: A status list credential

A Verifier processing the VC checks the revocation status of the credential
using the following steps:

1. Fetch the status list credential from URL in the `statusListCredential` field
   of the `credentialStatus` object.

1. Verify that the credential meets the criteria above.

1. Verify the signature and expiration status of the status list credential.

1. Perform the "Validate Algorithm" defined in [@!StatusList2021].

If the final step returns `true`, then the Verifier MUST regard the certificate
as suspended or revoked (depending on the `statusPurpose`).  In either case, the
Verifier MUST reject the credential.  If any step fails, then the Verifier
SHOULD reject the credential.



# Asynchronous Issuer JWK Set Distribution

One benefit of verifiable credentials is that the relationship between the
credential Issuer (here the OP) and the Verifier is more arms-length.  The
Verifier only needs to know how to verify signatures from a trusted Issuer.

Verifiers can discover the JWK Set for a given Issuer OP using OpenID Connect
Discovery, as discussed in (#verifiable-credential-validation).  However, this
risks introducing a requirement that the Issuer's discovery endpoint be online
at the time of verification.  In order to avoid such a requirement, this section
defines a mechanism for an OP to sign its JWK Set to prove its authenticity to
verifiers.  Such a signed JWK Set can be provided to a Verifier by an untrusted
party (for example, the party presenting a credential), not just the OP.

A Verifier requests a signed JWK Set by sending an HTTP GET request to the OP's
JWKS URL with the value `application/jose` in the HTTP `Accept` header field.

An OP provides a signed JWK Set in a response to such a request by sending a
response containing a JWS object of the following form:

* The payload of the JWS object MUST be the OP's JWK Set, encoded as JSON using
  UTF-8.

* The JWS object MUST be in the JWS compact format.

* The `x5c` field of the JWS header MUST be populated with a certificate chain
  that authenticates the domain name in the OP's Issuer Identifier.  The host
  name in the Issuer Identifier MUST appear as a `dNSName` entry in the
  `subjectAltName` extension of the end-entity certificate.

* The `alg` field of the JWS header MUST represent an algorithm that is
  compatible with the subject public key of the certificate in the `x5c`
  parameter.

```
GET /jwks HTTP/1.1
Host: server.example.com
Accept: application/jose

HTTP/1.1 200 OK
Content-Type: application/jose

[[ TODO example signed JWK set ]]
```

A Verifier that receives such a signed JWK Set validates it by taking the
folloinwg steps:

1. Verify that the certificate chain in the `x5c` field is valid from a trusted
   certificate authority.

1. Verify that the end-entity certificate matches the Issuer Identifier as
   described above,.

1. Verify the signature on the JWS using the subject public key of the
   end-entity certificate


# Security Considerations {#security-considerations}

TODO

# Implementation Considerations

TODO

# Privacy Considerations

TODO

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
