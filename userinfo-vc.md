%%%
title = "OpenID Connect UserInfo Verifiable Credentials"
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

The OpenID Connect UserInfo endpoint provides user attributes to OpenID Clients.
Providing these attributes in the form of a Verifiable Credential enables new
use cases.  This specification defines a new Verifiable Credential type
"UserInfoCredential" for this purpose, and defines a profile of the OpenID for
Verifiable Credential Issuance protocol for issuing these credentials.  We also
define an interoperable profile of the StatusList2021 credential revocation
mechanism, and a mechanism for distributing OpenID Provider JWK Sets that
enables credential verification even if the OpenID Provider is unreachable.

{mainmatter}

# Introduction

The OpenID Connect UserInfo endpoint is the channel by which an OpenID Provider
(OP) exposes user attributes to OpenID Client.  The standard claims defined in
the OpenID Connect Core specification [@!OpenID.Core] are widely supported,
forming the basis of much of today's identity ecosystem.

However, the bearer token structure of OpenID Connect means that each party that
wants to authenticate a user's attributes needs to be independently registered
as a Client of the OP and needs to do an independent OpenID Connect interaction
to authenticate the user.  This constraint is not too onerous in the cases where
OpenID Connect is typically deployed today, but it rules out other use cases.
For example, in the End-to-End Identity use case discussed in (#e2e-identity),
each individual user would have to be registered as a Client of every OP
involved in a session, which clearly does not scale.

Verifiable Credentials provide a more flexible model for distributing
information about a user [@!W3C.vc-data-model].  In this model, an Issuer that
knows a user's identity attributes issues a Verifiable Credential to a Holder
that acts on behalf of the user.  The Holder can then present the Verifiable
Credential to any Verifier that trusts the issuer, without the Verifier or the
verification transaction having to be known to the Issuer.

``` aasvg
+--------+               +--------+                   +----------+
| Issuer |--(issuance)-->| Holder |--(presentation)-->| Verifier |
+--------+               +--------+                   +----------+
    ^                                                      .
    .                                                      .
    .......................(trust)..........................
```

This specification defines the interfaces required for an OpenID Provider to
expose the information provided by the UserInfo endpoint in the form of a
Verifiable Credential:

* A new "UserInfoCredential" credential type that carries UserInfo claims
* A profile of the OpenID for Verifiable Credential Issuance [@!OpenID4VCI]
* A profile of the StatusList2021 mechanism for credential revocation [@!StatusList2021]
* A new mechanism for asynchronously distributing an OpenID Provider's JWK Set

Together, these interfaces allow the issuance of Verifiable Credentials
containing OpenID Connect claims with the same degree of simplicity and
interoperability as OpenID Connect itself.

# Overview

* Essentially the same flow as OpenID4VCI
* Maybe show validation / revocation checking

# Out of Scope section

* mention that MLS can be used for Presentation 


# UserInfo Credential Type

* `credentialSubject` contains Basic claims (UserInfo claims) + JWK Thumbprint `id`
* no JSON-LD, JWS signed
  * it's instead of approach and not in addition to: Constrained structure for other claims (e.g., "iss" instead of "vc.issuer")
* Example VC


## Revocation

* SHOULD include revocation info in `credentialStatus`
* If present, MUST use StatusList2021
  * [[ constraints on status list credential ]]
* Example status list credential


# Profile of OpenID for VC Issuance

* Wallet-initiated, authorized code flow MUST be supported
KY: What about pre-authorized code flow
* Optional endpoints in OpenID4VCI are also optional here
  * Issuance Initiation Endpoint
  * Batch Credential Endpoint
  * Deferred Credential Endpoint


## Authorization Endpoint

* MUST support `userinfo_credential` scope
* Example authorization request


## Token Endpoint

* No chage [[ would like to say MUST send `c_nonce`, might not be feasible? ]]
KY: `c_nonce` is optional 
* Example token request / response


## Credential Endpoint

### Credential Request

* MUST support the following:
  * `"format": "jwt_vc_json"`
  * `"types": ["VerifiableCredential", "UserInfoCredential"]`
  * `"proof": /* JWT with subject public key in "jwk"*/`
* When issuing UserInfoCredential:
  * Proof of possession MUST be provided; "jwk" proof type MUST be supported
* Example credential request

### Credential Response

* No change
* Example response

## Cryptosuite

MTI?
no HMAC for jwt proof. -> core VCI spec

### Server-Provided Nonces

* [[ non-normative, just helpful notes for clients ]]
* Clients will need a nonce to compute the proof to go in the credential request
* These come from token response, credential response, or error response
* If a client needs to make a credential request and does not have a nonce:
  * Send a "priming request" with only `format` and `types`
  * Expect to get back a 400 of type `missing_proof` containing a nonce

## Server Metadata

* MUST have a supportedCredentials entry for format `jwt_vc_json`, with the following properties:
  * `cryptographic_binding_methods_supported` MUST include `jwk`
  * `cryptographic_suites_supported` MUST NOT include MAC-based algorithms or `none`
  * `types` MUST include `UserInfoCredential`

# Signed JWK Sets

--- back matter

# Use Cases
## OpenID for Verifiable Presentations
## End-to-End Security
