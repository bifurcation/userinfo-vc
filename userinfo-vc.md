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
For example, in the End-to-End Identity use case discussed in
(#end-to-end-identity), each individual user would have to be registered as a
Client of every OP involved in a session, which clearly does not scale.

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

Since this specification is mainly a profile of OpenID for Verifiable Credential
Issuance [@!OpenID4VCI], the overal; flow of the protocol is the same.
(#fig-overview) shows how an OP is involved in the issuance and verification of
a UserInfo Verifiable Credential: 

1. The Client (Holder in the VC model) obtains the OP's server metadata, which
   indicates support for issuance of UserInfoCredential credentials.

1. The Client issues an authorization request including the
   `userinfo_credential` scope to request authorization to issue UserInfo
   credentials, as well as the `openid` scope and other scopes to request access
   to UserInfo information (e.g., `profile`, `email`).

1. The OP authenticates the user and obtains the user's consent to credential
   issuance.

1. The Authorization Response provides the Client with an authorization code

1. The Client sends a Token Request containing the authorization code

1. The Token Response provides the Client with:
    * An access token that can be used to access the credential endpoint
    * A nonce that can be used to prove possession of a private key

1. The Client sends a Credential Request specifying that it desires a
   UserInfoCredential, together with a proof that it controls the private key of
   an signature key pair.

1. The Credential Response contains a UserInfo VC that attests to the following
   attributes of the Holder:
    * The claims that would have been provided by the UserInfo endpoint
    * The public key corresponding to the private key used to compute the proof
      in the Credential Request

1. The Client sends the credential to a Verifier in some presentation protocol
   (outside the scope of this document)

1. The Verifier fetches the OP's JWK Set

1. The Verifier uses a public key from the OP's JWK Set to verify the signature
   on the credential.

``` aasvg
+--------+                                    +--------+              +----------+
| Client |                                    |   OP   |              |          | 
|   ==   |                                    |   ==   |              | Verifier |
| Holder |                                    | Issuer |              |          |
+---+----+                                    +---+----+              +-----+----+
    |                                             |                         |
    | 1. Obtain Issuer server metadata            |                         |
    |    (types=UserInfoCredential)               |                         |
    |<--------------------------------------------+                         |
    |                                             |                         |
    | 2. Authorization Request                    |                         |
    |    (scope=userinfo_credential)              |                         |
    +-------------------------------------------->|                         |
    |                                             |                         |
    |~~~~~~ 3. User authentication / consent ~~~~~|                         |
    |                                             |                         |
    | 4. Authorization Response (code)            |                         |
    |<--------------------------------------------+                         |
    |                                             |                         |
    | 5. Token Request (code)                     |                         |
    +-------------------------------------------->|                         |
    |                                             |                         |
    | 6. Token Response (access_token, c_nonce)   |                         |
    |<--------------------------------------------+                         |
    |                                             |                         |
    | 7. Credential Request                       |                         |
    |    (type=UserInfoCredential, proof)         |                         |
    +-------------------------------------------->|                         |
    |                                             |                         |
    | 8. Credential Response (credential)         |                         |
    |<--------------------------------------------+                         |
    |                                             |                         |
    |                                                                       |
    |~~~~~~~~~~~~~~~~~ 9. Presentation protocol (credential) ~~~~~~~~~~~~~~~|
    |                                                                       |
    |                                             |                         |
    |                                             | 10. Obtain Issuer JWKS  |
    |                                             +------------------------>|
    |                                             |                         |
    |                                             | 11. Verify credential   |
    |                                             |                 .-------+
    |                                             |                |        |
    |                                             |                 '------>|
    |                                             |                         |
```
Figure: Issuance, presentation, and verification of a UserInfo credential
{#fig-overview}

# Out of Scope

The focus of this specification is on the Verifiable Credential issuance
interaction, and on the processes to verify credentials so issued.  We do not
address the presentation interaction.  This step can be accomplished with a
standard presentation protocol such as OpenID for Verifiable Presentations
[@!OpenID4VP], or via integration with another protocol that provides
proof-of-possession mechanics, such as MLS or TLS [@!I-D.ietf-mls-protocol]
[@!RFC8446].

This specification is intended as a minimal profile of the more general VC
Issuance mechanism, and places no constraints on how an OP implements VC
Issuance for credential types other than `UserInfoCredential`.


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

# Security Considerations {#security-considerations}

TODO

# Implementation Considerations

TODO

# Privacy Considerations

TODO

{backmatter}

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

## OpenID for Verifiable Presentations

[[ TODO ]]

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

