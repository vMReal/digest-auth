# Digest-Auth

[![Node.js CI](https://github.com/vMReal/digest-auth/actions/workflows/nodejs.yml/badge.svg)](https://github.com/vMReal/digest-auth/actions/workflows/nodejs.yml)
[![Codecov](https://codecov.io/gh/vMReal/digest-auth/branch/master/graph/badge.svg)](https://codecov.io/gh/vMReal/digest-auth)

[![Version](https://img.shields.io/npm/v/@mreal/digest-auth.svg)](https://npmjs.org/package/@mreal/digest-auth)
![NPM Downloads](https://img.shields.io/npm/d18m/%40mreal%2Fdigest-auth?style=social)

![Node Current](https://img.shields.io/node/v/%40mreal%2Fdigest-auth?style=for-the-badge)
![NPM Type Definitions](https://img.shields.io/npm/types/%40mreal%2Fdigest-auth?style=for-the-badge)
![NPM License](https://img.shields.io/npm/l/%40mreal%2Fdigest-auth?style=for-the-badge)









## Features
* Digest authentication implemented for both **client** and **server**.
* Supports all qualities of protection (qop): **auth**, **auth-int**
* Encryption algorithms supported: **MD5**, **MD5-sess**
* Ability **to force** the use of specific **qop** and **algorithm** (to avoid certain vulnerabilities).
* Uses **cryptographic functions** under the hood to generate random nonces.

## Installation

`npm i @mreal/digest-auth -S`

## Usage Client Digest Auth

```javascript
  import {ClientDigestAuth} from '@mreal/digest-auth';

  const incomingDigest = ClientDigestAuth.analyze(headers['WWW-Authenticate']);
  const digest = ClientDigestAuth.generateUnprotected(incomingDigest, 'user', 'password', {
    method: 'POST',
    uri: '/some-uri'
  });

  console.log(digest.raw);
  // Digest username="user", realm="some-realm", nonce="some-nonce", uri="/some-uri", algorithm="MD5", response="48388ab4ca0c46a73e4d2f23ccc7632e"
```

The first step is to analyze the “WWW-Authenticate” header received from the server to parse, validate, and extract digest requirements. 

> As a result, we have an object of requirements, such as: `nonce`, `realm`, `qop`, etc.
> 
> This data can be utilized in its own logic and is necessary for the next step.

The second step generates a digest response based on the `incomingDigest`, `credentials`, and other payload involved in encryption.
> As a result, we obtain an object with parts of the response (`username`, `nonce`, `response` hash), and a `raw` string for the “Authorization” request header for the HTTP request.
> 
> Additionally, this data can be utilized on its own in more complex implementations.

### Quality of protection (qop) and algorithm

Client Digest Auth provides three methods to generate an Authorization header based on different qop values and without qop.

```javascript
  import {ClientDigestAuth} from '@mreal/digest-auth';

  
  const digest = ClientDigestAuth.generateUnprotected(incomingDigest, 'user', 'password', {
    method: 'POST',
    uri: '/some-uri',
  });
  
  // OR
  
  const digest = ClientDigestAuth.generateProtectionAuth(incomingDigest, 'user', 'password', {
    method: 'POST',
    uri: '/some-uri',
    counter: 1,
  });
  
  // OR
  
  const digest = ClientDigestAuth.generateProtectionAuthInt(incomingDigest, 'user', 'password', {
    method: 'POST',
    uri: '/some-uri',
    counter: 1,
    entryBody: '{"a": "b"}'
  });
```

You can also enforce a specific **algorithm** when using qop.

```javascript
  import {ClientDigestAuth, ALGORITHM_MD5_SESS} from '@mreal/digest-auth';
  
  const digest = ClientDigestAuth.generateProtectionAuth(incomingDigest, 'user', 'password', {
    method: 'POST',
    uri: '/some-uri',
    counter: 1,
    force_algorithm: ALGORITHM_MD5_SESS,
  });
```

By using these methods, you can enforce a specific qop and ignore the one requested by the server, protecting this aspect from a man-in-the-middle attack.

> From a security standpoint, this package does not support automatic selection of the qop method based on the server’s response.
>
>  The standard says:  
> _"A possible man-in-the-middle attack would be to add a weak
authentication scheme to the set of choices, hoping that the client
will use one that exposes the user's credentials (e.g., password).
For this reason, the client SHOULD always use the strongest scheme
that it understands from the choices offered."_
>
> [rfc7616 / 5.8 / Man-in-the-Middle Attacks](https://datatracker.ietf.org/doc/html/rfc7616#section-5.8)

## Usage Serve Digest Auth

The first step involves analyzing the “Authorization” header received from the client to parse, validate, and extract the digest payload from the client.

> As a result, we obtain an object containing payload elements such as `nonce`, `cnonce`, `username`, `qop`, etc.
>
> This data can be used to extract the password and is necessary for the next step.

```javascript
    import {ServerDigestAuth} from '@mreal/digest-auth';

    const incomingDigest = ServerDigestAuth.analyze(headers['Authorization'], false);
    
    console.log(incomingDigest); 
    // { username: 'user', response: 'e524170b3e02dedaf6a1110131fb5a50', nonce: 'd8483aa2fe3f31fe8b9497ed63e4899f3e352d980f7c56f0' ...
```

The second step performs verification through hash comparison.

> To do this, we must provide a password and HTTP payload (other fields will be obtained from the `incomingDigest`).
> 
> As a result, we have a `boolean` value as status of verification.


```javascript
    import {ServerDigestAuth} from '@mreal/digest-auth';

    const result = ServerDigestAuth.verifyByPassword(incomingDigest, password, { 
        method: 'POST', 
        uri: '/some-uri' 
    });
    
    console.log(result);
    // true
```


The last step involves generating a response.

> This response contains a raw string for the “WWW-Authenticate” header for a 401 HTTP response and an object with the original data from the `raw` string.
> 
> You should generate a digest response and return a 401 “WWW-Authenticate” header in all cases except successful authentication (analysis error, validation error, verification error, user not found, etc.).

```javascript
    import {ServerDigestAuth} from '@mreal/digest-auth';

    const response = ServerDigestAuth.generateResponse('all');
    
    console.log(response);
    // { realm: 'all', raw: 'Digest realm="all"...
```

Full example

```javascript
    import {ServerDigestAuth} from '@mreal/digest-auth';
  
    try {
        const incomingDigest = ServerDigestAuth.analyze(headers['Authorization'], false);
        
        // Get the "password" that is stored somewhere on your server using "username", "realm"
      
        const result = ServerDigestAuth.verifyByPassword(incomingDigest, password, { 
            method: 'POST', 
            uri: '/some-uri' 
        });
        
        if (!result)
            throw new Error('authentication_error');
        
        // The request was authenticated successfully
          
    } catch (e) {
        const response = ServerDigestAuth.generateResponse('all');
        
        // Generate unauthorized response with 401 status code and “WWW-Authenticate” header from "raw" property
    }
```

### Quality of protection (qop) 

This option allows you: 

1. Protect against repeated requests by signing request data (body, links, method).

2. Complicate the encryption algorithm

3. Have rapid detection of hacking attempts

However, this requires the server to implement additional functions:
1. Store the nonce temporarily after generation in any storage (memory, Redis, files, etc.).
2. Implement your own validation by searching for the received nonce from a client among those nonces you have in storage.
3. [Optional] Store the request counter in pairs with the nonce. Each successful request increments the request counter. Each request checks the counter provided by the client (nc) against the saved request counter in storage. 
4. [Optional] Error monitoring and alerts to detect hacking attempts.


```javascript
    import {ServerDigestAuth, QOP_AUTH_INT} from '@mreal/digest-auth';
  
    try {
        const incomingDigest = ServerDigestAuth.analyze(headers['Authorization'], [QOP_AUTH_INT]);
        
        const result = ServerDigestAuth.verifyByPassword(incomingDigest, password, { 
            method: 'POST', 
            uri: '/some-uri', 
            entryBody: '',
        });
        
        if (!result)
            throw new Error('authentication_error');
      
        // Validation by searching for the received nonce from a client among those nonces you have in a storage might look something like this:
        if (!storage.hasNonce(incomingDigest.nonce))  
            throw new Error('unknown_nonce_error');
        
        // To check the counter provided by the client (nc) against the saved request counter in a storage might look something like this:    
        if (storage.getNonceCounter(incomingDigest.nonce) !== (incomingDigest.nc - 1))  
            throw new Error('incorrect_nc_error');
        
        // Storing a request counter in pairs with the nonce and incrementing the request counter on each successful request might look something like this:
        storage.incrementNonceCounter(incomingDigest.nonce);

        // The request was authenticated and post-action was performed successfully
    
    } catch(e) {
        // Error monitoring to detect hacking attempts can be placed here.
        
        const response = ServerDigestAuth.generateResponse('all', {
            opaque: 'customValue',
            qop: QOP_AUTH_INT,
            algorithm: ALGORITHM_MD5_SESS,
        });
        
        // Storing the nonce temporarily after the generation might look something like this:
        storage.addNonce(response.nonce);

        // Generate unauthorized response with 401 status code and “WWW-Authenticate” header from "raw" property
    }
```


An example with **one time nonce** (without using a counter).
> This approach assumes that after each successful response there will be a 401 in order to generate a new "nonce", which will increase the load on the network and the server. This approach is not recommended unless you specifically want to achieve this.

```javascript
    try {
        ....
        
        if (!result)
            throw new Error('authentication_error');
      
        // Validation by searching for the received nonce from a client among those nonces you have in a storage might look something like this:
        if (!storage.hasNonce(incomingDigest.nonce))  
            throw new Error('unknown_nonce_error');
        
        // Making the nonce invalid immediately after the first use might look something like this:
        storage.removeNonce(incomingDigest.nonce);

        // The request was authenticated and post-action was performed successfully
    
    } catch(e) {
        ...
        
        storage.addNonce(response.nonce);

        // Generate unauthorized response with 401 status code and “WWW-Authenticate” header from "raw" property
    }
```

### Verify by secret

It allows you to use secrets (HA1) instead of passwords for Digest Authentication. 
This reduces the need to store the actual password in the database. 

> However, even though the password itself is not exposed, you must ensure the security of these secrets (HA1).
>
> If A1 is compromised, an attacker could use it to generate valid digest responses without knowing the actual password. 
> 
> Therefore, HA1 should be stored with the same security precautions as the password.

> The standard says:
> 
> _Digest authentication requires that the authenticating agent (usually
the server) store some data derived from the user's name and password
in a "password file" associated with a given realm. Normally this
might contain pairs consisting of username and H(A1), where H(A1) is
the digested value of the username, realm, and password as described
above._
>
> _The security implications of this are that if this password file is
compromised, then an attacker gains immediate access to documents on
the server using this realm._ 
> 
> [rfc7616 / 4.13 / Storing passwords](https://datatracker.ietf.org/doc/html/rfc2617#section-4.13)

For convenience in creating this hash, you can use the `HA1` helper.

```javascript
  import { HA1 } from '@mreal/digest-auth';
  
  const secret = HA1.create('username', 'realm', 'password');
  
  console.log(secret); // 4D86DBF27A98B2F451D973A00F567D6B

```

Next, use the `verifyBySecret` method instead of `verifyByPassword`.

```javascript
  const result = ServerDigestAuth.verifyBySecret(incomingDigest, secret, { 
      method: 'POST', 
      uri: '/some-uri', 
      entryBody: '',
  });
```

> recommendation to use "MD5-sess" algorithm for digest-auth.

## Other

### Multiple Authorization Header

Both server and client functions support analyzing multiple authorizations.

However, you must implement the business logic to choose the scheme that best suits your needs.

By default, without the “multiple authorization” option, the first found digest will be returned.

```javascript
const multipleAuthorization = ServerDigestAuth.analyze(headers['Authorization'], [QOP_AUTH_INT], true);

console.log(multipleAuthorization) // Outputs: [ {scheme: 'Basic', raw: '....'}, { scheme: 'Digest', username="user", nonce="some-nonce", ...}]
```

```javascript
const multipleAuthorization = ClientDigestAuth.analyze(headers['WWW-Authenticate'], true);

console.log(multipleAuthorization) // Outputs: [ {scheme: 'Basic', raw: '....'}, { scheme: 'Digest', username="user", nonce="some-nonce", ...}]
```
