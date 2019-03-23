# Digest-Auth

## Support

 Digest realization for **client** and **server**

 All quality of protection (qop): **auth**, **auth-int**
 
 Encryption algorithms: **MD5**, **MD5-sess**
 
 Ability **to force** use specific **qop** and **algorithm** (avoid some vulnerabilities) 
 
 Under the hood, use cryptographic functions for generating random nonces

## Solution

## Installation

`npm i @mreal/digest-auth -S`

## Usage Serve Digest Auth

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

The first step does the Analyze of the header "WWW-Authenticate" received from the server. 
Analyze implies parse, validation and extract digest requirements from server.
As a result, we have an object of requirements, such as: nonce, realm, qop, etc.
This data can be used in its own logic and necessary for the next step


The second step generates a digest response based on the incomingDigest, credentials, and other payload which is involved in encryption.
As a result, we have an object with parts of response (username, nonce, response hash), and raw string for "Authorization" request header for http request.
Also this data can be used in its own in more complex implementations.

### Quality of protection (qop) and algorithm

From a security point of view, this package does not support automatic selection of the **qop** method based on the server’s response. Although it leaves you the opportunity to realize it yourself

[rfc7616 5.8. Man-in-the-Middle Attacks](https://tools.ietf.org/html/rfc7616) 

>   A possible man-in-the-middle attack would be to add a weak
   authentication scheme to the set of choices, hoping that the client
   will use one that exposes the user's credentials (e.g., password).
   For this reason, the client SHOULD always use the strongest scheme
   that it understands from the choices offered.
   
   
Client Digest Auth provide 3 methods for generate Authorization header based different qop and without qop. Using this methods you force use specific qop and ignore a requested by server making the attack described above impossible  

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

You can also force **algorithm** when we use qop.

```javascript
  import {ClientDigestAuth, ALGORITHM_MD5_SESS} from '@mreal/digest-auth';
  
  const digest = ClientDigestAuth.generateProtectionAuth(incomingDigest, 'user', 'password', {
    method: 'POST',
    uri: '/some-uri',
    counter: 1,
    force_algorithm: ALGORITHM_MD5_SESS,
  });
```



## Detailed Usage Client Digest Auth

## Detailed Usage Serve Digest Auth

## Advice - Digest and highly loaded applications

## Recipe - Secure architecture based on authentication digest

package in TODO (actively developed. will be ready asap)
