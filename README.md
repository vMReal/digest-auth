# Digest-Auth

[![Build Status](https://travis-ci.com/vMReal/digest-auth.svg?branch=v1.0.3)](https://travis-ci.com/vMReal/digest-auth)

## Support

 Digest realization for **client** and **server**

 All quality of protection (qop): **auth**, **auth-int**
 
 Encryption algorithms: **MD5**, **MD5-sess**
 
 Ability **to force** use specific **qop** and **algorithm** (avoid some vulnerabilities) 
 
 Under the hood, use cryptographic functions for generating random nonces

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


## Usage Serve Digest Auth

```javascript
    import {ServerDigestAuth} from '@mreal/digest-auth';
  
    try {
        const incomingDigest = ServerDigestAuth.analyze(headers['Authorization'], false);
        const result = ServerDigestAuth.verifyByPassword(incomingDigest, password, { 
            method: 'POST', 
            uri: '/some-uri' 
        });
        
        if (!result)
            throw new Error('authentication_error');
          
    } catch (e) {
        const response = ServerDigestAuth.generateResponse('all');
    }
```


The first step does the Analyze of the header "Authorization" received from the server. 
Analyze implies parse, validation and extract digest payload from client.
As a result, we have an object of payload, such as: nonce, cnonce, username, qop, etc.
This data can be used for extract password and necessary for the next step

```javascript
    import {ServerDigestAuth} from '@mreal/digest-auth';

    const incomingDigest = ServerDigestAuth.analyze(headers['Authorization'], false);
    
    console.log(incomingDigest); 
    // { username: 'user', response: 'e524170b3e02dedaf6a1110131fb5a50', nonce: 'd8483aa2fe3f31fe8b9497ed63e4899f3e352d980f7c56f0' ...
```

The second step performs a verify by the hash comparison. To do this, we must provide a password and a http payload (other fields will be obtained from the incoming digest)

As a result, we have a boolean value as status of verification.


```javascript
    import {ServerDigestAuth} from '@mreal/digest-auth';

    const result = ServerDigestAuth.verifyByPassword(incomingDigest, password, { 
        method: 'POST', 
        uri: '/some-uri' 
    });
    
    console.log(result);
    // true
```


The last step performed a generation of response. This response contain raw string for "WWW-Authenticate" header for 401 http-response and object of original data from raw string.

We should generate digest response and return 401 "WWW-Authenticate" header in all cases expect success a authentication (analyze error, validation error, verify error, user not found, etc).

```javascript
    import {ServerDigestAuth} from '@mreal/digest-auth';

    const response = ServerDigestAuth.generateResponse('all');
    
    console.log(response);
    // { realm: 'all', raw: 'Digest realm="all"...
```

### Quality of protection (qop) 

This option allows you: 

1. protect against repeated requests by signing request data (body, links, method).

2. complicate the encryption algorithm

3. have rapid detection of hacking attempts

But this requires the server to implement additional functions:
1. Store nonce after generation short time anywhere (memory, redis, files, etc..).
2. Implement your own validation by searching for the received nocne from a client among those nocnes you have in storage.
3. [optional] Store the request counter in pairs with nonce. Each success request make increment a request counter. Each request check a counter provided by client (nc) with saved a request counter in storage. 
4. [optional] Error analysis for detection of hacking attempts


```javascript
    import {ServerDigestAuth, QOP_AUTH_INT} from '@mreal/digest-auth';
  
    try {
        const incomingDigest = ServerDigestAuth.analyze(headers['Authorization'], [QOP_AUTH_INT]);
        
        const result = ServerDigestAuth.verifyByPassword(incomingDigest, password, { 
            method: 'POST', 
            uri: '/some-uri' 
            entryBody: '',
        });
        
        if (!result)
            throw new Error('authentication_error');
      
        if (!storage.hasNonce(incomingDigest.nonce))  
            throw new Error('unknown_nonce_error');
            
        if (storage.getNonceCounter(incomingDigest.nonce) !=== (incomingDigest.nc - 1))  
            throw new Error('incorrect_nc_error');
            
        storage.incrementNonceCounter(incomingDigest.nonce);       
    
    } catch(e) {
        // error analysis for detection of hacking attempts
        
        const response = ServerDigestAuth.generateResponse('all', {
            opaque: 'customValue',
            qop: QOP_AUTH_INT,
            algorithm: ALGORITHM_MD5_SESS,
        });
        
        storage.addNonce(response.nonce); 
    }
```


An example with one time nonce without using a counter (without 3 point).

```javascript
    try {
        ....
        
        if (!result)
            throw new Error('authentication_error');
      
        if (!storage.hasNonce(incomingDigest.nonce))  
            throw new Error('unknown_nonce_error');
            
        if (incomingDigest.nc === 1)  
            throw new Error('incorrect_nc_error');
            
        storage.removeNonce(incomingDigest.nonce);       
    
    } catch(e) {
        ...
        
        storage.addNonce(response.nonce); 
    }
```


You may have difficulty with a consistent counter incrementation approach.

You can use counter like blacklist. 

You are still protected from repeated requests!


```javascript
    try {
        ....
        
        if (!result)
            throw new Error('authentication_error');
      
        if (!storage.hasNonce(incomingDigest.nonce))  
            throw new Error('unknown_nonce_error');
            
        if (storage.isBlacklistedNc(incomingDigest.nonce, incomingDigest.nc))  
            throw new Error('incorrect_nc_error');
            
        storage.extendNcBlacklist(incomingDigest.nonce, incomingDigest.nc);       
    
    } catch(e) {
        ...
        
        storage.addNonce(response.nonce); 
    }
```

### Verify by secret

In the case when you have a user database.

To store passwords in the open (human-readable) form is a bad idea.

Good practice is to store an irreversible hash. But digest comparing algorithm required password in open form.

In order to solve this problem, we can use the artifact of the initial stage of digest comparing (HA1 = MD5(username:realm:password) [rfc2617 А1](https://tools.ietf.org/html/rfc2617#section-3.2.2.2) )

For the convenience of creating this hash, you can use the `HA1` helper.

```javascript
  import { HA1 } from '@mreal/digest-auth';
  
  const secret = HA1.create('username', 'realm', 'password');
  
  console.log(secret); // 4D86DBF27A98B2F451D973A00F567D6B

```

Next use method `verifyBySecret` instead of `verifyByPassword`

```javascript
  const result = ServerDigestAuth.verifyBySecret(incomingDigest, secret, { 
      method: 'POST', 
      uri: '/some-uri' 
      entryBody: '',
  });
```

> recommendation to use "MD5-sess" algorithm for digest-auth.

