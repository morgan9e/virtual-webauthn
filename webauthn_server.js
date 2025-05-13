// ==UserScript==
// @name         WebAuthnOffload
// @description  
// @version      1.0
// @author       @morgan9e
// @include      *
// @connect      127.0.0.1
// @grant        GM_xmlhttpRequest
// ==/UserScript==

function abb64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary)
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
}

function b64ab(input) {
    const binary = atob(input.replace(/-/g, '+').replace(/_/g, '/'));
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

function myFetch(url, options = {}) {
  return new Promise((resolve, reject) => {
    GM_xmlhttpRequest({
      method: options.method || 'GET',
      url: url,
      headers: options.headers || {},
      data: options.body || undefined,
      responseType: options.responseType || 'json',
      onload: function(response) {
        const responseObj = {
          ok: response.status >= 200 && response.status < 300,
          status: response.status,
          statusText: response.statusText,
          headers: response.responseHeaders,
          text: () => Promise.resolve(response.responseText),
          json: () => Promise.resolve(JSON.parse(response.responseText)),
          response: response
        };
        resolve(responseObj);
      },
      onerror: function(error) {
        reject(new Error(`Request to ${url} failed`));
      }
    });
  });
}

const origGet = navigator.credentials.get;
const origCreate = navigator.credentials.create;

navigator.credentials.get = async function(options) {
    console.log("navigator.credentials.get", options)
    try {
        const authOptions = {publicKey: Object.assign({}, options.publicKey)};
        console.log(authOptions);
        authOptions.publicKey.challenge = abb64(authOptions.publicKey.challenge)
        authOptions.publicKey.allowCredentials = authOptions.publicKey.allowCredentials.map(credential => ({
            ...credential, id: abb64(credential.id)
        }));
        const response = await myFetch('http://127.0.0.1:20492', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                type: "get",
                data: { ...authOptions, origin: window.origin }
            })
        });
        if (!response.ok) throw new Error(`server error: ${response.status}`)
        const resp = await response.json()
        console.log("server response:", resp)
        const credential = {
            id: resp.id,
            type: resp.type,
            rawId: b64ab(resp.rawId),
            response: {
                authenticatorData: b64ab(resp.response.authenticatorData),
                clientDataJSON: b64ab(resp.response.clientDataJSON),
                signature: b64ab(resp.response.signature)
            },
            getClientExtensionResults: () => { return {} }
        }
        if (resp.response.userHandle) {
            credential.response.userHandle = b64ab(resp.response.userHandle);
        }
        console.log(credential)
        return credential;
    } catch (error) {
        console.error(`Error: ${error.message}, falling back to browser`);
        let r = await origGet.call(navigator.credentials, options);
        console.log(r);
        return r;
    }
};

navigator.credentials.create = async function(options) {
    console.log("navigator.credentials.create", options)
    try {
        const authOptions = {publicKey: Object.assign({}, options.publicKey)};
        console.log(authOptions);
        authOptions.publicKey.challenge = abb64(authOptions.publicKey.challenge)
        authOptions.publicKey.user.id = abb64(authOptions.publicKey.user.id)
        const response = await myFetch('http://127.0.0.1:20492', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                type: "create",
                data: { ...authOptions, origin: window.origin }
            })
        });
        if (!response.ok) throw new Error(`server error: ${response.status}`)
        const resp = await response.json()
        console.log("server response:", resp)
        const credential = {
            id: resp.id,
            type: resp.type,
            rawId: b64ab(resp.rawId),
            response: {
                attestationObject: b64ab(resp.response.attestationObject),
                clientDataJSON: b64ab(resp.response.clientDataJSON),
                pubKeyAlgo: resp.response.pubKeyAlgo,
                publicKey: b64ab(resp.response.publicKey),
                transports: resp.response.transports,
                authenticatorData: b64ab(resp.response.authenticatorData),
                getAuthenticatorData:() => { return b64ab(resp.response.authenticatorData) },
                getPublicKey: () => { return b64ab(resp.response.publicKey) },
                getPublicKeyAlgorithm: () => { return resp.response.pubKeyAlgo },
                getTransports: () => { return resp.response.transports }
            },
            getClientExtensionResults: () => { return {} }
        }
        console.log(credential)
        return credential;
    } catch (error) {
        console.error(`Error: ${error.message}, falling back to browser`);
        let r = await origCreate.call(navigator.credentials, options);
        console.log(r);
        return r;
    }
};

console.log("Injected WebAuthn")