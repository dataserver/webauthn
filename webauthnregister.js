/* 

This is key registration part of the client (browser) side of webauthn
authentication.

This really does little more than fetch the info from the physical key
or fingerprint reader etc, and repackage it in a palatable form for
sending to the server.

When registering a user account, or allowing them to add a key in their profile,
or whatever, request a challenge from $webauthn->challenge() (e.g. using Ajax)
and pass the resulting key string to
  webauthnRegister(key, cb)
where key is the contents of the hidden field (or however else you stored
the challenge string). 

The function will ask the browser to identify their key or touch fingerprint
or whatever.

On completion it will call the callback function cb:
  function cb(success, info)
success is a boolean, true for successful acquisition of info from the key,
in which case pass the info back to the server, call $webauth->register to 
validate it, and put the resulting string back in the user record for use
in future logins.

If success is false, then either info is the string 'abort', meaning the
user failed to complete the process, or an error message of whatever else
went wrong.

*/

function webauthnRegister(key, callbackfunc){
	key = JSON.parse(key);
	key.publicKey.attestation = undefined;
	key.publicKey.challenge = new Uint8Array(key.publicKey.challenge); // convert type for use by key
	key.publicKey.user.id = new Uint8Array(key.publicKey.user.id);
	
	// console.log(key);
	navigator.credentials.create({publicKey: key.publicKey}).
	then(function (aNewCredentialInfo) {
		// console.log("Credentials.Create response: ", aNewCredentialInfo);
		let cdata = JSON.parse(String.fromCharCode.apply(null, new Uint8Array(aNewCredentialInfo.response.clientDataJSON)));
		if (key.b64challenge != cdata.challenge){ 
			callbackfunc(false, 'key returned something unexpected (1)');
		}
		if ('https://'+key.publicKey.rp.name != cdata.origin) {
			return callbackfunc(false, 'key returned something unexpected (2)');
		}
		if (! ('type' in cdata)) {
			return callbackfunc(false, 'key returned something unexpected (3)');
		}
		if (cdata.type != 'webauthn.create') {
			return callbackfunc(false, 'key returned something unexpected (4)');
		}

		let attestationObject = [];
		(new Uint8Array(aNewCredentialInfo.response.attestationObject)).forEach(function(v){ attestationObject.push(v); });
		let rawId = [];
		(new Uint8Array(aNewCredentialInfo.rawId)).forEach(function(v){ rawId.push(v); });
		let info = {
			rawId: rawId,
			id: aNewCredentialInfo.id,
			type: aNewCredentialInfo.type,
			response: {
				attestationObject: attestationObject,
				clientDataJSON: JSON.parse(String.fromCharCode.apply(null, new Uint8Array(aNewCredentialInfo.response.clientDataJSON)))
			}
		};
		callbackfunc(true, JSON.stringify(info));
	}).
	catch(function(aError) {
		if (("name" in aError) && (aError.name == "AbortError" || aError.name == "NS_ERROR_ABORT") || aError.name == 'NotAllowedError') {
			callbackfunc(false, 'abort');
		} else {
			callbackfunc(false, aError.toString());
		}
	});
}
