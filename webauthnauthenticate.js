/* 

This is login part of the client (browser) side of webauthn authentication.

This really does little more than fetch the info from the physical key
or fingerprint reader etc, and repackage it in a palatable form for
sending to the server.

When generating the login page on the server, request a challenge from
webauthn->challenge(), and put the result into a hidden field on the
login form (which will also need your means to identify the user,
e.g. email address), probably as well as alternative means to log in
(such as a password login), or perhaps you're using the key as a
second factor, so this will be the second page or step in the login
sequence.

When they submit the form, call:
  webauthnAuthenticate(key, cb)
where key is the contents of the hidden field (or however else you stored
the challenge string). 

The function will ask the browser to get credentials from the user, prompting 
them to plug in the key, or touch finger or whatever.

On completion it will call the callback function cb:
  function cb(success, info)
success is a boolean, true for successful acquisition of info from the key,
in which case put info in the hidden field and continue with the submit
(or do an Ajax POST with the info, or whatever) and when received on the
server side call webauthn->authenticate.

If success is false, then either info is the string 'abort', meaning the
user failed to complete the process, or an error message of whatever else
went wrong.

*/

function webauthnAuthenticate(key, callbackfunc){
	let pkey = JSON.parse(key);
	let originalChallenge = pkey.challenge;
	pkey.challenge = new Uint8Array(pkey.challenge);
	pkey.allowCredentials.forEach(function(key, idx){
		pkey.allowCredentials[idx].id = new Uint8Array(key.id);
	});
	/* ask the browser to prompt the user */
	navigator.credentials.get({publicKey: pkey})
		.then(function(aAssertion) {
			// console.log("Credentials.Get response: ", aAssertion);
			let rawId = [];
			(new Uint8Array(aAssertion.rawId)).forEach(function(v){ rawId.push(v); });
			let clientData = JSON.parse(String.fromCharCode.apply(null, new Uint8Array(aAssertion.response.clientDataJSON)));
			let clientDataJSONarray = [];
			(new Uint8Array(aAssertion.response.clientDataJSON)).forEach(function(v){ clientDataJSONarray.push(v); });
			let authenticatorData = [];
			(new Uint8Array(aAssertion.response.authenticatorData)).forEach(function(v){ authenticatorData.push(v); });
			let signature = [];
			(new Uint8Array(aAssertion.response.signature)).forEach(function(v){ signature.push(v); });
			let info = {
				type: aAssertion.type,
				originalChallenge: originalChallenge,
				rawId: rawId,
				response: {
					authenticatorData: authenticatorData,
					clientData: clientData,
					clientDataJSONarray: clientDataJSONarray,
					signature: signature
				}
			};
			callbackfunc(true, JSON.stringify(info));
		})
		.catch(function (aError) {
			if (("name" in aError) && (aError.name == "AbortError" || aError.name == "NS_ERROR_ABORT" || aError.name == "NotAllowedError")) {
				callbackfunc(false, 'abort');
			} else {
				callbackfunc(false, aError.toString());
			}
		});
}
