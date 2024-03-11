(function () {
    const base64urlEncode = (array) => {
        let arrayBuf = array
        if (typeof array === "object") {
            arrayBuf = ArrayBuffer.isView(array) ? array : new Uint8Array(array);
        }

        const binString = Array.from(arrayBuf, (x) => String.fromCodePoint(x)).join("");
        return btoa(binString).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
    };

    const base64urlDecode = (base64) => {
        const padding = "====".substring(base64.length % 4);
        const binString = atob(base64.replaceAll("-", "+").replaceAll("_", "/") + (padding.length < 4 ? padding : ""));
        return Uint8Array.from(binString, (m) => m.codePointAt(0));
    };

    function arrayToBuffer(array) {
        /*Sometimes it is already an ArrayBuffer*/
        if (array.buffer) {
            return array.buffer.slice(array.byteOffset, array.byteLength + array.byteOffset)
        }
        return array
    }

    function assertFunc(assertion) {
        pk_input = document.getElementById("passkeys");
        if (pk_input.length == 0) {
            console.error("Did you add the 'passkey' hidden input field")
            return
        }
        if (assertion.rawId) {
            assertion.rawId = arrayToBuffer(assertion.rawId);
        }
        for (let key in assertion.response) {
            /*Careful about null values. On PC worked fine but on the android got null value */
            if (!Object.is(assertion.response[key], null)) {
                assertion.response[key] = arrayToBuffer(assertion.response[key])
            }
        }

        pk_input.value = JSON.stringify(credToJSON(assertion));
        let form = document.getElementById("loginForm")
        if (form === null || form === undefined) {
            console.error("Did you pass the correct form id to auth function")
            return;
        }
        form.submit()
    }

    // Define function to convert credentials to JSON
    const credToJSON = (pubKeyCred) => {
        if (pubKeyCred instanceof Array) {
            return pubKeyCred.map(credToJSON);
        }
        if (pubKeyCred instanceof ArrayBuffer) {
            return base64urlEncode(pubKeyCred);
        }
        if (pubKeyCred instanceof Object) {
            const res = {};
            for (const key in pubKeyCred) {
                res[key] = credToJSON(pubKeyCred[key]);
            }
            return res;
        }
        return pubKeyCred;
    };

    // Define function to handle assertion request
    const getAssertReq = (getAssert) => {
        console.log(getAssert)
        getAssert.publicKey.challenge = base64urlDecode(getAssert.publicKey.challenge);
        for (const allowCred of getAssert.publicKey.allowCredentials) {
            allowCred.id = base64urlDecode(allowCred.id);
        }
        return getAssert;
    };

    // Define function to handle registration request
    const makeCredReq = (creds) => {
        creds.publicKey.challenge = base64urlDecode(creds.publicKey.challenge);
        creds.publicKey.user.id = base64urlDecode(creds.publicKey.user.id);
        for (const excludeCred of creds.publicKey.excludeCredentials) {
            excludeCred.id = base64urlDecode(excludeCred.id);
        }
        return creds;
    };
    function getServerCredentials() {
        return new Promise((resolve, reject) => {
            fetch(window.passkeysConfig.urls.authBegin)
                .then(response => {
                    if (!response.ok) {
                        throw new Error('Could not get credentials from the server.');
                    }
                    return response.json();
                })
                .then(data => {
                    resolve(data);
                })
                .catch(error => {
                    reject(error);
                });
        });
    }
    function startAuthn(options, conditionalUI) {
        if (conditionalUI) {
            options.mediation = 'conditional';
            options.signal = window.conditionUIAbortSignal;
        }
        else
            window.conditionUIAbortController.abort()
        return navigator.credentials.get(options);
    }
    const beginReg = () => {
        fetch(window.passkeysConfig.urls.regBegin, {})
            .then(response => {
                if (response.ok) {
                    return response.json().then(makeCredReq);
                }
                throw new Error('Error getting registration data!');
            })
            .then(options => {
                return navigator.credentials.create(options);
            })
            .then(attestation => {
                attestation["key_name"] = document.querySelector("#key_name").value;
                attestation["rawId"] = base64urlEncode(attestation["rawId"]);
                for (const key in attestation["response"]) {
                    attestation["response"][key] = base64urlEncode(attestation.response[key]);
                }
                return fetch(window.passkeysConfig.urls.regComplete, {
                    method: 'POST',
                    body: JSON.stringify(credToJSON(attestation))
                });
            })
            .then(response => {
                return response.json();
            })
            .then(res => {
                if (res["status"] == 'OK') {
                    document.querySelector("#res").insertAdjacentHTML("afterbegin", `<div class='alert alert-success'>Registered Successfully, <a href='${window.passkeysConfig.homeURL}'> Refresh</a></div>`);
                } else {
                    document.querySelector("#res").insertAdjacentHTML("afterbegin", "<div class='alert alert-danger'>Registration Failed as " + res + ", <a href='javascript:void(0)' onclick='djangoPasskey.beginReg()'> try again </a> </div>");
                }
            })
            .catch(reason => {
                document.querySelector("#res").insertAdjacentHTML("afterbegin", "<div class='alert alert-danger'>Registration Failed as " + reason + ", <a href='javascript:void(0)' onclick='djangoPasskey.beginReg()'> try again </a> </div>");
            });
    };

    function confirmDel(id) {
        fetch(window.passkeysConfig.urls.delKey, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ id: id })
        })
            .then(response => response.text())
            .then(data => {
                alert(data);
                window.location = window.passkeysConfig.urls.home;
            })
            .catch(error => {
                console.error('Error confirming deletion:', error);
            });
    }

    function startRegistration() {
        const modalTitle = document.querySelector("#modal-title");
        const modalBody = document.querySelector("#modal-body");

        modalTitle.innerHTML = "Enter a token name";
        modalBody.innerHTML = `<p>Please enter a name for your new token</p>
                                <input type="text" placeholder="e.g Laptop, PC" id="key_name" class="form-control"/><br/>
                                <div id="res"></div>`;
        const modalFooter = document.querySelector("#modal-footer");
        modalFooter.insertAdjacentHTML('afterbegin', `<button id='actionBtn' class='btn btn-success' onclick="djangoPasskey.beginReg()">Start</button>`);
        document.querySelector("#popUpModal").style.display = "block";
    }

    function initialize() {
        getServerCredentials()
            .then(data => {
                startAuthn(getAssertReq(credToJSON(data))).then((assertion) => {
                    assertFunc(assertion);
                });
            })
            .catch(error => {
                console.error('Error during login:', error);
            });
    }



    window.djangoPasskey = {
        startRegistration: startRegistration,

        beginReg: beginReg,
        initialize: initialize
    };


    window.conditionalUI = false;
    window.conditionUIAbortController = new AbortController();
    window.conditionUIAbortSignal = window.conditionUIAbortController.signal;

})();

// Function to initiate authentication
function authn(formId) {
    startAuthn(formId, false);
}

/* TODO */
function displayPasskeyOption() {
    // Availability of `window.PublicKeyCredential` means WebAuthn is usable.
    // `isUserVerifyingPlatformAuthenticatorAvailable` means the feature detection is usable.
    // `​​isConditionalMediationAvailable` means the feature detection is usable.
    if (window.PublicKeyCredential &&
        PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable &&
        PublicKeyCredential.isConditionalMediationAvailable) {
        // Check if user verifying platform authenticator is available.
        Promise.all([
            PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable(),
            PublicKeyCredential.isConditionalMediationAvailable(),
        ]).then(results => {
            if (results.every(r => r === true)) {

            }
        });
    }
}


displayPasskeyOption();
