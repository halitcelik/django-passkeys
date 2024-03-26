(function () {
    function base64URLStringToBuffer(base64URLString) {
        if (typeof base64URLString === "undefined") {
            return
        }
        // Convert from Base64URL to Base64
        const base64 = base64URLString.replace(/-/g, '+').replace(/_/g, '/');
        /**
         * Pad with '=' until it's a multiple of four
         * (4 - (85 % 4 = 1) = 3) % 4 = 3 padding
         * (4 - (86 % 4 = 2) = 2) % 4 = 2 padding
         * (4 - (87 % 4 = 3) = 1) % 4 = 1 padding
         * (4 - (88 % 4 = 0) = 4) % 4 = 0 padding
         */
        const padLength = (4 - (base64.length % 4)) % 4;
        const padded = base64.padEnd(base64.length + padLength, '=');

        // Convert to a binary string
        const binary = atob(padded);

        // Convert binary string to buffer
        const buffer = new ArrayBuffer(binary.length);
        const bytes = new Uint8Array(buffer);

        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }

        return buffer;
    }

    function bufferToBase64URLString(buffer) {
        const bytes = new Uint8Array(buffer);
        let str = '';

        for (const charCode of bytes) {
            str += String.fromCharCode(charCode);
        }

        const base64String = btoa(str);

        return base64String.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }

    function bufferToUTF8String(value) {
        return new TextDecoder('utf-8').decode(value);
    }


    const base64urlEncode = (array) => {
        let arrayBuf = array
        if (typeof array === "object") {
            arrayBuf = ArrayBuffer.isView(array) ? array : new Uint8Array(array);
        }

        const binString = Array.from(arrayBuf, (x) => String.fromCodePoint(x)).join("");
        return btoa(binString).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
    };

    function handleForm(jsonData) {
        const pkInput = document.getElementById("passkeys");
        if (!pkInput) {
            console.error("Did you add the 'passkeys' hidden input field");
            return
        }


        pkInput.value = JSON.stringify(jsonData);
        let form = document.getElementById("login-form");
        form.action = window.passkeysConfig.urls.login.passkey;
        if (form === null || form === undefined) {
            console.error("Did you pass the correct form id 'login-form' to auth function");
            return;
        }
        form.submit()
    }

    const makeCredReq = (creds) => {
        creds.publicKey.challenge = base64URLStringToBuffer(creds.publicKey.challenge);
        creds.publicKey.user.id = base64URLStringToBuffer(creds.publicKey.user.id);
        for (const excludeCred of creds.publicKey.excludeCredentials) {
            excludeCred.id = base64URLStringToBuffer(excludeCred.id);
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

    function toPublicKeyCredentialDescriptor(descriptor) {
        const { id } = descriptor;

        return {
            ...descriptor,
            id: base64URLStringToBuffer(id),
            transports: descriptor.transports,
        };
    }

    function startAuthentication(requestOptionsJSON) {
        // We need to avoid passing empty array to avoid blocking retrieval
        // of public key
        let allowCredentials;
        if (requestOptionsJSON.allowCredentials && requestOptionsJSON.allowCredentials.length !== 0) {
            allowCredentials = requestOptionsJSON.allowCredentials.map(toPublicKeyCredentialDescriptor);
        }

        // We need to convert some values to Uint8Arrays before passing the credentials to the navigator
        const publicKey = {
            ...requestOptionsJSON,
            challenge: base64URLStringToBuffer(requestOptionsJSON.challenge),
            allowCredentials,
        };

        // Prepare options for `.get()`
        const options = {
            publicKey,
        };

        // Wait for the user to complete assertion
        navigator.credentials.get(options)
            .then(credential => {
                if (!credential) {
                    throw new Error('Authentication was not completed');
                }
                const { id, rawId, response, type } = credential;

                let userHandle = undefined;
                if (response.userHandle) {
                    userHandle = bufferToUTF8String(response.userHandle);
                }
                let attachmentOptions = ["platform", "cross-platform"];
                let attachment = response.authenticatorAttachment;
                handleForm({
                    id,
                    rawId: bufferToBase64URLString(rawId),
                    response: {
                        authenticatorData: bufferToBase64URLString(response.authenticatorData),
                        clientDataJSON: bufferToBase64URLString(response.clientDataJSON),
                        signature: bufferToBase64URLString(response.signature),
                        userHandle,
                    },
                    type,
                    clientExtensionResults: credential.getClientExtensionResults(),
                    authenticatorAttachment: attachment && attachmentOptions.indexOf(attachment) != -1 ? attachment : undefined,
                })
            })
            .catch(error => {
                console.error("Error occurred during authentication:", error);
            });
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
                const { id, rawId, response, type } = attestation;
                attestation["key_name"] = document.querySelector("#key_name").value;
                let transports;
                if (typeof response.getTransports === "function") {
                    transports = response.getTransports();
                }
                let responsePublicKeyAlgorithm;
                if (typeof response.getPublicKeyAlgorithm === "function") {
                    responsePublicKeyAlgorithm = response.getPublicKeyAlgorithm();
                }
                let responsePublicKey;
                if (typeof response.getPublicKey === "function") {
                    responsePublicKey = bufferToBase64URLString(response.getPublicKey());
                }
                let authenticatorData;
                if (typeof response.getAuthenticatorData === "function") {
                    try {
                        authenticatorData = bufferToBase64URLString(response.getAuthenticatorData());
                    } catch (error) {
                    }
                }

                let attachmentOptions = ["platform", "cross-platform"];
                let attachment = attestation.authenticatorAttachment;
                const res = {
                    id,
                    rawId: bufferToBase64URLString(rawId),
                    response: {
                        attestationObject: bufferToBase64URLString(response.attestationObject),
                        clientDataJSON: bufferToBase64URLString(response.clientDataJSON),
                        transports,
                        publicKeyAlgorithm: responsePublicKeyAlgorithm,
                        publicKey: responsePublicKey,
                        authenticatorData: authenticatorData,
                    },
                    type,
                    clientExtensionResults: attestation.getClientExtensionResults(),
                    authenticatorAttachment: attachment && attachmentOptions.indexOf(attachment) != -1 ? attachment : undefined,
                }
                return fetch(window.passkeysConfig.urls.regComplete, {
                    method: 'POST',
                    body: JSON.stringify(res)
                });
            })
            .then(response => {
                return response.json();
            })
            .then(res => {
                if (res["status"] == 'OK') {
                    window.location.href = window.passkeysConfig.urls.home;
                } else {
                    document.querySelector("#res").insertAdjacentHTML("afterbegin", "<div class='alert alert-danger'>Registration Failed as " + res + ", <a href='javascript:void(0)' onclick='djangoPasskey.beginReg()'> try again </a> </div>");
                }
            })
            .catch(reason => {
                document.querySelector("#res").insertAdjacentHTML("afterbegin", "<div class='alert alert-danger'>catch: Registration Failed as " + reason + ", <a href='javascript:void(0)' onclick='djangoPasskey.beginReg()'> try again </a> </div>");
            });
    };

    function deleteKey(id) {
        fetch(window.passkeysConfig.urls.delKey, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCookie('csrftoken'),
            },
            body: JSON.stringify({ id: id })
        })
            .then(response => response.text())
            .then(data => {
                alert(data);
                window.location.href = window.passkeysConfig.urls.home;
            })
            .catch(error => {
                console.error('Error confirming deletion:', error);
            });
    }


    function toggleKey(id) {
        fetch(window.passkeysConfig.urls.toggle, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCookie('csrftoken'),
            },
            body: JSON.stringify({ id: id })
        }).catch(error => {
            console.error('Error confirming deletion:', error);
        });
    }


    function initialize() {
        getServerCredentials()
            .then(data => {
                startAuthentication(data.publicKey);
            })
            .catch(error => {
                console.error('Error during login:', error);
            });
    }



    window.djangoPasskey = {
        deleteKey: deleteKey,
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
                document.querySelectorAll("[type='submit]'").forEach(button => {
                    if (button.dataset.passkeyValue == "passkey") {
                        button.style.display = "none";
                    }
                })
            }
        });
    }
}


displayPasskeyOption();
const form = document.getElementById("login-form");
const inputs = document.querySelectorAll(".otp-field input");

function handleOTPLogin() {
    inputs.forEach((input, index) => {
        input.dataset.index = index;
        input.addEventListener("keyup", handleOtp);
        input.addEventListener("paste", handleOnPasteOtp);
        input.addEventListener("focus", e => {
        })
    });
}

function handleOtp(e) {
    /**
     * <input type="text" 👉 maxlength="1" />
     * 👉 NOTE: On mobile devices `maxlength` property isn't supported,
     * So we to write our own logic to make it work. 🙂
     */
    const input = e.target;
    let value = input.value;
    let isValidInput = value.match(/[0-9a-z]/gi);
    input.value = "";
    input.value = isValidInput ? value[0] : "";
    let fieldIndex = input.dataset.index;
    if (fieldIndex < inputs.length - 1 && isValidInput) {
        input.nextElementSibling.focus();
    }
    if (e.key === "Backspace" || e.key === "Delete" && fieldIndex > 0) {
        input.previousElementSibling.focus();
    }
    if (fieldIndex == inputs.length - 1 && isValidInput) {
        addValueToForm();
    }
}
function handleOnPasteOtp(e) {
    const data = e.clipboardData.getData("text");
    const value = data.split("");
    if (value.length === inputs.length) {
        inputs.forEach((input, index) => (input.value = value[index]));
        addValueToForm();
    }
}
function addValueToForm() {
    // 👇 Entered OTP
    let otp = "";
    inputs.forEach((input) => {
        otp += input.value;
        input.disabled = true;
        input.classList.add("disabled");
    });
    if (otp.length === 6) {
        form.querySelector("#id_otp").value = otp;
        form.submit()
    }
}

handleOTPLogin();

document.addEventListener("submit", e => {
    if (e.target.id == "passkeys-registration-form") {
        e.preventDefault();
    }
})

function getCookie(name) {
    let cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        const cookies = document.cookie.split(';');
        for (let i = 0; i < cookies.length; i++) {
            const cookie = cookies[i].trim();
            // Does this cookie string begin with the name we want?
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}



