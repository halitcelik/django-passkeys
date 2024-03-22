
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

export function assertFunc(assertion, form, pkInput) {
    if (assertion.rawId) {
        assertion.rawId = arrayToBuffer(assertion.rawId);
    }
    for (let key in assertion.response) {
        /* Careful about null values. On PC worked fine but on the android got null value */
        if (!Object.is(assertion.response[key], null)) {
            assertion.response[key] = arrayToBuffer(assertion.response[key])
        }
    }

    pkInput.value = JSON.stringify(credToJSON(assertion));
    form.action = window.passkeysConfig.urls.login.passkey;
    form.submit()
}

export const credToJSON = (pubKeyCred) => {
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

export const getAssertReq = (getAssert) => {
    console.log(getAssert)
    getAssert.publicKey.challenge = base64urlDecode(getAssert.publicKey.challenge);
    for (const allowCred of getAssert.publicKey.allowCredentials) {
        allowCred.id = base64urlDecode(allowCred.id);
    }
    return getAssert;
};

export const makeCredReq = (creds) => {
    creds.publicKey.challenge = base64urlDecode(creds.publicKey.challenge);
    creds.publicKey.user.id = base64urlDecode(creds.publicKey.user.id);
    for (const excludeCred of creds.publicKey.excludeCredentials) {
        excludeCred.id = base64urlDecode(excludeCred.id);
    }
    return creds;
};
export function getServerCredentials() {
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
export function startAuthn(options, conditionalUI) {
    if (conditionalUI) {
        options.mediation = 'conditional';
        options.signal = window.conditionUIAbortSignal;
    }
    else
        window.conditionUIAbortController.abort()
    console.log(options)
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
                window.location.href = window.passkeysConfig.urls.home;
            } else {
                document.querySelector("#res").insertAdjacentHTML("afterbegin", "<div class='alert alert-danger'>Registration Failed as " + res + ", <a href='javascript:void(0)' onclick='djangoPasskey.beginReg()'> try again </a> </div>");
            }
        })
        .catch(reason => {
            document.querySelector("#res").insertAdjacentHTML("afterbegin", "<div class='alert alert-danger'>Registration Failed as " + reason + ", <a href='javascript:void(0)' onclick='djangoPasskey.beginReg()'> try again </a> </div>");
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



window.djangoPasskey = {
    deleteKey: deleteKey,
    toggleKey: toggleKey,
    beginReg: beginReg,
};


window.conditionalUI = false;
window.conditionUIAbortController = new AbortController();
window.conditionUIAbortSignal = window.conditionUIAbortController.signal;

// Function to initiate authentication
function authn(formId) {
    startAuthn(formId, false);
}

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
            console.log("focused ", e)
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
    console.log("Submitting...");
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