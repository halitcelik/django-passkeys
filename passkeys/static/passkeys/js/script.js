(function () {
    // Define base64url encoding and decoding functions
    const base64urlEncode = (bytes) => {
        const arrayBuf = ArrayBuffer.isView(bytes) ? bytes : new Uint8Array(bytes);
        const binString = Array.from(arrayBuf, (x) => String.fromCodePoint(x)).join("");
        return btoa(binString).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
    };

    const base64urlDecode = (base64) => {
        const padding = "====".substring(base64.length % 4);
        const binString = atob(base64.replaceAll("-", "+").replaceAll("_", "/") + (padding.length < 4 ? padding : ""));
        return Uint8Array.from(binString, (m) => m.codePointAt(0));
    };

    // Define function to convert credentials to JSON
    const credToJSON = (pubKeyCred) => {
        if (pubKeyCred instanceof Array) {
            return pubKeyCred.map(credToJSON);
        }
        if (pubKeyCred instanceof ArrayBuffer) {
            return base64urlDecode(pubKeyCred);
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

    // Define function to initiate authentication process
    const startAuthn = (form, conditionalUI = false) => {
        fetch(window.passkeysConfig.urls.authBegin, {
            method: 'GET',
        })
        .then(response => {
            if (response.ok) {
                return response.json().then(getAssertReq);
            }
            throw new Error('No credential available to authenticate!');
        })
        .then(options => {
            if (conditionalUI) {
                options.mediation = 'conditional';
                options.signal = window.conditionUIAbortSignal;
            } else {
                window.conditionUIAbortController.abort();
            }
            return navigator.credentials.get(options);
        })
        .then(assertion => {
            const pk = document.querySelector("#passkeys");
            if (!pk) {
                console.error("Did you add the 'passkeys' hidden input field?");
                return;
            }
            pk.value = JSON.stringify(credToJSON(assertion));
            console.log(pk.value);
            const formElement = document.getElementById(form);
            if (!formElement) {
                console.error("Did you pass the correct form id to auth function?");
                return;
            }
            formElement.submit();
        });
        document.addEventListener("DOMContentLoaded", () => {
            if (window.location.protocol != 'https:') {
                console.error("Passkeys must work under secure context");
            }
        });
    };

    // Define function to initiate registration process
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

    // Function to confirm deletion
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

    // Function to start registration process
    function startRegistration() {
        const modalTitle = document.querySelector("#modal-title");
        const modalBody = document.querySelector("#modal-body");
        const actionBtn = document.querySelector("#actionBtn");

        modalTitle.innerHTML = "Enter a token name";
        modalBody.innerHTML = `<p>Please enter a name for your new token</p>
                                <input type="text" placeholder="e.g Laptop, PC" id="key_name" class="form-control"/><br/>
                                <div id="res"></div>`;
        actionBtn.remove();
        const modalFooter = document.querySelector("#modal-footer");
        modalFooter.insertAdjacentHTML('afterbegin', `<button id='actionBtn' class='btn btn-success' onclick="djangoPasskey.beginReg()">Start</button>`);
        document.querySelector("#popUpModal").style.display = "block";
    }


    // Export functions
    const methods = {
        base64urldecode: base64urldecode,
        base64urlencode: base64urlencode,
        credToJson: credToJSON,
        getAssertReq: getAssertReq,
        startAuthn: startAuthn,
        makeCredReq: makeCredReq,
        beginReg: beginReg,
        startRegistration: startRegistration,
        confirmDel: confirmDel,
    };

    // Add methods to djangoPasskey object
    Object.assign(window.djangoPasskey, methods);

    // Initialize conditional UI variables
    window.conditionalUI = false;
    window.conditionUIAbortController = new AbortController();
    window.conditionUIAbortSignal = window.conditionUIAbortController.signal;

})();

// Function to initiate authentication
function authn(formId) {
    djangoPasskey.startAuthn(formId, false);
}
