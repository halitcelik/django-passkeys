(function () {
    'use strict';

    let chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

    // Use a lookup table to find the index.
    let lookup = new Uint8Array(256);
    for (let i = 0; i < chars.length; i++) {
        lookup[chars.charCodeAt(i)] = i;
    }

    let encode = function (arraybuffer) {
        let bytes = new Uint8Array(arraybuffer),
            i, len = bytes.length, base64url = '';

        for (i = 0; i < len; i += 3) {
            base64url += chars[bytes[i] >> 2];
            base64url += chars[((bytes[i] & 3) << 4) | (bytes[i + 1] >> 4)];
            base64url += chars[((bytes[i + 1] & 15) << 2) | (bytes[i + 2] >> 6)];
            base64url += chars[bytes[i + 2] & 63];
        }

        if ((len % 3) === 2) {
            base64url = base64url.substring(0, base64url.length - 1);
        } else if (len % 3 === 1) {
            base64url = base64url.substring(0, base64url.length - 2);
        }

        return base64url;
    };

    let decode = function (base64string) {
        let bufferLength = base64string.length * 0.75,
            len = base64string.length, i, p = 0,
            encoded1, encoded2, encoded3, encoded4;

        let bytes = new Uint8Array(bufferLength);

        for (i = 0; i < len; i += 4) {
            encoded1 = lookup[base64string.charCodeAt(i)];
            encoded2 = lookup[base64string.charCodeAt(i + 1)];
            encoded3 = lookup[base64string.charCodeAt(i + 2)];
            encoded4 = lookup[base64string.charCodeAt(i + 3)];

            bytes[p++] = (encoded1 << 2) | (encoded2 >> 4);
            bytes[p++] = ((encoded2 & 15) << 4) | (encoded3 >> 2);
            bytes[p++] = ((encoded3 & 3) << 6) | (encoded4 & 63);
        }

        return bytes.buffer
    };

    let methods = {
        'decode': decode,
        'encode': encode
    }

    /**
     * Exporting and stuff
     */
    if (typeof module !== 'undefined' && typeof module.exports !== 'undefined') {
        module.exports = methods;

    } else {
        if (typeof define === 'function' && define.amd) {
            define([], function () {
                return methods
            });
        } else {
            window.base64url = methods;
        }
    }
})();
var publicKeyCredentialToJSON = (pubKeyCred) => {
    if (pubKeyCred instanceof Array) {
        let arr = [];
        for (let i of pubKeyCred)
            arr.push(publicKeyCredentialToJSON(i));

        return arr
    }

    if (pubKeyCred instanceof ArrayBuffer) {
        return base64url.encode(pubKeyCred)
    }

    if (pubKeyCred instanceof Object) {
        let obj = {};

        for (let key in pubKeyCred) {
            obj[key] = publicKeyCredentialToJSON(pubKeyCred[key])
        }

        return obj
    }

    return pubKeyCred
}

window.conditionalUI = false;
window.conditionUIAbortController = new AbortController();
window.conditionUIAbortSignal = conditionUIAbortController.signal;
function checkConditionalUI(form) {
    if (window.PublicKeyCredential && PublicKeyCredential.isConditionalMediationAvailable) {
        // Check if conditional mediation is available.
        PublicKeyCredential.isConditionalMediationAvailable().then((result) => {
            window.conditionalUI = result;
            if (window.conditionalUI) {
                start_authn(form, true)
            }
        });
    }
}

var GetAssertReq = (getAssert) => {
    getAssert.publicKey.challenge = base64url.decode(getAssert.publicKey.challenge);

    for (let allowCred of getAssert.publicKey.allowCredentials) {
        allowCred.id = base64url.decode(allowCred.id);
    }

    return getAssert
}

function start_authn(form, conditionalUI = false) {
    window.loginForm = form;
    fetch(window.passkeysConfig.urls.authBegin, {
        method: 'GET',
    }).then(function (response) {
        if (response.ok) {
            return response.json().then(function (req) {
                return GetAssertReq(req)
            });
        }
        throw new Error('No credential available to authenticate!');
    }).then(function (options) {
        if (conditionalUI) {
            options.mediation = 'conditional';
            options.signal = window.conditionUIAbortSignal;
        }
        else
            window.conditionUIAbortController.abort()
        console.log(options)
        return navigator.credentials.get(options);
    }).then(function (assertion) {
        pk = $("#passkeys")
        if (pk.length == 0) {
            console.error("Did you add the 'passkeys' hidden input field")
            return
        }
        pk.val(JSON.stringify(publicKeyCredentialToJSON(assertion)));
        x = document.getElementById(window.loginForm)
        if (x === null || x === undefined) {
            console.error("Did you pass the correct form id to auth function")
            return;
        }
        x.submit()

    });
    $(document).ready(function () {
        if (location.protocol != 'https:') {
            console.error("Passkeys must work under secure context")
        }
    });
}
function authn(form) {
    start_authn(form, false)
}


function check_passkey(platform_authenticator = true, success_func, fail_func) {
    if (window.passkeysConfig.crossPlatform) {
        if (platform_authenticator) {
            PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
                .then((available) => {
                    if (available) {
                        success_func();
                    }
                    else {
                        fail_func();
                    }
                })
        }
        success_func();
    }
}

function check_passkeys(success_func, fail_func) {
    PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
        .then((available) => {
            if (available) {
                success_func();
            } else {
                fail_func()
            }
        }).catch((err) => {
            // Something went wrong
            console.error(err);
        });
}

var MakeCredReq = (makeCredReq) => {
    makeCredReq.publicKey.challenge = base64url.decode(makeCredReq.publicKey.challenge);
    makeCredReq.publicKey.user.id = base64url.decode(makeCredReq.publicKey.user.id);

    for (let excludeCred of makeCredReq.publicKey.excludeCredentials) {
        excludeCred.id = base64url.decode(excludeCred.id);
    }

    return makeCredReq
}
function beginReg() {
    fetch(window.passkeysConfig.urls.authBegin, {}).then(function (response) {
        if (response.ok) {
            return response.json().then(function (req) {
                return MakeCredReq(req)
            });
        }
        throw new Error('Error getting registration data!');
    }).then(function (options) {

        //options.publicKey.attestation="direct"
        console.log(options)

        return navigator.credentials.create(options);
    }).then(function (attestation) {
        attestation["key_name"] = $("#key_name").val();
        return fetch(window.passkeysConfig.urls.regComplete, {
            method: 'POST',
            body: JSON.stringify(publicKeyCredentialToJSON(attestation))
        });
    }).then(function (response) {

        var stat = response.ok ? 'successful' : 'unsuccessful';
        return response.json()
    }).then(function (res) {
        if (res["status"] == 'OK')
            $("#res").html(`<div class='alert alert-success'>Registered Successfully, <a href='${window.passkeysConfig.homeURL}'> Refresh</a></div>`)
        else
            $("#res").html("<div class='alert alert-danger'>Registration Failed as " + res["message"] + ", <a href='javascript:void(0)' onclick='beginReg()'> try again </a> </div>")


    }, function (reason) {
        $("#res").html("<div class='alert alert-danger'>Registration Failed as " + reason + ", <a href='javascript:void(0)' onclick='beginReg()'> try again </a> </div>")
    })
}




function confirmDel(id) {
    $.ajax({
        url: window.passkeysConfig.urls.delKey,
        data: { "id": id },
        success: function (data) {
            alert(data)
            window.location = window.passkeysConfig.urls.home;
        }
    })
}

function start() {
    $("#modal-title").html("Enter a token name")
    $("#modal-body").html(`<p>Please enter a name for your new token</p>
                            <input type="text" placeholder="e.g Laptop, PC" id="key_name" class="form-control"/><br/>
                            <div id="res"></div>
                            `)
    $("#actionBtn").remove();
    $("#modal-footer").prepend(`<button id='actionBtn' class='btn btn-success' onclick="beginReg()">Start</button>`)
    $("#popUpModal").show();
}
function deleteKey(id, name) {
    $("#modal-title").html("Confirm Delete")
    $("#modal-body").html("Are you sure you want to delete '" + name + "'? you may lose access to your system if this your only 2FA.");
    $("#actionBtn").remove()
    $("#modal-footer").prepend("<button id='actionBtn' class='btn btn-danger' onclick='confirmDel(" + id + ")'>Confirm Deletion</button>")
    $("#popUpModal").modal('show')
}

function toggleKey(id) {
    $.ajax({
        url: `${window.passkeysConfig.urls.toggle}?id=${id}`,
        success: function (data) {
            if (data == "Error")
                $("#toggle_" + id).toggle()

        },
        error: function (data) {
            $("#toggle_" + id).toggle()
        }
    })
}

if (window.passkeysConfig.enroll) {
    $(document).ready(start)
}