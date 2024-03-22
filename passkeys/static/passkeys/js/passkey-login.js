import element, { getInternals } from "https://stephen.band/dom/modules/element.js";
import { getServerCredentials, startAuthn, getAssertReq, credToJSON, assertFunc } from "./script.js"
function checkSecureConnection() {
    if (window.location.protocol != 'https:') {
        console.error("Passkeys must work under secure context");
    }
    return window.location.protocol == 'https:';
}

function initialize(submitButtons, form, passkeyInput) {
    submitButtons.forEach(button => {
        button.disabled = true;
    });
    getServerCredentials()
        .then(data => {
            startAuthn(getAssertReq(credToJSON(data))).then(assertion => {
                assertFunc(assertion, form, passkeyInput)
            })
        })
        .catch(error => {
            submitButtons.forEach(button => {
                button.disabled = false;
            })
            console.error('Error during login:', error);
        });
}

export default element(
    "passkey-login", {
    shadow: `
    <form class="login-form" id="login-form" method="post" action="." data-bitwarden-watching="1">
        <input type="hidden" name="csrfmiddlewaretoken" value="">
        <div class="form-row">
        </div>
        <div class="form-row">
            <label for="id_email">Your email adress:</label> <protonpass-root-da79 data-protonpass-role="icon"></protonpass-root-da79><input type="email" name="email" value="halit@cruncher.ch" autofocus="" autocomplete="username webauthn" maxlength="320" required="" id="id_email" style="padding-right: 35.3333px !important;" data-protonpass-base-css="{&quot;padding-right&quot;:&quot;&quot;}">
        </div>
        <div class="form-row"> 
            <label for="id_password">Password:</label> <input type="password" name="password" id="id_password">
            <input type="hidden" name="next" value="/passkeys/">
        </div>
        <div class="submit-row">
            <input type="submit" value="Log in">
            <input id="passkeys" type="hidden" name="passkeys">
            <input type="submit" data-passkey-value="passkey" value="Login with passkey">
            <input type="submit" data-passkey-value="otp" value="Receive email code">
            <input type="hidden" value="" name="type">
        </div>
    </form>
    `,
    construct: function (shadow, internals) {
        /* Find all the elements */
        const form = shadow.querySelector("#login-form");
        const submitButtons = shadow.querySelectorAll("input[type='submit']");
        const passkeyInput = shadow.querySelector("#passkeys");

        /* Prevend default submission and modify action attribute */
        form.addEventListener("click", e => {
            let element = e.target;
            if (element.dataset.passkeyValue && element.dataset.passkeyValue) {
                e.preventDefault();
                let form = element.closest("form");
                form.querySelector("#id_password").required = false;
                form.querySelector("input[name='type']").value = element.dataset.passkeyValue;
                form.action = passkeysConfig.urls.login[element.dataset.passkeyValue];
                form.submit();
            }
        })
        /* Initialize passkey */
        if (checkSecureConnection()) {
            initialize(submitButtons, form, passkeyInput);
        }
    },
    connect: function (shadow, internals) {
        console.log("CONNECT", this, shadow, internals)
        const csrfInput = shadow.querySelector('[name="csrfmiddlewaretoken"]');
        csrfInput.value = internals.csrftoken;
        internals.styleurls.split(" ").forEach(url => {
            const linkElem = document.createElement("link");
            linkElem.setAttribute("rel", "stylesheet");
            linkElem.setAttribute("href", url);
            shadow.appendChild(linkElem);
        })

    }

}, {
    crossplatform: {
        attribute: function (value) {
            const internals = getInternals(this);
            internals.crossplatform = parseInt(value);
        }
    },
    loginurl: {
        attribute: function (url) {
            const internals = getInternals(this);
            internals.loginurl = url;
        }
    },
    homeurl: {
        attribute: function (url) {
            const internals = getInternals(this);
            internals.homeurl = url;
        }
    },
    authbeginurl: {
        attribute: function (url) {
            const internals = getInternals(this);
            internals.authbeginurl = url;
        }
    },
    regbeginurl: {
        attribute: function (url) {
            const internals = getInternals(this);
            internals.regbeginurl = url;
        }
    },
    regcompleteurl: {
        attribute: function (url) {
            const internals = getInternals(this);
            internals.regcompleteurl = url;
        }
    },
    delkeyurl: {
        attribute: function (url) {
            const internals = getInternals(this);
            internals.delkeyurl = url;
        }
    },
    toggleurl: {
        attribute: function (url) {
            const internals = getInternals(this);
            internals.toggleurl = url;
        }
    },
    passkeyloginurl: {
        attribute: function (url) {
            const internals = getInternals(this);
            internals.passkeyloginurl = url;
        }
    },
    otploginurl: {
        attribute: function (url) {
            const internals = getInternals(this);
            internals.otploginurl = url;
        }
    },
    csrf: {
        attribute: function (csrftoken) {
            const internals = getInternals(this);
            internals.csrftoken = csrftoken;
        }
    },
    styleurls: {
        attribute: function (styles) {
            const internals = getInternals(this);
            internals.styleurls = styles;
        }
    }
});

