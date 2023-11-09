function main() {
    setInterval(tryLogin, 15000);

    google.accounts.id.initialize({
        client_id: '637321499771-gioemfem1ngm8i027cf9nj03l9nj2n0l.apps.googleusercontent.com',
        callback: handleCredentialResponse,
        ux_mode: "popup",
        auto_select: true,
        nonce: "11111111111111111"
    });
    tryLogin();

    const parent = document.getElementById('gsi-google-btn');
    google.accounts.id.renderButton(parent, { theme: "filled_blue" });
}

async function handleCredentialResponse(googleUser) {
    if (!googleUser || !googleUser.credential)
        return;

    console.log(googleUser);

    let apiKey = null;
    try {
        apiKey = await signIn(googleUser.credential);
    }
    catch (ex) {
        if (ex.TypeName == "UnregisteredUser")
            apiKey = await signUp(googleUser.credential);
    }

    console.log(apiKey);
}

function tryLogin() {
    google.accounts.id.prompt((notification) => {
        if (notification.isNotDisplayed() || notification.isSkippedMoment()) {
            // continue with another identity provider.
            console.log("continue with another identity provider", notification);
        }
        else
            console.log("success", notification);

        console.log("xxx", notification.getDismissedReason());
    });
}

async function signIn(idToken) {
    // get new access key
    const response = await fetch('https://localhost:7118/api/v1/authentication/signin', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            idToken
        })
    });

    if (response.status != 200)
        throw await response.json();

    return await response.json();
 }

async function signUp(idToken) {
    // get new access key
    const response = await fetch('https://localhost:7118/api/v1/authentication/signup', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            idToken
        })
    });

    if (response.status != 200)
        throw await response.json();

    return await response.json();
}