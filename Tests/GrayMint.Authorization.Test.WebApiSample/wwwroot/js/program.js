function main() {
    setInterval(tryLogin, 15000);

    google.accounts.id.initialize({
        client_id: '637321499771-gioemfem1ngm8i027cf9nj03l9nj2n0l.apps.googleusercontent.com',
        callback: handleCredentialResponse,
        login_uri: "https://localhost:7118/api/v1/authentication/external/google/signin-handler",
        ux_mode: "popup",
        auto_select: true,
        nonce: "11111111111111111"
    });

    google.accounts.id.prompt((notification) => {
        if (notification.isNotDisplayed() || notification.isSkippedMoment()) {
            // continue with another identity provider.
        }
    });

    const parent = document.getElementById('google_btn');
    google.accounts.id.renderButton(parent, { theme: "filled_blue" });
}

function tryLogin() {
    google.accounts.id.prompt((notification) => {
        console.log(notification);
        if (notification.isNotDisplayed() || notification.isSkippedMoment()) {
            // continue with another identity provider.
            console.log("continue with another identity provider");
        }
    }, 10000);
}

async function handleCredentialResponse(googleUser) {
    if (!googleUser || !googleUser.credential)
        return;

    let apiKey = null;
    try {
        apiKey = await signIn(googleUser.credential);
    }
    catch(e)
    {
        if (e.TypeName == "UnregisteredUser")
            apiKey = await signUp(googleUser.credential);
    }

    console.log(apiKey);
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