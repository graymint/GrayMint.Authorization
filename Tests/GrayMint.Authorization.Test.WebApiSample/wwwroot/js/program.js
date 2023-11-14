function main() {
    setInterval(tryLogin, 15000);

    google.accounts.id.initialize({
        client_id: '993024855233-n5svhn1is1dtrmskmjjtsg37upjcpp60.apps.googleusercontent.com',
        callback: handleCredentialResponse,
        ux_mode: "popup",
        auto_select: true,
    });

    tryLogin();

    const parent = document.getElementById('gsi-google-btn');
    google.accounts.id.renderButton(parent, { theme: "filled_blue" });
}

async function handleCredentialResponse(googleUser) {
    if (!googleUser || !googleUser.credential)
        return;

    console.log("GoogleUser", googleUser);

    let apiKey = null;
    try {
        apiKey = await signIn(googleUser.credential);
    }
    catch (ex) {
        if (ex.TypeName == "UnregisteredUserException")
            apiKey = await signUp(googleUser.credential);
    }

    console.log("GrayMintApiKey", apiKey);
}

function tryLogin() {
    google.accounts.id.prompt((notification) => {
        if (notification.isNotDisplayed() || notification.isSkippedMoment())
            console.log("continue with another identity provider", notification);
        else
            console.log("success", notification);

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