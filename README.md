# HEIG_SLH_Labo2

**Date: **06.01.2024

**Author: ** Timothée Van Hove

![](figures/title.png)



## Introduction

The goal of this lab is to manage the authentication of a simple website. The authentication is managed with JWT access and refresh tokens. The only functionalities of the website are to register, login, and change password.



## Question1

> *What is the purpose of a JWT access token? And what is the purpose of a JWT refresh token? Why do we have both?*



In a typical web application, our objectives are:

1. **Seamless User Experience**: We aim to keep users logged in for as long as possible without interruptions. Think of how you stay logged in on platforms like LinkedIn or Google Drive for months at a stretch.
2. **Robust Security**: While ensuring user convenience, we must not compromise on security.

Starting with the first goal, let's consider **persistent login**. When a user registers or logs in on our web app, our server responds with an **access token**. To facilitate a long-lasting session, we could set this token's expiry to, say, one year. Each time the user performs actions requiring authentication, this token is sent with the request.

This approach nails our first goal. But what about security? If an attacker gets hijack this access token, they can impersonate the user for a long duration. we have a huge security problem! 

The solution? Short-lived access tokens. Ideally, these should expire quickly – In our application, 10 minutes. An attacker hijacking a short-lived token is less problematic, as their window of opportunity is short. But, if the user's access expires every 10 minutes and they have to login again, the UX is ugly.

Enter refresh tokens. When a user logs in, they receive two tokens: a short-lived access token and a long-lived refresh token. The refresh token doesn't grant access directly but can be used to obtain a new access token. As an access token nears expiry, our web app silently requests a new one using the refresh token, keeping the user experience smooth and uninterrupted.

By combining short-lived access tokens with securely managed refresh tokens, we strike a balance between user convenience and robust security, ensuring our web application remains both user-friendly and secure.

#### But what if someone hijacks the refresh token?

While less likely, it's still a risk, particularly in less secure environments like browser-based applications. To mitigate this, we could implement a strategy known [as refresh token rotation](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps-05#section-8), recommended by the Internet Engineering Task Force. **This rotation is not implemented** in our web app, but here is how it would work:

- Each time a user logs in, new access and refresh tokens are generated and sent to the client. The new refresh token replaces the old one in the database.
- Each refresh token can be used only once. If a token is reused (indicating potential theft), the server immediately locks the user's account and alerts the support team.
- If an attacker uses the stolen refresh token before the legitimate user, the subsequent legitimate refresh attempt fails, triggering account lockout and alerting us to the breach.

This method would ensures that even if a refresh token is compromised, the damage is contained, and we're alerted to the breach promptly. Users can then re-authenticate after we've addressed any security concerns.



## Question 2

> *Where are the access token stored? Where are the refresh token stored ?*

#### Access tokens

Stored in the client's browser (cookie) and sent with each request that requires authentication.

#### Refresh tokens

Stored on the client side in the local storage. The local storage is a web storage object that allows JavaScript sites and apps to store right in the browser with no expiration date. This means the data stored in the browser will persist even after the browser window is closed.



## Question 3

> *Is it a good idea to store them there? Is there a better solution?*

#### Access tokens

Yes, it is a good idea to store access tokens in a cookie and are automatically sent with every request to the same domain,  which is easy for maintaining a session. They are configured as **HttpOnly**, preventing JavaScript access and mitigating the risk of XSS attacks, and use the **SameSite** attribute to prevent them from being sent in cross-site requests. In addition with the usage of anti-CSRF tokens, it mitigates CSRF attacks.

#### Refresh tokens

No, it is not a good idea to store the refresh tokens on the client side. While, it is easier to use and persist across browser sessions, it is vulnerable to XSS attacks. If a script can inject malicious code into our application, it can steal tokens from local storage. We should store the refresh tokens in the database (server-side) and implement the refresh token rotation strategy as mentioned in the [Question 1](####But-what-if-someone-hijacks-the-refresh-token?).



## modifications to the code base

I have deliberately modified the given code base to fix certain bugs or to enhance the UX.



#### DB not saved after a user password change

In the given code base, the new password is never saved in the mocked database. I don't know if it was a deliberate implementation choice, but if we want to fix this behavior, we have to modify the `change_password` function:

```rust
pub fn change_password(email: &str, new_hash: &str) -> Result<bool> {
	info!("Change password of user");
	let mut db = DB.write().or(Err(anyhow!("DB poisoned")))?;

	let user = match db.get_mut(email) {
		None => {
			trace!("User not found");
			return Ok(false)
		},
		Some(u) => u,
	};

	user.hash = new_hash.to_string();

	trace!("Password changed");

	save(db).ok(); // Add this line
	Ok(true)
}
```



#### Error message not cleared when the password change succeeds

In the index.hbs template, when the password change succeeds, the pervious errors are not reset. To do this we just have to set the text of the error message to an empty string:

```javascript
function change_password(e) {
	e.preventDefault()
	$.postJSON(
		"/change-password",
		{
			old_password: $('#old_password').val(),
			password: $('#new_password').val(),
			password2: $('#confirmation').val(),
			csrf: $('#csrf').val(),
		},
		() => {
			$('#pwd_error').text('') // Add this line
			$('#pwd_success').text('Password changed, you will be logged out in 5s')
			clearInterval(checker)
			localStorage.clear()
			$.get("/logout", () => {}, () => {}, false)
			setTimeout(() => window.location.href = '/login', 5000)
		},
		data => {
			$('#pwd_error').text(data.responseText)
		}
	)
}
```



#### Adding password strength indicator

I modified the index.hbs and login.hbs files to display a password strength indicator to the user using `zxcvbn`. I added the exact same function in both template files because I couldn't find how to configure **Static File Serving** in router.rs with `Axum`.

HTML: I added a progress bar and a text field

````html
<!-- Password strength progress bar -->
<div id="password-strength-bar" class="progress mt-2" style="height: 8px;">
	<div class="progress-bar" role="progressbar" style="width: 0" aria-valuenow="0" aria-valuemin="0" aria-valuemax="100"></div>
</div>

<!-- Password strength text -->
<div id="password-strength-text" class="mt-2" style="margin-bottom: 24px">Password strength:</div>
````



JS: I added the `updatePasswordStrength()` function 

````javascript
function updatePasswordStrength(password) {
    let strength = zxcvbn(password);
    let hint = strength.feedback.warning;
    let strengthValue = 20 + strength.score * 20;

    // Update progress bar
    let progressBar = $('#password-strength-bar .progress-bar');
    progressBar.css('width', strengthValue + '%');

    progressBar.removeClass('bg-danger bg-warning bg-info bg-success');

    // Update strength text based on the score
    let strengthText = $('#password-strength-text');
    switch(strength.score) {
        case 0:
            strengthText.text('Password strength too weak. ' + hint);
            progressBar.addClass('bg-danger');
            break;
        case 1:
            strengthText.text('Password strength: Weak. ' + hint);
            progressBar.addClass('bg-danger');
            break;
        case 2:
            strengthText.text('Password strength: Fair. ' + hint);
            progressBar.addClass('bg-warning');
            break;
        case 3:
            strengthText.text('Password strength: Good. ' + hint);
            progressBar.addClass('bg-info');
            break;
        case 4:
            strengthText.text('Password strength: Strong. ' + hint);
            progressBar.addClass('bg-success');
            break;
    }
}
````



The function is called when the password field is being edited:
````javascript
$(document).ready(function() {
	$('#new_password').on('input', function() {
	let password = $(this).val();
	updatePasswordStrength(password);
	});
});
````

