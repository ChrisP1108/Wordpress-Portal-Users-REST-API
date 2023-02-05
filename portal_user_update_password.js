// Check If User Is Already Logged In To Fix Login Loop Issues With Browser Cache To Force Another Reload
    
if (document.cookie.includes('portal_user_information_updated')) {
    window.location.reload();
}

// Select Submit Button

const submitBtn = document.querySelector('#submit');

// Select Error Message Field

const errMsg = document.querySelector('#formErrMsg');

function setErrMsg(msg) {
    errMsg.innerHTML = msg;
}

// Button HTML Selector

const btnHTML = submitBtn.querySelector('.elementor-button-text')

// Capture submitBtn HTML 

const btnStaticHTML = btnHTML.innerHTML;

// Loading Spinner Inside Button HTML

const spinnerHTML = '<div class="lds-ellipsis"><div></div><div></div><div></div><div></div></div>';

function setBtnHTML(html) {
    btnHTML.innerHTML = html;
}

// Monitor For Inputs Typed To Clear Error Message If Present

const inputs = document.querySelectorAll('#portalPasswordUpdateForm input');

inputs.forEach(input => {
   input.addEventListener('input', () => setErrMsg('')); 
   input.addEventListener('keyup', (e) => {
       if (e.key === 'Enter') {
           submitForm();
       }
   })
});

// Makes HTTP Request On Submit

function submitForm() {
    const password1 = document.querySelector('#loginPassword1').value;
    const password2 = document.querySelector('#loginPassword2').value;
    
    // Check For Missing Fields
    
    if (!password1 && !password2) {
        setErrMsg('Please provide an updated password and reenter it.');
        return;
    }
    if (!password1) {
        setErrMsg('Please provide your password.');
        return;
    }
    if (!password2) {
        setErrMsg('Please reenter your password.');
        return;
    }
    
    // Check that passwords match
    
    if (password1 !== password2) {
        setErrMsg('Passwords do not match.  Please reenter.');
        return;
    }
    
    // Execute HTTP Req To API If Fields Properly Filled
    
    const domainURL = 'http://box2496.temp.domains/~foundbw0/magellanfinancial.com';
    
    // Loading Spinner
    
    setBtnHTML(spinnerHTML);
    
    // Get User Data Information.  Should Be Able To Load Without Login Credentials If User Logged In As A Cookie Will Have Been Stored In Their Browser And Will Verify The Cookie
    
    async function getUserDataAndUpdateHTTPReq() {
        try {
            const res = await fetch(domainURL + '/wp-json/portal/user/login', {
               method: 'POST',
               headers: {
                   'content-type': 'application/json'
               }
            });
            
            if (res.ok) {
                const data = await res.json();
                
                // Makes Sure User ID Was Acquired.  Otherwise Update Password HTTP Request Does Not Execute
                
                if (data.data.id) {
                    updatePasswordHTTPReq(data.data.id);
                } else {
                    setBtnHTML(btnStaticHTML);
                    setErrMsg('Failed to update password. Please try again or contact Magellan for support.');
                }
            } else {
                setBtnHTML(btnStaticHTML);
                setErrMsg('Failed to connect to server to update password. Please try again or contact Magellan for support.')
                return;
            }
        } catch (err) {
            setErrMsg('Connection error. Please check your internet connection and try again.');
            console.error(err);
        }
    }
    
    // Send Updated Password To Server
    
    async function updatePasswordHTTPReq(id) {
        try {
            const update = await fetch(domainURL + '/wp-json/portal/user/' + id, {
               method: 'PUT',
               headers: {
                   'content-type': 'application/json'
               },
               body: JSON.stringify({ password: password1 })
            });
            
            if (update.ok) {
                setTimeout(() => {
                    window.location.replace("http://box2496.temp.domains/~foundbw0/magellanfinancial.com/test-portal-page/");
                }, 1000);
            } else {
                setBtnHTML(btnStaticHTML);
                setErrMsg('Failed to update password. Please try again or contact Magellan for support.');
                return;
            }
        } catch (err) {
            setBtnHTML(btnStaticHTML);
            setErrMsg('Connection error. Please check your internet connection and try again.');
            console.error(err);
        }
    }
    
    // Makes HTTPS Requests To Get User Data And Update
    
    getUserDataAndUpdateHTTPReq();
};

// Monitor For Button Click And Execute submitForm Function

submitBtn.addEventListener('click', submitForm);
