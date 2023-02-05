// Check If User Is Already Logged In To Fix Login Loop Issues With Browser Cache To Force Another Reload
    
if (document.cookie.includes('portal_logged_in')) {
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

// Monitor For Inputs Typed To Clear Error Message If Present And Monitor For Enter Key

const inputs = document.querySelectorAll('#portalLoginForm input');
    
inputs.forEach(input => {
   input.addEventListener('input', () => setErrMsg('')); 
   input.addEventListener('keyup', (e) => {
       if (e.key === 'Enter') {
           submitForm();
       }
   })
});

// Makes HTTP Request On Form Submit

function submitForm() {
    const email = document.querySelector('#loginEmail').value;
    const password = document.querySelector('#loginPassword').value;
    
    // Check For Missing Fields
    
    if (!email && !password) {
        setErrMsg('Please provide your email and password');
        return;
    }
    if (!email) {
        setErrMsg('Please provide your email');
        return;
    }
    if (!email.includes('@')) {
        setErrMsg('Please provide a valid email');
        return;
    }
    if (!password) {
        setErrMsg('Please provide your password');
        return;
    }
    
    // Execute HTTP Req To API If Fields Properly Filled
    
    const domainURL = 'http://box2496.temp.domains/~foundbw0/magellanfinancial.com';
    
    // Loading Spinner
    
    setBtnHTML(spinnerHTML);
    
    async function loginHTTPReq() {
        try {
            const res = await fetch(domainURL + '/wp-json/portal/user/login', {
               method: 'POST',
               headers: {
                   'content-type': 'application/json'
               },
               body: JSON.stringify({ email, password})
            });
            
            if (res.ok) {
                
                const data = await res.json();
                
                setTimeout(() => {
                    if (data.data.updated_password === "0") {
                        window.location.replace("http://box2496.temp.domains/~foundbw0/magellanfinancial.com/test-portal-user-update-information/");
                    } else window.location.replace("http://box2496.temp.domains/~foundbw0/magellanfinancial.com/test-portal-page/");
                }, 1000);
            } else {
                setBtnHTML(btnStaticHTML);
                setErrMsg('Login failed. Please check your credentials and try again.  If you have forgotten your password, click the "Forgot Password?" button below.')
                return;
            }
        } catch (err) {
            setBtnHTML(btnStaticHTML);
            setErrMsg('Connection error. Please check your internet connection and try again.');
            console.error(err);
        }
    }
    
    loginHTTPReq();
};

// Monitor For Button Click And Execute Login Attempt

submitBtn.addEventListener('click', submitForm);
