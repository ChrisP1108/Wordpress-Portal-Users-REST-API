    // Select Submit Button
    
    const submitBtn = document.querySelector('#submit');
    
    // Select Error Message Field
    
    const msgText = document.querySelector('#formErrMsg');
    console.log(msgText)
    
    function setMsg(msg) {
        msgText.innerHTML = msg;
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
    
    const input = document.querySelector('#portalLoginForm input');
        
    input.addEventListener('input', () => setMsg('')); 
    input.addEventListener('keyup', (e) => {
       if (e.key === 'Enter') {
           submitForm();
       }
    });

    // Makes HTTP Request On Form Submit
    
    function submitForm() {
        const email = document.querySelector('#emailRecover').value;
        
        // Check If Email Field Is Missing
        
        if (!email) {
            setMsg('Please provide your email');
            return;
        }
        if (!email.includes('@')) {
            setMsg('Please provide a valid email');
            return;
        }
        
        // Execute HTTP Req To API If Fields Properly Filled
        
        const domainURL = 'http://box2496.temp.domains/~foundbw0/magellanfinancial.com';
        
        // Loading Spinner
        
        setBtnHTML(spinnerHTML);
        
        async function submitEmailHTTP() {
            try {
                const res = await fetch(domainURL + '/wp-json/portal/user/forgot', {
                   method: 'POST',
                   headers: {
                       'content-type': 'application/json'
                   },
                   body: JSON.stringify({ email })
                });
                
                setBtnHTML(btnStaticHTML);
                
                if (res.ok) {
                    submitBtn.remove();
                    document.querySelector('#emailHeading').remove();
                    document.querySelector('#portalLoginForm').remove();
                    setMsg('Thank you.  You will receive an email shortly with a new temporary password to log back in.');
                    setTimeout(() => {
                       window.location.replace("http://box2496.temp.domains/~foundbw0/magellanfinancial.com/test-portal-user-login/"); 
                    }, 10000);
                } else {
                    if (res.status === 400) {
                        setMsg('You provided an invalid email.  Please try again or contact Magellan for support.');
                    }
                    if (res.status >= 500) {
                        setMsg('An error occured in submitting your email.  Please try again or contact Magellan for support.');
                    }
                    return;
                }
            } catch (err) {
                setBtnHTML(btnStaticHTML);
                setMsg('Connection error. Please check your internet connection and try again.');
                console.error(err);
            }
        }
        
        submitEmailHTTP();
    };
    
    // Monitor For Button Click And Execute Login Attempt
    
    submitBtn.addEventListener('click', submitForm);