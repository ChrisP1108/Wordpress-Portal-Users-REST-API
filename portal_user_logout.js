// Check If User Is Logged Out To Fix Logout Loop Issues With Browser Cache To Force Another Reload
    
    if (!document.cookie.includes('portal_logged_in') && !document.cookie.includes('wp')) {
        window.location.reload();
    }

    // Selects Logout Button
    
    const btn = document.querySelector('#logoutBtn');
    
    // Button HTML Selector
    
    const btnHTML = btn.querySelector('.elementor-button-text')
    
    // Loading Spinner Inside Button HTML
    
    const spinnerHTML = '<div class="lds-ellipsis"><div></div><div></div><div></div><div></div></div>';
    
    // Execute HTTP Req To API If Fields Properly Filled
        
    const domainURL = 'http://box2496.temp.domains/~foundbw0/magellanfinancial.com';
        
    // Monitors When Logout Button Is Clicked And Performs Logout HTTP Request To Server
        
    btn.addEventListener('click', async () => {
        
        // Loading Spinner In Button
        
        btnHTML.innerHTML = spinnerHTML;
        
        const logout = await fetch(domainURL + '/wp-json/portal/logout', {
           method: 'POST',
           headers: {
               'content-type': 'application/json'
           },
           body: JSON.stringify({ })
        });
        
        setTimeout(() => {
            window.location.replace("http://box2496.temp.domains/~foundbw0/magellanfinancial.com/test-portal-user-login/");
        }, 1000);
    });
