    // Selects Logout Button
    
    const btn = document.querySelector('#logoutBtn');
    
    // Execute HTTP Req To API If Fields Properly Filled
        
        const domainURL = 'http://box2496.temp.domains/~foundbw0/magellanfinancial.com';
        
    // Monitors When Logout Button Is Clicked And Performs Logout HTTP Request To Server
        
    btn.addEventListener('click', async () => {
        const logout = await fetch(domainURL + '/wp-json/portal/logout', {
           method: 'POST',
           headers: {
               'content-type': 'application/json'
           },
           body: JSON.stringify({ })
        });
        
        window.location.replace("http://box2496.temp.domains/~foundbw0/magellanfinancial.com/test-portal-user-login/");
    });