document.addEventListener('DOMContentLoaded', function() {
    // Safe handling of URL parameters
    const urlParams = new URLSearchParams(window.location.search);
    const theme = urlParams.get('theme');
   
    if (theme) {
      const themeMessage = document.getElementById('theme-message');
      if (themeMessage) {
        // Use textContent instead of innerHTML to prevent XSS
        themeMessage.textContent = 'Current theme: ' + theme;
        themeMessage.style.display = 'block';
      }
    }
   
    // Safe handling of hash fragment
    if (window.location.hash) {
      const welcomeBanner = document.getElementById('welcome-message');
      if (welcomeBanner) {
        // Use textContent instead of innerHTML to prevent XSS
        const username = window.location.hash.substring(1);
        welcomeBanner.textContent = 'Welcome back, ' + username;
      }
    }
  });