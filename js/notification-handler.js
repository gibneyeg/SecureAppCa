document.addEventListener('DOMContentLoaded', function() {
    // Safe handling of URL parameters
    const urlParams = new URLSearchParams(window.location.search);
    const notification = urlParams.get('notification');
    
    if (notification) {
      const notificationArea = document.getElementById('notification-area');
      if (notificationArea) {
        // Use textContent instead of innerHTML to prevent XSS
        notificationArea.textContent = notification;
        notificationArea.style.display = 'block';
      }
    }
  });