document.addEventListener('DOMContentLoaded', function() {
    // Basic auto-refresh for the home page (for a simplified "real-time" feel)
    // In a real application, you'd use WebSockets (e.g., Flask-SocketIO) for true real-time updates.
    if (window.location.pathname === '/') {
        setTimeout(function() {
            window.location.reload();
        }, 60000); // Reload every 60 seconds
    }

    // Optional: Hide flash messages after a few seconds
    const flashMessages = document.querySelectorAll('.flash-message');
    flashMessages.forEach(msg => {
        setTimeout(() => {
            msg.style.opacity = '0';
            msg.style.transition = 'opacity 0.5s ease-out';
            setTimeout(() => msg.remove(), 500); // Remove after transition
        }, 5000); // Hide after 5 seconds
    });
});