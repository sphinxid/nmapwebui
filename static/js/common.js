// Common JavaScript functions for NmapWebUI

async function logout() {
    try {
        await fetch('/api/auth/logout', { method: 'POST', credentials: 'same-origin' });
        window.location.href = '/login';
    } catch (error) {
        console.error('Logout error:', error);
        window.location.href = '/login';
    }
}

function toggleTheme() {
    // Theme toggle functionality (placeholder)
    document.body.classList.toggle('light-theme');
}

function refreshPage() {
    window.location.reload();
}

// Auto-refresh functionality
let autoRefreshInterval;
function startAutoRefresh(interval = 30000) {
    autoRefreshInterval = setInterval(() => {
        const event = new CustomEvent('autoRefresh');
        document.dispatchEvent(event);
    }, interval);
}

function stopAutoRefresh() {
    if (autoRefreshInterval) {
        clearInterval(autoRefreshInterval);
    }
}

// Initialize auto-refresh for dashboard-like pages
document.addEventListener('DOMContentLoaded', () => {
    if (window.location.pathname === '/' || window.location.pathname.includes('/dashboard')) {
        startAutoRefresh();
    }
});