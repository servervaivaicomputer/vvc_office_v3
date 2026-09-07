/* ═══════════════════════════════════════
   Secure Workspace — Frontend Utilities
   ═══════════════════════════════════════ */

// Backend URL — change this to your Render deployment URL
window.__BACKEND_URL = 'https://your-backend.onrender.com';

// If user is already logged in (flag set during login), update UI
(function () {
  const loggedIn = sessionStorage.getItem('loggedIn');

  // On any page, if the user has the "loggedIn" flag, upgrade CTAs
  if (loggedIn) {
    document.querySelectorAll('a[href*="/login/"]').forEach(el => {
      // Replace "Login" links with "Continue" links pointing to backend
      el.textContent = 'Continue →';
      el.href = window.__BACKEND_URL + '/projects/home';
    });
  }

  // Clear the flag on landing (the actual auth is in the backend cookie)
  // This flag is purely for UX — never trusted for security
})();
