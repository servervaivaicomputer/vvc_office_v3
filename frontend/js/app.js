/* ═══════════════════════════════════════════
   Secure Workspace — Frontend Auth Module
   ═══════════════════════════════════════════ */

window.__BACKEND_URL = 'https://vvc-office-v3.onrender.com';

const Auth = {
  TOKEN_KEY: 'sw_auth_token',

  /* Token সংরক্ষণ */
  setToken(token) {
    sessionStorage.setItem(this.TOKEN_KEY, token);
  },

  /* Token পাওয়া */
  getToken() {
    return sessionStorage.getItem(this.TOKEN_KEY);
  },

  /* Token মুছে ফেলা */
  clearToken() {
    sessionStorage.removeItem(this.TOKEN_KEY);
  },

  /* Logged in কিনা চেক */
  isLoggedIn() {
    return !!this.getToken();
  },

  /* Backend API call — token দিয়ে protected page content আনা */
  async fetchPage(pageName) {
    const token = this.getToken();
    if (!token) return { error: 'not_logged_in', status: 401 };

    try {
      const res = await fetch(`${window.__BACKEND_URL}/api/pages/${pageName}`, {
        method:      'GET',
        credentials: 'include',
        headers: {
          'Content-Type':  'application/json',
          'Authorization': `Bearer ${token}`
        }
      });

      if (res.status === 401) {
        this.clearToken();
        return { error: 'session_expired', status: 401 };
      }

      if (res.status === 403) {
        return { error: 'access_denied', status: 403 };
      }

      if (!res.ok) {
        return { error: 'server_error', status: res.status };
      }

      const html = await res.text();
      return { html, status: 200 };

    } catch (err) {
      return { error: 'network_error', status: 0 };
    }
  },

  /* Login */
  async login(username, password) {
    try {
      const res = await fetch(`${window.__BACKEND_URL}/api/auth/login`, {
        method:      'POST',
        credentials: 'include',
        headers:     { 'Content-Type': 'application/json' },
        body:        JSON.stringify({ username, password })
      });

      const data = await res.json();

      if (!res.ok) {
        return {
          error: data.error,
          attemptsRemaining: data.attemptsRemaining
        };
      }

      this.setToken(data.token);
      return { success: true, user: data.user };

    } catch (err) {
      return { error: 'Network error' };
    }
  },

  /* Admin Login */
  async adminLogin(username, password) {
    try {
      const res = await fetch(`${window.__BACKEND_URL}/api/auth/admin-login`, {
        method:      'POST',
        credentials: 'include',
        headers:     { 'Content-Type': 'application/json' },
        body:        JSON.stringify({ username, password })
      });

      const data = await res.json();

      if (!res.ok) {
        return { error: data.error };
      }

      this.setToken(data.token);
      return { success: true, user: data.user };

    } catch (err) {
      return { error: 'Network error' };
    }
  },

  /* Admin panel fetch */
  async fetchAdminPanel() {
    const token = this.getToken();
    if (!token) return { error: 'not_logged_in', status: 401 };

    try {
      const res = await fetch(`${window.__BACKEND_URL}/api/pages/admin/panel`, {
        method:      'GET',
        credentials: 'include',
        headers: {
          'Content-Type':  'application/json',
          'Authorization': `Bearer ${token}`
        }
      });

      if (res.status === 401) {
        this.clearToken();
        return { error: 'session_expired', status: 401 };
      }

      if (res.status === 403) {
        return { error: 'admin_only', status: 403 };
      }

      if (!res.ok) {
        return { error: 'server_error', status: res.status };
      }

      const html = await res.text();
      return { html, status: 200 };

    } catch (err) {
      return { error: 'network_error', status: 0 };
    }
  },

  /* Logout */
  async logout() {
    const token = this.getToken();
    if (token) {
      try {
        await fetch(`${window.__BACKEND_URL}/api/auth/logout`, {
          method:      'POST',
          credentials: 'include',
          headers:     { 'Authorization': `Bearer ${token}` }
        });
      } catch (e) { /* ignore */ }
    }
    this.clearToken();
    window.location.href = '/';
  }
};
