/* ═══════════════════════════════════════════
   Secure Workspace — Frontend Auth Module
   ═══════════════════════════════════════════ */

window.__BACKEND_URL = (window.__BACKEND_URL || 'https://vvc-office-v3.onrender.com').replace(/\/$/, '');

async function requestBackend(path, options) {
  var response = await fetch(window.__BACKEND_URL + path, Object.assign({
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' }
  }, options || {}));
  var contentType = response.headers.get('content-type') || '';
  var body = contentType.indexOf('application/json') !== -1
    ? await response.json()
    : await response.text();
  return { response: response, body: body };
}

var Auth = {
  TOKEN_KEY: 'sw_auth_token',

  setToken: function(token) {
    sessionStorage.setItem(this.TOKEN_KEY, token);
  },

  getToken: function() {
    return sessionStorage.getItem(this.TOKEN_KEY);
  },

  clearToken: function() {
    sessionStorage.removeItem(this.TOKEN_KEY);
  },

  isLoggedIn: function() {
    return !!this.getToken();
  },

  /* ── Fetch protected page content ── */
  fetchPage: async function(pageName) {
    var token = this.getToken();
    if (!token) return { error: 'not_logged_in', status: 401 };

    try {
      var result = await requestBackend('/api/pages/' + encodeURIComponent(pageName), {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer ' + token
        }
      });
      var res = result.response;

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

      var html = await res.text();
      return { html: html, status: 200 };

    } catch (err) {
      return { error: 'network_error', status: 0 };
    }
  },

  /* ── User Login ── */
  login: async function(username, password) {
    try {
      var result = await requestBackend('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: username, password: password })
      });
      var res = result.response;
      var data = result.body;

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

  /* ── Admin Login ── */
  adminLogin: async function(username, password) {
    try {
      var result = await requestBackend('/api/auth/admin-login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: username, password: password })
      });
      var res = result.response;
      var data = result.body;

      if (!res.ok) {
        return { error: data.error };
      }

      this.setToken(data.token);
      return { success: true, user: data.user };

    } catch (err) {
      return { error: 'Network error' };
    }
  },

  /* ── Fetch Admin Panel HTML ── */
  fetchAdminPanel: async function() {
    var token = this.getToken();
    if (!token) return { error: 'not_logged_in', status: 401 };

    try {
      var result = await requestBackend('/api/admin/panel-content', {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer ' + token
        }
      });
      var res = result.response;

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

      var html = typeof result.body === 'string' ? result.body : '';
      return { html: html, status: 200 };

    } catch (err) {
      return { error: 'network_error', status: 0 };
    }
  },

  /* ── Logout ── */
  logout: async function() {
    var token = this.getToken();
    if (token) {
      try {
        await fetch(window.__BACKEND_URL + '/api/auth/logout', {
          method: 'POST',
          credentials: 'include',
          headers: { 'Authorization': 'Bearer ' + token }
        });
      } catch (e) { /* ignore */ }
    }
    this.clearToken();
    window.location.href = '/';
  }
};
