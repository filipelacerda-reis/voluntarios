let authToken = localStorage.getItem('token') || '';

function authHeader() {
  return authToken ? { Authorization: `Bearer ${authToken}` } : {};
}

export function setAuthToken(token) {
  authToken = token || '';
  if (authToken) {
    localStorage.setItem('token', authToken);
  } else {
    localStorage.removeItem('token');
  }
}

export function clearAuthToken() {
  setAuthToken('');
}

export function jsonAuthHeaders(extraHeaders = {}) {
  return {
    'Content-Type': 'application/json',
    ...extraHeaders,
    ...authHeader(),
  };
}

export async function api(path, options = {}) {
  const res = await fetch(path, {
    ...options,
    headers: {
      ...(options.headers || {}),
      ...authHeader(),
    },
  });

  if (res.status === 204) return null;
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.message || 'Falha na requisição');
  return body;
}
