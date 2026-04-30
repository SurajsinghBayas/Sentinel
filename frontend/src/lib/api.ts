import axios from 'axios'
import { auth } from './auth'

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || '/api',
  headers: { 'Content-Type': 'application/json' },
})

// Attach token
api.interceptors.request.use((config) => {
  const token = auth.getToken()
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

// Auto-refresh on 401
api.interceptors.response.use(
  (res) => res,
  async (error) => {
    const original = error.config
    if (error.response?.status === 401 && !original._retry) {
      original._retry = true
      const refreshToken = auth.getRefreshToken()
      if (refreshToken) {
        try {
          const baseURL = import.meta.env.VITE_API_URL || '/api'
          const { data } = await axios.post(`${baseURL}/auth/refresh`, { refresh_token: refreshToken })
          auth.setTokens(data.access_token, data.refresh_token)
          original.headers.Authorization = `Bearer ${data.access_token}`
          return api(original)
        } catch {
          auth.clear()
          window.location.href = '/login'
        }
      } else {
        auth.clear()
        window.location.href = '/login'
      }
    }
    return Promise.reject(error)
  }
)

export default api
