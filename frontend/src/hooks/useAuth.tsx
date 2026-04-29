import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react'
import api from '@/lib/api'
import { auth } from '@/lib/auth'

interface User { id: string; name: string; email: string; role: string; avatar_initials?: string }
interface AuthCtx {
  user: User | null
  isLoading: boolean
  login: (email: string, password: string) => Promise<void>
  signup: (name: string, email: string, password: string) => Promise<void>
  logout: () => void
}

const AuthContext = createContext<AuthCtx | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(auth.getUser())
  const [isLoading, setIsLoading] = useState(!!auth.getToken() && !auth.getUser())

  useEffect(() => {
    if (auth.getToken() && !user) {
      api.get('/auth/me').then(r => { setUser(r.data); auth.setUser(r.data) })
        .catch(() => { auth.clear(); setUser(null) })
        .finally(() => setIsLoading(false))
    } else {
      setIsLoading(false)
    }
  }, [])

  const login = async (email: string, password: string) => {
    const { data } = await api.post('/auth/login', { email, password })
    auth.setTokens(data.access_token, data.refresh_token)
    const me = await api.get('/auth/me')
    auth.setUser(me.data)
    setUser(me.data)
  }

  const signup = async (name: string, email: string, password: string) => {
    const { data } = await api.post('/auth/signup', { name, email, password })
    auth.setTokens(data.access_token, data.refresh_token)
    const me = await api.get('/auth/me')
    auth.setUser(me.data)
    setUser(me.data)
  }

  const logout = () => { auth.clear(); setUser(null) }

  return <AuthContext.Provider value={{ user, isLoading, login, signup, logout }}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}
