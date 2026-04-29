import React, { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { useForm } from 'react-hook-form'
import { z } from 'zod'
import { zodResolver } from '@hookform/resolvers/zod'
import { motion } from 'framer-motion'
import { Shield, Mail, Lock, Eye, EyeOff, Loader2 } from 'lucide-react'
import { useAuth } from '@/hooks/useAuth'
import { toast } from 'sonner'

const schema = z.object({
  email: z.string().email('Invalid email'),
  password: z.string().min(1, 'Password required'),
})
type Form = z.infer<typeof schema>

export default function Login() {
  const { login } = useAuth()
  const navigate = useNavigate()
  const [showPw, setShowPw] = useState(false)
  const { register, handleSubmit, formState: { errors, isSubmitting } } = useForm<Form>({ resolver: zodResolver(schema) })

  const onSubmit = async (data: Form) => {
    try {
      await login(data.email, data.password)
      toast.success('Welcome back, Sentinel')
      navigate('/dashboard')
    } catch (e: any) {
      toast.error(e?.response?.data?.detail || 'Login failed')
    }
  }

  return (
    <div className="min-h-screen bg-sentinel-bg cyber-grid flex items-center justify-center p-4">
      <motion.div initial={{ opacity: 0, y: 24 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5 }}
        className="w-full max-w-md">
        {/* Logo */}
        <div className="flex flex-col items-center gap-3 mb-8">
          <div className="h-16 w-16 rounded-2xl flex items-center justify-center animate-pulse-glow"
            style={{ background: 'linear-gradient(135deg, #00d4ff22, #00d4ff44)', border: '1px solid #00d4ff55' }}>
            <Shield className="h-8 w-8 text-sentinel-cyan" />
          </div>
          <div className="text-center">
            <h1 className="text-2xl font-bold text-foreground tracking-wide">ANBU Sentinel</h1>
            <p className="text-xs text-sentinel-cyan font-mono tracking-widest mt-1">AI-POWERED THREAT INTELLIGENCE</p>
          </div>
        </div>

        {/* Card */}
        <div className="glass-card p-8">
          <h2 className="text-lg font-semibold text-foreground mb-1">Sign In</h2>
          <p className="text-sm text-muted-foreground mb-6">Access your security dashboard</p>

          <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
            <div>
              <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Email</label>
              <div className="relative mt-1.5">
                <Mail className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <input {...register('email')} type="email" placeholder="analyst@sentinel.io"
                  className="w-full bg-sentinel-surface border border-sentinel-border rounded-lg pl-10 pr-4 py-2.5 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:border-sentinel-cyan transition-colors" />
              </div>
              {errors.email && <p className="text-xs text-sentinel-red mt-1">{errors.email.message}</p>}
            </div>

            <div>
              <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Password</label>
              <div className="relative mt-1.5">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <input {...register('password')} type={showPw ? 'text' : 'password'} placeholder="••••••••"
                  className="w-full bg-sentinel-surface border border-sentinel-border rounded-lg pl-10 pr-10 py-2.5 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:border-sentinel-cyan transition-colors" />
                <button type="button" onClick={() => setShowPw(!showPw)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground">
                  {showPw ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
              {errors.password && <p className="text-xs text-sentinel-red mt-1">{errors.password.message}</p>}
            </div>

            <button type="submit" disabled={isSubmitting}
              className="btn-primary w-full justify-center py-2.5 mt-2 disabled:opacity-50">
              {isSubmitting ? <Loader2 className="h-4 w-4 animate-spin" /> : 'Sign In'}
            </button>
          </form>

          <p className="text-center text-sm text-muted-foreground mt-6">
            No account?{' '}
            <Link to="/signup" className="text-sentinel-cyan hover:underline font-medium">Create one</Link>
          </p>
        </div>
      </motion.div>
    </div>
  )
}
