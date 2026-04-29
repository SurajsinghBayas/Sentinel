import React, { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { useForm } from 'react-hook-form'
import { z } from 'zod'
import { zodResolver } from '@hookform/resolvers/zod'
import { motion } from 'framer-motion'
import { Shield, Mail, Lock, User, Loader2 } from 'lucide-react'
import { useAuth } from '@/hooks/useAuth'
import { toast } from 'sonner'

const schema = z.object({
  name: z.string().min(2, 'Name must be at least 2 chars'),
  email: z.string().email('Invalid email'),
  password: z.string().min(8, 'Minimum 8 characters'),
  confirmPassword: z.string(),
}).refine(d => d.password === d.confirmPassword, { message: "Passwords don't match", path: ['confirmPassword'] })
type Form = z.infer<typeof schema>

export default function Signup() {
  const { signup } = useAuth()
  const navigate = useNavigate()
  const { register, handleSubmit, formState: { errors, isSubmitting } } = useForm<Form>({ resolver: zodResolver(schema) })

  const onSubmit = async (data: Form) => {
    try {
      await signup(data.name, data.email, data.password)
      toast.success('Account created — Welcome to ANBU Sentinel')
      navigate('/dashboard')
    } catch (e: any) {
      toast.error(e?.response?.data?.detail || 'Signup failed')
    }
  }

  return (
    <div className="min-h-screen bg-sentinel-bg cyber-grid flex items-center justify-center p-4">
      <motion.div initial={{ opacity: 0, y: 24 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5 }}
        className="w-full max-w-md">
        <div className="flex flex-col items-center gap-3 mb-8">
          <div className="h-16 w-16 rounded-2xl flex items-center justify-center animate-pulse-glow"
            style={{ background: 'linear-gradient(135deg, #00d4ff22, #00d4ff44)', border: '1px solid #00d4ff55' }}>
            <Shield className="h-8 w-8 text-sentinel-cyan" />
          </div>
          <div className="text-center">
            <h1 className="text-2xl font-bold text-foreground tracking-wide">ANBU Sentinel</h1>
            <p className="text-xs text-sentinel-cyan font-mono tracking-widest mt-1">CREATE ANALYST ACCOUNT</p>
          </div>
        </div>

        <div className="glass-card p-8">
          <h2 className="text-lg font-semibold text-foreground mb-1">Create Account</h2>
          <p className="text-sm text-muted-foreground mb-6">Join the ANBU Sentinel security platform</p>

          <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
            {[
              { field: 'name', label: 'Full Name', icon: User, type: 'text', placeholder: 'Alex Mercer' },
              { field: 'email', label: 'Email', icon: Mail, type: 'email', placeholder: 'analyst@sentinel.io' },
              { field: 'password', label: 'Password', icon: Lock, type: 'password', placeholder: '••••••••' },
              { field: 'confirmPassword', label: 'Confirm Password', icon: Lock, type: 'password', placeholder: '••••••••' },
            ].map(({ field, label, icon: Icon, type, placeholder }) => (
              <div key={field}>
                <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">{label}</label>
                <div className="relative mt-1.5">
                  <Icon className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                  <input {...register(field as any)} type={type} placeholder={placeholder}
                    className="w-full bg-sentinel-surface border border-sentinel-border rounded-lg pl-10 pr-4 py-2.5 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:border-sentinel-cyan transition-colors" />
                </div>
                {(errors as any)[field] && <p className="text-xs text-sentinel-red mt-1">{(errors as any)[field]?.message}</p>}
              </div>
            ))}

            <button type="submit" disabled={isSubmitting}
              className="btn-primary w-full justify-center py-2.5 mt-2 disabled:opacity-50">
              {isSubmitting ? <Loader2 className="h-4 w-4 animate-spin" /> : 'Create Account'}
            </button>
          </form>

          <p className="text-center text-sm text-muted-foreground mt-6">
            Already have an account?{' '}
            <Link to="/login" className="text-sentinel-cyan hover:underline font-medium">Sign in</Link>
          </p>
        </div>
      </motion.div>
    </div>
  )
}
