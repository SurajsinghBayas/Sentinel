import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`
}

export function formatRelativeTime(dateStr: string): string {
  const date = new Date(dateStr)
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  const diffMin = Math.floor(diffMs / 60000)
  if (diffMin < 1) return 'just now'
  if (diffMin < 60) return `${diffMin}m ago`
  const diffHr = Math.floor(diffMin / 60)
  if (diffHr < 24) return `${diffHr}h ago`
  return date.toLocaleDateString()
}

export const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#f43f5e',
  HIGH: '#ff6b35',
  MEDIUM: '#eab308',
  LOW: '#22c55e',
  NORMAL: '#64748b',
}

export const ATTACK_TYPE_LABELS: Record<string, string> = {
  BRUTE_FORCE: 'Brute Force',
  DDOS: 'DDoS',
  SQL_INJECTION: 'SQL Injection',
  XSS: 'XSS',
  PORT_SCAN: 'Port Scan',
  DATA_EXFILTRATION: 'Data Exfiltration',
  DIRECTORY_TRAVERSAL: 'Directory Traversal',
  ML_ANOMALY: 'ML Anomaly',
  UNKNOWN: 'Unknown',
}
