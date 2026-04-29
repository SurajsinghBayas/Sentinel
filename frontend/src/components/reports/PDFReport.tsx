import React from 'react'
import { Document, Page, Text, View, StyleSheet, Font } from '@react-pdf/renderer'

const COLORS = {
  bg: '#060b18',
  surface: '#0d1526',
  cyan: '#00d4ff',
  amber: '#ff6b35',
  red: '#f43f5e',
  yellow: '#eab308',
  green: '#22c55e',
  text: '#e2e8f0',
  muted: '#64748b',
  border: '#1e3a5f',
}

const styles = StyleSheet.create({
  page: { backgroundColor: COLORS.bg, color: COLORS.text, fontFamily: 'Helvetica', padding: 40 },
  coverPage: { backgroundColor: COLORS.bg, color: COLORS.text, fontFamily: 'Helvetica', padding: 60, flexDirection: 'column', justifyContent: 'center' },

  // Cover
  coverBadge: { backgroundColor: '#00d4ff22', borderWidth: 1, borderColor: COLORS.cyan, borderRadius: 8, padding: '8 16', alignSelf: 'flex-start', marginBottom: 24 },
  coverBadgeText: { color: COLORS.cyan, fontSize: 10, letterSpacing: 3 },
  coverTitle: { fontSize: 36, fontFamily: 'Helvetica-Bold', color: COLORS.text, marginBottom: 8 },
  coverSubtitle: { fontSize: 14, color: COLORS.muted, marginBottom: 40 },
  coverMeta: { borderTopWidth: 1, borderTopColor: COLORS.border, paddingTop: 24, marginTop: 40 },
  coverMetaRow: { flexDirection: 'row', justifyContent: 'space-between', marginBottom: 8 },
  coverMetaLabel: { fontSize: 8, color: COLORS.muted, letterSpacing: 2 },
  coverMetaValue: { fontSize: 10, color: COLORS.text },
  classificationBadge: { backgroundColor: '#f43f5e22', borderWidth: 1, borderColor: COLORS.red, borderRadius: 4, padding: '4 10', alignSelf: 'flex-start', marginTop: 20 },
  classificationText: { color: COLORS.red, fontSize: 9, letterSpacing: 2, fontFamily: 'Helvetica-Bold' },

  // Sections
  sectionTitle: { fontSize: 14, fontFamily: 'Helvetica-Bold', color: COLORS.cyan, marginBottom: 12, paddingBottom: 8, borderBottomWidth: 1, borderBottomColor: COLORS.border },
  section: { marginBottom: 24 },

  // Card
  card: { backgroundColor: COLORS.surface, borderRadius: 8, padding: 16, marginBottom: 10, borderWidth: 1, borderColor: COLORS.border },
  cardHeader: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 },
  cardTitle: { fontSize: 11, fontFamily: 'Helvetica-Bold', color: COLORS.text },
  cardMeta: { fontSize: 9, color: COLORS.muted, fontFamily: 'Courier' },
  cardBody: { fontSize: 10, color: COLORS.text, lineHeight: 1.5 },

  // Badge
  badgeCritical: { backgroundColor: '#f43f5e22', borderWidth: 1, borderColor: COLORS.red, borderRadius: 4, padding: '2 6' },
  badgeHigh: { backgroundColor: '#ff6b3522', borderWidth: 1, borderColor: COLORS.amber, borderRadius: 4, padding: '2 6' },
  badgeMedium: { backgroundColor: '#eab30822', borderWidth: 1, borderColor: COLORS.yellow, borderRadius: 4, padding: '2 6' },
  badgeLow: { backgroundColor: '#22c55e22', borderWidth: 1, borderColor: COLORS.green, borderRadius: 4, padding: '2 6' },
  badgeTextCritical: { color: COLORS.red, fontSize: 8, fontFamily: 'Helvetica-Bold' },
  badgeTextHigh: { color: COLORS.amber, fontSize: 8, fontFamily: 'Helvetica-Bold' },
  badgeTextMedium: { color: COLORS.yellow, fontSize: 8, fontFamily: 'Helvetica-Bold' },
  badgeTextLow: { color: COLORS.green, fontSize: 8, fontFamily: 'Helvetica-Bold' },

  // Stats grid
  statsGrid: { flexDirection: 'row', gap: 10, marginBottom: 16 },
  statBox: { flex: 1, backgroundColor: COLORS.surface, borderRadius: 8, padding: 14, borderWidth: 1, borderColor: COLORS.border, alignItems: 'center' },
  statValue: { fontSize: 24, fontFamily: 'Helvetica-Bold', color: COLORS.text },
  statLabel: { fontSize: 8, color: COLORS.muted, letterSpacing: 1, marginTop: 4 },

  // Recommendations
  recItem: { flexDirection: 'row', gap: 8, marginBottom: 8 },
  recNum: { fontSize: 9, color: COLORS.cyan, fontFamily: 'Courier', width: 20, flexShrink: 0, marginTop: 1 },
  recText: { fontSize: 10, color: COLORS.text, flex: 1, lineHeight: 1.5 },

  // Page number
  pageNum: { position: 'absolute', bottom: 20, right: 40, fontSize: 9, color: COLORS.muted },
  footer: { position: 'absolute', bottom: 20, left: 40, fontSize: 9, color: COLORS.muted },
})

const ATTACK_LABELS: Record<string, string> = {
  BRUTE_FORCE: 'Brute Force', DDOS: 'DDoS', SQL_INJECTION: 'SQL Injection',
  XSS: 'XSS', PORT_SCAN: 'Port Scan', DATA_EXFILTRATION: 'Data Exfiltration',
  DIRECTORY_TRAVERSAL: 'Directory Traversal', ML_ANOMALY: 'ML Anomaly', UNKNOWN: 'Unknown',
}

function SeverityBadge({ severity }: { severity: string }) {
  const map: Record<string, any> = {
    CRITICAL: { style: styles.badgeCritical, text: styles.badgeTextCritical },
    HIGH: { style: styles.badgeHigh, text: styles.badgeTextHigh },
    MEDIUM: { style: styles.badgeMedium, text: styles.badgeTextMedium },
    LOW: { style: styles.badgeLow, text: styles.badgeTextLow },
  }
  const cfg = map[severity] || map.LOW
  return (
    <View style={cfg.style}>
      <Text style={cfg.text}>{severity}</Text>
    </View>
  )
}

export function IncidentReportPDF({ data }: { data: any }) {
  const threats = data.threats || []
  const stats = data.stats || {}
  const now = new Date(data.generated_at || Date.now()).toLocaleString()

  return (
    <Document title={data.title} author="ANBU Sentinel" creator="ANBU Sentinel v2.0">
      {/* ── Cover Page ── */}
      <Page size="A4" style={styles.coverPage}>
        <View style={styles.coverBadge}><Text style={styles.coverBadgeText}>AI-POWERED THREAT INTELLIGENCE</Text></View>
        <Text style={styles.coverTitle}>ANBU Sentinel</Text>
        <Text style={styles.coverSubtitle}>{data.title}</Text>
        <View style={styles.classificationBadge}><Text style={styles.classificationText}>⚠ {data.classification}</Text></View>
        <View style={styles.coverMeta}>
          {[
            ['GENERATED', now],
            ['ANALYST', data.analyst_name || 'System'],
            ['TOTAL THREATS', String(data.total_events || 0)],
            ['CRITICAL', String(stats.critical || 0)],
          ].map(([k, v]) => (
            <View key={k} style={styles.coverMetaRow}>
              <Text style={styles.coverMetaLabel}>{k}</Text>
              <Text style={styles.coverMetaValue}>{v}</Text>
            </View>
          ))}
        </View>
        <Text style={styles.footer}>ANBU Sentinel v2.0 — Confidential Security Report</Text>
      </Page>

      {/* ── Executive Summary ── */}
      <Page size="A4" style={styles.page}>
        <Text style={styles.sectionTitle}>01. Executive Summary</Text>
        <View style={styles.statsGrid}>
          {[
            { label: 'TOTAL THREATS', value: data.total_events || 0 },
            { label: 'CRITICAL', value: stats.critical || 0 },
            { label: 'HIGH', value: stats.high || 0 },
            { label: 'MEDIUM', value: stats.medium || 0 },
          ].map(s => (
            <View key={s.label} style={styles.statBox}>
              <Text style={styles.statValue}>{s.value}</Text>
              <Text style={styles.statLabel}>{s.label}</Text>
            </View>
          ))}
        </View>
        <View style={styles.card}>
          <Text style={[styles.cardTitle, { marginBottom: 8 }]}>AI-Generated Incident Summary</Text>
          <Text style={styles.cardBody}>{data.summary_narration}</Text>
        </View>
        <Text style={styles.pageNum}>2</Text>
        <Text style={styles.footer}>ANBU Sentinel — {data.classification}</Text>
      </Page>

      {/* ── Threat Details ── */}
      <Page size="A4" style={styles.page}>
        <Text style={styles.sectionTitle}>02. Detected Threats ({threats.length})</Text>
        {threats.slice(0, 10).map((t: any, i: number) => (
          <View key={t.id} style={styles.card}>
            <View style={styles.cardHeader}>
              <View style={{ flexDirection: 'row', alignItems: 'center', gap: 8 }}>
                <SeverityBadge severity={t.severity} />
                <Text style={styles.cardTitle}>{ATTACK_LABELS[t.attack_type] || t.attack_type}</Text>
              </View>
              <Text style={styles.cardMeta}>{t.source_ip}</Text>
            </View>
            <Text style={styles.cardMeta}>{t.rule_name} • {Math.round(t.confidence * 100)}% confidence</Text>
            {t.evidence?.length > 0 && (
              <Text style={[styles.cardBody, { marginTop: 4 }]}>{t.evidence[0]}</Text>
            )}
            {t.ai_narration && (
              <Text style={[styles.cardBody, { marginTop: 6, color: COLORS.muted }]}>{t.ai_narration}</Text>
            )}
          </View>
        ))}
        <Text style={styles.pageNum}>3</Text>
        <Text style={styles.footer}>ANBU Sentinel — {data.classification}</Text>
      </Page>

      {/* ── Recommendations ── */}
      <Page size="A4" style={styles.page}>
        <Text style={styles.sectionTitle}>03. Security Recommendations</Text>
        {(data.recommendations || []).map((r: string, i: number) => (
          <View key={i} style={styles.recItem}>
            <Text style={styles.recNum}>{String(i + 1).padStart(2, '0')}.</Text>
            <Text style={styles.recText}>{r}</Text>
          </View>
        ))}
        <Text style={[styles.sectionTitle, { marginTop: 24 }]}>04. Report Metadata</Text>
        <View style={styles.card}>
          {[
            ['Report Title', data.title],
            ['Classification', data.classification],
            ['Generated At', now],
            ['Analyst', data.analyst_name || 'System'],
            ['Platform', 'ANBU Sentinel v2.0'],
            ['AI Engine', 'AWS Bedrock Claude 3.5 Sonnet'],
          ].map(([k, v]) => (
            <View key={k} style={{ flexDirection: 'row', justifyContent: 'space-between', paddingVertical: 4, borderBottomWidth: 1, borderBottomColor: COLORS.border }}>
              <Text style={[styles.cardMeta, { letterSpacing: 1 }]}>{k.toUpperCase()}</Text>
              <Text style={styles.cardBody}>{v}</Text>
            </View>
          ))}
        </View>
        <Text style={styles.pageNum}>4</Text>
        <Text style={styles.footer}>ANBU Sentinel — {data.classification}</Text>
      </Page>
    </Document>
  )
}
