/**
 * Demo Data Generator for Threat Dashboard
 * Generates realistic threat data for demonstration purposes
 */

const attackTypes = [
  'dos',
  'ddos',
  'port_scan',
  'brute_force',
  'sql_injection',
  'xss',
  'malware',
  'botnet',
  'probe',
  'r2l'
]

const riskLevels = ['critical', 'high', 'medium', 'low']

const explanationTemplates = {
  dos: [
    'Denial of Service attack detected with extremely high packet rate ({pps} pps). Service availability at risk.',
    'DoS pattern identified: High bandwidth consumption ({bw} MB/s) overwhelming target resources.',
    'Sustained high-volume traffic from single source indicative of DoS attack methodology.'
  ],
  ddos: [
    'Distributed Denial of Service attack detected from multiple sources. Coordinated attack pattern confirmed.',
    'DDoS attack in progress with {pps} packets per second. Multiple attack vectors identified.',
    'Large-scale coordinated attack overwhelming network infrastructure. Immediate mitigation required.'
  ],
  port_scan: [
    'Port scanning activity detected: {packets} packets sent to {ports} different ports.',
    'Systematic port enumeration identified. Potential reconnaissance for future attack.',
    'Network mapping behavior detected with sequential port probing pattern.'
  ],
  brute_force: [
    'Brute force authentication attempt detected with {attempts} login failures.',
    'Credential stuffing attack identified against authentication service.',
    'Systematic password guessing detected with automated tooling signatures.'
  ],
  sql_injection: [
    'SQL injection attack detected in HTTP request parameters. Database security compromised.',
    'Malicious SQL payloads identified in user input. Potential data exfiltration risk.',
    'Database manipulation attempt through application vulnerabilities.'
  ],
  malware: [
    'Malware communication detected. Command & Control (C2) traffic patterns identified.',
    'Known malicious payload signatures detected in network traffic.',
    'Trojan activity confirmed with suspicious outbound connections.'
  ],
  botnet: [
    'Botnet participation detected. System may be compromised and part of larger attack network.',
    'Command & Control communication pattern consistent with botnet activity.',
    'Coordinated malicious activity suggesting botnet membership.'
  ]
}

const contributingFactors = [
  'High packet rate',
  'Excessive bandwidth usage',
  'Unusual port access pattern',
  'Malformed packet structure',
  'Suspicious payload content',
  'Known malicious signature',
  'Abnormal connection duration',
  'Multiple failed authentication attempts',
  'nDPI risk indicators',
  'Geographic anomaly',
  'Unusual protocol usage',
  'Encrypted suspicious traffic'
]

const recommendedActions = {
  critical: [
    'Immediately block source IP address',
    'Alert security operations center',
    'Escalate to incident response team',
    'Initiate forensic analysis',
    'Activate DDoS mitigation if applicable',
    'Review firewall rules and update',
    'Monitor for lateral movement',
    'Preserve logs for investigation'
  ],
  high: [
    'Block source IP address',
    'Alert security team',
    'Log incident for analysis',
    'Enable rate limiting',
    'Review access logs',
    'Update intrusion prevention rules',
    'Consider quarantine of affected systems'
  ],
  medium: [
    'Add to watchlist for monitoring',
    'Alert security team',
    'Log incident for review',
    'Increase logging verbosity',
    'Review recent activity patterns',
    'Consider temporary access restriction'
  ],
  low: [
    'Continue monitoring',
    'Log incident for analysis',
    'Review during next security audit',
    'Update threat intelligence database'
  ]
}

function randomChoice(array) {
  return array[Math.floor(Math.random() * array.length)]
}

function randomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min
}

function generateIPAddress() {
  return `${randomInt(1, 255)}.${randomInt(0, 255)}.${randomInt(0, 255)}.${randomInt(1, 254)}`
}

function generateFlowId() {
  const srcIP = generateIPAddress()
  const dstIP = generateIPAddress()
  const srcPort = randomInt(1024, 65535)
  const dstPort = randomChoice([80, 443, 22, 21, 25, 53, 3306, 8080, 3389])

  return `${srcIP}:${srcPort}->${dstIP}:${dstPort}`
}

function getRiskLevel(attackType) {
  const criticalAttacks = ['ddos', 'malware', 'sql_injection']
  const highAttacks = ['dos', 'brute_force', 'botnet']
  const mediumAttacks = ['port_scan', 'xss']

  if (criticalAttacks.includes(attackType)) {
    return Math.random() > 0.3 ? 'critical' : 'high'
  } else if (highAttacks.includes(attackType)) {
    return Math.random() > 0.4 ? 'high' : 'medium'
  } else if (mediumAttacks.includes(attackType)) {
    return Math.random() > 0.5 ? 'medium' : 'low'
  }
  return 'low'
}

function getRiskScore(riskLevel) {
  const ranges = {
    critical: [0.8, 1.0],
    high: [0.6, 0.8],
    medium: [0.4, 0.6],
    low: [0.1, 0.4]
  }
  const [min, max] = ranges[riskLevel]
  return min + Math.random() * (max - min)
}

function generateExplanation(attackType) {
  const templates = explanationTemplates[attackType] || ['Suspicious network activity detected.']
  let explanation = randomChoice(templates)

  // Replace placeholders
  explanation = explanation.replace('{pps}', randomInt(1000, 50000).toLocaleString())
  explanation = explanation.replace('{bw}', randomInt(100, 5000))
  explanation = explanation.replace('{packets}', randomInt(100, 1000))
  explanation = explanation.replace('{ports}', randomInt(50, 500))
  explanation = explanation.replace('{attempts}', randomInt(50, 500))

  return explanation
}

function selectContributingFactors(attackType, count = 3) {
  const factors = [...contributingFactors]
  const selected = []

  // Add attack-specific factors
  if (attackType === 'dos' || attackType === 'ddos') {
    selected.push('High packet rate', 'Excessive bandwidth usage')
  } else if (attackType === 'port_scan') {
    selected.push('Unusual port access pattern', 'Systematic probe pattern')
  } else if (attackType === 'brute_force') {
    selected.push('Multiple failed authentication attempts')
  }

  // Add random factors
  while (selected.length < count) {
    const factor = randomChoice(factors)
    if (!selected.includes(factor)) {
      selected.push(factor)
    }
  }

  return selected.slice(0, count)
}

function selectRecommendedActions(riskLevel) {
  const actions = recommendedActions[riskLevel] || []
  const count = randomInt(3, Math.min(actions.length, 5))

  const selected = []
  const available = [...actions]

  for (let i = 0; i < count; i++) {
    if (available.length === 0) break
    const index = randomInt(0, available.length - 1)
    selected.push(available.splice(index, 1)[0])
  }

  return selected
}

export function generateDemoThreat(id = null) {
  const attackType = randomChoice(attackTypes)
  const riskLevel = getRiskLevel(attackType)
  const riskScore = getRiskScore(riskLevel)
  const confidence = 0.7 + Math.random() * 0.29

  return {
    id: id || `threat_${Date.now()}_${randomInt(1000, 9999)}`,
    flow_id: generateFlowId(),
    timestamp: new Date().toISOString(),
    attack_type: attackType,
    confidence: confidence,
    is_malicious: true,
    risk_score: riskScore,
    risk_level: riskLevel,
    anomaly_score: Math.random() * 0.5,
    is_anomaly: Math.random() > 0.5,
    explanation: generateExplanation(attackType),
    feature_importance: {
      packets_per_second: Math.random(),
      bytes_per_second: Math.random(),
      duration: Math.random(),
      packet_size_mean: Math.random()
    },
    contributing_factors: selectContributingFactors(attackType),
    recommended_actions: selectRecommendedActions(riskLevel),
    processing_time_ms: randomInt(2, 15)
  }
}

export function generateDemoThreats(count = 10) {
  const threats = []
  for (let i = 0; i < count; i++) {
    threats.push(generateDemoThreat(`threat_${i}`))
  }

  // Sort by risk level (critical first)
  const riskPriority = { critical: 0, high: 1, medium: 2, low: 3 }
  threats.sort((a, b) => riskPriority[a.risk_level] - riskPriority[b.risk_level])

  return threats
}

export function generateRealTimeThreats() {
  // Generate new threats periodically
  const interval = randomInt(5000, 15000) // Every 5-15 seconds
  return setInterval(() => {
    return generateDemoThreat()
  }, interval)
}
