<template>
  <div class="threat-card" :class="threat.risk_level">
    <div class="threat-header">
      <div class="threat-title">
        <span class="threat-icon">{{ getRiskIcon(threat.risk_level) }}</span>
        <h3>{{ threat.attack_type.toUpperCase() }}</h3>
        <span class="threat-badge" :class="threat.risk_level">
          {{ threat.risk_level }}
        </span>
      </div>
      <div class="threat-time">
        {{ formatTime(threat.timestamp) }}
      </div>
    </div>

    <div class="threat-body">
      <div class="threat-info">
        <div class="info-row">
          <span class="label">Flow:</span>
          <span class="value monospace">{{ threat.flow_id }}</span>
        </div>
        <div class="info-row">
          <span class="label">Confidence:</span>
          <span class="value">{{ (threat.confidence * 100).toFixed(1) }}%</span>
        </div>
        <div class="info-row">
          <span class="label">Risk Score:</span>
          <span class="value">{{ (threat.risk_score * 100).toFixed(1) }}/100</span>
        </div>
      </div>

      <div class="threat-explanation">
        <p class="explanation-text">{{ threat.explanation }}</p>
      </div>

      <div class="threat-factors">
        <h4>Contributing Factors:</h4>
        <div class="factors-list">
          <span
            v-for="(factor, index) in threat.contributing_factors"
            :key="index"
            class="factor-tag"
          >
            {{ factor }}
          </span>
        </div>
      </div>

      <div class="threat-actions-section">
        <h4>Recommended Actions:</h4>
        <ul class="actions-list">
          <li v-for="(action, index) in threat.recommended_actions" :key="index">
            {{ action }}
          </li>
        </ul>
      </div>
    </div>

    <div class="threat-footer">
      <button @click="$emit('investigate', threat)" class="btn btn-primary">
        🔍 Investigate
      </button>
      <button @click="$emit('block', threat)" class="btn btn-danger">
        🚫 Block IP
      </button>
      <button class="btn btn-secondary">
        📋 View Details
      </button>
    </div>
  </div>
</template>

<script>
import dayjs from 'dayjs'
import relativeTime from 'dayjs/plugin/relativeTime'

dayjs.extend(relativeTime)

export default {
  name: 'ThreatCard',
  props: {
    threat: {
      type: Object,
      required: true
    }
  },
  emits: ['investigate', 'block'],
  methods: {
    getRiskIcon(level) {
      const icons = {
        critical: '🔴',
        high: '🟠',
        medium: '🟡',
        low: '🟢'
      }
      return icons[level] || '⚪'
    },
    formatTime(timestamp) {
      return dayjs(timestamp).fromNow()
    }
  }
}
</script>

<style scoped>
.threat-card {
  background: #0f0f1e;
  border: 2px solid;
  border-radius: 8px;
  padding: 1.5rem;
  transition: all 0.3s;
}

.threat-card.critical {
  border-color: #ff4757;
}

.threat-card.high {
  border-color: #ffa502;
}

.threat-card.medium {
  border-color: #ffd32a;
}

.threat-card.low {
  border-color: #2ecc71;
}

.threat-card:hover {
  transform: translateX(4px);
  box-shadow: -4px 0 8px rgba(0, 217, 255, 0.2);
}

.threat-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 1rem;
  padding-bottom: 1rem;
  border-bottom: 1px solid #2a2a3e;
}

.threat-title {
  display: flex;
  align-items: center;
  gap: 0.75rem;
}

.threat-icon {
  font-size: 1.5rem;
}

.threat-title h3 {
  color: #fff;
  font-size: 1.25rem;
  margin: 0;
}

.threat-badge {
  padding: 0.25rem 0.75rem;
  border-radius: 12px;
  font-size: 0.75rem;
  font-weight: bold;
  text-transform: uppercase;
}

.threat-badge.critical {
  background: rgba(255, 71, 87, 0.2);
  color: #ff4757;
}

.threat-badge.high {
  background: rgba(255, 165, 2, 0.2);
  color: #ffa502;
}

.threat-badge.medium {
  background: rgba(255, 211, 42, 0.2);
  color: #ffd32a;
}

.threat-badge.low {
  background: rgba(46, 204, 113, 0.2);
  color: #2ecc71;
}

.threat-time {
  color: #888;
  font-size: 0.875rem;
}

.threat-body {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.threat-info {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 0.75rem;
}

.info-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.label {
  color: #888;
  font-size: 0.875rem;
}

.value {
  color: #00d9ff;
  font-weight: 500;
}

.monospace {
  font-family: 'Courier New', monospace;
  font-size: 0.875rem;
}

.threat-explanation {
  padding: 1rem;
  background: rgba(0, 217, 255, 0.05);
  border-left: 3px solid #00d9ff;
  border-radius: 4px;
}

.explanation-text {
  color: #e0e0e0;
  line-height: 1.5;
  margin: 0;
}

.threat-factors h4,
.threat-actions-section h4 {
  color: #888;
  font-size: 0.875rem;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  margin-bottom: 0.5rem;
}

.factors-list {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
}

.factor-tag {
  padding: 0.375rem 0.75rem;
  background: #1a1a2e;
  border: 1px solid #2a2a3e;
  border-radius: 4px;
  font-size: 0.875rem;
  color: #e0e0e0;
}

.actions-list {
  list-style: none;
  padding: 0;
}

.actions-list li {
  padding: 0.5rem 0;
  border-bottom: 1px solid #2a2a3e;
  color: #e0e0e0;
}

.actions-list li:last-child {
  border-bottom: none;
}

.actions-list li::before {
  content: '→';
  margin-right: 0.5rem;
  color: #00d9ff;
}

.threat-footer {
  display: flex;
  gap: 1rem;
  margin-top: 1rem;
  padding-top: 1rem;
  border-top: 1px solid #2a2a3e;
  flex-wrap: wrap;
}

.btn {
  padding: 0.5rem 1rem;
  border: none;
  border-radius: 4px;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
  flex: 1;
  min-width: 120px;
}

.btn-primary {
  background: #00d9ff;
  color: #0f0f1e;
}

.btn-primary:hover {
  background: #00b8d4;
}

.btn-danger {
  background: #ff4757;
  color: #fff;
}

.btn-danger:hover {
  background: #ff3838;
}

.btn-secondary {
  background: transparent;
  border: 1px solid #2a2a3e;
  color: #e0e0e0;
}

.btn-secondary:hover {
  background: #1a1a2e;
  border-color: #3a3a4e;
}

@media (max-width: 768px) {
  .threat-info {
    grid-template-columns: 1fr;
  }

  .threat-footer {
    flex-direction: column;
  }

  .btn {
    width: 100%;
  }
}
</style>
