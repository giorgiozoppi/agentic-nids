<template>
  <div class="threat-dashboard">
    <!-- Real-time Alert Banner -->
    <div v-if="latestThreat" class="alert-banner" :class="latestThreat.risk_level">
      <div class="alert-content">
        <span class="alert-icon">⚠️</span>
        <div class="alert-text">
          <strong>{{ latestThreat.attack_type.toUpperCase() }} DETECTED</strong>
          <span>{{ latestThreat.flow_id }} - Risk: {{ latestThreat.risk_level }}</span>
        </div>
      </div>
      <button @click="dismissAlert" class="dismiss-btn">×</button>
    </div>

    <!-- Statistics Cards -->
    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-icon critical">🔴</div>
        <div class="stat-info">
          <h3>Critical Threats</h3>
          <p class="stat-number">{{ stats.critical }}</p>
        </div>
      </div>

      <div class="stat-card">
        <div class="stat-icon high">🟠</div>
        <div class="stat-info">
          <h3>High Risk</h3>
          <p class="stat-number">{{ stats.high }}</p>
        </div>
      </div>

      <div class="stat-card">
        <div class="stat-icon medium">🟡</div>
        <div class="stat-info">
          <h3>Medium Risk</h3>
          <p class="stat-number">{{ stats.medium }}</p>
        </div>
      </div>

      <div class="stat-card">
        <div class="stat-icon low">🟢</div>
        <div class="stat-info">
          <h3>Low Risk</h3>
          <p class="stat-number">{{ stats.low }}</p>
        </div>
      </div>
    </div>

    <!-- Threat List -->
    <div class="threat-section">
      <div class="section-header">
        <h2>🚨 Active Threats</h2>
        <div class="filter-controls">
          <select v-model="filterLevel" class="filter-select">
            <option value="all">All Levels</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <button @click="refreshThreats" class="refresh-btn">🔄 Refresh</button>
        </div>
      </div>

      <div class="threat-list">
        <ThreatCard
          v-for="threat in filteredThreats"
          :key="threat.id"
          :threat="threat"
          @investigate="investigateThreat"
          @block="blockThreat"
        />
      </div>

      <div v-if="filteredThreats.length === 0" class="no-threats">
        <span class="icon">✓</span>
        <p>No active threats detected</p>
      </div>
    </div>
  </div>
</template>

<script>
import ThreatCard from '../components/ThreatCard.vue'
import { generateDemoThreats } from '../services/demoData'

export default {
  name: 'ThreatDashboard',
  components: {
    ThreatCard
  },
  data() {
    return {
      threats: [],
      filterLevel: 'all',
      latestThreat: null,
      stats: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0
      }
    }
  },
  computed: {
    filteredThreats() {
      if (this.filterLevel === 'all') {
        return this.threats
      }
      return this.threats.filter(t => t.risk_level === this.filterLevel)
    }
  },
  mounted() {
    this.loadThreats()
    // Auto-refresh every 10 seconds
    this.refreshInterval = setInterval(this.refreshThreats, 10000)
  },
  beforeUnmount() {
    if (this.refreshInterval) {
      clearInterval(this.refreshInterval)
    }
  },
  methods: {
    loadThreats() {
      // Load demo threats (will be replaced with API call)
      this.threats = generateDemoThreats(20)
      this.updateStats()

      // Show latest critical/high threat as banner
      const criticalThreats = this.threats.filter(
        t => t.risk_level === 'critical' || t.risk_level === 'high'
      )
      if (criticalThreats.length > 0) {
        this.latestThreat = criticalThreats[0]
      }
    },
    refreshThreats() {
      // Simulate new threat detection
      const newThreat = generateDemoThreats(1)[0]
      if (newThreat.risk_level === 'critical' || newThreat.risk_level === 'high') {
        this.threats.unshift(newThreat)
        this.latestThreat = newThreat
        this.updateStats()

        // Keep only last 50 threats
        if (this.threats.length > 50) {
          this.threats = this.threats.slice(0, 50)
        }
      }
    },
    updateStats() {
      this.stats = {
        critical: this.threats.filter(t => t.risk_level === 'critical').length,
        high: this.threats.filter(t => t.risk_level === 'high').length,
        medium: this.threats.filter(t => t.risk_level === 'medium').length,
        low: this.threats.filter(t => t.risk_level === 'low').length
      }
    },
    dismissAlert() {
      this.latestThreat = null
    },
    investigateThreat(threat) {
      console.log('Investigating threat:', threat)
      // TODO: Open investigation modal/view
    },
    blockThreat(threat) {
      console.log('Blocking threat:', threat)
      // TODO: Call API to block IP
      alert(`Blocking IP: ${threat.flow_id.split(':')[0]}`)
    }
  }
}
</script>

<style scoped>
.threat-dashboard {
  display: flex;
  flex-direction: column;
  gap: 2rem;
}

/* Alert Banner */
.alert-banner {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 1rem 1.5rem;
  border-radius: 8px;
  border-left: 4px solid;
  animation: slideIn 0.5s ease-out;
}

@keyframes slideIn {
  from {
    transform: translateY(-20px);
    opacity: 0;
  }
  to {
    transform: translateY(0);
    opacity: 1;
  }
}

.alert-banner.critical {
  background: rgba(255, 71, 87, 0.2);
  border-color: #ff4757;
}

.alert-banner.high {
  background: rgba(255, 165, 2, 0.2);
  border-color: #ffa502;
}

.alert-content {
  display: flex;
  align-items: center;
  gap: 1rem;
}

.alert-icon {
  font-size: 1.5rem;
}

.alert-text {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}

.alert-text strong {
  color: #fff;
  font-size: 1.1rem;
}

.alert-text span {
  color: #ccc;
  font-size: 0.9rem;
}

.dismiss-btn {
  background: transparent;
  border: none;
  color: #fff;
  font-size: 2rem;
  cursor: pointer;
  padding: 0 0.5rem;
  transition: opacity 0.2s;
}

.dismiss-btn:hover {
  opacity: 0.7;
}

/* Stats Grid */
.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 1.5rem;
}

.stat-card {
  background: #1a1a2e;
  border: 1px solid #2a2a3e;
  border-radius: 8px;
  padding: 1.5rem;
  display: flex;
  align-items: center;
  gap: 1rem;
  transition: transform 0.2s;
}

.stat-card:hover {
  transform: translateY(-2px);
  border-color: #3a3a4e;
}

.stat-icon {
  font-size: 2.5rem;
}

.stat-info h3 {
  font-size: 0.875rem;
  color: #888;
  margin-bottom: 0.5rem;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.stat-number {
  font-size: 2rem;
  font-weight: bold;
  color: #00d9ff;
}

/* Threat Section */
.threat-section {
  background: #1a1a2e;
  border: 1px solid #2a2a3e;
  border-radius: 8px;
  padding: 1.5rem;
}

.section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 1.5rem;
  flex-wrap: wrap;
  gap: 1rem;
}

.section-header h2 {
  color: #00d9ff;
  font-size: 1.5rem;
}

.filter-controls {
  display: flex;
  gap: 1rem;
}

.filter-select {
  padding: 0.5rem 1rem;
  background: #0f0f1e;
  border: 1px solid #2a2a3e;
  border-radius: 4px;
  color: #e0e0e0;
  cursor: pointer;
}

.refresh-btn {
  padding: 0.5rem 1rem;
  background: #00d9ff;
  border: none;
  border-radius: 4px;
  color: #0f0f1e;
  font-weight: bold;
  cursor: pointer;
  transition: background 0.2s;
}

.refresh-btn:hover {
  background: #00b8d4;
}

.threat-list {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.no-threats {
  text-align: center;
  padding: 3rem;
  color: #888;
}

.no-threats .icon {
  font-size: 3rem;
  color: #2ecc71;
  display: block;
  margin-bottom: 1rem;
}

.no-threats p {
  font-size: 1.1rem;
}

@media (max-width: 768px) {
  .stats-grid {
    grid-template-columns: 1fr;
  }

  .section-header {
    flex-direction: column;
    align-items: flex-start;
  }

  .filter-controls {
    width: 100%;
  }

  .filter-select,
  .refresh-btn {
    flex: 1;
  }
}
</style>
