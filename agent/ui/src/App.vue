<template>
  <div id="app">
    <header class="app-header">
      <div class="header-content">
        <h1>
          <span class="icon">🛡️</span>
          Agentic NIDS
        </h1>
        <p class="subtitle">Network Intrusion Detection System</p>
      </div>
      <div class="header-stats">
        <div class="stat-item">
          <span class="stat-label">Active Threats</span>
          <span class="stat-value critical">{{ activeThreats }}</span>
        </div>
        <div class="stat-item">
          <span class="stat-label">Monitored Flows</span>
          <span class="stat-value">{{ monitoredFlows }}</span>
        </div>
        <div class="stat-item">
          <span class="stat-label">Status</span>
          <span class="stat-value" :class="systemStatus">{{ systemStatus }}</span>
        </div>
      </div>
    </header>

    <main class="app-main">
      <router-view />
    </main>
  </div>
</template>

<script>
export default {
  name: 'App',
  data() {
    return {
      activeThreats: 0,
      monitoredFlows: 0,
      systemStatus: 'active'
    }
  },
  mounted() {
    this.updateStats()
    // Update stats every 5 seconds
    setInterval(this.updateStats, 5000)
  },
  methods: {
    updateStats() {
      // Simulate stats update (will be replaced with API call)
      this.monitoredFlows = Math.floor(Math.random() * 10000) + 5000
      this.activeThreats = Math.floor(Math.random() * 10)
    }
  }
}
</script>

<style>
* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

body {
  font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
  background: #0f0f1e;
  color: #e0e0e0;
}

#app {
  min-height: 100vh;
  display: flex;
  flex-direction: column;
}

.app-header {
  background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
  padding: 2rem;
  box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
  border-bottom: 2px solid #2a2a3e;
}

.header-content {
  margin-bottom: 1.5rem;
}

.header-content h1 {
  font-size: 2.5rem;
  color: #00d9ff;
  margin-bottom: 0.5rem;
  display: flex;
  align-items: center;
  gap: 1rem;
}

.icon {
  font-size: 2rem;
}

.subtitle {
  color: #888;
  font-size: 1rem;
  margin-left: 3.5rem;
}

.header-stats {
  display: flex;
  gap: 2rem;
  flex-wrap: wrap;
}

.stat-item {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.stat-label {
  font-size: 0.875rem;
  color: #888;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.stat-value {
  font-size: 1.5rem;
  font-weight: bold;
  color: #00d9ff;
}

.stat-value.critical {
  color: #ff4757;
  animation: pulse 2s infinite;
}

.stat-value.active {
  color: #2ecc71;
}

@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.6; }
}

.app-main {
  flex: 1;
  padding: 2rem;
  max-width: 1400px;
  width: 100%;
  margin: 0 auto;
}

@media (max-width: 768px) {
  .app-header {
    padding: 1rem;
  }

  .header-content h1 {
    font-size: 1.75rem;
  }

  .header-stats {
    flex-direction: column;
    gap: 1rem;
  }

  .app-main {
    padding: 1rem;
  }
}
</style>
