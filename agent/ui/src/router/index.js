import { createRouter, createWebHistory } from 'vue-router'
import ThreatDashboard from '../views/ThreatDashboard.vue'

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: [
    {
      path: '/',
      name: 'dashboard',
      component: ThreatDashboard
    }
  ]
})

export default router
