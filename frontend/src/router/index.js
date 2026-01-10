import { createRouter, createWebHistory } from 'vue-router'

const routes = [
  {
    path: '/',
    name: 'dashboard',
    component: () => import('../views/DashboardView.vue')
  },
  {
    path: '/findings',
    name: 'findings',
    component: () => import('../views/FindingsView.vue')
  },
  {
    path: '/findings/:id',
    name: 'finding-detail',
    component: () => import('../views/FindingDetailView.vue'),
    props: true
  },
  {
    path: '/attack-paths',
    name: 'attack-paths',
    component: () => import('../views/AttackPathsView.vue')
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

export default router
