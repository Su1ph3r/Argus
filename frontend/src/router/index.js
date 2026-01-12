import { createRouter, createWebHistory } from 'vue-router'

const routes = [
  {
    path: '/',
    name: 'dashboard',
    component: () => import('../views/DashboardView.vue'),
  },
  {
    path: '/compliance',
    name: 'compliance',
    component: () => import('../views/ComplianceView.vue'),
  },
  {
    path: '/findings',
    name: 'findings',
    component: () => import('../views/FindingsView.vue'),
  },
  {
    path: '/findings/:id',
    name: 'finding-detail',
    component: () => import('../views/FindingDetailView.vue'),
    props: true,
  },
  {
    path: '/attack-paths',
    name: 'attack-paths',
    component: () => import('../views/AttackPathsView.vue'),
  },
  // Pentest feature routes
  {
    path: '/public-exposures',
    name: 'public-exposures',
    component: () => import('../views/PublicExposuresView.vue'),
  },
  {
    path: '/exposed-credentials',
    name: 'exposed-credentials',
    component: () => import('../views/ExposedCredentialsView.vue'),
  },
  {
    path: '/severity-overrides',
    name: 'severity-overrides',
    component: () => import('../views/SeverityOverridesView.vue'),
  },
  {
    path: '/privesc-paths',
    name: 'privesc-paths',
    component: () => import('../views/PrivescPathsView.vue'),
  },
  {
    path: '/imds-checks',
    name: 'imds-checks',
    component: () => import('../views/ImdsChecksView.vue'),
  },
  {
    path: '/cloudfox',
    name: 'cloudfox',
    component: () => import('../views/CloudfoxView.vue'),
  },
  {
    path: '/pacu',
    name: 'pacu',
    component: () => import('../views/PacuView.vue'),
  },
  {
    path: '/enumerate-iam',
    name: 'enumerate-iam',
    component: () => import('../views/EnumerateIamView.vue'),
  },
  {
    path: '/assumed-roles',
    name: 'assumed-roles',
    component: () => import('../views/AssumedRolesView.vue'),
  },
  {
    path: '/lambda-analysis',
    name: 'lambda-analysis',
    component: () => import('../views/LambdaAnalysisView.vue'),
  },
  {
    path: '/credentials',
    name: 'credentials',
    component: () => import('../views/CredentialsView.vue'),
  },
  // Configuration routes
  {
    path: '/scans',
    name: 'scans',
    component: () => import('../views/ScansView.vue'),
  },
  {
    path: '/scans/:id',
    name: 'scan-detail',
    component: () => import('../views/ScanDetailView.vue'),
    props: true,
  },
  {
    path: '/settings',
    name: 'settings',
    component: () => import('../views/SettingsView.vue'),
  },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

export default router
