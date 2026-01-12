<template>
  <div class="chart-container">
    <h3 class="chart-title">
      {{ title }}
    </h3>
    <div class="chart-wrapper">
      <Doughnut
        v-if="chartData.labels.length > 0"
        :data="chartData"
        :options="chartOptions"
      />
      <div
        v-else
        class="no-data"
      >
        No data available
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { Doughnut } from 'vue-chartjs'
import {
  Chart as ChartJS,
  ArcElement,
  Tooltip,
  Legend,
} from 'chart.js'

ChartJS.register(ArcElement, Tooltip, Legend)

const props = defineProps({
  title: {
    type: String,
    default: 'Findings by Severity',
  },
  data: {
    type: Array,
    default: () => [],
  },
})

const chartData = computed(() => ({
  labels: props.data.map(item => item.label),
  datasets: [{
    data: props.data.map(item => item.value),
    backgroundColor: props.data.map(item => item.color || '#667eea'),
    borderWidth: 0,
  }],
}))

const chartOptions = {
  responsive: true,
  maintainAspectRatio: false,
  plugins: {
    legend: {
      position: 'right',
      labels: {
        padding: 20,
        usePointStyle: true,
        font: {
          size: 12,
        },
      },
    },
    tooltip: {
      callbacks: {
        label: (context) => {
          const total = context.dataset.data.reduce((a, b) => a + b, 0)
          const percentage = ((context.raw / total) * 100).toFixed(1)
          return `${context.label}: ${context.raw} (${percentage}%)`
        },
      },
    },
  },
  cutout: '60%',
}
</script>

<style scoped>
.chart-container {
  background: var(--bg-secondary);
  border-radius: var(--radius-md);
  padding: var(--spacing-lg);
  box-shadow: var(--shadow-md);
}

.chart-title {
  font-size: 1rem;
  font-weight: 600;
  margin-bottom: var(--spacing-md);
  color: var(--text-primary);
}

.chart-wrapper {
  height: 250px;
  display: flex;
  align-items: center;
  justify-content: center;
}

.no-data {
  color: var(--text-secondary);
  font-style: italic;
}
</style>
