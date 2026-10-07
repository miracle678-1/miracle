<template>
  <div class="cards">
    <div class="card">
      <div class="label">数据包总数</div>
      <div class="value">{{ formatNumber(overview.totalPackets) }}</div>
    </div>
    <div class="card">
      <div class="label">总流量</div>
      <div class="value">{{ formatBytes(overview.totalBytes) }}</div>
    </div>
    <div class="card">
      <div class="label">独立 IP 数</div>
      <div class="value">{{ overview.uniqueIpCount }}</div>
    </div>
    <div class="card">
      <div class="label">攻击类型</div>
      <div class="value small">{{ attackTypes }}</div>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  overview: { type: Object, default: () => ({}) }
})

const attackTypes = computed(() => {
  const labels = props.overview.attackLabels || {}
  const values = [...new Set(Object.values(labels))]
  return values.length ? values.join('、') : '-'
})

function formatNumber(n) {
  return (n || 0).toLocaleString('zh-CN')
}

function formatBytes(bytes) {
  const b = Number(bytes) || 0
  if (b >= 1024 * 1024 * 1024) return (b / 1024 / 1024 / 1024).toFixed(2) + ' GB'
  if (b >= 1024 * 1024) return (b / 1024 / 1024).toFixed(2) + ' MB'
  if (b >= 1024) return (b / 1024).toFixed(2) + ' KB'
  return b + ' B'
}
</script>

<style scoped>
.value.small {
  font-size: 15px;
  line-height: 1.4;
}
</style>
