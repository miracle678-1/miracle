<template>
  <div class="pie-layout">
    <div class="pie" :style="{ background: gradient }">
      <div class="pie-hole"></div>
    </div>
    <div class="legend">
      <div v-for="(d, i) in data" :key="i" class="legend-item">
        <span class="dot" :style="{ background: colorAt(i) }"></span>
        <span class="name">{{ d.name }}</span>
        <span class="val">{{ format(d.value) }} · {{ percent(d.value) }}%</span>
      </div>
      <div v-if="!data.length" class="empty">暂无数据</div>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  data: { type: Array, default: () => [] },
  colors: { type: Array, default: () => ['#2563eb', '#059669', '#d97706', '#7c3aed', '#0e7490', '#dc2626', '#6b7280'] }
})

const total = computed(() => props.data.reduce((s, d) => s + (Number(d.value) || 0), 0))

const gradient = computed(() => {
  if (!total.value) return '#f3f4f6'
  let acc = 0
  const stops = props.data.map((d, i) => {
    const start = acc
    acc += ((Number(d.value) || 0) / total.value) * 360
    return `${colorAt(i)} ${start}deg ${acc}deg`
  })
  return `conic-gradient(${stops.join(', ')})`
})

function colorAt(i) {
  return props.colors[i % props.colors.length]
}

function percent(v) {
  if (!total.value) return 0
  return (((Number(v) || 0) / total.value) * 100).toFixed(1)
}

function format(n) {
  return (Number(n) || 0).toLocaleString('zh-CN')
}
</script>

<style scoped>
.pie-layout {
  display: flex;
  align-items: center;
  gap: 24px;
  min-height: 260px;
}
.pie {
  width: 200px;
  height: 200px;
  border-radius: 50%;
  flex-shrink: 0;
  position: relative;
}
.pie-hole {
  position: absolute;
  inset: 0;
  margin: auto;
  width: 90px;
  height: 90px;
  background: #fff;
  border-radius: 50%;
}
.legend {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.legend-item {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 13px;
}
.dot {
  width: 12px;
  height: 12px;
  border-radius: 3px;
  flex-shrink: 0;
}
.name {
  width: 60px;
  color: #374151;
}
.val {
  color: #6b7280;
}
.empty {
  color: #9ca3af;
  font-size: 13px;
}
</style>
