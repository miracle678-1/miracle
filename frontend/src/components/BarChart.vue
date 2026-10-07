<template>
  <!-- 垂直柱状图 -->
  <div v-if="!horizontal" class="vchart">
    <div v-for="(v, i) in values" :key="i" class="vcol">
      <div class="vnum">{{ format(v) }}</div>
      <div class="vtrack">
        <div class="vfill" :style="{ height: pct(v), background: color }"></div>
      </div>
      <div class="vtick" :title="labels[i]">{{ labels[i] }}</div>
    </div>
  </div>

  <!-- 水平柱状图 -->
  <div v-else class="hchart">
    <div v-for="(v, i) in values" :key="i" class="hrow">
      <div class="hlabel" :title="labels[i]">{{ labels[i] }}</div>
      <div class="htrack">
        <div class="hfill" :style="{ width: pct(v), background: color }"></div>
      </div>
      <div class="hnum">{{ format(v) }}</div>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  labels: { type: Array, default: () => [] },
  values: { type: Array, default: () => [] },
  color: { type: String, default: '#2563eb' },
  horizontal: { type: Boolean, default: false }
})

const max = computed(() => Math.max(1, ...props.values))

function pct(v) {
  return ((Number(v) || 0) / max.value) * 100 + '%'
}

function format(n) {
  return (Number(n) || 0).toLocaleString('zh-CN')
}
</script>

<style scoped>
.vchart {
  display: flex;
  align-items: flex-end;
  gap: 12px;
  height: 260px;
  padding-top: 8px;
}
.vcol {
  flex: 1;
  display: flex;
  flex-direction: column;
  align-items: center;
  height: 100%;
}
.vnum {
  font-size: 11px;
  color: #6b7280;
  margin-bottom: 4px;
  white-space: nowrap;
}
.vtrack {
  flex: 1;
  width: 100%;
  max-width: 48px;
  display: flex;
  align-items: flex-end;
  border-radius: 4px;
  background: #f3f4f6;
}
.vfill {
  width: 100%;
  border-radius: 4px;
  transition: height 0.3s;
}
.vtick {
  margin-top: 6px;
  font-size: 11px;
  color: #4b5563;
  text-align: center;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  max-width: 100%;
}

.hchart {
  display: flex;
  flex-direction: column;
  gap: 10px;
  height: 260px;
  justify-content: center;
}
.hrow {
  display: flex;
  align-items: center;
  gap: 10px;
}
.hlabel {
  width: 130px;
  text-align: right;
  font-size: 12px;
  color: #374151;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.htrack {
  flex: 1;
  height: 16px;
  background: #f3f4f6;
  border-radius: 4px;
  overflow: hidden;
}
.hfill {
  height: 100%;
  border-radius: 4px;
  transition: width 0.3s;
}
.hnum {
  width: 90px;
  font-size: 12px;
  color: #6b7280;
}
</style>
