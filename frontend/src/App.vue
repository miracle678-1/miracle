<template>
  <div class="page">
    <div class="header">
      <h1>基于网络流量的网络攻击检测可视化</h1>
      <p>基于 DPI 思想解析 pcap 抓包文件，提取五元组信息并统计可视化</p>
    </div>

    <div v-if="error" class="error">{{ error }}</div>

    <SummaryCards :overview="stats.overview || {}" />

    <div class="chart-grid">
      <div class="panel">
        <h3>协议类型及流量数量</h3>
        <PieChart :data="protocolData" :colors="palette" />
      </div>
      <div class="panel">
        <h3>数据包大小及流量数量</h3>
        <BarChart :labels="sizeLabels" :values="sizeValues" color="#2563eb" />
      </div>
      <div class="panel">
        <h3>异常端口流量统计（445 / 136 / 137 / 138 / 139）</h3>
        <BarChart :labels="portLabels" :values="portValues" color="#dc2626" />
      </div>
      <div class="panel">
        <h3>按 IP 地址统计流量（Top 20）</h3>
        <BarChart :labels="ipLabels" :values="ipValues" color="#059669" horizontal />
      </div>
    </div>

    <PacketTable />
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { fetchStats } from './api'
import SummaryCards from './components/SummaryCards.vue'
import PieChart from './components/PieChart.vue'
import BarChart from './components/BarChart.vue'
import PacketTable from './components/PacketTable.vue'

const stats = ref({ overview: {}, protocol: [], size: [], port: [], ip: [] })
const error = ref('')

const palette = ['#2563eb', '#059669', '#d97706', '#7c3aed', '#0e7490', '#dc2626', '#6b7280']

const protocolData = computed(() =>
  stats.value.protocol.map((p) => ({ name: p.name, value: p.count }))
)
const sizeLabels = computed(() => stats.value.size.map((s) => s.range))
const sizeValues = computed(() => stats.value.size.map((s) => s.count))
const portLabels = computed(() => stats.value.port.map((p) => String(p.port)))
const portValues = computed(() => stats.value.port.map((p) => p.count))
const ipLabels = computed(() => [...stats.value.ip].reverse().map((i) => i.ip))
const ipValues = computed(() => [...stats.value.ip].reverse().map((i) => i.packets))

onMounted(async () => {
  try {
    stats.value = await fetchStats()
  } catch (e) {
    error.value = '无法连接后端服务，请确认 Spring Boot 已启动（端口 8081）：' + e.message
  }
})
</script>
