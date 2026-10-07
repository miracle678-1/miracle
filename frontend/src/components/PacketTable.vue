<template>
  <div class="table-panel">
    <h3 style="margin-bottom: 12px">数据包五元组信息</h3>

    <table>
      <thead>
        <tr>
          <th>时间</th>
          <th>源 IP</th>
          <th>源端口</th>
          <th>目的 IP</th>
          <th>目的端口</th>
          <th>协议</th>
          <th>长度</th>
          <th>攻击类型</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="(p, i) in items" :key="i">
          <td>{{ formatTime(p.timestamp) }}</td>
          <td>{{ p.srcIp }}</td>
          <td>{{ p.srcPort || '-' }}</td>
          <td>{{ p.dstIp }}</td>
          <td>{{ p.dstPort || '-' }}</td>
          <td>
            <span :class="'tag ' + tagClass(p.protocol)">{{ p.protocol }}</span>
          </td>
          <td>{{ p.length }}</td>
          <td>{{ p.attackType }}</td>
        </tr>
        <tr v-if="!items.length">
          <td colspan="8" style="text-align: center; color: #9ca3af">暂无数据</td>
        </tr>
      </tbody>
    </table>

    <div class="pagination">
      <button :disabled="page <= 0" @click="go(page - 1)">上一页</button>
      <span>第 {{ page + 1 }} / {{ totalPages }} 页</span>
      <button :disabled="page >= totalPages - 1" @click="go(page + 1)">下一页</button>
      <span style="margin-left: auto">共 {{ total }} 条</span>
    </div>

    <div v-if="sampled" class="hint">
      注：仅展示抓包文件前 {{ total }} 个采样数据包（总流量 {{ formatNumber(totalPackets) }} 个数据包），
      统计图表基于全部数据包计算。
    </div>
  </div>
</template>

<script setup>
import { onMounted, ref } from 'vue'
import { fetchPackets } from '../api'

const items = ref([])
const page = ref(0)
const size = 20
const total = ref(0)
const totalPages = ref(1)
const sampled = ref(false)
const totalPackets = ref(0)

async function load() {
  const data = await fetchPackets(page.value, size)
  items.value = data.items || []
  total.value = data.total
  totalPackets.value = data.totalPackets
  sampled.value = data.sampled
  totalPages.value = Math.max(1, Math.ceil(data.total / data.size))
}

function go(p) {
  page.value = Math.max(0, p)
  load()
}

function formatTime(ts) {
  if (!ts) return '-'
  const d = new Date(ts)
  return d.toLocaleString('zh-CN', { hour12: false })
}

function formatNumber(n) {
  return (n || 0).toLocaleString('zh-CN')
}

function tagClass(protocol) {
  return (protocol || '').toLowerCase()
}

onMounted(load)
</script>

<style scoped>
.tag {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 10px;
  font-size: 12px;
  color: #fff;
}
.tag.tcp {
  background: #2563eb;
}
.tag.udp {
  background: #059669;
}
.tag.icmp {
  background: #d97706;
}
.tag.arp {
  background: #7c3aed;
}
.tag.ipv6 {
  background: #0e7490;
}
.tag.other {
  background: #6b7280;
}
</style>
