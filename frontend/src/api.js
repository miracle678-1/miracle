import axios from 'axios'

const http = axios.create({
  baseURL: '/api',
  timeout: 60000
})

export async function fetchStats() {
  const { data } = await http.get('/stats')
  return data
}

export async function fetchPackets(page = 0, size = 20) {
  const { data } = await http.get('/packets', { params: { page, size } })
  return data
}
