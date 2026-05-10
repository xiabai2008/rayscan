import axios from 'axios'
import { ElMessage } from 'element-plus'
import { getToken, removeToken } from '@/utils/auth'
import router from '@/router'

// 创建axios实例
const service = axios.create({
  baseURL: process.env.VUE_APP_API_BASE_URL || '/api',
  timeout: 30000, // 30秒超时
  headers: {
    'Content-Type': 'application/json'
  }
})

// 请求拦截器
service.interceptors.request.use(
  config => {
    // 添加token到请求头
    const token = getToken()
    if (token) {
      config.headers['Authorization'] = `Bearer ${token}`
    }
    return config
  },
  error => {
    console.error('请求错误:', error)
    return Promise.reject(error)
  }
)

// 响应拦截器
service.interceptors.response.use(
  response => {
    const res = response.data

    // 如果返回的状态码不是200，则判断为错误
    if (response.status !== 200) {
      ElMessage.error(res.message || '请求失败')
      return Promise.reject(new Error(res.message || '请求失败'))
    }

    return res
  },
  error => {
    console.error('响应错误:', error)

    if (error.response) {
      const { status, data } = error.response

      switch (status) {
        case 400:
          ElMessage.error(data.detail || '请求参数错误')
          break
        case 401:
          ElMessage.error('登录已过期，请重新登录')
          removeToken()
          router.push('/login')
          break
        case 403:
          ElMessage.error('没有权限访问')
          break
        case 404:
          ElMessage.error('请求的资源不存在')
          break
        case 500:
          ElMessage.error(data.detail || '服务器内部错误')
          break
        case 502:
          ElMessage.error('网关错误')
          break
        case 503:
          ElMessage.error('服务不可用')
          break
        case 504:
          ElMessage.error('网关超时')
          break
        default:
          ElMessage.error(error.message || '请求失败')
      }
    } else if (error.request) {
      ElMessage.error('网络错误，请检查网络连接')
    } else {
      ElMessage.error(error.message || '请求失败')
    }

    return Promise.reject(error)
  }
)

// 通用请求方法
export const request = {
  get(url, params = {}) {
    return service.get(url, { params })
  },

  post(url, data = {}) {
    return service.post(url, data)
  },

  put(url, data = {}) {
    return service.put(url, data)
  },

  delete(url, params = {}) {
    return service.delete(url, { params })
  },

  patch(url, data = {}) {
    return service.patch(url, data)
  }
}

export default service