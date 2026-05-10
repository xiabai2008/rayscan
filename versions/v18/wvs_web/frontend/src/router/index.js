import { createRouter, createWebHistory } from 'vue-router'
import { useAuthStore } from '@/store/auth'

// 懒加载组件
const Login = () => import('@/views/Login.vue')
const Layout = () => import('@/layouts/Layout.vue')
const Dashboard = () => import('@/views/dashboard/Dashboard.vue')
const ScanTasks = () => import('@/views/scans/ScanTasks.vue')
const ScanTaskDetail = () => import('@/views/scans/ScanTaskDetail.vue')
const ScanTaskCreate = () => import('@/views/scans/ScanTaskCreate.vue')
const Vulnerabilities = () => import('@/views/vulnerabilities/Vulnerabilities.vue')
const VulnerabilityDetail = () => import('@/views/vulnerabilities/VulnerabilityDetail.vue')
const Reports = () => import('@/views/reports/Reports.vue')
const Config = () => import('@/views/config/Config.vue')
const Profile = () => import('@/views/profile/Profile.vue')
const Users = () => import('@/views/users/Users.vue')

const routes = [
  {
    path: '/login',
    name: 'Login',
    component: Login,
    meta: { requiresAuth: false }
  },
  {
    path: '/',
    component: Layout,
    redirect: '/dashboard',
    meta: { requiresAuth: true },
    children: [
      {
        path: 'dashboard',
        name: 'Dashboard',
        component: Dashboard,
        meta: { title: '仪表板', icon: 'dashboard' }
      },
      {
        path: 'scans',
        name: 'ScanTasks',
        component: ScanTasks,
        meta: { title: '扫描任务', icon: 'scan' }
      },
      {
        path: 'scans/create',
        name: 'ScanTaskCreate',
        component: ScanTaskCreate,
        meta: { title: '创建扫描任务', hidden: true }
      },
      {
        path: 'scans/:id',
        name: 'ScanTaskDetail',
        component: ScanTaskDetail,
        meta: { title: '扫描任务详情', hidden: true }
      },
      {
        path: 'vulnerabilities',
        name: 'Vulnerabilities',
        component: Vulnerabilities,
        meta: { title: '漏洞管理', icon: 'bug' }
      },
      {
        path: 'vulnerabilities/:id',
        name: 'VulnerabilityDetail',
        component: VulnerabilityDetail,
        meta: { title: '漏洞详情', hidden: true }
      },
      {
        path: 'reports',
        name: 'Reports',
        component: Reports,
        meta: { title: '报告管理', icon: 'document' }
      },
      {
        path: 'config',
        name: 'Config',
        component: Config,
        meta: { title: '系统配置', icon: 'setting' }
      },
      {
        path: 'profile',
        name: 'Profile',
        component: Profile,
        meta: { title: '个人中心', hidden: true }
      },
      {
        path: 'users',
        name: 'Users',
        component: Users,
        meta: { title: '用户管理', icon: 'user', requiresAdmin: true }
      }
    ]
  },
  {
    path: '/:pathMatch(.*)*',
    redirect: '/dashboard'
  }
]

const router = createRouter({
  history: createWebHistory(process.env.BASE_URL),
  routes
})

// 路由守卫
router.beforeEach(async (to, from, next) => {
  const authStore = useAuthStore()

  // 检查是否需要认证
  if (to.meta.requiresAuth === false) {
    next()
    return
  }

  // 检查用户是否已登录
  if (!authStore.isAuthenticated) {
    // 尝试从本地存储恢复token
    await authStore.restoreAuth()

    if (!authStore.isAuthenticated) {
      // 重定向到登录页
      next('/login')
      return
    }
  }

  // 检查是否需要管理员权限
  if (to.meta.requiresAdmin && !authStore.user?.is_superuser) {
    // 无权限访问
    next('/dashboard')
    return
  }

  // 设置页面标题
  if (to.meta.title) {
    document.title = `${to.meta.title} - WVS管理平台`
  }

  next()
})

export default router