<script>
  import { link, location } from 'svelte-spa-router';
  import { writable } from 'svelte/store';
  import { onMount, onDestroy } from 'svelte';
  import { push } from 'svelte-spa-router';
  import axios from 'axios';
  import { isAuthenticated, authLoading, currentUser, isAdmin, hasPermission, setAuthenticatedUser, resetAuth } from './stores/auth.js';
  
  // State variables
  let isMobileMenuOpen = writable(false);
  let isSidebarCollapsed = writable(false);
  let authCheckInterval;
  let navItems = [];
  
  // WebSocket management
  let ws = null;
  let wsConnected = false;
  let wsReconnectAttempts = 0;
  const maxReconnectAttempts = 5;
  
  // Dynamic navigation items based on user permissions
  $: {
    // Ensure we always have at least the basic navigation when authenticated
    if ($currentUser) {
      // Base navigation items for all authenticated users
      let baseNavItems = [
        { name: 'dashboard', label: 'Dashboard', href: '/', permission: null, icon: '🏠' }
      ];
      
      // Add role-specific navigation items
      if (hasPermission('manual_testing')) {
        baseNavItems.push({ name: 'manual-testing', label: 'Manual Testing', href: '/manual-testing', permission: 'manual_testing', icon: '🧪' });
      }
      
      if (hasPermission('view_reports')) {
        baseNavItems.push({ name: 'reports', label: 'Reports', href: '/reports', permission: 'view_reports', icon: '📋' });
      }
      
      if (hasPermission('real_time_detection')) {
        baseNavItems.push({ name: 'realtime', label: 'Real-time Detection', href: '/realtime', permission: 'real_time_detection', icon: '🔄' });
      }
      
      if (hasPermission('view_reports')) {
        baseNavItems.push({ name: 'attackmap', label: 'Attack Map', href: '/attackmap', permission: 'view_reports', icon: '🗺️' });
      }
      
      if (hasPermission('pcap_analysis')) {
        baseNavItems.push({ name: 'pcap', label: 'PCAP Analyzer', href: '/pcap', permission: 'pcap_analysis', icon: '📁' });
      }
      
      if (hasPermission('view_alerts')) {
        baseNavItems.push({ name: 'alerts', label: 'Alert System', href: '/alerts', permission: 'view_alerts', icon: '🚨' });
      }
      
      // Network Security feature removed

      navItems = baseNavItems;

      // Add User Management for admins
      if (isAdmin()) {
        navItems.push({ name: 'user-management', label: 'User Management', href: '/users', icon: '👥', permission: 'user_management' });
      }
    } else {
      // Show only User Profile when not authenticated (fallback)
      navItems = [
        { href: '/profile', label: 'User Profile', icon: '👤', permission: null }
      ];
    }
  }
  
  // Helper functions
  function isActive(path) {
    return $location === path;
  }
  
  function toggleMobileMenu() {
    isMobileMenuOpen.update(open => !open);
  }
  
  function closeMobileMenu() {
    isMobileMenuOpen.set(false);
  }
  
  function toggleSidebar() {
    isSidebarCollapsed.update(collapsed => !collapsed);
  }
  
  // WebSocket functions
  function connectWebSocket() {
    if (ws && ws.readyState === WebSocket.OPEN) {
      console.log('WebSocket already connected');
      return;
    }
    
    try {
      const wsUrl = window.location.hostname === "localhost"
        ? "ws://localhost:8000/api/alerts/ws"
        : `wss://${window.location.hostname}/api/alerts/ws`;
      
      console.log('Connecting to WebSocket:', wsUrl);
      ws = new WebSocket(wsUrl);
      
      ws.onopen = () => {
        console.log('WebSocket connected successfully');
        wsConnected = true;
        wsReconnectAttempts = 0;
      };
      
      ws.onmessage = (event) => {
        try {
          const message = JSON.parse(event.data);
          if (message.type === 'alert') {
            console.log('🚨 Received alert via WebSocket:', message.data);
            // Dispatch custom event to notify AlertNotification component
            const alertEvent = new CustomEvent('newAlert', {
              detail: message.data,
              bubbles: true
            });
            document.dispatchEvent(alertEvent);
          }
        } catch (e) {
          console.error('Error parsing WebSocket message:', e);
        }
      };
      
              ws.onclose = (event) => {
          console.log('WebSocket closed:', event.code, event.reason);
          wsConnected = false;
          
          // Auto-reconnection logic
          if (wsReconnectAttempts < maxReconnectAttempts) {
            wsReconnectAttempts++;
            console.log(`Attempting to reconnect WebSocket (${wsReconnectAttempts}/${maxReconnectAttempts})...`);
            setTimeout(connectWebSocket, 5000);
          } else {
            console.log('Max WebSocket reconnection attempts reached');
          }
        };
      
      ws.onerror = (error) => {
        console.error('WebSocket error:', error);
        wsConnected = false;
      };
      
    } catch (e) {
      console.error('Failed to connect WebSocket:', e);
    }
  }
  
  function disconnectWebSocket() {
    if (ws) {
      console.log('Disconnecting WebSocket');
      ws.close();
      ws = null;
      wsConnected = false;
    }
  }
  
  // Authentication functions
  async function checkAuth() {
    try {
      const response = await axios.get('http://localhost:8000/auth/check-auth', {
        withCredentials: true,
        timeout: 5000
      });
      
      if (response.data.authenticated) {
        setAuthenticatedUser(response.data.user);
        console.log('Auth check: User authenticated', response.data.user);
        
        // Connect WebSocket if user has permission and WebSocket is not connected
        if (hasPermission('view_alerts') && !wsConnected) {
          console.log('User authenticated, connecting WebSocket...');
          connectWebSocket();
        }
      } else {
        resetAuth();
        console.log('Auth check: User not authenticated');
        
        // Disconnect WebSocket if user is not authenticated
        if (wsConnected) {
          console.log('User not authenticated, disconnecting WebSocket...');
          disconnectWebSocket();
        }
      }
    } catch (e) {
      console.error('Auth check error:', e);
      if (e.response && e.response.status === 401) {
        isAuthenticated.set(false);
        currentUser.set(null);
      } else {
        console.warn('Auth check failed due to network/CORS error, keeping current state');
      }
    } finally {
      authLoading.set(false);
    }
  }
  
  async function logout() {
    try {
      await axios.post('http://localhost:8000/auth/logout', {}, {
        withCredentials: true
      });
      
      resetAuth();
      push('/login');
    } catch (e) {
      console.error('Logout error:', e);
      resetAuth();
      push('/login');
    }
  }
  
    // Lifecycle
  onMount(() => {
    checkAuth();
    
    authCheckInterval = setInterval(() => {
      if ($location === '/login' || $location === '/register') {
        checkAuth();
      }
    }, 5000);
    
    return () => {
      if (authCheckInterval) {
        clearInterval(authCheckInterval);
      }
    };
  });
  
  // Monitor authentication state changes and automatically manage WebSocket connections
  $: if ($isAuthenticated && hasPermission('view_alerts') && !wsConnected) {
    console.log('User authenticated with alerts permission, connecting WebSocket...');
    connectWebSocket();
  }
  
  $: if (!$isAuthenticated && wsConnected) {
    console.log('User not authenticated, disconnecting WebSocket...');
    disconnectWebSocket();
  }
  
  onDestroy(() => {
    if (authCheckInterval) {
      clearInterval(authCheckInterval);
    }
    
    // Clean up WebSocket connection
    disconnectWebSocket();
  });
  
  // Reactive statements for redirection
  $: {
    if (!$authLoading) {
      console.log('Redirect logic: isAuthenticated=', $isAuthenticated, 'location=', $location, 'authLoading=', $authLoading);

      // Allow unauthenticated users to access public routes (no redirect to login)
      const publicRoutes = ['/login', '/register', '/forgot-password', '/reset-password', '/verify-registration'];

      if (!$isAuthenticated && !publicRoutes.includes($location)) {
        console.log('Redirecting to login - user not authenticated');
        push('/login');
      } else if ($isAuthenticated && publicRoutes.includes($location)) {
        console.log('Redirecting to dashboard - user authenticated, current location:', $location);
        setTimeout(() => {
          push('/');
          console.log('Redirect to dashboard completed');
        }, 100);
      }
    }
  }
</script>

<div class="app-layout">
  {#if $authLoading}
    <div class="auth-loading">
      <div class="loading-spinner"></div>
      <p>Loading...</p>
    </div>
  {:else if !$isAuthenticated}
    <main class="auth-main">
      <slot />
    </main>
  {:else}
    <!-- Mobile Header -->
    <header class="mobile-header">
      <div class="mobile-header-content">
        <h1 class="mobile-app-title">🛡️ PreTech-NIDS</h1>
        <button 
          class="hamburger-button" 
          on:click={toggleMobileMenu} 
          aria-label="Toggle navigation menu"
        >
          <span class="hamburger-line"></span>
          <span class="hamburger-line"></span>
          <span class="hamburger-line"></span>
        </button>
      </div>
    </header>

    <!-- Mobile Overlay -->
    {#if $isMobileMenuOpen}
      <div
        class="mobile-overlay"
        on:click={closeMobileMenu}
        on:keydown={(e) => {
          if (e.key === 'Escape') {
            closeMobileMenu();
          }
        }}
        role="button"
        tabindex="0"
        aria-label="Close mobile menu"
      ></div>
    {/if}

    <!-- Sidebar Navigation -->
    <nav class="sidebar" class:sidebar-open={$isMobileMenuOpen} class:collapsed={$isSidebarCollapsed}>
      <div class="sidebar-content">
        <div class="sidebar-header">
          <div class="logo-section">
            <div class="logo">🛡️</div>
            {#if !$isSidebarCollapsed}
              <h2 class="app-title">PreTech-NIDS</h2>
            {/if}
          </div>
          <button class="sidebar-toggle" on:click={toggleSidebar} title="Toggle Sidebar">
            {#if $isSidebarCollapsed}
              ☰
            {:else}
              ☰
            {/if}
          </button>
        </div>

        <div class="nav-section">
          <ul class="nav-list">
            {#each navItems as item}
              <li class="nav-item">
                <a
                  href={item.href}
                  use:link
                  class="nav-link"
                  class:active={isActive(item.href)}
                  on:click={closeMobileMenu}
                  title={$isSidebarCollapsed ? item.label : ''}
                >
                  <span class="nav-icon">{item.icon}</span>
                  {#if !$isSidebarCollapsed}
                    <span class="nav-label">{item.label}</span>
                  {/if}
                </a>
              </li>
            {/each}
          </ul>
        </div>

        <div class="user-section">
          <div class="user-info">
            {#if $currentUser?.avatar_url}
              <img src={$currentUser.avatar_url} alt="User Avatar" class="user-avatar-image" />
            {:else}
              <div class="user-avatar">👤</div>
            {/if}
            {#if !$isSidebarCollapsed}
              <div class="user-details">
                <div class="user-name">{$currentUser?.username || 'User'}</div>
                <div class="user-role">{$currentUser?.role_display || 'Report Viewer'}</div>
              </div>
            {/if}
          </div>
          
          <!-- User Profile Button -->
          <button class="profile-button" on:click={() => push('/profile')} title={$isSidebarCollapsed ? 'Profile' : ''}>
            <span class="profile-icon">⚙️</span>
            {#if !$isSidebarCollapsed}
              <span class="profile-text">Profile</span>
            {/if}
          </button>
          
          <button class="logout-button" on:click={logout} title={$isSidebarCollapsed ? 'Logout' : ''}>
            <span class="logout-icon">🚪</span>
            {#if !$isSidebarCollapsed}
              <span class="logout-text">Logout</span>
            {/if}
          </button>
        </div>
        
        <div class="sidebar-footer">
          <p class="version-info">v1.0.0</p>
        </div>
      </div>
    </nav>

    <!-- Main Content Area -->
    <main class="main-content" class:sidebar-expanded={!$isSidebarCollapsed} class:sidebar-collapsed={$isSidebarCollapsed}>
      <slot />
    </main>
  {/if}
</div>

<style>
  .app-layout {
    min-height: 100vh;
    background-color: #f8f9fa;
    display: flex;
    flex-direction: column;
  }

  /* Authentication Loading */
  .auth-loading {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
    background-color: #f8f9fa;
  }

  .loading-spinner {
    width: 40px;
    height: 40px;
    border: 4px solid #e5e7eb;
    border-left: 4px solid #3b82f6;
    border-radius: 50%;
    animation: spin 1s linear infinite;
    margin-bottom: 1rem;
  }

  .auth-loading p {
    color: #6b7280;
    font-size: 1.125rem;
  }

  /* Authentication Pages */
  .auth-main {
    min-height: 100vh;
    width: 100vw;
    display: flex;
    align-items: center;
    justify-content: center;
    background-color: #f8f9fa;
    padding: 0;
    margin: 0;
    overflow-x: hidden;
  }

  /* Mobile Header */
  .mobile-header {
    display: none;
    background: #1f2937;
    color: white;
    padding: 1rem;
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    z-index: 1000;
    height: 60px;
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
  }

  .mobile-header-content {
    display: flex;
    justify-content: space-between;
    align-items: center;
    max-width: 100%;
  }

  .mobile-app-title {
    font-size: 1.25rem;
    font-weight: bold;
    color: white;
    margin: 0;
  }

  .hamburger-button {
    background: none;
    border: none;
    cursor: pointer;
    padding: 0.5rem;
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .hamburger-line {
    width: 24px;
    height: 3px;
    background-color: white;
    border-radius: 2px;
    transition: all 0.3s ease;
  }

  /* Mobile Overlay */
  .mobile-overlay {
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: rgba(0, 0, 0, 0.5);
    z-index: 1001;
  }

  /* Sidebar */
  .sidebar {
    position: fixed;
    top: 0;
    left: 0;
    width: 280px;
    height: 100vh;
    background: #1f2937;
    color: white;
    transition: all 0.3s ease;
    z-index: 1002;
    overflow-y: auto;
    transform: translateX(-100%);
  }

  .sidebar.collapsed {
    width: 60px;
  }

  .sidebar.collapsed .sidebar-content {
    padding: 0.5rem 0;
  }

  .sidebar.collapsed .sidebar-header {
    padding: 0 0.5rem;
    margin-bottom: 1rem;
    flex-direction: column;
    gap: 0.5rem;
    align-items: center;
    justify-content: center;
  }

  .sidebar.collapsed .logo-section {
    flex-direction: column;
    gap: 0.25rem;
    order: 1;
  }

  .sidebar.collapsed .sidebar-toggle {
    order: 0;
    margin-bottom: 0.5rem;
  }

  .sidebar.collapsed .nav-link {
    padding: 0.75rem 0.5rem;
    justify-content: center;
  }

  .sidebar.collapsed .user-section {
    padding: 0.5rem;
  }

  .sidebar.collapsed .user-info {
    flex-direction: column;
    align-items: center;
    gap: 0.25rem;
  }

  .sidebar.collapsed .profile-button,
  .sidebar.collapsed .logout-button {
    padding: 0.5rem;
    min-height: 35px;
    font-size: 0.8rem;
  }

  .sidebar.collapsed .sidebar-footer {
    padding: 0 0.5rem;
  }

  .sidebar.sidebar-open {
    transform: translateX(0);
  }

  .sidebar-content {
    display: flex;
    flex-direction: column;
    height: 100%;
    padding: 2rem 0;
  }

  .sidebar-header {
    padding: 0 2rem;
    margin-bottom: 2rem;
    border-bottom: 1px solid #374151;
    padding-bottom: 1.5rem;
    display: flex;
    justify-content: flex-start;
    align-items: center;
    min-height: 60px;
    gap: 1rem;
  }

  .logo-section {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    flex: 1;
  }

  .logo {
    font-size: 2rem;
    min-width: 2rem;
  }

  .app-title {
    font-size: 1.5rem;
    font-weight: bold;
    color: #ffffff;
    margin: 0;
    white-space: nowrap;
  }

  .sidebar-toggle {
    background: none;
    border: none;
    cursor: pointer;
    color: #d1d5db;
    font-size: 1.5rem;
    padding: 0.5rem;
    transition: color 0.2s ease;
    min-width: 2rem;
    display: flex;
    align-items: center;
    justify-content: center;
    order: -1;
  }

  .sidebar-toggle:hover {
    color: #ffffff;
  }

  /* Navigation */
  .nav-section {
    flex: 1;
    padding: 0;
  }

  .nav-list {
    list-style: none;
    padding: 0;
    margin: 0;
  }

  .nav-item {
    margin: 0.5rem 0;
  }

  .nav-link {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    padding: 1rem 2rem;
    color: #d1d5db;
    text-decoration: none;
    transition: all 0.2s ease;
    border-left: 3px solid transparent;
  }

  .nav-link:hover {
    background-color: #374151;
    color: #ffffff;
    border-left-color: #3b82f6;
  }

  .nav-link.active {
    background-color: #1e40af;
    color: #ffffff;
    border-left-color: #60a5fa;
    font-weight: 600;
  }

  .nav-icon {
    font-size: 1.25rem;
    width: 1.5rem;
    text-align: center;
  }

  .nav-label {
    font-weight: 500;
    font-size: 1rem;
  }

  /* User Section */
  .user-section {
    padding: 1.5rem 2rem;
    border-top: 1px solid #374151;
    margin-top: auto;
  }

  .user-info {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    margin-bottom: 1rem;
  }

  .user-avatar {
    width: 40px;
    height: 40px;
    background-color: #4b5563;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 1.25rem;
  }

  .user-avatar-image {
    width: 40px;
    height: 40px;
    border-radius: 50%;
    object-fit: cover;
    flex-shrink: 0;
  }

  .user-details {
    flex: 1;
  }

  .user-name {
    font-weight: 600;
    color: #ffffff;
    font-size: 0.95rem;
  }

  .user-role {
    font-size: 0.8rem;
    color: #9ca3af;
  }

  .profile-button {
    width: 100%;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.5rem;
    padding: 0.75rem;
    background-color: #4f46e5; /* A different color for profile button */
    color: white;
    border: none;
    border-radius: 8px;
    cursor: pointer;
    font-size: 0.9rem;
    font-weight: 600;
    transition: background-color 0.2s ease;
    margin-bottom: 0.75rem; /* Add some space below the profile button */
  }

  .profile-button:hover {
    background-color: #4338ca;
  }

  .profile-icon {
    font-size: 1rem;
  }

  .profile-text {
    font-weight: 500;
  }

  .logout-button {
    width: 100%;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.5rem;
    padding: 0.75rem;
    background-color: #dc2626;
    color: white;
    border: none;
    border-radius: 8px;
    cursor: pointer;
    font-size: 0.9rem;
    font-weight: 600;
    transition: background-color 0.2s ease;
  }

  .logout-button:hover {
    background-color: #b91c1c;
  }

  .logout-icon {
    font-size: 1rem;
  }

  .sidebar-footer {
    padding: 0 2rem;
    text-align: center;
  }

  .version-info {
    font-size: 0.8rem;
    color: #6b7280;
    margin: 0;
  }

  /* Main Content */
  .main-content {
    margin-left: 0;
    padding-top: 0;
    min-height: 100vh;
    background-color: #f8f9fa;
    transition: margin-left 0.3s ease;
  }

  .main-content.sidebar-expanded {
    margin-left: 280px;
  }

  .main-content.sidebar-collapsed {
    margin-left: 60px;
  }

  @keyframes spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
  }

  /* Desktop styles */
  @media (min-width: 768px) {
    .mobile-header {
      display: none;
    }

    .sidebar {
      transform: translateX(0);
      z-index: 100;
    }

    .mobile-overlay {
      display: none;
    }

    .main-content.sidebar-expanded {
      margin-left: 280px;
    }

    .main-content.sidebar-collapsed {
      margin-left: 60px;
    }

    .app-layout {
      flex-direction: row;
    }
  }

  /* Mobile styles */
  @media (max-width: 767px) {
    .mobile-header {
      display: block;
    }

    .main-content {
      padding-top: 60px;
      margin-left: 0;
    }

    /* Ensure no leftover sidebar margin on mobile */
    .main-content.sidebar-collapsed {
      margin-left: 0;
    }
    .main-content.sidebar-expanded {
      margin-left: 0;
    }

    .sidebar {
      transform: translateX(-100%);
    }

    .sidebar.sidebar-open {
      transform: translateX(0);
    }

    .sidebar.collapsed {
      width: 60px;
    }

    /* Hide the sidebar's internal toggle on mobile – use only the top-left hamburger */
    .sidebar-toggle {
      display: none;
    }

    .sidebar.collapsed .sidebar-header {
      flex-direction: column;
      gap: 0.5rem;
      align-items: center;
      justify-content: center;
    }

    .sidebar.collapsed .logo-section {
      flex-direction: column;
      gap: 0.25rem;
      order: 1;
    }

    .sidebar.collapsed .sidebar-toggle {
      order: 0;
      margin-bottom: 0.5rem;
    }
  }

  /* Tablet design */
  @media (min-width: 769px) and (max-width: 1024px) {
    .sidebar {
      width: 240px;
    }

    .sidebar.collapsed {
      width: 60px;
    }

    .main-content.sidebar-expanded {
      margin-left: 240px;
    }

    .main-content.sidebar-collapsed {
      margin-left: 60px;
    }
  }

  /* Large screens */
  @media (min-width: 1200px) {
    .sidebar {
      width: 320px;
    }

    .sidebar.collapsed {
      width: 60px;
    }

    .main-content.sidebar-expanded {
      margin-left: 320px;
    }

    .main-content.sidebar-collapsed {
      margin-left: 60px;
    }

    .sidebar-content {
      padding: 2.5rem 0;
    }

    .sidebar.collapsed .sidebar-content {
      padding: 0.5rem 0;
    }

    .sidebar-header {
      padding: 0 2.5rem;
      margin-bottom: 2.5rem;
    }

    .sidebar.collapsed .sidebar-header {
      padding: 0 0.5rem;
      margin-bottom: 1rem;
    }

    .nav-link {
      padding: 1.25rem 2.5rem;
    }

    .sidebar.collapsed .nav-link {
      padding: 0.75rem 0.5rem;
    }

    .user-section {
      padding: 2rem 2.5rem;
    }

    .sidebar.collapsed .user-section {
      padding: 0.5rem;
    }
  }
</style> 