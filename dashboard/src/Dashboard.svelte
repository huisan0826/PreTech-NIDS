<script>
  import { writable } from 'svelte/store';
  import { onMount, onDestroy } from 'svelte';
  import { currentUser, hasPermission } from './stores/auth.js';
  import { push, link } from 'svelte-spa-router';

  let stats = writable({
    totalAttacks: 0,
    totalAlerts: 0,
    recentAttacks: 0,
    systemStatus: 'Online',
    lastUpdate: new Date().toLocaleString()
  });
  
  let recentAlerts = writable([]);
  let loading = writable(false);
  let error = writable(null);
  
  // Auto-refresh configuration
  let autoRefreshEnabled = true;
  let autoRefreshInterval = 5000; // 5 seconds
  let autoRefreshTimer = null;
  let lastRefreshTime = new Date();

  async function loadDashboardData() {
    try {
      loading.set(true);
      error.set(null);
      
      // Load recent alerts (latest 5) - same as AlertSystem
      const alertsResponse = await fetch('http://localhost:8000/api/alerts/alerts?page=1&per_page=5');
      if (alertsResponse.ok) {
        const alertsData = await alertsResponse.json();
        if (alertsData.success) {
          recentAlerts.set(alertsData.alerts || []);
        }
      }
      
      // Load statistics - same API and structure as AlertSystem
      const statsResponse = await fetch('http://localhost:8000/api/alerts/statistics');
      if (statsResponse.ok) {
        const statsData = await statsResponse.json();
        
        if (statsData.success) {
          const statistics = statsData.statistics;
          
          // Use the same field names as AlertSystem
          stats.set({
            totalAttacks: statistics.total_alerts_24h || 0,        // Total alerts in last 24h
            totalAlerts: statistics.total_alerts_24h || 0,        // Same as above for consistency
            recentAttacks: statistics.by_level?.critical || 0,    // Critical alerts as recent attacks
            systemStatus: 'Online',                               // Default system status
            lastUpdate: new Date().toLocaleString()
          });
          
          console.log('📊 Dashboard stats loaded (matching AlertSystem):', {
            totalAttacks: statistics.total_alerts_24h,
            totalAlerts: statistics.total_alerts_24h,
            recentAttacks: statistics.by_level?.critical,
            byLevel: statistics.by_level,
            rawStatistics: statistics
          });
        } else {
          console.error('API returned success: false');
        }
      } else {
        // Fallback to default stats if API fails
        stats.set({
          totalAttacks: 0,
          totalAlerts: 0,
          recentAttacks: 0,
          systemStatus: 'Online',
          lastUpdate: new Date().toLocaleString()
        });
      }
      
    } catch (e) {
      console.error('Failed to load dashboard data:', e);
      error.set('Failed to load dashboard data');
      
      // Set default values if there's an error
      stats.set({
        totalAttacks: 0,
        totalAlerts: 0,
        recentAttacks: 0,
        systemStatus: 'Online',
        lastUpdate: new Date().toLocaleString()
      });
      recentAlerts.set([]);
    } finally {
      loading.set(false);
    }
  }

  function refreshData() {
    loadDashboardData();
  }
  
  // Start auto-refresh timer
  function startAutoRefresh() {
    if (autoRefreshTimer) {
      clearInterval(autoRefreshTimer);
    }
    
    if (autoRefreshEnabled) {
      autoRefreshTimer = setInterval(async () => {
        console.log('🔄 Auto-refreshing dashboard data...');
        await loadDashboardData();
        lastRefreshTime = new Date();
      }, autoRefreshInterval);
      
      console.log(`✅ Auto-refresh started (${autoRefreshInterval/1000}s interval)`);
    }
  }
  
  // Stop auto-refresh timer
  function stopAutoRefresh() {
    if (autoRefreshTimer) {
      clearInterval(autoRefreshTimer);
      autoRefreshTimer = null;
      console.log('⏹️ Auto-refresh stopped');
    }
  }
  
  // Toggle auto-refresh
  function toggleAutoRefresh() {
    autoRefreshEnabled = !autoRefreshEnabled;
    if (autoRefreshEnabled) {
      startAutoRefresh();
    } else {
      stopAutoRefresh();
    }
  }
  
    // Change refresh interval
  function changeRefreshInterval(newInterval) {
    autoRefreshInterval = newInterval;
    if (autoRefreshEnabled) {
      startAutoRefresh(); // Restart with new interval
    }
  }
  
  // Handle interval change event
  function handleIntervalChange(event) {
    const value = event.target.value;
    if (value) {
      changeRefreshInterval(parseInt(value));
    }
  }
  
  // Function to navigate to different pages
  function navigateTo(path) {
    push(path);
  }
  
  // Lifecycle management
  onMount(async () => {
    console.log('🚀 Dashboard mounted, starting auto-refresh...');
    await loadDashboardData();
    startAutoRefresh();
  });
  
  onDestroy(() => {
    console.log('🛑 Dashboard unmounting, stopping auto-refresh...');
    stopAutoRefresh();
  });
</script>

<div class="page-container">
  <div class="page-header">
    <div class="header-content">
      <h1 class="page-title">🏠 Dashboard</h1>
      <p class="page-description">Welcome to PreTech-NIDS - Your Network Security Command Center</p>
    </div>
    
    <div class="refresh-controls">
      <button class="refresh-button" on:click={refreshData} disabled={$loading}>
        {#if $loading}
          <span class="spinner"></span>
        {:else}
          🔄
        {/if}
        Refresh
      </button>
      
      <button class="auto-refresh-toggle {autoRefreshEnabled ? 'enabled' : 'disabled'}" 
              on:click={toggleAutoRefresh} title="Toggle auto-refresh">
        {#if autoRefreshEnabled}
          ⏸️ Auto-refresh: ON
        {:else}
          ▶️ Auto-refresh: OFF
        {/if}
      </button>
      
      <select class="refresh-interval" on:change={handleIntervalChange}>
        <option value={3000}>3s</option>
        <option value={5000} selected>5s</option>
        <option value={10000}>10s</option>
        <option value={30000}>30s</option>
      </select>
      
      <span class="last-refresh">
        Last: {lastRefreshTime.toLocaleTimeString()}
      </span>
    </div>
  </div>

  {#if $error}
    <div class="error-banner">
      ⚠️ {$error}
    </div>
  {/if}

  <div class="dashboard-grid">
    <!-- System Status Cards -->
    <div class="status-cards">
      <div class="status-card">
        <div class="status-icon">🚨</div>
        <div class="status-content">
          <h3 class="status-title">Total Alerts</h3>
          <p class="status-value">{$stats.totalAttacks || 0}</p>
          <p class="status-subtitle">Last 24 hours</p>
        </div>
      </div>

      <div class="status-card">
        <div class="status-icon">⚡</div>
        <div class="status-content">
          <h3 class="status-title">Critical Alerts</h3>
          <p class="status-value">{$stats.recentAttacks || 0}</p>
          <p class="status-subtitle">Last 24 hours</p>
        </div>
      </div>

      <div class="status-card">
        <div class="status-icon">📊</div>
        <div class="status-content">
          <h3 class="status-title">All Alerts</h3>
          <p class="status-value">{$stats.totalAlerts || 0}</p>
          <p class="status-subtitle">Last 24 hours</p>
        </div>
      </div>

      <div class="status-card">
        <div class="status-icon">🟢</div>
        <div class="status-content">
          <h3 class="status-title">System Status</h3>
          <p class="status-value">{$stats.systemStatus || 'Online'}</p>
          <p class="status-subtitle">All systems operational</p>
        </div>
      </div>
    </div>

    <!-- Quick Actions -->
    <div class="quick-actions">
      <h2 class="section-title">Quick Actions</h2>
      <div class="action-buttons">
        {#if $currentUser && hasPermission('manual_testing')}
          <button class="action-button" on:click={() => navigateTo('/manual-testing')}>
            <span class="action-icon">🧪</span>
            <span class="action-text">Manual Testing</span>
          </button>
        {/if}
        
        {#if $currentUser && hasPermission('real_time_detection')}
          <button class="action-button" on:click={() => navigateTo('/realtime')}>
            <span class="action-icon">🔄</span>
            <span class="action-text">Real-time Detection</span>
          </button>
        {/if}
        
        {#if $currentUser && hasPermission('pcap_analysis')}
          <button class="action-button" on:click={() => navigateTo('/pcap')}>
            <span class="action-icon">📁</span>
            <span class="action-text">PCAP Analysis</span>
          </button>
        {/if}
        
        {#if $currentUser && hasPermission('view_alerts')}
          <button class="action-button" on:click={() => navigateTo('/alerts')}>
            <span class="action-icon">🚨</span>
            <span class="action-text">View Alerts</span>
          </button>
        {/if}
        
        {#if $currentUser && hasPermission('view_reports')}
          <button class="action-button" on:click={() => navigateTo('/reports')}>
            <span class="action-icon">📋</span>
            <span class="action-text">View Reports</span>
          </button>
        {/if}

        {#if $currentUser && hasPermission('view_reports')}
          <button class="action-button" on:click={() => navigateTo('/attackmap')}>
            <span class="action-icon">🗺️</span>
            <span class="action-text">Attack Map</span>
          </button>
        {/if}

        {#if $currentUser && hasPermission('user_management')}
          <button class="action-button" on:click={() => navigateTo('/users')}>
            <span class="action-icon">👥</span>
            <span class="action-text">User Management</span>
          </button>
    {/if}
      </div>
    </div>

    <!-- Recent Alerts -->
    <div class="recent-alerts">
      <h2 class="section-title">Recent Alerts ({$recentAlerts.length} latest)</h2>
      {#if $recentAlerts.length > 0}
        <div class="alerts-list">
          {#each $recentAlerts.slice(0, 5) as alert}
            <div class="alert-item">
              <div class="alert-header">
                <span class="alert-type {alert.severity}">{alert.type}</span>
                <span class="alert-time">{new Date(alert.timestamp).toLocaleString()}</span>
              </div>
              <p class="alert-message">{alert.message}</p>
            </div>
          {/each}
        </div>
        <div class="view-all-alerts">
          <a href="/alerts" use:link class="view-all-link">View All Alerts →</a>
        </div>
      {:else}
        <div class="no-alerts">
          <div class="no-alerts-icon">✅</div>
          <p>No recent alerts - Your network is secure!</p>
          <p class="no-alerts-subtitle">The system is actively monitoring for any suspicious activity</p>
        </div>
      {/if}
    </div>


  </div>
</div>

<style>
  .page-container {
    padding: 2rem;
    max-width: 100%;
    margin: 0;
    width: 100%;
  }

  .page-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 2rem;
    flex-wrap: wrap;
    gap: 1rem;
  }

  .header-content {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    text-align: center;
    flex-grow: 1;
  }

  .page-title {
    font-size: 2.5rem;
    font-weight: bold;
    color: #1f2937;
    margin: 0 0 0.5rem 0;
  }

  .page-description {
    color: #6b7280;
    margin: 0;
    font-size: 1.1rem;
    line-height: 1.5;
  }

  .refresh-controls {
    display: flex;
    align-items: center;
    gap: 1rem;
    flex-wrap: wrap;
  }
  
  .refresh-button {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.75rem 1.5rem;
    background-color: #3b82f6;
    color: white;
    border: none;
    border-radius: 8px;
    cursor: pointer;
    font-weight: 600;
    transition: background-color 0.2s ease;
  }

  .refresh-button:hover:not(:disabled) {
    background-color: #2563eb;
  }
  
  .auto-refresh-toggle {
    background: #10b981;
    color: white;
    border: none;
    padding: 0.75rem 1.5rem;
    border-radius: 8px;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.2s ease;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
  
  .auto-refresh-toggle.disabled {
    background-color: #b91c1c;
  }
  
  .auto-refresh-toggle:hover {
    transform: translateY(-1px);
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
  }
  
  .refresh-interval {
    background: white;
    border: 1px solid #d1d5db;
    padding: 0.75rem 1rem;
    border-radius: 8px;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.2s ease;
  }
  
  .refresh-interval:hover {
    border-color: #3b82f6;
  }
  
  .last-refresh {
    color: #6b7280;
    font-size: 0.875rem;
    font-weight: 500;
  }

  .refresh-button:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  .spinner {
    width: 16px;
    height: 16px;
    border: 2px solid #ffffff40;
    border-left: 2px solid #ffffff;
    border-radius: 50%;
    animation: spin 1s linear infinite;
  }

  .error-banner {
    background-color: #fee2e2;
    color: #991b1b;
    padding: 1rem;
    border-radius: 8px;
    margin-bottom: 2rem;
    border: 1px solid #fecaca;
  }

  .dashboard-grid {
    display: grid;
    gap: 2rem;
    grid-template-columns: 1fr;
  }

  /* Status Cards */
  .status-cards {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 1.5rem;
  }

  .status-card {
    background: white;
    padding: 1.5rem;
    border-radius: 12px;
    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
    border: 1px solid #e5e7eb;
    display: flex;
    align-items: center;
    gap: 1rem;
  }

  .status-icon {
    font-size: 2rem;
    width: 60px;
    height: 60px;
    display: flex;
    align-items: center;
    justify-content: center;
    background-color: #f3f4f6;
    border-radius: 12px;
  }

  .status-content {
    flex: 1;
  }

  .status-title {
    font-size: 0.875rem;
    color: #6b7280;
    margin: 0 0 0.5rem 0;
    font-weight: 500;
  }

  .status-value {
    font-size: 1.5rem;
    font-weight: bold;
    color: #1f2937;
    margin: 0;
  }

  .status-subtitle {
    font-size: 0.75rem;
    color: #9ca3af;
    margin-top: 0.25rem;
  }

  /* Quick Actions */
  .quick-actions {
    background: white;
    padding: 2rem;
    border-radius: 12px;
    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
    border: 1px solid #e5e7eb;
  }

  .section-title {
    font-size: 1.25rem;
    font-weight: 600;
    color: #1f2937;
    margin: 0 0 1.5rem 0;
  }

  .action-buttons {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1rem;
  }

  .action-button {
    display: flex;
      flex-direction: column;
    align-items: center;
      gap: 0.75rem;
    padding: 1.5rem;
    background-color: #f8fafc;
    border: 2px solid #e5e7eb;
    border-radius: 12px;
    text-decoration: none;
    color: #374151;
    transition: all 0.2s ease;
    cursor: pointer;
    font-family: inherit;
    font-size: inherit;
  }

  .action-button:hover {
    background-color: #f1f5f9;
    border-color: #3b82f6;
    transform: translateY(-2px);
    box-shadow: 0 8px 25px rgba(59, 130, 246, 0.15);
  }

  .action-button:focus {
    outline: none;
    border-color: #3b82f6;
    box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
  }

  .action-icon {
      font-size: 2rem;
    }

  .action-text {
    font-weight: 600;
    font-size: 0.875rem;
  }

  /* Recent Alerts */
  .recent-alerts {
    background: white;
    padding: 2rem;
    border-radius: 12px;
    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
    border: 1px solid #e5e7eb;
  }

  .alerts-list {
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }

  .alert-item {
    padding: 1rem;
    border: 1px solid #e5e7eb;
    border-radius: 8px;
    background-color: #f9fafb;
  }

  .alert-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.5rem;
  }

  .alert-type {
    padding: 0.25rem 0.75rem;
    border-radius: 20px;
      font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
  }

  .alert-type.high {
    background-color: #fee2e2;
    color: #991b1b;
  }

  .alert-type.medium {
    background-color: #fef3c7;
    color: #92400e;
  }

  .alert-type.low {
    background-color: #d1fae5;
    color: #065f46;
  }

  .alert-time {
      font-size: 0.75rem;
    color: #6b7280;
  }

  .alert-message {
    margin: 0;
    color: #374151;
    font-size: 0.875rem;
  }

  .view-all-alerts {
    margin-top: 1rem;
    text-align: center;
  }

  .view-all-link {
    color: #3b82f6;
    text-decoration: none;
    font-weight: 600;
  }

  .view-all-link:hover {
    text-decoration: underline;
  }

  .no-alerts {
    text-align: center;
    color: #6b7280;
    padding: 2rem;
  }

  .no-alerts-icon {
    font-size: 3rem;
    margin-bottom: 0.5rem;
  }

  .no-alerts-subtitle {
    font-size: 0.875rem;
    color: #9ca3af;
  }



  @keyframes spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
  }

  /* Responsive Design */
  @media (max-width: 768px) {
    .page-container {
      padding: 1rem;
    }

    .page-header {
      flex-direction: column;
      align-items: center;
      text-align: center;
      gap: 1.5rem;
    }

    .header-content {
      align-items: center;
      text-align: center;
      order: 1;
    }

    .page-title {
      font-size: 2rem;
    }

    .page-description {
      font-size: 1rem;
    }

    .refresh-controls {
      flex-direction: column;
      align-items: center;
      gap: 0.5rem;
      order: 2;
    }

    .refresh-button, .auto-refresh-toggle, .refresh-interval {
      width: 100%;
      justify-content: center;
    }

    .status-cards { grid-template-columns: 1fr; }
    .dashboard-grid { gap: 1rem; }
    .status-card { padding: 1rem; }
    .status-icon { width: 48px; height: 48px; font-size: 1.5rem; }
    .status-value { font-size: 1.25rem; }
    .quick-actions { padding: 1rem; }
    .action-buttons { grid-template-columns: 1fr; }
    .recent-alerts { padding: 1rem; }
  }
</style>
