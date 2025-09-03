<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { writable, get } from 'svelte/store';
  import axios from 'axios';
  import { hasPermission, isAuthenticated } from './stores/auth.js';

  // type declaration
  interface AlertStatistics {
    total_alerts_24h?: number;
    by_level?: { [key: string]: number };
    by_type?: { [key: string]: number };
    top_source_ips?: { [key: string]: number };
    top_target_ports?: { [key: string]: number };
    active_rules?: number;
  }

  // State management
  let alerts = writable([]);
  let statistics = writable<AlertStatistics>({});
  let loading = writable(true);
  let error = writable(null);
  let success = writable(null);
  let connected = writable(false);
  let alertRules = writable([]);

  // WebSocket connection
  let ws = null;
  let reconnectAttempts = 0;
  let maxReconnectAttempts = 5;
  let reconnectTimer = null;

  // Alert settings with localStorage persistence
  let soundEnabled = true;
  let desktopNotificationsEnabled = true;
  let autoAcknowledge = false;
  let showOnlyUnresolved = true;
  let alertLevelFilter = 'all';
  
  // Pagination and filtering
  let currentPage = 1;
  let perPage = 100;
  let totalPages = 1;
  let totalAlerts = 0;
  let startDate = '';
  let endDate = '';
  let loadingAlerts = false;
  


  // UI state
  let showNewAlertModal = false;
  let newAlert = null;
  let showSettingsModal = false;
  let showRulesModal = false;
  let playingSound = false;
  
  // Event listener cleanup
  let globalCloseAllListener = null;


  // Audio context for alert sounds
  let audioContext = null;
  let alertSound = null;

  // Authentication check function
  function checkAuthentication() {
    if (!get(isAuthenticated)) {
      error.set('Please log in to perform this action.');
      setTimeout(() => {
        window.location.href = '/login';
      }, 2000);
      return false;
    }
    return true;
  }

  // Keyboard event handler for closing modals
  function handleKeydown(event) {
    if (event.key === 'Escape') {
      if (showNewAlertModal) closeAlertModal();
      if (showSettingsModal) showSettingsModal = false;
      if (showRulesModal) { showRulesModal = false; cancelAddEditModal(); }
      if (showAddEditModal) cancelAddEditModal();
    }
  }

  // rules management related
  let editingRule = null;
  let ruleForm = {
    name: '',
    description: '',
    alert_type: 'threat_detected',
    conditions: '{}',
    actions: [],
    enabled: true,
    threshold: '',
    time_window: ''
  };
  const alertTypeOptions = [
    { value: 'threat_detected', label: 'Threat Detected' },
    { value: 'anomaly_detected', label: 'Anomaly Detected' },
    { value: 'multiple_attacks', label: 'Multiple Attacks' },
    { value: 'suspicious_ip', label: 'Suspicious IP' },
    { value: 'high_risk_port', label: 'High-Risk Port' },
    { value: 'zero_day_attack', label: 'Zero-day Attack' },
    { value: 'brute_force', label: 'Brute Force' },
    { value: 'system_overload', label: 'System Overload' }
  ];
  const actionOptions = [
    { value: 'websocket', label: 'Push Notification' },
    { value: 'log', label: 'Log' },
    { value: 'store', label: 'Store' },
    { value: 'email', label: 'Email Notification' }
  ];

  // Add a state variable to control Add/Edit modal visibility
  let showAddEditModal = false;

  function openAddRule() {
    editingRule = null;
    ruleForm = {
      name: '',
      description: '',
      alert_type: 'threat_detected',
      conditions: '{}',
      actions: [],
      enabled: true,
      threshold: '',
      time_window: ''
    };
    showAddEditModal = true;
  }
  function openEditRule(rule) {
    editingRule = rule;
    ruleForm = {
      name: rule.name,
      description: rule.description,
      alert_type: rule.alert_type,
      conditions: JSON.stringify(rule.conditions, null, 2),
      actions: rule.actions || [],
      enabled: rule.enabled,
      threshold: rule.threshold ?? '',
      time_window: rule.time_window ?? ''
    };
    showAddEditModal = true;
  }
  async function saveRule() {
    try {
      let payload = {
        name: ruleForm.name,
        description: ruleForm.description,
        alert_type: ruleForm.alert_type,
        conditions: JSON.parse(ruleForm.conditions),
        actions: ruleForm.actions,
        enabled: ruleForm.enabled,
        threshold: ruleForm.threshold === '' ? null : Number(ruleForm.threshold),
        time_window: ruleForm.time_window === '' ? null : Number(ruleForm.time_window)
      };
      if (editingRule) {
        // Update
        await axios.put(`http://localhost:8000/api/alerts/rules/${editingRule.id}`, payload, { withCredentials: true });
      } else {
        // Add
        await axios.post('http://localhost:8000/api/alerts/rules', payload, { withCredentials: true });
      }
      await loadAlertRules();
      editingRule = null;
      ruleForm = {
        name: '', description: '', alert_type: 'threat_detected', conditions: '{}', actions: [], enabled: true, threshold: '', time_window: ''
      };
      showAddEditModal = false;
    } catch (e) {
      if (e.response?.status === 403) {
        alert('You do not have permission to manage alert rules. Please contact your administrator.');
        return;
      }
      alert('Failed to save rule: ' + (e.response?.data?.detail || e.message));
    }
  }
  function cancelAddEditModal() {
    editingRule = null;
    ruleForm = {
      name: '', description: '', alert_type: 'threat_detected', conditions: '{}', actions: [], enabled: true, threshold: '', time_window: ''
    };
    showAddEditModal = false;
  }
  async function deleteRule(rule) {
    if (!confirm('Are you sure you want to delete this rule?')) return;
    try {
      await axios.delete(`http://localhost:8000/api/alerts/rules/${rule.id}`, { withCredentials: true });
      await loadAlertRules();
      // If editing the same rule, close the form
      if (editingRule && editingRule.id === rule.id) {
        cancelAddEditModal();
      }
    } catch (e) {
      if (e.response?.status === 403) {
        alert('You do not have permission to manage alert rules. Please contact your administrator.');
        return;
      }
      alert('Failed to delete rule: ' + (e.response?.data?.detail || e.message));
    }
  }

  const alertLevels = ['all', 'critical', 'high', 'medium', 'low', 'info'];
  const alertTypes = {
    'threat_detected': '🚨 Threat Detected',
    'zero_day_attack': '⚠️ Zero-day Attack',
    'multiple_attacks': '🔄 Multiple Attacks',
    'high_risk_port': '🎯 High-Risk Port',
    'brute_force': '🔓 Brute Force',
    'anomaly_detected': '📊 Anomaly',
    'system_overload': '⚡ System Overload'
  };

  // fix onMount async problem
  let refreshInterval = null;
  
  // Auto-refresh functionality
  let autoRefreshEnabled = true; // Default to enabled like Dashboard
  let autoRefreshInterval = 5000; // 5 seconds default
  let autoRefreshTimer = null;
  let lastRefreshTime = new Date();
  
  // Auto-refresh functions
  function startAutoRefresh() {
    if (autoRefreshTimer) {
      clearInterval(autoRefreshTimer);
    }
    
    if (autoRefreshEnabled) {
      autoRefreshTimer = setInterval(async () => {
        console.log('🔄 Auto-refreshing AlertSystem data...');
        await loadAlerts(currentPage);
        await loadStatistics();
        lastRefreshTime = new Date();
      }, autoRefreshInterval);
      
      console.log(`✅ Auto-refresh started (${autoRefreshInterval/1000}s interval)`);
    }
  }
  
  function stopAutoRefresh() {
    if (autoRefreshTimer) {
      clearInterval(autoRefreshTimer);
      autoRefreshTimer = null;
      console.log('⏹️ Auto-refresh stopped');
    }
  }
  
  function toggleAutoRefresh() {
    autoRefreshEnabled = !autoRefreshEnabled;
    if (autoRefreshEnabled) {
      startAutoRefresh();
    } else {
      stopAutoRefresh();
    }
    console.log('🔄 Auto-refresh toggled:', autoRefreshEnabled);
  }
  
  function changeRefreshInterval(newInterval) {
    autoRefreshInterval = newInterval;
    if (autoRefreshEnabled) {
      startAutoRefresh(); // Restart with new interval
    }
    console.log('⏱️ Refresh interval changed to:', newInterval);
  }
  
  function handleIntervalChange(event) {
    const value = event.target.value;
    if (value) {
      changeRefreshInterval(parseInt(value));
    }
  }
  
  onMount(async () => {
    if (!hasPermission('view_alerts')) {
      return;
    }

    console.log('🚀 AlertSystem mounted, starting auto-refresh...');
    
    // Load saved alert settings first
    loadAlertSettings();
    
    // Initialize audio context for alert sounds
    await initializeAudio();
    
    // Request notification permission for desktop notifications
    await requestNotificationPermission();
    
    // Load initial data
    await loadAlerts();
    await loadStatistics();
    await loadAlertRules();
    
    // Connect WebSocket
    connectWebSocket();
    
    // Add keyboard event listener
    document.addEventListener('keydown', handleKeydown);
    
    // Listen for global close all alerts event from Alert Manager
    const handleGlobalCloseAll = () => {
      console.log('🎯 AlertSystem received global close all alerts event');
      closeAlertModal();
    };
    
    document.addEventListener('closeAllAlerts', handleGlobalCloseAll);
    
    // Store cleanup function for onDestroy
    globalCloseAllListener = handleGlobalCloseAll;
    
    // Start auto-refresh immediately (like Dashboard)
    startAutoRefresh();
  });

  onDestroy(() => {
    console.log('🛑 AlertSystem unmounting, stopping auto-refresh...');
    
    // Cleanup WebSocket
    if (ws) {
      ws.close();
    }
    
    // Cleanup reconnect timer
    if (reconnectTimer) {
      clearTimeout(reconnectTimer);
    }
    
    // Cleanup auto-refresh timer
    stopAutoRefresh();
    
    // Cleanup audio context
    if (audioContext) {
      audioContext.close();
    }
    
    // Cleanup event listeners
    document.removeEventListener('keydown', handleKeydown);
    
    // Cleanup global event listener
    if (globalCloseAllListener) {
      document.removeEventListener('closeAllAlerts', globalCloseAllListener);
      globalCloseAllListener = null;
    }
  });

  // Settings persistence functions
  function loadAlertSettings() {
    try {
      const savedSettings = localStorage.getItem('alertSettings');
      if (savedSettings) {
        const settings = JSON.parse(savedSettings);
        soundEnabled = settings.soundEnabled ?? true;
        desktopNotificationsEnabled = settings.desktopNotificationsEnabled ?? true;
        autoAcknowledge = settings.autoAcknowledge ?? false;
        showOnlyUnresolved = settings.showOnlyUnresolved ?? true;
        alertLevelFilter = settings.alertLevelFilter ?? 'all';
        console.log('🔧 Loaded alert settings from localStorage:', settings);
      } else {
        console.log('🔧 No saved alert settings found, using defaults');
      }
    } catch (e) {
      console.error('❌ Failed to load alert settings:', e);
    } finally {
      // Mark settings as loaded to enable auto-save
      settingsLoaded = true;
    }
  }

  function saveAlertSettings() {
    try {
      const settings = {
        soundEnabled,
        desktopNotificationsEnabled,
        autoAcknowledge,
        showOnlyUnresolved,
        alertLevelFilter
      };
      localStorage.setItem('alertSettings', JSON.stringify(settings));
      console.log('💾 Saved alert settings to localStorage:', settings);
    } catch (e) {
      console.error('❌ Failed to save alert settings:', e);
    }
  }

  // Auto-save settings when they change (but not during initial load)
  let settingsLoaded = false;
  let settingsSaved = false;
  $: if (settingsLoaded && soundEnabled !== undefined) {
    saveAlertSettings();
    settingsSaved = true;
    // Reset saved status after 2 seconds
    setTimeout(() => settingsSaved = false, 2000);
  }

  // fix webkitAudioContext type error
  async function initializeAudio() {
    try {
      // @ts-ignore
      audioContext = new (window.AudioContext || (window as any).webkitAudioContext)();
      
      // Create alert sound using Web Audio API
      alertSound = await createAlertTone();
    } catch (e) {
      console.error('Audio initialization failed:', e);
    }
  }

  async function createAlertTone() {
    if (!audioContext) return null;

    // Create a simple alert tone
    const oscillator = audioContext.createOscillator();
    const gainNode = audioContext.createGain();
    
    oscillator.connect(gainNode);
    gainNode.connect(audioContext.destination);
    
    return { oscillator, gainNode };
  }

  async function playAlertSound() {
    console.log('🔊 Attempting to play alert sound...', {
      soundEnabled,
      audioContext: !!audioContext,
      playingSound,
      audioContextState: audioContext?.state
    });

    if (!soundEnabled) {
      console.log('🔇 Sound is disabled');
      return;
    }

    if (!audioContext) {
      console.log('🔇 Audio context not initialized, attempting to initialize...');
      await initializeAudio();
      if (!audioContext) {
        console.error('❌ Failed to initialize audio context');
        return;
      }
    }

    if (playingSound) {
      console.log('🔇 Already playing sound');
      return;
    }

    try {
      playingSound = true;
      
      // Resume audio context if suspended
      if (audioContext.state === 'suspended') {
        console.log('🔊 Resuming suspended audio context...');
        await audioContext.resume();
      }

      // Create new oscillator for each sound
      const oscillator = audioContext.createOscillator();
      const gainNode = audioContext.createGain();
      
      oscillator.connect(gainNode);
      gainNode.connect(audioContext.destination);
      
      // Configure alert tone (two-tone alarm)
      oscillator.frequency.setValueAtTime(800, audioContext.currentTime);
      oscillator.frequency.setValueAtTime(600, audioContext.currentTime + 0.3);
      oscillator.frequency.setValueAtTime(800, audioContext.currentTime + 0.6);
      
      gainNode.gain.setValueAtTime(0, audioContext.currentTime);
      gainNode.gain.linearRampToValueAtTime(0.3, audioContext.currentTime + 0.1);
      gainNode.gain.linearRampToValueAtTime(0, audioContext.currentTime + 0.9);
      
      oscillator.start(audioContext.currentTime);
      oscillator.stop(audioContext.currentTime + 1);
      
      console.log('🔊 Alert sound started successfully');
      
      oscillator.onended = () => {
        playingSound = false;
        console.log('🔊 Alert sound ended');
      };
      
    } catch (e) {
      console.error('❌ Failed to play alert sound:', e);
      playingSound = false;
    }
  }

  async function requestNotificationPermission() {
    if (!('Notification' in window)) {
      console.log('🔔 Desktop notifications not supported in this browser');
      return;
    }

    if (Notification.permission === 'granted') {
      console.log('🔔 Desktop notifications already granted');
      return;
    }

    if (Notification.permission === 'denied') {
      console.log('🔔 Desktop notifications denied by user');
      return;
    }

    if (Notification.permission === 'default') {
      console.log('🔔 Requesting desktop notification permission...');
      const permission = await Notification.requestPermission();
      console.log('🔔 Desktop notification permission:', permission);
      
      if (permission === 'granted') {
        console.log('✅ Desktop notifications enabled');
      } else {
        console.log('❌ Desktop notifications denied');
      }
    }
  }

  function showDesktopNotification(alert) {
    console.log('🔔 Attempting to show desktop notification...', {
      desktopNotificationsEnabled,
      notificationSupported: 'Notification' in window,
      permission: Notification.permission,
      alert: alert.title
    });

    if (!desktopNotificationsEnabled) {
      console.log('🔔 Desktop notifications disabled in settings');
      return;
    }

    if (!('Notification' in window)) {
      console.log('🔔 Desktop notifications not supported in this browser');
      return;
    }

    if (Notification.permission !== 'granted') {
      console.log('🔔 Desktop notification permission not granted:', Notification.permission);
      return;
    }

    try {
      const options = {
        body: alert.message,
        icon: '/favicon.ico',
        badge: '/favicon.ico',
        tag: `alert-${alert.id}`,
        requireInteraction: alert.level === 'critical',
        silent: false
      };

      const notification = new Notification(alert.title, options);
      console.log('🔔 Desktop notification shown successfully');
      
      notification.onclick = () => {
        console.log('🔔 Desktop notification clicked');
        window.focus();
        showAlertDetails(alert);
        notification.close();
      };

      // Auto-close after 10 seconds for non-critical alerts
      if (alert.level !== 'critical') {
        setTimeout(() => {
          notification.close();
          console.log('🔔 Desktop notification auto-closed');
        }, 10000);
      }
    } catch (e) {
      console.error('❌ Failed to show desktop notification:', e);
    }
  }

  function connectWebSocket() {
    try {
      const wsUrl =
        window.location.hostname === "localhost"
          ? "ws://localhost:8000/api/alerts/ws"
          : `wss://${window.location.hostname}/api/alerts/ws`;
      ws = new WebSocket(wsUrl);
      
      ws.onopen = () => {
        connected.set(true);
        reconnectAttempts = 0;
        console.log('WebSocket connected for alerts');
      };
      
      ws.onmessage = (event) => {
        try {
          const message = JSON.parse(event.data);
          if (message.type === 'alert') {
            handleNewAlert(message.data);
          }
        } catch (e) {
          console.error('Error parsing WebSocket message:', e);
        }
      };
      
      ws.onclose = () => {
        connected.set(false);
        console.log('WebSocket disconnected');
        attemptReconnect();
      };
      
      ws.onerror = (error) => {
        console.error('WebSocket error:', error);
        connected.set(false);
      };
      
    } catch (e) {
      console.error('Failed to connect WebSocket:', e);
      connected.set(false);
    }
  }

  function attemptReconnect() {
    if (reconnectAttempts >= maxReconnectAttempts) {
      console.log('Max reconnection attempts reached');
      return;
    }

    reconnectAttempts++;
    const delay = Math.min(1000 * Math.pow(2, reconnectAttempts), 30000);
    
    console.log(`Attempting to reconnect in ${delay}ms (attempt ${reconnectAttempts})`);
    
    reconnectTimer = setTimeout(() => {
      connectWebSocket();
    }, delay);
  }

  function handleNewAlert(alertData) {
    const alert = alertData;
    
    // Add to alerts list
    alerts.update(current => [alert, ...current]);
    
    // Play sound
    playAlertSound();
    
    // Show desktop notification
    showDesktopNotification(alert);
    
    // Show modal for critical alerts
    if (alert.level === 'critical') {
      showAlertModal(alert);
    }
    
    // Auto-acknowledge if enabled
    if (autoAcknowledge && alert.level !== 'critical') {
      setTimeout(() => acknowledgeAlert(alert.id), 5000);
    }
  }

  function showAlertModal(alert) {
    newAlert = alert;
    showNewAlertModal = true;
  }

  function closeAlertModal() {
    showNewAlertModal = false;
    newAlert = null;
  }

  async function loadAlerts(page = 1) {
    try {
      loadingAlerts = true;
      error.set(null);

      // Build query parameters
      const params = new URLSearchParams({
        page: page.toString(),
        per_page: perPage.toString()
      });

      if (startDate) {
        params.append('start_date', startDate);
      }
      if (endDate) {
        params.append('end_date', endDate);
      }
      if (alertLevelFilter !== 'all') {
        params.append('level_filter', alertLevelFilter);
      }
      if (showOnlyUnresolved) {
        params.append('resolved_filter', 'false');
        console.log('🔍 Filtering: Show only unresolved alerts');
      } else {
        console.log('🔍 Filtering: Show all alerts (including resolved)');
      }

      console.log('🔍 Loading alerts with params:', params.toString());
      const response = await axios.get(`http://localhost:8000/api/alerts/alerts?${params.toString()}`);
      
      if (response.data.success) {
        alerts.set(response.data.alerts);
        currentPage = response.data.pagination.page;
        totalPages = response.data.pagination.total_pages;
        totalAlerts = response.data.pagination.total_alerts;
      } else {
        error.set('Failed to load alerts: API returned false');
      }
    } catch (e) {
      console.error('Error loading alerts:', e);
      error.set('Failed to load alerts');
    } finally {
      loadingAlerts = false;
    }
  }

  async function loadStatistics() {
    try {
      const response = await axios.get('http://localhost:8000/api/alerts/statistics');
      
      if (response.data.success) {
        statistics.set(response.data.statistics);
      }
    } catch (e) {
      console.error('Error loading alert statistics:', e);
    }
  }

  async function loadAlertRules() {
    try {
      const response = await axios.get('http://localhost:8000/api/alerts/rules');
      
      if (response.data.success) {
        alertRules.set(response.data.rules);
      }
    } catch (e) {
      console.error('Error loading alert rules:', e);
    }
  }

  async function acknowledgeAlert(alertId) {
    if (!checkAuthentication()) return;
    
    try {
      const response = await axios.post(`http://localhost:8000/api/alerts/${alertId}/acknowledge`, {}, {
        withCredentials: true
      });
      
      if (response.data.success) {
        // Update local state
        alerts.update(current => 
          current.map(alert => 
            alert.id === alertId 
              ? { ...alert, acknowledged: true }
              : alert
          )
        );
        
        // Show success message
        error.set(null);
        success.set('Alert acknowledged successfully');
        setTimeout(() => success.set(null), 3000);
      }
    } catch (e) {
      console.error('Error acknowledging alert:', e);
      
      // Handle different error types
      if (e.response?.status === 401) {
        error.set('Authentication required. Please log in to acknowledge alerts.');
        // Redirect to login after a short delay
        setTimeout(() => {
          window.location.href = '/login';
        }, 2000);
      } else if (e.response?.status === 404) {
        error.set('Alert not found. It may have been deleted or already processed.');
      } else if (e.response?.status === 403) {
        error.set('Permission denied. You do not have permission to acknowledge alerts.');
      } else if (e.response?.status === 500) {
        error.set('Server error. Please try again later.');
      } else if (e.code === 'NETWORK_ERROR' || e.code === 'ERR_NETWORK') {
        error.set('Network error. Please check your connection and try again.');
      } else {
        error.set(`Failed to acknowledge alert: ${e.response?.data?.detail || e.message || 'Unknown error'}`);
      }
    }
  }

  async function resolveAlert(alertId) {
    if (!checkAuthentication()) return;
    
    try {
      const response = await axios.post(`http://localhost:8000/api/alerts/${alertId}/resolve`, {}, {
        withCredentials: true
      });
      
      if (response.data.success) {
        // Update local state
        alerts.update(current => 
          current.map(alert => 
            alert.id === alertId 
              ? { ...alert, resolved: true }
              : alert
          )
        );
        
        // Show success message
        error.set(null);
        success.set('Alert resolved successfully');
        setTimeout(() => success.set(null), 3000);
      }
    } catch (e) {
      console.error('Error resolving alert:', e);
      
      // Handle different error types
      if (e.response?.status === 401) {
        error.set('Authentication required. Please log in to resolve alerts.');
        // Redirect to login after a short delay
        setTimeout(() => {
          window.location.href = '/login';
        }, 2000);
      } else if (e.response?.status === 404) {
        error.set('Alert not found. It may have been deleted or already processed.');
      } else if (e.response?.status === 403) {
        error.set('Permission denied. You do not have permission to resolve alerts.');
      } else if (e.response?.status === 500) {
        error.set('Server error. Please try again later.');
      } else if (e.code === 'NETWORK_ERROR' || e.code === 'ERR_NETWORK') {
        error.set('Network error. Please check your connection and try again.');
      } else {
        error.set(`Failed to resolve alert: ${e.response?.data?.detail || e.message || 'Unknown error'}`);
      }
    }
  }

  function showAlertDetails(alert) {
    // Open alert details in modal
    newAlert = alert;
    showNewAlertModal = true;
  }

  function getAlertLevelColor(level) {
    const colors = {
      'critical': 'alert-critical',
      'high': 'alert-high',
      'medium': 'alert-medium',
      'low': 'alert-low',
      'info': 'alert-info'
    };
    return colors[level] || 'alert-info';
  }

  function getAlertIcon(type) {
    const icons = {
      'threat_detected': '🚨',
      'zero_day_attack': '⚠️',
      'multiple_attacks': '🔄',
      'high_risk_port': '🎯',
      'brute_force': '🔓',
      'anomaly_detected': '📊',
      'system_overload': '⚡'
    };
    return icons[type] || '⚠️';
  }

  function formatTimestamp(timestamp) {
    return new Date(timestamp).toLocaleString();
  }

  // Since filtering is now done on the server side, we just use the alerts directly
  $: filteredAlerts = $alerts;

  // Computed property to determine if there are active attacks or warning prompts
  $: activeThreats = $alerts.filter(alert => 
    !alert.acknowledged && 
    ['critical', 'high', 'medium'].includes(alert.level) &&
    ['threat_detected', 'zero_day_attack', 'multiple_attacks', 'brute_force', 'system_overload'].includes(alert.alert_type)
  );

  $: hasActiveThreats = activeThreats.length > 0;
  $: hasUnacknowledgedAlerts = $alerts.some(alert => !alert.acknowledged);
</script>

<div class="alert-system-container">
  <div class="alert-header">
    <h1 class="alert-title">🚨 Real-time Alert System</h1>
    <p class="alert-description">Monitor and manage security alerts in real-time</p>
    
    <div class="alert-controls">
      <div class="main-controls">
        <div class="connection-status">
          <span class="status-indicator {$connected ? 'connected' : 'disconnected'}"></span>
          <span class="status-text">{$connected ? 'Connected' : 'Disconnected'}</span>
        </div>
        
        <div class="auth-status">
          <span class="status-indicator {$isAuthenticated ? 'connected' : 'disconnected'}"></span>
          <span class="status-text">{$isAuthenticated ? 'Authenticated' : 'Not Logged In'}</span>
        </div>
        
        <button class="settings-button" on:click={() => showSettingsModal = true}>
          ⚙️ Settings
        </button>
        
        {#if hasPermission('alert_management')}
          <button class="rules-button" on:click={() => showRulesModal = true}>
            📋 Rules
          </button>
        {/if}
        
        <button class="refresh-button" on:click={() => loadAlerts(1)}>
          🔄 Refresh
        </button>
      </div>
      
      <!-- Auto-refresh controls -->
      <div class="auto-refresh-controls">
        <button class="auto-refresh-toggle {autoRefreshEnabled ? 'enabled' : 'disabled'}" 
                on:click={toggleAutoRefresh}
                title="Toggle auto-refresh">
          {#if autoRefreshEnabled}
            ⏸️ Auto-refresh: ON
          {:else}
            ▶️ Auto-refresh: OFF
          {/if}
        </button>
        
        <select class="refresh-interval-select" 
                value={autoRefreshInterval}
                on:change={handleIntervalChange}>
          <option value={3000}>3s</option>
          <option value={5000}>5s</option>
          <option value={10000}>10s</option>
          <option value={30000}>30s</option>
        </select>
        
        <span class="last-refresh-time">
          Last: {lastRefreshTime.toLocaleTimeString()}
        </span>
      </div>
     </div>
  </div>

  {#if $error}
    <div class="error-message">
      <span class="error-icon">⚠️</span>
      <span>{$error}</span>
    </div>
  {/if}

  {#if $success}
    <div class="success-message">
      <span class="success-icon">✅</span>
      <span>{$success}</span>
    </div>
  {/if}

  <!-- Alert Statistics Dashboard -->
  <div class="statistics-section">
    <div class="stats-grid">
      <div class="stat-card total">
        <div class="stat-icon">📊</div>
        <div class="stat-content">
          <div class="stat-value">{$statistics.total_alerts_24h || 0}</div>
          <div class="stat-label">Total Alerts (24h)</div>
        </div>
      </div>
      
      <div class="stat-card critical">
        <div class="stat-icon">🚨</div>
        <div class="stat-content">
          <div class="stat-value">{$statistics.by_level?.critical || 0}</div>
          <div class="stat-label">Critical</div>
        </div>
      </div>
      
      <div class="stat-card high">
        <div class="stat-icon">⚠️</div>
        <div class="stat-content">
          <div class="stat-value">{$statistics.by_level?.high || 0}</div>
          <div class="stat-label">High</div>
        </div>
      </div>
      
      <div class="stat-card rules">
        <div class="stat-icon">📋</div>
        <div class="stat-content">
          <div class="stat-value">{$statistics.active_rules || 0}</div>
          <div class="stat-label">Active Rules</div>
        </div>
      </div>
    </div>
  </div>

  <!-- Alert Filters -->
  <div class="filter-section">
    <div class="filter-controls">
      <div class="filter-group">
        <label class="filter-label">
          <input type="checkbox" bind:checked={showOnlyUnresolved} on:change={() => loadAlerts(1)} />
          Show only unresolved
        </label>
      </div>
      
      <div class="filter-group">
        <label class="filter-label">Alert Level:</label>
        <select bind:value={alertLevelFilter} class="filter-select">
          {#each alertLevels as level}
            <option value={level}>{level === 'all' ? 'All Levels' : level.toUpperCase()}</option>
          {/each}
        </select>
      </div>
      
      <div class="filter-group">
        <label class="filter-label">Start Date:</label>
        <input 
          type="datetime-local" 
          bind:value={startDate} 
          class="filter-input"
          on:change={() => loadAlerts(1)}
        />
      </div>
      
      <div class="filter-group">
        <label class="filter-label">End Date:</label>
        <input 
          type="datetime-local" 
          bind:value={endDate} 
          class="filter-input"
          on:change={() => loadAlerts(1)}
        />
      </div>
      
      <div class="filter-group">
        <button class="filter-button" on:click={() => loadAlerts(1)}>
          🔍 Apply Filters
        </button>
        <button class="filter-button" on:click={() => {
          startDate = '';
          endDate = '';
          alertLevelFilter = 'all';
          showOnlyUnresolved = true;
          loadAlerts(1);
        }}>
          🗑️ Clear Filters
        </button>
      </div>
    </div>
  </div>

  <!-- Alerts List -->
  <div class="alerts-section">
    {#if loadingAlerts}
      <div class="loading-state">
        <div class="loading-spinner"></div>
        <p>Loading alerts...</p>
      </div>
    {:else if filteredAlerts.length === 0}
      <div class="empty-state">
        <div class="empty-icon">🎉</div>
        <h3>No Alerts</h3>
        <p>
          No alerts found for the current filters.
          {#if startDate || endDate}
            Try adjusting the date range or clearing filters.
          {:else}
            System is secure!
          {/if}
        </p>
      </div>
    {:else}

      
      <div class="alerts-list">
        {#each filteredAlerts as alert}
          <div class="alert-item {getAlertLevelColor(alert.level)} {alert.acknowledged ? 'acknowledged' : ''} {alert.resolved ? 'resolved' : ''}">
            
            <div class="alert-icon">
              {getAlertIcon(alert.alert_type)}
            </div>
            
            <div class="alert-content">
              <div class="alert-header-row">
                <h4 class="alert-item-title">{alert.title}</h4>
                <div class="alert-badges">
                  <span class="level-badge {getAlertLevelColor(alert.level)}">{alert.level.toUpperCase()}</span>
                  {#if alert.acknowledged}
                    <span class="status-badge acknowledged">✓ Acknowledged</span>
                  {/if}
                  {#if alert.resolved}
                    <span class="status-badge resolved">✅ Resolved</span>
                  {/if}
                </div>
              </div>
              
              <p class="alert-message">{alert.message}</p>
              
              <div class="alert-details">
                <div class="alert-meta">
                  <span class="meta-item">
                    <strong>Time:</strong> {formatTimestamp(alert.timestamp)}
                  </span>
                  {#if alert.source_ip}
                    <span class="meta-item">
                      <strong>Source:</strong> {alert.source_ip}
                    </span>
                  {/if}
                  {#if alert.target_port}
                    <span class="meta-item">
                      <strong>Port:</strong> {alert.target_port}
                    </span>
                  {/if}
                  {#if alert.model}
                    <span class="meta-item">
                      <strong>Model:</strong> {alert.model}
                    </span>
                  {/if}
                  {#if alert.confidence}
                    <span class="meta-item">
                      <strong>Confidence:</strong> {(alert.confidence * 100).toFixed(1)}%
                    </span>
                  {/if}
                </div>
              </div>
              
              <div class="alert-actions">
                {#if !alert.acknowledged}
                  <button class="action-button acknowledge" on:click={() => acknowledgeAlert(alert.id)}>
                    ✓ Acknowledge
                  </button>
                {/if}
                
                {#if !alert.resolved}
                  <button class="action-button resolve" on:click={() => resolveAlert(alert.id)}>
                    ✅ Resolve
                  </button>
                {/if}
                
                <button class="action-button details" on:click={() => showAlertDetails(alert)}>
                  👁️ Details
                </button>
              </div>
            </div>
          </div>
        {/each}
      </div>
      
      <!-- Pagination Controls -->
      {#if totalPages > 1}
        <div class="pagination-controls">
          <div class="pagination-info">
            Showing page {currentPage} of {totalPages} ({totalAlerts} total alerts)
          </div>
          
          <div class="pagination-buttons">
            <button 
              class="pagination-button" 
              disabled={currentPage === 1}
              on:click={() => loadAlerts(currentPage - 1)}
            >
              ← Previous
            </button>
            
            {#each (() => {
              const pages = [];
              const startPage = Math.max(1, currentPage - 2);
              const endPage = Math.min(totalPages, startPage + 4);
              
              for (let i = startPage; i <= endPage; i++) {
                pages.push(i);
              }
              return pages;
            })() as pageNum}
              <button 
                class="pagination-button {currentPage === pageNum ? 'active' : ''}"
                on:click={() => loadAlerts(pageNum)}
              >
                {pageNum}
              </button>
            {/each}
            
            <button 
              class="pagination-button" 
              disabled={currentPage === totalPages}
              on:click={() => loadAlerts(currentPage + 1)}
            >
              Next →
            </button>
          </div>
        </div>
      {/if}
    {/if}
  </div>

  <!-- New Alert Modal -->
  {#if showNewAlertModal && newAlert}
    <div class="modal-overlay" on:click={closeAlertModal}>
      <div class="modal-content alert-modal" on:click|stopPropagation>
        <div class="modal-header {getAlertLevelColor(newAlert.level)}">
          <h3>🚨 Critical Security Alert</h3>
          <button class="close-button" on:click={closeAlertModal}>✕</button>
        </div>
        
        <div class="modal-body">
          <div class="alert-details-full">
            <h4>{newAlert.title}</h4>
            <p class="alert-message-full">{newAlert.message}</p>
            
            <div class="alert-meta-full">
              <div class="meta-row">
                <span class="meta-label">Time:</span>
                <span class="meta-value">{formatTimestamp(newAlert.timestamp)}</span>
              </div>
              {#if newAlert.source_ip}
                <div class="meta-row">
                  <span class="meta-label">Source IP:</span>
                  <span class="meta-value">{newAlert.source_ip}</span>
                </div>
              {/if}
              {#if newAlert.target_port}
                <div class="meta-row">
                  <span class="meta-label">Target Port:</span>
                  <span class="meta-value">{newAlert.target_port}</span>
                </div>
              {/if}
              {#if newAlert.model}
                <div class="meta-row">
                  <span class="meta-label">Detection Model:</span>
                  <span class="meta-value">{newAlert.model}</span>
                </div>
              {/if}
              {#if newAlert.confidence}
                <div class="meta-row">
                  <span class="meta-label">Confidence:</span>
                  <span class="meta-value">{(newAlert.confidence * 100).toFixed(1)}%</span>
                </div>
              {/if}
            </div>
          </div>
        </div>
        
        <div class="modal-footer">
          <button class="modal-button secondary" on:click={closeAlertModal}>
            Close
          </button>
          <button class="modal-button primary" on:click={() => { acknowledgeAlert(newAlert.id); closeAlertModal(); }}>
            ✓ Acknowledge
          </button>
        </div>
      </div>
    </div>
  {/if}

  <!-- Settings Modal -->
  {#if showSettingsModal}
    <div class="modal-overlay" on:click={() => showSettingsModal = false}>
      <div class="modal-content settings-modal" on:click|stopPropagation>
        <div class="modal-header">
          <h3>⚙️ Alert Settings</h3>
          <button class="close-button" on:click={() => showSettingsModal = false}>✕</button>
        </div>
        
        <div class="modal-body">
          <div class="settings-grid">
            <div class="setting-item">
              <label class="setting-label">
                <input type="checkbox" bind:checked={soundEnabled} />
                <span>Enable alert sounds</span>
              </label>
            </div>
            
            <div class="setting-item">
              <label class="setting-label">
                <input type="checkbox" bind:checked={desktopNotificationsEnabled} />
                <span>Enable desktop notifications</span>
              </label>
            </div>
            
            <div class="setting-item">
              <label class="setting-label">
                <input type="checkbox" bind:checked={autoAcknowledge} />
                <span>Auto-acknowledge non-critical alerts</span>
              </label>
            </div>
          </div>
          
          <div class="settings-actions">
            <button class="test-button" on:click={playAlertSound}>
              🔊 Test Sound
            </button>
            {#if settingsSaved}
              <div class="save-status" style="color: #10b981; font-size: 0.9em; margin-top: 0.5rem;">
                ✅ Settings saved automatically
              </div>
            {/if}
          </div>
        </div>
        
        <div class="modal-footer">
          <button class="modal-button secondary" on:click={() => showSettingsModal = false}>
            Close
          </button>
          <button class="modal-button primary" on:click={() => { 
            saveAlertSettings(); 
            settingsSaved = true;
            setTimeout(() => settingsSaved = false, 2000);
            showSettingsModal = false; 
          }}>
            Save Settings
          </button>
        </div>
      </div>
    </div>
  {/if}

  <!-- Rule Management Modal -->
  {#if showRulesModal}
    <div class="modal-overlay" on:click={() => { showRulesModal = false; cancelAddEditModal(); }}>
      <div class="modal-content settings-modal" style="max-width:900px;min-width:600px;" on:click|stopPropagation>
        <div class="modal-header">
          <h3>📋 Rule Management</h3>
          <button class="close-button" on:click={() => { showRulesModal = false; cancelAddEditModal(); }}>✕</button>
        </div>
        <div class="modal-body" style="position:relative;">
          <button class="modal-button primary" on:click={openAddRule} style="margin-bottom:1rem;" disabled={showAddEditModal}>➕ Add Rule</button>
          <table style="width:100%;border-collapse:collapse;">
            <thead>
              <tr style="background:#f3f4f6;">
                <th>Name</th><th>Type</th><th>Conditions</th><th>Actions</th><th>Enabled</th><th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {#each $alertRules as rule}
                <tr style="border-bottom:1px solid #eee;">
                  <td>{rule.name}</td>
                  <td>{rule.alert_type}</td>
                  <td><pre style="font-size:0.8em;max-width:200px;overflow-x:auto;">{JSON.stringify(rule.conditions, null, 1)}</pre></td>
                  <td>{rule.actions?.join(',')}</td>
                  <td>{rule.enabled ? 'Yes' : 'No'}</td>
                  <td>
                    <button class="modal-button secondary" on:click={() => openEditRule(rule)} disabled={showAddEditModal}>Edit</button>
                    <button class="modal-button danger" on:click={() => deleteRule(rule)} disabled={showAddEditModal}>Delete</button>
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
          {#if showAddEditModal}
            <div class="modal-overlay" style="z-index:1100; background:rgba(0,0,0,0.4);" on:click={cancelAddEditModal}>
              <div class="modal-content settings-modal" style="max-width:600px;" on:click|stopPropagation>
                <div class="modal-header">
                  <h4>{editingRule ? 'Edit Rule' : 'Add Rule'}</h4>
                  <button class="close-button" on:click={cancelAddEditModal}>✕</button>
                </div>
                <div class="modal-body">
                  <form on:submit|preventDefault={saveRule}>
                    <div style="display:flex;gap:1rem;flex-wrap:wrap;">
                      <div style="flex:1;min-width:200px;">
                        <label>Name<input type="text" bind:value={ruleForm.name} required /></label>
                      </div>
                      <div style="flex:1;min-width:200px;">
                        <label>Type
                          <select bind:value={ruleForm.alert_type}>
                            {#each alertTypeOptions as opt}
                              <option value={opt.value}>{opt.label}</option>
                            {/each}
                          </select>
                        </label>
                      </div>
                      <div style="flex:2;min-width:300px;">
                        <label>Conditions(JSON)<textarea bind:value={ruleForm.conditions} rows="3" style="width:100%;font-family:monospace;"></textarea></label>
                      </div>
                      <div style="flex:1;min-width:200px;">
                        <label>Actions
                          <select multiple bind:value={ruleForm.actions} style="height:80px;">
                            {#each actionOptions as opt}
                              <option value={opt.value}>{opt.label}</option>
                            {/each}
                          </select>
                        </label>
                      </div>
                      <div style="flex:1;min-width:100px;">
                        <label>Enabled <input type="checkbox" bind:checked={ruleForm.enabled} /></label>
                      </div>
                      <div style="flex:1;min-width:100px;">
                        <label>Threshold <input type="number" step="0.01" bind:value={ruleForm.threshold} /></label>
                      </div>
                      <div style="flex:1;min-width:100px;">
                        <label>Time Window(minutes) <input type="number" bind:value={ruleForm.time_window} /></label>
                      </div>
                    </div>
                    <div style="margin-top:1rem;display:flex;gap:1rem;justify-content:flex-end;">
                      <button class="modal-button primary" type="submit">Save</button>
                      <button class="modal-button secondary" type="button" on:click={cancelAddEditModal}>Cancel</button>
                    </div>
                  </form>
                </div>
              </div>
            </div>
          {/if}
        </div>
      </div>
    </div>
  {/if}
</div>

<style>
  .alert-system-container {
    padding: 2rem;
    max-width: 100%;
    margin: 0;
    min-height: 100vh;
    width: 100%;
  }

  .alert-header {
    margin-bottom: 2rem;
    text-align: center;
  }

  .alert-title {
    font-size: 2.5rem;
    font-weight: bold;
    margin: 0 0 0.5rem 0;
    color: #1f2937;
  }

  .alert-description {
    font-size: 1.1rem;
    color: #6b7280;
    margin: 0 0 2rem 0;
  }

  .alert-controls {
    display: flex;
    justify-content: center;
    align-items: center;
    gap: 1rem;
    flex-wrap: wrap;
    background: white;
    padding: 1rem 2rem;
    border-radius: 12px;
    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
  }

  .main-controls {
    display: flex;
    align-items: center;
    gap: 1rem;
    flex-wrap: wrap;
  }

  .connection-status {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.9rem;
    color: #6b7280;
  }

  .auth-status {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.9rem;
    color: #6b7280;
  }

  .status-indicator {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    display: inline-block;
  }

  .status-indicator.connected {
    background-color: #10b981;
  }

  .status-indicator.disconnected {
    background-color: #ef4444;
  }

  .status-text {
    font-size: 0.875rem;
    font-weight: 500;
    color: #374151;
  }

  .settings-button, .rules-button, .refresh-button {
    background-color: #6b7280;
    color: white;
    border: none;
    padding: 0.5rem 1rem;
    border-radius: 6px;
    font-size: 0.875rem;
    cursor: pointer;
    transition: background-color 0.2s ease;
    font-weight: 500;
  }

  .settings-button:hover, .rules-button:hover, .refresh-button:hover {
    background-color: #4b5563;
  }
  
  /* Auto-refresh controls styling */
  .auto-refresh-controls {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    margin-left: 1rem;
    padding-left: 1rem;
    border-left: 1px solid #e5e7eb;
  }
  
  .auto-refresh-toggle {
    background-color: #10b981;
    color: white;
    border: none;
    padding: 0.5rem 1rem;
    border-radius: 6px;
    font-size: 0.875rem;
    cursor: pointer;
    transition: all 0.2s ease;
    font-weight: 500;
    white-space: nowrap;
  }
  
  .auto-refresh-toggle:hover {
    background-color: #059669;
    transform: translateY(-1px);
  }
  
  .auto-refresh-toggle.enabled {
    background-color: #10b981;
  }
  
  .auto-refresh-toggle.enabled:hover {
    background-color: #059669;
  }
  
  .auto-refresh-toggle.disabled {
    background-color: #dc2626;
  }
  
  .auto-refresh-toggle.disabled:hover {
    background-color: #b91c1c;
  }
  
  .refresh-interval-select {
    background-color: white;
    border: 1px solid #d1d5db;
    border-radius: 6px;
    padding: 0.5rem;
    font-size: 0.875rem;
    color: #374151;
    cursor: pointer;
    transition: border-color 0.2s ease;
  }
  
  .refresh-interval-select:hover {
    border-color: #9ca3af;
  }
  
  .refresh-interval-select:focus {
    outline: none;
    border-color: #3b82f6;
    box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
  }
  
  .last-refresh-time {
    font-size: 0.75rem;
    color: #6b7280;
    font-style: italic;
    white-space: nowrap;
  }

  .statistics-section {
    margin-bottom: 2rem;
  }



  .stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1rem;
  }

  .stat-card {
    background: white;
    padding: 1.5rem;
    border-radius: 12px;
    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
    display: flex;
    align-items: center;
    gap: 1rem;
    border-left: 4px solid #e5e7eb;
  }

  .stat-card.total { border-left-color: #3b82f6; }
  .stat-card.critical { border-left-color: #ef4444; }
  .stat-card.high { border-left-color: #f59e0b; }
  .stat-card.rules { border-left-color: #10b981; }

  .stat-icon {
    font-size: 2rem;
  }

  .stat-value {
    font-size: 2rem;
    font-weight: bold;
    color: #1f2937;
  }

  .stat-label {
    font-size: 0.875rem;
    color: #6b7280;
  }

  .filter-section {
    background: white;
    padding: 1rem 1.5rem;
    border-radius: 12px;
    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
    margin-bottom: 1.5rem;
  }

  .filter-controls {
    display: flex;
    align-items: center;
    gap: 2rem;
    flex-wrap: wrap;
  }

  .filter-group {
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }

  .filter-label {
    font-size: 0.875rem;
    font-weight: 500;
    color: #374151;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }

  .filter-select {
    border: 1px solid #d1d5db;
    padding: 0.375rem 0.75rem;
    border-radius: 6px;
    font-size: 0.875rem;
  }

  .alerts-section {
    background: white;
    border-radius: 12px;
    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
    overflow: hidden;
  }

  .loading-state, .empty-state {
    padding: 3rem;
    text-align: center;
  }

  .loading-spinner {
    width: 40px;
    height: 40px;
    border: 4px solid #e5e7eb;
    border-left: 4px solid #3b82f6;
    border-radius: 50%;
    animation: spin 1s linear infinite;
    margin: 0 auto 1rem auto;
  }

  .empty-icon {
    font-size: 4rem;
    margin-bottom: 1rem;
  }

  .empty-state h3 {
    margin: 0 0 0.5rem 0;
    color: #1f2937;
  }

  .empty-state p {
    margin: 0;
    color: #6b7280;
  }

  .alerts-list {
    max-height: 600px;
    overflow-y: auto;
  }

  .alert-item {
    display: flex;
    align-items: flex-start;
    gap: 1rem;
    padding: 1.5rem;
    border-bottom: 1px solid #f3f4f6;
    transition: background-color 0.2s ease;
    border-left: 4px solid transparent;
  }

  .alert-item:hover {
    background-color: #f9fafb;
  }

  .alert-item.acknowledged {
    opacity: 0.7;
  }

  .alert-item.resolved {
    opacity: 0.5;
  }

  .alert-item.alert-critical { border-left-color: #ef4444; background-color: #fef2f2; }
  .alert-item.alert-high { border-left-color: #f59e0b; background-color: #fffbeb; }
  .alert-item.alert-medium { border-left-color: #f59e0b; background-color: #fefce8; }
  .alert-item.alert-low { border-left-color: #10b981; background-color: #f0fdf4; }
  .alert-item.alert-info { border-left-color: #3b82f6; background-color: #eff6ff; }

  .alert-icon {
    font-size: 1.5rem;
    margin-top: 0.25rem;
  }

  .alert-content {
    flex: 1;
  }

  .alert-header-row {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    margin-bottom: 0.5rem;
  }

  .alert-item-title {
    margin: 0;
    color: #1f2937;
    font-size: 1.125rem;
    font-weight: 600;
  }

  .alert-badges {
    display: flex;
    gap: 0.5rem;
    flex-wrap: wrap;
  }

  .level-badge, .status-badge {
    padding: 0.25rem 0.5rem;
    border-radius: 12px;
    font-size: 0.75rem;
    font-weight: 600;
    white-space: nowrap;
  }

  .level-badge.alert-critical { background: #fee2e2; color: #991b1b; }
  .level-badge.alert-high { background: #fef3c7; color: #92400e; }
  .level-badge.alert-medium { background: #fef3c7; color: #d97706; }
  .level-badge.alert-low { background: #dcfce7; color: #166534; }
  .level-badge.alert-info { background: #dbeafe; color: #1e40af; }

  .status-badge.acknowledged { background: #e0e7ff; color: #3730a3; }
  .status-badge.resolved { background: #dcfce7; color: #166534; }

  .alert-message {
    margin: 0 0 1rem 0;
    color: #374151;
    line-height: 1.5;
  }

  .alert-meta {
    display: flex;
    flex-wrap: wrap;
    gap: 1rem;
    margin-bottom: 1rem;
  }

  .meta-item {
    font-size: 0.875rem;
    color: #6b7280;
  }

  .meta-item strong {
    color: #374151;
  }

  .alert-actions {
    display: flex;
    gap: 0.75rem;
    flex-wrap: wrap;
  }

  .action-button {
    border: none;
    padding: 0.5rem 1rem;
    border-radius: 6px;
    font-size: 0.75rem;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.2s ease;
  }

  .action-button.acknowledge {
    background: #e0e7ff;
    color: #3730a3;
  }

  .action-button.acknowledge:hover {
    background: #c7d2fe;
  }

  .action-button.resolve {
    background: #dcfce7;
    color: #166534;
  }

  .action-button.resolve:hover {
    background: #bbf7d0;
  }

  .action-button.details {
    background: #f3f4f6;
    color: #374151;
  }

  .action-button.details:hover {
    background: #e5e7eb;
  }

  .error-message {
    background-color: #fee2e2;
    color: #991b1b;
    padding: 1rem;
    border-radius: 8px;
    margin-bottom: 1rem;
    display: flex;
    align-items: center;
    gap: 0.75rem;
    border: 1px solid #fecaca;
  }

  .success-message {
    background-color: #dcfce7;
    color: #166534;
    padding: 1rem;
    border-radius: 8px;
    margin-bottom: 1rem;
    display: flex;
    align-items: center;
    gap: 0.75rem;
    border: 1px solid #bbf7d0;
  }

  /* Modal Styles - Beautified and Responsive */
  .modal-overlay {
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: rgba(0, 0, 0, 0.5);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 1000;
    padding: 1rem;
    cursor: pointer;
  }
  .modal-content {
    background: white;
    border-radius: 14px;
    box-shadow: 0 8px 32px rgba(0,0,0,0.18), 0 1.5px 4px rgba(0,0,0,0.08);
    max-width: 900px;
    width: 100%;
    max-height: 80vh;
    overflow-y: auto;
    font-size: 1.05rem;
    padding: 0;
  }
  /* Main rules modal */
  .modal-content.settings-modal {
    max-width: 900px;
    min-width: 320px;
    font-size: 1.05rem;
  }
  /* Add/Edit modal */
  .modal-content.settings-modal[style*="max-width:600px"] {
    max-width: 480px !important;
    min-width: 260px;
    font-size: 1rem;
  }
  /* Alert modal */
  .modal-content.alert-modal {
    max-width: 600px;
    min-width: 260px;
    font-size: 1.1rem;
  }
  .modal-header {
    padding: 1.25rem 1.5rem;
    border-bottom: 1px solid #e5e7eb;
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-size: 1.15rem;
    font-weight: 600;
  }
  .modal-header.alert-critical {
    background: #fee2e2;
    border-bottom-color: #fecaca;
  }

  .modal-header h3 {
    margin: 0;
    color: #1f2937;
    font-size: 1.25rem;
  }

  .close-button {
    background: none;
    border: none;
    font-size: 1.5rem;
    cursor: pointer;
    color: #6b7280;
    padding: 0.25rem;
    border-radius: 4px;
    transition: color 0.2s;
  }

  .close-button:hover {
    color: #374151;
  }





  .modal-body {
    padding: 1.5rem 1.5rem 1.5rem 1.5rem;
    font-size: 1.05rem;
  }

  .modal-footer {
    padding: 1rem 1.5rem;
    border-top: 1px solid #e5e7eb;
    display: flex;
    gap: 1rem;
    justify-content: flex-end;
  }

  .modal-button {
    border: none;
    padding: 0.75rem 1.5rem;
    border-radius: 6px;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.2s ease;
  }

  .modal-button.secondary {
    background: #f3f4f6;
    color: #374151;
  }

  .modal-button.secondary:hover {
    background: #e5e7eb;
  }

  .modal-button.primary {
    background: #3b82f6;
    color: white;
  }

  .modal-button.primary:hover {
    background: #2563eb;
  }

  .alert-details-full h4 {
    margin: 0 0 1rem 0;
    color: #1f2937;
    font-size: 1.25rem;
  }

  .alert-message-full {
    margin: 0 0 1.5rem 0;
    color: #374151;
    line-height: 1.6;
  }

  .alert-meta-full {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }

  .meta-row {
    display: flex;
    justify-content: space-between;
    padding: 0.5rem 0;
    border-bottom: 1px solid #f3f4f6;
  }

  .meta-label {
    font-weight: 600;
    color: #374151;
  }

  .meta-value {
    color: #1f2937;
    font-family: 'Monaco', 'Consolas', 'Courier New', monospace;
    font-size: 0.875rem;
  }

  .settings-grid {
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }

  .setting-item {
    padding: 1rem;
    border: 1px solid #e5e7eb;
    border-radius: 8px;
  }

  .setting-label {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    font-weight: 500;
    color: #374151;
    cursor: pointer;
  }

  .settings-actions {
    margin-top: 1.5rem;
    padding-top: 1.5rem;
    border-top: 1px solid #e5e7eb;
  }

  .test-button {
    background: #6b7280;
    color: white;
    border: none;
    padding: 0.75rem 1.5rem;
    border-radius: 6px;
    cursor: pointer;
    transition: background-color 0.2s ease;
  }

  .test-button:hover {
    background: #4b5563;
  }

  /* Pagination Controls */
  .pagination-controls {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 1rem;
    margin-top: 2rem;
    padding: 1rem;
    background: #1f2937;
    border-radius: 8px;
    border: 1px solid #374151;
  }

  .pagination-info {
    color: #9ca3af;
    font-size: 0.9rem;
  }

  .pagination-buttons {
    display: flex;
    gap: 0.5rem;
    align-items: center;
  }

  .pagination-button {
    padding: 0.5rem 1rem;
    background: #374151;
    color: #e5e7eb;
    border: 1px solid #4b5563;
    border-radius: 6px;
    cursor: pointer;
    transition: all 0.2s ease;
    font-size: 0.9rem;
  }

  .pagination-button:hover:not(:disabled) {
    background: #4b5563;
    border-color: #6b7280;
  }

  .pagination-button.active {
    background: #3b82f6;
    border-color: #3b82f6;
    color: white;
  }

  .pagination-button:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  /* Filter Controls */
  .filter-input {
    padding: 0.5rem;
    background: white;
    border: 1px solid #d1d5db;
    border-radius: 6px;
    color: #374151;
    font-size: 0.9rem;
    min-width: 200px;
  }

  .filter-input:focus {
    outline: none;
    border-color: #3b82f6;
    box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.2);
  }

  .filter-input[type="datetime-local"] {
    font-family: inherit;
  }

  .filter-button {
    padding: 0.5rem 1rem;
    background: #3b82f6;
    color: white;
    border: none;
    border-radius: 6px;
    cursor: pointer;
    transition: background-color 0.2s ease;
    font-size: 0.9rem;
    margin-left: 0.5rem;
  }

  .filter-button:hover {
    background: #2563eb;
  }

  .filter-button:last-child {
    background: #6b7280;
  }

  .filter-button:last-child:hover {
    background: #4b5563;
  }

  @keyframes pulse {
    0%, 100% {
      opacity: 1;
    }
    50% {
      opacity: 0.5;
    }
  }

  @keyframes spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
  }

  @keyframes modalSlideIn {
    from {
      opacity: 0;
      transform: translateY(-20px) scale(0.95);
    }
    to {
      opacity: 1;
      transform: translateY(0) scale(1);
    }
  }

  /* Responsive Design */
  @media (max-width: 768px) {
    .alert-system-container {
      padding: 1rem;
    }

    .alert-title {
      font-size: 2rem;
    }

    .alert-controls {
      flex-direction: column;
      gap: 1rem;
    }
    
    /* Mobile: Main controls (status + buttons) in one row */
    .main-controls {
      display: flex;
      flex-direction: row;
      gap: 0.5rem;
      justify-content: center;
      flex-wrap: wrap;
      align-items: center;
    }
    
    /* Mobile: Settings, Rules, Refresh buttons in same row */
    .settings-button, .rules-button, .refresh-button {
      flex: 1;
      min-width: 120px;
      max-width: 150px;
    }
    
    /* Mobile: Status indicators smaller on mobile */
    .connection-status, .auth-status {
      font-size: 0.8rem;
      min-width: 100px;
    }
    
    .auto-refresh-controls {
      margin-left: 0;
      padding-left: 0;
      border-left: none;
      border-top: 1px solid #e5e7eb;
      padding-top: 1rem;
      justify-content: center;
      flex-wrap: wrap;
      display: flex;
      flex-direction: row;
      gap: 0.5rem;
    }
    
    /* Mobile: Auto-refresh controls in same row */
    .auto-refresh-toggle {
      flex: 1;
      min-width: 120px;
      max-width: 150px;
    }
    
    .refresh-interval-select {
      flex: 1;
      min-width: 80px;
      max-width: 100px;
    }
    
    .last-refresh-time {
      flex: 1;
      min-width: 120px;
      max-width: 150px;
      text-align: center;
    }

    .stats-grid {
      grid-template-columns: repeat(2, 1fr);
    }

    .filter-controls {
      flex-direction: column;
      align-items: flex-start;
      gap: 1rem;
    }

    .bulk-controls {
      flex-direction: column;
      align-items: flex-start;
      gap: 1rem;
    }

    .bulk-action-buttons {
      width: 100%;
      justify-content: flex-start;
    }

    .alert-item {
      flex-direction: column;
      align-items: flex-start;
    }

    .alert-header-row {
      flex-direction: column;
      align-items: flex-start;
      gap: 0.5rem;
    }

    .alert-meta {
      flex-direction: column;
      gap: 0.5rem;
    }

    .modal-content {
      margin: 0.5rem;
      max-height: 95vh;
    }

    .modal-header, .modal-body, .modal-footer {
      padding: 1rem;
    }
  }

  @media (max-width: 480px) {
    .stats-grid {
      grid-template-columns: 1fr;
    }

    .stat-card {
      padding: 1rem;
    }

    .stat-value {
      font-size: 1.5rem;
    }
    
    /* Very small screens: Stack auto-refresh controls vertically */
    .auto-refresh-controls {
      flex-direction: column;
      gap: 0.5rem;
      align-items: center;
      flex-wrap: wrap;
    }
    
    .auto-refresh-toggle,
    .refresh-interval-select,
    .last-refresh-time {
      width: 100%;
      max-width: 200px;
      min-width: 0;
      flex: none;
    }
    
    .auto-refresh-toggle {
      padding: 0.4rem 0.5rem;
    }
    
    .refresh-interval-select {
      padding: 0.4rem;
    }
    
    .last-refresh-time {
      font-size: 0.7rem;
    }
    
    /* Very small screens: Stack main controls vertically */
    .main-controls {
      flex-direction: column;
      align-items: center;
      gap: 0.5rem;
    }
    
    .settings-button, .rules-button, .refresh-button {
      width: 100%;
      max-width: 200px;
      min-width: 0;
      flex: none;
    }
    
    .connection-status, .auth-status {
      width: 100%;
      max-width: 200px;
      justify-content: center;
    }

    .alert-actions {
      flex-direction: column;
    }

    .action-button {
      width: 100%;
      text-align: center;
    }
  }
  /* Table and pre block improvements */
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.95rem;
    table-layout: fixed;
  }
  th, td {
    padding: 0.5rem 0.5rem;
    text-align: left;
    word-break: break-word;
    vertical-align: top;
    max-width: 180px;
    overflow-wrap: break-word;
  }
  th {
    font-size: 1rem;
    background: #f3f4f6;
  }
  pre {
    font-size: 0.85rem;
    background: #f8fafc;
    border-radius: 6px;
    padding: 0.25rem 0.5rem;
    margin: 0;
    max-width: 100%;
    overflow-x: auto;
    white-space: pre-wrap;
    word-break: break-all;
  }
  @media (max-width: 600px) {
    .modal-content, .modal-content.settings-modal, .modal-content.alert-modal {
      max-width: 98vw !important;
      min-width: 0;
      font-size: 0.98rem;
      padding: 0;
    }
    .modal-header, .modal-body, .modal-footer {
      padding: 0.75rem 0.75rem;
    }
    th, td {
      font-size: 0.9rem;
      padding: 0.35rem 0.25rem;
      max-width: 90vw;
    }
  }
  /* End modal beautification */
</style> 