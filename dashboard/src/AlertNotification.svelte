<script>
    import { onMount, onDestroy } from 'svelte';
  import { writable } from 'svelte/store';
  import { hasPermission } from './stores/auth.js';
  
  // Props
  export let maxNotifications = 5; // Increased from 1 to 5
  export let autoHideDelay = 3000; // 10 seconds
  
  // State
  // Store for active notifications
  let notifications = writable([]);
  // Map to track recent alert keys and their timestamps for throttling
  let recentAlertMap = new Map();
  // Throttle window in milliseconds
  const throttleWindow = 2000;
  
  // Alert aggregation and management
  let alertGroups = new Map(); // Group alerts by type, IP, etc.
  let totalUnacknowledged = 0;
  let showAlertManager = false;
  let forceUpdate = 0; // Force re-render when needed
  
  // Audio
  let audioContext = null;
  let soundEnabled = true;
  
  let alertEventListener = null;
  
  onMount(async () => {
    if (!hasPermission('view_alerts')) {
      return;
    }

    await initializeAudio();
    
    // Listen for WebSocket alert messages from Layout.svelte
    alertEventListener = (event) => {
      handleNewAlert(event.detail);
    };
    
    document.addEventListener('newAlert', alertEventListener);
  });
  
  onDestroy(() => {
    // Cleanup event listener
    if (alertEventListener) {
      document.removeEventListener('newAlert', alertEventListener);
    }
    
    if (audioContext) {
      audioContext.close();
    }
  });

  async function initializeAudio() {
    try {
      // @ts-ignore - webkitAudioContext is a fallback for older browsers
      audioContext = new (window.AudioContext || window.webkitAudioContext)();
    } catch (e) {
      console.error('Audio initialization failed:', e);
    }
  }

  async function playNotificationSound() {
    if (!soundEnabled || !audioContext) return;

    try {
      if (audioContext.state === 'suspended') {
        await audioContext.resume();
      }

      // Create a subtle notification sound
      const oscillator = audioContext.createOscillator();
      const gainNode = audioContext.createGain();
      
      oscillator.connect(gainNode);
      gainNode.connect(audioContext.destination);
      
      oscillator.frequency.setValueAtTime(800, audioContext.currentTime);
      oscillator.frequency.exponentialRampToValueAtTime(400, audioContext.currentTime + 0.3);
      
      gainNode.gain.setValueAtTime(0, audioContext.currentTime);
      gainNode.gain.linearRampToValueAtTime(0.2, audioContext.currentTime + 0.05);
      gainNode.gain.exponentialRampToValueAtTime(0.01, audioContext.currentTime + 0.3);
      
      oscillator.start(audioContext.currentTime);
      oscillator.stop(audioContext.currentTime + 0.3);
      
    } catch (e) {
      console.error('Failed to play notification sound:', e);
    }
  }

  function handleNewAlert(alertData) {
    
    // Generate a unique key for de-duplication (type + source_ip + target_port)
    const alertKey = `${alertData.title}|${alertData.source_ip || ''}|${alertData.target_port || ''}`;
    const now = Date.now();
    
    // If a similar alert was shown within the throttle window, refresh its timestamp and skip adding a new one
    if (recentAlertMap.has(alertKey)) {
      const existing = recentAlertMap.get(alertKey);
      // Update timestamp to extend visibility
      existing.timestamp = now;
      // Update notifications store to refresh the timestamp
      notifications.update(current => {
        return current.map(n =>
          n.key === alertKey ? { ...n, timestamp: new Date(now) } : n
        );
      });
      return;
    }
    
    // Create notification object
    const notification = {
      id: alertData.id,
      key: alertKey,
      title: alertData.title,
      message: alertData.message,
      level: alertData.level,
      timestamp: new Date(now),
      autoHide: alertData.level !== 'critical',
      source_ip: alertData.source_ip,
      target_port: alertData.target_port,
      attack_type: alertData.attack_type || 'Unknown'
    };
    
    // Add to notifications with smart filtering
    notifications.update(current => {
      let updated = [notification, ...current];
      
      // Smart filtering based on alert level and frequency
      if (alertData.level === 'critical') {
        // Critical alerts always show, but limit to 3
        const criticalAlerts = updated.filter(n => n.level === 'critical');
        if (criticalAlerts.length > 3) {
          // Remove oldest critical alerts
          const oldestCritical = criticalAlerts.slice(3);
          updated = updated.filter(n => !oldestCritical.includes(n));
        }
      } else if (alertData.level === 'high') {
        // High alerts limited to 5
        const highAlerts = updated.filter(n => n.level === 'high');
        if (highAlerts.length > 5) {
          const oldestHigh = highAlerts.slice(5);
          updated = updated.filter(n => !oldestHigh.includes(n));
        }
      } else {
        // Medium/Low alerts limited to 3
        const mediumLowAlerts = updated.filter(n => ['medium', 'low'].includes(n.level));
        if (mediumLowAlerts.length > 3) {
          const oldestMediumLow = mediumLowAlerts.slice(3);
          updated = updated.filter(n => !oldestMediumLow.includes(n));
        }
      }
      
      // Overall limit
      updated = updated.slice(0, maxNotifications);
      
      return updated;
    });
    
    // Track this alert in the recent map
    recentAlertMap.set(alertKey, notification);
    
    // Update total unacknowledged count
    totalUnacknowledged++;
    
    // Play sound
    playNotificationSound();
    
    // Auto-hide non-critical notifications after throttleWindow
    if (notification.autoHide) {
      setTimeout(() => {
        removeNotification(notification.id);
        recentAlertMap.delete(alertKey);
        totalUnacknowledged = Math.max(0, totalUnacknowledged - 1);
      }, throttleWindow);
    } else {
      // For critical, remove from map after throttleWindow but keep notification until user closes
      setTimeout(() => {
        recentAlertMap.delete(alertKey);
      }, throttleWindow);
    }
  }
  
  // Batch operations
  function closeAllAlerts() {
    // First, close the Alert Manager panel immediately
    showAlertManager = false;
    
    // Force a complete re-render by triggering a state change
    forceUpdate++;
    
    notifications.set([]);
    recentAlertMap.clear();
    totalUnacknowledged = 0;
    
    // Dispatch global event to close AlertSystem modals as well
    const globalEvent = new CustomEvent('closeAllAlerts', {
      detail: { source: 'AlertNotification' },
      bubbles: true
    });
    document.dispatchEvent(globalEvent);
  }
  
  function closeAlertsByLevel(level) {
    // First, close the Alert Manager panel immediately
    showAlertManager = false;
    
    // Force a complete re-render by triggering a state change
    forceUpdate++;
    
    // Then process the alerts
    notifications.update(current => {
      const filtered = current.filter(n => n.level !== level);
      const removed = current.filter(n => n.level === level);
      
      // Remove from recent map
      removed.forEach(n => recentAlertMap.delete(n.key));
      
      return filtered;
    });
    
    // Update unacknowledged count after store update
    setTimeout(() => {
      totalUnacknowledged = $notifications.length;
    }, 0);
    
    // If closing critical alerts, also close AlertSystem modals
    if (level === 'critical') {
      const globalEvent = new CustomEvent('closeAllAlerts', {
        detail: { source: 'AlertNotification', level: 'critical' },
        bubbles: true
      });
      document.dispatchEvent(globalEvent);
    }
  }
  
  function closeOldAlerts(hours) {
    // First, close the Alert Manager panel immediately
    showAlertManager = false;
    
    // Force a complete re-render by triggering a state change
    forceUpdate++;
    
    const cutoffTime = new Date(Date.now() - (hours * 60 * 60 * 1000));
    
    notifications.update(current => {
      const filtered = current.filter(n => n.timestamp > cutoffTime);
      const removed = current.filter(n => n.timestamp <= cutoffTime);
      
      // Remove from recent map
      removed.forEach(n => recentAlertMap.delete(n.key));
      
      return filtered;
    });
    
    // Update unacknowledged count after store update
    setTimeout(() => {
      totalUnacknowledged = $notifications.length;
    }, 0);
    
    // Dispatch global event for old alerts
    const globalEvent = new CustomEvent('closeAllAlerts', {
      detail: { source: 'AlertNotification', hours: hours },
      bubbles: true
    });
    document.dispatchEvent(globalEvent);
  }

  function removeNotification(id) {
    notifications.update(current => {
      const removed = current.find(n => n.id === id);
      if (removed) {
        recentAlertMap.delete(removed.key);
      }
      return current.filter(notification => notification.id !== id);
    });
    
    // Update unacknowledged count after store update
    setTimeout(() => {
      totalUnacknowledged = $notifications.length;
    }, 0);
  }

  function getLevelColor(level) {
    const colors = {
      'critical': 'notification-critical',
      'high': 'notification-high',
      'medium': 'notification-medium',
      'low': 'notification-low',
      'info': 'notification-info'
    };
    return colors[level] || 'notification-info';
  }

  function getLevelIcon(level) {
    const icons = {
      'critical': '🚨',
      'high': '⚠️',
      'medium': '⚠️',
      'low': 'ℹ️',
      'info': 'ℹ️'
    };
    return icons[level] || 'ℹ️';
  }

  function formatTime(timestamp) {
    return timestamp.toLocaleTimeString();
  }
  
  function toggleAlertManager() {
    showAlertManager = !showAlertManager;
  }
  
  // Reactive statement to keep totalUnacknowledged in sync
  $: {
    if ($notifications) {
      totalUnacknowledged = $notifications.length;
    }
  }
  
  // Computed properties to check if alerts of each level exist
  $: hasCriticalAlerts = $notifications && $notifications.some(n => n.level === 'critical');
  $: hasHighAlerts = $notifications && $notifications.some(n => n.level === 'high');
  $: hasMediumAlerts = $notifications && $notifications.some(n => n.level === 'medium');
  $: hasLowAlerts = $notifications && $notifications.some(n => n.level === 'low');
</script>

{#if hasPermission('view_alerts')}
  <div class="notification-container">
    <!-- Alert Manager Toggle -->
    {#if totalUnacknowledged > 0}
      <div class="alert-manager-toggle">
        <button class="manager-toggle-btn" on:click={toggleAlertManager}>
          🚨 Alert Manager ({totalUnacknowledged})
        </button>
      </div>
    {/if}
    
    <!-- Alert Manager Panel -->
    {#if showAlertManager}
      <div class="alert-manager-panel">
        <div class="manager-header">
          <h3>🚨 Alert Management</h3>
          <button class="close-manager" on:click={toggleAlertManager}>✕</button>
        </div>
        
        <div class="manager-stats">
          <span>Total: {totalUnacknowledged}</span>
          <span>Critical: {$notifications.filter(n => n.level === 'critical').length}</span>
          <span>High: {$notifications.filter(n => n.level === 'high').length}</span>
        </div>
        
        <div class="manager-actions">
          <button class="action-btn critical" 
                  on:click={() => closeAlertsByLevel('critical')}
                  disabled={!hasCriticalAlerts}>
            🚨 Close Critical
          </button>
          <button class="action-btn high" 
                  on:click={() => closeAlertsByLevel('high')}
                  disabled={!hasHighAlerts}>
            ⚠️ Close High
          </button>
          <button class="action-btn medium" 
                  on:click={() => closeAlertsByLevel('medium')}
                  disabled={!hasMediumAlerts}>
            ⚠️ Close Medium
          </button>
          <button class="action-btn low" 
                  on:click={() => closeAlertsByLevel('low')}
                  disabled={!hasLowAlerts}>
            ℹ️ Close Low
          </button>
          <button class="action-btn danger" 
                  on:click={closeAllAlerts}
                  disabled={totalUnacknowledged === 0}>
            🗑️ Close All Alerts
          </button>
        </div>
      </div>
    {/if}
    
    <!-- Individual Notifications -->
    {#each $notifications as notification (notification.id)}
      <div class="notification {getLevelColor(notification.level)}" 
           class:critical={notification.level === 'critical'}>
        <div class="notification-header">
          <div class="notification-icon">
            {getLevelIcon(notification.level)}
          </div>
          <div class="notification-title">
            {notification.title}
          </div>
          <div class="notification-time">
            {formatTime(notification.timestamp)}
          </div>
          <button class="notification-close" on:click={() => removeNotification(notification.id)}>
            ✕
          </button>
        </div>
        
        <div class="notification-body">
          <p class="notification-message">
            {notification.message}
          </p>
          {#if notification.source_ip || notification.target_port}
            <div class="notification-details">
              {#if notification.source_ip}
                <span class="detail-item">IP: {notification.source_ip}</span>
              {/if}
              {#if notification.target_port}
                <span class="detail-item">Port: {notification.target_port}</span>
              {/if}
            </div>
          {/if}
        </div>
        
        {#if notification.level === 'critical'}
          <div class="notification-actions">
            <button class="notification-action primary" on:click={() => removeNotification(notification.id)}>
              Acknowledge
            </button>
            <button class="notification-action secondary" on:click={() => window.location.href = '/alerts'}>
              View Details
            </button>
          </div>
        {/if}
      </div>
    {/each}
  </div>
{/if}

<style>
  .notification-container {
    position: fixed;
    top: 1rem;
    right: 1rem;
    z-index: 9999;
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
    max-width: 400px;
    width: 100%;
  }
  
  .alert-manager-toggle {
    margin-bottom: 0.5rem;
  }
  
  .manager-toggle-btn {
    background: #ef4444;
    color: white;
    border: none;
    padding: 0.75rem 1rem;
    border-radius: 8px;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.2s ease;
    width: 100%;
  }
  
  .manager-toggle-btn:hover {
    background: #dc2626;
    transform: translateY(-1px);
  }
  
  .alert-manager-panel {
    background: white;
    border-radius: 12px;
    box-shadow: 0 10px 25px rgba(0, 0, 0, 0.15);
    border: 1px solid #e5e7eb;
    padding: 1rem;
    margin-bottom: 1rem;
  }
  
  .manager-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1rem;
    padding-bottom: 0.5rem;
    border-bottom: 1px solid #e5e7eb;
  }
  
  .manager-header h3 {
    margin: 0;
    color: #1f2937;
    font-size: 1rem;
  }
  
  .close-manager {
    background: none;
    border: none;
    color: #6b7280;
    cursor: pointer;
    padding: 0.25rem;
    border-radius: 4px;
    font-size: 1.2rem;
  }
  
  .close-manager:hover {
    background: #f3f4f6;
    color: #374151;
  }
  
  .manager-stats {
    display: flex;
    gap: 1rem;
    margin-bottom: 1rem;
    font-size: 0.875rem;
    color: #6b7280;
  }
  
  .manager-actions {
    display: flex;
    gap: 0.5rem;
    margin-bottom: 1rem;
    flex-wrap: wrap;
  }
  
  .action-btn {
    border: none;
    padding: 0.5rem 0.75rem;
    border-radius: 6px;
    font-size: 0.75rem;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.2s ease;
    flex: 1;
    min-width: 80px;
  }
  
  .action-btn.critical {
    background: #ef4444;
    color: white;
  }
  
  .action-btn.high {
    background: #f59e0b;
    color: white;
  }
  
  .action-btn.medium {
    background: #f59e0b;
    color: white;
  }
  
  .action-btn.low {
    background: #10b981;
    color: white;
  }
  
  .action-btn.time {
    background: #3b82f6;
    color: white;
  }
  
  .action-btn.danger {
    background: #dc2626;
    color: white;
  }
  
  .action-btn:hover {
    transform: translateY(-1px);
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
  }
  
  .action-btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
    transform: none;
    box-shadow: none;
  }
  
  .action-btn:disabled:hover {
    transform: none;
    box-shadow: none;
  }

  .notification {
    background: white;
    border-radius: 12px;
    box-shadow: 0 10px 25px rgba(0, 0, 0, 0.15);
    border: 1px solid #e5e7eb;
    overflow: hidden;
    animation: slideIn 0.3s ease;
    border-left: 4px solid #6b7280;
  }

  .notification.critical {
    animation: shake 0.5s ease-in-out, slideIn 0.3s ease;
  }

  .notification-critical { border-left-color: #ef4444; background: linear-gradient(135deg, #fef2f2 0%, #fee2e2 100%); }
  .notification-high { border-left-color: #f59e0b; background: linear-gradient(135deg, #fffbeb 0%, #fef3c7 100%); }
  .notification-medium { border-left-color: #f59e0b; background: linear-gradient(135deg, #fefce8 0%, #fef3c7 100%); }
  .notification-low { border-left-color: #10b981; background: linear-gradient(135deg, #f0fdf4 0%, #dcfce7 100%); }
  .notification-info { border-left-color: #3b82f6; background: linear-gradient(135deg, #eff6ff 0%, #dbeafe 100%); }

  .notification-header {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    padding: 1rem 1rem 0.5rem 1rem;
  }

  .notification-icon {
    font-size: 1.25rem;
    flex-shrink: 0;
  }

  .notification-title {
    flex: 1;
    font-weight: 600;
    color: #1f2937;
    font-size: 0.875rem;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .notification-time {
    font-size: 0.75rem;
    color: #6b7280;
    flex-shrink: 0;
  }

  .notification-close {
    background: none;
    border: none;
    color: #6b7280;
    cursor: pointer;
    padding: 0.25rem;
    border-radius: 4px;
    transition: all 0.2s ease;
    flex-shrink: 0;
  }

  .notification-close:hover {
    background-color: #f3f4f6;
    color: #374151;
  }

  .notification-body {
    padding: 0 1rem 1rem 1rem;
  }

  .notification-message {
    margin: 0 0 0.5rem 0;
    color: #374151;
    font-size: 0.875rem;
    line-height: 1.4;
    word-wrap: break-word;
  }
  
  .notification-details {
    display: flex;
    gap: 1rem;
    font-size: 0.75rem;
    color: #6b7280;
  }
  
  .detail-item {
    background: #f3f4f6;
    padding: 0.25rem 0.5rem;
    border-radius: 4px;
  }

  .notification-actions {
    padding: 0.75rem 1rem 1rem 1rem;
    display: flex;
    gap: 0.5rem;
    border-top: 1px solid rgba(0, 0, 0, 0.1);
  }

  .notification-action {
    border: none;
    padding: 0.5rem 1rem;
    border-radius: 6px;
    font-size: 0.75rem;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.2s ease;
    flex: 1;
  }

  .notification-action.primary {
    background: #ef4444;
    color: white;
  }

  .notification-action.primary:hover {
    background: #dc2626;
  }

  .notification-action.secondary {
    background: #f3f4f6;
    color: #374151;
  }

  .notification-action.secondary:hover {
    background: #e5e7eb;
  }

  @keyframes slideIn {
    from {
      opacity: 0;
      transform: translateX(100%);
    }
    to {
      opacity: 1;
      transform: translateX(0);
    }
  }

  @keyframes shake {
    0%, 100% { transform: translateX(0); }
    10%, 30%, 50%, 70%, 90% { transform: translateX(-2px); }
    20%, 40%, 60%, 80% { transform: translateX(2px); }
  }

  /* Responsive Design */
  @media (max-width: 768px) {
    .notification-container {
      top: 0.5rem;
      right: 0.5rem;
      left: 0.5rem;
      max-width: none;
    }

    .notification {
      margin: 0;
    }

    .notification-header {
      padding: 0.75rem 0.75rem 0.25rem 0.75rem;
    }

    .notification-body {
      padding: 0 0.75rem 0.75rem 0.75rem;
    }

    .notification-actions {
      padding: 0.5rem 0.75rem 0.75rem 0.75rem;
    }

    .notification-title {
      font-size: 0.8rem;
    }

    .notification-message {
      font-size: 0.8rem;
    }
    
    .manager-actions {
      flex-direction: column;
    }
    
    .action-btn {
      min-width: auto;
    }
  }

  @media (max-width: 480px) {
    .notification-container {
      top: 0.25rem;
      right: 0.25rem;
      left: 0.25rem;
    }

    .notification-actions {
      flex-direction: column;
    }

    .notification-action {
      text-align: center;
    }
  }

  /* Reduce motion for accessibility */
  @media (prefers-reduced-motion: reduce) {
    .notification {
      animation: none;
    }
  }
</style> 