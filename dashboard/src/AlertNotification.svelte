<script>
  import { onMount, onDestroy } from 'svelte';
  import { writable } from 'svelte/store';
  import { hasPermission } from './stores/auth.js';

  // Props
  export let maxNotifications = 1;
  export let autoHideDelay = 3000; // 10 seconds

  // State
  // Store for active notifications
  let notifications = writable([]);
  // Map to track recent alert keys and their timestamps for throttling
  let recentAlertMap = new Map();
  // Throttle window in milliseconds
  const throttleWindow = 2000;
  let ws = null;
  let connected = false;

  // Audio
  let audioContext = null;
  let soundEnabled = true;

  onMount(async () => {
    if (!hasPermission('view_alerts')) {
      return;
    }

    await initializeAudio();
    connectWebSocket();
  });

  onDestroy(() => {
    if (ws) {
      ws.close();
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

  function connectWebSocket() {
    try {
      const wsUrl =
        window.location.hostname === "localhost"
          ? "ws://localhost:8000/api/alerts/ws"
          : `wss://${window.location.hostname}/api/alerts/ws`;
      ws = new WebSocket(wsUrl);
      
      ws.onopen = () => {
        connected = true;
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
        connected = false;
        // Attempt to reconnect after 5 seconds
        setTimeout(connectWebSocket, 5000);
      };
      
      ws.onerror = () => {
        connected = false;
      };
      
    } catch (e) {
      console.error('Failed to connect WebSocket:', e);
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
      autoHide: alertData.level !== 'critical'
    };
    // Add to notifications
    notifications.update(current => {
      const updated = [notification, ...current];
      return updated.slice(0, maxNotifications);
    });
    // Track this alert in the recent map
    recentAlertMap.set(alertKey, notification);
    // Play sound
    playNotificationSound();
    // Auto-hide non-critical notifications after throttleWindow
    if (notification.autoHide) {
      setTimeout(() => {
        removeNotification(notification.id);
        recentAlertMap.delete(alertKey);
      }, throttleWindow);
    } else {
      // For critical, remove from map after throttleWindow but keep notification until user closes
      setTimeout(() => {
        recentAlertMap.delete(alertKey);
      }, throttleWindow);
    }
  }

  function removeNotification(id) {
    notifications.update(current => 
      current.filter(notification => notification.id !== id)
    );
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
</script>

{#if hasPermission('view_alerts')}
  <div class="notification-container">
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
    margin: 0;
    color: #374151;
    font-size: 0.875rem;
    line-height: 1.4;
    word-wrap: break-word;
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