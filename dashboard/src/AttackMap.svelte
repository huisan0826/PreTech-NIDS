<script>
  import { onMount, onDestroy } from 'svelte';
  import { writable } from 'svelte/store';
  import axios from 'axios';

  // State management
  let attacks = writable([]);
  let statistics = writable({});
  let loading = writable(true);
  let error = writable(null);
  let mapContainer;
  let map = null;
  let attackMarkers = [];
  let heatmapLayer = null;
  
  // Configuration
  let timeWindow = 60; // minutes
  let refreshInterval = 30000; // 30 seconds
  let refreshTimer = null;
  let mapInitialized = false;

  // Enhanced colors for different attack types
  const attackTypeColors = {
    'SSH Brute Force': '#dc2626',      // Red
    'Tomcat': '#f59e0b',               // Orange
    'Reverse Shell': '#8b5cf6',        // Purple
    'Backdoor': '#ef4444',             // Bright Red
    'RDP Brute Force': '#f97316',      // Orange Red
    'Database Attack': '#ec4899',      // Pink
    'Mail Server Attack': '#06b6d4',   // Cyan
    'DNS Attack': '#84cc16',           // Lime
    'SMB Attack': '#f59e0b',           // Orange
    'Web Attack': '#3b82f6',           // Blue
    'Malware C2': '#dc2626',           // Red
    'Phishing Attack': '#8b5cf6',      // Purple
    'Ransomware': '#ef4444',           // Bright Red
    'Crypto Mining': '#fbbf24',        // Yellow
    'IoT Attack': '#10b981',           // Green
    'ICS Attack': '#f59e0b',           // Orange
    'Port Scan': '#6b7280',            // Gray
    'SYN Flood': '#dc2626',            // Red
    'Local Network': '#6b7280',        // Gray
    'Unknown': '#6b7280'               // Gray
  };

  // Threat level colors
  const threatLevelColors = {
    critical: '#dc2626',      // Red
    high: '#f59e0b',          // Orange  
    medium: '#10b981',        // Green
    low: '#3b82f6',           // Blue
    info: '#6b7280'           // Gray
  };

  onMount(async () => {
    await loadMapLibraries();
    await initializeMap();
    await loadAttackData();
    
    startAutoRefresh();
  });

  onDestroy(() => {
    if (refreshTimer) {
      clearInterval(refreshTimer);
    }
    if (map) {
      map.remove();
    }
  });

  async function loadMapLibraries() {
    // Load Leaflet CSS and JS dynamically
    if (!document.querySelector('link[href*="leaflet"]')) {
      const link = document.createElement('link');
      link.rel = 'stylesheet';
      link.href = 'https://unpkg.com/leaflet@1.9.4/dist/leaflet.css';
      document.head.appendChild(link);
    }

    // @ts-ignore - Leaflet attaches L to window at runtime
    if (!window.L) {
      return new Promise((resolve, reject) => {
        const script = document.createElement('script');
        script.src = 'https://unpkg.com/leaflet@1.9.4/dist/leaflet.js';
        script.onload = resolve;
        script.onerror = reject;
        document.head.appendChild(script);
      });
    }
  }

  async function initializeMap() {
    // @ts-ignore
    if (!window.L || !mapContainer || mapInitialized) return;

    try {
      // Initialize map centered on world view
      // @ts-ignore
      map = window.L.map(mapContainer, {
        center: [20, 0],
        zoom: 2,
        minZoom: 2,
        maxZoom: 18,
        worldCopyJump: true
      });

      // Add tile layer
      // @ts-ignore
      window.L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        attribution: '© OpenStreetMap contributors',
        maxZoom: 18
      }).addTo(map);

      // Add custom controls
      addCustomControls();
      
      // Ensure map resizes with container
      const resizeObserver = new ResizeObserver(() => {
        try {
          // @ts-ignore
          map?.invalidateSize(false);
        } catch {}
      });
      if (mapContainer) {
        resizeObserver.observe(mapContainer);
      }

      mapInitialized = true;
      console.log('Map initialized successfully');
    } catch (e) {
      console.error('Error initializing map:', e);
      error.set('Failed to initialize map');
    }
  }

  function addCustomControls() {
    // Legend moved to external side panel to avoid covering the map
  }

  async function loadAttackData() {
    try {
      loading.set(true);
      error.set(null);

      // Ensure numeric minutes
      const minutes = Number(timeWindow) || 60;

      // Load recent attacks
      const attacksResponse = await axios.get(`http://localhost:8000/api/geomap/recent-attacks?minutes=${minutes}`);
      const attacksData = attacksResponse.data;

      // Load statistics
      const statsResponse = await axios.get(`http://localhost:8000/api/geomap/statistics?minutes=${minutes}`);
      const statsData = statsResponse.data;

      if (attacksData.success) {
        attacks.set(attacksData.attacks);
        updateMapMarkers(attacksData.attacks);
      }

      if (statsData.success) {
        statistics.set(statsData.statistics);
        updateStatsPanel(statsData.statistics, minutes);
      }

    } catch (e) {
      console.error('Error loading attack data:', e);
      error.set('Failed to load attack data');
    } finally {
      loading.set(false);
    }
  }

  function updateMapMarkers(attackData) {
    if (!map) return;

    // Clear existing markers
    attackMarkers.forEach(marker => map.removeLayer(marker));
    attackMarkers = [];

    // Group attacks by location for clustering
    const locationGroups = groupAttacksByLocation(attackData);
    const attackLines = [];

    // Create attack flow lines first
    attackData.forEach(attack => {
      if (attack.country !== 'Local Network' && attack.latitude !== 0 && attack.longitude !== 0) {
        // Create lines to nearby locations or random destinations for demo
        const targetLat = attack.latitude + (Math.random() - 0.5) * 15;
        const targetLng = attack.longitude + (Math.random() - 0.5) * 15;
        
        const attackType = attack.attack_details?.attack_type || 'Unknown';
        const color = attackTypeColors[attackType] || attackTypeColors['Unknown'];
        
        // @ts-ignore
        const polyline = window.L.polyline([attack.latitude, attack.longitude], [targetLat, targetLng], {
          color: color,
          weight: 2,
          opacity: 0.7,
          dashArray: '8, 8'
        }).bindPopup(`
          <div style="min-width: 150px;">
            <h4 style="margin: 0 0 5px 0; color: #1f2937;">${attackType}</h4>
            <p style="margin: 0 0 5px 0; color: #6b7280;">From: ${attack.country}</p>
            <p style="margin: 0 0 5px 0; color: #6b7280;">Time: ${new Date(attack.timestamp).toLocaleTimeString()}</p>
          </div>
        `);
        
        attackMarkers.push(polyline);
        polyline.addTo(map);
      }
    });

    // Add markers for each location group
    Object.entries(locationGroups).forEach(([locationKey, attacks]) => {
      const [lat, lng] = locationKey.split(',').map(Number);
      
      if (lat === 0 && lng === 0) return; // Skip invalid coordinates

      const attackCount = attacks.length;
      
      // Get the most common attack type for this location
      const attackTypes = attacks.map(a => a.attack_details?.attack_type || 'Unknown');
      const mostCommonType = attackTypes.reduce((a, b, i, arr) => 
        arr.filter(v => v === a).length >= arr.filter(v => v === b).length ? a : b
      );
      
      // Use attack type color instead of threat level color
      const color = attackTypeColors[mostCommonType] || attackTypeColors['Unknown'];
      
      // Check if this location has recent attacks (last 5 minutes)
      const isRecent = attacks.some(attack => 
        new Date(attack.timestamp) > new Date(Date.now() - 5 * 60 * 1000)
      );
      
      // Create pulsing effect for recent attacks
      const pulseClass = isRecent ? 'pulse-animation' : '';
      
      // Create custom marker with attack type indicator
      // @ts-ignore
      const marker = window.L.circleMarker([lat, lng], {
        radius: Math.min(8 + attackCount * 2, 30),
        fillColor: color,
        color: '#ffffff',
        weight: 3,
        opacity: 0.9,
        fillOpacity: 0.7,
        className: pulseClass
      });

      // Create enhanced popup content
      const popupContent = createEnhancedPopupContent(attacks, attackCount, mostCommonType, color);
      marker.bindPopup(popupContent);

      // Add hover effects
      marker.on('mouseover', function() {
        this.setStyle({
          fillOpacity: 0.9,
          weight: 4,
          radius: Math.min(10 + attackCount * 2, 35)
        });
      });

      marker.on('mouseout', function() {
        this.setStyle({
          fillOpacity: 0.7,
          weight: 3,
          radius: Math.min(8 + attackCount * 2, 30)
        });
      });

      marker.addTo(map);
      attackMarkers.push(marker);
    });
  }

  function groupAttacksByLocation(attacks) {
    const groups = {};
    
    attacks.forEach(attack => {
      const lat = attack.latitude || 0;
      const lng = attack.longitude || 0;
      const key = `${lat},${lng}`;
      
      if (!groups[key]) {
        groups[key] = [];
      }
      groups[key].push(attack);
    });

    return groups;
  }

  function getThreatLevel(attackCount) {
    if (attackCount >= 10) return 'high';
    if (attackCount >= 3) return 'medium';
    if (attackCount >= 1) return 'low';
    return 'unknown';
  }

  function createPopupContent(attacks, attackCount) {
    const firstAttack = attacks[0];
    const country = firstAttack.country || 'Unknown';
    const city = firstAttack.location?.city || 'Unknown';
    
    // Get unique models used
    const models = [...new Set(attacks.map(a => a.attack_details?.model).filter(Boolean))];
    
    // Get latest attack time
    const latestAttack = new Date(Math.max(...attacks.map(a => new Date(a.timestamp))));
    
    return `
      <div class="attack-popup">
        <h3>${country} ${city !== 'Unknown' ? `- ${city}` : ''}</h3>
        <div class="popup-stats">
          <div class="stat-item">
            <span class="stat-label">Attacks:</span>
            <span class="stat-value">${attackCount}</span>
          </div>
          <div class="stat-item">
            <span class="stat-label">Latest:</span>
            <span class="stat-value">${latestAttack.toLocaleTimeString()}</span>
          </div>
          <div class="stat-item">
            <span class="stat-label">Models:</span>
            <span class="stat-value">${models.join(', ') || 'Various'}</span>
          </div>
          <div class="stat-item">
            <span class="stat-label">Source IP:</span>
            <span class="stat-value">${firstAttack.source_ip || 'Unknown'}</span>
          </div>
        </div>
      </div>
    `;
  }

  function createEnhancedPopupContent(attacks, attackCount, mostCommonType, color) {
    const firstAttack = attacks[0];
    const country = firstAttack.country || 'Unknown';
    const city = firstAttack.location?.city || 'Unknown';
    
    // Get unique models used
    const models = [...new Set(attacks.map(a => a.attack_details?.model).filter(Boolean))];
    
    // Get latest attack time
    const latestAttack = new Date(Math.max(...attacks.map(a => new Date(a.timestamp))));
    
    // Get attack type distribution
    const typeDistribution = attacks.reduce((acc, attack) => {
      const type = attack.attack_details?.attack_type || 'Unknown';
      acc[type] = (acc[type] || 0) + 1;
      return acc;
    }, {});
    
    return `
      <div style="min-width: 280px; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;">
        <div style="display: flex; align-items: center; margin-bottom: 12px; padding-bottom: 8px; border-bottom: 2px solid #e5e7eb;">
          <div style="width: 16px; height: 16px; background-color: ${color}; border-radius: 50%; margin-right: 8px;"></div>
          <h3 style="margin: 0; color: #1f2937; font-size: 16px; font-weight: 600;">${country} ${city !== 'Unknown' ? `- ${city}` : ''}</h3>
        </div>
        
        <div style="margin-bottom: 12px;">
          <div style="display: flex; justify-content: space-between; margin-bottom: 6px;">
            <span style="color: #6b7280; font-size: 14px;">Total Attacks:</span>
            <span style="color: #1f2937; font-weight: 600; font-size: 14px;">${attackCount}</span>
          </div>
          <div style="display: flex; justify-content: space-between; margin-bottom: 6px;">
            <span style="color: #6b7280; font-size: 14px;">Primary Type:</span>
            <span style="color: ${color}; font-weight: 600; font-size: 14px;">${mostCommonType}</span>
          </div>
          <div style="display: flex; justify-content: space-between; margin-bottom: 6px;">
            <span style="color: #6b7280; font-size: 14px;">Latest:</span>
            <span style="color: #1f2937; font-weight: 500; font-size: 14px;">${latestAttack.toLocaleTimeString()}</span>
          </div>
          <div style="display: flex; justify-content: space-between; margin-bottom: 6px;">
            <span style="color: #6b7280; font-size: 14px;">Models:</span>
            <span style="color: #1f2937; font-weight: 500; font-size: 14px;">${models.join(', ')}</span>
          </div>
        </div>
        
        <div style="margin-bottom: 12px;">
          <h4 style="margin: 0 0 8px 0; color: #374151; font-size: 14px; font-weight: 600;">Attack Types:</h4>
          <div style="max-height: 100px; overflow-y: auto;">
            ${Object.entries(typeDistribution).map(([type, count]) => {
              const typeColor = attackTypeColors[type] || attackTypeColors['Unknown'];
              return `
                <div style="display: flex; justify-content: space-between; align-items: center; padding: 4px 0; border-bottom: 1px solid #f3f4f6;">
                  <div style="display: flex; align-items: center;">
                    <div style="width: 8px; height: 8px; background-color: ${typeColor}; border-radius: 50%; margin-right: 6px;"></div>
                    <span style="color: #374151; font-size: 13px;">${type}</span>
                  </div>
                  <span style="color: #6b7280; font-size: 13px; font-weight: 500;">${count}</span>
                </div>
              `;
            }).join('')}
          </div>
        </div>
      </div>
    `;
  }

  function updateStatsPanel(stats, windowMinutes) {
    const panel = document.getElementById('map-stats-panel');
    if (!panel) return;

    const topCountries = stats.countries?.slice(0, 5) || [];
    const minutes = Number(windowMinutes) || 1440;
    const title = minutes >= 1440 ? '24h' : minutes >= 60 ? `${Math.floor(minutes / 60)}h` : `${minutes}m`;
    
    panel.innerHTML = `
      <div class="stats-content">
        <h3>LIVE CYBER THREAT MAP</h3>
        <div class="total-attacks">
          <span class="big-number">${stats.total_attacks || stats.total_attacks_24h || 0}</span>
          <span class="label">ATTACKS ON THIS DAY</span>
        </div>
        
        <h4>Top Attack Sources</h4>
        <div class="country-list">
          ${topCountries.map(country => `
            <div class="country-item">
              <span class="country-flag">${getCountryFlag(country.country_code)}</span>
              <span class="country-name">${country.country}</span>
              <span class="attack-count">${country.attack_count} attacks</span>
            </div>
          `).join('')}
        </div>

        <h4 style="margin-top:1rem;">Attack Types</h4>
        <div class="legend-item">
          <span class="legend-color" style="background: #dc2626;"></span>
          Malware
        </div>
        <div class="legend-item">
          <span class="legend-color" style="background: #8b5cf6;"></span>
          Phishing
        </div>
        <div class="legend-item">
          <span class="legend-color" style="background: #f59e0b;"></span>
          Exploit
        </div>
        <div class="legend-item">
          <span class="legend-color" style="background: #10b981;"></span>
          IoT Attack
        </div>
        <div class="legend-item">
          <span class="legend-color" style="background: #3b82f6;"></span>
          Web Attack
        </div>
        <div class="legend-item">
          <span class="legend-color" style="background: #6b7280;"></span>
          Local Network
        </div>
        
        <div class="real-time-indicator">
          <div class="pulse-dot"></div>
          <span>LIVE</span>
        </div>
      </div>
    `;
  }

  function getCountryFlag(countryCode) {
    if (!countryCode || countryCode === 'UNKNOWN') return '🌍';
    
    // Convert country code to flag emoji
    const codePoints = countryCode
      .toUpperCase()
      .split('')
      .map(char => 127397 + char.charCodeAt());
    return String.fromCodePoint(...codePoints);
  }

  function startAutoRefresh() {
    refreshTimer = setInterval(() => {
      loadAttackData();
    }, refreshInterval);
  }

  function stopAutoRefresh() {
    if (refreshTimer) {
      clearInterval(refreshTimer);
      refreshTimer = null;
    }
  }

  // Control functions
  function refreshData() {
    loadAttackData();
  }

  function changeTimeWindow(minutes) {
    timeWindow = minutes;
    loadAttackData();
  }

  // Auto refresh is always enabled; manual refresh remains available
</script>

<div class="attack-map-container">
  <div class="map-header">
    <h1 class="map-title">🗺️ Real-time Attack Map</h1>
    <p class="map-description">Global visualization of network attack sources and patterns</p>
    
    <div class="map-controls">
      <div class="control-group">
        <label for="time-window">Time Window:</label>
        <select id="time-window" bind:value={timeWindow} on:change={() => changeTimeWindow(timeWindow)}>
          <option value={15}>Last 15 minutes</option>
          <option value={60}>Last hour</option>
          <option value={360}>Last 6 hours</option>
          <option value={1440}>Last 24 hours</option>
        </select>
      </div>

      <button class="refresh-btn" on:click={refreshData} disabled={$loading}>
        {#if $loading}
          <span class="spinner"></span>
        {:else}
          🔄
        {/if}
        Refresh
      </button>
    </div>
  </div>

  {#if $error}
    <div class="error-message">
      <span class="error-icon">⚠️</span>
      <span>{$error}</span>
      <button class="retry-btn" on:click={refreshData}>Retry</button>
    </div>
  {/if}

  <div class="map-wrapper">
    <div class="map-layout">
      <div class="map-main">
        <div bind:this={mapContainer} class="leaflet-map" id="attack-map"></div>
        {#if $loading}
          <div class="map-loading">
            <div class="loading-spinner"></div>
            <p>Loading attack data...</p>
          </div>
        {/if}
      </div>
      <aside class="map-sidepanel">
        <div id="map-stats-panel" class="stats-panel-external"></div>
      </aside>
    </div>
  </div>
</div>

<style>
  .attack-map-container {
    padding: 1rem 0.75rem;
    max-width: 100%;
    margin: 0;
    min-height: 100vh;
  }

  .map-header {
    margin-bottom: 2rem;
    text-align: center;
  }

  .map-title {
    font-size: 2.5rem;
    font-weight: bold;
    margin: 0 0 0.5rem 0;
    color: #1f2937;
  }

  .map-description {
    font-size: 1.1rem;
    color: #6b7280;
    margin: 0 0 2rem 0;
  }

  .map-controls {
    display: flex;
    justify-content: center;
    align-items: center;
    gap: 2rem;
    flex-wrap: wrap;
    background: white;
    padding: 1rem 2rem;
    border-radius: 12px;
    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
  }

  .control-group {
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }

  .control-group label {
    font-weight: 600;
    color: #374151;
    font-size: 0.875rem;
  }

  .control-group select {
    border: 1px solid #d1d5db;
    padding: 0.5rem;
    border-radius: 6px;
    font-size: 0.875rem;
  }

  /* removed .checkbox-label as auto-refresh toggle was deleted */

  .refresh-btn, .retry-btn {
    background-color: #3b82f6;
    color: white;
    border: none;
    padding: 0.5rem 1rem;
    border-radius: 6px;
    font-size: 0.875rem;
    cursor: pointer;
    transition: background-color 0.2s ease;
    font-weight: 500;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }

  .refresh-btn:hover, .retry-btn:hover {
    background-color: #2563eb;
  }

  .refresh-btn:disabled {
    opacity: 0.6;
    cursor: not-allowed;
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

  .map-wrapper {
    position: relative;
    background: transparent;
    border-radius: 0;
    overflow: visible;
    box-shadow: none;
  }

  .map-layout {
    display: grid;
    grid-template-columns: minmax(0, 3fr) minmax(280px, 1.2fr);
    gap: 1rem;
    align-items: start;
  }

  .map-main { position: relative; }

  .map-sidepanel {
    background: transparent;
    border-left: none;
    padding: 0;
  }

  .stats-panel-external { position: sticky; top: 70px; }

  .leaflet-map {
    height: 72vh;
    width: 100%;
    z-index: 1;
  }

  .map-loading {
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: rgba(255, 255, 255, 0.9);
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    z-index: 1000;
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

  .spinner {
    width: 16px;
    height: 16px;
    border: 2px solid #ffffff40;
    border-left: 2px solid #ffffff;
    border-radius: 50%;
    animation: spin 1s linear infinite;
  }

  @keyframes spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
  }

  :global(.legend-item) {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    margin-bottom: 0.5rem;
  }

  :global(.legend-color) {
    width: 16px;
    height: 16px;
    border-radius: 50%;
    border: 2px solid white;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.3);
  }

  :global(.stats-panel) {
    background: rgba(255, 255, 255, 0.95);
    padding: 1rem;
    border-radius: 8px;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.15);
    min-width: 250px;
    max-width: 300px;
  }

  :global(.stats-content h3) {
    margin: 0 0 1rem 0;
    color: #1f2937;
    font-size: 1.125rem;
  }

  :global(.stats-content h4) {
    margin: 1rem 0 0.5rem 0;
    color: #374151;
    font-size: 0.875rem;
  }

  :global(.total-attacks) {
    text-align: center;
    margin-bottom: 1rem;
    padding: 1rem;
    background: #fef2f2;
    border-radius: 6px;
    border: 1px solid #fecaca;
  }

  :global(.big-number) {
    display: block;
    font-size: 2rem;
    font-weight: bold;
    color: #dc2626;
  }

  :global(.label) {
    display: block;
    font-size: 0.75rem;
    color: #6b7280;
    margin-top: 0.25rem;
  }

  :global(.country-list) {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  :global(.country-item) {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0.5rem;
    background: #f9fafb;
    border-radius: 4px;
    border: 1px solid #e5e7eb;
  }

  :global(.country-flag) {
    font-size: 1.25rem;
    margin-right: 0.5rem;
  }

  :global(.country-name) {
    flex: 1;
    font-size: 0.875rem;
    color: #374151;
  }

  :global(.attack-count) {
    background: #dc2626;
    color: white;
    padding: 0.125rem 0.5rem;
    border-radius: 12px;
    font-size: 0.75rem;
    font-weight: 600;
  }

  :global(.attack-popup) {
    min-width: 200px;
  }

  :global(.attack-popup h3) {
    margin: 0 0 0.75rem 0;
    color: #1f2937;
    font-size: 1rem;
  }

  :global(.popup-stats) {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  :global(.stat-item) {
    display: flex;
    justify-content: space-between;
    align-items: center;
  }

  :global(.stat-label) {
    font-weight: 600;
    color: #6b7280;
    font-size: 0.8rem;
  }

  :global(.stat-value) {
    color: #1f2937;
    font-size: 0.8rem;
    font-family: 'Monaco', 'Consolas', 'Courier New', monospace;
  }

  /* Pulse animation for recent attacks */
  @keyframes pulse {
    0% {
      transform: scale(1);
      opacity: 1;
    }
    50% {
      transform: scale(1.1);
      opacity: 0.8;
    }
    100% {
      transform: scale(1);
      opacity: 1;
    }
  }

  .pulse-animation {
    animation: pulse 2s infinite;
  }

  /* Enhanced marker styles */
  .custom-marker {
    background: transparent !important;
    border: none !important;
  }

  /* Attack flow line styles */
  .attack-flow-line {
    stroke-dasharray: 8, 8;
    animation: dash 1s linear infinite;
  }

  @keyframes dash {
    to {
      stroke-dashoffset: -16;
    }
  }

  /* Real-time indicator */
  .real-time-indicator {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-top: 1rem;
    padding: 8px 12px;
    background: linear-gradient(135deg, #dc2626, #ef4444);
    border-radius: 20px;
    color: white;
    font-weight: 600;
    font-size: 14px;
    box-shadow: 0 2px 4px rgba(220, 38, 38, 0.3);
  }

  .pulse-dot {
    width: 8px;
    height: 8px;
    background-color: white;
    border-radius: 50%;
    animation: pulse 1.5s infinite;
  }

  /* Responsive Design */
  @media (max-width: 768px) {
    .attack-map-container {
      padding: 0.75rem;
    }

    .map-title {
      font-size: 2rem;
    }

    .map-controls {
      flex-direction: column;
      gap: 1rem;
    }

    .map-layout { grid-template-columns: 1fr; }
    .map-sidepanel { display: none; }
    .leaflet-map { height: 65vh; }

    :global(.stats-panel) {
      min-width: 200px;
      max-width: 250px;
      padding: 0.75rem;
    }
  }

  @media (max-width: 480px) {
    .attack-map-container {
      padding: 0.75rem;
    }

    .map-title {
      font-size: 1.75rem;
    }

    .leaflet-map {
      height: 350px;
    }

    :global(.stats-panel) {
      min-width: 180px;
      max-width: 220px;
      padding: 0.5rem;
    }

    :global(.stats-content h3) {
      font-size: 1rem;
    }

    :global(.big-number) {
      font-size: 1.5rem;
    }
  }
</style> 