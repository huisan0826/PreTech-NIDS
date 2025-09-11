<script>
  import { writable } from 'svelte/store';
  import axios from 'axios';
  import { onMount } from 'svelte';

  let realtimeStatus = writable('stopped');
  let realtimeLoading = writable(false);
  let useAllModels = writable(true);
  let availableInterfaces = writable([]);
  let selectedInterface = writable('eth0');
  let selectedModel = 'kitsune';
  let error = writable(null);
  
  // Current configuration from server
  let currentInterface = null;
  let currentModel = null;
  let currentUseAllModels = null;
  
  // Loading state for initial page load
  let initialLoading = writable(true);

  const models = ['kitsune', 'autoencoder', 'lstm', 'cnn', 'rf'];

  async function loadInterfaces() {
    try {
      const res = await axios.get('http://localhost:8000/interfaces');
      availableInterfaces.set(res.data.interfaces);
      
      // Auto-select the first available interface
      if (res.data.interfaces.length > 0) {
        selectedInterface.set(res.data.interfaces[0].name);
      }
    } catch (e) {
      console.error('Failed to load network interfaces:', e);
    }
  }

  async function startRealtimeDetection() {
    realtimeLoading.set(true);
    error.set(null);
    
    try {
      const res = await axios.post('http://localhost:8000/start-realtime', {
        interface: $selectedInterface,
        model: selectedModel,
        use_all_models: $useAllModels
      });
      
      if (res.data.status === 'running') {
        realtimeStatus.set('running');
      }
    } catch (e) {
      if (e.response?.data?.error) {
        error.set(e.response.data.error);
        if (e.response.data.available_interfaces) {
          availableInterfaces.set(e.response.data.available_interfaces);
        }
      } else {
        error.set('Failed to start real-time detection');
      }
    } finally {
      realtimeLoading.set(false);
    }
  }

  async function stopRealtimeDetection() {
    realtimeLoading.set(true);
    error.set(null);
    
    try {
      const res = await axios.post('http://localhost:8000/stop-realtime');
      
      if (res.data.status === 'stopped') {
        realtimeStatus.set('stopped');
      }
    } catch (e) {
      error.set(e.response?.data?.error || 'Failed to stop real-time detection');
    } finally {
      realtimeLoading.set(false);
    }
  }

  async function checkRealtimeStatus() {
    try {
      const res = await axios.get('http://localhost:8000/realtime-status');
      realtimeStatus.set(res.data.status);
      
      // Update current configuration from server
      currentInterface = res.data.current_interface;
      currentModel = res.data.current_model;
      currentUseAllModels = res.data.current_use_all_models;
      
      // If detection is running, update UI to show current configuration
      if (res.data.status === 'running' && currentInterface) {
        selectedInterface.set(currentInterface);
        useAllModels.set(currentUseAllModels || true);
        if (currentModel) {
          selectedModel = currentModel;
        }
        console.log('🔄 Updated UI with current detection configuration:', {
          interface: currentInterface,
          model: currentModel,
          useAllModels: currentUseAllModels
        });
      }
    } catch (e) {
      console.error('Failed to check status:', e);
    }
  }

    // Check status and load interfaces on page load
  onMount(() => {
    // Set up periodic status check to keep UI in sync
    const statusInterval = setInterval(() => {
      checkRealtimeStatus();
    }, 2000); 
    
    // Load interfaces and check status
    (async () => {
      try {
        // Load interfaces first, then check status
        await loadInterfaces();
        await checkRealtimeStatus();
      } finally {
        // Always set loading to false, even if there's an error
        initialLoading.set(false);
      }
    })();
    
    // Cleanup interval on component destroy
    return () => {
      clearInterval(statusInterval);
    };
  });
</script>

<div class="page-container">
  <div class="page-header">
    <h1 class="page-title">🔄 Real-Time Threat Detection</h1>
    <p class="page-description">Monitor network traffic continuously for potential threats</p>
  </div>

  {#if $initialLoading}
    <div class="loading-container">
      <div class="loading-spinner"></div>
      <p class="loading-text">Loading detection status...</p>
    </div>
  {:else}
    <div class="content-section">
    <!-- Status Overview Card -->
    <div class="status-card">
      <div class="status-header">
        <h2 class="status-title">Detection Status</h2>
        <div class="status-indicator">
          <span class={`status-badge ${$realtimeStatus}`}>
            <span class="status-dot"></span>
            {$realtimeStatus.toUpperCase()}
          </span>
        </div>
      </div>
      <p class="status-description">
        {#if $realtimeStatus === 'running'}
          Real-time detection is actively monitoring network traffic for threats.
        {:else}
          Real-time detection is currently stopped. Configure settings and start monitoring.
        {/if}
      </p>
    </div>

    <!-- Configuration Card -->
    <div class="config-card">
      <h2 class="config-title">Configuration</h2>
      
      <div class="config-section">
        <label class="label">
          Network Interface:
          <select
            bind:value={$selectedInterface}
            class="select"
            disabled={$realtimeStatus === 'running'}
          >
            {#each $availableInterfaces as iface}
              <option value={iface.name}>{iface.display}</option>
            {/each}
          </select>
        </label>
      </div>
      
      <div class="config-section">
        <label class="checkbox-label">
          <input 
            type="checkbox" 
            bind:checked={$useAllModels}
            disabled={$realtimeStatus === 'running'}
          />
          <span class="checkbox-text">Use All Models for Detection</span>
        </label>
        <p class="help-text">
          When enabled, all available models will be used for comprehensive threat analysis.
        </p>
      </div>
      
      {#if !$useAllModels}
        <div class="config-section model-selection">
          <label class="label">
            Select Detection Model:
            <select
              bind:value={selectedModel}
              class="select"
              disabled={$realtimeStatus === 'running'}
            >
              {#each models as model}
                <option value={model}>{model.toUpperCase()}</option>
              {/each}
            </select>
          </label>
          <p class="help-text">
            Choose a specific model for detection. Each model has different strengths.
          </p>
        </div>
      {/if}
    </div>

    <!-- Control Card -->
    <div class="control-card">
      <h2 class="control-title">Detection Control</h2>
      
      <div class="control-buttons">
        <button 
          class="button start-button" 
          on:click={startRealtimeDetection}
          disabled={$realtimeLoading || $realtimeStatus === 'running'}
        >
          <span class="button-icon">▶️</span>
          {$realtimeLoading && $realtimeStatus === 'stopped' ? 'Starting...' : 'Start Detection'}
        </button>
        
        <button 
          class="button stop-button" 
          on:click={stopRealtimeDetection}
          disabled={$realtimeLoading || $realtimeStatus === 'stopped'}
        >
          <span class="button-icon">⏹️</span>
          {$realtimeLoading && $realtimeStatus === 'running' ? 'Stopping...' : 'Stop Detection'}
        </button>
      </div>
    </div>

    <!-- Information Card -->
    <div class="info-card">
      <h2 class="info-title">Important Information</h2>
      <div class="info-content">
        <div class="info-item">
          <span class="info-icon">💡</span>
          <div class="info-text">
            <strong>Continuous Monitoring:</strong> Real-time detection runs independently in the background and will continue even when navigating to other pages.
          </div>
        </div>
        
        <div class="info-item">
          <span class="info-icon">🔍</span>
          <div class="info-text">
            <strong>Detection Mode:</strong> 
            {#if $realtimeStatus === 'running' && currentUseAllModels !== null}
              {#if currentUseAllModels}
                Using all models for comprehensive threat analysis.
              {:else}
                Using {(currentModel && currentModel.toUpperCase()) || 'UNKNOWN'} model only.
              {/if}
            {:else if $useAllModels}
              Using all models for comprehensive threat analysis.
            {:else}
              Using {selectedModel.toUpperCase()} model only.
            {/if}
          </div>
        </div>
        
        <div class="info-item">
          <span class="info-icon">🌐</span>
          <div class="info-text">
            <strong>Network Interface:</strong> 
            {#if $realtimeStatus === 'running' && currentInterface}
              {@const currentIface = $availableInterfaces.find(i => i.name === currentInterface)}
              {(currentIface && currentIface.display) || currentInterface} (Currently Monitoring)
            {:else}
              {@const selectedIface = $availableInterfaces.find(i => i.name === $selectedInterface)}
              {(selectedIface && selectedIface.display) || $selectedInterface}
            {/if}
            <br>
            <small class="interface-help">
              💡 <strong>Interface Types:</strong> Physical adapters show as "Ethernet/Wireless Interface", 
              virtual adapters (VMware, Docker, VPN) show as "Virtual Interface", 
              and system interfaces may show as "Unknown Interface" but are still functional.
            </small>
          </div>
        </div>
        
        <div class="info-item">
          <span class="info-icon">⚠️</span>
          <div class="info-text">
            <strong>Administrator Access:</strong> Requires administrator privileges for packet capture functionality.
          </div>
        </div>
        
        <div class="info-item">
          <span class="info-icon">📊</span>
          <div class="info-text">
            <strong>Threat Reports:</strong> Detected threats are automatically saved and can be viewed in the Reports section.
          </div>
        </div>
      </div>
    </div>

    {#if $error}
      <div class="error-card">
        <h3 class="error-title">⚠️ Detection Error</h3>
        <p class="error-message">{$error}</p>
      </div>
    {/if}
    </div>
  {/if}
</div>

<style>
  .page-container {
    padding: 2rem;
    max-width: 100%;
    margin: 0;
    min-height: 100vh;
    width: 100%;
    display: grid;
    grid-template-columns: minmax(0, 1fr);
  }

  .page-header {
    margin-bottom: 2rem;
    text-align: center;
  }

  .page-title {
    font-size: 2.5rem;
    font-weight: bold;
    margin: 0 0 0.5rem 0;
    color: #1f2937;
  }

  .page-description {
    font-size: 1.1rem;
    color: #6b7280;
    margin: 0;
  }

  .loading-container {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 4rem 2rem;
    text-align: center;
  }

  .loading-spinner {
    width: 40px;
    height: 40px;
    border: 4px solid #e5e7eb;
    border-top: 4px solid #3b82f6;
    border-radius: 50%;
    animation: spin 1s linear infinite;
    margin-bottom: 1rem;
  }

  .loading-text {
    color: #6b7280;
    font-size: 1rem;
    margin: 0;
  }

  @keyframes spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
  }

  .content-section {
    display: flex;
    flex-direction: column;
    gap: 1.5rem;
  }

  /* Card Styles */
  .status-card, .config-card, .control-card, .info-card {
    background: white;
    border-radius: 12px;
    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
    border: 1px solid #e5e7eb;
    padding: 2rem;
  }

  .status-card {
    border-left: 4px solid #3b82f6;
  }

  .status-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1rem;
  }

  .status-title, .config-title, .control-title, .info-title {
    font-size: 1.5rem;
    font-weight: bold;
    margin: 0;
    color: #1f2937;
  }

  .status-indicator {
    display: flex;
    align-items: center;
  }

  .status-badge {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.5rem 1rem;
    border-radius: 20px;
    font-size: 0.875rem;
    font-weight: 600;
  }

  .status-badge.running {
    background-color: #dcfce7;
    color: #166534;
  }

  .status-badge.stopped {
    background-color: #fee2e2;
    color: #991b1b;
  }

  .status-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background-color: currentColor;
    animation: pulse 2s infinite;
  }

  .status-description {
    color: #6b7280;
    margin: 0;
    font-size: 1rem;
  }

  .config-section {
    margin-bottom: 1.5rem;
  }

  .label {
    display: block;
    margin-bottom: 0.5rem;
    font-weight: 600;
    color: #374151;
    font-size: 1rem;
  }

  .select {
    width: 100%;
    border: 2px solid #d1d5db;
    padding: 0.75rem;
    margin-top: 0.5rem;
    border-radius: 8px;
    background-color: white;
    color: #1f2937;
    font-size: 1rem;
    transition: border-color 0.2s ease;
  }

  .select:focus {
    outline: none;
    border-color: #3b82f6;
    box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
  }

  .select:disabled {
    background-color: #f9fafb;
    opacity: 0.6;
  }

  .checkbox-label {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    cursor: pointer;
    user-select: none;
  }

  .checkbox-label input[type="checkbox"] {
    width: 1.25rem;
    height: 1.25rem;
    margin: 0;
    accent-color: #3b82f6;
  }

  .checkbox-text {
    font-weight: 600;
    color: #374151;
    font-size: 1rem;
  }

  .help-text {
    font-size: 0.875rem;
    color: #6b7280;
    margin: 0.5rem 0 0 0;
    line-height: 1.4;
  }

  .model-selection {
    background-color: #f8fafc;
    padding: 1.5rem;
    border-radius: 8px;
    border: 1px solid #e2e8f0;
  }

  .control-buttons {
    display: flex;
    gap: 1rem;
  }

  .button {
    flex: 1;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.5rem;
    padding: 1rem 2rem;
    border-radius: 8px;
    font-weight: 600;
    cursor: pointer;
    font-size: 1rem;
    transition: all 0.2s ease;
    border: none;
  }

  .start-button {
    background-color: #10b981;
    color: white;
  }

  .start-button:hover:not(:disabled) {
    background-color: #059669;
    transform: translateY(-1px);
    box-shadow: 0 4px 12px rgba(16, 185, 129, 0.3);
  }

  .stop-button {
    background-color: #ef4444;
    color: white;
  }

  .stop-button:hover:not(:disabled) {
    background-color: #dc2626;
    transform: translateY(-1px);
    box-shadow: 0 4px 12px rgba(239, 68, 68, 0.3);
  }

  .button:disabled {
    opacity: 0.6;
    cursor: not-allowed;
    transform: none;
    box-shadow: none;
  }

  .button-icon {
    font-size: 1.1rem;
  }

  .info-content {
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }

  .info-item {
    display: flex;
    align-items: flex-start;
    gap: 0.75rem;
  }

  .info-icon {
    font-size: 1.25rem;
    margin-top: 0.125rem;
  }

  .info-text {
    flex: 1;
    color: #374151;
    line-height: 1.5;
  }

  .info-text strong {
    color: #1f2937;
  }

  .interface-help {
    color: #6b7280;
    font-size: 0.875rem;
    line-height: 1.4;
    margin-top: 0.5rem;
    display: block;
  }

  .error-card {
    background: white;
    border-radius: 12px;
    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
    border: 1px solid #fecaca;
    border-left: 4px solid #ef4444;
    padding: 2rem;
  }

  .error-title {
    font-size: 1.25rem;
    font-weight: bold;
    margin: 0 0 1rem 0;
    color: #991b1b;
  }

  .error-message {
    color: #dc2626;
    margin: 0;
    font-size: 1rem;
  }

  @keyframes pulse {
    0%, 100% {
      opacity: 1;
    }
    50% {
      opacity: 0.5;
    }
  }

  /* Responsive design */
  @media (max-width: 768px) {
    .page-container {
      padding: 1rem;
    }

    .page-title {
      font-size: 2rem;
    }

    .status-card, .config-card, .control-card, .info-card {
      padding: 1.5rem;
    }

    .control-buttons {
      flex-direction: column;
    }

    .status-header {
      flex-direction: column;
      gap: 1rem;
      align-items: flex-start;
    }
  }

  /* Large Desktop (1200px and up) */
  @media (min-width: 1200px) {
    .page-container {
      max-width: 100%;
      padding: 3rem;
    }

    .page-title {
      font-size: 3rem;
    }

    .page-description {
      font-size: 1.25rem;
    }

    .status-card, .config-card, .control-card, .info-card {
      padding: 3rem;
    }

    .status-title, .config-title, .control-title, .info-title {
      font-size: 1.75rem;
    }

    .button {
      font-size: 1.125rem;
      padding: 1.25rem 2.5rem;
    }

    .select, .label {
      font-size: 1.125rem;
    }

    .help-text {
      font-size: 1rem;
    }

    .info-text {
      font-size: 1.125rem;
    }

    .content-section {
      gap: 2.5rem;
    }

    .config-section {
      margin-bottom: 2rem;
    }

    .model-selection {
      padding: 2rem;
    }
  }

  /* Medium Desktop (992px to 1199px) */
  @media (min-width: 992px) and (max-width: 1199px) {
    .page-container {
      padding: 2.5rem;
    }

    .page-title {
      font-size: 2.75rem;
    }

    .status-card, .config-card, .control-card, .info-card {
      padding: 2.5rem;
    }

    .content-section {
      gap: 2rem;
    }
  }

  /* Tablet Landscape (768px to 991px) */
  @media (min-width: 768px) and (max-width: 991px) {
    .page-container {
      padding: 1.5rem;
    }

    .page-title {
      font-size: 2.25rem;
    }

    .page-description {
      font-size: 1rem;
    }

    .status-card, .config-card, .control-card, .info-card {
      padding: 2rem;
    }

    .status-title, .config-title, .control-title, .info-title {
      font-size: 1.375rem;
    }

    .status-header {
      flex-direction: column;
      gap: 1rem;
      align-items: flex-start;
    }

    .control-buttons {
      flex-direction: column;
      gap: 0.75rem;
    }

    .button {
      font-size: 1rem;
    }

    .info-content {
      gap: 0.875rem;
    }

    .info-item {
      flex-direction: column;
      gap: 0.5rem;
      align-items: flex-start;
    }

    .info-icon {
      align-self: flex-start;
    }
  }

  /* Mobile and Tablet Portrait (below 768px) */
  @media (max-width: 767px) {
    .page-container {
      padding: 1rem;
      min-height: calc(100vh - 60px);
    }

    .page-header {
      margin-bottom: 1.5rem;
    }

    .page-title {
      font-size: 2rem;
    }

    .page-description {
      font-size: 0.95rem;
    }

    .content-section {
      gap: 1.25rem;
    }

    .status-card, .config-card, .control-card, .info-card {
      padding: 1.25rem;
    }

    .status-title, .config-title, .control-title, .info-title {
      font-size: 1.25rem;
    }

    .status-header {
      flex-direction: column;
      gap: 0.75rem;
      align-items: flex-start;
    }

    .status-badge {
      font-size: 0.75rem;
      padding: 0.375rem 0.75rem;
    }

    .control-buttons {
      flex-direction: column;
      gap: 0.75rem;
    }

    .button {
      font-size: 0.95rem;
      padding: 0.875rem 1.5rem;
    }

    .select {
      font-size: 0.95rem;
      padding: 0.625rem;
    }

    .label {
      font-size: 0.95rem;
    }

    .checkbox-text {
      font-size: 0.95rem;
    }

    .help-text {
      font-size: 0.8rem;
    }

    .info-content {
      gap: 0.875rem;
    }

    .info-item {
      flex-direction: row;
      gap: 0.5rem;
      align-items: flex-start;
    }

    .info-icon {
      font-size: 1.125rem;
      margin-top: 0.125rem;
      flex-shrink: 0;
    }

    .info-text {
      font-size: 0.9rem;
      line-height: 1.4;
    }

    .config-section {
      margin-bottom: 1.25rem;
    }

    .model-selection {
      padding: 1.25rem;
    }

    .error-card {
      padding: 1.25rem;
    }

    .error-title {
      font-size: 1.125rem;
    }

    .error-message {
      font-size: 0.9rem;
    }
  }

  /* Small Mobile (below 480px) */
  @media (max-width: 479px) {
    .page-container {
      padding: 0.75rem;
    }

    .page-title {
      font-size: 1.75rem;
    }

    .page-description {
      font-size: 0.875rem;
    }

    .content-section {
      gap: 1rem;
    }

    .status-card, .config-card, .control-card, .info-card {
      padding: 1rem;
    }

    .status-title, .config-title, .control-title, .info-title {
      font-size: 1.125rem;
    }

    .status-description {
      font-size: 0.875rem;
    }

    .button {
      font-size: 0.875rem;
      padding: 0.75rem 1.25rem;
    }

    .button-icon {
      font-size: 1rem;
    }

    .select {
      font-size: 0.875rem;
      padding: 0.5rem;
    }

    .label {
      font-size: 0.875rem;
    }

    .checkbox-text {
      font-size: 0.875rem;
    }

    .checkbox-label input[type="checkbox"] {
      width: 1rem;
      height: 1rem;
    }

    .help-text {
      font-size: 0.75rem;
    }

    .info-text {
      font-size: 0.825rem;
    }

    .info-icon {
      font-size: 1rem;
    }

    .config-section {
      margin-bottom: 1rem;
    }

    .model-selection {
      padding: 1rem;
    }

    .error-card {
      padding: 1rem;
    }

    .error-title {
      font-size: 1rem;
    }

    .error-message {
      font-size: 0.825rem;
    }
  }

  /* Ultra-wide screens (1600px and up) */
  @media (min-width: 1600px) {
    .page-container {
      max-width: 100%;
      padding: 4rem;
    }

    .page-title {
      font-size: 3.5rem;
    }

    .page-description {
      font-size: 1.375rem;
    }

    .status-card, .config-card, .control-card, .info-card {
      padding: 4rem;
    }

    .status-title, .config-title, .control-title, .info-title {
      font-size: 2rem;
    }

    .button {
      font-size: 1.25rem;
      padding: 1.5rem 3rem;
    }

    .select, .label {
      font-size: 1.25rem;
    }

    .help-text {
      font-size: 1.125rem;
    }

    .info-text {
      font-size: 1.25rem;
    }

    .content-section {
      gap: 3rem;
    }

    .config-section {
      margin-bottom: 2rem;
    }

    .model-selection {
      padding: 2rem;
    }
  }

  /* Extra small devices (below 320px) */
  @media (max-width: 319px) {
    .page-container {
      padding: 0.5rem;
    }

    .page-title {
      font-size: 1.5rem;
    }

    .page-description {
      font-size: 0.8rem;
    }

    .status-card, .config-card, .control-card, .info-card {
      padding: 0.75rem;
    }

    .status-title, .config-title, .control-title, .info-title {
      font-size: 1rem;
    }

    .button {
      font-size: 0.8rem;
      padding: 0.625rem 1rem;
    }

    .select {
      font-size: 0.8rem;
    }

    .label, .checkbox-text {
      font-size: 0.8rem;
    }

    .help-text {
      font-size: 0.7rem;
    }

    .info-text {
      font-size: 0.775rem;
    }
  }

  /* Landscape orientation on mobile */
  @media (max-width: 767px) and (orientation: landscape) {
    .page-container {
      padding: 0.75rem;
    }

    .page-header {
      margin-bottom: 1rem;
    }

    .content-section {
      gap: 1rem;
    }

    .status-card, .config-card, .control-card, .info-card {
      padding: 1rem;
    }

    .control-buttons {
      flex-direction: row;
      gap: 0.75rem;
    }

    .info-content {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 0.75rem;
    }
  }

  /* Print styles */
  @media print {
    .page-container {
      padding: 1rem;
    }

    .button {
      display: none;
    }

    .status-card, .config-card, .control-card, .info-card {
      border: 1px solid #000;
      box-shadow: none;
      break-inside: avoid;
    }

    .page-title {
      color: #000;
    }

    .content-section {
      gap: 1rem;
    }
  }

  /* High contrast mode */
  @media (prefers-contrast: high) {
    .status-card, .config-card, .control-card, .info-card {
      border: 2px solid #000;
    }

    .button {
      border: 2px solid #000;
    }

    .select {
      border: 2px solid #000;
    }
  }

  /* Reduced motion */
  @media (prefers-reduced-motion: reduce) {
    .status-dot {
      animation: none;
    }

    .button {
      transition: none;
    }

    .select {
      transition: none;
    }
  }
</style> 