<script>
  import { onMount } from 'svelte';
  import axios from 'axios';
  import { writable } from 'svelte/store';
  import { hasPermission } from './stores/auth.js';

  let reports = writable([]);
  let pagination = writable({ total: 0, limit: 50, skip: 0, has_more: false });
  let error = writable(null);
  let loading = writable(true);
  let loadingMore = writable(false);
  let availableInterfaces = writable([]);
  let exportLoading = false;
  let deleteLoading = writable({});
  let showDeleteConfirm = writable(null);
  
  // Pagination and filtering
  let currentPage = 0;
  let pageSize = 50;
  let selectedModel = 'all';
  let selectedStatus = 'all';
  let selectedType = 'all';
  let selectedInterface = 'all';
  let dateFrom = '';
  let dateTo = '';
  
  // Available filter options
  const models = ['all', 'kitsune', 'autoencoder', 'lstm', 'cnn', 'rf'];
  const statusOptions = ['all', 'normal', 'threat'];
  const typeOptions = ['all', 'manual_testing', 'real_time_detection'];

  onMount(async () => {
    await loadInterfaces();
    await loadReports();
  });

  async function loadInterfaces() {
    try {
      const res = await axios.get('http://localhost:8000/interfaces');
      const interfaces = [
        { name: 'all', display: 'All Interfaces' },
        ...res.data.interfaces
      ];
      availableInterfaces.set(interfaces);
    } catch (e) {
      console.error('Failed to load network interfaces:', e);
      // Fallback to basic interfaces if API fails
      availableInterfaces.set([
        { name: 'all', display: 'All Interfaces' },
        { name: 'eth0', display: 'Ethernet' },
        { name: 'wlan0', display: 'Wi-Fi' }
      ]);
    }
  }

  async function loadReports(append = false) {
    try {
      if (!append) {
        loading.set(true);
        currentPage = 0;
      } else {
        loadingMore.set(true);
      }
      
      const params = new URLSearchParams({
        limit: pageSize.toString(),
        skip: (currentPage * pageSize).toString()
      });
      
      // Add filters
      if (selectedModel !== 'all') {
        params.append('model', selectedModel);
      }
      
      if (selectedStatus !== 'all') {
        const statusValue = selectedStatus === 'threat' ? 'Attack' : 'Normal';
        params.append('status', statusValue);
      }
      
      if (selectedType !== 'all') {
        params.append('type', selectedType);
      }
      
      if (selectedInterface !== 'all') {
        params.append('interface', selectedInterface);
      }
      
      if (dateFrom) {
        params.append('date_from', dateFrom);
      }
      
      if (dateTo) {
        params.append('date_to', dateTo);
      }
      
      const res = await axios.get(`http://localhost:8000/reports?${params}`);
      
      if (append) {
        reports.update(current => [...current, ...res.data.reports]);
      } else {
        reports.set(res.data.reports);
      }
      
      pagination.set(res.data.pagination);
      error.set(null);
      
    } catch (e) {
      console.error('Failed to load reports:', e);
      error.set('Failed to load reports');
    } finally {
      loading.set(false);
      loadingMore.set(false);
    }
  }

  async function loadMore() {
    currentPage++;
    await loadReports(true);
  }

  async function applyFilters() {
    currentPage = 0;
    reports.set([]);
    await loadReports();
  }

  async function clearFilters() {
    selectedModel = 'all';
    selectedStatus = 'all';
    selectedType = 'all';
    selectedInterface = 'all';
    dateFrom = '';
    dateTo = '';
    await applyFilters();
  }

  async function refreshReports() {
    currentPage = 0;
    reports.set([]);
    await loadReports();
  }

  // Function to format timestamp
  function formatTimestamp(timestamp) {
    return new Date(timestamp).toLocaleString();
  }

  // Function to get status color
  function getStatusColor(prediction) {
    if (!prediction) return 'unknown';
    return prediction === 'Attack' || prediction === 1 ? 'threat' : 'normal';
  }

  // Function to get model badge color - Fixed to handle actual database model names
  function getModelBadgeColor(model) {
    if (!model) return 'bg-gray';
    const colors = {
      // Handle actual database model names (case-sensitive)
      'Autoencoder': 'bg-green',
      'CNN-DNN': 'bg-orange', 
      'LSTM': 'bg-purple',
      'Random Forest': 'bg-teal',
      'Kitsune': 'bg-blue',
      // Also handle lowercase versions for consistency
      'autoencoder': 'bg-green',
      'cnn-dnn': 'bg-orange',
      'cnn': 'bg-orange',
      'lstm-ae': 'bg-purple', 
      'lstm': 'bg-purple',
      'random forest': 'bg-teal',
      'rf': 'bg-teal',
      'kitsune': 'bg-blue'
    };
    return colors[model] || 'bg-gray';
  }

  // Function to get detection type display name
  function getTypeDisplayName(type) {
    if (type === 'real_time_detection') return 'Real-time Detection';
    if (type === 'manual_testing') return 'Manual Testing';
    return 'Unknown';
  }

  // Generate brief threat summary for table display
  function getBriefThreatSummary(report) {
    if (!report.result || report.result.prediction === 'Normal') {
      return 'Normal Traffic';
    }

    // Extract key features for brief description
    if (report.features && report.features.length >= 3) {
      const dstPort = report.features[2] || 0;
      
      if (dstPort === 22) {
        return 'SSH Service Anomaly';
      } else if (dstPort === 80 || dstPort === 443) {
        return 'Web Service Anomaly';
      } else if (dstPort === 21) {
        return 'FTP Service Suspicious';
      } else if (dstPort === 3389) {
        return 'RDP Brute Force';
      } else if (dstPort < 1024) {
        return 'System Port Unauthorized';
      } else if (dstPort > 0) {
        return `Port ${dstPort} Anomaly`;
      }
    }

    // Fallback to model-specific description
    const model = report.result ? report.result.model || '' : '';
    if (model.includes('Kitsune')) {
      return 'Zero-day Detection';
    } else if (model.includes('CNN') || model.includes('Random Forest')) {
      return 'Known Attack Pattern';
    } else {
      return 'Anomalous Behavior';
    }
  }

  // Helper to get current date in YYYY-MM-DD format
  function getCurrentDate() {
    return new Date().toISOString().split('T')[0];
  }

  // Helper to get date 7 days ago
  function getWeekAgoDate() {
    const date = new Date();
    date.setDate(date.getDate() - 7);
    return date.toISOString().split('T')[0];
  }

  // Export functionality
  async function exportReports(format = 'csv') {
    try {
      exportLoading = true;
      
      const params = new URLSearchParams();
      params.append('format', format);
      
      // Add current filters
      if (selectedModel !== 'all') {
        params.append('model', selectedModel);
      }
      if (selectedStatus !== 'all') {
        const statusValue = selectedStatus === 'threat' ? 'Attack' : 'Normal';
        params.append('status', statusValue);
      }
      if (selectedType !== 'all') {
        params.append('type', selectedType);
      }
      if (selectedInterface !== 'all') {
        params.append('interface', selectedInterface);
      }
      if (dateFrom) {
        params.append('date_from', dateFrom);
      }
      if (dateTo) {
        params.append('date_to', dateTo);
      }
      
      // Create download
      const response = await axios.get(`http://localhost:8000/reports/export?${params}`, {
        withCredentials: true,
        responseType: 'blob'
      });
      
      // Create download link
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      
      const contentDisposition = response.headers['content-disposition'];
      const filename = contentDisposition ? 
        contentDisposition.split('filename=')[1].replace(/"/g, '') :
        `detection_reports_${new Date().toISOString().split('T')[0]}.${format}`;
      
      link.setAttribute('download', filename);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
      
    } catch (e) {
      console.error('Export failed:', e);
      if (e.response?.status === 403) {
        error.set('Permission denied: Export data access required');
      } else {
        error.set('Export failed');
      }
      setTimeout(() => error.set(null), 5000);
    } finally {
      exportLoading = false;
    }
  }

  // Delete functionality
  async function deleteReport(reportId) {
    try {
      await axios.delete(`http://localhost:8000/reports/${reportId}`, {
        withCredentials: true
      });
      
      // Remove from local state
      reports.update(current => current.filter(r => r._id !== reportId));
      
    } catch (e) {
      console.error('Delete failed:', e);
      if (e.response?.status === 403) {
        error.set('Permission denied: Delete reports access required');
      } else {
        error.set('Delete failed');
      }
      setTimeout(() => error.set(null), 5000);
        }
  }

  // Generate natural language description for attack reports
  function generateAttackDescription(report) {
    if (!report.result || report.result.prediction === 'Normal') {
      return "Normal network traffic detected. No security threats identified.";
    }

    const model = report.result ? report.result.model || 'Unknown' : 'Unknown';
    const type = report.type === 'real_time_detection' ? 'Real-time Detection' : 'Manual Testing';
    const timestamp = new Date(report.timestamp).toLocaleString('en-US');
    const networkInterface = report.interface || 'Unknown Interface';
    
    let description = `🚨 **Threat Detection Report**\n\n`;
    
    // Basic information
    description += `**Detection Time:** ${timestamp}\n`;
    description += `**Detection Model:** ${model}\n`;
    description += `**Detection Method:** ${type}\n`;
    if (report.interface) {
      description += `**Network Interface:** ${networkInterface}\n`;
    }
    description += `\n`;

    // Analyze feature data to generate specific descriptions
    if (report.features && report.features.length >= 11) {
      const features = report.features;
      
      // Extract key features (based on common network packet feature positions)
      const packetLen = features[0] || 0;      // Packet length
      const srcPort = features[1] || 0;        // Source port
      const dstPort = features[2] || 0;        // Destination port
      const flags = features[3] || 0;          // TCP flags
      const ttl = features[8] || 0;           // TTL value
      const protocol = features[11] || 0;      // Protocol type

      description += `**Detected Anomalous Behaviors:**\n`;

      // Analyze port behavior
      if (dstPort > 0) {
        if (dstPort === 22) {
          description += `• Suspicious access attempt detected against SSH service (port ${dstPort})\n`;
        } else if (dstPort === 80 || dstPort === 443) {
          description += `• Abnormal HTTP requests detected against Web service (port ${dstPort})\n`;
        } else if (dstPort === 21) {
          description += `• Suspicious file transfer activity detected against FTP service (port ${dstPort})\n`;
        } else if (dstPort === 23) {
          description += `• Unencrypted login attempt detected against Telnet service (port ${dstPort})\n`;
        } else if (dstPort === 3389) {
          description += `• Brute force attack detected against Remote Desktop service (port ${dstPort})\n`;
        } else if (dstPort < 1024) {
          description += `• Unauthorized access attempt detected against system service port (${dstPort})\n`;
        } else {
          description += `• Abnormal connection behavior detected against application port (${dstPort})\n`;
        }
      }

      // Analyze packet size
      if (packetLen > 1500) {
        description += `• Abnormally large packet detected (${Math.round(packetLen)} bytes), possible data exfiltration or buffer overflow attack\n`;
      } else if (packetLen < 60 && packetLen > 0) {
        description += `• Abnormally small packet detected (${Math.round(packetLen)} bytes), possible network scanning or probing behavior\n`;
      }

      // Analyze TTL value
      if (ttl > 0 && ttl < 32) {
        description += `• Abnormal TTL value detected (${Math.round(ttl)}), possibly indicating network hop anomalies or IP spoofing\n`;
      } else if (ttl > 128) {
        description += `• Abnormally high TTL value detected (${Math.round(ttl)}), possible forged network traffic\n`;
      }

      // Analyze TCP flags
      if (flags > 0) {
        if (flags & 0x02) { // SYN flag
          description += `• SYN flooding attack characteristics detected, possibly part of a DDoS attack\n`;
        }
        if (flags & 0x01) { // FIN flag  
          description += `• Abnormal connection termination behavior detected, possible port scanning or connection hijacking\n`;
        }
      }

      // Analyze source port
      if (srcPort > 0) {
        if (srcPort < 1024) {
          description += `• Source port using system privileged port (${Math.round(srcPort)}), possible privilege escalation attack\n`;
        } else if (srcPort > 65000) {
          description += `• Using abnormally high source port number (${Math.round(srcPort)}), possible port spoofing behavior\n`;
        }
      }
    }

    // Model-specific threat analysis
    description += `\n**${model} Model Analysis:**\n`;
    
    if (model.includes('Autoencoder') || model.includes('LSTM')) {
      const score = report.result ? report.result.anomaly_score || 0 : 0;
      description += `• Anomaly Score: ${score.toFixed(4)} (higher threshold indicates more anomalous)\n`;
      description += `• This model detects anomalies through reconstruction error, current traffic pattern significantly deviates from normal baseline\n`;
      if (score > 0.1) {
        description += `• High anomaly score indicates this traffic is highly similar to known attack patterns\n`;
      }
    } else if (model.includes('CNN') || model.includes('Random Forest')) {
      const prob = report.result ? report.result.probability || 0 : 0;
      description += `• Threat Probability: ${(prob * 100).toFixed(2)}%\n`;
      description += `• This model classifies based on known attack features, identifying obvious malicious behavior patterns\n`;
      if (prob > 0.8) {
        description += `• High threat probability indicates this traffic is very likely a malicious attack\n`;
      }
    } else if (model.includes('Kitsune')) {
      const score = report.result ? report.result.anomaly_score || 0 : 0;
      description += `• Kitsune Anomaly Score: ${score.toFixed(4)}\n`;
      description += `• Kitsune model specializes in zero-day attack detection, discovering unknown anomalous network behavior\n`;
    }

    // Security recommendations
    description += `\n**Security Recommendations:**\n`;
    description += `• Immediately check related system logs and network connections\n`;
    description += `• Verify the legitimacy of involved IP addresses and ports\n`;
    description += `• Consider implementing additional network access control measures\n`;
    description += `• Monitor for similar patterns in subsequent activities\n`;

    return description;
  }

  // Delete confirmation and functionality
  function confirmDelete(reportId) {
    showDeleteConfirm.set(reportId);
  }

  function cancelDelete() {
    showDeleteConfirm.set(null);
  }

  async function deleteSelectedReport(reportId) {
    try {
      deleteLoading.update(loading => ({ ...loading, [reportId]: true }));
      
      await axios.delete(`http://localhost:8000/reports/${reportId}`, {
        withCredentials: true
      });
      
      // Remove from local state
      reports.update(current => current.filter(r => r._id !== reportId));
      showDeleteConfirm.set(null);
      
    } catch (e) {
      console.error('Delete failed:', e);
      if (e.response?.status === 403) {
        error.set('Permission denied: Delete reports access required');
      } else {
        error.set('Delete failed');
      }
      setTimeout(() => error.set(null), 5000);
    } finally {
      deleteLoading.update(loading => ({ ...loading, [reportId]: false }));
    }
  }

 
</script>

<div class="page-container">
  <div class="page-header">
    <h1 class="page-title">📋 Detection Reports</h1>
    <p class="page-description">Review historical detection results and threat analysis with advanced filtering</p>
  </div>

  <div class="content-section">
    <!-- Advanced Filter Controls -->
    <div class="filters-card">
      <div class="filters-header">
        <h3>Filters & Controls</h3>
        <div class="filter-actions">
          <button class="clear-filters-button" on:click={clearFilters}>Clear All</button>
          <button class="refresh-button" on:click={refreshReports}>🔄 Refresh</button>
          
          <!-- Export Controls -->
          {#if hasPermission('export_data')}
            <div class="export-dropdown">
              <button class="export-button" class:loading={exportLoading} disabled={exportLoading}>
                {#if exportLoading}
                  <span class="button-spinner"></span>
                  Exporting...
                {:else}
                  📊 Export Data
                {/if}
              </button>
              <div class="export-menu">
                <button class="export-option" on:click={() => exportReports('csv')} disabled={exportLoading}>
                  📄 Export as CSV
                </button>
                <button class="export-option" on:click={() => exportReports('json')} disabled={exportLoading}>
                  📋 Export as JSON
                </button>
              </div>
            </div>
          {/if}
        </div>
      </div>
      
      <div class="filters-grid">
        <!-- Model Filter -->
        <div class="filter-group">
          <label class="filter-label" for="model-select">Model:</label>
          <select id="model-select" class="filter-select" bind:value={selectedModel} on:change={applyFilters}>
            {#each models as model}
              <option value={model}>{model === 'all' ? 'All Models' : model.toUpperCase()}</option>
            {/each}
          </select>
        </div>

        <!-- Status Filter -->
        <div class="filter-group">
          <label class="filter-label" for="status-select">Status:</label>
          <select id="status-select" class="filter-select" bind:value={selectedStatus} on:change={applyFilters}>
            {#each statusOptions as status}
              <option value={status}>
                {status === 'all' ? 'All Status' : 
                 status === 'threat' ? '🚨 Threat' : 
                 '✅ Normal'}
              </option>
            {/each}
          </select>
        </div>

        <!-- Detection Type Filter -->
        <div class="filter-group">
          <label class="filter-label" for="type-select">Detection Type:</label>
          <select id="type-select" class="filter-select" bind:value={selectedType} on:change={applyFilters}>
            {#each typeOptions as type}
              <option value={type}>
                {type === 'all' ? 'All Types' : 
                 type === 'manual_testing' ? '🧪 Manual Testing' : 
                 '🔄 Real-time Detection'}
              </option>
            {/each}
          </select>
        </div>

        <!-- Network Interface Filter -->
        <div class="filter-group">
          <label class="filter-label" for="interface-select">Network Interface:</label>
          <select id="interface-select" class="filter-select" bind:value={selectedInterface} on:change={applyFilters}>
            {#each $availableInterfaces as iface}
              <option value={iface.name}>{iface.display}</option>
            {/each}
          </select>
        </div>

        <!-- Date Range Filters -->
        <div class="filter-group date-filter">
          <label class="filter-label" for="date-from">Date From:</label>
          <input 
            id="date-from"
            type="date" 
            class="filter-input"
            bind:value={dateFrom}
            on:change={applyFilters}
            max={getCurrentDate()}
          />
        </div>

        <div class="filter-group date-filter">
          <label class="filter-label" for="date-to">Date To:</label>
          <input 
            id="date-to"
            type="date" 
            class="filter-input"
            bind:value={dateTo}
            on:change={applyFilters}
            max={getCurrentDate()}
          />
        </div>

        <!-- Quick Date Filters -->
        <div class="filter-group quick-dates">
          <label class="filter-label" for="quick-date-group">Quick Select:</label>
          <div class="quick-date-buttons"
               id="quick-date-group"
               role="group" 
               aria-labelledby="quick-date-group">
            <button 
              class="quick-date-button"
              type="button"
              on:click={() => {
                dateFrom = getCurrentDate();
                dateTo = getCurrentDate();
                applyFilters();
              }}
            >
              Today
            </button>
            <button 
              class="quick-date-button"
              type="button"
              on:click={() => {
                dateFrom = getWeekAgoDate();
                dateTo = getCurrentDate();
                applyFilters();
              }}
            >
              Last 7 Days
            </button>
          </div>
        </div>
      </div>
      
      <!-- Filter Summary -->
      {#if $pagination.total !== undefined}
        <div class="filter-summary">
          <div class="stats-info">
            Showing {$reports.length} of {$pagination.total} reports
            {#if selectedModel !== 'all' || selectedStatus !== 'all' || selectedType !== 'all' || selectedInterface !== 'all' || dateFrom || dateTo}
              <span class="filter-indicator">(filtered)</span>
            {/if}
          </div>
          
          <!-- Active Filters Display -->
          {#if selectedModel !== 'all' || selectedStatus !== 'all' || selectedType !== 'all' || selectedInterface !== 'all' || dateFrom || dateTo}
            <div class="active-filters">
              <span class="active-filters-label">Active filters:</span>
              {#if selectedModel !== 'all'}
                <span class="filter-tag">{selectedModel.toUpperCase()}</span>
              {/if}
              {#if selectedStatus !== 'all'}
                <span class="filter-tag">{selectedStatus === 'threat' ? '🚨 Threat' : '✅ Normal'}</span>
              {/if}
              {#if selectedType !== 'all'}
                <span class="filter-tag">{selectedType === 'manual_testing' ? '🧪 Manual' : '🔄 Real-time'}</span>
              {/if}
              {#if selectedInterface !== 'all'}
                <span class="filter-tag">{selectedInterface.toUpperCase()}</span>
              {/if}
              {#if dateFrom}
                <span class="filter-tag">From: {dateFrom}</span>
              {/if}
              {#if dateTo}
                <span class="filter-tag">To: {dateTo}</span>
              {/if}
            </div>
          {/if}
        </div>
      {/if}
    </div>

    {#if $loading}
      <div class="loading-card">
        <div class="loading-spinner"></div>
        <p>Loading detection reports...</p>
      </div>
    {:else if $error}
      <div class="error-card">
        <h3 class="error-title">⚠️ Error Loading Reports</h3>
        <p class="error-message">{$error}</p>
        <button class="retry-button" on:click={refreshReports}>Try Again</button>
      </div>
    {:else if $reports.length === 0}
      <div class="empty-card">
        <div class="empty-icon">📊</div>
        <h3 class="empty-title">No Reports Found</h3>
        <p class="empty-message">
          {#if selectedModel !== 'all' || selectedStatus !== 'all' || selectedType !== 'all' || selectedInterface !== 'all' || dateFrom || dateTo}
            No detection reports match your current filters. Try adjusting the filter criteria.
          {:else}
            No detection reports have been generated yet. Run some detections to see results here.
          {/if}
        </p>
        {#if selectedModel !== 'all' || selectedStatus !== 'all' || selectedType !== 'all' || selectedInterface !== 'all' || dateFrom || dateTo}
          <button class="clear-filter-button" on:click={clearFilters}>Clear All Filters</button>
        {/if}
      </div>
    {:else}
      <div class="reports-card">
        <div class="reports-header">
          <h2 class="reports-title">Detection History</h2>
          <div class="reports-actions">
            <span class="count-badge">{$pagination.total || $reports.length} Total</span>
          </div>
        </div>

        <div class="table-container">
          <table class="reports-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Model</th>
                <th>Status</th>
                <th>Type</th>
                <th>Threat Summary</th>
                <th>Score/Probability</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {#each $reports as report, index}
                <tr class="report-row">
                  <td class="timestamp-cell">
                    <div class="timestamp">
                      {formatTimestamp(report.timestamp)}
                    </div>
                  </td>
                  
                  <td class="model-cell">
                    <span class="model-badge {getModelBadgeColor(report.result ? report.result.model : null)}">
                      {report.result ? (report.result.model?.toUpperCase() || 'Unknown') : 'Unknown'}
                    </span>
                  </td>
                  
                  <td class="status-cell">
                    <span class="status-badge {getStatusColor(report.result ? report.result.prediction : null)}">
                      <span class="status-dot"></span>
                      {report.result ? (report.result.prediction === 'Attack' || report.result.prediction === 1 ? 'Threat' : 'Normal') : 'Unknown'}
                    </span>
                  </td>

                  <td class="type-cell">
                    <span class="type-badge {report.type === 'real_time_detection' ? 'realtime' : 'manual'}">
                      {getTypeDisplayName(report.type)}
                    </span>
                  </td>

                  <td class="summary-cell">
                    <span class="summary-text {getStatusColor(report.result ? report.result.prediction : null)}">
                      {getBriefThreatSummary(report)}
                    </span>
                  </td>
                  
                  <td class="score-cell">
                    {#if report.result && report.result.anomaly_score !== undefined}
                      <span class="score">{report.result.anomaly_score.toFixed(4)}</span>
                    {:else if report.result && report.result.probability !== undefined}
                      <span class="score">{(report.result.probability * 100).toFixed(2)}%</span>
                    {:else}
                      <span class="score-na">N/A</span>
                    {/if}
                  </td>
                  
                  <td class="details-cell">
                    <div class="action-buttons">
                      <button 
                        class="details-button"
                        on:click={() => {
                          const detailsRow = document.getElementById(`details-${index}`);
                          if (detailsRow.style.display === 'none' || !detailsRow.style.display) {
                            detailsRow.style.display = 'table-row';
                          } else {
                            detailsRow.style.display = 'none';
                          }
                        }}
                      >
                        View
                      </button>
                      {#if hasPermission('delete_reports')}
                        <button 
                          class="delete-button"
                          on:click={() => confirmDelete(report._id)}
                          title="Delete this report"
                        >
                          🗑️
                        </button>
                      {/if}
                    </div>
                  </td>
                </tr>
                
                <!-- Expandable details row -->
                <tr id="details-{index}" class="details-row" style="display: none;">
                  <td colspan="7" class="details-content">
                    <div class="details-panel">
                      <!-- Natural Language Description for Threats -->
                      {#if report.result && (report.result.prediction === 'Attack' || report.result.prediction === 1)}
                        <div class="threat-description-section">
                          <h4>🛡️ Threat Analysis Report</h4>
                          <div class="threat-description">
                            {#each generateAttackDescription(report).split('\n') as line}
                              {#if line.trim().startsWith('**') && line.trim().endsWith('**')}
                                <h5 class="description-heading">{line.replace(/\*\*/g, '')}</h5>
                              {:else if line.trim().startsWith('•')}
                                <div class="description-bullet">{line}</div>
                              {:else if line.trim()}
                                <p class="description-text">{line}</p>
                              {/if}
                            {/each}
                          </div>
                        </div>
                      {:else}
                        <div class="normal-description-section">
                          <h4>✅ Detection Result</h4>
                          <p class="normal-description">Normal network traffic detected. No security threats identified.</p>
                        </div>
                      {/if}
                      
                      <h4>Technical Details</h4>
                      <div class="details-grid">
                        <div class="detail-item">
                          <strong>Model:</strong> {report.result ? report.result.model : 'N/A'}
                        </div>
                        <div class="detail-item">
                          <strong>Prediction:</strong> {report.result ? report.result.prediction : 'N/A'}
                        </div>
                        <div class="detail-item">
                          <strong>Detection Type:</strong> {getTypeDisplayName(report.type)}
                        </div>
                        {#if report.result && report.result.anomaly_score !== undefined}
                          <div class="detail-item">
                            <strong>Anomaly Score:</strong> {report.result.anomaly_score.toFixed(4)}
                          </div>
                        {/if}
                        {#if report.result && report.result.probability !== undefined}
                          <div class="detail-item">
                            <strong>Probability:</strong> {(report.result.probability * 100).toFixed(2)}%
                          </div>
                        {/if}
                        <div class="detail-item">
                          <strong>Timestamp:</strong> {formatTimestamp(report.timestamp)}
                        </div>
                      </div>
                      
                      {#if report.features}
                        <div class="features-section">
                          <h5>Input Features ({report.features.length})</h5>
                          <div class="features-preview">
                            {report.features.slice(0, 10).join(', ')}
                            {#if report.features.length > 10}
                              ... (+{report.features.length - 10} more)
                            {/if}
                          </div>
                        </div>
                      {/if}
                    </div>
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
        
        <!-- Load More Button -->
        {#if $pagination.has_more}
          <div class="load-more-section">
            <button 
              class="load-more-button" 
              on:click={loadMore}
              disabled={$loadingMore}
            >
              {#if $loadingMore}
                <span class="loading-spinner small"></span>
                Loading more...
              {:else}
                Load More Reports
              {/if}
            </button>
          </div>
        {/if}
      </div>
    {/if}
  </div>

  <!-- Delete Confirmation Modal -->
  {#if $showDeleteConfirm}
    <div class="modal-overlay">
      <div class="modal-content">
        <div class="modal-header">
          <h3 class="modal-title">⚠️ Confirm Delete</h3>
        </div>
        <div class="modal-body">
          <p>Are you sure you want to delete this detection report?</p>
          <p class="modal-warning">This action cannot be undone.</p>
        </div>
        <div class="modal-actions">
          <button class="modal-cancel-button" on:click={cancelDelete}>
            Cancel
          </button>
          <button 
            class="modal-delete-button" 
            on:click={() => deleteSelectedReport($showDeleteConfirm)}
            disabled={$deleteLoading[$showDeleteConfirm]}
          >
            {#if $deleteLoading[$showDeleteConfirm]}
              <span class="button-spinner"></span>
              Deleting...
            {:else}
              🗑️ Delete
            {/if}
          </button>
        </div>
      </div>
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

  .content-section {
    display: flex;
    flex-direction: column;
    gap: 1.5rem;
  }

  /* Advanced Filters Card */
  .filters-card {
    background: white;
    border-radius: 12px;
    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
    border: 1px solid #e5e7eb;
    padding: 2rem;
  }

  .filters-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1.5rem;
  }

  .filters-header h3 {
    margin: 0;
    color: #1f2937;
    font-size: 1.25rem;
    font-weight: 600;
  }

  .filter-actions {
    display: flex;
    gap: 0.75rem;
  }

  .clear-filters-button, .refresh-button, .export-button {
    background-color: #6b7280;
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

  .refresh-button {
    background-color: #3b82f6;
  }

  .export-button {
    background-color: #10b981;
  }

  .clear-filters-button:hover {
    background-color: #4b5563;
  }

  .refresh-button:hover {
    background-color: #2563eb;
  }

  .export-button:hover:not(:disabled) {
    background-color: #059669;
  }

  .export-button:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  /* Export Dropdown */
  .export-dropdown {
    position: relative;
    display: inline-block;
  }

  .export-dropdown:hover .export-menu {
    display: block;
  }

  .export-menu {
    display: none;
    position: absolute;
    top: 100%;
    right: 0;
    background: white;
    border: 1px solid #e5e7eb;
    border-radius: 8px;
    box-shadow: 0 10px 25px rgba(0, 0, 0, 0.15);
    z-index: 10;
    min-width: 160px;
    margin-top: 0.25rem;
  }

  .export-option {
    display: block;
    width: 100%;
    text-align: left;
    padding: 0.75rem 1rem;
    border: none;
    background: none;
    color: #374151;
    cursor: pointer;
    transition: background-color 0.2s ease;
    font-size: 0.875rem;
    font-weight: 500;
  }

  .export-option:first-child {
    border-radius: 8px 8px 0 0;
  }

  .export-option:last-child {
    border-radius: 0 0 8px 8px;
  }

  .export-option:hover:not(:disabled) {
    background-color: #f3f4f6;
    color: #1f2937;
  }

  .export-option:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .button-spinner {
    width: 14px;
    height: 14px;
    border: 2px solid #ffffff40;
    border-left: 2px solid #ffffff;
    border-radius: 50%;
    animation: spin 1s linear infinite;
  }

  .filters-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1rem;
    margin-bottom: 1.5rem;
  }

  .filter-group {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .filter-group.date-filter {
    min-width: 150px;
  }

  .filter-group.quick-dates {
    min-width: 200px;
  }

  .filter-label {
    font-weight: 600;
    color: #374151;
    font-size: 0.875rem;
  }

  .filter-select, .filter-input {
    border: 1px solid #d1d5db;
    padding: 0.5rem;
    border-radius: 6px;
    font-size: 0.875rem;
    background-color: white;
    transition: border-color 0.2s ease;
  }

  .filter-select:focus, .filter-input:focus {
    outline: none;
    border-color: #3b82f6;
    box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
  }

  .quick-date-buttons {
    display: flex;
    gap: 0.5rem;
  }

  .quick-date-button {
    background-color: #f3f4f6;
    color: #374151;
    border: none;
    padding: 0.375rem 0.75rem;
    border-radius: 6px;
    font-size: 0.75rem;
    cursor: pointer;
    transition: background-color 0.2s ease;
    font-weight: 500;
  }

  .quick-date-button:hover {
    background-color: #e5e7eb;
  }

  /* Filter Summary */
  .filter-summary {
    padding-top: 1rem;
    border-top: 1px solid #e5e7eb;
  }

  .stats-info {
    font-size: 0.875rem;
    color: #6b7280;
    margin-bottom: 0.75rem;
  }

  .filter-indicator {
    color: #3b82f6;
    font-weight: 600;
  }

  .active-filters {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 0.5rem;
  }

  .active-filters-label {
    font-size: 0.75rem;
    color: #6b7280;
    font-weight: 600;
  }

  .filter-tag {
    background-color: #e0e7ff;
    color: #3730a3;
    padding: 0.25rem 0.5rem;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 500;
  }

  /* Loading State */
  .loading-card {
    background: white;
    border-radius: 12px;
    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
    border: 1px solid #e5e7eb;
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

  .loading-spinner.small {
    width: 16px;
    height: 16px;
    border-width: 2px;
    margin: 0;
  }

  /* Empty State */
  .empty-card {
    background: white;
    border-radius: 12px;
    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
    border: 1px solid #e5e7eb;
    padding: 3rem;
    text-align: center;
  }

  .empty-icon {
    font-size: 4rem;
    margin-bottom: 1rem;
  }

  .empty-title {
    font-size: 1.5rem;
    font-weight: bold;
    margin: 0 0 1rem 0;
    color: #1f2937;
  }

  .empty-message {
    color: #6b7280;
    margin: 0 0 1.5rem 0;
    font-size: 1rem;
    line-height: 1.5;
  }

  .clear-filter-button, .retry-button {
    background-color: #6b7280;
    color: white;
    border: none;
    padding: 0.75rem 1.5rem;
    border-radius: 8px;
    font-size: 0.875rem;
    cursor: pointer;
    transition: background-color 0.2s ease;
    font-weight: 500;
  }

  .clear-filter-button:hover, .retry-button:hover {
    background-color: #4b5563;
  }

  /* Reports Card */
  .reports-card {
    background: white;
    border-radius: 12px;
    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
    border: 1px solid #e5e7eb;
    overflow: hidden;
  }

  .reports-header {
    padding: 2rem;
    background: #f9fafb;
    border-bottom: 1px solid #e5e7eb;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }

  .reports-title {
    font-size: 1.5rem;
    font-weight: bold;
    margin: 0;
    color: #1f2937;
  }

  .reports-actions {
    display: flex;
    align-items: center;
    gap: 1rem;
  }

  .count-badge {
    background-color: #e0e7ff;
    color: #3730a3;
    padding: 0.5rem 1rem;
    border-radius: 20px;
    font-size: 0.875rem;
    font-weight: 600;
  }



  /* Table Styles */
  .table-container {
    overflow-x: auto;
  }

  .reports-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.875rem;
  }

  .reports-table th {
    background-color: #f9fafb;
    padding: 1rem;
    text-align: left;
    font-weight: 600;
    color: #374151;
    border-bottom: 1px solid #e5e7eb;
    white-space: nowrap;
  }

  .reports-table td {
    padding: 1rem;
    border-bottom: 1px solid #f3f4f6;
    vertical-align: middle;
  }

  .report-row:hover {
    background-color: #f9fafb;
  }

  /* Cell Styles */
  .timestamp {
    color: #6b7280;
    font-size: 0.875rem;
    white-space: nowrap;
  }

  .model-badge {
    padding: 0.25rem 0.75rem;
    border-radius: 15px;
    font-size: 0.75rem;
    font-weight: 600;
    color: white;
    white-space: nowrap;
  }

  .bg-blue { background-color: #3b82f6; }
  .bg-green { background-color: #10b981; }
  .bg-purple { background-color: #8b5cf6; }
  .bg-orange { background-color: #f59e0b; }
  .bg-teal { background-color: #14b8a6; }
  .bg-gray { background-color: #6b7280; }

  .status-badge {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.5rem 1rem;
    border-radius: 20px;
    font-size: 0.75rem;
    font-weight: 600;
    width: fit-content;
    white-space: nowrap;
  }

  .status-badge.threat {
    background-color: #fee2e2;
    color: #991b1b;
  }

  .status-badge.normal {
    background-color: #dcfce7;
    color: #166534;
  }

  .type-badge {
    padding: 0.25rem 0.75rem;
    border-radius: 15px;
    font-size: 0.75rem;
    font-weight: 600;
    color: white;
    white-space: nowrap;
  }

  .type-badge.realtime {
    background-color: #8b5cf6;
  }

  .type-badge.manual {
    background-color: #06b6d4;
  }

  .status-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background-color: currentColor;
  }

  .score {
    font-family: 'Monaco', 'Consolas', 'Courier New', monospace;
    font-weight: 600;
    color: #374151;
  }

  .score-na {
    color: #9ca3af;
    font-style: italic;
  }

  .summary-cell {
    max-width: 200px;
  }

  .summary-text {
    font-size: 0.875rem;
    font-weight: 500;
    padding: 0.25rem 0.75rem;
    border-radius: 12px;
    display: inline-block;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    max-width: 100%;
  }

  .summary-text.threat {
    background-color: #fee2e2;
    color: #991b1b;
  }

  .summary-text.normal {
    background-color: #dcfce7;
    color: #166534;
  }

  .action-buttons {
    display: flex;
    gap: 0.5rem;
    align-items: center;
  }

  .details-button, .delete-button {
    border: none;
    padding: 0.5rem 1rem;
    border-radius: 6px;
    font-size: 0.75rem;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.2s ease;
    white-space: nowrap;
    display: flex;
    align-items: center;
    gap: 0.25rem;
  }

  .details-button {
    background-color: #e0e7ff;
    color: #3730a3;
  }

  .details-button:hover {
    background-color: #c7d2fe;
  }

  .delete-button {
    background-color: #fee2e2;
    color: #dc2626;
    padding: 0.5rem;
    min-width: 36px;
    justify-content: center;
  }

  .delete-button:hover {
    background-color: #fecaca;
    transform: scale(1.05);
  }

  /* Details Panel */
  .details-row {
    background-color: #f8fafc;
  }

  .details-content {
    padding: 0;
  }

  .details-panel {
    padding: 1.5rem 2rem;
    border-top: 1px solid #e2e8f0;
  }

  .details-panel h4 {
    margin: 0 0 1rem 0;
    color: #1f2937;
    font-size: 1.125rem;
    font-weight: 600;
  }

  /* Natural Language Description Styles */
  .threat-description-section {
    background: linear-gradient(135deg, #fef2f2 0%, #fee2e2 100%);
    border: 1px solid #fecaca;
    border-left: 4px solid #ef4444;
    border-radius: 8px;
    padding: 1.5rem;
    margin-bottom: 2rem;
  }

  .normal-description-section {
    background: linear-gradient(135deg, #f0fdf4 0%, #dcfce7 100%);
    border: 1px solid #bbf7d0;
    border-left: 4px solid #10b981;
    border-radius: 8px;
    padding: 1.5rem;
    margin-bottom: 2rem;
  }

  .threat-description {
    margin-top: 1rem;
  }

  .description-heading {
    color: #991b1b;
    font-size: 1rem;
    font-weight: 600;
    margin: 1rem 0 0.5rem 0;
    border-bottom: 2px solid #fecaca;
    padding-bottom: 0.25rem;
  }

  .description-text {
    color: #374151;
    margin: 0.5rem 0;
    line-height: 1.6;
  }

  .description-bullet {
    color: #dc2626;
    margin: 0.25rem 0;
    padding-left: 1rem;
    line-height: 1.5;
    font-size: 0.95rem;
  }

  .normal-description {
    color: #059669;
    margin: 0.5rem 0 0 0;
    font-size: 1rem;
    font-weight: 500;
  }

  .details-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 0.75rem;
    margin-bottom: 1.5rem;
  }

  .detail-item {
    color: #374151;
    font-size: 0.875rem;
  }

  .detail-item strong {
    color: #1f2937;
  }

  .features-section {
    border-top: 1px solid #e2e8f0;
    padding-top: 1rem;
  }

  .features-section h5 {
    margin: 0 0 0.5rem 0;
    color: #1f2937;
    font-size: 1rem;
    font-weight: 600;
  }

  .features-preview {
    font-family: 'Monaco', 'Consolas', 'Courier New', monospace;
    font-size: 0.75rem;
    color: #6b7280;
    background-color: #f1f5f9;
    padding: 1rem;
    border-radius: 6px;
    overflow-x: auto;
  }

  /* Load More Section */
  .load-more-section {
    padding: 2rem;
    text-align: center;
    border-top: 1px solid #e5e7eb;
  }

  .load-more-button {
    background-color: #f3f4f6;
    color: #374151;
    border: none;
    padding: 0.75rem 2rem;
    border-radius: 8px;
    font-size: 0.875rem;
    font-weight: 600;
    cursor: pointer;
    transition: background-color 0.2s ease;
    display: flex;
    align-items: center;
    gap: 0.5rem;
    margin: 0 auto;
  }

  .load-more-button:hover:not(:disabled) {
    background-color: #e5e7eb;
  }

  .load-more-button:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  /* Error Card */
  .error-card {
    background: white;
    border-radius: 12px;
    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
    border: 1px solid #fecaca;
    border-left: 4px solid #ef4444;
    padding: 2rem;
    text-align: center;
  }

  .error-title {
    font-size: 1.25rem;
    font-weight: bold;
    margin: 0 0 1rem 0;
    color: #991b1b;
  }

  .error-message {
    color: #dc2626;
    margin: 0 0 1.5rem 0;
    font-size: 1rem;
  }

  @keyframes spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
  }

  /* Delete Confirmation Modal */
  .modal-overlay {
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background-color: rgba(0, 0, 0, 0.5);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 1000;
    padding: 1rem;
  }

  .modal-content {
    background: white;
    border-radius: 12px;
    box-shadow: 0 25px 50px rgba(0, 0, 0, 0.25);
    max-width: 400px;
    width: 100%;
    animation: modalSlideIn 0.2s ease;
  }

  .modal-header {
    padding: 1.5rem 1.5rem 1rem 1.5rem;
    border-bottom: 1px solid #e5e7eb;
  }

  .modal-title {
    font-size: 1.25rem;
    font-weight: 600;
    margin: 0;
    color: #1f2937;
  }

  .modal-body {
    padding: 1.5rem;
  }

  .modal-body p {
    margin: 0 0 0.75rem 0;
    color: #374151;
    line-height: 1.5;
  }

  .modal-warning {
    color: #dc2626;
    font-weight: 500;
    font-size: 0.9rem;
  }

  .modal-actions {
    padding: 1rem 1.5rem 1.5rem 1.5rem;
    display: flex;
    gap: 0.75rem;
    justify-content: flex-end;
  }

  .modal-cancel-button, .modal-delete-button {
    padding: 0.75rem 1.5rem;
    border-radius: 8px;
    font-size: 0.875rem;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.2s ease;
    border: none;
    display: flex;
    align-items: center;
    gap: 0.5rem;
    min-height: 44px;
  }

  .modal-cancel-button {
    background-color: #f3f4f6;
    color: #374151;
  }

  .modal-cancel-button:hover {
    background-color: #e5e7eb;
  }

  .modal-delete-button {
    background-color: #dc2626;
    color: white;
  }

  .modal-delete-button:hover:not(:disabled) {
    background-color: #b91c1c;
  }

  .modal-delete-button:disabled {
    opacity: 0.6;
    cursor: not-allowed;
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

  /* Screen reader only text */
  .sr-only {
    position: absolute;
    width: 1px;
    height: 1px;
    padding: 0;
    margin: -1px;
    overflow: hidden;
    clip: rect(0, 0, 0, 0);
    white-space: nowrap;
    border: 0;
  }

  /* Responsive Design */

  /* Large Desktop (1200px and up) */
  @media (min-width: 1200px) {
    .page-container {
      padding: 3rem;
    }

    .page-title {
      font-size: 3rem;
    }

    .page-description {
      font-size: 1.25rem;
    }

    .filters-card {
      padding: 2.5rem;
    }

    .filters-grid {
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 1.5rem;
    }

    .reports-header {
      padding: 2.5rem 3rem;
    }

    .reports-title {
      font-size: 1.75rem;
    }

    .reports-table {
      font-size: 1rem;
    }

    .reports-table th,
    .reports-table td {
      padding: 1.25rem;
    }

    .details-panel {
      padding: 2rem 3rem;
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

    .filters-grid {
      grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
    }

    .reports-header {
      padding: 2rem 2.5rem;
    }

    .details-panel {
      padding: 1.75rem 2.5rem;
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

    .filters-card {
      padding: 1.5rem;
    }

    .filters-grid {
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 1rem;
    }

    .filters-header {
      flex-direction: column;
      gap: 1rem;
      align-items: flex-start;
    }

    .filter-actions {
      align-self: stretch;
      justify-content: flex-end;
    }

    .reports-header {
      padding: 1.5rem 2rem;
      flex-direction: column;
      gap: 1rem;
      align-items: flex-start;
    }

    .reports-title {
      font-size: 1.375rem;
    }

    .table-container {
      overflow-x: auto;
      -webkit-overflow-scrolling: touch;
    }

    .reports-table {
      min-width: 800px;
      font-size: 0.875rem;
    }

    .reports-table th,
    .reports-table td {
      padding: 1rem 0.75rem;
    }

    .details-grid {
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 0.5rem;
    }

    .details-panel {
      padding: 1.5rem;
    }

    .threat-description-section,
    .normal-description-section {
      padding: 1rem;
      margin-bottom: 1.5rem;
    }

    .description-heading {
      font-size: 0.95rem;
    }

    .description-text,
    .description-bullet {
      font-size: 0.9rem;
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

    .filters-card {
      padding: 1.25rem;
    }

    .filters-header {
      flex-direction: column;
      gap: 0.75rem;
      align-items: flex-start;
    }

    .filters-header h3 {
      font-size: 1.125rem;
    }

    .filter-actions {
      align-self: stretch;
      justify-content: space-between;
    }

    .filters-grid {
      grid-template-columns: 1fr;
      gap: 1rem;
    }

    .filter-group.quick-dates .quick-date-buttons {
      justify-content: stretch;
    }

    .quick-date-button {
      flex: 1;
    }

    .active-filters {
      flex-direction: column;
      align-items: flex-start;
      gap: 0.5rem;
    }

    .reports-header {
      padding: 1.25rem;
      flex-direction: column;
      gap: 0.75rem;
      align-items: flex-start;
    }

    .reports-title {
      font-size: 1.25rem;
    }

    .count-badge {
      font-size: 0.8rem;
      padding: 0.375rem 0.75rem;
    }

    .table-container {
      overflow-x: auto;
      -webkit-overflow-scrolling: touch;
    }

    .reports-table {
      min-width: 700px;
      font-size: 0.75rem;
    }

    .summary-text {
      font-size: 0.7rem;
      padding: 0.2rem 0.5rem;
      max-width: 120px;
    }

    .reports-table th,
    .reports-table td {
      padding: 0.75rem 0.5rem;
    }

    .reports-table th {
      font-size: 0.7rem;
      position: sticky;
      top: 0;
      background-color: #f9fafb;
      z-index: 10;
    }

    .timestamp {
      font-size: 0.7rem;
      max-width: 100px;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    .model-badge, .type-badge {
      font-size: 0.65rem;
      padding: 0.25rem 0.5rem;
    }

    .status-badge {
      font-size: 0.65rem;
      padding: 0.25rem 0.5rem;
    }

    .status-dot {
      width: 4px;
      height: 4px;
    }

    .score {
      font-size: 0.7rem;
    }

    .details-button, .delete-button {
      font-size: 0.65rem;
      padding: 0.25rem 0.5rem;
    }

    .delete-button {
      padding: 0.25rem;
      min-width: 28px;
    }

    .action-buttons {
      gap: 0.25rem;
    }

    .details-panel {
      padding: 1.25rem;
    }

    .details-panel h4 {
      font-size: 1.125rem;
    }

    .detail-item {
      font-size: 0.825rem;
    }

    .features-section h5 {
      font-size: 0.95rem;
    }

    .features-preview {
      font-size: 0.65rem;
      padding: 0.75rem;
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

    .threat-description-section,
    .normal-description-section {
      padding: 1rem;
      margin-bottom: 1rem;
    }

    .description-heading {
      font-size: 0.9rem;
      margin: 0.75rem 0 0.25rem 0;
    }

    .description-text,
    .description-bullet {
      font-size: 0.85rem;
      line-height: 1.4;
    }

    .description-bullet {
      padding-left: 0.75rem;
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

    .filters-card {
      padding: 1rem;
    }

    .filters-header h3 {
      font-size: 1rem;
    }

    .clear-filters-button, .refresh-button {
      padding: 0.375rem 0.75rem;
      font-size: 0.8rem;
    }

    .filter-label {
      font-size: 0.8rem;
    }

    .filter-select, .filter-input {
      padding: 0.375rem;
      font-size: 0.8rem;
    }

    .quick-date-button {
      padding: 0.25rem 0.5rem;
      font-size: 0.7rem;
    }

    .filter-tag {
      font-size: 0.7rem;
      padding: 0.2rem 0.4rem;
    }

    .reports-header {
      padding: 1rem;
    }

    .reports-title {
      font-size: 1.125rem;
    }

    .count-badge {
      font-size: 0.75rem;
      padding: 0.25rem 0.5rem;
    }

    .reports-table {
      min-width: 600px;
      font-size: 0.7rem;
    }

    .summary-text {
      font-size: 0.65rem;
      padding: 0.15rem 0.4rem;
      max-width: 100px;
    }

    .reports-table th,
    .reports-table td {
      padding: 0.5rem 0.375rem;
    }

    .timestamp {
      font-size: 0.65rem;
      max-width: 80px;
    }

    .model-badge, .type-badge {
      font-size: 0.6rem;
      padding: 0.2rem 0.4rem;
    }

    .status-badge {
      font-size: 0.6rem;
      padding: 0.2rem 0.4rem;
    }

    .score {
      font-size: 0.65rem;
    }

    .details-button {
      font-size: 0.6rem;
      padding: 0.2rem 0.4rem;
    }

    .details-panel {
      padding: 1rem;
    }

    .details-panel h4 {
      font-size: 1rem;
    }

    .detail-item {
      font-size: 0.75rem;
    }

    .features-section h5 {
      font-size: 0.875rem;
    }

    .features-preview {
      font-size: 0.6rem;
      padding: 0.625rem;
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

  /* Landscape orientation on mobile */
  @media (max-width: 767px) and (orientation: landscape) and (max-height: 500px) {
    .page-container {
      padding: 0.5rem;
    }

    .page-header {
      margin-bottom: 0.75rem;
    }

    .page-title {
      font-size: 1.5rem;
    }

    .page-description {
      font-size: 0.825rem;
    }

    .content-section {
      gap: 0.75rem;
    }

    .filters-card {
      padding: 1rem;
    }

    .filters-grid {
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 0.75rem;
    }

    .reports-header {
      padding: 0.75rem;
      flex-direction: row;
      gap: 1rem;
    }

    .table-container {
      max-height: 60vh;
      overflow-y: auto;
    }

    .details-panel {
      padding: 0.75rem;
    }
  }

  /* Print styles */
  @media print {
    .page-container {
      padding: 1rem;
      max-width: none;
    }

    .filters-card {
      display: none;
    }

    .loading-card, .empty-card, .error-card, .reports-card {
      border: 1px solid #000;
      box-shadow: none;
      break-inside: avoid;
    }

    .page-title {
      color: #000;
    }

    .details-button, .load-more-button {
      display: none;
    }

    .details-row {
      display: table-row !important;
    }

    .reports-table {
      font-size: 10pt;
    }

    .reports-table th,
    .reports-table td {
      padding: 0.25rem;
    }

    .model-badge, .status-badge, .type-badge {
      border: 1px solid #000;
      background: white !important;
      color: #000 !important;
    }
  }

  /* High contrast mode */
  @media (prefers-contrast: high) {
    .filters-card, .reports-card, .loading-card, .empty-card, .error-card {
      border: 2px solid #000;
    }

    .reports-table th,
    .reports-table td {
      border: 1px solid #000;
    }

    .model-badge, .status-badge, .type-badge {
      border: 2px solid #000;
    }

    .details-button, .filter-select, .filter-input {
      border: 2px solid #000;
    }
  }

  /* Reduced motion */
  @media (prefers-reduced-motion: reduce) {
    .loading-spinner {
      animation: none;
    }

    .details-button, .filter-select, .filter-input {
      transition: none;
    }

    .report-row {
      transition: none;
    }
  }
</style>