<script>
  import { onMount } from 'svelte';
  import { writable } from 'svelte/store';
  import axios from 'axios';
  import { hasPermission } from './stores/auth.js';

  // State management
  let uploading = writable(false);
  let analyzing = writable(false);
  let uploadProgress = writable(0);
  let error = writable(null);
  let success = writable(null);
  let analyses = writable([]);
  let selectedAnalysis = writable(null);
  let selectedReport = writable(null);
  let loading = writable(true);

  // File upload state
  let fileInput;
  let dragOver = false;
  let selectedFile = null;

  // Analysis results state
  let currentAnalysisId = null;
  let showAnalysisDetails = false;
  let showReportModal = false;

  // Pagination
  let currentPage = 0;
  let pageSize = 20;
  let hasMore = true;

  // File validation
  const MAX_FILE_SIZE = 100 * 1024 * 1024; // 100MB
  const ALLOWED_EXTENSIONS = ['.pcap', '.pcapng', '.cap'];

  onMount(async () => {
    if (!hasPermission('pcap_analysis')) {
      error.set('Permission denied: PCAP analysis access required');
      loading.set(false);
      return;
    }
    
    await loadAnalyses();
  });

  async function loadAnalyses() {
    try {
      loading.set(true);
      error.set(null);

      const response = await axios.get(`http://localhost:8000/api/pcap/analyses?limit=${pageSize}&skip=${currentPage * pageSize}`);
      
      if (response.data.success) {
        if (currentPage === 0) {
          analyses.set(response.data.analyses);
        } else {
          analyses.update(current => [...current, ...response.data.analyses]);
        }
        
        hasMore = response.data.pagination.has_more;
      }
    } catch (e) {
      console.error('Error loading analyses:', e);
      error.set('Failed to load PCAP analyses');
    } finally {
      loading.set(false);
    }
  }

  function validateFile(file) {
    // Check file type
    const fileName = file.name.toLowerCase();
    if (!ALLOWED_EXTENSIONS.some(ext => fileName.endsWith(ext))) {
      return `Invalid file type. Supported formats: ${ALLOWED_EXTENSIONS.join(', ')}`;
    }

    // Check file size
    if (file.size > MAX_FILE_SIZE) {
      return `File too large. Maximum size: ${MAX_FILE_SIZE / (1024 * 1024)}MB`;
    }

    return null;
  }

  function handleFileSelect(event) {
    const files = event.target.files || event.dataTransfer.files;
    if (files.length > 0) {
      const file = files[0];
      const validationError = validateFile(file);
      
      if (validationError) {
        error.set(validationError);
        selectedFile = null;
      } else {
        selectedFile = file;
        error.set(null);
      }
    }
  }

  function handleDrop(event) {
    event.preventDefault();
    dragOver = false;
    handleFileSelect(event);
  }

  function handleDragOver(event) {
    event.preventDefault();
    dragOver = true;
  }

  function handleDragLeave(event) {
    event.preventDefault();
    dragOver = false;
  }

  async function uploadFile() {
    if (!selectedFile) {
      error.set('Please select a PCAP file first');
      return;
    }

    try {
      uploading.set(true);
      analyzing.set(true);
      uploadProgress.set(0);
      error.set(null);
      success.set(null);

      // Create FormData
      const formData = new FormData();
      formData.append('file', selectedFile);

      // Upload with progress tracking
      const response = await axios.post('http://localhost:8000/api/pcap/upload', formData, {
        headers: {
          'Content-Type': 'multipart/form-data'
        },
        withCredentials: true,
        onUploadProgress: (progressEvent) => {
          const progress = Math.round((progressEvent.loaded * 100) / progressEvent.total);
          uploadProgress.set(progress);
        }
      });

      if (response.data.success) {
        success.set(`Analysis completed! ${response.data.summary.threats_detected} threats detected.`);
        currentAnalysisId = response.data.analysis_id;
        
        // Reset file input
        selectedFile = null;
        if (fileInput) fileInput.value = '';
        
        // Reload analyses list
        currentPage = 0;
        await loadAnalyses();
        
        // Show analysis details
        await viewAnalysisDetails(response.data.analysis_id);
      }
    } catch (e) {
      console.error('Upload error:', e);
      if (e.response?.status === 403) {
        error.set('Permission denied: PCAP analysis access required');
      } else if (e.response?.status === 400) {
        error.set(e.response.data.detail || 'Invalid file or request');
      } else {
        error.set('Upload failed. Please try again.');
      }
    } finally {
      uploading.set(false);
      analyzing.set(false);
      uploadProgress.set(0);
    }
  }

  async function viewAnalysisDetails(analysisId) {
    try {
      const response = await axios.get(`http://localhost:8000/api/pcap/analysis/${analysisId}`);
      
      if (response.data.success) {
        selectedAnalysis.set(response.data.analysis);
        showAnalysisDetails = true;
      }
    } catch (e) {
      console.error('Error loading analysis details:', e);
      error.set('Failed to load analysis details');
    }
  }

  async function viewReport(analysisId) {
    try {
      // Find the analysis to get the report ID
      const analysis = $analyses.find(a => a._id === analysisId);
      if (!analysis) {
        error.set('Analysis not found');
        return;
      }

      // For now, we'll fetch the analysis details which include the report info
      // In a full implementation, you'd have a separate report ID
      const response = await axios.get(`http://localhost:8000/api/pcap/analysis/${analysisId}`);
      
      if (response.data.success) {
        selectedReport.set(response.data.analysis);
        showReportModal = true;
      }
    } catch (e) {
      console.error('Error loading report:', e);
      error.set('Failed to load report');
    }
  }

  function closeAnalysisDetails() {
    showAnalysisDetails = false;
    selectedAnalysis.set(null);
  }

  function closeReportModal() {
    showReportModal = false;
    selectedReport.set(null);
  }

  function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  function formatTimestamp(timestamp) {
    return new Date(timestamp).toLocaleString();
  }

  function getRiskColor(riskLevel) {
    const colors = {
      'Critical': 'risk-critical',
      'High': 'risk-high', 
      'Medium': 'risk-medium',
      'Low': 'risk-low',
      'Minimal': 'risk-minimal'
    };
    return colors[riskLevel] || 'risk-unknown';
  }

  async function loadMoreAnalyses() {
    if (!hasMore || $loading) return;
    
    currentPage++;
    await loadAnalyses();
  }

  function clearFile() {
    selectedFile = null;
    if (fileInput) fileInput.value = '';
    error.set(null);
  }

  async function exportReport(format) {
    try {
      if (!$selectedReport) {
        error.set('No report selected for export');
        return;
      }

      // Get the analysis ID from the selected report
      const analysisId = $selectedReport._id;
      if (!analysisId) {
        error.set('Analysis ID not found');
        return;
      }

      // Create download link
      const downloadUrl = `http://localhost:8000/api/pcap/export/${analysisId}?format=${format}`;
      
      // Create a temporary link element and trigger download
      const link = document.createElement('a');
      link.href = downloadUrl;
      link.download = `pcap_analysis_${$selectedReport.filename?.replace('.pcap', '') || 'report'}_${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.${format}`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);

      success.set(`Report exported successfully as ${format.toUpperCase()}`);
      
      // Clear success message after 3 seconds
      setTimeout(() => {
        success.set(null);
      }, 3000);

    } catch (e) {
      console.error('Error exporting report:', e);
      error.set(`Failed to export report as ${format.toUpperCase()}`);
    }
  }
</script>

<div class="pcap-analyzer-container">
  <div class="page-header">
    <h1 class="page-title">📁 PCAP File Analyzer</h1>
    <p class="page-description">Upload and analyze PCAP files for comprehensive threat detection and security assessment</p>
  </div>

  {#if !hasPermission('pcap_analysis')}
    <div class="error-card">
      <h3>⚠️ Access Denied</h3>
      <p>You don't have permission to access PCAP analysis functionality.</p>
    </div>
  {:else}
    <div class="content-section">
      <!-- File Upload Section -->
      <div class="upload-section">
        <div class="upload-card">
          <h2 class="upload-title">Upload PCAP File</h2>
          
          <div 
            class="upload-area" 
            class:drag-over={dragOver}
            role="button"
            tabindex="0"
            on:keydown={(e) => { if (e.key === 'Enter' || e.key === ' ') fileInput?.click(); }}
            on:drop={handleDrop}
            on:dragover={handleDragOver}
            on:dragleave={handleDragLeave}
            aria-label="Drop PCAP file here or click to browse"
            on:click={() => fileInput?.click()}
          >
            <div class="upload-content">
              {#if selectedFile}
                <div class="selected-file">
                  <div class="file-icon">📄</div>
                  <div class="file-info">
                    <div class="file-name">{selectedFile.name}</div>
                    <div class="file-size">{formatFileSize(selectedFile.size)}</div>
                  </div>
                  <button class="clear-file-btn" on:click|stopPropagation={clearFile}>✕</button>
                </div>
              {:else}
                <div class="upload-placeholder">
                  <div class="upload-icon">📁</div>
                  <h3>Drop PCAP file here or click to browse</h3>
                  <p>Supported formats: .pcap, .pcapng, .cap</p>
                  <p>Maximum file size: 100MB</p>
                </div>
              {/if}
            </div>
            
            <input 
              bind:this={fileInput}
              type="file" 
              accept=".pcap,.pcapng,.cap"
              on:change={handleFileSelect}
              style="display: none;"
            />
            
            {#if !selectedFile}
              <button class="browse-btn" on:click|stopPropagation={() => fileInput.click()}>
                Browse Files
              </button>
            {/if}
          </div>

          {#if $uploading}
            <div class="progress-section">
              <div class="progress-info">
                <span>Uploading and analyzing...</span>
                <span>{$uploadProgress}%</span>
              </div>
              <div class="progress-bar">
                <div class="progress-fill" style="width: {$uploadProgress}%"></div>
              </div>
            </div>
          {/if}

          <div class="upload-actions">
            <button 
              class="upload-btn"
              on:click={uploadFile}
              disabled={!selectedFile || $uploading}
            >
              {#if $uploading}
                <span class="spinner"></span>
                Analyzing...
              {:else}
                🔍 Analyze PCAP File
              {/if}
            </button>
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

      <!-- Analysis History Section -->
      <div class="history-section">
        <div class="history-card">
          <div class="history-header">
            <h2 class="history-title">Analysis History</h2>
            <button class="refresh-btn" on:click={() => { currentPage = 0; loadAnalyses(); }}>
              🔄 Refresh
            </button>
          </div>

          {#if $loading && $analyses.length === 0}
            <div class="loading-state">
              <div class="loading-spinner"></div>
              <p>Loading analysis history...</p>
            </div>
          {:else if $analyses.length === 0}
            <div class="empty-state">
              <div class="empty-icon">📊</div>
              <h3>No Analyses Yet</h3>
              <p>Upload your first PCAP file to see analysis results here.</p>
            </div>
          {:else}
            <div class="analyses-list">
              {#each $analyses as analysis}
                <div class="analysis-item">
                  <div class="analysis-info">
                    <div class="analysis-name">{analysis.filename}</div>
                    <div class="analysis-meta">
                      <span>{formatTimestamp(analysis.analysis_timestamp)}</span>
                      <span>•</span>
                      <span>{analysis.total_packets?.toLocaleString() || 0} packets</span>
                      <span>•</span>
                      <span>{formatFileSize(analysis.file_size || 0)}</span>
                    </div>
                  </div>
                  
                  <div class="analysis-status">
                    <div class="risk-badge {getRiskColor(analysis.threat_analysis?.risk_assessment)}">
                      {analysis.threat_analysis?.risk_assessment || 'Unknown'}
                    </div>
                    <div class="threat-count">
                      {analysis.threat_analysis?.total_threats || 0} threats
                    </div>
                  </div>
                  
                  <div class="analysis-actions">
                    <button 
                      class="action-btn view-btn"
                      on:click={() => viewAnalysisDetails(analysis._id)}
                    >
                      👁️ View
                    </button>
                    <button 
                      class="action-btn report-btn"
                      on:click={() => viewReport(analysis._id)}
                    >
                      📋 Report
                    </button>
                  </div>
                </div>
              {/each}
            </div>

            {#if hasMore}
              <div class="load-more-section">
                <button 
                  class="load-more-btn"
                  on:click={loadMoreAnalyses}
                  disabled={$loading}
                >
                  {#if $loading}
                    <span class="spinner"></span>
                    Loading...
                  {:else}
                    Load More
                  {/if}
                </button>
              </div>
            {/if}
          {/if}
        </div>
      </div>
    </div>
  {/if}

  <!-- Analysis Details Modal -->
  {#if showAnalysisDetails && $selectedAnalysis}
    <div class="modal-overlay" on:click={closeAnalysisDetails}>
      <div class="modal-content analysis-modal" on:click|stopPropagation>
        <div class="modal-header">
          <h3>📊 Analysis Details: {$selectedAnalysis.filename}</h3>
          <button class="close-btn" on:click={closeAnalysisDetails}>✕</button>
        </div>
        
        <div class="modal-body">
          <div class="details-grid">
            <div class="detail-section">
              <h4>File Information</h4>
              <div class="detail-item">
                <span class="label">Filename:</span>
                <span class="value">{$selectedAnalysis.filename}</span>
              </div>
              <div class="detail-item">
                <span class="label">File Size:</span>
                <span class="value">{formatFileSize($selectedAnalysis.file_size)}</span>
              </div>
              <div class="detail-item">
                <span class="label">Total Packets:</span>
                <span class="value">{$selectedAnalysis.total_packets?.toLocaleString()}</span>
              </div>
              <div class="detail-item">
                <span class="label">Analysis Time:</span>
                <span class="value">{formatTimestamp($selectedAnalysis.analysis_timestamp)}</span>
              </div>
            </div>

            <div class="detail-section">
              <h4>Threat Assessment</h4>
              <div class="detail-item">
                <span class="label">Risk Level:</span>
                <span class="value risk-badge {getRiskColor($selectedAnalysis.threat_analysis?.risk_assessment)}">
                  {$selectedAnalysis.threat_analysis?.risk_assessment || 'Unknown'}
                </span>
              </div>
              <div class="detail-item">
                <span class="label">Total Threats:</span>
                <span class="value">{$selectedAnalysis.threat_analysis?.total_threats || 0}</span>
              </div>
              <div class="detail-item">
                <span class="label">Threat Rate:</span>
                <span class="value">{$selectedAnalysis.summary_statistics?.detection_summary?.threat_percentage || 0}%</span>
              </div>
            </div>

            <div class="detail-section">
              <h4>Protocol Distribution</h4>
              {#each Object.entries($selectedAnalysis.summary_statistics?.protocol_distribution || {}) as [protocol, count]}
                <div class="detail-item">
                  <span class="label">{protocol}:</span>
                  <span class="value">{count.toLocaleString()} packets</span>
                </div>
              {/each}
            </div>

            <div class="detail-section">
              <h4>Top Targeted Ports</h4>
              {#each Object.entries($selectedAnalysis.summary_statistics?.top_ports || {}).slice(0, 5) as [port, count]}
                <div class="detail-item">
                  <span class="label">Port {port}:</span>
                  <span class="value">{count} connections</span>
                </div>
              {/each}
            </div>
          </div>
        </div>
        
        <div class="modal-footer">
          <button class="btn secondary" on:click={closeAnalysisDetails}>Close</button>
          <button class="btn primary" on:click={() => viewReport($selectedAnalysis._id)}>
            📋 View Full Report
          </button>
        </div>
      </div>
    </div>
  {/if}

  <!-- Report Modal -->
  {#if showReportModal && $selectedReport}
    <div class="modal-overlay" on:click={closeReportModal}>
      <div class="modal-content report-modal" on:click|stopPropagation>
        <div class="modal-header">
          <h3>📋 Analysis Report: {$selectedReport.filename}</h3>
          <button class="close-btn" on:click={closeReportModal}>✕</button>
        </div>
        
        <div class="modal-body">
          <div class="report-content">
            <div class="report-section">
              <h4>Executive Summary</h4>
              <div class="summary-stats">
                <div class="stat-card">
                  <div class="stat-value">{$selectedReport.total_packets?.toLocaleString()}</div>
                  <div class="stat-label">Total Packets</div>
                </div>
                <div class="stat-card">
                  <div class="stat-value">{$selectedReport.threat_analysis?.total_threats || 0}</div>
                  <div class="stat-label">Threats Detected</div>
                </div>
                <div class="stat-card risk-{getRiskColor($selectedReport.threat_analysis?.risk_assessment)}">
                  <div class="stat-value">{$selectedReport.threat_analysis?.risk_assessment || 'Unknown'}</div>
                  <div class="stat-label">Risk Level</div>
                </div>
                <div class="stat-card">
                  <div class="stat-value">{$selectedReport.summary_statistics?.detection_summary?.threat_percentage || 0}%</div>
                  <div class="stat-label">Threat Rate</div>
                </div>
              </div>
            </div>

            {#if $selectedReport.threat_analysis?.threat_types && Object.keys($selectedReport.threat_analysis.threat_types).length > 0}
              <div class="report-section">
                <h4>Threat Types Detected</h4>
                <div class="threat-types">
                  {#each Object.entries($selectedReport.threat_analysis.threat_types) as [type, count]}
                    <div class="threat-type-item">
                      <span class="threat-type">{type}</span>
                      <span class="threat-count">{count} instances</span>
                    </div>
                  {/each}
                </div>
              </div>
            {/if}

            {#if $selectedReport.threat_analysis?.high_risk_packets && $selectedReport.threat_analysis.high_risk_packets.length > 0}
              <div class="report-section">
                <h4>High-Risk Packets</h4>
                <div class="high-risk-packets">
                  {#each $selectedReport.threat_analysis.high_risk_packets.slice(0, 10) as packet}
                    <div class="risk-packet-item">
                      <div class="packet-info">
                        <span class="packet-index">Packet #{packet.packet_index}</span>
                        <span class="confidence">Confidence: {packet.confidence.toFixed(2)}</span>
                      </div>
                      <div class="packet-details">
                        {#if packet.src_ip}<span>From: {packet.src_ip}</span>{/if}
                        {#if packet.dst_ip}<span>To: {packet.dst_ip}</span>{/if}
                        {#if packet.dst_port}<span>Port: {packet.dst_port}</span>{/if}
                      </div>
                      <div class="packet-threats">
                        {packet.threat_types.join(', ')}
                      </div>
                    </div>
                  {/each}
                </div>
              </div>
            {/if}

            <div class="report-section">
              <h4>Technical Summary</h4>
              <div class="technical-details">
                <div class="tech-item">
                  <span class="tech-label">File Hash:</span>
                  <span class="tech-value hash">{$selectedReport.file_hash}</span>
                </div>
                <div class="tech-item">
                  <span class="tech-label">Analysis Method:</span>
                  <span class="tech-value">77-feature network packet analysis</span>
                </div>
                <div class="tech-item">
                  <span class="tech-label">Models Used:</span>
                  <span class="tech-value">{Object.keys($selectedReport.threat_analysis?.threat_models || {}).join(', ') || 'Multiple ML models'}</span>
                </div>
              </div>
            </div>
          </div>
        </div>
        
        <div class="modal-footer">
          <button class="btn secondary" on:click={closeReportModal}>Close</button>
          <div class="export-buttons">
            <button class="btn secondary" on:click={() => exportReport('pdf')}>
              📄 PDF
            </button>
            <button class="btn secondary" on:click={() => exportReport('json')}>
              📊 JSON
            </button>
            <button class="btn secondary" on:click={() => exportReport('csv')}>
              📋 CSV
            </button>
          </div>
        </div>
      </div>
    </div>
  {/if}
</div>

<style>
  .pcap-analyzer-container {
    padding: 1rem 0.75rem;
    max-width: 100%;
    margin: 0;
    min-height: 100vh;
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
    display: grid;
    grid-template-columns: 1.2fr 1fr;
    gap: 1rem;
  }

  /* Upload Section */
  .upload-section {
    width: 100%;
  }

  .upload-card {
    background: white;
    border-radius: 12px;
    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
    border: 1px solid #e5e7eb;
    padding: 2rem;
  }

  .upload-title {
    font-size: 1.5rem;
    font-weight: 600;
    margin: 0 0 1.5rem 0;
    color: #1f2937;
  }

  .upload-area {
    border: 2px dashed #d1d5db;
    border-radius: 8px;
    padding: 2rem;
    text-align: center;
    transition: all 0.2s ease;
    position: relative;
    min-height: 200px;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
  }

  .upload-area.drag-over {
    border-color: #3b82f6;
    background-color: #eff6ff;
  }

  .upload-content {
    width: 100%;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 1rem;
  }

  .upload-placeholder {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 1rem;
  }

  .upload-icon {
    font-size: 3rem;
  }

  .upload-placeholder h3 {
    margin: 0;
    color: #374151;
    font-size: 1.25rem;
  }

  .upload-placeholder p {
    margin: 0;
    color: #6b7280;
    font-size: 0.875rem;
  }

  .selected-file {
    display: flex;
    align-items: center;
    gap: 1rem;
    padding: 1rem;
    background: #f9fafb;
    border-radius: 8px;
    border: 1px solid #e5e7eb;
    width: 100%;
    max-width: 400px;
  }

  .file-icon {
    font-size: 2rem;
  }

  .file-info {
    flex: 1;
    text-align: left;
  }

  .file-name {
    font-weight: 600;
    color: #1f2937;
    word-break: break-all;
  }

  .file-size {
    color: #6b7280;
    font-size: 0.875rem;
  }

  .clear-file-btn {
    background: #ef4444;
    color: white;
    border: none;
    border-radius: 50%;
    width: 24px;
    height: 24px;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 0.75rem;
  }

  .clear-file-btn:hover {
    background: #dc2626;
  }

  .browse-btn {
    margin-top: 1rem;
    background: #3b82f6;
    color: white;
    border: none;
    padding: 0.75rem 1.5rem;
    border-radius: 6px;
    cursor: pointer;
    font-weight: 500;
  }

  .browse-btn:hover {
    background: #2563eb;
  }

  .progress-section {
    margin-top: 1.5rem;
  }

  .progress-info {
    display: flex;
    justify-content: space-between;
    margin-bottom: 0.5rem;
    font-size: 0.875rem;
    color: #374151;
  }

  .progress-bar {
    width: 100%;
    height: 8px;
    background: #e5e7eb;
    border-radius: 4px;
    overflow: hidden;
  }

  .progress-fill {
    height: 100%;
    background: #3b82f6;
    transition: width 0.2s ease;
  }

  .upload-actions {
    margin-top: 1.5rem;
    text-align: center;
  }

  .upload-btn {
    background: #10b981;
    color: white;
    border: none;
    padding: 0.875rem 2rem;
    border-radius: 8px;
    font-size: 1rem;
    font-weight: 600;
    cursor: pointer;
    transition: background-color 0.2s ease;
    display: flex;
    align-items: center;
    gap: 0.5rem;
    margin: 0 auto;
  }

  .upload-btn:hover:not(:disabled) {
    background: #059669;
  }

  .upload-btn:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  /* History Section */
  .history-card {
    background: white;
    border-radius: 12px;
    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
    border: 1px solid #e5e7eb;
    overflow: hidden;
  }

  .history-header {
    padding: 1.5rem 2rem;
    background: #f9fafb;
    border-bottom: 1px solid #e5e7eb;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }

  .history-title {
    font-size: 1.25rem;
    font-weight: 600;
    margin: 0;
    color: #1f2937;
  }

  .refresh-btn {
    background: #6b7280;
    color: white;
    border: none;
    padding: 0.5rem 1rem;
    border-radius: 6px;
    font-size: 0.875rem;
    cursor: pointer;
    transition: background-color 0.2s ease;
  }

  .refresh-btn:hover {
    background: #4b5563;
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

  .analyses-list {
    padding: 1rem;
  }

  .analysis-item {
    display: flex;
    align-items: center;
    gap: 1rem;
    padding: 1rem;
    border-bottom: 1px solid #f3f4f6;
    transition: background-color 0.2s ease;
  }

  .analysis-item:hover {
    background: #f9fafb;
  }

  .analysis-item:last-child {
    border-bottom: none;
  }

  .analysis-info {
    flex: 1;
  }

  .analysis-name {
    font-weight: 600;
    color: #1f2937;
    margin-bottom: 0.25rem;
  }

  .analysis-meta {
    font-size: 0.875rem;
    color: #6b7280;
    display: flex;
    gap: 0.5rem;
  }

  .analysis-status {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 0.25rem;
  }

  .risk-badge {
    padding: 0.25rem 0.75rem;
    border-radius: 12px;
    font-size: 0.75rem;
    font-weight: 600;
    white-space: nowrap;
  }

  .risk-critical { background: #fee2e2; color: #991b1b; }
  .risk-high { background: #fef3c7; color: #92400e; }
  .risk-medium { background: #fef3c7; color: #d97706; }
  .risk-low { background: #dcfce7; color: #166534; }
  .risk-minimal { background: #e0e7ff; color: #3730a3; }
  .risk-unknown { background: #f3f4f6; color: #6b7280; }

  .threat-count {
    font-size: 0.75rem;
    color: #6b7280;
  }

  .analysis-actions {
    display: flex;
    gap: 0.5rem;
  }

  .action-btn {
    border: none;
    padding: 0.5rem 1rem;
    border-radius: 6px;
    font-size: 0.75rem;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.2s ease;
  }

  .view-btn {
    background: #e0e7ff;
    color: #3730a3;
  }

  .view-btn:hover {
    background: #c7d2fe;
  }

  .report-btn {
    background: #dcfce7;
    color: #166534;
  }

  .report-btn:hover {
    background: #bbf7d0;
  }

  .load-more-section {
    padding: 1rem;
    text-align: center;
    border-top: 1px solid #e5e7eb;
  }

  .load-more-btn {
    background: #f3f4f6;
    color: #374151;
    border: none;
    padding: 0.75rem 1.5rem;
    border-radius: 6px;
    cursor: pointer;
    transition: background-color 0.2s ease;
    display: flex;
    align-items: center;
    gap: 0.5rem;
    margin: 0 auto;
  }

  .load-more-btn:hover:not(:disabled) {
    background: #e5e7eb;
  }

  .load-more-btn:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  /* Modal Styles */
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
  }

  .modal-content {
    background: white;
    border-radius: 12px;
    box-shadow: 0 25px 50px rgba(0, 0, 0, 0.25);
    max-width: 800px;
    width: 100%;
    max-height: 90vh;
    overflow-y: auto;
    animation: modalSlideIn 0.2s ease;
  }

  .modal-header {
    padding: 1.5rem 2rem;
    border-bottom: 1px solid #e5e7eb;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }

  .modal-header h3 {
    margin: 0;
    color: #1f2937;
    font-size: 1.25rem;
  }

  .close-btn {
    background: none;
    border: none;
    font-size: 1.5rem;
    cursor: pointer;
    color: #6b7280;
    padding: 0.25rem;
  }

  .close-btn:hover {
    color: #374151;
  }

  .modal-body {
    padding: 2rem;
  }

  .modal-footer {
    padding: 1rem 2rem;
    border-top: 1px solid #e5e7eb;
    display: flex;
    gap: 1rem;
    justify-content: flex-end;
  }

  .export-buttons {
    display: flex;
    gap: 0.5rem;
  }

  .export-buttons .btn {
    padding: 0.5rem 1rem;
    font-size: 0.875rem;
    min-width: 80px;
  }

  .btn {
    border: none;
    padding: 0.75rem 1.5rem;
    border-radius: 6px;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.2s ease;
  }

  .btn.secondary {
    background: #f3f4f6;
    color: #374151;
  }

  .btn.secondary:hover {
    background: #e5e7eb;
  }

  .btn.primary {
    background: #3b82f6;
    color: white;
  }

  .btn.primary:hover {
    background: #2563eb;
  }

  /* Analysis Details */
  .details-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 2rem;
  }

  .detail-section {
    background: #f9fafb;
    padding: 1.5rem;
    border-radius: 8px;
    border: 1px solid #e5e7eb;
  }

  .detail-section h4 {
    margin: 0 0 1rem 0;
    color: #1f2937;
    font-size: 1.125rem;
  }

  .detail-item {
    display: flex;
    justify-content: space-between;
    margin-bottom: 0.75rem;
    font-size: 0.875rem;
  }

  .detail-item:last-child {
    margin-bottom: 0;
  }

  .label {
    font-weight: 600;
    color: #374151;
  }

  .value {
    color: #1f2937;
    text-align: right;
  }

  /* Report Content */
  .report-content {
    display: flex;
    flex-direction: column;
    gap: 2rem;
  }

  .report-section h4 {
    margin: 0 0 1rem 0;
    color: #1f2937;
    font-size: 1.125rem;
    border-bottom: 2px solid #e5e7eb;
    padding-bottom: 0.5rem;
  }

  .summary-stats {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 1rem;
    margin-bottom: 1rem;
  }

  .stat-card {
    background: #f9fafb;
    padding: 1rem;
    border-radius: 8px;
    text-align: center;
    border: 1px solid #e5e7eb;
  }

  .stat-value {
    font-size: 1.5rem;
    font-weight: bold;
    color: #1f2937;
  }

  .stat-label {
    font-size: 0.875rem;
    color: #6b7280;
    margin-top: 0.25rem;
  }

  .threat-types {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .threat-type-item {
    display: flex;
    justify-content: space-between;
    padding: 0.75rem;
    background: #fee2e2;
    border-radius: 6px;
    border: 1px solid #fecaca;
  }

  .threat-type {
    font-weight: 600;
    color: #991b1b;
  }

  .threat-count {
    color: #dc2626;
  }

  .high-risk-packets {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }

  .risk-packet-item {
    padding: 1rem;
    background: #fef2f2;
    border-radius: 6px;
    border: 1px solid #fecaca;
  }

  .packet-info {
    display: flex;
    justify-content: space-between;
    margin-bottom: 0.5rem;
    font-weight: 600;
    color: #991b1b;
  }

  .packet-details {
    display: flex;
    gap: 1rem;
    margin-bottom: 0.5rem;
    font-size: 0.875rem;
    color: #6b7280;
  }

  .packet-threats {
    font-size: 0.875rem;
    color: #dc2626;
    font-style: italic;
  }

  .technical-details {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }

  .tech-item {
    display: flex;
    gap: 1rem;
  }

  .tech-label {
    font-weight: 600;
    color: #374151;
    min-width: 120px;
  }

  .tech-value {
    color: #1f2937;
    flex: 1;
  }

  .tech-value.hash {
    font-family: 'Monaco', 'Consolas', 'Courier New', monospace;
    font-size: 0.75rem;
    word-break: break-all;
  }

  /* Messages */
  .error-message, .success-message {
    padding: 1rem;
    border-radius: 8px;
    margin-bottom: 1rem;
    display: flex;
    align-items: center;
    gap: 0.75rem;
  }

  .error-message {
    background: #fee2e2;
    color: #991b1b;
    border: 1px solid #fecaca;
  }

  .success-message {
    background: #dcfce7;
    color: #166534;
    border: 1px solid #bbf7d0;
  }

  .error-card {
    background: white;
    border-radius: 12px;
    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
    border: 1px solid #fecaca;
    border-left: 4px solid #ef4444;
    padding: 2rem;
    text-align: center;
  }

  .error-card h3 {
    margin: 0 0 1rem 0;
    color: #991b1b;
  }

  .error-card p {
    margin: 0;
    color: #dc2626;
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
    .pcap-analyzer-container {
      padding: 0.75rem;
    }

    .content-section {
      display: flex;
      flex-direction: column;
      gap: 1rem;
    }

    .page-title {
      font-size: 2rem;
    }

    .upload-card {
      padding: 1.5rem;
    }

    .upload-area {
      padding: 1.5rem;
      min-height: 150px;
    }

    .analysis-item {
      flex-direction: column;
      align-items: flex-start;
      gap: 0.75rem;
    }

    .analysis-status {
      flex-direction: row;
      align-items: center;
      gap: 1rem;
    }

    .modal-content {
      margin: 0.5rem;
      max-height: 95vh;
    }

    .modal-header, .modal-body, .modal-footer {
      padding: 1rem;
    }

    .details-grid {
      grid-template-columns: 1fr;
      gap: 1rem;
    }

    .summary-stats {
      grid-template-columns: repeat(2, 1fr);
    }
  }

  @media (max-width: 480px) {
    .summary-stats {
      grid-template-columns: 1fr;
    }

    .selected-file {
      flex-direction: column;
      text-align: center;
    }

    .packet-details {
      flex-direction: column;
      gap: 0.25rem;
    }

    .tech-item {
      flex-direction: column;
      gap: 0.25rem;
    }
  }
</style> 