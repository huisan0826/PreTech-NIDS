<script>
  import { writable } from 'svelte/store';
  import axios from 'axios';

  let inputFeatures = '';
  let selectedModel = 'kitsune';
  let result = writable(null);
  let error = writable(null);
  let loading = writable(false);

  const models = ['kitsune', 'autoencoder', 'lstm', 'cnn', 'rf'];

  async function sendPrediction() {
    error.set(null);
    result.set(null);
    loading.set(true);

    const features = inputFeatures
      .split(',')
      .map(f => parseFloat(f.trim()))
      .filter(f => !isNaN(f));

    try {
      const res = await axios.post('http://localhost:8000/predict', {
        features,
        model: selectedModel
      });
      result.set(res.data);

      // Save report to database
      await axios.post('http://localhost:8000/report', {
        model: selectedModel,
        input: features,
        output: res.data
      });

      scrollToResult();
    } catch (e) {
      error.set(e.response?.data?.error || 'Unexpected error');
    } finally {
      loading.set(false);
    }
  }

  function scrollToResult() {
    setTimeout(() => {
      const el = document.getElementById("result-block");
      if (el) el.scrollIntoView({ behavior: 'smooth' });
    }, 100);
  }

  $: resultText = $result ? JSON.stringify($result, null, 2) : '';
  $: isAttack = $result?.prediction === 1 || $result?.prediction === "Attack";
</script>

<div class="page-container">
  <div class="page-header">
    <h1 class="page-title">🧪 Manual Testing</h1>
    <p class="page-description">Test individual network traffic samples using trained models</p>
  </div>

  <div class="content-section">
    <div class="input-section">
      <div class="input-grid">
        <div class="input-group">
          <label class="label">
            Input Features (comma-separated):
            <textarea
              bind:value={inputFeatures}
              class="input textarea"
              placeholder="e.g. 0.1, 0.2, 0.3, ..., 0.77 (77 features total)&#10;Example: 1.2, 0.8, 2.1, 0.5, ..."
              rows="4"
            ></textarea>
          </label>
        </div>

        <div class="input-group">
          <label class="label">
            Select Detection Model:
            <select
              bind:value={selectedModel}
              class="select"
            >
              {#each models as model}
                <option value={model}>{model.toUpperCase()}</option>
              {/each}
            </select>
          </label>

          <button
            class="button primary-button"
            on:click={sendPrediction}
            disabled={$loading}
          >
            <span class="button-icon">
              {#if $loading}
                <span class="spinner"></span>
              {:else}
                🔍
              {/if}
            </span>
            {$loading ? 'Analyzing...' : 'Run Detection'}
          </button>
        </div>
      </div>
    </div>

    {#if $result}
      <div id="result-block" class="result-section">
        <div class={`result-card ${isAttack ? 'threat' : 'normal'}`}>
          <div class="result-header">
            <div class="result-title-section">
              <h2 class="result-title">
                {isAttack ? '🚨 Threat Detected!' : '✅ Normal Traffic'}
              </h2>
              <span class="result-badge {isAttack ? 'threat-badge' : 'normal-badge'}">
                {isAttack ? 'MALICIOUS' : 'BENIGN'}
              </span>
            </div>
            <div class="result-model">
              Model: <strong>{$result.model}</strong>
            </div>
          </div>
          <div class="result-content">
            <h3>Detection Results:</h3>
            <div class="result-data-container">
              <pre class="result-data">{resultText}</pre>
            </div>
          </div>
        </div>
      </div>
    {/if}

    {#if $error}
      <div class="error-section">
        <div class="error-card">
          <h3 class="error-title">⚠️ Detection Error</h3>
          <p class="error-message">{$error}</p>
        </div>
      </div>
    {/if}
  </div>
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
    text-align: center;
    margin-bottom: 2rem;
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
    line-height: 1.5;
  }

  .content-section {
    display: flex;
    flex-direction: column;
    gap: 2rem;
    width: 100%;
  }

  /* Input Section */
  .input-section {
    background: white;
    padding: 2rem;
    border-radius: 12px;
    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
    border: 1px solid #e5e7eb;
    width: 100%;
  }

  .input-grid {
    display: grid;
    grid-template-columns: 1fr;
    gap: 2rem;
    width: 100%;
  }

  .input-group {
    display: flex;
    flex-direction: column;
    gap: 1rem;
    width: 100%;
  }

  .label {
    display: block;
    font-weight: 600;
    color: #374151;
    font-size: 1rem;
    margin-bottom: 0.5rem;
  }

  .input, .select, .textarea {
    width: 100%;
    border: 2px solid #d1d5db;
    padding: 0.75rem;
    border-radius: 8px;
    background-color: white;
    color: #1f2937;
    font-size: 1rem;
    transition: border-color 0.2s ease;
    font-family: inherit;
  }

  .textarea {
    resize: vertical;
    min-height: 100px;
    font-family: 'Monaco', 'Consolas', 'Courier New', monospace;
    font-size: 0.875rem;
    line-height: 1.5;
  }

  .input:focus, .select:focus, .textarea:focus {
    outline: none;
    border-color: #3b82f6;
    box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
  }

  .button {
    background-color: #3b82f6;
    color: white;
    border: none;
    padding: 0.875rem 2rem;
    border-radius: 8px;
    font-weight: 600;
    cursor: pointer;
    font-size: 1rem;
    transition: all 0.2s ease;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.5rem;
    min-height: 48px;
    width: 100%;
  }

  .button:hover:not(:disabled) {
    background-color: #2563eb;
    transform: translateY(-1px);
    box-shadow: 0 4px 12px rgba(59, 130, 246, 0.3);
  }

  .button:disabled {
    opacity: 0.6;
    cursor: not-allowed;
    transform: none;
    box-shadow: none;
  }

  .button-icon {
    font-size: 1.1rem;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .spinner {
    width: 16px;
    height: 16px;
    border: 2px solid #ffffff40;
    border-left: 2px solid #ffffff;
    border-radius: 50%;
    animation: spin 1s linear infinite;
  }

  /* Result Section */
  .result-section {
    animation: slideIn 0.3s ease;
    width: 100%;
  }

  .result-card {
    background: white;
    border-radius: 12px;
    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
    overflow: hidden;
    border: 1px solid #e5e7eb;
    width: 100%;
  }

  .result-card.threat {
    border-left: 4px solid #ef4444;
  }

  .result-card.normal {
    border-left: 4px solid #10b981;
  }

  .result-header {
    padding: 1.5rem 2rem;
    background: #f9fafb;
    border-bottom: 1px solid #e5e7eb;
  }

  .result-title-section {
    display: flex;
    flex-wrap: wrap;
    justify-content: space-between;
    align-items: center;
    gap: 1rem;
    margin-bottom: 0.5rem;
  }

  .result-title {
    font-size: 1.5rem;
    font-weight: bold;
    margin: 0;
    color: #1f2937;
    flex: 1;
    min-width: 0;
  }

  .result-badge {
    padding: 0.5rem 1rem;
    border-radius: 20px;
    font-size: 0.875rem;
    font-weight: 600;
    white-space: nowrap;
    flex-shrink: 0;
  }

  .threat-badge {
    background-color: #fee2e2;
    color: #991b1b;
  }

  .normal-badge {
    background-color: #dcfce7;
    color: #166534;
  }

  .result-model {
    color: #6b7280;
    font-size: 0.875rem;
  }

  .result-content {
    padding: 2rem;
  }

  .result-content h3 {
    margin: 0 0 1rem 0;
    color: #374151;
    font-size: 1.25rem;
  }

  .result-data-container {
    background-color: #f8fafc;
    border-radius: 8px;
    border: 1px solid #e2e8f0;
    overflow: hidden;
  }

  .result-data {
    font-family: 'Monaco', 'Consolas', 'Courier New', monospace;
    font-size: 0.875rem;
    white-space: pre-wrap;
    word-wrap: break-word;
    color: #1e293b;
    padding: 1.5rem;
    margin: 0;
    overflow-x: auto;
    line-height: 1.6;
  }

  /* Error Section */
  .error-section {
    animation: slideIn 0.3s ease;
    width: 100%;
  }

  .error-card {
    background: white;
    border-radius: 12px;
    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
    border: 1px solid #fecaca;
    border-left: 4px solid #ef4444;
    padding: 2rem;
    width: 100%;
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
    line-height: 1.5;
    word-wrap: break-word;
  }

  @keyframes slideIn {
    from {
      opacity: 0;
      transform: translateY(20px);
    }
    to {
      opacity: 1;
      transform: translateY(0);
    }
  }

  @keyframes spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
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

    .input-grid {
      grid-template-columns: 2fr 1fr;
      gap: 3rem;
    }

    .input-section {
      padding: 3rem;
    }

    .result-header {
      padding: 2rem 3rem;
    }

    .result-content {
      padding: 3rem;
    }

    .result-title {
      font-size: 1.75rem;
    }

    .button {
      font-size: 1.125rem;
      padding: 1rem 2.5rem;
    }
  }

  /* Medium Desktop (992px to 1199px) */
  @media (min-width: 992px) and (max-width: 1199px) {
    .input-grid {
      grid-template-columns: 1fr 1fr;
      gap: 2rem;
    }

    .page-title {
      font-size: 2.75rem;
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

    .input-section {
      padding: 1.5rem;
    }

    .result-header {
      padding: 1.5rem;
    }

    .result-content {
      padding: 1.5rem;
    }

    .result-title-section {
      flex-direction: column;
      align-items: flex-start;
      gap: 0.75rem;
    }

    .result-title {
      font-size: 1.375rem;
    }

    .textarea {
      min-height: 80px;
    }
  }

  /* Mobile and Tablet Portrait (below 768px) */
  @media (max-width: 767px) {
    .page-container {
      padding: 1rem;
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
      gap: 1.5rem;
    }

    .input-section {
      padding: 1.25rem;
    }

    .input-group {
      gap: 0.75rem;
    }

    .result-header {
      padding: 1.25rem;
    }

    .result-content {
      padding: 1.25rem;
    }

    .result-title-section {
      flex-direction: column;
      align-items: flex-start;
      gap: 0.75rem;
    }

    .result-title {
      font-size: 1.25rem;
    }

    .result-badge {
      font-size: 0.75rem;
      padding: 0.375rem 0.75rem;
    }

    .textarea {
      min-height: 70px;
      font-size: 0.8rem;
    }

    .button {
      padding: 0.75rem 1.5rem;
      font-size: 0.95rem;
    }

    .error-card {
      padding: 1.25rem;
    }

    .result-data {
      font-size: 0.75rem;
      padding: 1rem;
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
      font-size: 0.9rem;
    }

    .input-section {
      padding: 1rem;
    }

    .result-header {
      padding: 1rem;
    }

    .result-content {
      padding: 1rem;
    }

    .result-title {
      font-size: 1.125rem;
    }

    .result-content h3 {
      font-size: 1.125rem;
    }

    .textarea {
      min-height: 60px;
      font-size: 0.75rem;
    }

    .button {
      padding: 0.625rem 1.25rem;
      font-size: 0.9rem;
    }

    .label {
      font-size: 0.9rem;
    }

    .input, .select {
      font-size: 0.9rem;
      padding: 0.625rem;
    }

    .result-data {
      font-size: 0.7rem;
      padding: 0.75rem;
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

    .input-section {
      padding: 4rem;
    }

    .result-header {
      padding: 3rem 4rem;
    }

    .result-content {
      padding: 4rem;
    }

    .result-title {
      font-size: 2rem;
    }

    .button {
      font-size: 1.25rem;
      padding: 1.25rem 3rem;
    }

    .input-grid {
      gap: 4rem;
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

    .result-card {
      border: 1px solid #000;
      box-shadow: none;
    }

    .page-title {
      color: #000;
    }
  }
</style>
