<script>
  import { writable } from 'svelte/store';
  import { push } from 'svelte-spa-router';
  import axios from 'axios';
  import { onMount } from 'svelte';

  let email = '';
  let otpCode = '';
  let loading = writable(false);
  let error = writable(null);
  let success = writable(null);

  onMount(() => {
    // Priority: Get email address from URL parameters (supports hash routing)
    let emailParam = null;
    
    // Try to get email from hash route query parameters
    if (window.location.hash && window.location.hash.includes('?')) {
      const hashQueryString = window.location.hash.split('?')[1];
      const urlParams = new URLSearchParams(hashQueryString);
      emailParam = urlParams.get('email');
    }
    
    // Fallback: Try to get from regular search parameters
    if (!emailParam) {
      const urlParams = new URLSearchParams(window.location.search);
      emailParam = urlParams.get('email');
    }
    
    console.log('Current URL:', window.location.href);
    console.log('URL hash:', window.location.hash);
    console.log('URL search params:', window.location.search);
    console.log('Email param from URL:', emailParam);
    
    if (emailParam) {
      email = emailParam;
      // Save to localStorage as backup
      localStorage.setItem('pendingVerificationEmail', email);
      console.log('✅ Email loaded from URL:', email);
    } else {
      // If not in URL, try to restore from localStorage
      const savedEmail = localStorage.getItem('pendingVerificationEmail');
      if (savedEmail) {
        email = savedEmail;
        console.log('✅ Email loaded from localStorage:', email);
      } else {
        console.log('❌ No email found in URL or localStorage');
        // If no email address, redirect to registration page
        setTimeout(() => {
          push('/register');
        }, 1000);
      }
    }
  });

  async function handleVerify() {
    if (!email || !otpCode) {
      error.set('Please enter the verification code');
      return;
    }

    // Verification code format check
    const code = String(otpCode || '').trim();
    if (!/^[0-9]{6}$/.test(code)) {
      error.set('Verification code must be 6 digits');
      return;
    }

    try {
      loading.set(true);
      error.set(null);
      success.set(null);

      const response = await axios.post('http://localhost:8000/auth/register/verify', {
        email,
        otp_code: code
      });

      success.set('Registration verified successfully! Redirecting to login...');
      
      // Clear email address from localStorage
      localStorage.removeItem('pendingVerificationEmail');

      setTimeout(() => {
        push('/login');
      }, 1200);
    } catch (e) {
      if (e.response?.status === 400) {
        error.set(e.response?.data?.detail || 'Invalid or expired verification code');
      } else {
        error.set('Verification failed. Please try again.');
      }
    } finally {
      loading.set(false);
    }
  }

  async function resendCode() {
    if (!email) {
      error.set('Email address not found');
      return;
    }
    try {
      loading.set(true);
      error.set(null);
      success.set(null);
      await axios.post('http://localhost:8000/auth/register/resend', { email });
      success.set('A new verification code has been sent to your email.');
    } catch (e) {
      error.set('Failed to resend code. Please try again.');
    } finally {
      loading.set(false);
    }
  }

  function goBackToLogin() {
    // Clear email address from localStorage
    localStorage.removeItem('pendingVerificationEmail');
    push('/login');
  }
</script>

<div class="verify-container">
  <div class="verify-card">
    <div class="verify-header">
      <div class="logo">🛡️</div>
      <h1 class="title">Email Verification</h1>
      <p class="subtitle">Check Your Email</p>
      <p class="instruction">We've sent a 6-digit verification code to</p>
      <div class="email-display">{email || 'Loading...'}</div>
    </div>

    <form class="verify-form" on:submit|preventDefault={handleVerify}>
      <div class="form-group">
        <label for="otp" class="form-label">Enter Verification Code</label>
        <input 
          id="otp" 
          type="text" 
          class="form-input" 
          bind:value={otpCode} 
          placeholder="0 0 0 0 0 0" 
          disabled={$loading} 
          required 
          inputmode="numeric" 
          maxlength="6" 
          autocomplete="one-time-code" 
        />
      </div>

      {#if $error}
        <div class="error-message">⚠️ {$error}</div>
      {/if}
      {#if $success}
        <div class="success-message">✅ {$success}</div>
      {/if}

      <button type="submit" class="verify-button" disabled={$loading}>
        {#if $loading}
          <span class="spinner"></span>
          Verifying...
        {:else}
          🔐 Verify Code
        {/if}
      </button>

      <div class="resend-section">
        <span>Didn't receive the code?</span>
        <button type="button" class="link-button" on:click={resendCode} disabled={$loading}>
          Resend Code
        </button>
      </div>

      <button type="button" class="back-button" on:click={goBackToLogin}>
        Back to Login
      </button>
    </form>

    <div class="note-box">
      <p><strong>Note:</strong> The verification code will expire in 10 minutes. If you don't see the email, please check your spam folder.</p>
    </div>
  </div>
</div>

<style>
  .verify-container {
    min-height: 100vh;
    width: 100%;
    display: flex;
    align-items: center;
    justify-content: center;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    padding: 1rem;
    box-sizing: border-box;
  }
  
  .verify-card {
    background: white;
    border-radius: 16px;
    box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
    padding: 3rem;
    width: 100%;
    max-width: 450px;
    animation: slideIn 0.3s ease;
    box-sizing: border-box;
  }
  
  .verify-header {
    text-align: center;
    margin-bottom: 2rem;
  }
  
  .logo {
    font-size: 3rem;
    margin-bottom: 1rem;
  }
  
  .title {
    font-size: 1.75rem;
    font-weight: bold;
    color: #1f2937;
    margin: 0 0 0.5rem 0;
  }
  
  .subtitle {
    font-size: 1.25rem;
    font-weight: 600;
    color: #374151;
    margin: 0 0 0.5rem 0;
  }
  
  .instruction {
    color: #6b7280;
    margin: 0 0 1rem 0;
    font-size: 1rem;
  }
  
  .email-display {
    font-weight: bold;
    color: #1f2937;
    font-size: 1.1rem;
    margin: 0 0 1.5rem 0;
    padding: 0.75rem;
    background: #f3f4f6;
    border-radius: 8px;
    border: 2px solid #e5e7eb;
    word-break: break-all;
  }
  
  .verify-form {
    display: flex;
    flex-direction: column;
    gap: 1.5rem;
  }
  
  .form-group {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }
  
  .form-label {
    font-weight: 600;
    color: #374151;
    font-size: 0.875rem;
  }
  
  .form-input {
    padding: 0.875rem;
    border: 2px solid #e5e7eb;
    border-radius: 8px;
    font-size: 1rem;
    transition: border-color 0.2s ease, box-shadow 0.2s ease;
    background-color: white;
    width: 100%;
    box-sizing: border-box;
    text-align: center;
    letter-spacing: 0.5rem;
    font-weight: 600;
  }
  
  .form-input:focus {
    outline: none;
    border-color: #3b82f6;
    box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
  }
  
  .form-input:disabled {
    background-color: #f9fafb;
    opacity: 0.6;
  }
  
  .error-message {
    background-color: #fee2e2;
    color: #991b1b;
    padding: 0.75rem;
    border-radius: 8px;
    font-size: 0.875rem;
    border: 1px solid #fecaca;
  }
  
  .success-message {
    background-color: #dcfce7;
    color: #166534;
    padding: 0.75rem;
    border-radius: 8px;
    font-size: 0.875rem;
    border: 1px solid #bbf7d0;
  }
  
  .verify-button {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    border: none;
    padding: 1rem;
    border-radius: 8px;
    font-size: 1rem;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.2s ease;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.5rem;
    min-height: 48px;
    width: 100%;
    box-sizing: border-box;
  }
  
  .verify-button:hover:not(:disabled) {
    transform: translateY(-1px);
    box-shadow: 0 8px 20px rgba(102, 126, 234, 0.3);
  }
  
  .verify-button:disabled {
    opacity: 0.6;
    cursor: not-allowed;
    transform: none;
    box-shadow: none;
  }
  
  .resend-section {
    text-align: center;
    color: #6b7280;
    font-size: 0.875rem;
  }
  
  .link-button {
    background: none;
    border: none;
    color: #3b82f6;
    text-decoration: underline;
    cursor: pointer;
    font-size: 0.875rem;
    padding: 0;
    font-family: inherit;
    margin-left: 0.25rem;
  }
  
  .link-button:hover {
    color: #2563eb;
  }
  
  .back-button {
    background: white;
    border: 1px solid #d1d5db;
    color: #374151;
    padding: 0.75rem;
    border-radius: 8px;
    font-size: 0.875rem;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.2s ease;
    width: 100%;
    box-sizing: border-box;
  }
  
  .back-button:hover {
    background: #f9fafb;
    border-color: #9ca3af;
  }
  
  .note-box {
    background: #eff6ff;
    border: 1px solid #bfdbfe;
    border-radius: 8px;
    padding: 1rem;
    margin-top: 1.5rem;
    font-size: 0.875rem;
    color: #1e40af;
    line-height: 1.4;
  }
  

  
  .spinner {
    width: 16px;
    height: 16px;
    border: 2px solid #ffffff40;
    border-left: 2px solid #ffffff;
    border-radius: 50%;
    animation: spin 1s linear infinite;
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
    0% {
      transform: rotate(0deg);
    }
    100% {
      transform: rotate(360deg);
    }
  }
</style>


