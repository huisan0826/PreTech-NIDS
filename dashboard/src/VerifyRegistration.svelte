<script>
  import { writable } from 'svelte/store';
  import { push } from 'svelte-spa-router';
  import axios from 'axios';

  let email = '';
  let otpCode = '';
  let loading = writable(false);
  let error = writable(null);
  let success = writable(null);

  import { onMount } from 'svelte';
  onMount(() => {
    const qs = new URLSearchParams(window.location.search);
    const e = qs.get('email');
    if (e) email = e;
  });

  async function handleVerify() {
    if (!email || !otpCode) {
      error.set('Please enter your email and the verification code');
      return;
    }

    // Soft client-side validation to avoid native pattern tooltip
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
      error.set('Please enter your email to resend the code');
      return;
    }
    try {
      loading.set(true);
      error.set(null);
      success.set(null);
      await axios.post('http://localhost:8000/auth/register/resend', { email });
      success.set('A new verification code has been sent (if the email is pending verification).');
    } catch (e) {
      error.set('Failed to resend code.');
    } finally {
      loading.set(false);
    }
  }
</script>

<div class="verify-container">
  <div class="verify-card">
    <div class="verify-header">
      <div class="logo">✉️</div>
      <h1 class="title">Verify Your Email</h1>
      <p class="subtitle">Enter the verification code sent to your email</p>
    </div>

    <form class="verify-form" on:submit|preventDefault={handleVerify}>
      <div class="form-group">
        <label for="email" class="form-label">Email Address</label>
        <input id="email" type="email" class="form-input" bind:value={email} placeholder="Enter your email" disabled={$loading} required />
      </div>

      <div class="form-group">
        <label for="otp" class="form-label">Verification Code</label>
        <input id="otp" type="text" class="form-input" bind:value={otpCode} placeholder="6-digit code" disabled={$loading} required inputmode="numeric" maxlength="6" autocomplete="one-time-code" />
      </div>

      {#if $error}
        <div class="error-message">⚠️ {$error}</div>
      {/if}
      {#if $success}
        <div class="success-message">✅ {$success}</div>
      {/if}

      <button type="submit" class="submit-button" disabled={$loading}>
        {#if $loading}
          <span class="spinner"></span>
          Verifying...
        {:else}
          ✅ Verify
        {/if}
      </button>

      <button type="button" class="link-button" on:click={resendCode} disabled={$loading}>Resend code</button>
    </form>
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
  .verify-header { text-align: center; margin-bottom: 2rem; }
  .logo { font-size: 3rem; margin-bottom: 1rem; }
  .title { font-size: 1.75rem; font-weight: bold; color: #1f2937; margin: 0 0 0.5rem 0; }
  .subtitle { color: #6b7280; margin: 0; font-size: 1rem; }
  .verify-form { display: flex; flex-direction: column; gap: 1.5rem; }
  .form-group { display: flex; flex-direction: column; gap: 0.5rem; }
  .form-label { font-weight: 600; color: #374151; font-size: 0.875rem; }
  .form-input { padding: 0.875rem; border: 2px solid #e5e7eb; border-radius: 8px; font-size: 1rem; transition: border-color 0.2s ease, box-shadow 0.2s ease; background-color: white; width: 100%; box-sizing: border-box; }
  .form-input:focus { outline: none; border-color: #3b82f6; box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1); }
  .error-message { background-color: #fee2e2; color: #991b1b; padding: 0.75rem; border-radius: 8px; font-size: 0.875rem; border: 1px solid #fecaca; }
  .success-message { background-color: #dcfce7; color: #166534; padding: 0.75rem; border-radius: 8px; font-size: 0.875rem; border: 1px solid #bbf7d0; }
  .submit-button { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border: none; padding: 1rem; border-radius: 8px; font-size: 1rem; font-weight: 600; cursor: pointer; transition: all 0.2s ease; display: flex; align-items: center; justify-content: center; gap: 0.5rem; min-height: 48px; width: 100%; box-sizing: border-box; }
  .submit-button:hover:not(:disabled) { transform: translateY(-1px); box-shadow: 0 8px 20px rgba(102, 126, 234, 0.3); }
  .submit-button:disabled { opacity: 0.6; cursor: not-allowed; transform: none; box-shadow: none; }
  .link-button { background: none; border: none; color: #3b82f6; text-decoration: underline; cursor: pointer; font-size: 0.875rem; padding: 0; font-family: inherit; }
  .link-button:hover { color: #2563eb; }
  .spinner { width: 16px; height: 16px; border: 2px solid #ffffff40; border-left: 2px solid #ffffff; border-radius: 50%; animation: spin 1s linear infinite; }
  @keyframes slideIn { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
  @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
</style>


