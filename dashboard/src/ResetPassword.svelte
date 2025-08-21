<script>
  import { writable } from 'svelte/store';
  import { push } from 'svelte-spa-router';
  import axios from 'axios';
  import { onMount } from 'svelte';

  // Form state (OTP flow)
  let email = '';
  let otpCode = '';
  let newPassword = '';
  let confirmPassword = '';
  let showNewPassword = false;
  let showConfirmPassword = false;
  let loading = writable(false);
  let error = writable(null);
  let success = writable(null);

  // Password requirements checklist for new password
  // English-only labels per requirement
  $: rp_len = newPassword.length >= 8;
  $: rp_upper = /[A-Z]/.test(newPassword);
  $: rp_lower = /[a-z]/.test(newPassword);
  $: rp_digit = /[0-9]/.test(newPassword);
  $: rp_special = /[!@#$%^&*()_+\-=[\]{};':"\\|,.<>\/?`~]/.test(newPassword);

  // Optional: prefill email from query param
  onMount(() => {
    const urlParams = new URLSearchParams(window.location.search);
    email = urlParams.get('email') || '';
  });

  // Reset password
  async function handleResetPassword() {
    if (!email || !otpCode || !newPassword || !confirmPassword) {
      error.set('Please fill in all password fields');
      return;
    }

    // Script-side OTP validation to avoid native pattern tooltip
    const code = String(otpCode || '').trim();
    if (!/^[0-9]{6}$/.test(code)) {
      error.set('Verification code must be 6 digits');
      return;
    }

    if (newPassword !== confirmPassword) {
      error.set('New password and confirm password do not match');
      return;
    }

    // Strong password (same as backend)
    if (newPassword.length < 8) {
      error.set('New password must be at least 8 characters long');
      return;
    }
    if (!/[A-Z]/.test(newPassword)) {
      error.set('New password must include at least one uppercase letter');
      return;
    }
    if (!/[a-z]/.test(newPassword)) {
      error.set('New password must include at least one lowercase letter');
      return;
    }
    if (!/[0-9]/.test(newPassword)) {
      error.set('New password must include at least one number');
      return;
    }
    if (!/[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?`~]/.test(newPassword)) {
      error.set('New password must include at least one special character');
      return;
    }

    try {
      loading.set(true);
      error.set(null);
      success.set(null);

      const response = await axios.post('http://localhost:8000/auth/password-reset/verify-otp', {
        email,
        otp_code: code,
        new_password: newPassword,
        confirm_password: confirmPassword
      });

      success.set('Password reset successful! Redirecting to login page...');
      
      // Clear form
      newPassword = '';
      confirmPassword = '';

      // Redirect to login after 2 seconds
      setTimeout(() => {
        push('/login');
      }, 2000);

    } catch (e) {
      console.error('Reset password error:', e);
      if (e.response?.status === 400) {
        error.set(e.response.data?.detail || 'Invalid request data');
      } else if (e.response?.status === 404) {
        error.set('Email address is not registered');
      } else {
        error.set('Password reset failed, please try again later');
      }
    } finally {
      loading.set(false);
    }
  }

  function goToLogin() {
    push('/login');
  }

  function handleKeyPress(event) {
    if (event.key === 'Enter') {
      handleResetPassword();
    }
  }
</script>

<div class="reset-password-container">
  <div class="reset-password-card">
    <div class="reset-password-header">
      <div class="logo">🔑</div>
      <h1 class="title">Reset Password</h1>
      <p class="subtitle">Please enter your new password</p>
    </div>

      <form class="reset-password-form" on:submit|preventDefault={handleResetPassword}>
        <div class="form-group">
          <label for="email" class="form-label">Email Address</label>
          <input
            id="email"
            type="email"
            class="form-input"
            bind:value={email}
            placeholder="Enter your email"
            disabled={$loading}
            required
          />
        </div>

        <div class="form-group">
          <label for="otp" class="form-label">Verification Code</label>
          <input
            id="otp"
            type="text"
            class="form-input"
            bind:value={otpCode}
            placeholder="Enter the 6-digit code"
            disabled={$loading}
            required
            maxlength="6"
            inputmode="numeric"
            autocomplete="one-time-code"
          />
          <div class="form-hint">Check your email for the one-time code</div>
        </div>
        <div class="form-group">
          <label for="new-password" class="form-label">New Password</label>
          <div class="password-input-wrapper">
          <input
            id="new-password"
            type={showNewPassword ? 'text' : 'password'}
            class="form-input"
            bind:value={newPassword}
            on:keypress={handleKeyPress}
            placeholder="Enter new password"
            disabled={$loading}
            required
            minlength="8"
          />
          <button type="button" class="toggle-password" on:click={() => showNewPassword = !showNewPassword} aria-label={showNewPassword ? 'Hide password' : 'Show password'}>
            {showNewPassword ? '🙈' : '👁️'}
          </button>
          </div>
          <div class="form-hint">Password must satisfy all requirements below:</div>
          <ul class="password-reqs">
            <li class={rp_len ? 'ok' : ''}>At least 8 characters</li>
            <li class={rp_upper ? 'ok' : ''}>At least 1 uppercase letter (A-Z)</li>
            <li class={rp_lower ? 'ok' : ''}>At least 1 lowercase letter (a-z)</li>
            <li class={rp_digit ? 'ok' : ''}>At least 1 number (0-9)</li>
            <li class={rp_special ? 'ok' : ''}>At least 1 special character (!@#$%^&* etc.)</li>
          </ul>
        </div>

        <div class="form-group">
          <label for="confirm-password" class="form-label">Confirm New Password</label>
          <div class="password-input-wrapper">
          <input
            id="confirm-password"
            type={showConfirmPassword ? 'text' : 'password'}
            class="form-input"
            bind:value={confirmPassword}
            on:keypress={handleKeyPress}
            placeholder="Enter new password again"
            disabled={$loading}
            required
            minlength="8"
          />
          <button type="button" class="toggle-password" on:click={() => showConfirmPassword = !showConfirmPassword} aria-label={showConfirmPassword ? 'Hide password' : 'Show password'}>
            {showConfirmPassword ? '🙈' : '👁️'}
          </button>
          </div>
        </div>

        {#if $error}
          <div class="error-message">
            ⚠️ {$error}
          </div>
        {/if}

        {#if $success}
          <div class="success-message">
            ✅ {$success}
          </div>
        {/if}

        <button 
          type="submit" 
          class="submit-button"
          disabled={$loading}
        >
          {#if $loading}
            <span class="spinner"></span>
            Resetting...
          {:else}
            🔑 Reset Password
          {/if}
        </button>
      </form>

      <div class="reset-password-footer">
        <p class="back-to-login">
          Remember your password? 
          <button class="link-button" on:click={goToLogin}>
            Back to Login
          </button>
        </p>
      </div>
  </div>
</div>

<style>
  .reset-password-container {
    min-height: 100vh;
    width: 100%;
    display: flex;
    align-items: center;
    justify-content: center;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    padding: 1rem;
    box-sizing: border-box;
  }

  .reset-password-card {
    background: white;
    border-radius: 16px;
    box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
    padding: 3rem;
    width: 100%;
    max-width: 450px;
    animation: slideIn 0.3s ease;
    box-sizing: border-box;
  }

  .reset-password-header {
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
    color: #6b7280;
    margin: 0;
    font-size: 1rem;
  }

  .reset-password-form {
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

  .password-input-wrapper { position: relative; }
  .password-input-wrapper .toggle-password {
    position: absolute;
    right: 10px;
    top: 50%;
    transform: translateY(-50%);
    background: none;
    border: none;
    cursor: pointer;
    font-size: 1rem;
  }

  .form-hint {
    font-size: 0.8rem;
    color: #6b7280;
    margin-top: 0.25rem;
  }
  .password-reqs {
    margin: 0.25rem 0 0;
    padding-left: 1.25rem;
    color: #6b7280;
    font-size: 0.8rem;
    list-style: disc;
    list-style-position: outside;
  }
  .password-reqs li { margin: 0.125rem 0; }
  .password-reqs li.ok { color: #059669; }

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

  .submit-button {
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

  .submit-button:hover:not(:disabled) {
    transform: translateY(-1px);
    box-shadow: 0 8px 20px rgba(102, 126, 234, 0.3);
  }

  .submit-button:disabled {
    opacity: 0.6;
    cursor: not-allowed;
    transform: none;
    box-shadow: none;
  }

  .spinner {
    width: 16px;
    height: 16px;
    border: 2px solid #ffffff40;
    border-left: 2px solid #ffffff;
    border-radius: 50%;
    animation: spin 1s linear infinite;
  }

  .reset-password-footer {
    margin-top: 2rem;
    text-align: center;
  }

  .back-to-login {
    color: #6b7280;
    font-size: 0.875rem;
    margin: 0;
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
  }

  .link-button:hover {
    color: #2563eb;
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
  @media (max-width: 767px) {
    .reset-password-container {
      padding: 1rem;
    }

    .reset-password-card {
      max-width: 400px;
      padding: 2rem;
    }

    .title {
      font-size: 1.5rem;
    }

    .logo {
      font-size: 2.5rem;
    }
  }

  @media (max-width: 479px) {
    .reset-password-card {
      max-width: 350px;
      padding: 1.5rem;
    }

    .title {
      font-size: 1.375rem;
    }

    .logo {
      font-size: 2.25rem;
    }

    .subtitle {
      font-size: 0.875rem;
    }
  }
</style>
