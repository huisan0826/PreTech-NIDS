<script>
  import { writable } from 'svelte/store';
  import { push } from 'svelte-spa-router';
  import axios from 'axios';
  import { onMount } from 'svelte';

  // Form state
  let email = '';
  let otpCode = '';
  let newPassword = '';
  let confirmPassword = '';
  let showNewPassword = false;
  let showConfirmPassword = false;
  let loading = writable(false);
  let error = writable(null);
  let success = writable(null);
  
  // Flow control
  let otpVerified = false;
  let resendCooldown = 0;
  let resendTimer = null;
  let userEmail = '';

  // Password requirements checklist for new password
  $: rp_len = newPassword.length >= 8;
  $: rp_upper = /[A-Z]/.test(newPassword);
  $: rp_lower = /[a-z]/.test(newPassword);
  $: rp_digit = /[0-9]/.test(newPassword);
  $: rp_special = /[!@#$%^&*()_+\-=[\]{};':"\\|,.<>\/?`~]/.test(newPassword);

  // Format OTP code with spaces
  $: formattedOtp = otpCode.replace(/(\d{1})/g, '$1 ').trim();

  // Verify OTP
  async function handleVerifyOTP() {
    if (!otpCode) {
      error.set('Please enter the verification code');
      return;
    }

    const code = String(otpCode || '').trim();
    if (!/^[0-9]{6}$/.test(code)) {
      error.set('Verification code must be 6 digits');
      return;
    }

    try {
      loading.set(true);
      error.set(null);

      const response = await axios.post('http://localhost:8000/auth/password-reset/verify-otp', {
        email: email,
        otp_code: code
      });

      otpVerified = true;
      userEmail = email; // Save the email from URL params
      success.set('OTP verified successfully! Please enter your new password.');
      
      // Clear OTP input
      otpCode = '';

    } catch (e) {
      console.error('OTP verification error:', e);
      if (e.response?.status === 400) {
        error.set(e.response.data?.detail || 'Invalid verification code');
      } else if (e.response?.status === 404) {
        error.set('Verification code not found or expired');
      } else {
        error.set('Verification failed, please try again');
      }
    } finally {
      loading.set(false);
    }
  }

  // Resend OTP
  async function handleResendOTP() {
    try {
      loading.set(true);
      error.set(null);

      const response = await axios.post('http://localhost:8000/auth/password-reset/resend-otp', {
        email: email
      });

      success.set('New verification code sent to your email!');
      
      // Start cooldown timer
      resendCooldown = 60;
      resendTimer = setInterval(() => {
        resendCooldown--;
        if (resendCooldown <= 0) {
          clearInterval(resendTimer);
          resendTimer = null;
        }
      }, 1000);

    } catch (e) {
      console.error('Resend OTP error:', e);
      if (e.response?.status === 400) {
        error.set(e.response.data?.detail || 'Failed to resend code');
      } else {
        error.set('Failed to resend verification code, please try again later');
      }
    } finally {
      loading.set(false);
    }
  }

  // Reset password
  async function handleResetPassword() {
    if (!newPassword || !confirmPassword) {
      error.set('Please fill in all password fields');
      return;
    }

    if (newPassword !== confirmPassword) {
      error.set('New password and confirm password do not match');
      return;
    }

    // Strong password validation
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

      const response = await axios.post('http://localhost:8000/auth/password-reset/complete', {
        email: userEmail,
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
      if (!otpVerified) {
        handleVerifyOTP();
      } else {
        handleResetPassword();
      }
    }
  }

  // Get email from URL params
  onMount(() => {
    console.log('ResetPassword component mounted');
    
    let emailParam = null;
    
    // Priority: Try to get email from hash route query parameters
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
    
    if (emailParam) {
      email = emailParam;
      console.log('✅ Email loaded from URL:', email);
    } else {
      console.log('❌ No email found in URL');
    }
    
    return () => {
      if (resendTimer) {
        clearInterval(resendTimer);
      }
    };
  });
</script>

<div class="verify-container">
  <div class="verify-card">
    {#if !otpVerified}
      <!-- Email Verification Header -->
      <div class="verify-header">
        <div class="logo">
          <img src="/logo.png" alt="PreTech-NIDS Logo" class="auth-logo" />
        </div>
        <h1 class="title">Password Reset Verification</h1>
        <p class="subtitle">Check Your Email</p>
        <p class="instruction">We've sent a 6-digit reset code to</p>
        <div class="email-display">{email || 'Loading...'}</div>
      </div>

      <!-- OTP Verification Form -->
      <form class="verification-form" on:submit|preventDefault={handleVerifyOTP}>
        <div class="form-group">
          <label for="otp" class="form-label">Enter Reset Code</label>
          <input
            id="otp"
            type="text"
            class="form-input"
            bind:value={otpCode}
            placeholder="0 0 0 0 0 0"
            disabled={$loading}
            required
            maxlength="6"
            inputmode="numeric"
            autocomplete="one-time-code"
            on:keypress={handleKeyPress}
          />
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

        <button type="submit" class="verify-button" disabled={$loading}>
          {#if $loading}
            <span class="spinner"></span>
            Verifying...
          {:else}
            🔐 Verify Reset Code
          {/if}
        </button>

        <div class="resend-section">
          <span>Didn't receive the code?</span>
          <button type="button" class="link-button" on:click={handleResendOTP} disabled={$loading || resendCooldown > 0}>
            {#if resendCooldown > 0}
              Resend Code ({resendCooldown}s)
            {:else}
              Resend Code
            {/if}
          </button>
        </div>

        <button type="button" class="back-button" on:click={goToLogin}>
          Back to Login
        </button>
      </form>

            <div class="note-box">
        <p><strong>Note:</strong> The reset code will expire in 10 minutes. If you don't see the email, please check your spam folder.</p>
      </div>

    {:else}
      <!-- Password Reset Form -->
      <div class="reset-header">
        <h1 class="title">Reset Password</h1>
        <p class="subtitle">Enter your new password for {userEmail}</p>
      </div>

      <form class="reset-password-form" on:submit|preventDefault={handleResetPassword}>
        <div class="form-group">
          <label for="new-password" class="form-label">New Password</label>
          <div class="password-input-wrapper">
            <input
              id="new-password"
              type={showNewPassword ? 'text' : 'password'}
              class="form-input password-input"
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
              class="form-input password-input"
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
    {/if}
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
    margin-bottom: 1rem;
  }

  .auth-logo {
    width: 80px;
    height: 80px;
    object-fit: contain;
    margin: 0 auto;
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
  
  .verification-form {
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
  }

  .back-button {
    background: white;
    color: #374151;
    border: 2px solid #d1d5db;
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



  /* Password Reset Styles */
  .reset-header {
    padding: 2rem 2rem 0 2rem;
    text-align: center;
  }

  .subtitle {
    color: #6b7280;
    margin: 0.5rem 0 0 0;
    font-size: 1rem;
  }

  .reset-password-form {
    padding: 2rem;
    display: flex;
    flex-direction: column;
    gap: 1.5rem;
  }

  .form-group {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    margin-bottom: 1.5rem; /* 增加底部间距 */
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

  /* 验证码输入框特殊样式 */
  .form-input[placeholder*="0 0 0 0 0 0"] {
    margin-bottom: 1rem; /* 为验证码输入框添加底部间距 */
    text-align: center; /* 验证码居中对齐 */
    letter-spacing: 0.5rem; /* 验证码字母间距 */
  }

  .password-input-wrapper {
    position: relative;
  }

  .password-input {
    padding-right: 3rem; /* 为眼睛图标留出空间 */
    text-align: left; /* 密码输入框左对齐 */
    letter-spacing: normal; /* 密码输入框正常字母间距 */
  }

  .toggle-password {
    position: absolute;
    right: 12px;
    top: 50%;
    transform: translateY(-50%);
    background: none;
    border: none;
    cursor: pointer;
    font-size: 1rem;
    padding: 0;
    color: #6b7280;
    transition: color 0.2s ease;
  }

  .toggle-password:hover {
    color: #374151;
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

  /* Password Reset Styles */
  .reset-header {
    text-align: center;
    margin-bottom: 2rem;
  }

  .reset-password-form {
    display: flex;
    flex-direction: column;
    gap: 1.5rem;
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
  
  .password-reqs li { 
    margin: 0.125rem 0; 
  }
  
  .password-reqs li.ok { 
    color: #059669; 
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
    .verify-container {
      padding: 1rem;
    }

    .verify-card {
      max-width: 400px;
    }

    .title {
      font-size: 1.5rem;
    }

    .verify-header,
    .verification-form,
    .reset-header,
    .reset-password-form {
      padding: 1.5rem;
    }
  }

  @media (max-width: 479px) {
    .verify-card {
      max-width: 350px;
    }

    .title {
      font-size: 1.375rem;
    }

    .verify-header,
    .verification-form,
    .reset-header,
    .reset-password-form {
      padding: 1rem;
    }
  }
</style>
