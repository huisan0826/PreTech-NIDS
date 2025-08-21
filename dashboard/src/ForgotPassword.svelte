<script>
  import { writable } from 'svelte/store';
  import { push } from 'svelte-spa-router';
  import axios from 'axios';

  // Form state
  let email = '';
  let loading = writable(false);
  let error = writable(null);
  let success = writable(null);

  // Send password reset OTP
  async function handleForgotPassword() {
    if (!email.trim()) {
      error.set('Please enter your email address');
      return;
    }

    try {
      loading.set(true);
      error.set(null);
      success.set(null);

      const response = await axios.post('http://localhost:8000/auth/password-reset/initiate-otp', {
        email: email.trim()
      });

      success.set('A reset code has been sent to your email');

      // Go to reset page with email prefilled
      setTimeout(() => {
        const params = new URLSearchParams({ email: email.trim() });
        push(`/reset-password?${params.toString()}`);
      }, 800);

      // Clear success message after 5 seconds
      setTimeout(() => {
        success.set(null);
      }, 5000);

    } catch (e) {
      console.error('Forgot password error:', e);
      if (e.response?.status === 404) {
        error.set('This email is not registered');
      } else if (e.response?.status === 400) {
        error.set(e.response.data?.detail || 'Invalid email address');
      } else if (e.response?.status === 500) {
        error.set('Failed to send reset email, please try again later');
      } else {
        error.set('Network error, please check your connection');
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
      handleForgotPassword();
    }
  }
</script>

<div class="forgot-password-container">
  <div class="forgot-password-card">
    <div class="forgot-password-header">
      <div class="logo">🔐</div>
      <h1 class="title">Forgot Password</h1>
      <p class="subtitle">Enter your email address and we'll send you a one-time code</p>
    </div>

    <form class="forgot-password-form" on:submit|preventDefault={handleForgotPassword}>
      <div class="form-group">
        <label for="email" class="form-label">Email Address</label>
        <input
          id="email"
          type="email"
          class="form-input"
          bind:value={email}
          on:keypress={handleKeyPress}
          placeholder="Enter your email address"
          disabled={$loading}
          required
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

      <button 
        type="submit" 
        class="submit-button"
        disabled={$loading}
      >
        {#if $loading}
          <span class="spinner"></span>
          Sending...
        {:else}
          📧 Send Reset Link
        {/if}
      </button>
    </form>

    <div class="forgot-password-footer">
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
  .forgot-password-container {
    min-height: 100vh;
    width: 100%;
    display: flex;
    align-items: center;
    justify-content: center;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    padding: 1rem;
    box-sizing: border-box;
  }

  .forgot-password-card {
    background: white;
    border-radius: 16px;
    box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
    padding: 3rem;
    width: 100%;
    max-width: 450px;
    animation: slideIn 0.3s ease;
    box-sizing: border-box;
  }

  .forgot-password-header {
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

  .forgot-password-form {
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

  .forgot-password-footer {
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
    .forgot-password-container {
      padding: 1rem;
    }

    .forgot-password-card {
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
    .forgot-password-card {
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
