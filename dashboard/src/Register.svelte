<script>
  import { createEventDispatcher } from 'svelte';
  import { writable } from 'svelte/store';
  import { push } from 'svelte-spa-router';
  import axios from 'axios';

  const dispatch = createEventDispatcher();
  
  let username = '';
  let email = '';
  let password = '';
  let confirmPassword = '';
  let showPassword = false;
  let showConfirmPassword = false;
  let loading = writable(false);
  let error = writable(null);
  let success = writable(null);
  // Initialize known fields to satisfy linter/type inference
  let fieldErrors = writable({ username: null, email: null, password: null, confirmPassword: null });

  // Password requirements (live checklist state)
  // All labels and comments are in English as requested
  $: pw_len = password.length >= 8;
  $: pw_upper = /[A-Z]/.test(password);
  $: pw_lower = /[a-z]/.test(password);
  $: pw_digit = /[0-9]/.test(password);
  $: pw_special = /[!@#$%^&*()_+\-=[\]{};':"\\|,.<>\/?`~]/.test(password);

  function validateUsername(value) {
    if (!value) return 'Username is required';
    if (value.length < 3 || value.length > 20) return 'Username must be between 3 and 20 characters';
    if (!/^[a-zA-Z0-9_]+$/.test(value)) return 'Username can only contain letters, numbers, and underscores';
    return null;
  }

  function validateEmail(value) {
    if (!value) return 'Email is required';
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(value)) return 'Please enter a valid email address';
    return null;
  }

  function validatePassword(value) {
    if (!value) return 'Password is required';
    // Strong password: 8+ chars, upper, lower, digit, special
    if (value.length < 8) return 'Password must be at least 8 characters long';
    if (!/[A-Z]/.test(value)) return 'Password must include at least one uppercase letter';
    if (!/[a-z]/.test(value)) return 'Password must include at least one lowercase letter';
    if (!/[0-9]/.test(value)) return 'Password must include at least one number';
    if (!/[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?`~]/.test(value)) return 'Password must include at least one special character';
    return null;
  }

  function validateConfirmPassword(value) {
    if (!value) return 'Please confirm your password';
    if (value !== password) return 'Passwords do not match';
    return null;
  }

  function validateForm() {
    const errors = { username: null, email: null, password: null, confirmPassword: null };
    
    const usernameError = validateUsername(username);
    if (usernameError) errors.username = usernameError;
    
    const emailError = validateEmail(email);
    if (emailError) errors.email = emailError;
    
    const passwordError = validatePassword(password);
    if (passwordError) errors.password = passwordError;
    
    const confirmPasswordError = validateConfirmPassword(confirmPassword);
    if (confirmPasswordError) errors.confirmPassword = confirmPasswordError;
    
    fieldErrors.set(errors);
    // valid if all are null
    return !errors.username && !errors.email && !errors.password && !errors.confirmPassword;
  }

  async function handleRegister() {
    if (!validateForm()) {
      error.set('Please fix the errors below');
      return;
    }

    loading.set(true);
    error.set(null);

    try {
      const response = await axios.post('http://localhost:8000/auth/register/initiate', {
        username,
        email,
        password,
        confirm_password: confirmPassword
      });

      success.set('Verification code sent to your email. Please check and verify.');
      
      // 保存邮箱地址到localStorage作为备份
      localStorage.setItem('pendingVerificationEmail', email);
      
      // Redirect to verify page with email prefilled
      setTimeout(() => {
        const params = new URLSearchParams({ email });
        push(`/verify-registration?${params.toString()}`);
      }, 800);

    } catch (e) {
      if (e.response?.status === 400) {
        const detail = e.response.data.detail;
        if (detail.includes('Username already registered')) {
          fieldErrors.update(errors => ({ ...errors, username: 'Username already taken' }));
        } else if (detail.includes('Email already registered')) {
          fieldErrors.update(errors => ({ ...errors, email: 'Email already registered' }));
        } else {
          error.set(detail);
        }
      } else if (e.response?.data?.detail && Array.isArray(e.response.data.detail)) {
        // Handle validation errors from FastAPI
        const errors = { username: null, email: null, password: null, confirmPassword: null };
        e.response.data.detail.forEach(err => {
          if (err.loc && err.msg) {
            const field = err.loc[err.loc.length - 1];
            errors[field] = err.msg;
          }
        });
        fieldErrors.set(errors);
      } else {
        error.set(e.response?.data?.detail || 'Registration failed. Please try again.');
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
      handleRegister();
    }
  }
</script>

<div class="register-container">
  <div class="register-card">
    <div class="register-header">
              <div class="logo">
          <img src="/logo.png" alt="PreTech-NIDS Logo" class="auth-logo" />
        </div>
      <h1 class="title">Join PreTect-NIDS</h1>
      <p class="subtitle">Create your account to start monitoring network security</p>
    </div>

    <form class="register-form" on:submit|preventDefault={handleRegister}>
      <div class="form-group">
        <label for="username" class="form-label">Username</label>
        <input
          id="username"
          type="text"
          class={`form-input ${$fieldErrors.username ? 'error' : ''}`}
          bind:value={username}
          on:keypress={handleKeyPress}
          placeholder="Choose a username"
          disabled={$loading}
        />
        {#if $fieldErrors.username && $fieldErrors.username !== null}
          <span class="field-error">{$fieldErrors.username}</span>
        {/if}
      </div>

      <div class="form-group">
        <label for="email" class="form-label">Email Address</label>
        <input
          id="email"
          type="email"
          class={`form-input ${$fieldErrors.email ? 'error' : ''}`}
          bind:value={email}
          on:keypress={handleKeyPress}
          placeholder="Enter your email"
          disabled={$loading}
        />
        {#if $fieldErrors.email}
          <span class="field-error">{$fieldErrors.email}</span>
        {/if}
      </div>

      <div class="form-group">
        <label for="password" class="form-label">Password</label>
        <div class="password-input-wrapper">
        <input
          id="password"
          type={showPassword ? 'text' : 'password'}
          class={`form-input ${$fieldErrors.password ? 'error' : ''}`}
          bind:value={password}
          on:keypress={handleKeyPress}
          placeholder="Create a password"
          disabled={$loading}
        />
        <button type="button" class="toggle-password" on:click={() => showPassword = !showPassword} aria-label={showPassword ? 'Hide password' : 'Show password'}>
          {showPassword ? '🙈' : '👁️'}
        </button>
        </div>
        <ul class="password-reqs">
          <li class={pw_len ? 'ok' : ''}>At least 8 characters</li>
          <li class={pw_upper ? 'ok' : ''}>At least 1 uppercase letter (A-Z)</li>
          <li class={pw_lower ? 'ok' : ''}>At least 1 lowercase letter (a-z)</li>
          <li class={pw_digit ? 'ok' : ''}>At least 1 number (0-9)</li>
          <li class={pw_special ? 'ok' : ''}>At least 1 special character (!@#$%^&* etc.)</li>
        </ul>
        {#if $fieldErrors.password}
          <span class="field-error">{$fieldErrors.password}</span>
        {/if}
      </div>

      <div class="form-group">
        <label for="confirmPassword" class="form-label">Confirm Password</label>
        <div class="password-input-wrapper">
        <input
          id="confirmPassword"
          type={showConfirmPassword ? 'text' : 'password'}
          class={`form-input ${$fieldErrors.confirmPassword ? 'error' : ''}`}
          bind:value={confirmPassword}
          on:keypress={handleKeyPress}
          placeholder="Confirm your password"
          disabled={$loading}
        />
        <button type="button" class="toggle-password" on:click={() => showConfirmPassword = !showConfirmPassword} aria-label={showConfirmPassword ? 'Hide password' : 'Show password'}>
          {showConfirmPassword ? '🙈' : '👁️'}
        </button>
        </div>
        {#if $fieldErrors.confirmPassword}
          <span class="field-error">{$fieldErrors.confirmPassword}</span>
        {/if}
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
        class="register-button"
        disabled={$loading}
      >
        {#if $loading}
          <span class="spinner"></span>
          Sending Code...
        {:else}
          🚀 Sign Up (Email Verification)
        {/if}
      </button>
    </form>

    <div class="register-footer">
      <div class="footer-links">
        <p class="login-link">
          Already have an account? 
          <button class="link-button" on:click={goToLogin}>
            Login here
          </button>
        </p>
      </div>
    </div>
  </div>
</div>

<style>
  .register-container {
    min-height: 100vh;
    width: 100%;
    display: flex;
    align-items: center;
    justify-content: center;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    padding: 1rem;
    box-sizing: border-box;
  }

  .register-card {
    background: white;
    border-radius: 16px;
    box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
    padding: 3rem;
    width: 100%;
    max-width: 450px;
    animation: slideIn 0.3s ease;
    box-sizing: border-box;
  }

  .register-header {
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
    color: #6b7280;
    margin: 0;
    font-size: 1rem;
  }

  .register-form {
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

  .form-input.error {
    border-color: #ef4444;
  }

  .form-input.error:focus {
    border-color: #ef4444;
    box-shadow: 0 0 0 3px rgba(239, 68, 68, 0.1);
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

  .field-error {
    color: #ef4444;
    font-size: 0.75rem;
    margin-top: 0.25rem;
  }

  /* Password requirements checklist */
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
    color: #059669; /* green when satisfied */
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

  .register-button {
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

  .register-button:hover:not(:disabled) {
    transform: translateY(-1px);
    box-shadow: 0 8px 20px rgba(102, 126, 234, 0.3);
  }

  .register-button:disabled {
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

  .register-footer {
    margin-top: 2rem;
    text-align: center;
  }

  .footer-links {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
    align-items: center;
  }

  .login-link {
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
  
  /* Large Desktop (1200px and up) */
  @media (min-width: 1200px) {
    .register-container {
      padding: 2rem;
    }

    .register-card {
      max-width: 500px;
      padding: 4rem;
    }

    .title {
      font-size: 2rem;
    }

    .logo {
      font-size: 3.5rem;
    }
  }

  /* Standard Desktop (992px to 1199px) */
  @media (min-width: 992px) and (max-width: 1199px) {
    .register-container {
      padding: 1.5rem;
    }

    .register-card {
      max-width: 480px;
      padding: 3.5rem;
    }
  }

  /* Tablet Landscape (768px to 991px) */
  @media (min-width: 768px) and (max-width: 991px) {
    .register-container {
      padding: 1.5rem;
    }

    .register-card {
      max-width: 450px;
      padding: 3rem;
    }

    .title {
      font-size: 1.625rem;
    }

    .logo {
      font-size: 2.75rem;
    }
  }

  /* Mobile and Tablet Portrait (below 768px) */
  @media (max-width: 767px) {
    .register-container {
      padding: 1rem;
    }

    .register-card {
      max-width: 400px;
      padding: 2rem;
    }

    .title {
      font-size: 1.5rem;
    }

    .logo {
      font-size: 2.5rem;
    }

    .form-input {
      padding: 0.75rem;
      font-size: 0.95rem;
    }

    .register-button {
      padding: 0.875rem;
      font-size: 0.95rem;
    }
  }

  /* Small Mobile (below 480px) */
  @media (max-width: 479px) {
    .register-container {
      padding: 0.75rem;
    }

    .register-card {
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

    .form-input {
      padding: 0.625rem;
      font-size: 0.875rem;
    }

    .register-button {
      padding: 0.75rem;
      font-size: 0.875rem;
    }

    .form-label {
      font-size: 0.8rem;
    }
  }

  /* Ultra-wide screens (1600px and up) */
  @media (min-width: 1600px) {
    .register-container {
      padding: 3rem;
    }

    .register-card {
      max-width: 550px;
      padding: 5rem;
    }

    .title {
      font-size: 2.25rem;
    }

    .logo {
      font-size: 4rem;
    }

    .subtitle {
      font-size: 1.125rem;
    }

    .form-input {
      padding: 1rem;
      font-size: 1.125rem;
    }

    .register-button {
      padding: 1.25rem;
      font-size: 1.125rem;
    }
  }

  /* Landscape orientation on mobile */
  @media (max-height: 500px) and (orientation: landscape) {
    .register-container {
      padding: 0.5rem;
      align-items: flex-start;
      padding-top: 1rem;
    }

    .register-card {
      padding: 1.5rem;
      margin: 0;
    }

    .logo {
      font-size: 2rem;
      margin-bottom: 0.5rem;
    }

    .title {
      font-size: 1.25rem;
    }

    .register-header {
      margin-bottom: 1rem;
    }

    .register-form {
      gap: 1rem;
    }

    .register-footer {
      margin-top: 1rem;
    }
  }

  /* Print styles */
  @media print {
    .register-container {
      background: white;
      padding: 1rem;
    }

    .register-card {
      box-shadow: none;
      border: 1px solid #000;
    }

    .register-button {
      background: #333;
    }
  }

  /* High contrast mode */
  @media (prefers-contrast: high) {
    .register-card {
      border: 2px solid #000;
    }

    .form-input {
      border: 2px solid #000;
    }

    .register-button {
      border: 2px solid #000;
    }
  }

  /* Reduced motion */
  @media (prefers-reduced-motion: reduce) {
    .register-card {
      animation: none;
    }

    .register-button {
      transition: none;
    }

    .spinner {
      animation: none;
    }
  }
</style> 