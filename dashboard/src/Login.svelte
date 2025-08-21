<script>
  import { createEventDispatcher } from 'svelte';
  import { writable } from 'svelte/store';
  import { push } from 'svelte-spa-router';
  import axios from 'axios';
  import { setAuthenticatedUser } from './stores/auth.js';

  const dispatch = createEventDispatcher();
  
  let username = '';
  let password = '';
  let showPassword = false;
  let loading = writable(false);
  let error = writable(null);
  let success = writable(null);

  // Alternative login method using fetch
  async function handleLoginWithFetch() {
    try {
      console.log('Trying alternative fetch method for login...');
      
      const response = await fetch('http://localhost:8000/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({
          username,
          password
        })
      });
      
      console.log('Fetch response status:', response.status);
      
      if (response.ok) {
        const data = await response.json();
        console.log('Fetch login successful:', data);
        
        // Set authenticated user immediately
        setAuthenticatedUser(data.user);
        
        error.set(null);
        success.set('Login successful! Redirecting...');
        username = '';
        password = '';
        
        // Navigate to dashboard
        setTimeout(() => push('/'), 500);
        return true;
      } else {
        console.log('Fetch login failed with status:', response.status);
        const errorData = await response.json().catch(() => ({}));
        if (response.status === 401) {
          error.set('Invalid username or password');
        } else {
          error.set(errorData.detail || `Login failed (${response.status})`);
        }
        return false;
      }
    } catch (e) {
      console.error('Fetch method also failed:', e);
      return false;
    }
  }

  async function handleLogin() {
    if (!username || !password) {
      error.set('Please fill in all fields');
      success.set(null);
      return;
    }

    loading.set(true);
    error.set(null);
    success.set(null);

    // Try fetch method first
    const fetchSuccess = await handleLoginWithFetch();
    if (fetchSuccess) {
      loading.set(false);
      return;
    }

    // If fetch failed, try axios as backup
    try {
      console.log('Fetch failed, trying axios method for user:', username);
      
      const response = await axios.post('http://localhost:8000/auth/login', {
        username,
        password
      }, {
        withCredentials: true,
        timeout: 15000,  // Increased to 15 seconds
        validateStatus: function (status) {
          // Consider 200-299 as success, anything else will throw
          return status >= 200 && status < 300;
        }
      });

      console.log('Axios login response received:', response.status, response.data);

      // If we reach here, login was successful
      // Set authenticated user immediately
      setAuthenticatedUser(response.data.user);
      
      error.set(null);
      success.set('Login successful! Redirecting...');
      
      // Clear form data for security
      username = '';
      password = '';
      
      console.log('Axios login successful, clearing form and redirecting...');
      
      // Navigate to dashboard
      setTimeout(() => push('/'), 500);

    } catch (e) {
      console.error('Both fetch and axios failed. Axios error:', e);
      
      success.set(null); // Clear success message
      
      // Check if this is actually a successful response that was mishandled
      if (e.response && e.response.status === 200) {
        console.log('Axios response was actually successful, treating as success');
        // Set authenticated user immediately
        setAuthenticatedUser(e.response.data.user);
        
        error.set(null);
        success.set('Login successful! Redirecting...');
        username = '';
        password = '';
        
        // Navigate to dashboard
        setTimeout(() => push('/'), 500);
        return;
      }
      
      // Handle actual errors
      if (e.response) {
        // Server responded with error status
        console.log('Server error response:', e.response.status, e.response.data);
        if (e.response.status === 401) {
          error.set('Invalid username or password');
        } else if (e.response.status === 500) {
          error.set('Server error. Please try again later.');
        } else {
          error.set(e.response.data?.detail || `Server error (${e.response.status})`);
        }
      } else if (e.request) {
        // Request was made but no response received
        console.log('Request error:', e.request);
        if (e.code === 'ECONNREFUSED') {
          error.set('Cannot connect to server. Please check if the backend is running.');
        } else if (e.code === 'TIMEOUT' || e.message?.includes('timeout')) {
          console.warn('Login request timed out, checking auth status...');
          error.set(null);
          success.set('Checking login status...');
          
          // Check auth status after timeout
          setTimeout(async () => {
            try {
              const authCheck = await axios.get('http://localhost:8000/auth/check-auth', {
                withCredentials: true,
                timeout: 5000
              });
              if (authCheck.data.authenticated) {
                success.set('Login successful! Redirecting...');
              } else {
                success.set(null);
                error.set('Login timed out. Please try again.');
              }
            } catch (authError) {
              console.error('Auth check failed:', authError);
              success.set(null);
              error.set('Login timed out. Please try again.');
            }
          }, 1000);
        } else {
          error.set('Network error. Please check your connection.');
        }
      } else {
        // Something else happened
        console.log('Unknown error:', e.message);
        error.set('An unexpected error occurred. Please try again.');
      }
    } finally {
      loading.set(false);
    }
  }

  function goToRegister() {
    push('/register');
  }

  function handleKeyPress(event) {
    if (event.key === 'Enter') {
      handleLogin();
    }
  }
</script>

<div class="login-container">
  <div class="login-card">
    <div class="login-header">
      <div class="logo">🛡️</div>
      <h1 class="title">Login to PreTect-NIDS</h1>
      <p class="subtitle">Access your network security dashboard</p>
    </div>

    <form class="login-form" on:submit|preventDefault={handleLogin}>
      <div class="form-group">
        <label for="username" class="form-label">Username</label>
        <input
          id="username"
          type="text"
          class="form-input"
          bind:value={username}
          on:keypress={handleKeyPress}
          placeholder="Enter your username"
          disabled={$loading}
        />
      </div>

      <div class="form-group">
        <label for="password" class="form-label">Password</label>
        <div class="password-input-wrapper">
        <input
          id="password"
          type={showPassword ? 'text' : 'password'}
          class="form-input"
          bind:value={password}
          on:keypress={handleKeyPress}
          placeholder="Enter your password"
          disabled={$loading}
        />
        <button type="button" class="toggle-password" on:click={() => showPassword = !showPassword} aria-label={showPassword ? 'Hide password' : 'Show password'}>
          {showPassword ? '🙈' : '👁️'}
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
        class="login-button"
        disabled={$loading}
      >
        {#if $loading}
          <span class="spinner"></span>
          Logging in...
        {:else}
          🔐 Login
        {/if}
      </button>
    </form>

    <div class="login-footer">
      <div class="footer-links">
        <p class="forgot-password-link">
          <button class="link-button" on:click={() => push('/forgot-password')}>
            Forgot Password?
          </button>
        </p>
        <p class="register-link">
          Don't have an account? 
          <button class="link-button" on:click={goToRegister}>
            Register here
          </button>
        </p>
      </div>
    </div>
  </div>
</div>

<style>
  .login-container {
    min-height: 100vh;
    width: 100%;
    display: flex;
    align-items: center;
    justify-content: center;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    padding: 1rem;
    box-sizing: border-box;
  }

  .login-card {
    background: white;
    border-radius: 16px;
    box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
    padding: 3rem;
    width: 100%;
    max-width: 450px;
    animation: slideIn 0.3s ease;
    box-sizing: border-box;
  }

  .login-header {
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

  .login-form {
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

  .password-input-wrapper {
    position: relative;
  }
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

  .login-button {
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

  .login-button:hover:not(:disabled) {
    transform: translateY(-1px);
    box-shadow: 0 8px 20px rgba(102, 126, 234, 0.3);
  }

  .login-button:disabled {
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

  .login-footer {
    margin-top: 2rem;
    text-align: center;
  }

  .footer-links {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
    align-items: center;
  }

  .forgot-password-link, .register-link {
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
    .login-container {
      padding: 2rem;
    }

    .login-card {
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
    .login-container {
      padding: 1.5rem;
    }

    .login-card {
      max-width: 480px;
      padding: 3.5rem;
    }
  }

  /* Tablet Landscape (768px to 991px) */
  @media (min-width: 768px) and (max-width: 991px) {
    .login-container {
      padding: 1.5rem;
    }

    .login-card {
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
    .login-container {
      padding: 1rem;
    }

    .login-card {
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

    .login-button {
      padding: 0.875rem;
      font-size: 0.95rem;
    }
  }

  /* Small Mobile (below 480px) */
  @media (max-width: 479px) {
    .login-container {
      padding: 0.75rem;
    }

    .login-card {
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

    .login-button {
      padding: 0.75rem;
      font-size: 0.875rem;
    }

    .form-label {
      font-size: 0.8rem;
    }
  }

  /* Ultra-wide screens (1600px and up) */
  @media (min-width: 1600px) {
    .login-container {
      padding: 3rem;
    }

    .login-card {
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

    .login-button {
      padding: 1.25rem;
      font-size: 1.125rem;
    }
  }

  /* Landscape orientation on mobile */
  @media (max-height: 500px) and (orientation: landscape) {
    .login-container {
      padding: 0.5rem;
      align-items: flex-start;
      padding-top: 1rem;
    }

    .login-card {
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

    .login-header {
      margin-bottom: 1rem;
    }

    .login-form {
      gap: 1rem;
    }

    .login-footer {
      margin-top: 1rem;
    }
  }

  /* Print styles */
  @media print {
    .login-container {
      background: white;
      padding: 1rem;
    }

    .login-card {
      box-shadow: none;
      border: 1px solid #000;
    }

    .login-button {
      background: #333;
    }
  }

  /* High contrast mode */
  @media (prefers-contrast: high) {
    .login-card {
      border: 2px solid #000;
    }

    .form-input {
      border: 2px solid #000;
    }

    .login-button {
      border: 2px solid #000;
    }
  }

  /* Reduced motion */
  @media (prefers-reduced-motion: reduce) {
    .login-card {
      animation: none;
    }

    .login-button {
      transition: none;
    }

    .spinner {
      animation: none;
    }
  }
</style> 