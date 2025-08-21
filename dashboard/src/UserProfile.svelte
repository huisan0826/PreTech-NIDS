<script>
  import { writable, get } from 'svelte/store';
  import axios from 'axios';
  import { push } from 'svelte-spa-router';
  import { currentUser as globalCurrentUser, setAuthenticatedUser } from './stores/auth.js';

  // Form state
  let currentUser = writable(null);
  let loading = writable(false);
  let error = writable(null);
  let success = writable(null);

  // Form data
  let username = '';
  let email = '';
  let currentPassword = '';
  let newPassword = '';
  let confirmPassword = '';
  let avatarFile = null;
  let avatarPreview = null;
  let showCurrent = false;
  let showNew = false;
  let showConfirm = false;

  // Password requirements checklist (for new password)
  // English-only labels as requested
  $: np_len = newPassword.length >= 8;
  $: np_upper = /[A-Z]/.test(newPassword);
  $: np_lower = /[a-z]/.test(newPassword);
  $: np_digit = /[0-9]/.test(newPassword);
  $: np_special = /[!@#$%^&*()_+\-=[\]{};':"\\|,.<>\/?`~]/.test(newPassword);

  // Form section states
  let showPasswordSection = false;
  let profileLoading = false;
  let passwordLoading = false;
  let avatarLoading = false;

  // Load current user data
  async function loadUserProfile() {
    try {
      profileLoading = true;
      const response = await axios.get('http://localhost:8000/auth/me', {
        withCredentials: true
      });
      
      currentUser.set(response.data);
      username = response.data.username;
      email = response.data.email || '';
      error.set(null);
    } catch (e) {
      console.error('Failed to load user profile:', e);
      if (e.response?.status === 401) {
        push('/login');
      } else {
        error.set('Failed to load user profile');
      }
    } finally {
      profileLoading = false;
    }
  }

  // Handle avatar file selection
  function handleAvatarSelect(event) {
    const file = event.target.files[0];
    if (file) {
      // Validate file type
      if (!file.type.startsWith('image/')) {
        error.set('Please select an image file');
        return;
      }
      
      // Validate file size (5MB)
      if (file.size > 5 * 1024 * 1024) {
        error.set('Image file size cannot exceed 5MB');
        return;
      }
      
      avatarFile = file;
      
      // Create preview
      const reader = new FileReader();
      reader.onload = (e) => {
        avatarPreview = e.target.result;
      };
      reader.readAsDataURL(file);
    }
  }

  // Upload avatar
  async function uploadAvatar() {
    if (!avatarFile) {
      error.set('Please select an image file');
      return;
    }

    try {
      avatarLoading = true;
      error.set(null);
      success.set(null);

      const formData = new FormData();
      formData.append('file', avatarFile);

      const response = await axios.post('http://localhost:8000/auth/avatar', formData, {
        withCredentials: true,
        headers: {
          'Content-Type': 'multipart/form-data'
        }
      });

      success.set('Avatar uploaded successfully!');
      
      // Update local currentUser
      currentUser.set({ ...$currentUser, avatar: response.data.avatar, avatar_url: response.data.avatar_url });
      
      // Update global currentUser store to reflect in sidebar
      const updatedUser = { ...get(globalCurrentUser), avatar: response.data.avatar, avatar_url: response.data.avatar_url };
      setAuthenticatedUser(updatedUser);
      
      // Immediately refresh user profile to ensure consistency
      await loadUserProfile();
      
      // Clear file selection
      avatarFile = null;
      avatarPreview = null;
      
      // Clear success message after 3 seconds
      setTimeout(() => {
        success.set(null);
      }, 3000);

    } catch (e) {
      console.error('Avatar upload error:', e);
      if (e.response?.status === 400) {
        error.set(e.response.data?.detail || 'Invalid file');
      } else if (e.response?.status === 401) {
        push('/login');
      } else {
        error.set('Avatar upload failed');
      }
    } finally {
      avatarLoading = false;
    }
  }

  // Delete avatar
  async function deleteAvatar() {
    try {
      avatarLoading = true;
      error.set(null);
      success.set(null);

      await axios.delete('http://localhost:8000/auth/avatar', {
        withCredentials: true
      });

      success.set('Avatar deleted successfully!');
      
      // Update local currentUser
      currentUser.set({ ...$currentUser, avatar: null, avatar_url: null });
      
      // Update global currentUser store to reflect in sidebar
      const updatedUser = { ...get(globalCurrentUser), avatar: null, avatar_url: null };
      setAuthenticatedUser(updatedUser);
      
      // Immediately refresh user profile to ensure consistency
      await loadUserProfile();
      
      // Clear success message after 3 seconds
      setTimeout(() => {
        success.set(null);
      }, 3000);

    } catch (e) {
      console.error('Avatar delete error:', e);
      if (e.response?.status === 401) {
        push('/login');
      } else {
        error.set('Avatar delete failed');
      }
    } finally {
      avatarLoading = false;
    }
  }

  // Update profile information
  async function updateProfile() {
    if (!username.trim()) {
      error.set('Username is required');
      return;
    }

    try {
      loading.set(true);
      error.set(null);
      success.set(null);

      const response = await axios.put('http://localhost:8000/auth/profile', {
        username: username.trim(),
        email: email.trim()
      }, {
        withCredentials: true
      });

      success.set('Profile updated successfully!');
      
      // Update local currentUser
      currentUser.set(response.data);
      
      // Update global currentUser store to reflect in sidebar
      setAuthenticatedUser(response.data);
      
      // Clear success message after 3 seconds
      setTimeout(() => {
        success.set(null);
      }, 3000);

    } catch (e) {
      console.error('Profile update error:', e);
      if (e.response?.status === 401) {
        push('/login');
      } else if (e.response?.status === 400) {
        error.set(e.response.data?.detail || 'Invalid input data');
      } else if (e.response?.status === 409) {
        error.set('Username already exists');
      } else {
        error.set('Failed to update profile');
      }
    } finally {
      loading.set(false);
    }
  }

  // Change password
  async function changePassword() {
    if (!currentPassword || !newPassword || !confirmPassword) {
      error.set('All password fields are required');
      return;
    }

    if (newPassword !== confirmPassword) {
      error.set('New passwords do not match');
      return;
    }

    if (newPassword.length < 6) {
      error.set('New password must be at least 6 characters long');
      return;
    }

    try {
      passwordLoading = true;
      error.set(null);
      success.set(null);

      await axios.put('http://localhost:8000/auth/password', {
        current_password: currentPassword,
        new_password: newPassword
      }, {
        withCredentials: true
      });

      success.set('Password changed successfully!');
      
      // Clear password fields
      currentPassword = '';
      newPassword = '';
      confirmPassword = '';
      showPasswordSection = false;

      // Clear success message after 3 seconds
      setTimeout(() => {
        success.set(null);
      }, 3000);

    } catch (e) {
      console.error('Password change error:', e);
      if (e.response?.status === 401) {
        if (e.response.data?.detail?.includes('current password')) {
          error.set('Current password is incorrect');
        } else {
          push('/login');
        }
      } else {
        error.set('Failed to change password');
      }
    } finally {
      passwordLoading = false;
    }
  }

  // Helper functions for role and permissions display
  function getRoleColor(role) {
    const colors = {
      'admin': 'admin-role',
      'analyst': 'analyst-role', 
      'viewer': 'viewer-role'
    };
    return colors[role] || 'viewer-role';
  }
  
  function getPermissionDisplayName(permission) {
    const displayNames = {
      'user_management': 'User Management',
      'system_settings': 'System Settings',
      'view_reports': 'View Reports',
      'manual_testing': 'Manual Testing',
      'real_time_detection': 'Real-time Detection',
      'export_data': 'Export Data',
      'delete_reports': 'Delete Reports'
    };
    return displayNames[permission] || permission.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase());
  }

  // Load user profile on component mount
  import { onMount } from 'svelte';
  onMount(() => {
    loadUserProfile();
  });
</script>

<div class="profile-container">
  <div class="profile-header">
    <h1 class="profile-title">👤 User Profile</h1>
    <p class="profile-description">Manage your account settings and preferences</p>
  </div>

  {#if profileLoading}
    <div class="loading-card">
      <div class="loading-spinner"></div>
      <p>Loading profile...</p>
    </div>
  {:else}
    <div class="profile-content">
      <!-- Success Message -->
      {#if $success}
        <div class="success-alert">
          <span class="success-icon">✅</span>
          <span class="success-text">{$success}</span>
        </div>
      {/if}

      <!-- Error Message -->
      {#if $error}
        <div class="error-alert">
          <span class="error-icon">⚠️</span>
          <span class="error-text">{$error}</span>
        </div>
      {/if}

      <!-- Avatar Management Card -->
      <div class="profile-card">
        <div class="card-header">
          <h2 class="card-title">🖼️ Avatar Management</h2>
          <p class="card-description">Upload and manage your profile picture</p>
        </div>

        <div class="avatar-section">
          <div class="current-avatar">
            {#if $currentUser?.avatar_url}
              <img src={$currentUser.avatar_url} alt="Current Avatar" class="avatar-image" />
            {:else}
              <div class="default-avatar">
                <span class="avatar-placeholder">👤</span>
              </div>
            {/if}
          </div>

          <div class="avatar-actions">
            <div class="file-input-wrapper">
              <input
                type="file"
                id="avatar-input"
                accept="image/*"
                on:change={handleAvatarSelect}
                class="file-input"
                disabled={avatarLoading}
              />
              <label for="avatar-input" class="file-input-label">
                📁 Select Image
              </label>
            </div>

            {#if avatarFile}
              <div class="avatar-preview">
                <img src={avatarPreview} alt="Preview" class="preview-image" />
                <div class="preview-actions">
                  <button
                    type="button"
                    class="upload-avatar-button"
                    on:click={uploadAvatar}
                    disabled={avatarLoading}
                  >
                    {#if avatarLoading}
                      <span class="button-spinner"></span>
                      Uploading...
                    {:else}
                      📤 Upload Avatar
                    {/if}
                  </button>
                  <button
                    type="button"
                    class="cancel-avatar-button"
                    on:click={() => {
                      avatarFile = null;
                      avatarPreview = null;
                    }}
                    disabled={avatarLoading}
                  >
                    Cancel
                  </button>
                </div>
              </div>
            {/if}

            {#if $currentUser?.avatar && !avatarFile}
              <button
                type="button"
                class="delete-avatar-button"
                on:click={deleteAvatar}
                disabled={avatarLoading}
              >
                {#if avatarLoading}
                  <span class="button-spinner"></span>
                  Deleting...
                {:else}
                  🗑️ Delete Avatar
                {/if}
              </button>
            {/if}
          </div>
        </div>
      </div>

      <!-- Profile Information Card -->
      <div class="profile-card">
        <div class="card-header">
          <h2 class="card-title">📝 Profile Information</h2>
          <p class="card-description">Update your basic account information</p>
        </div>

        <form on:submit|preventDefault={updateProfile} class="profile-form">
          <div class="form-group">
            <label for="username" class="form-label">Username</label>
            <input
              id="username"
              type="text"
              bind:value={username}
              class="form-input"
              placeholder="Enter your username"
              required
              minlength="3"
              maxlength="50"
            />
          </div>

          <div class="form-group">
            <label for="email" class="form-label">Email Address</label>
            <input
              id="email"
              type="email"
              bind:value={email}
              class="form-input"
              placeholder="Enter your email (optional)"
              maxlength="255"
            />
          </div>

          <div class="form-actions">
            <button
              type="submit"
              class="update-button"
              disabled={$loading}
            >
              {#if $loading}
                <span class="button-spinner"></span>
                Updating...
              {:else}
                💾 Update Profile
              {/if}
            </button>
          </div>
        </form>
      </div>

      <!-- Password Change Card -->
      <div class="profile-card">
        <div class="card-header">
          <h2 class="card-title">🔒 Change Password</h2>
          <p class="card-description">Update your account password for security</p>
        </div>

        {#if !showPasswordSection}
          <div class="password-toggle">
            <button
              type="button"
              class="toggle-password-button"
              on:click={() => showPasswordSection = true}
            >
              🔐 Change Password
            </button>
          </div>
        {:else}
          <form on:submit|preventDefault={changePassword} class="password-form">
            <div class="form-group">
              <label for="current-password" class="form-label">Current Password</label>
              <div class="password-input-wrapper">
                <input
                  id="current-password"
                  type={showCurrent ? 'text' : 'password'}
                  bind:value={currentPassword}
                  class="form-input"
                  placeholder="Enter your current password"
                  required
                />
                <button type="button" class="toggle-password" on:click={() => showCurrent = !showCurrent} aria-label={showCurrent ? 'Hide password' : 'Show password'}>
                  {showCurrent ? '🙈' : '👁️'}
                </button>
              </div>
            </div>

            <div class="form-group">
              <label for="new-password" class="form-label">New Password</label>
              <div class="password-input-wrapper">
                <input
                  id="new-password"
                  type={showNew ? 'text' : 'password'}
                  bind:value={newPassword}
                  class="form-input"
                  placeholder="Enter your new password"
                  required
                  minlength="8"
                />
                <button type="button" class="toggle-password" on:click={() => showNew = !showNew} aria-label={showNew ? 'Hide password' : 'Show password'}>
                  {showNew ? '🙈' : '👁️'}
                </button>
              </div>
              <div class="form-hint">Password must satisfy all requirements below:</div>
              <ul class="password-reqs">
                <li class={np_len ? 'ok' : ''}>At least 8 characters</li>
                <li class={np_upper ? 'ok' : ''}>At least 1 uppercase letter (A-Z)</li>
                <li class={np_lower ? 'ok' : ''}>At least 1 lowercase letter (a-z)</li>
                <li class={np_digit ? 'ok' : ''}>At least 1 number (0-9)</li>
                <li class={np_special ? 'ok' : ''}>At least 1 special character (!@#$%^&* etc.)</li>
              </ul>
            </div>

            <div class="form-group">
              <label for="confirm-password" class="form-label">Confirm New Password</label>
              <div class="password-input-wrapper">
                <input
                  id="confirm-password"
                  type={showConfirm ? 'text' : 'password'}
                  bind:value={confirmPassword}
                  class="form-input"
                  placeholder="Confirm your new password"
                  required
                  minlength="8"
                />
                <button type="button" class="toggle-password" on:click={() => showConfirm = !showConfirm} aria-label={showConfirm ? 'Hide password' : 'Show password'}>
                  {showConfirm ? '🙈' : '👁️'}
                </button>
              </div>
            </div>

            <div class="form-actions">
              <button
                type="button"
                class="cancel-button"
                on:click={() => {
                  showPasswordSection = false;
                  currentPassword = '';
                  newPassword = '';
                  confirmPassword = '';
                  error.set(null);
                }}
              >
                Cancel
              </button>
              <button
                type="submit"
                class="password-button"
                disabled={passwordLoading}
              >
                {#if passwordLoading}
                  <span class="button-spinner"></span>
                  Changing...
                {:else}
                  🔑 Change Password
                {/if}
              </button>
            </div>
          </form>
        {/if}
      </div>

      <!-- Account Information Card -->
      {#if $currentUser}
        <div class="info-card">
          <div class="card-header">
            <h2 class="card-title">ℹ️ Account Information</h2>
            <p class="card-description">View your account details</p>
          </div>

          <div class="info-grid">
            <div class="info-item">
              <span class="info-label">User ID:</span>
              <span class="info-value">{$currentUser.id || 'N/A'}</span>
            </div>
            <div class="info-item">
              <span class="info-label">Created:</span>
              <span class="info-value">
                {$currentUser.created_at ? new Date($currentUser.created_at).toLocaleDateString() : 'N/A'}
              </span>
            </div>
            <div class="info-item">
              <span class="info-label">Last Updated:</span>
              <span class="info-value">
                {$currentUser.updated_at ? new Date($currentUser.updated_at).toLocaleDateString() : 'N/A'}
              </span>
            </div>
            <div class="info-item">
              <span class="info-label">Role:</span>
              <span class="info-value role-badge {getRoleColor($currentUser.role || 'viewer')}">
                {$currentUser.role_display || 'Report Viewer'}
              </span>
            </div>
            <div class="info-item permissions-item">
              <span class="info-label">Permissions:</span>
              <div class="permissions-list">
                {#if $currentUser.permissions && $currentUser.permissions.length > 0}
                  {#each $currentUser.permissions as permission}
                    <span class="permission-tag">{getPermissionDisplayName(permission)}</span>
                  {/each}
                {:else}
                  <span class="permission-tag">View Reports</span>
                {/if}
              </div>
            </div>
          </div>
        </div>
      {/if}
    </div>
  {/if}
</div>

<style>
  .profile-container {
    padding: 2rem;
    max-width: 800px;
    margin: 0 auto;
    min-height: 100vh;
  }

  .profile-header {
    margin-bottom: 2rem;
    text-align: center;
  }

  .profile-title {
    font-size: 2.5rem;
    font-weight: bold;
    margin: 0 0 0.5rem 0;
    color: #1f2937;
  }

  .profile-description {
    font-size: 1.1rem;
    color: #6b7280;
    margin: 0;
  }

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

  .profile-content {
    display: flex;
    flex-direction: column;
    gap: 2rem;
  }

  /* Alerts */
  .success-alert, .error-alert {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    padding: 1rem 1.5rem;
    border-radius: 8px;
    font-weight: 500;
    animation: slideIn 0.3s ease;
  }

  .success-alert {
    background-color: #dcfce7;
    color: #166534;
    border: 1px solid #bbf7d0;
  }

  .error-alert {
    background-color: #fee2e2;
    color: #991b1b;
    border: 1px solid #fecaca;
  }

  /* Cards */
  .profile-card, .info-card {
    background: white;
    border-radius: 12px;
    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
    border: 1px solid #e5e7eb;
    overflow: hidden;
  }

  .card-header {
    padding: 2rem 2rem 1rem 2rem;
    border-bottom: 1px solid #f3f4f6;
  }

  .card-title {
    font-size: 1.5rem;
    font-weight: bold;
    margin: 0 0 0.5rem 0;
    color: #1f2937;
  }

  .card-description {
    color: #6b7280;
    margin: 0;
    font-size: 0.95rem;
  }

  /* Forms */
  .profile-form, .password-form {
    padding: 2rem;
  }

  .form-group {
    margin-bottom: 1.5rem;
  }

  .form-label {
    display: block;
    font-weight: 600;
    color: #374151;
    font-size: 0.95rem;
    margin-bottom: 0.5rem;
  }

  .form-input {
    width: 100%;
    border: 2px solid #d1d5db;
    padding: 0.75rem;
    border-radius: 8px;
    font-size: 1rem;
    transition: border-color 0.2s ease, box-shadow 0.2s ease;
  }

  .form-input:focus {
    outline: none;
    border-color: #3b82f6;
    box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
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

  .form-actions {
    display: flex;
    gap: 1rem;
    justify-content: flex-end;
    margin-top: 2rem;
  }

  /* Buttons */
  .update-button, .password-button, .toggle-password-button, .cancel-button {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.5rem;
    padding: 0.75rem 1.5rem;
    border-radius: 8px;
    font-weight: 600;
    font-size: 0.95rem;
    cursor: pointer;
    transition: all 0.2s ease;
    border: none;
    min-height: 44px;
  }

  .update-button, .password-button {
    background-color: #3b82f6;
    color: white;
  }

  .update-button:hover:not(:disabled), .password-button:hover:not(:disabled) {
    background-color: #2563eb;
    transform: translateY(-1px);
    box-shadow: 0 4px 12px rgba(59, 130, 246, 0.3);
  }

  .toggle-password-button {
    background-color: #f59e0b;
    color: white;
    width: 100%;
  }

  .toggle-password-button:hover {
    background-color: #d97706;
  }

  .cancel-button {
    background-color: #6b7280;
    color: white;
  }

  .cancel-button:hover {
    background-color: #4b5563;
  }

  .update-button:disabled, .password-button:disabled {
    opacity: 0.6;
    cursor: not-allowed;
    transform: none;
    box-shadow: none;
  }

  .button-spinner {
    width: 16px;
    height: 16px;
    border: 2px solid #ffffff40;
    border-left: 2px solid #ffffff;
    border-radius: 50%;
    animation: spin 1s linear infinite;
  }

  .password-toggle {
    padding: 2rem;
  }

  /* Info Grid */
  .info-grid {
    padding: 2rem;
    display: grid;
    grid-template-columns: 1fr;
    gap: 1rem;
  }

  .info-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 0.75rem;
    background-color: #f9fafb;
    border-radius: 6px;
  }

  .info-label {
    font-weight: 600;
    color: #374151;
  }

  .info-value {
    color: #6b7280;
    font-family: 'Monaco', 'Consolas', 'Courier New', monospace;
    font-size: 0.9rem;
  }

  .role-badge {
    color: white;
    padding: 0.25rem 0.75rem;
    border-radius: 12px;
    font-size: 0.8rem;
    font-weight: 600;
    font-family: inherit;
  }
  
  .admin-role {
    background-color: #dc2626;
  }
  
  .analyst-role {
    background-color: #3b82f6;
  }
  
  .viewer-role {
    background-color: #10b981;
  }
  
  .permissions-item {
    flex-direction: column;
    align-items: flex-start;
    gap: 0.5rem;
  }
  
  .permissions-list {
    display: flex;
    flex-wrap: wrap;
    gap: 0.375rem;
  }
  
  .permission-tag {
    background-color: #e0e7ff;
    color: #3730a3;
    padding: 0.125rem 0.5rem;
    border-radius: 8px;
    font-size: 0.75rem;
    font-weight: 500;
  }

  /* Avatar Styles */
  .avatar-section {
    padding: 2rem;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 1.5rem;
  }

  .current-avatar {
    display: flex;
    justify-content: center;
  }

  .avatar-image {
    width: 120px;
    height: 120px;
    border-radius: 50%;
    object-fit: cover;
    border: 4px solid #e5e7eb;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
  }

  .default-avatar {
    width: 120px;
    height: 120px;
    border-radius: 50%;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    display: flex;
    align-items: center;
    justify-content: center;
    border: 4px solid #e5e7eb;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
  }

  .avatar-placeholder {
    font-size: 3rem;
    color: white;
  }

  .avatar-actions {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 1rem;
    width: 100%;
    max-width: 300px;
  }

  .file-input-wrapper {
    position: relative;
    width: 100%;
  }

  .file-input {
    position: absolute;
    opacity: 0;
    width: 100%;
    height: 100%;
    cursor: pointer;
  }

  .file-input-label {
    display: block;
    background-color: #3b82f6;
    color: white;
    padding: 0.75rem 1.5rem;
    border-radius: 8px;
    text-align: center;
    cursor: pointer;
    font-weight: 600;
    transition: background-color 0.2s ease;
  }

  .file-input-label:hover {
    background-color: #2563eb;
  }

  .avatar-preview {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 1rem;
    padding: 1rem;
    background-color: #f9fafb;
    border-radius: 8px;
    border: 1px solid #e5e7eb;
  }

  .preview-image {
    width: 80px;
    height: 80px;
    border-radius: 50%;
    object-fit: cover;
    border: 2px solid #d1d5db;
  }

  .preview-actions {
    display: flex;
    gap: 0.5rem;
  }

  .upload-avatar-button, .delete-avatar-button, .cancel-avatar-button {
    padding: 0.5rem 1rem;
    border-radius: 6px;
    font-weight: 600;
    font-size: 0.875rem;
    cursor: pointer;
    border: none;
    transition: all 0.2s ease;
  }

  .upload-avatar-button {
    background-color: #10b981;
    color: white;
  }

  .upload-avatar-button:hover:not(:disabled) {
    background-color: #059669;
  }

  .delete-avatar-button {
    background-color: #ef4444;
    color: white;
  }

  .delete-avatar-button:hover:not(:disabled) {
    background-color: #dc2626;
  }

  .cancel-avatar-button {
    background-color: #6b7280;
    color: white;
  }

  .cancel-avatar-button:hover:not(:disabled) {
    background-color: #4b5563;
  }

  .upload-avatar-button:disabled, .delete-avatar-button:disabled, .cancel-avatar-button:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  @keyframes slideIn {
    from {
      opacity: 0;
      transform: translateY(-10px);
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
  @media (min-width: 640px) {
    .info-grid {
      grid-template-columns: 1fr 1fr;
    }

    .form-actions {
      justify-content: flex-start;
    }
  }

  @media (max-width: 639px) {
    .profile-container {
      padding: 1rem;
    }

    .card-header {
      padding: 1.5rem 1.5rem 1rem 1.5rem;
    }

    .profile-form, .password-form, .info-grid, .password-toggle {
      padding: 1.5rem;
    }

    .form-actions {
      flex-direction: column;
    }

    .update-button, .password-button, .cancel-button {
      width: 100%;
    }

    .profile-title {
      font-size: 2rem;
    }
  }
</style> 