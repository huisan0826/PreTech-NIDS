<script>
  import { onMount } from 'svelte';
  import axios from 'axios';
  import { writable } from 'svelte/store';
  import { currentUser } from './stores/auth.js';
  import { push } from 'svelte-spa-router';

  let users = writable([]);
  let roles = writable([]);
  let loading = writable(true);
  let error = writable(null);
  let success = writable(null);
  let updatingUserId = null;

  onMount(async () => {
    // Check if user has admin role
    if ($currentUser?.role !== 'admin') {
      push('/');
      return;
    }
    
    await loadUsers();
    await loadRoles();
  });

  async function loadUsers() {
    try {
      loading.set(true);
      const response = await axios.get('http://localhost:8000/auth/users', {
        withCredentials: true
      });
      users.set(response.data.users);
      error.set(null);
    } catch (e) {
      console.error('Failed to load users:', e);
      error.set('Failed to load users');
    } finally {
      loading.set(false);
    }
  }

  async function loadRoles() {
    try {
      const response = await axios.get('http://localhost:8000/auth/roles', {
        withCredentials: true
      });
      roles.set(response.data.roles);
    } catch (e) {
      console.error('Failed to load roles:', e);
    }
  }

  async function updateUserRole(userId, newRole) {
    try {
      updatingUserId = userId;
      const response = await axios.put(
        `http://localhost:8000/auth/users/${userId}/role`,
        { role: newRole },
        { withCredentials: true }
      );
      
      success.set(response.data.message);
      setTimeout(() => success.set(null), 3000);
      
      // Reload users to get updated data
      await loadUsers();
    } catch (e) {
      console.error('Failed to update user role:', e);
      error.set(e.response?.data?.detail || 'Failed to update user role');
      setTimeout(() => error.set(null), 5000);
    } finally {
      updatingUserId = null;
    }
  }

  async function deleteUser(userId) {
    try {
      if (!confirm('Are you sure you want to delete this user? This action cannot be undone.')) return;
      updatingUserId = userId;
      const response = await axios.delete(`http://localhost:8000/auth/users/${userId}`, { withCredentials: true });
      success.set(response.data.message || 'User deleted successfully');
      setTimeout(() => success.set(null), 3000);
      await loadUsers();
    } catch (e) {
      console.error('Failed to delete user:', e);
      error.set(e.response?.data?.detail || 'Failed to delete user');
      setTimeout(() => error.set(null), 5000);
    } finally {
      updatingUserId = null;
    }
  }

  function getRoleColor(role) {
    const colors = {
      'admin': 'admin-role',
      'analyst': 'analyst-role', 
      'viewer': 'viewer-role'
    };
    return colors[role] || 'viewer-role';
  }

  function getPermissionDisplayName(permission) {
    const names = {
      'user_management': 'User Management',
      'system_settings': 'System Settings',
      'view_reports': 'View Reports',
      'manual_testing': 'Manual Testing', 
      'real_time_detection': 'Real-time Detection',
      'export_data': 'Export Data',
      'delete_reports': 'Delete Reports'
    };
    return names[permission] || permission;
  }

  function formatDate(dateString) {
    if (!dateString) return 'N/A';
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  }
</script>

<div class="page-container">
  <div class="page-header">
    <h1 class="page-title">👥 User Management</h1>
    <p class="page-description">Manage user accounts, roles, and permissions (Administrator Only)</p>
  </div>

  <div class="content-section">
    {#if $loading}
      <div class="loading-card">
        <div class="loading-spinner"></div>
        <p>Loading users...</p>
      </div>
    {:else if $error}
      <div class="error-card">
        <h3 class="error-title">⚠️ Error</h3>
        <p class="error-message">{$error}</p>
        <button class="retry-button" on:click={loadUsers}>Try Again</button>
      </div>
    {:else}
      {#if $success}
        <div class="success-card">
          <h3 class="success-title">✅ Success</h3>
          <p class="success-message">{$success}</p>
        </div>
      {/if}

      <!-- Users Overview -->
      <div class="overview-card">
        <h2 class="overview-title">System Overview</h2>
        <div class="stats-grid">
          <div class="stat-item">
            <div class="stat-number">{$users.length}</div>
            <div class="stat-label">Total Users</div>
          </div>
          <div class="stat-item">
            <div class="stat-number">{$users.filter(u => u.role === 'admin').length}</div>
            <div class="stat-label">Administrators</div>
          </div>
          <div class="stat-item">
            <div class="stat-number">{$users.filter(u => u.role === 'analyst').length}</div>
            <div class="stat-label">Analysts</div>
          </div>
          <div class="stat-item">
            <div class="stat-number">{$users.filter(u => u.role === 'viewer').length}</div>
            <div class="stat-label">Viewers</div>
          </div>
        </div>
      </div>

      <!-- Role Information -->
      <div class="roles-card">
        <h2 class="roles-title">Role Information</h2>
        <div class="roles-grid">
          {#each $roles as role}
            <div class="role-card">
              <div class="role-header">
                <h3 class="role-name {getRoleColor(role.role)}">{role.display_name}</h3>
                <span class="role-badge {getRoleColor(role.role)}">{role.role.toUpperCase()}</span>
              </div>
              <div class="role-permissions">
                <h4>Permissions:</h4>
                <div class="permissions-list">
                  {#each role.permissions as permission}
                    <span class="permission-tag">{getPermissionDisplayName(permission)}</span>
                  {/each}
                </div>
              </div>
            </div>
          {/each}
        </div>
      </div>

      <!-- Users Table -->
      <div class="users-card">
        <div class="users-header">
          <h2 class="users-title">User Accounts</h2>
          <button class="refresh-button" on:click={loadUsers}>🔄 Refresh</button>
        </div>

        <div class="table-container">
          <table class="users-table">
            <thead>
              <tr>
                <th>User</th>
                <th>Email</th>
                <th>Current Role</th>
                <th>Created</th>
                <th>Updated</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {#each $users as user}
                <tr class="user-row">
                  <td class="user-cell">
                    <div class="user-info">
                      <div class="username">{user.username}</div>
                      <div class="user-id">ID: {user.id.slice(-8)}</div>
                    </div>
                  </td>
                  
                  <td class="email-cell">{user.email || 'No email'}</td>
                  
                  <td class="role-cell">
                    <span class="role-badge {getRoleColor(user.role)}">
                      {user.role_display}
                    </span>
                  </td>
                  
                  <td class="date-cell">{formatDate(user.created_at)}</td>
                  <td class="date-cell">{formatDate(user.updated_at)}</td>
                  
                  <td class="actions-cell">
                    {#if user.username !== $currentUser?.username}
                      <div class="role-selector">
                        <label for="role-{user.id}" class="role-label">Change Role:</label>
                        <select 
                          id="role-{user.id}"
                          class="role-select"
                          value={user.role}
                          disabled={updatingUserId === user.id}
                          on:change={(e) => updateUserRole(user.id, e.currentTarget.value)}
                        >
                          {#each $roles as role}
                            <option value={role.role}>{role.display_name}</option>
                          {/each}
                        </select>
                        {#if updatingUserId === user.id}
                          <div class="updating-spinner"></div>
                        {/if}
                        <button class="delete-button" on:click={() => deleteUser(user.id)} disabled={updatingUserId === user.id}>
                          🗑️ Delete
                        </button>
                      </div>
                    {:else}
                      <span class="current-user-label">Current User</span>
                    {/if}
                  </td>
                </tr>
                
                <!-- Expandable user details -->
                <tr class="user-details-row">
                  <td colspan="6">
                    <div class="user-details-panel">
                      <h4>User Permissions</h4>
                      <div class="permissions-display">
                        {#each $roles.find(r => r.role === user.role)?.permissions || [] as permission}
                          <span class="permission-badge">{getPermissionDisplayName(permission)}</span>
                        {/each}
                      </div>
                    </div>
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
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
    display: flex;
    flex-direction: column;
    gap: 2rem;
  }

  /* Cards */
  .loading-card, .error-card, .success-card, .overview-card, .roles-card, .users-card {
    background: white;
    border-radius: 12px;
    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
    border: 1px solid #e5e7eb;
    padding: 2rem;
  }

  .success-card {
    border-left: 4px solid #10b981;
    background-color: #f0fdf4;
  }

  .error-card {
    border-left: 4px solid #ef4444;
    background-color: #fef2f2;
  }

  .loading-card {
    text-align: center;
  }

  .loading-spinner, .updating-spinner {
    width: 32px;
    height: 32px;
    border: 3px solid #e5e7eb;
    border-left: 3px solid #3b82f6;
    border-radius: 50%;
    animation: spin 1s linear infinite;
    margin: 0 auto 1rem auto;
  }

  .updating-spinner {
    width: 16px;
    height: 16px;
    border-width: 2px;
    margin: 0 0 0 0.5rem;
    display: inline-block;
  }

  /* Overview */
  .overview-title, .roles-title, .users-title {
    font-size: 1.5rem;
    font-weight: bold;
    margin: 0 0 1.5rem 0;
    color: #1f2937;
  }

  .stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 1rem;
  }

  .stat-item {
    text-align: center;
    padding: 1rem;
    background: #f8fafc;
    border-radius: 8px;
    border: 1px solid #e2e8f0;
  }

  .stat-number {
    font-size: 2rem;
    font-weight: bold;
    color: #3b82f6;
  }

  .stat-label {
    font-size: 0.875rem;
    color: #64748b;
    margin-top: 0.25rem;
  }

  /* Roles */
  .roles-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 1.5rem;
  }

  .role-card {
    border: 1px solid #e5e7eb;
    border-radius: 8px;
    padding: 1.5rem;
    background: #f9fafb;
  }

  .role-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1rem;
  }

  .role-name {
    font-size: 1.25rem;
    font-weight: 600;
    margin: 0;
  }

  .role-permissions h4 {
    margin: 0 0 0.75rem 0;
    color: #374151;
    font-size: 1rem;
  }

  .permissions-list, .permissions-display {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
  }

  .permission-tag, .permission-badge {
    background-color: #e0e7ff;
    color: #3730a3;
    padding: 0.25rem 0.5rem;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 500;
  }

  .permission-badge {
    background-color: #dcfce7;
    color: #166534;
  }

  /* Role badges and colors */
  .role-badge {
    padding: 0.25rem 0.75rem;
    border-radius: 15px;
    font-size: 0.75rem;
    font-weight: 600;
    color: white;
  }

  .admin-role { background-color: #dc2626; }
  .analyst-role { background-color: #3b82f6; }
  .viewer-role { background-color: #10b981; }

  /* Users table */
  .users-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1.5rem;
  }

  .refresh-button, .retry-button {
    background-color: #3b82f6;
    color: white;
    border: none;
    padding: 0.5rem 1rem;
    border-radius: 6px;
    font-size: 0.875rem;
    cursor: pointer;
    transition: background-color 0.2s ease;
    font-weight: 500;
  }

  .delete-button {
    margin-left: 0.5rem;
    background-color: #ef4444;
    color: white;
    border: none;
    padding: 0.375rem 0.75rem;
    border-radius: 6px;
    font-size: 0.75rem;
    cursor: pointer;
  }
  .delete-button:hover { background-color: #dc2626; }

  .refresh-button:hover, .retry-button:hover {
    background-color: #2563eb;
  }

  .table-container {
    overflow-x: auto;
  }

  .users-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.875rem;
  }

  .users-table th {
    background-color: #f9fafb;
    padding: 1rem;
    text-align: left;
    font-weight: 600;
    color: #374151;
    border-bottom: 1px solid #e5e7eb;
    white-space: nowrap;
  }

  .users-table td {
    padding: 1rem;
    border-bottom: 1px solid #f3f4f6;
    vertical-align: middle;
  }

  .user-row:hover {
    background-color: #f9fafb;
  }

  .user-info {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }

  .username {
    font-weight: 600;
    color: #1f2937;
  }

  .user-id {
    font-size: 0.75rem;
    color: #6b7280;
    font-family: 'Monaco', 'Consolas', 'Courier New', monospace;
  }

  .email-cell {
    color: #6b7280;
    font-size: 0.875rem;
  }

  .date-cell {
    color: #6b7280;
    font-size: 0.8rem;
    white-space: nowrap;
  }

  .role-selector {
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }

  .role-label {
    font-size: 0.75rem;
    color: #6b7280;
    white-space: nowrap;
  }

  .role-select {
    border: 1px solid #d1d5db;
    padding: 0.375rem 0.5rem;
    border-radius: 4px;
    font-size: 0.75rem;
    background-color: white;
  }

  .role-select:focus {
    outline: none;
    border-color: #3b82f6;
    box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
  }

  .current-user-label {
    font-size: 0.75rem;
    color: #10b981;
    font-weight: 600;
    background-color: #dcfce7;
    padding: 0.25rem 0.5rem;
    border-radius: 4px;
  }

  .user-details-row {
    background-color: #f8fafc;
  }

  .user-details-panel {
    padding: 1rem 0;
    border-top: 1px solid #e2e8f0;
  }

  .user-details-panel h4 {
    margin: 0 0 0.75rem 0;
    color: #374151;
    font-size: 0.875rem;
    font-weight: 600;
  }

  .success-title, .error-title {
    font-size: 1.125rem;
    font-weight: 600;
    margin: 0 0 0.5rem 0;
  }

  .success-title { color: #065f46; }
  .error-title { color: #991b1b; }

  .success-message, .error-message {
    margin: 0;
    font-size: 0.875rem;
  }

  .success-message { color: #047857; }
  .error-message { color: #dc2626; }

  @keyframes spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
  }

  /* Responsive Design */
  @media (max-width: 768px) {
    .page-container {
      padding: 1rem;
    }

    .page-title {
      font-size: 2rem;
    }

    .stats-grid {
      grid-template-columns: repeat(2, 1fr);
    }

    .roles-grid {
      grid-template-columns: 1fr;
    }

    .users-header {
      flex-direction: column;
      gap: 1rem;
      align-items: flex-start;
    }

    .table-container {
      overflow-x: auto;
      -webkit-overflow-scrolling: touch;
    }

    .users-table {
      min-width: 800px;
    }

    .users-table th,
    .users-table td {
      padding: 0.75rem 0.5rem;
    }

    .role-selector {
      flex-direction: column;
      align-items: flex-start;
      gap: 0.25rem;
    }
  }

  @media (max-width: 480px) {
    .page-container {
      padding: 0.75rem;
    }

    .page-title {
      font-size: 1.75rem;
    }

    .stats-grid {
      grid-template-columns: 1fr;
    }

    .overview-card, .roles-card, .users-card {
      padding: 1.25rem;
    }

    .users-table {
      min-width: 600px;
      font-size: 0.75rem;
    }

    .users-table th,
    .users-table td {
      padding: 0.5rem 0.375rem;
    }
  }
</style> 