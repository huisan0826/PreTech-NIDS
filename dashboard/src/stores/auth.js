import { writable, get } from 'svelte/store';

// Authentication state
export const isAuthenticated = writable(false);
export const authLoading = writable(true);
export const currentUser = writable(null);

// Permission checking function
export function hasPermission(permission) {
  const user = get(currentUser);
  
  if (!user || !user.permissions) {
    return false;
  }
  
  return user.permissions.includes(permission);
}

// Role checking function
export function hasRole(role) {
  const user = get(currentUser);
  
  return user?.role === role;
}

// Check if user is admin
export function isAdmin() {
  return hasRole('admin');
}

// Check if user is analyst or higher
export function isAnalyst() {
  const user = get(currentUser);
  
  return user?.role === 'admin' || user?.role === 'analyst';
}

// Reset auth state
export function resetAuth() {
  isAuthenticated.set(false);
  authLoading.set(false);
  currentUser.set(null);
}

// Set authenticated user
export function setAuthenticatedUser(user) {
  isAuthenticated.set(true);
  authLoading.set(false);
  currentUser.set(user);
} 