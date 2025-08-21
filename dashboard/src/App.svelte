<script>
  import Router from 'svelte-spa-router';
  import Layout from './Layout.svelte';
  import Dashboard from './Dashboard.svelte';
  import Report from './Report.svelte';
  import RealTimeDetection from './RealTimeDetection.svelte';
  import Login from './Login.svelte';
  import Register from './Register.svelte';
  import UserProfile from './UserProfile.svelte';
  import ForgotPassword from './ForgotPassword.svelte';
  import ResetPassword from './ResetPassword.svelte';
  import VerifyRegistration from './VerifyRegistration.svelte';
  import UserManagement from './UserManagement.svelte';
  import AttackMap from './AttackMap.svelte';
  import PcapAnalyzer from './PcapAnalyzer.svelte';
  import AlertSystem from './AlertSystem.svelte';
  import AlertNotification from './AlertNotification.svelte';
  import ManualTesting from './ManualTesting.svelte';
  import './global.css';

  // Define routes for the application
  const routes = {
    '/': Dashboard,
    '/manual-testing': ManualTesting,
    '/reports': Report,
    '/realtime': RealTimeDetection,
    '/attackmap': AttackMap,
    '/pcap': PcapAnalyzer,
    '/alerts': AlertSystem,
    '/profile': UserProfile,
    '/users': UserManagement,
    '/login': Login,
    '/register': Register,
    '/forgot-password': ForgotPassword,
    '/reset-password': ResetPassword,
    '/verify-registration': VerifyRegistration
  };
</script>

<Layout>
  <Router {routes} />
  <AlertNotification />
</Layout>
