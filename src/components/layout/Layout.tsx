import React, { useState } from 'react';
import { Outlet } from 'react-router-dom';
import { Sidebar } from './Sidebar';
import { Header } from './Header';
import { ToastContainer } from '../common/ToastContainer';
import { AlertDetailModal } from '../common/AlertDetailModal';

export const Layout: React.FC = () => {
  const [mobileSidebarOpen, setMobileSidebarOpen] = useState(false);

  return (
    <div className="min-h-screen bg-[#080b11] text-slate-200">
      <Sidebar 
        isOpen={mobileSidebarOpen} 
        onCloseMobile={() => setMobileSidebarOpen(false)} 
      />

      <div className="flex flex-col min-h-screen lg:pl-64">
        <Header 
          onToggleMobileMenu={() => setMobileSidebarOpen(!mobileSidebarOpen)} 
        />

        <main className="flex-1 p-4 sm:p-6 lg:p-8 max-w-7xl w-full mx-auto space-y-6">
          <Outlet />
        </main>
      </div>

      <AlertDetailModal />
      <ToastContainer />
    </div>
  );
};
