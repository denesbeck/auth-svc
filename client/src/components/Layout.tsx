const Layout = ({ children }: { children: React.ReactNode }) => {
  return (
    <div className="flex flex-col items-center w-screen h-full min-h-screen bg-gradient-to-tr sm:justify-center from-dark-900 to-dark-400">
      <div className="relative z-10">{children}</div>
    </div>
  );
};

export default Layout;
