const Layout = ({ children }: { children: React.ReactNode }) => {
  return (
    <div className="flex flex-col items-center w-screen h-full min-h-screen from-cyan-300 via-indigo-500 to-blue-400 sm:justify-center bg-linear-to-tr">
      <div className="relative top-0 z-10 py-12 px-8 sm:block sm:fixed sm:py-4 sm:px-12 bg-[#1a1d23] w-[100vw] sm:h-[30vh]">
        <h1 className="flex items-center text-5xl font-extrabold font-[DepartureMono] text-sky-300">
          CodeSync
        </h1>
        <p className="text-lg text-white">
          A collaboration platform for software developers.
        </p>
      </div>
      <div className="hidden fixed top-0 -left-10 sm:block h-[95vh] bg-[#1a1d23] rounded-[3rem] w-[50vw]" />

      {children}
    </div>
  );
};

export default Layout;
