import Redis from "ioredis";

export default function redis() {
  let instance: Redis | null = null;

  return {
    getInstance: () => {
      if (!instance) {
        instance = new Redis();
      }
      return instance;
    },
  };
}
