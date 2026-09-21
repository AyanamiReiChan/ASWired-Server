import { useEffect, useState } from "react";

type IdentityOptions = { enabled: boolean; loginUrl: string };

export function useIdentityOptions() {
  const [options, setOptions] = useState<IdentityOptions | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    const controller = new AbortController();
    fetch("/api/aswired/auth", { cache: "no-store", signal: controller.signal })
      .then(async (response) => {
        if (!response.ok) throw new Error("Identity service unavailable");
        const data = await response.json() as IdentityOptions;
        if (typeof data.enabled !== "boolean") throw new Error("Invalid identity options");
        if (data.enabled) {
          const url = new URL(data.loginUrl);
          const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
          if (url.username || url.password || url.search || url.hash ||
              !(url.protocol === "https:" || (url.protocol === "http:" && loopback))) {
            throw new Error("Invalid login URL");
          }
        }
        if (!controller.signal.aborted) setOptions(data);
      })
      .catch(() => { if (!controller.signal.aborted) setFailed(true); });
    return () => controller.abort();
  }, []);

  return { options, failed };
}
