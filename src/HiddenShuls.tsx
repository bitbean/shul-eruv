import { useEffect, useState, type FormEvent, type RefObject } from "react";
import L from "leaflet";
import type { LatLngTuple } from "./mapData";

type Shul = { name: string; position: LatLngTuple };
type Access =
  | { status: "loading" }
  | { status: "locked"; error?: string }
  | { status: "unlocked"; items: Shul[]; expiresAt: number };

async function requestAccess(password?: string, signal?: AbortSignal): Promise<Access> {
  try {
    const response = await fetch("/api/hidden-items", {
      cache: "no-store",
      signal,
      ...(password !== undefined && {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password }),
      }),
    });

    if (response.ok) {
      const { items, expiresAt }: { items: Shul[]; expiresAt: number } = await response.json();
      return { status: "unlocked", items, expiresAt };
    }
    if (response.status === 401) {
      return { status: "locked", error: password !== undefined ? "Incorrect password." : undefined };
    }
  } catch {
    // A network error or an unavailable server leaves the layer locked.
  }
  return { status: "locked", error: "Shul access is unavailable. Try again later." };
}

export default function HiddenShuls({ mapRef }: { mapRef: RefObject<L.Map> }) {
  const [access, setAccess] = useState<Access>({ status: "loading" });
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    const controller = new AbortController();
    void requestAccess(undefined, controller.signal).then((nextAccess) => {
      if (!controller.signal.aborted) setAccess(nextAccess);
    });
    return () => controller.abort();
  }, []);

  useEffect(() => {
    const map = mapRef.current;
    if (access.status !== "unlocked" || !map) return;

    const icon = L.divIcon({
      className: "shul-pin",
      iconSize: [12, 12],
      iconAnchor: [6, 6],
    });
    const layer = L.layerGroup().addTo(map);
    for (const shul of access.items) {
      const name = document.createElement("span");
      name.dir = "rtl";
      name.lang = "he";
      name.textContent = shul.name;
      L.marker(shul.position, { icon, interactive: false, keyboard: false })
        .bindTooltip(name, {
          className: "shul-label",
          direction: "top",
          offset: [0, -6],
          permanent: true,
        })
        .addTo(layer);
    }

    const timeout = window.setTimeout(() => setAccess({ status: "locked" }), access.expiresAt - Date.now());
    return () => {
      window.clearTimeout(timeout);
      layer.remove();
    };
  }, [access, mapRef]);

  async function unlock(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const password = new FormData(form).get("password");
    if (typeof password !== "string" || submitting) return;
    setSubmitting(true);
    const nextAccess = await requestAccess(password);
    form.reset();
    setAccess(nextAccess);
    setSubmitting(false);
  }

  if (access.status === "unlocked") return null;

  return (
    <section className="layer-card shul-access" aria-label="Shul locations">
      {access.status === "loading" ? (
        <p role="status">Checking shul access…</p>
      ) : (
        <form method="post" onSubmit={unlock}>
          <label htmlFor="shul-password">Password for shul locations</label>
          <input id="shul-password" name="password" type="password" autoComplete="current-password" maxLength={128} required />
          <button type="submit" disabled={submitting}>{submitting ? "Unlocking…" : "Show shuls"}</button>
          {access.error && <p role="alert">{access.error}</p>}
        </form>
      )}
    </section>
  );
}
